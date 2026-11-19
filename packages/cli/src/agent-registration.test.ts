import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const output = vi.hoisted(() => ({ stdout: [] as string[], stderr: [] as string[] }));
vi.mock('node:process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:process')>();
  return {
    ...actual,
    exit: (code?: number) => { throw new Error(`unexpected exit ${code}`); },
    stdout: { write: (chunk: string) => { output.stdout.push(chunk); return true; } },
    stderr: { isTTY: false, write: (chunk: string) => { output.stderr.push(chunk); return true; } },
  };
});

import { cmdAgent } from './agent.js';
import { cmdQuickstart } from './quickstart.js';

const approvalId = 'gvr_registration_fixture';
const approvalUrl = `https://getstack.run/app/approve/${approvalId}`;
const agent = { id: 'agt_registration_fixture', name: 'support-worker' };

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function approvalRequired(): Response {
  return response({ error: {
    code: 'GOVERNANCE_APPROVAL_REQUIRED',
    message: 'approval required',
    details: { approval_id: approvalId, approval_url: approvalUrl },
  } }, 403);
}

function approvals(status: string): Response {
  return response({ approvals: [
    { id: 'gvr_other_request', status: 'approved', expires_at: new Date(Date.now() + 60_000).toISOString() },
    { id: approvalId, status, expires_at: new Date(Date.now() + 60_000).toISOString() },
  ] });
}

describe('agent register governance', () => {
  beforeEach(() => {
    output.stdout.length = 0;
    output.stderr.length = 0;
    vi.stubEnv('STACK_API_KEY', 'synthetic-registration-token');
    vi.stubEnv('STACK_AGENT_ID', '');
    vi.stubEnv('STACK_NO_BROWSER', '1');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('prints the review link and retries the exact registration with its approved request id', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(approvalRequired())
      .mockResolvedValueOnce(approvals('approved'))
      .mockResolvedValueOnce(response(agent, 201));
    vi.stubGlobal('fetch', fetch);

    await cmdAgent(['register', agent.name, '--description', 'Support updates', '--profile', 'proxied-llm-bot', '--json']);

    expect(fetch).toHaveBeenCalledTimes(3);
    const [firstUrl, first] = fetch.mock.calls[0]!;
    const [pollUrl, poll] = fetch.mock.calls[1]!;
    const [retryUrl, retry] = fetch.mock.calls[2]!;
    expect(new URL(String(firstUrl)).pathname).toBe('/v1/agents/register');
    expect(first?.method).toBe('POST');
    expect(JSON.parse(String(first?.body))).toEqual({
      name: agent.name, description: 'Support updates', profile: 'proxied-llm-bot',
    });
    expect(new Headers(first?.headers).has('X-Governance-Approval')).toBe(false);
    expect(new URL(String(pollUrl)).pathname).toBe('/v1/governance/approvals');
    expect(poll?.method).toBe('GET');
    expect(retryUrl).toBe(firstUrl);
    expect(retry?.method).toBe(first?.method);
    expect(retry?.body).toBe(first?.body);
    expect(new Headers(retry?.headers).get('X-Governance-Approval')).toBe(approvalId);
    expect(JSON.parse(output.stdout.join(''))).toEqual(agent);
    expect(output.stderr.join('')).toContain(approvalUrl);
    expect(output.stderr.join('')).not.toContain('synthetic-registration-token');
    expect(output.stderr.join('')).not.toContain('read-only');
  });

  it.each([
    ['rejected', 'was rejected'],
    ['consumed', 'was already used'],
  ])('does not retry registration when %s or use another approved request', async (status, message) => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(approvalRequired())
      .mockResolvedValueOnce(approvals(status));
    vi.stubGlobal('fetch', fetch);

    await expect(cmdAgent(['register', agent.name, '--json'])).rejects.toThrow(message);

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(output.stdout).toEqual([]);
  });

  it('returns registrations that need no review without polling', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(response(agent, 201));
    vi.stubGlobal('fetch', fetch);

    await cmdAgent(['register', agent.name, '--json']);

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(JSON.parse(output.stdout.join(''))).toEqual(agent);
    expect(output.stderr).toEqual([]);
  });

  it('sends the posture an owner names at registration: a strict mode and test traffic, in the one request', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(response(agent, 201));
    vi.stubGlobal('fetch', fetch);

    await cmdAgent(['register', agent.name, '--accountability-mode', 'enforced', '--eval-traffic', 'true', '--json']);

    expect(JSON.parse(String(fetch.mock.calls[0]![1]?.body))).toEqual({ name: agent.name, accountability_mode: 'enforced', eval_traffic: true });
  });

  it('names no mode of its own: a bare registration leaves the server default, which is logged', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(response(agent, 201));
    vi.stubGlobal('fetch', fetch);

    await cmdAgent(['register', agent.name, '--json']);

    expect(JSON.parse(String(fetch.mock.calls[0]![1]?.body))).toEqual({ name: agent.name });
  });

  it('sets an agent up from a file as one request, and asks for one approval', async () => {
    const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = await mkdtemp(join(tmpdir(), 'cli-setup-'));
    const file = join(dir, 'setup.json');
    const setup = {
      agent: { name: agent.name },
      grants: [{ service_connection_id: 'scon_a', scopes: ['read'] }],
      allowed_hosts: [{ service_connection_id: 'scon_a', allowed_hosts: ['api.example.com'] }],
    };
    await writeFile(file, JSON.stringify(setup));
    const result = { agent, grants: [{ id: 'g_1', service_connection_id: 'scon_a' }], allowed_hosts: setup.allowed_hosts };
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(approvalRequired())
      .mockResolvedValueOnce(approvals('approved'))
      .mockResolvedValueOnce(response(result, 201));
    vi.stubGlobal('fetch', fetch);
    try {
      await cmdAgent(['setup', '--from-file', file, '--json']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
    expect(fetch).toHaveBeenCalledTimes(3);
    const [firstUrl, first] = fetch.mock.calls[0]!;
    const [, retry] = fetch.mock.calls[2]!;
    expect(new URL(String(firstUrl)).pathname).toBe('/v1/agents/setup');
    expect(JSON.parse(String(first?.body))).toEqual(setup);
    expect(retry?.body).toBe(first?.body);
    expect(new Headers(retry?.headers).get('X-Governance-Approval')).toBe(approvalId);
    expect(JSON.parse(output.stdout.join(''))).toEqual(result);
  });

  it('dismisses an agent\'s open warnings by name and says criticals stay open', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (url) => {
      const path = new URL(String(url)).pathname;
      if (path === '/v1/agents') return response([agent]);
      if (path === `/v1/agents/${agent.id}/dismiss-warnings`) {
        return response({ agent_id: agent.id, dismissed: 2, by_signal_type: { undeclared_target: 2 }, repeats_hidden_for_seconds: 86400 });
      }
      return response({}, 404);
    });
    vi.stubGlobal('fetch', fetch);

    await cmdAgent(['dismiss-warnings', agent.name]);

    expect(output.stdout.join('')).toContain('dismissed 2 open warnings for support-worker');
    expect(output.stdout.join('')).toContain('criticals stay open');
    const post = fetch.mock.calls.find(([url]) => new URL(String(url)).pathname.endsWith('/dismiss-warnings'))!;
    expect(post[1]?.method).toBe('POST');
  });

  it.each([false, true])('quickstart completes approved registration and grant with existing agent = %s', async (reuseAgent) => {
    const grantApprovalId = 'gvr_grant_fixture';
    let pendingApproval = '';
    const syntheticToken = `fixture.${Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 900 })).toString('base64url')}.fixture`;
    const fetch = vi.fn<typeof globalThis.fetch>(async (url, options) => {
      const path = new URL(String(url)).pathname;
      if (path === '/v1/services/connected') return response([
        { id: 'svc_fixture', provider: 'anthropic', status: 'active', scopes: ['messages.create'] },
      ]);
      if (path === '/v1/agents') return response(reuseAgent ? [{
        ...agent, credential_access: 'proxy_only', accountability_mode: 'logged', key_mode: 'stack_managed',
      }] : []);
      if (path === '/v1/governance/approvals') return response({ approvals: [{
        id: pendingApproval, status: 'approved', expires_at: new Date(Date.now() + 60_000).toISOString(),
      }] });
      if (path === '/v1/agents/register' || path === '/v1/services/grant') {
        const requiredId = path === '/v1/agents/register' ? approvalId : grantApprovalId;
        if (!new Headers(options?.headers).has('X-Governance-Approval')) {
          pendingApproval = requiredId;
          return response({ error: {
            code: 'GOVERNANCE_APPROVAL_REQUIRED', message: 'approval required',
            details: { approval_id: requiredId, approval_url: `https://getstack.run/app/approve/${requiredId}` },
          } }, 403);
        }
        expect(new Headers(options?.headers).get('X-Governance-Approval')).toBe(requiredId);
        return response(path === '/v1/agents/register' ? agent : { granted: true }, 201);
      }
      if (path === `/v1/agents/${agent.id}/permissions`) return response([]);
      if (path === '/v1/missions/start') return response({
        mission_id: 'ms_quickstart_fixture', claim_id: 'mc_fixture',
        expires_at: new Date(Date.now() + 900_000).toISOString(),
        passport: { token: syntheticToken, jti: 'pp_fixture', expires_at: new Date(Date.now() + 900_000).toISOString() },
      }, 201);
      if (path === '/v1/missions/ms_quickstart_fixture/complete') return response({ mission_id: 'ms_quickstart_fixture' });
      if (path === '/v1/llm/anthropic/messages') return response({ content: [{ type: 'text', text: 'works' }] });
      if (path === '/v1/audit') return response({ entries: [] });
      throw new Error(`Unexpected fixture request: ${path}`);
    });
    vi.stubGlobal('fetch', fetch);

    await cmdQuickstart(['--provider', 'anthropic', '--agent', agent.name]);

    for (const path of ['/v1/agents/register', '/v1/services/grant']) {
      const calls = fetch.mock.calls.filter(([url]) => new URL(String(url)).pathname === path);
      if (reuseAgent && path === '/v1/agents/register') {
        expect(calls).toHaveLength(0);
        continue;
      }
      expect(calls).toHaveLength(2);
      expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body);
    }
    const grant = fetch.mock.calls.find(([url]) => new URL(String(url)).pathname === '/v1/services/grant')!;
    expect(JSON.parse(String(grant[1]?.body))).toEqual({
      agent_id: agent.id, service_connection_id: 'svc_fixture', scopes: ['messages.create'],
    });
    expect(fetch.mock.calls.filter(([url]) => new URL(String(url)).pathname === '/v1/llm/anthropic/messages')).toHaveLength(1);
    expect(fetch.mock.calls.some(([url]) => new URL(String(url)).pathname === '/v1/passports/issue')).toBe(false);
    const start = fetch.mock.calls.filter(([url]) => new URL(String(url)).pathname === '/v1/missions/start');
    expect(start).toHaveLength(1);
    expect(JSON.parse(String(start[0]![1]?.body))).toEqual({
      agent_id: agent.id,
      mission: { intent_summary: 'quickstart: one governed anthropic call', intent_services: ['anthropic'], expires_in_seconds: 900 },
    });
    expect(fetch.mock.calls.filter(([url]) => new URL(String(url)).pathname === '/v1/missions/ms_quickstart_fixture/complete')).toHaveLength(1);
    expect(output.stdout.join('')).toContain('call succeeded');
    expect(output.stderr.join('')).toContain(grantApprovalId);
  });
});
