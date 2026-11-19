import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  SetControlCheckedTypesInput,
  SetControlDecisionAddressInput,
  SetControlEventsAddressInput,
  SetControlModeInput,
} from '@stack/shared';
import { createStackMcpServer } from './index.js';

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

const SECRET = 'whsec_' + 'a1b2c3d4'.repeat(6);

async function connect(response: () => Response = () => new Response('{}', { status: 200 })) {
  const calls: Captured[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
    calls.push({
      url,
      method: init.method ?? 'GET',
      headers: init.headers ?? {},
      body: init.body ? JSON.parse(init.body) as unknown : undefined,
    });
    return response();
  }));
  const server = createStackMcpServer('http://api.test', 'sk_test_unused');
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'control-socket-contract', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, calls };
}

const textOf = (result: unknown) => (result as { content: Array<{ text: string }> }).content[0]!.text;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('control socket tools', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('reads and changes the socket on its own routes with the API bodies', async () => {
    const { client, calls } = await connect();
    await client.callTool({ name: 'stack_get_control_socket', arguments: {} });
    await client.callTool({ name: 'stack_set_control_decision_address', arguments: { url: 'https://control.example/decide', timeout_ms: 2000, governance_approval_id: 'gvr_ok' } });
    await client.callTool({ name: 'stack_set_control_events_address', arguments: { url: 'https://control.example/events' } });
    await client.callTool({ name: 'stack_clear_control_address', arguments: { target: 'events' } });
    await client.callTool({ name: 'stack_verify_control_address', arguments: { target: 'decision' } });
    await client.callTool({ name: 'stack_test_control_address', arguments: { target: 'events' } });
    await client.callTool({ name: 'stack_rotate_control_secret', arguments: { target: 'decision' } });
    await client.callTool({ name: 'stack_set_control_mode', arguments: { mode: 'none' } });
    await client.callTool({ name: 'stack_set_control_checked_types', arguments: { types: null } });
    await client.callTool({ name: 'stack_set_control_on_unavailable', arguments: { on_unavailable: 'allow' } });

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      'GET http://api.test/v1/control-socket',
      'PUT http://api.test/v1/control-socket/decision',
      'PUT http://api.test/v1/control-socket/events',
      'DELETE http://api.test/v1/control-socket/events',
      'POST http://api.test/v1/control-socket/decision/verify',
      'POST http://api.test/v1/control-socket/events/test',
      'POST http://api.test/v1/control-socket/decision/secret/rotate',
      'PUT http://api.test/v1/control-socket/mode',
      'PUT http://api.test/v1/control-socket/checked-types',
      'PUT http://api.test/v1/control-socket/on-unavailable',
    ]);
    expect(SetControlDecisionAddressInput.parse(calls[1]?.body)).toEqual({ url: 'https://control.example/decide', timeout_ms: 2000 });
    expect(calls[1]?.headers['X-Governance-Approval']).toBe('gvr_ok');
    expect(SetControlEventsAddressInput.parse(calls[2]?.body)).toEqual({ url: 'https://control.example/events' });
    expect(calls[2]?.headers['X-Governance-Approval']).toBeUndefined();
    expect(SetControlModeInput.parse(calls[7]?.body)).toEqual({ mode: 'none' });
    expect(SetControlCheckedTypesInput.parse(calls[8]?.body)).toEqual({ types: null });
    expect(calls[9]?.body).toEqual({ on_unavailable: 'allow' });
  });

  it('lists decisions with the filters on the query and reads one by id', async () => {
    const { client, calls } = await connect();
    await client.callTool({ name: 'stack_list_control_decisions', arguments: {} });
    await client.callTool({
      name: 'stack_list_control_decisions',
      arguments: { limit: 20, account_id: 'acct_1', verdict: 'deny', before: '2026-10-01T00:00:00.000Z' },
    });
    await client.callTool({ name: 'stack_get_control_decision', arguments: { decision_id: 'dec_0123456789abcdef' } });
    expect(calls[0]?.url).toBe('http://api.test/v1/control-decisions');
    const listed = new URL(calls[1]!.url);
    expect(listed.pathname).toBe('/v1/control-decisions');
    expect(Object.fromEntries(listed.searchParams)).toEqual({
      limit: '20', account_id: 'acct_1', verdict: 'deny', before: '2026-10-01T00:00:00.000Z',
    });
    expect(calls[2]?.url).toBe('http://api.test/v1/control-decisions/dec_0123456789abcdef');
  });

  it('never lets a signing secret into the conversation, and points the person to the Console link instead', async () => {
    const reveal = { url: 'https://getstack.run/app/control-secret#tok', expires_at: '2026-10-21T11:00:00.000Z' };
    const { client } = await connect(() => json({ socket: { socket_id: 'csk_1' }, secret: null, secret_reveal: reveal }, 201));
    for (const [name, args] of [
      ['stack_set_control_decision_address', { url: 'https://control.example/decide' }],
      ['stack_set_control_events_address', { url: 'https://control.example/events' }],
      ['stack_rotate_control_secret', { target: 'decision' }],
    ] as const) {
      const text = textOf(await client.callTool({ name, arguments: args }));
      const body = JSON.parse(text) as { secret_note?: string; secret?: unknown; secret_reveal?: { url: string } };
      expect(body, name).not.toHaveProperty('secret');
      expect(body.secret_reveal?.url, name).toBe(reveal.url);
      expect(body.secret_note, name).toMatch(/never shown in a chat/);
      expect(body.secret_note, name).toMatch(/secret_reveal\.url/);
    }
  });

  it('drops a secret the API returns anyway, wherever it sits in the answer', async () => {
    const answers = [
      { socket: { socket_id: 'csk_1' }, secret: SECRET },
      { target: 'decision', secret: SECRET, previous_valid_until: '2026-10-22T00:00:00.000Z' },
      { socket: { socket_id: 'csk_1', decision: { secret: SECRET, secret_set: true } }, secret: SECRET, secret_reveal: null },
    ];
    for (const answer of answers) {
      const { client } = await connect(() => json(answer, 201));
      for (const [name, args] of [
        ['stack_set_control_decision_address', { url: 'https://control.example/decide' }],
        ['stack_set_control_events_address', { url: 'https://control.example/events' }],
        ['stack_rotate_control_secret', { target: 'events' }],
      ] as const) {
        const text = textOf(await client.callTool({ name, arguments: args }));
        expect(text, name).not.toContain(SECRET);
        expect(text, name).not.toContain('whsec_');
      }
    }
  });

  it('adds no secret note when no secret was created, and says in the descriptions that the chat never holds it', async () => {
    const { client } = await connect(() => json({ socket: { socket_id: 'csk_1' }, secret: null, secret_reveal: null }));
    const body = JSON.parse(textOf(await client.callTool({ name: 'stack_set_control_decision_address', arguments: { url: 'https://control.example/decide' } }))) as Record<string, unknown>;
    expect(body).not.toHaveProperty('secret_note');
    const tools = new Map((await client.listTools()).tools.map((tool) => [tool.name, tool.description ?? '']));
    for (const name of ['stack_set_control_decision_address', 'stack_set_control_events_address', 'stack_rotate_control_secret']) {
      expect(tools.get(name), name).toMatch(/never returned in the chat/);
      expect(tools.get(name), name).toMatch(/secret_reveal/);
    }
  });

  it('surfaces the approval link and never asks the chat for a browser-only approval', async () => {
    const { client, calls } = await connect(() => json({
      error: {
        code: 'GOVERNANCE_APPROVAL_REQUIRED',
        message: 'Approval required',
        details: { approval_id: 'gvr_1', approval_url: 'https://getstack.run/app/approve/gvr_1' },
      },
    }, 403));
    const result = await client.callTool({ name: 'stack_set_control_decision_address', arguments: { url: 'https://control.example/decide' } });
    expect(result.isError).toBe(true);
    const text = textOf(result);
    expect(text).toContain('GOVERNANCE_APPROVAL_REQUIRED');
    expect(text).toContain('https://getstack.run/app/approve/gvr_1');
    // No chat session: the call is made once and the link comes back.
    expect(calls).toHaveLength(1);
  });

  it('says in each changing tool that the person approves in their browser', async () => {
    const { client } = await connect();
    const tools = new Map((await client.listTools()).tools.map((tool) => [tool.name, tool.description ?? '']));
    for (const name of [
      'stack_set_control_decision_address',
      'stack_set_control_events_address',
      'stack_clear_control_address',
      'stack_verify_control_address',
      'stack_rotate_control_secret',
      'stack_set_control_mode',
      'stack_set_control_checked_types',
      'stack_set_control_on_unavailable',
    ]) {
      expect(tools.get(name), name).toMatch(/approve it in their browser, never in the chat/);
      expect(tools.get(name), name).toMatch(/approval_url/);
    }
  });
});
