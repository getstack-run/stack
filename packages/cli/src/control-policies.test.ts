import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { governedApi } from './governance.js';
import { printJson } from './format.js';
import { cmdPolicies, cmdReviews } from './control-policies.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));

const stdinText = vi.hoisted(() => ({ value: '' }));
vi.mock('node:fs', async importOriginal => {
  const real = await importOriginal<typeof import('node:fs')>();
  return {
    ...real,
    readFileSync: ((path: unknown, ...rest: unknown[]) =>
      path === 0 ? stdinText.value : (real.readFileSync as (...a: unknown[]) => unknown)(path, ...rest)) as typeof real.readFileSync,
  };
});

const AGENT = 'agt_abcdefgh1234';
const definition = { name: 'Support agent', spend: { max_per_action_cents: 500 } };

const dir = mkdtempSync(join(tmpdir(), 'stack-cli-policies-'));
const file = (name: string, value: unknown): string => {
  const path = join(dir, name);
  writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
  return path;
};

afterAll(() => rmSync(dir, { recursive: true, force: true }));

beforeEach(() => {
  vi.clearAllMocks();
  stdinText.value = '';
});

describe('policies CLI wire contract', () => {
  it('lists and reads without an approval flow', async () => {
    await cmdPolicies(['list']);
    await cmdPolicies(['get', 'default']);
    await cmdPolicies(['get', AGENT]);
    await cmdPolicies(['revisions', 'cpl_abc']);
    expect(vi.mocked(api).mock.calls).toEqual([
      ['GET', '/v1/control-policies'],
      ['GET', '/v1/control-policies/default'],
      ['GET', `/v1/control-policies/agents/${AGENT}`],
      ['GET', '/v1/control-policies/cpl_abc/revisions'],
    ]);
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('creates through the approval flow without an expected revision, and revises with one', async () => {
    const path = file('definition.json', definition);
    await cmdPolicies(['set', 'default', '--file', path]);
    await cmdPolicies(['set', AGENT, '--file', path, '--expected-revision', '3']);
    await cmdPolicies(['set', '--expected-revision', '0', '--file', path, AGENT]);
    expect(vi.mocked(governedApi).mock.calls).toEqual([
      ['PUT', '/v1/control-policies/default', { body: { definition } }],
      ['PUT', `/v1/control-policies/agents/${AGENT}`, { body: { definition, expected_revision: 3 } }],
      ['PUT', `/v1/control-policies/agents/${AGENT}`, { body: { definition, expected_revision: 0 } }],
    ]);
    expect(api).not.toHaveBeenCalled();
  });

  it('reads the definition from stdin, and unwraps what get prints', async () => {
    stdinText.value = JSON.stringify(definition);
    await cmdPolicies(['set', 'default', '--stdin']);
    stdinText.value = JSON.stringify({ id: 'cpl_1', agent_id: null, revision: 2, definition, findings: [] });
    await cmdPolicies(['set', 'default', '--stdin', '--expected-revision', '2']);
    stdinText.value = JSON.stringify({ policy: { id: 'cpl_2', revision: 5, definition }, in_force: { id: 'cpl_2', revision: 5, source: 'agent' }, controls_enabled: true });
    await cmdPolicies(['set', AGENT, '--stdin']);
    expect(vi.mocked(governedApi).mock.calls).toEqual([
      ['PUT', '/v1/control-policies/default', { body: { definition } }],
      ['PUT', '/v1/control-policies/default', { body: { definition, expected_revision: 2 } }],
      ['PUT', `/v1/control-policies/agents/${AGENT}`, { body: { definition } }],
    ]);
  });

  it('deletes through the approval flow, with the revision in the query only when given', async () => {
    await cmdPolicies(['delete', 'default']);
    await cmdPolicies(['delete', AGENT, '--expected-revision', '4']);
    expect(vi.mocked(governedApi).mock.calls).toEqual([
      ['DELETE', '/v1/control-policies/default', undefined],
      ['DELETE', `/v1/control-policies/agents/${AGENT}`, { query: { expected_revision: 4 } }],
    ]);
  });

  it('starts from current access through the approval flow', async () => {
    await cmdPolicies(['start', AGENT]);
    expect(governedApi).toHaveBeenCalledWith('POST', `/v1/control-policies/agents/${AGENT}/start-from-current-access`);
    expect(api).not.toHaveBeenCalled();
  });

  it('prints what the API answered', async () => {
    vi.mocked(governedApi).mockResolvedValueOnce({ change: 'tighten', policy: { id: 'cpl_1' } });
    await cmdPolicies(['set', 'default', '--file', file('definition.json', definition)]);
    expect(printJson).toHaveBeenCalledWith({ change: 'tighten', policy: { id: 'cpl_1' } });
  });
});

describe('policies simulate', () => {
  it('builds the call from flags and applies nothing through the approval flow', async () => {
    await cmdPolicies(['simulate', '--agent', AGENT, '--action', 'card.checkout', '--amount-cents', '900', '--connection', 'scon_abcdefgh', '--target', '{"merchant":"shop.example.com"}']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/control-policies/simulate', {
      body: {
        agent_id: AGENT,
        call: { action: 'card.checkout', amount_cents: 900, connection_id: 'scon_abcdefgh', target: { merchant: 'shop.example.com' } },
      },
    });
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('tries the call inside a Mission with --mission, and refuses anything that is not a Mission id', async () => {
    await cmdPolicies(['simulate', '--agent', AGENT, '--action', 'email.send', '--mission', 'ms_abc123', '--target', '{"to":"ana@example.com"}']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/control-policies/simulate', {
      body: { agent_id: AGENT, call: { action: 'email.send', mission_id: 'ms_abc123', target: { to: 'ana@example.com' } } },
    });
    vi.mocked(api).mockClear();
    await expect(cmdPolicies(['simulate', '--agent', AGENT, '--action', 'email.send', '--mission', 'agt_1'])).rejects.toThrow('Mission id');
    expect(api).not.toHaveBeenCalled();
  });

  it('tries a draft definition without naming an agent', async () => {
    await cmdPolicies(['simulate', '--definition', file('draft.json', definition), '--action', 'email.send']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/control-policies/simulate', { body: { definition, call: { action: 'email.send' } } });
  });

  it('takes the whole input from a file, with flags overriding it', async () => {
    const input = { agent_id: AGENT, call: { action: 'wallet.payment', amount_cents: 100, target: { payee: '0xabc' } } };
    await cmdPolicies(['simulate', '--file', file('input.json', input), '--amount-cents', '900']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/control-policies/simulate', {
      body: { agent_id: AGENT, call: { action: 'wallet.payment', amount_cents: 900, target: { payee: '0xabc' } } },
    });
  });
});

describe('reviews CLI', () => {
  it('lists pending reviews by default, all with --all, and reads one', async () => {
    await cmdReviews(['list']);
    await cmdReviews(['list', '--all', '--limit', '10']);
    await cmdReviews(['get', 'crv_abc']);
    expect(vi.mocked(api).mock.calls).toEqual([
      ['GET', '/v1/control-reviews', { query: { status: 'pending' } }],
      ['GET', '/v1/control-reviews', { query: { status: 'all', limit: 10 } }],
      ['GET', '/v1/control-reviews/crv_abc'],
    ]);
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('has no decide command: a person decides at the approval link', async () => {
    await expect(cmdReviews(['approve', 'crv_abc'])).rejects.toThrow(/reviews takes list or get/);
    await expect(cmdReviews(['decide', 'crv_abc'])).rejects.toThrow(/reviews takes list or get/);
    expect(api).not.toHaveBeenCalled();
  });
});

describe('policies CLI input checks', () => {
  const path = (): string => file('definition.json', definition);

  it.each([
    [() => ['get'], /policy scope/],
    [() => ['get', 'default', 'extra'], /unexpected argument extra/],
    [() => ['set', 'default'], /--file <path> or --stdin/],
    [() => ['set', '--file', path()], /policy scope/],
    [() => ['set', 'default', '--file', path(), '--stdin'], /not both/],
    [() => ['set', 'default', '--file', path(), '--expected-revision', 'latest'], /whole number/],
    [() => ['set', 'default', '--file', file('list.json', '[]')], /one JSON object/],
    [() => ['set', 'default', '--file', file('broken.json', '{')], /not valid JSON/],
    [() => ['delete'], /policy scope/],
    [() => ['delete', 'default', '--expected-revision', '-1'], /whole number/],
    [() => ['start'], /the agent/],
    [() => ['revisions'], /policy id/],
    [() => ['simulate', '--agent', AGENT], /needs an action/],
    [() => ['simulate', '--action', 'card.checkout'], /name an agent/],
    [() => ['simulate', '--agent', AGENT, '--action', 'teleport'], /unknown action type teleport/],
    [() => ['simulate', '--agent', AGENT, '--action', 'card.checkout', '--target', '[1]'], /one JSON object/],
    [() => ['nope'], /policies takes/],
    [() => [], /policies takes/],
  ] as Array<[() => string[], RegExp]>)('refuses case %# before any request', async (argv, message) => {
    await expect(cmdPolicies(argv())).rejects.toThrow(message);
    expect(api).not.toHaveBeenCalled();
    expect(governedApi).not.toHaveBeenCalled();
  });
});
