import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { SetControlPolicyInput, SimulateControlPolicyInput } from '@stack/shared';
import { createStackMcpServer } from './index.js';

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

const AGENT = 'agt_0123456789abcdef';
const APPROVAL_URL = 'https://getstack.run/app/approve/gvr_1';

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
  const client = new Client({ name: 'control-policies-contract', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, calls };
}

const textOf = (result: unknown) => (result as { content: Array<{ text: string }> }).content[0]!.text;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const approvalRequired = () => json({
  error: {
    code: 'GOVERNANCE_APPROVAL_REQUIRED',
    message: 'Approval required',
    details: { approval_id: 'gvr_1', approval_url: APPROVAL_URL },
  },
}, 403);

const DEFINITION = {
  name: 'Support agent',
  actions: { kinds: { 'card.checkout': 'review' as const } },
  spend: { max_per_action_cents: 5_000 },
};

const POLICY_TOOLS = [
  'stack_list_control_policies',
  'stack_get_control_policy',
  'stack_set_control_policy',
  'stack_delete_control_policy',
  'stack_policy_start_from_current_access',
  'stack_simulate_control_policy',
  'stack_list_control_reviews',
  'stack_get_control_review',
  'stack_list_control_policy_revisions',
];

describe('control policy tools', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('reads policies and held actions on their own routes', async () => {
    const { client, calls } = await connect();
    await client.callTool({ name: 'stack_list_control_policies', arguments: {} });
    await client.callTool({ name: 'stack_get_control_policy', arguments: {} });
    await client.callTool({ name: 'stack_get_control_policy', arguments: { agent_id: AGENT } });
    await client.callTool({ name: 'stack_list_control_reviews', arguments: {} });
    await client.callTool({ name: 'stack_list_control_reviews', arguments: { status: 'all', limit: 20 } });

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      'GET http://api.test/v1/control-policies',
      'GET http://api.test/v1/control-policies/default',
      `GET http://api.test/v1/control-policies/agents/${AGENT}`,
      'GET http://api.test/v1/control-reviews',
      'GET http://api.test/v1/control-reviews?status=all&limit=20',
    ]);
  });

  it('reads one held action and the revisions of one policy by id', async () => {
    const { client, calls } = await connect();
    await client.callTool({ name: 'stack_get_control_review', arguments: { review_id: 'crv_abc-1' } });
    await client.callTool({ name: 'stack_list_control_policy_revisions', arguments: { policy_id: 'cpl_abc-1' } });

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      'GET http://api.test/v1/control-reviews/crv_abc-1',
      'GET http://api.test/v1/control-policies/cpl_abc-1/revisions',
    ]);
    expect(calls.every((call) => call.body === undefined)).toBe(true);
  });

  it('creates and revises a policy with the API body, the revision only when given', async () => {
    const { client, calls } = await connect();
    await client.callTool({ name: 'stack_set_control_policy', arguments: { definition: DEFINITION } });
    await client.callTool({
      name: 'stack_set_control_policy',
      arguments: { agent_id: AGENT, definition: DEFINITION, expected_revision: 3, governance_approval_id: 'gvr_ok' },
    });

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      'PUT http://api.test/v1/control-policies/default',
      `PUT http://api.test/v1/control-policies/agents/${AGENT}`,
    ]);
    const created = SetControlPolicyInput.parse(calls[0]?.body);
    expect(created.expected_revision).toBeUndefined();
    expect(created.definition.name).toBe('Support agent');
    expect(created.definition.actions.kinds).toEqual({ 'card.checkout': 'review' });
    expect(Object.keys(calls[0]?.body as object)).toEqual(['definition']);
    expect(calls[0]?.headers['X-Governance-Approval']).toBeUndefined();
    const revised = SetControlPolicyInput.parse(calls[1]?.body);
    expect(revised.expected_revision).toBe(3);
    expect(Object.keys(calls[1]?.body as object).sort()).toEqual(['definition', 'expected_revision']);
    expect(calls[1]?.headers['X-Governance-Approval']).toBe('gvr_ok');
  });

  it('deletes a policy with the revision on the query and the approval on the header', async () => {
    const { client, calls } = await connect();
    await client.callTool({ name: 'stack_delete_control_policy', arguments: {} });
    await client.callTool({
      name: 'stack_delete_control_policy',
      arguments: { agent_id: AGENT, expected_revision: 2, governance_approval_id: 'gvr_ok' },
    });

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      'DELETE http://api.test/v1/control-policies/default',
      `DELETE http://api.test/v1/control-policies/agents/${AGENT}?expected_revision=2`,
    ]);
    expect(calls[0]?.body).toBeUndefined();
    expect(calls[1]?.headers['X-Governance-Approval']).toBe('gvr_ok');
  });

  it('starts a policy from current access and simulates a stored policy or a draft', async () => {
    const { client, calls } = await connect();
    await client.callTool({ name: 'stack_policy_start_from_current_access', arguments: { agent_id: AGENT } });
    await client.callTool({
      name: 'stack_simulate_control_policy',
      arguments: { agent_id: AGENT, call: { action: 'card.checkout', amount_cents: 9_900, target: { merchant: 'shop.example' } } },
    });
    await client.callTool({
      name: 'stack_simulate_control_policy',
      arguments: {
        definition: DEFINITION,
        call: { action: 'proxy.call', connection_id: 'scon_1', request: { method: 'POST', url: 'https://api.example/v1/send', body: { to: 'a@b.example' } } },
      },
    });

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `POST http://api.test/v1/control-policies/agents/${AGENT}/start-from-current-access`,
      'POST http://api.test/v1/control-policies/simulate',
      'POST http://api.test/v1/control-policies/simulate',
    ]);
    expect(calls[0]?.body).toBeUndefined();
    const stored = SimulateControlPolicyInput.parse(calls[1]?.body);
    expect(stored.agent_id).toBe(AGENT);
    expect(stored.definition).toBeUndefined();
    expect(stored.call).toMatchObject({ action: 'card.checkout', amount_cents: 9_900, target: { merchant: 'shop.example' } });
    const draft = SimulateControlPolicyInput.parse(calls[2]?.body);
    expect(draft.agent_id).toBeUndefined();
    expect(draft.definition?.name).toBe('Support agent');
    expect(draft.call.request?.url).toBe('https://api.example/v1/send');
  });

  it('sets recipients per job: a rule may say "per_mission", the account lists may say it too, and a simulation can run inside a Mission', async () => {
    const perJob = {
      name: 'Support agent',
      connections: { mode: 'listed' as const, rules: [{
        id: 'mail-per-job', effect: 'allow' as const, recipients: 'per_mission' as const,
        access: { connection_id: 'scon_mail', intents: [{ name: 'gmail.send_message', params: {} }] },
      }] },
      recipients: { email: ['ana@example.com', '@example.org'], sms: 'per_mission' as const, call: 'per_mission' as const },
    };
    const { client, calls } = await connect();
    await client.callTool({ name: 'stack_set_control_policy', arguments: { agent_id: AGENT, definition: perJob, expected_revision: 2 } });
    await client.callTool({
      name: 'stack_simulate_control_policy',
      arguments: { agent_id: AGENT, call: { action: 'email.send', target: { to: 'ana@example.com' }, mission_id: 'ms_abc123' } },
    });
    const set = SetControlPolicyInput.parse(calls[0]?.body);
    expect(set.definition.connections.rules[0]?.recipients).toBe('per_mission');
    expect(set.definition.recipients).toEqual({ email: ['ana@example.com', '@example.org'], sms: 'per_mission', call: 'per_mission' });
    expect((calls[0]?.body as { definition: { recipients: unknown } }).definition.recipients).toEqual({ email: ['ana@example.com', '@example.org'], sms: 'per_mission', call: 'per_mission' });
    const simulated = SimulateControlPolicyInput.parse(calls[1]?.body);
    expect(simulated.call.mission_id).toBe('ms_abc123');

    const refused: Array<[string, Record<string, unknown>]> = [
      ['stack_set_control_policy', { definition: { name: 'x', connections: { rules: [{ id: 'r', effect: 'review', recipients: 'per_mission', access: { connection_id: 'scon_mail' } }] } } }],
      ['stack_set_control_policy', { definition: { name: 'x', connections: { rules: [{ id: 'r', effect: 'allow', recipients: 'anyone', access: { connection_id: 'scon_mail' } }] } } }],
      ['stack_set_control_policy', { definition: { name: 'x', recipients: { email: 'anyone' } } }],
      ['stack_set_control_policy', { definition: { name: 'x', recipients: { sms: 'per-mission' } } }],
      ['stack_set_control_policy', { definition: { name: 'x', recipients: { call: ['per_mission'] } } }],
      ['stack_simulate_control_policy', { agent_id: AGENT, call: { action: 'email.send', mission_id: 'mis_abc' } }],
    ];
    for (const [name, args] of refused) {
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError, name + JSON.stringify(args)).toBe(true);
    }
    expect(calls).toHaveLength(2);

    const tools = new Map((await client.listTools()).tools.map((tool) => [tool.name, tool.description ?? '']));
    expect(tools.get('stack_set_control_policy')).toMatch(/set the rule's recipients to "per_mission" so each Mission names them/);
    expect(tools.get('stack_set_control_policy')).toMatch(/recipients_not_pinned/);
    expect(tools.get('stack_set_control_policy')).toMatch(/recipient_not_allowed/);
    expect(tools.get('stack_set_control_policy')).not.toMatch(/each list may instead/);
    expect(tools.get('stack_set_control_policy')).toMatch(/A delegated Passport carries the same Mission/);
    expect(tools.get('stack_set_control_policy')).toMatch(/recipients\.email, recipients\.sms and recipients\.call may also be "per_mission"/);
    expect(tools.get('stack_set_control_policy')).toMatch(/reply_to_message/);
    expect(tools.get('stack_set_control_policy')).toMatch(/each a list, or "per_mission"/);
    expect(tools.get('stack_simulate_control_policy')).toMatch(/Nothing is counted, held or sent/);
  });

  it('hands the control_policy notice of a grant through whole, and says in the grant tool what it means', async () => {
    const notice = {
      policy_id: 'cpl_1', policy_revision: 3, source: 'agent', agent_id: AGENT, connection_id: 'scon_late',
      action_needed: 'list_connection', revision_needed: 4, message: 'The grant is made, but this agent cannot call the connection until a revision lists it.',
    };
    const { client, calls } = await connect(() => json({ id: 'grant_1', control_policy: notice }, 201));
    const result = await client.callTool({ name: 'stack_grant_agent_access', arguments: { agent_id: AGENT, service_connection_id: 'scon_late', scopes: ['read'] } });
    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual(['POST http://api.test/v1/services/grant']);
    expect(JSON.parse(textOf(result))).toEqual({ id: 'grant_1', control_policy: notice });
    const tools = new Map((await client.listTools()).tools.map((tool) => [tool.name, tool.description ?? '']));
    expect(tools.get('stack_grant_agent_access')).toMatch(/not callable until a revision of that policy lists it/);
    expect(tools.get('stack_grant_agent_access')).toMatch(/connection_not_listed/);
    expect(tools.get('stack_grant_agent_access')).toMatch(/loosening they approve in their browser/);
  });

  it('refuses a malformed input before any call is made', async () => {
    const { client, calls } = await connect();
    const bad: Array<[string, Record<string, unknown>]> = [
      ['stack_get_control_policy', { agent_id: 'not-an-agent' }],
      ['stack_set_control_policy', { definition: { name: 'x', actions: { kinds: { 'email.send': 'maybe' } } } }],
      ['stack_set_control_policy', { definition: { name: 'x', unknown_section: {} } }],
      ['stack_delete_control_policy', { agent_id: AGENT, expected_revision: -1 }],
      ['stack_policy_start_from_current_access', {}],
      ['stack_simulate_control_policy', { agent_id: AGENT, call: { action: 'not.an.action' } }],
      ['stack_list_control_reviews', { status: 'decided' }],
      ['stack_get_control_review', { review_id: '../control-policies/default' }],
      ['stack_get_control_review', { review_id: 'cpl_abc' }],
      ['stack_list_control_policy_revisions', { policy_id: 'crv_abc' }],
      ['stack_list_control_policy_revisions', { policy_id: 'cpl_a/../b' }],
    ];
    for (const [name, args] of bad) {
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError, name).toBe(true);
    }
    expect(calls).toHaveLength(0);
  });

  it('surfaces the approval link once and never asks the chat to approve a loosening or a deletion', async () => {
    for (const [name, args] of [
      ['stack_set_control_policy', { agent_id: AGENT, definition: DEFINITION, expected_revision: 1 }],
      ['stack_delete_control_policy', { agent_id: AGENT, expected_revision: 1 }],
      ['stack_policy_start_from_current_access', { agent_id: AGENT }],
    ] as const) {
      const { client, calls } = await connect(approvalRequired);
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError, name).toBe(true);
      const text = textOf(result);
      expect(text, name).toContain('GOVERNANCE_APPROVAL_REQUIRED');
      expect(text, name).toContain(APPROVAL_URL);
      expect(text, name).toContain('gvr_1');
      // No chat session: the call is made once and the link comes back.
      expect(calls, name).toHaveLength(1);
    }
  });

  it('passes an API refusal on as the tool error', async () => {
    const { client } = await connect(() => json({
      error: { code: 'UNBOUNDED_SEND_RULE', message: 'Rule send-any allows a send that does not name who receives it.', details: { rules: [] } },
    }, 400));
    const result = await client.callTool({ name: 'stack_set_control_policy', arguments: { definition: DEFINITION } });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('does not name who receives it');
  });

  it('states in the descriptions that policies only narrow and that loosening and deleting need a browser', async () => {
    const { client } = await connect();
    const tools = new Map((await client.listTools()).tools.map((tool) => [tool.name, tool.description ?? '']));
    for (const name of POLICY_TOOLS) expect(tools.has(name), name).toBe(true);
    for (const name of ['stack_list_control_policies', 'stack_set_control_policy']) {
      expect(tools.get(name), name).toMatch(/only narrows/);
    }
    for (const name of [
      'stack_set_control_policy',
      'stack_delete_control_policy',
      'stack_policy_start_from_current_access',
    ]) {
      expect(tools.get(name), name).toMatch(/Tightening applies at once/);
      expect(tools.get(name), name).toMatch(/approve it in their browser, never in the chat/);
      expect(tools.get(name), name).toMatch(/never waits or loops/);
      expect(tools.get(name), name).toMatch(/approval_url/);
    }
    expect(tools.get('stack_set_control_policy')).toMatch(/UNBOUNDED_SEND_RULE/);
    expect(tools.get('stack_set_control_policy')).toMatch(/CONTROLS_NOT_ENABLED/);
    expect(tools.get('stack_simulate_control_policy')).toMatch(/never a value the call carried/);
    expect(tools.get('stack_simulate_control_policy')).toMatch(/Nothing is counted, held or sent/);
    expect(tools.get('stack_list_control_reviews')).toMatch(/no tool to approve or reject it/);
    expect(tools.get('stack_get_control_review')).toMatch(/no tool to approve or reject it/);
  });

  it('calls only routes the API registers, with the verb the route uses', () => {
    const routes = readFileSync(new URL('../../../apps/api/src/routes/control-policies.ts', import.meta.url), 'utf8');
    const registered = new Set([...routes.matchAll(/app\.(get|put|delete|post)\('([^']+)'/g)].map((m) => `${m[1]!.toUpperCase()} ${m[2]}`));
    const source = readFileSync(new URL('./tools/control-policies.ts', import.meta.url), 'utf8');
    const used = new Set<string>();
    for (const m of source.matchAll(/api\(\s*'(GET|PUT|DELETE|POST)',\s*(`[^`]*`|'[^']*')/g)) {
      const path = m[2]!
        .slice(1, -1)
        .replace(/\$\{encodeURIComponent\((agent_id|agentId)\)\}/g, ':agentId')
        .replace(/\$\{encodeURIComponent\([^)]*\)\}/g, ':id')
        .replace(/\$\{query\}$/, '');
      used.add(`${m[1]} ${path}`);
    }
    expect([...used].sort()).toEqual([
      'DELETE /v1/control-policies/agents/:agentId',
      'DELETE /v1/control-policies/default',
      'GET /v1/control-policies',
      'GET /v1/control-policies/:id/revisions',
      'GET /v1/control-policies/agents/:agentId',
      'GET /v1/control-policies/default',
      'GET /v1/control-reviews',
      'GET /v1/control-reviews/:id',
      'POST /v1/control-policies/agents/:agentId/start-from-current-access',
      'POST /v1/control-policies/simulate',
      'PUT /v1/control-policies/agents/:agentId',
      'PUT /v1/control-policies/default',
    ]);
    for (const entry of used) expect(registered.has(entry), entry).toBe(true);
  });
});
