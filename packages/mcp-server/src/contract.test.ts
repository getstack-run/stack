import { describe, it, expect, vi, afterEach } from 'vitest';
import { z } from 'zod';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { RegisterAgentInput, GrantAgentAccessInput, IssuePassportInput, IssuePassportInputObject, MissionLimitBehaviorInput, MissionRecipientList, MissionRecipientPins, MissionReviewInput, ProxyRequestInput, DelegatePassportInput, OperatorTier, SetMissionMakingAllowanceInput } from '@stack/shared';
import { createStackMcpServer } from './index.js';
import { captureOutboundBody, captureOutboundRequest } from './contract.test-support.js';

/**
 * 244 — cross-surface (MCP↔API) contract test.
 *
 * The through-line across/243/244 was that the SDK, MCP, and API
 * surfaces disagreed about field names — e.g. the SDK typed a grant's
 * connection as `connection_id` while the API (and MCP) call it
 * `service_connection_id`, so the SDK grant 400'd. This test catches that
 * class MECHANICALLY at the MCP↔API boundary by asserting the actual WIRE
 * BODY an MCP tool POSTs contains only fields the API's canonical Zod input
 * schema accepts.
 *
 * It tests the wire body (post-handler), NOT the tool's input params — so a
 * tool that exposes ergonomic flat params and correctly MAPS them into the
 * nested API shape (like stack_issue_passport) passes, while a tool that
 * puts a renamed/bogus field on the wire (which the API silently drops or
 * 400s) fails.
 */

// MCP tool → { API schema it POSTs to, a minimal valid tool input }.
const CONTRACTS: Array<{
  tool: string;
  schema: z.ZodObject<z.ZodRawShape>;
  input: Record<string, unknown>;
}> = [
  {
    tool: 'stack_register_agent',
    schema: RegisterAgentInput as unknown as z.ZodObject<z.ZodRawShape>,
    input: { name: 'contract-bot', profile: 'proxied-llm-bot' },
  },
  {
    tool: 'stack_grant_agent_access',
    schema: GrantAgentAccessInput as unknown as z.ZodObject<z.ZodRawShape>,
    input: { agent_id: 'agt_x', service_connection_id: 'scon_x', scopes: ['messages'] },
  },
  {
    tool: 'stack_issue_passport',
    schema: IssuePassportInputObject as unknown as z.ZodObject<z.ZodRawShape>,
    // Flat convenience params — the handler must MAP these into the nested
    // `intent` / `checkpoint_interval_seconds` shape the API expects.
    input: {
      agent_id: 'agt_x',
      mission_ids: ['ms_x'],
      intent_summary: 'do a thing',
      intent_services: ['openrouter'],
      checkpoint_interval: '5m',
      authority_binding_ids: ['abn_x'],
    },
  },
  {
    tool: 'stack_partner_issue_account_passport',
    schema: IssuePassportInputObject as unknown as z.ZodObject<z.ZodRawShape>,
    input: {
      account_id: 'op_account',
      agent_id: 'agt_x',
      mission_ids: ['ms_x'],
      ttl_seconds: 900,
      intent: { summary: 'stamp outbound mail', services: ['agentmail'] },
    },
  },
  {
    tool: 'stack_start_mission',
    // Operator form of POST /v1/missions/start (OperatorMissionStartInput).
    schema: z.object({ agent_id: z.string(), mission: z.unknown(), passport: z.unknown() }),
    input: {
      agent_id: 'agt_x',
      mission: { intent_summary: 'triage inbox', intent_services: ['slack'] },
      passport: { ttl_seconds: 600 },
    },
  },
  {
    tool: 'stack_open_mission',
    schema: z.object({ intent_summary: z.string(), intent_services: z.unknown(), agent_id: z.string() }),
    input: { intent_summary: 'triage inbox', intent_services: ['slack'], agent_id: 'agt_x' },
  },
  {
    tool: 'stack_open_mission',
    schema: z.object({ intent_summary: z.string(), coverage_cap_cents: z.number(), ...MissionLimitBehaviorInput, making_orders_up_to_cents: z.number() }),
    input: {
      intent_summary: 'print run', coverage_cap_cents: 500, coverage_cap_period: 'day', cap_time_zone: 'Europe/Stockholm',
      cap_behavior: { coverage_cap_cents: 'end_mission', max_actions: 'refuse_action' }, making_orders_up_to_cents: 2_000,
    },
  },
  {
    tool: 'stack_review_paused_mission',
    schema: MissionReviewInput.innerType() as unknown as z.ZodObject<z.ZodRawShape>,
    input: { mission_id: 'ms_x', decision: 'raise', limit: 10 },
  },
  {
    tool: 'stack_proxy_request',
    schema: ProxyRequestInput as unknown as z.ZodObject<z.ZodRawShape>,
    input: {
      service: 'openrouter',
      url: 'https://api.openrouter.ai/api/v1/chat/completions',
      method: 'POST',
      body: { model: 'x' },
      passport_token: 'tok', // header, not body
      authority_request_id: 'authority_request_abc123', // header, not body
    },
  },
  {
    tool: 'stack_delegate_passport',
    schema: DelegatePassportInput as unknown as z.ZodObject<z.ZodRawShape>,
    input: { parent_passport_token: 'jwt', child_agent_id: 'agt_x', scopes: [{ service_connection_id: 'scon_openrouter', scopes: ['chat:write'] }], ttl_seconds: 900 },
  },
  {
    tool: 'stack_deposit',
    schema: z.object({
      agent_id: z.string(),
      payload: z.record(z.unknown()),
      passport_jti: z.string().optional(),
      mission_id: z.string().optional(),
    }),
    input: {
      dropoff_id: 'dof_x',
      agent_id: 'agt_x',
      payload: { value: 1 },
      passport_jti: 'pas_x',
      mission_id: 'ms_x',
    },
  },
];

describe('MCP↔API wire-body field contract', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('every core mutating tool POSTs only fields the API schema accepts', async () => {
    const violations: string[] = [];
    for (const { tool, schema, input } of CONTRACTS) {
      const body = await captureOutboundBody(tool, input);
      const apiFields = new Set(Object.keys(schema.shape));
      for (const field of Object.keys(body)) {
        if (!apiFields.has(field)) {
          violations.push(
            `${tool} POSTs "${field}" but the API schema has no such field ` +
              `(accepts: [${[...apiFields].join(', ')}]). SDK/MCP↔API drift — silently dropped or 400s.`,
          );
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  it('stack_set_mission_making_allowance PUTs a body the API schema accepts, null included', async () => {
    const sent: Array<{ method: string | undefined; url: string; body: unknown }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: { method?: string; body?: string }) => {
        sent.push({ method: init.method, url, body: init.body ? JSON.parse(init.body) : undefined });
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      }),
    );
    const server = createStackMcpServer('http://localhost:0', 'sk_test_unused');
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'contract-test', version: '0.0.0' });
    await Promise.all([server.connect(st), client.connect(ct)]);
    await client.callTool({ name: 'stack_set_mission_making_allowance', arguments: { mission_id: 'ms_x', making_orders_up_to_cents: 2_000 } });
    await client.callTool({ name: 'stack_set_mission_making_allowance', arguments: { mission_id: 'ms_x', making_orders_up_to_cents: null } });
    await client.close();

    expect(sent.map((call) => [call.method, new URL(call.url).pathname])).toEqual([
      ['PUT', '/v1/missions/ms_x/making-allowance'],
      ['PUT', '/v1/missions/ms_x/making-allowance'],
    ]);
    expect(sent.map((call) => SetMissionMakingAllowanceInput.safeParse(call.body).success)).toEqual([true, true]);
    expect(sent.map((call) => call.body)).toEqual([{ making_orders_up_to_cents: 2_000 }, { making_orders_up_to_cents: null }]);
  });

  it('stack_issue_passport maps its flat params into the nested `intent` shape', async () => {
    const body = await captureOutboundBody('stack_issue_passport', {
      agent_id: 'agt_x',
      mission_ids: ['ms_x'],
      intent_summary: 'do a thing',
      intent_services: ['openrouter'],
      authority_binding_ids: ['abn_x'],
    });
    // The refined API schema (exactly one Mission) accepts the wire body.
    expect(IssuePassportInput.safeParse(body).success).toBe(true);
    expect(body.mission_ids).toEqual(['ms_x']);
    // Must send nested `intent`, NOT flat intent_summary/intent_services.
    expect(body).toHaveProperty('intent');
    expect((body.intent as Record<string, unknown>).summary).toBe('do a thing');
    expect((body.intent as Record<string, unknown>).services).toEqual(['openrouter']);
    expect(body).not.toHaveProperty('intent_summary');
    expect(body).not.toHaveProperty('intent_services');
    expect(body.authority_binding_ids).toEqual(['abn_x']);
  });

  it('Passport issue tools refuse anything but exactly one Mission before calling the API', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const server = createStackMcpServer('http://localhost:0', 'sk_test_unused');
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'contract-test', version: '0.0.0' });
    await Promise.all([server.connect(st), client.connect(ct)]);
    const attempts: Array<{ name: string; arguments: Record<string, unknown> }> = [
      { name: 'stack_issue_passport', arguments: { agent_id: 'agt_x' } },
      { name: 'stack_issue_passport', arguments: { agent_id: 'agt_x', mission_ids: [] } },
      { name: 'stack_issue_passport', arguments: { agent_id: 'agt_x', mission_ids: ['ms_a', 'ms_b'] } },
      { name: 'stack_issue_passport', arguments: { agent_id: 'agt_x', mission_ids: ['not_a_mission'] } },
      { name: 'stack_partner_issue_account_passport', arguments: { account_id: 'op_t', agent_id: 'agt_x' } },
      { name: 'stack_partner_issue_account_passport', arguments: { account_id: 'op_t', agent_id: 'agt_x', mission_ids: ['ms_a', 'ms_b'] } },
    ];
    for (const attempt of attempts) {
      const result = await client.callTool(attempt);
      expect(result.isError, JSON.stringify(attempt)).toBe(true);
    }
    expect(fetchMock).not.toHaveBeenCalled();
    await client.close();
  });

  it('partner account issue POSTs a body the refined API schema accepts', async () => {
    const body = await captureOutboundBody('stack_partner_issue_account_passport', {
      account_id: 'op_account',
      agent_id: 'agt_x',
      mission_ids: ['ms_x'],
      intent: { summary: 'stamp outbound mail', services: ['agentmail'] },
    });
    expect(body).not.toHaveProperty('account_id');
    expect(IssuePassportInput.safeParse(body).success).toBe(true);
  });

  it('stack_start_mission operator form POSTs agent_id + mission + passport to /v1/missions/start', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 201, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const server = createStackMcpServer('http://api.fixture', 'sk_test_unused');
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'contract-test', version: '0.0.0' });
    await Promise.all([server.connect(st), client.connect(ct)]);
    const ok = await client.callTool({ name: 'stack_start_mission', arguments: {
      agent_id: 'agt_x', mission: { intent_summary: 'triage inbox', intent_services: ['slack'], expires_in_seconds: 1800 },
      passport: { ttl_seconds: 600 } } });
    expect(ok.isError).not.toBe(true);
    const bare = await client.callTool({ name: 'stack_start_mission', arguments: {
      agent_id: 'agt_x', mission: { intent_summary: 'triage inbox' } } });
    expect(bare.isError).not.toBe(true);
    // Refused locally: no form, half a form, both forms, Mission-binding fields in passport.
    for (const args of [
      {},
      { agent_id: 'agt_x' },
      { mission: { intent_summary: 'x' } },
      { agent_id: 'agt_x', mission: { intent_summary: 'x' }, passport: { mission_ids: ['ms_x'] } },
      { agent_id: 'agt_x', mission: { intent_summary: 'x' }, passport: { intent: { summary: 'x', services: [], platform_intent: 'staff' } } },
      { agent_id: 'agt_x', mission: { intent_summary: 'x' }, request: { fleet_policy_id: 'flp_x', idempotency_key: 'job-key-123', intent_summary: 'x',
        requested_access: [{ connection_id: 'scon_x', scopes: ['a'] }], limits: { max_actions: 1, max_concurrent_actions: 1, max_duration_seconds: 60 } } },
    ]) {
      expect((await client.callTool({ name: 'stack_start_mission', arguments: args })).isError, JSON.stringify(args)).toBe(true);
    }
    await client.close();
    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls).toHaveLength(2);
    expect(calls[0]![0]).toBe('http://api.fixture/v1/missions/start');
    expect(JSON.parse(calls[0]![1].body as string)).toEqual({
      agent_id: 'agt_x',
      mission: { intent_summary: 'triage inbox', intent_services: ['slack'], expires_in_seconds: 1800 },
      passport: { ttl_seconds: 600 },
    });
    expect(JSON.parse(calls[1]![1].body as string)).toEqual({ agent_id: 'agt_x', mission: { intent_summary: 'triage inbox' } });
  });

  it('a Mission names who it may send to when it opens or starts, and refuses a malformed pin before any call', async () => {
    const recipients = ['ana@example.com', '+442071838750'];
    const recipient_pins = [{ path: 'body.to', op: 'in', value: ['ana@example.com'] }, { path: 'url.pathname', op: 'eq', value: '/v1/chats/42' }];
    const opened = await captureOutboundBody('stack_open_mission', {
      intent_summary: 'reply to a customer', agent_id: 'agt_x', recipients, recipient_pins, reply_to_message: 'amsg_abc123',
    });
    expect(opened).toMatchObject({ recipients, recipient_pins, reply_to_message: 'amsg_abc123' });
    // A recipient named twice is kept once, not refused.
    const twice = await captureOutboundBody('stack_open_mission', { intent_summary: 'x', recipients: ['ana@example.com', 'ANA@example.com'] });
    expect(twice['recipients']).toEqual(['ana@example.com']);
    expect(MissionRecipientList.safeParse(opened.recipients).success).toBe(true);
    expect(MissionRecipientPins.safeParse(opened.recipient_pins).success).toBe(true);

    const fetchMock = vi.fn(async () => new Response('{}', { status: 201, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const server = createStackMcpServer('http://api.fixture', 'sk_test_unused');
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'contract-test', version: '0.0.0' });
    await Promise.all([server.connect(st), client.connect(ct)]);
    const started = await client.callTool({ name: 'stack_start_mission', arguments: {
      agent_id: 'agt_x', mission: { intent_summary: 'reply to a customer', reply_to_message: 'amsg_abc123' } } });
    expect(started.isError).not.toBe(true);
    for (const bad of [
      { recipients: [] },
      { recipient_pins: [] },
      { recipient_pins: [{ path: 'body.to', op: 'in', value: 'ana@example.com' }] },
      { recipient_pins: [{ path: 'body.to', op: 'eq', value: ['ana@example.com'] }] },
      { recipient_pins: [{ path: 'body.to', op: 'eq', value: 'a@example.com' }, { path: 'body.to', op: 'eq', value: 'b@example.com' }] },
      { recipient_pins: [{ path: 'not a path!', op: 'eq', value: 'a@example.com' }] },
      { reply_to_message: '' },
    ]) {
      for (const name of ['stack_open_mission', 'stack_start_mission']) {
        const args = name === 'stack_open_mission'
          ? { intent_summary: 'x', ...bad }
          : { agent_id: 'agt_x', mission: { intent_summary: 'x', ...bad } };
        expect((await client.callTool({ name, arguments: args })).isError, `${name} ${JSON.stringify(bad)}`).toBe(true);
      }
    }
    await client.close();
    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0]![1].body as string)).toEqual({
      agent_id: 'agt_x', mission: { intent_summary: 'reply to a customer', reply_to_message: 'amsg_abc123' },
    });
  });

  it('the Mission tool descriptions say who a Mission may send to', async () => {
    const server = createStackMcpServer('http://api.fixture', 'sk_test_unused');
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'contract-test', version: '0.0.0' });
    await Promise.all([server.connect(st), client.connect(ct)]);
    const tools = new Map((await client.listTools()).tools.map((tool) => [tool.name, tool]));
    const open = tools.get('stack_open_mission')!;
    expect(open.description).toMatch(/recipients, recipient_pins and reply_to_message/);
    const props = (open.inputSchema as { properties: Record<string, { description?: string }> }).properties;
    expect(props.recipients?.description).toMatch(/^Who this Mission may send to \(exact addresses, numbers or ids\), applied at every recipient field a send names, a recipient inside the URL included/);
    expect(props.recipients?.description).toMatch(/The owner can add more to a running Mission./);
    expect(props.reply_to_message?.description).toMatch(/^The id of a message you received, or of an incoming call you answered or declined \(acall_\*\)\./);
    expect(props.recipient_pins?.description).toMatch(/one pin per path/);
    expect(tools.get('stack_start_mission')!.description).toMatch(/recipients, recipient_pins or reply_to_message/);
    expect(tools.get('stack_get_mission')!.description).toMatch(/recipient_pins/);
    await client.close();
  });

  it('adds recipients to a running Mission through its route, with only the fields given', async () => {
    const body = await captureOutboundBody('stack_add_mission_recipients', { mission_id: 'ms_abc', recipients: ['ana@example.com'] });
    expect(body).toEqual({ recipients: ['ana@example.com'] });
    const urls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      urls.push(url);
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }));
    const server = createStackMcpServer('http://api.fixture', 'sk_test_unused');
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'contract-test', version: '0.0.0' });
    await Promise.all([server.connect(st), client.connect(ct)]);
    await client.callTool({ name: 'stack_add_mission_recipients', arguments: { mission_id: 'ms_abc', reply_to_message: 'acall_1' } });
    const empty = await client.callTool({ name: 'stack_add_mission_recipients', arguments: { mission_id: 'ms_abc' } });
    await client.close();
    expect(urls).toEqual(['http://api.fixture/v1/missions/ms_abc/recipients']);
    expect(empty.isError).toBe(true);
  });

  it('threads proxy authority correlation only as a header', async () => {
    const request = await captureOutboundRequest('stack_proxy_request', {
      service: 'openrouter',
      url: 'https://openrouter.ai/api/v1/chat/completions',
      method: 'POST',
      passport_token: 'passport',
      authority_request_id: 'authority_request_abc123',
    });
    expect(request.headers['X-STACK-Authority-Request-Id']).toBe('authority_request_abc123');
    expect(request.body).not.toHaveProperty('authority_request_id');
  });

  it('requires callers to persist an operation id before non-GET proxy calls', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const server = createStackMcpServer('http://localhost:0', 'sk_test_unused');
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'contract-test', version: '0.0.0' });
    await Promise.all([server.connect(st), client.connect(ct)]);
    const result = await client.callTool({
      name: 'stack_proxy_request',
      arguments: {
        service: 'stripe',
        url: 'https://api.stripe.com/v1/refunds',
        method: 'POST',
        passport_token: 'passport',
      },
    });
    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
    await client.close();
  });

  it('allows GET proxy calls without an operation id', async () => {
    const request = await captureOutboundRequest('stack_proxy_request', {
      service: 'slack',
      url: 'https://slack.com/api/auth.test',
      method: 'GET',
      passport_token: 'passport',
    });
    expect(request.headers['X-STACK-Authority-Request-Id']).toBeUndefined();
  });

  it('reads proxy operation state with body identity and live Passport auth', async () => {
    const request = await captureOutboundRequest('stack_get_proxy_operation', {
      operation_id: 'authority_request_abc123',
      passport_token: 'passport',
      include_response: true,
    });
    expect(request.body).toEqual({
      operation_id: 'authority_request_abc123',
      include_response: true,
    });
    expect(request.headers['X-Passport-Token']).toBe('passport');
  });

  it('threads the drop-off Mission Passport only as X-Passport-Token', async () => {
    const calls: Array<[string, Record<string, unknown>]> = [
      ['stack_create_dropoff', { from_agent: 'agt_a', to_agent: 'agt_b', schema: { type: 'object' } }],
      ['stack_deposit', { dropoff_id: 'dof_x', agent_id: 'agt_a', payload: { value: 1 } }],
      ['stack_collect', { dropoff_id: 'dof_x', agent_id: 'agt_b' }],
    ];
    for (const [tool, input] of calls) {
      const request = await captureOutboundRequest(tool, { ...input, passport_token: 'passport' });
      expect(request.headers['X-Passport-Token'], tool).toBe('passport');
      expect(request.body, tool).not.toHaveProperty('passport_token');
    }
  });

 it('the grant tool POSTs service_connection_id (the exact drift)', async () => {
    const body = await captureOutboundBody('stack_grant_agent_access', {
      agent_id: 'agt_x',
      service_connection_id: 'scon_x',
      scopes: ['messages'],
    });
    expect(body).toHaveProperty('service_connection_id', 'scon_x');
    expect(body).not.toHaveProperty('connection_id');
  });

  describe('tool description claims that have drifted before', () => {
    async function descriptions(): Promise<Map<string, string>> {
      const server = createStackMcpServer('http://localhost:0', 'sk_test_unused');
      const [ct, st] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'contract-test', version: '0.0.0' });
      await Promise.all([server.connect(st), client.connect(ct)]);
      const { tools } = await client.listTools();
      await client.close();
      return new Map(tools.map((tool) => [tool.name, tool.description ?? '']));
    }

    it('name only plans that exist when they gate a tool on a plan', async () => {
      const plans: string[] = [...OperatorTier.options];
      const named: string[] = [];
      for (const [name, text] of await descriptions()) {
        for (const match of text.matchAll(/\b([A-Za-z]+) (?:plan|tier) or above/g)) {
          named.push(`${name}: ${match[1]}`);
          expect(plans, `${name} names the plan "${match[1]}"`).toContain(match[1]!.toLowerCase());
        }
      }
      // The retired plan names are gone. Detector settings are a controls feature with no tier check and no approval, and
      // every build (a self-managed install has every controls feature) can read the sentence as true.
      expect(named).toEqual([]);
      const all = await descriptions();
      for (const name of ['stack_upsert_detector_config', 'stack_reset_detector_config']) {
        expect(all.get(name), name).toMatch(/Detector settings are a controls feature: with controls on a (change|reset) applies at once, with no approval.*A self-managed install has every controls feature/);
        expect(all.get(name), name).not.toMatch(/\b(Pro|Developer|Business|Free)\b/);
      }
      expect(all.get('stack_add_delivery_method')).not.toMatch(/paid plan/);
    });

    it('name no identity vendor in the provider list, which an install may have none of', async () => {
      const text = (await descriptions()).get('stack_list_identity_providers')!;
      expect(text).not.toMatch(/Turnstile|Stripe/);
      expect(text).toMatch(/self-managed install lists none/);
    });

    it('say stack_scan keeps the verdict and snippets, never the content, and name no classifier vendor, model or gate', async () => {
      for (const profile of ['standard', 'directory'] as const) {
        const server = createStackMcpServer('http://localhost:0', 'sk_test_unused', { profile });
        const [ct, st] = InMemoryTransport.createLinkedPair();
        const client = new Client({ name: 'contract-test', version: '0.0.0' });
        await Promise.all([server.connect(st), client.connect(ct)]);
        const text = (await client.listTools()).tools.find((tool) => tool.name === 'stack_scan')?.description ?? '';
        await client.close();
        expect(text, profile).toMatch(/optional classifier layer/);
        expect(text, profile).toMatch(/keeps the verdict and snippets, never the scanned content/);
        // The audit row names the pattern and the field path (a key of a scanned object), so it is not said to hold no content.
        expect(text, profile).toMatch(/audit row that holds at most the matched pattern id and field path, never the scanned text/);
        expect(text, profile).not.toMatch(/audit row that holds no content/);
        expect(text, profile).not.toMatch(/OpenRouter|Haiku|60 characters|2,500|1,500|4,000/);
      }
    });

    it('say a checkpoint moves the stored monitoring deadline, not the signed Passport token', async () => {
      const text = (await descriptions()).get('stack_checkpoint')!;
      expect(text).not.toMatch(/extends the Passport expiry/i);
      expect(text).toMatch(/stored monitoring deadline/);
      expect(text).toMatch(/token's own expiry does not change/);
    });
  });

  it('threads a data-flow approval only as the governance header', async () => {
    const request = await captureOutboundRequest('stack_grant_agent_access', {
      agent_id: 'agt_x',
      service_connection_id: 'scon_x',
      scopes: ['messages'],
      allow_data_from: ['slack'],
      governance_approval_id: 'gvr_approved',
    });
    expect(request.headers['X-Governance-Approval']).toBe('gvr_approved');
    expect(request.body.allow_data_from).toEqual(['slack']);
    expect(request.body).not.toHaveProperty('governance_approval_id');
  });
});
