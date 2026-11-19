import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { FleetMissionStartInput } from '@stack/shared';
import { createStackMcpServer } from './index.js';

afterEach(() => vi.unstubAllGlobals());

async function withClient(work: (client: Client) => Promise<void>) {
  const [left, right] = InMemoryTransport.createLinkedPair();
  const server = createStackMcpServer('http://api.fixture', 'fleet-session-fixture');
  const client = new Client({ name: 'fleet-contract', version: '1' });
  await server.connect(right); await client.connect(left);
  try { await work(client); } finally { await client.close(); await server.close(); }
}

describe('fleet MCP transport contract', () => {
  it('advertises fleet tools and no staff tools to a customer session', async () => {
    await withClient(async client => {
      const { tools } = await client.listTools();
      expect(tools.some(tool => tool.name.startsWith('stack_repo_'))).toBe(false);
      expect(tools.map(tool => tool.name)).toEqual(expect.arrayContaining(['stack_start_mission', 'stack_renew_mission', 'stack_enroll_fleet_agent']));
    });
  });

  it('starts and renews a Mission with the complete canonical request and stable session bearer', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ mission_id: 'ms_fixture', passport: { token: 'worker' } })));
    vi.stubGlobal('fetch', fetch);
    const request = { fleet_policy_id: 'flp_fixture', idempotency_key: 'job-key-123', intent_summary: 'Update support',
      requested_access: [{ connection_id: 'scon_slack', scopes: ['chat:write'],
        intents: [{ name: 'slack.post_to_channel', params: { channel: 'C123' } }], allow_data_from: ['github'] }],
      requested_operations: [{ producer: 'skill', target_id: 'skl_support', action: 'invoke' }],
      limits: { max_actions: 20, max_concurrent_actions: 2, max_duration_seconds: 900 },
      expected_output_shape: { type: 'object' }, authority_binding_ids: ['abn_fixture'] };
    await withClient(async client => {
      expect((await client.callTool({ name: 'stack_start_mission', arguments: { request } })).isError).not.toBe(true);
      await client.callTool({ name: 'stack_renew_mission', arguments: { mission_id: 'ms_fixture' } });
    });
    const calls = fetch.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls[0]![0]).toBe('http://api.fixture/v1/missions/start');
    expect(JSON.parse(calls[0]![1].body as string)).toEqual(FleetMissionStartInput.parse(request));
    expect(calls[0]![1].headers).toMatchObject({ Authorization: 'Bearer fleet-session-fixture' });
    expect(calls[1]![0]).toBe('http://api.fixture/v1/missions/ms_fixture/renew');
    expect(JSON.parse(calls[1]![1].body as string)).toEqual({});
  });

  it('forwards Mission binding in ordinary Passport issuance', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ token: 'worker' })));
    vi.stubGlobal('fetch', fetch);
    await withClient(async client => {
      await client.callTool({ name: 'stack_issue_passport', arguments: { agent_id: 'agt_fixture', mission_ids: ['ms_fixture'] } });
    });
    const calls = fetch.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(JSON.parse(calls[0]![1].body as string).mission_ids).toEqual(['ms_fixture']);
  });

  it('opens a fleet Mission separately and preserves exact child scope objects', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ token: 'worker' })));
    vi.stubGlobal('fetch', fetch);
    const scopes = [{ service_connection_id: 'scon_slack', scopes: ['chat:write'], allow_data_from: [],
      intents: [{ name: 'slack.post_to_channel', params: { channel: 'C123' } }] }];
    await withClient(async client => {
      const open = await client.callTool({ name: 'stack_open_mission', arguments: { fleet_policy_id: 'flp_fixture',
        idempotency_key: 'job-12345', intent_summary: 'work', requested_access: [{ connection_id: 'scon_slack', scopes: ['chat:write'] }],
        limits: { max_actions: 20, max_concurrent_actions: 2, max_duration_seconds: 900 } } });
      expect(open.isError).not.toBe(true);
      const delegated = await client.callTool({ name: 'stack_delegate_passport', arguments: {
        parent_passport_token: 'fixture-parent', child_agent_id: 'agt_child', scopes } });
      expect(delegated.isError).not.toBe(true);
    });
    const calls = fetch.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls[0]![0]).toBe('http://api.fixture/v1/missions');
    expect(JSON.parse(calls[0]![1].body as string).fleet_policy_id).toBe('flp_fixture');
    expect(JSON.parse(calls[1]![1].body as string).scopes).toEqual(scopes);
  });

  it('keeps the exact approval link and id in a governance-required error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'GOVERNANCE_APPROVAL_REQUIRED',
      message: 'Approval required', details: { approval_id: 'gvr_fixture', approval_url: 'https://getstack.run/app/approve/gvr_fixture' } } }), { status: 403 })));
    await withClient(async client => {
      const result = await client.callTool({ name: 'stack_list_fleets', arguments: {} });
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result.content)).toContain('gvr_fixture');
      expect(JSON.stringify(result.content)).toContain('https://getstack.run/app/approve/gvr_fixture');
    });
  });
});
