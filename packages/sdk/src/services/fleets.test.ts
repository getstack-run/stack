import { describe, expect, it, vi } from 'vitest';
import { FleetsService, type FleetPolicyInput, type FleetMissionStartInput } from './fleets.js';
import { MissionsService } from './missions.js';
import { PassportService } from './passports.js';

describe('fleet client wire contract', () => {
  it('preserves exact Mission access, operations, limits and idempotency through start and renewal', async () => {
    const post = vi.fn(async () => ({ mission_id: 'ms_fixture', passport: { token: 'worker' } }));
    const service = new MissionsService({ post } as never);
    const input: FleetMissionStartInput = { fleet_policy_id: 'flp_fixture', idempotency_key: 'idem-0001',
      intent_summary: 'Support update', requested_access: [{ connection_id: 'scon_slack', scopes: ['chat:write'],
        intents: [{ name: 'slack.post_to_channel', params: { channel: 'C123' } }], allow_data_from: ['github'] }],
      requested_operations: [{ producer: 'skill', target_id: 'skl_support', action: 'invoke', constraints: [] }],
      limits: { max_actions: 20, max_concurrent_actions: 2, max_duration_seconds: 900 },
      authority_binding_ids: ['abn_fixture'], expected_output_shape: { type: 'object' } };
    await service.start(input); await service.renew('ms_one/two');
    expect(post).toHaveBeenNthCalledWith(1, '/v1/missions/start', input);
    expect(post).toHaveBeenNthCalledWith(2, '/v1/missions/ms_one%2Ftwo/renew', {});
  });

  it('preserves approval and concurrency preconditions across policy revisions', async () => {
    const post = vi.fn(async () => ({})); const put = vi.fn(async () => ({}));
    const service = new FleetsService({ post, put } as never);
    const policy = { name: 'Policy', rules: [] } as unknown as FleetPolicyInput;
    await service.activate(policy, { idempotencyKey: 'create-123', governanceApprovalId: 'gvr_create' });
    await service.revise('flp_one/two', policy, { expectedRevision: 3, idempotencyKey: 'revise-123', governanceApprovalId: 'gvr_revise' });
    expect(post).toHaveBeenCalledWith('/v1/fleets', policy, { headers: { 'Idempotency-Key': 'create-123', 'X-Governance-Approval': 'gvr_create' } });
    expect(put).toHaveBeenCalledWith('/v1/fleets/flp_one%2Ftwo', policy, { headers: {
      'If-Match': '3', 'Idempotency-Key': 'revise-123', 'X-Governance-Approval': 'gvr_revise' } });
  });

  it('forwards mission_ids on ordinary Passport issuance and creates an agent session without a body identity', async () => {
    const post = vi.fn(async () => ({}));
    await new PassportService({ post } as never).issue({ agent_id: 'agt_fixture', mission_ids: ['ms_fixture'] });
    await new FleetsService({ post } as never).session();
    await new FleetsService({ post } as never).session('flp_provisioner');
    expect(post).toHaveBeenNthCalledWith(1, '/v1/passports/issue', { agent_id: 'agt_fixture', mission_ids: ['ms_fixture'] });
    expect(post).toHaveBeenNthCalledWith(2, '/v1/fleets/session', {});
    expect(post).toHaveBeenNthCalledWith(3, '/v1/fleets/session', { fleet_policy_id: 'flp_provisioner' });
  });

  it('translates the public delegate helper to the canonical API token field and scoped objects', async () => {
    const post = vi.fn(async () => ({}));
    const scopes = [{ service_connection_id: 'scon_slack', scopes: ['chat:write'], constraints: [{ path: 'body.channel', op: 'eq', value: 'C123' }] }];
    await new PassportService({ post } as never).delegate({ parent_token: 'fixture', child_agent_id: 'agt_child', scopes });
    expect(post).toHaveBeenCalledWith('/v1/passports/delegate', { parent_passport_token: 'fixture', child_agent_id: 'agt_child', scopes });
  });
});
