import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { cmdFleets } from './fleets.js';
import { cmdMissions } from './missions.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));
vi.mock('node:fs', async importOriginal => ({ ...await importOriginal<object>(), readFileSync: vi.fn(() => JSON.stringify({
  fleet_policy_id: 'flp_test', requested_access: [{ connection_id: 'scon_test', scopes: ['read'] }],
  idempotency_key: 'job-12345', limits: { max_actions: 20, max_concurrent_actions: 2, max_duration_seconds: 900 },
})) }));

beforeEach(() => vi.clearAllMocks());
describe('fleet CLI wire contract', () => {
  it('preserves the request file on mission start', async () => {
    await cmdMissions(['start', '--file', 'synthetic.json', '--json']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/missions/start', { body: {
      fleet_policy_id: 'flp_test', requested_access: [{ connection_id: 'scon_test', scopes: ['read'] }],
      idempotency_key: 'job-12345', limits: { max_actions: 20, max_concurrent_actions: 2, max_duration_seconds: 900 },
    } });
  });
  it('passes exact revision and approval headers', async () => {
    await cmdFleets(['revise', 'flp_test', '--file', 'synthetic.json', '--expected-revision', '2', '--idempotency-key', 'revise-123', '--governance-approval-id', 'gvr_test']);
    expect(api).toHaveBeenCalledWith('PUT', '/v1/fleets/flp_test', { body: expect.any(Object), headers: {
      'If-Match': '2', 'Idempotency-Key': 'revise-123', 'X-Governance-Approval': 'gvr_test',
    } });
  });
  it('renews existing Missions and requests sessions without changing identity or limits', async () => {
    await cmdMissions(['renew', 'ms_test']); await cmdFleets(['session']);
    await cmdFleets(['session', '--fleet-policy-id', 'flp_provisioner']);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', '/v1/missions/ms_test/renew', { body: {} });
    expect(api).toHaveBeenNthCalledWith(2, 'POST', '/v1/fleets/session', { body: {} });
    expect(api).toHaveBeenNthCalledWith(3, 'POST', '/v1/fleets/session', { body: { fleet_policy_id: 'flp_provisioner' } });
  });
});
