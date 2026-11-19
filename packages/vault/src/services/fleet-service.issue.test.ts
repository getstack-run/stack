import { describe, expect, it, vi } from 'vitest';
import { FleetService } from './fleet-service.js';
import type { IssuePassportInput } from '@stack/shared';

function fixture() {
  const live = { policy: { id: 'flp_one', revision: 1, root_agent_id: 'agt_root' }, member: { id: 'fmb_one' },
    mission: { intent_summary: 'Support' }, binding: { session_id: 'ses_one', authority_binding_ids: ['abn_worker'], access: [{
      access: { connection_id: 'scon_slack', scopes: ['chat:write'], intents: [], constraints: [], allow_data_from: [] },
      constraints: [{ path: 'body.channel', op: 'eq', value: 'C123' }],
    }] } };
  const connection = { status: 'active', proxy_enabled: true, allowed_hosts: ['slack.com'], scopes: ['chat:write'], provider: 'slack' };
  const issueFleetMission = vi.fn(async (..._args: unknown[]) => ({ token: 'signed', jti: 'pp_one' }));
  const repo = { membership: vi.fn(async () => ({ id: 'fmb_one' })), liveMission: vi.fn(async () => live),
    db: { select: () => ({ from: () => ({ where: async () => [connection] }) }) } };
  const service = new FleetService({ repo, passport: { issueFleetMission } } as never);
  const input: IssuePassportInput = { agent_id: 'agt_worker', mission_ids: ['ms_one'] };
  return { service, repo, issueFleetMission, input, live };
}
describe('separate fleet Mission Passport issue', () => {
  it('issues from sealed Mission authority and preserves session', async () => {
    const f = fixture(); await f.service.issueFromMission('op_one', f.input);
    expect(f.issueFleetMission).toHaveBeenCalledWith('op_one', expect.objectContaining({ agent_id: 'agt_root', authority_binding_ids: ['abn_worker'] }),
      expect.objectContaining({ child_agent_id: 'agt_worker', scopes: [{ service_connection_id: 'scon_slack', scopes: ['chat:write'], constraints: [{ path: 'body.channel', op: 'eq', value: 'C123' }], allow_data_from: [] }] }),
      { policy_id: 'flp_one', policy_revision: 1, membership_id: 'fmb_one', mission_id: 'ms_one' }, 'ses_one');
  });
  it('accepts narrower scopes and TTL without replacing the Mission ceiling', async () => {
    const f = fixture(); await f.service.issueFromMission('op_one', { ...f.input, scopes: [], ttl_seconds: 60 });
    expect(f.issueFleetMission.mock.calls[0]?.[1]).toMatchObject({ ttl_seconds: 60, scopes: [expect.objectContaining({ service_connection_id: 'scon_slack' })] });
    expect(f.issueFleetMission.mock.calls[0]?.[2]).toMatchObject({ ttl_seconds: 60, scopes: [] });
  });
  it('refuses missing/multiple Missions and identity, connection, scope or Authority expansion', async () => {
    const f = fixture();
    for (const patch of [{ mission_ids: [] }, { mission_ids: ['ms_one', 'ms_two'] }, { identity_claim_ids: [] },
      { authority_binding_ids: ['abn_foreign'] }, { scopes: [{ service_connection_id: 'scon_foreign', scopes: ['chat:write'] }] },
      { scopes: [{ service_connection_id: 'scon_slack', scopes: ['admin'] }] }]) {
      await expect(f.service.issueFromMission('op_one', { ...f.input, ...patch })).rejects.toThrow();
    }
    expect(f.issueFleetMission).not.toHaveBeenCalled();
  });
  it('rechecks live membership and Mission ownership rather than trusting the request', async () => {
    const f = fixture(); f.repo.liveMission.mockRejectedValue(new Error('Forbidden'));
    await expect(f.service.issueFromMission('op_one', f.input)).rejects.toThrow();
    expect(f.repo.liveMission).toHaveBeenCalledWith('op_one', 'ms_one', 'agt_worker');
    expect(f.issueFleetMission).not.toHaveBeenCalled();
  });
});
