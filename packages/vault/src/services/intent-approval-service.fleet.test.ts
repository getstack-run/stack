import { describe, expect, it, vi } from 'vitest';
import { fleetDigest, type IntentClaim } from '@stack/shared';
import { IntentApprovalService } from './intent-approval-service.js';

function fixture() {
  let row: Record<string, any> | undefined;
  let plaintext = '';
  const request = { producer: 'proxy', target_id: 'slack', connection_id: 'scon_one', action: 'POST', request: { body: { channel: 'C123', text: 'private support update' } } };
  const input = { operatorId: 'op_one', agentId: 'agt_one', passportJti: 'pp_one', intentClaimId: 'clm_one',
    policyId: 'flp_one', policyRevision: 2, missionId: 'ms_one', requestHash: fleetDigest(request), reviewKey: fleetDigest('review'),
    expiresAt: new Date(Date.now() + 60000), exactRequest: request };
  const claim = { operator_id: 'op_one', body_json: { agent_id: 'agt_one', policy_decision: {
    origin: 'fleet_policy', policy_id: input.policyId, policy_revision: input.policyRevision, mission_id: input.missionId, request_hash: input.requestHash, effect: 'review',
  } } };
  const kms = { encrypt: vi.fn(async (value: string, _context: unknown) => { plaintext = value; return { ciphertext: 'encrypted-envelope', keyRef: 'key-ref' }; }),
    decrypt: vi.fn(async (_cipher: string, _context: unknown) => plaintext) };
  const repo = { insertFleetReview: vi.fn(async (value: Record<string, any>) => { row = value; return { row, created: true }; }),
    findById: vi.fn(async () => row), markDecided: vi.fn(async () => ({ ...row, decided_at: new Date() })) };
  const service = new IntentApprovalService({ repo, kms, claimRegistry: { getClaim: vi.fn(async () => claim) } } as never);
  return { service, input, request, kms, repo, claim, row: () => row!, mutateEnvelope: (change: (value: any) => void) => { const parsed = JSON.parse(plaintext); change(parsed); plaintext = JSON.stringify(parsed); } };
}
describe('fleet exception review custody', () => {
  it('stores only encrypted exact request and returns it only after identity and signed digest checks', async () => {
    const f = fixture(); const row = await f.service.submitFleetReview(f.input);
    expect(JSON.stringify(f.row())).not.toContain('private support update');
    expect(f.kms.encrypt).toHaveBeenCalledWith(expect.any(String), { operator_id: 'op_one', store: 'fleet_review', review_key: f.input.reviewKey });
    expect(await f.service.readFleetReview('op_one', row.id)).toEqual(f.request);
  });
  it('hides another tenant before decrypting', async () => {
    const f = fixture(); const row = await f.service.submitFleetReview(f.input);
    await expect(f.service.readFleetReview('op_other', row.id)).rejects.toThrow();
    expect(f.kms.decrypt).not.toHaveBeenCalled();
  });
  it.each(['agent_id', 'policy_id', 'policy_revision', 'mission_id', 'request_hash', 'review_key'])('rejects swapped %s metadata', async field => {
    const f = fixture(); const row = await f.service.submitFleetReview(f.input);
    f.mutateEnvelope(value => { value[field] = 'different'; });
    await expect(f.service.readFleetReview('op_one', row.id)).rejects.toThrow();
  });
  it('rejects modified content and signed claim disagreement before approval', async () => {
    const f = fixture(); const row = await f.service.submitFleetReview(f.input);
    f.mutateEnvelope(value => { value.request.request.body.channel = 'C999'; });
    await expect(f.service.approve({ id: row.id, operatorId: 'op_one' })).rejects.toThrow();
    expect(f.repo.markDecided).not.toHaveBeenCalled();
    const g = fixture(); const other = await g.service.submitFleetReview(g.input);
    g.claim.body_json.policy_decision.policy_revision = 3;
    await expect(g.service.readFleetReview('op_one', other.id)).rejects.toThrow();
  });
  it('refuses caller-forged policy provenance before Passport verification', async () => {
    const f = fixture();
    await expect(f.service.submit({ passportToken: 'irrelevant', intent: f.claim.body_json as IntentClaim })).rejects.toThrow();
    expect(f.repo.insertFleetReview).not.toHaveBeenCalled();
  });
});
