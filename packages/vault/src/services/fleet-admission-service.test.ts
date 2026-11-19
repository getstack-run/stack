import { describe, expect, it, vi } from 'vitest';
import { FleetAccess, FleetPolicyInput, type IntentClaim, type NormalizedRequest } from '@stack/shared';
import { FleetAdmissionService, decideFleetRequest } from './fleet-admission-service.js';
import { ApprovalGateService } from './approval-gate-service.js';
import type { PassportJWTPayload } from './passport-service.js';

const limits = { max_actions: 20, max_concurrent_actions: 4, max_duration_seconds: 900 };
const access = FleetAccess.parse({ connection_id: 'scon_slack', scopes: ['chat:write'], intents: [{ name: 'slack.post_to_channel', params: { channel: 'C123' } }] });
const policy = FleetPolicyInput.parse({ name: 'Support', rules: [{ id: 'post', effect: 'allow', access }], limits,
  window_seconds: 3600, max_members: 100, max_enrollments_per_hour: 100, identity_lease_seconds: 3600,
  provisioner_agent_ids: ['agt_controller'], expires_at: '2030-01-01T00:00:00Z' });
const request: NormalizedRequest = { method: 'POST', url: { origin: 'https://slack.com', host: 'slack.com', pathname: '/api/chat.postMessage' }, body: { channel: 'C123', text: 'update' }, query: {}, headers: {} };
const binding = { policy_id: 'flp_test', policy_revision: 1, membership_id: 'fmb_test', mission_id: 'ms_test' };
const claims = { jti: 'pp_test', stk: { operator_id: 'op_test', agent_id: 'agt_test', accountability: 'enforced', session_id: 'ses_test', mission_ids: ['ms_test'], fleet: binding } } as PassportJWTPayload;
const intent = { type: 'intent_claim', intent_type: 'http_call', agent_id: 'agt_test', named_intent: 'slack.post_to_channel', target: 'slack', action: 'POST', parameters: {}, estimated_cost: { wallet_cents: null, tokens: null, gas_gwei: null }, accountability: 'enforced', reason: null, requires: [], user_subject: null, mission_ref: 'ms_test', submitted_at: Date.now() } as IntentClaim;
function fixture() {
  const live = { policy: { id: binding.policy_id, revision: 1, definition: structuredClone(policy) }, member: { id: binding.membership_id }, mission: { expires_at: new Date(Date.now() + 900000) }, binding: { session_id: 'ses_test', access: [{ access, rule_id: 'post', effect: 'allow', constraints: [{ path: 'body.channel', op: 'eq', value: 'C123' }] }], operations: [] } };
  const repo = { liveMission: vi.fn(async () => live), membership: vi.fn(async () => null), rootForAgent: vi.fn(async () => null), reserve: vi.fn(async () => ({ operation: { id: 'fop_test' }, replay: false })), dispatch: vi.fn(async (_o, _p, _id, cb) => { await cb({}); }), settle: vi.fn(async () => {}) };
  const registerClaim = vi.fn(async (_input: unknown) => ({ claimId: 'clm_test' }));
  const submitFleetReview = vi.fn(async (_input: { reviewKey: string }) => ({ id: 'ia_test', status: 'approved', expires_at: new Date(Date.now() + 60000) }));
  const approvalGate = { reserveForDispatch: vi.fn(async () => true), markConsumed: vi.fn(async () => true) };
  const service = new FleetAdmissionService({ repo, claimRegistry: { registerClaim }, intentApproval: { submitFleetReview }, approvalGate } as never);
  const input = { claims, producer: 'proxy' as const, operationKey: 'abcdefghijklmnopqrstuv', connectionId: 'scon_slack', action: 'POST', normalizedRequest: request, intent };
  return { live, repo, service, input, registerClaim, submitFleetReview, approvalGate };
}
describe('fleet runtime admission', () => {
  it('writes explicit signed policy evidence before reserving and dispatching', async () => {
    const f = fixture();
    const a = (await f.service.prepare(f.input))!;
    expect(f.repo.reserve).not.toHaveBeenCalled();
    expect(f.registerClaim.mock.calls[0]?.[0]).toMatchObject({ payload: { policy_decision: { origin: 'fleet_policy', effect: 'allow', mission_id: 'ms_test' } } });
    await f.service.dispatch(a, 0);
    expect(f.repo.reserve).toHaveBeenCalledWith(expect.objectContaining({ intentClaimId: 'clm_test', maxSpendCents: 0 }));
    expect(f.approvalGate.markConsumed).not.toHaveBeenCalled();
    await f.service.finish(a, 0);
    expect(f.repo.settle).toHaveBeenCalledWith('op_test', 'fop_test', 'settled', 0);
  });
  it('rejects a changed channel, foreign connection and stale policy before evidence', async () => {
    const f = fixture();
    await expect(f.service.prepare({ ...f.input, normalizedRequest: { ...request, body: { channel: 'C999' } } })).rejects.toThrow();
    await expect(f.service.prepare({ ...f.input, connectionId: 'scon_other' })).rejects.toThrow();
    f.live.policy.revision++;
    await expect(f.service.prepare(f.input)).rejects.toThrow();
    expect(f.registerClaim).not.toHaveBeenCalled();
  });
  it('checks overlapping deny and review rules against the actual request', async () => {
    const f = fixture();
    const review = { id: 'sensitive', effect: 'review' as const, access: { ...access, constraints: [{ path: 'body.text', op: 'eq' as const, value: 'update' }] } };
    f.live.policy.definition.rules.push(review);
    expect(decideFleetRequest(f.live as never, f.input)).toEqual({ effect: 'review', ruleId: 'sensitive' });
    f.live.policy.definition.rules.push({ ...review, id: 'deny', effect: 'deny' });
    await expect(f.service.prepare(f.input)).rejects.toThrow();
  });
  it.each(['skill', 'a2a', 'dropoff'] as const)('allows declared %s operations and rejects another target', async producer => {
    const f = fixture();
    const action: 'invoke' | 'tasks/send' | 'deposit' = producer === 'skill' ? 'invoke' : producer === 'a2a' ? 'tasks/send' : 'deposit';
    const operation = { producer, target_id: 'target_1', action, constraints: [] };
    f.live.policy.definition.operation_rules.push({ id: 'operation', effect: 'allow', access: operation });
    (f.live.binding.operations as unknown[]).push({ rule_id: 'operation', effect: 'allow', access: operation });
    expect(decideFleetRequest(f.live as never, { ...f.input, producer, targetId: 'target_1', action }).effect).toBe('allow');
    expect(() => decideFleetRequest(f.live as never, { ...f.input, producer, targetId: 'target_2', action })).toThrow();
  });
  it('deduplicates exact review identity across Passport renewal and consumes once inside dispatch', async () => {
    const f = fixture();
    f.live.policy.definition.rules[0]!.effect = 'review';
    const a = (await f.service.prepare(f.input))!;
    await f.service.prepare({ ...f.input, claims: { ...claims, jti: 'pp_renewed' } });
    expect(f.submitFleetReview.mock.calls[0]?.[0]).toMatchObject({ reviewKey: (f.submitFleetReview.mock.calls[1]?.[0] as any).reviewKey });
    expect(f.approvalGate.markConsumed).not.toHaveBeenCalled();
    await f.service.dispatch(a, 0);
    expect(f.approvalGate.reserveForDispatch).toHaveBeenCalledOnce();
    expect(f.approvalGate.markConsumed).toHaveBeenCalledOnce();
  });
  it.each([
    ['pending', { status: 'pending', expires_at: new Date(Date.now() + 60000) }, 'FLEET_REVIEW_PENDING'],
    ['rejected', { status: 'rejected', expires_at: new Date(Date.now() + 60000) }, 'FLEET_REVIEW_REJECTED'],
    ['expired', { status: 'expired', expires_at: new Date(Date.now() - 1000) }, 'FLEET_REVIEW_EXPIRED'],
    ['approved past its window', { status: 'approved', expires_at: new Date(Date.now() - 1000) }, 'FLEET_REVIEW_EXPIRED'],
    ['used', { status: 'consumed', expires_at: new Date(Date.now() + 60000) }, 'FLEET_REVIEW_USED'],
  ])('answers a review that is %s with a typed status, not a bare FORBIDDEN', async (_name, review, code) => {
    const f = fixture();
    f.live.policy.definition.rules[0]!.effect = 'review';
    f.submitFleetReview.mockResolvedValueOnce({ id: 'ia_held', ...review } as never);
    const refused = await f.service.prepare(f.input).then(() => null, (error: unknown) => error as { code: string; statusCode: number; details: unknown });
    expect(refused).toMatchObject({ code, statusCode: 403, details: { approval_id: 'ia_held', status: code.slice('FLEET_REVIEW_'.length).toLowerCase() } });
  });
  it('retains reservations after an uncertain dispatched outcome', async () => {
    const f = fixture(); const a = (await f.service.prepare(f.input))!;
    await f.service.dispatch(a, 12); await f.service.abort(a);
    expect(f.repo.settle).toHaveBeenCalledWith('op_test', 'fop_test', 'unknown');
    await f.service.finish(a, 0);
    expect(f.repo.settle).toHaveBeenCalledOnce();
  });
  it('never allows a replay-only proxy admission to dispatch again', async () => {
    const f = fixture(); const a = (await f.service.prepare(f.input))!;
    f.repo.reserve.mockResolvedValue({ operation: { id: 'fop_test' }, replay: true });
    await f.service.reserve(a, undefined, true);
    await expect(f.service.dispatch(a)).rejects.toThrow();
    expect(f.repo.dispatch).not.toHaveBeenCalled();
  });
  it('returns an explicit policy decision without forging human approval', async () => {
    const f = fixture(); const a = (await f.service.prepare(f.input))!;
    const gate = new ApprovalGateService({} as never);
    expect(await gate.check({ operatorId: 'op_test', passportJti: 'pp_test', agentId: 'agt_test', missionId: 'ms_test', sessionId: 'ses_test', accountabilityMode: 'enforced', approvalIdHeader: undefined, policyAuthorization: a.authorization })).toMatchObject({ allowed: true, skipped: false, origin: 'fleet_policy', approvalId: undefined });
  });
});
