// A retry that names a governance approval it cannot use says where the approval stands in its code, not only in its
// message: GOVERNANCE_APPROVAL_PENDING (wait), _REJECTED or _EXPIRED (ask again). Still 403.

import { describe, expect, it } from 'vitest';
import { GovernanceApprovalStateError, type StackError } from '@stack/shared';
import { OP, baseReq, createPending, makeService, payload } from './governance-approval-service.test-support.js';

async function refusal(promise: Promise<unknown>): Promise<StackError> {
  try {
    await promise;
  } catch (error) {
    return error as StackError;
  }
  throw new Error('expected a refusal');
}

describe('a governance approval that cannot be used', () => {
  const consume = (svc: ReturnType<typeof makeService>['svc'], approvalId: string) =>
    svc.consume({ approvalId, operatorId: OP, action: baseReq.action, resourceId: baseReq.resourceId, payload });

  it('still waiting for the person: GOVERNANCE_APPROVAL_PENDING with the approval and its status', async () => {
    const { svc } = makeService();
    const id = await createPending(svc);
    const error = await refusal(consume(svc, id));
    expect(error).toBeInstanceOf(GovernanceApprovalStateError);
    expect([error.code, error.statusCode, error.details]).toEqual(['GOVERNANCE_APPROVAL_PENDING', 403, { approval_id: id, status: 'pending' }]);
  });

  it('declined: GOVERNANCE_APPROVAL_REJECTED', async () => {
    const { svc } = makeService();
    const id = await createPending(svc);
    await svc.decide(id, OP, 'reject');
    const error = await refusal(consume(svc, id));
    expect([error.code, error.details]).toEqual(['GOVERNANCE_APPROVAL_REJECTED', { approval_id: id, status: 'rejected' }]);
  });

  it('out of time, decided or not: GOVERNANCE_APPROVAL_EXPIRED', async () => {
    const pending = makeService();
    const waiting = await createPending(pending.svc);
    pending.rows.get(waiting)!.expires_at = new Date(Date.now() - 1_000);
    expect((await refusal(consume(pending.svc, waiting))).code).toBe('GOVERNANCE_APPROVAL_EXPIRED');

    const approved = makeService();
    const used = await createPending(approved.svc);
    await approved.svc.decide(used, OP, 'approve');
    approved.rows.get(used)!.expires_at = new Date(Date.now() - 1_000);
    const error = await refusal(consume(approved.svc, used));
    expect([error.code, error.details]).toEqual(['GOVERNANCE_APPROVAL_EXPIRED', { approval_id: used, status: 'expired' }]);
  });
});
