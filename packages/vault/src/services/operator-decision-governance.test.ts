import { describe, expect, it, vi } from 'vitest';
import { OperatorDecisionService } from './operator-decision-service.js';

const owner = { kind: 'operator_owner' as const, operator_id: 'op_one' };

function fixture(options: { missionId?: string | null; claimFails?: boolean; auditFailsOnce?: boolean } = {}) {
  let status = 'pending';
  const registerClaim = vi.fn(async () => {
    if (options.claimFails) throw new Error('claim failed');
    return { claimId: 'pc_governance_decision', envelopeCose: 'cose', subject: 'stack://operator/op_one' };
  });
  const source = {
    id: 'gvr_one',
    operator_id: 'op_one',
    action: 'review_decide_approve',
    resource_id: 'cout_one',
    summary: 'Approve checkout',
    requested_via: 'operator_key',
    status: 'pending',
    expires_at: new Date(1_800_000_000_000),
    created_at: new Date(1_700_000_000_000),
    decided_at: null,
    mission_id: options.missionId === undefined ? 'ms_one' : options.missionId,
    agent_id: options.missionId === null ? null : 'agt_one',
  };
  let auditAttempts = 0;
  const auditWrite = vi.fn(async () => {
    auditAttempts += 1;
    if (options.auditFailsOnce && auditAttempts === 1) throw new Error('audit failed');
    return 'ae_governance';
  });
  const repo = {
    transaction: async (callback: (ctx: { decisions: Record<string, unknown>; claimPersistence: { insert: unknown } }) => Promise<unknown>) => {
      let pendingStatus = status;
      const decisions = {
        findGovernanceApprovalSource: vi.fn(async () => ({ ...source, status })),
        applyGovernanceDecision: vi.fn(async (input: { status: string }) => {
          if (status !== 'pending') return null;
          pendingStatus = input.status;
          return { ...source, status: input.status };
        }),
        findByIdempotencyKey: vi.fn(async () => null),
        create: vi.fn(async (row: Record<string, unknown>) => row),
        createSources: vi.fn(async () => undefined),
      };
      const result = await callback({ decisions, claimPersistence: { insert: vi.fn() } });
      status = pendingStatus;
      return result;
    },
    findByIdempotencyKey: vi.fn(async () => null),
  };
  const service = new OperatorDecisionService({
    repo: repo as never,
    claimRegistry: { registerClaim } as never,
    claimVerifier: { verifyClaim: vi.fn() } as never,
    audit: { write: auditWrite } as never,
    now: () => 1_766_000_000_000,
    generateId: () => 'odec_governance',
  });
  return { service, registerClaim, auditWrite, status: () => status };
}

describe('OperatorDecisionService governance integration', () => {
  it('updates an exact mission approval and signs its decision in one transaction', async () => {
    const { service, registerClaim, status } = fixture();
    const result = await service.decideGovernance({
      operatorId: 'op_one',
      approvalId: 'gvr_one',
      decision: 'approve',
      authoredBy: owner,
    });

    expect(status()).toBe('approved');
    expect(result.operator_decision).toMatchObject({
      claim_id: 'pc_governance_decision',
      mission_id: 'ms_one',
      action: 'governance_approved',
      effect: 'governance_approval_approved',
    });
    expect(registerClaim).toHaveBeenCalledWith(expect.objectContaining({
      payload: expect.objectContaining({
        mission_ref: 'ms_one',
        source_refs: expect.objectContaining({ approval_ids: ['gvr_one'] }),
      }),
    }), expect.any(Object));
  });

  it('keeps an unbound or ambiguous approval audit-only', async () => {
    const { service, registerClaim, status } = fixture({ missionId: null });
    const result = await service.decideGovernance({
      operatorId: 'op_one',
      approvalId: 'gvr_one',
      decision: 'reject',
      authoredBy: owner,
    });
    expect(status()).toBe('rejected');
    expect(result.operator_decision).toBeNull();
    expect(registerClaim).not.toHaveBeenCalled();
  });

  it('rolls back the approval when exact decision signing fails', async () => {
    const { service, status } = fixture({ claimFails: true });
    await expect(service.decideGovernance({
      operatorId: 'op_one',
      approvalId: 'gvr_one',
      decision: 'approve',
      authoredBy: owner,
    })).rejects.toThrow('claim failed');
    expect(status()).toBe('pending');
  });

  it('rolls back the approval and signed claim when audit fails, then permits retry', async () => {
    const { service, auditWrite, status } = fixture({ auditFailsOnce: true });
    const request = {
      operatorId: 'op_one',
      approvalId: 'gvr_one',
      decision: 'approve' as const,
      authoredBy: owner,
      auditContext: {
        trace_id: 'req_one',
        span_id: 'gvr_one',
        operator_id: 'op_one',
        agent_id: 'system',
        passport_jti: 'none',
      },
    };
    await expect(service.decideGovernance(request as never)).rejects.toThrow('audit failed');
    expect(status()).toBe('pending');
    await expect(service.decideGovernance(request as never)).resolves.toBeDefined();
    expect(status()).toBe('approved');
    expect(auditWrite).toHaveBeenCalledTimes(2);
  });
});

describe('OperatorDecisionService chat and bearer channels', () => {
  const hash = 'a'.repeat(64);
  const chat = { via: 'chat_elicitation' as const, mcpSessionHash: 'b'.repeat(64), elicitationId: 'e1', oauthClientId: 'client_1' };
  const request = { operatorId: 'op_one', approvalId: 'gvr_one', authoredBy: owner };

  it('refuses an approval from a Bearer credential, which may only reject', async () => {
    const { service, status } = fixture();
    await expect(service.decideGovernance({ ...request, decision: 'approve', channel: { via: 'bearer_reject' } }))
      .rejects.toThrow('can only reject');
    expect(status()).toBe('pending');
  });

  it('lets a non-admin member reject through a Bearer credential, never approve', async () => {
    const standard = { kind: 'team_member' as const, member_id: 'mem_1', role_at_signing: 'standard' as const };
    const { service, status } = fixture({ missionId: null });
    await expect(service.decideGovernance({ ...request, authoredBy: standard, decision: 'approve', channel: chat, expectedPayloadHash: hash }))
      .rejects.toThrow('require an admin member');
    expect(status()).toBe('pending');
    await expect(service.decideGovernance({ ...request, authoredBy: standard, decision: 'reject', channel: { via: 'bearer_reject' } }))
      .resolves.toMatchObject({ approval: { status: 'rejected' } });
    expect(status()).toBe('rejected');
  });

  it('refuses a chat confirmation that does not name the change it confirms', async () => {
    const { service, status } = fixture();
    await expect(service.decideGovernance({ ...request, decision: 'approve', channel: chat }))
      .rejects.toThrow('must name the change');
    expect(status()).toBe('pending');
  });
});
