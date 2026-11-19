import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OperatorDecisionClaim } from '@stack/shared';

// The browser-session recheck needs a live transaction; its own behaviour is
// covered against PostgreSQL. Here it is observed, not exercised.
const assertBrowserDecisionSession = vi.fn(async (..._args: unknown[]) => undefined);
vi.mock('./browser-decision-session.js', () => ({
  assertBrowserDecisionSession: (...args: unknown[]) => assertBrowserDecisionSession(...args),
}));

const { OperatorDecisionService } = await import('./operator-decision-service.js');

const PARTNER = 'op_partner';
const TENANT = 'op_tenant';
const ownerSession = { email: 'partner@example.invalid', ownerSessionRevision: '0' };
const memberSession = { email: 'admin@example.invalid', memberId: 'mem_admin' };

function fixture(options: { missionId?: string | null; tenantFound?: boolean } = {}) {
  let status = 'pending';
  const source = {
    id: 'gvr_tenant',
    operator_id: TENANT,
    action: options.missionId ? 'review_decide_approve' : 'fleet_policy_activate',
    resource_id: 'flp_one',
    summary: 'Tenant fleet',
    requested_via: 'operator_key',
    status: 'pending',
    expires_at: new Date(1_800_000_000_000),
    created_at: new Date(1_700_000_000_000),
    decided_at: null,
    mission_id: options.missionId ?? null,
    agent_id: options.missionId ? 'agt_one' : null,
  };
  const applied: Array<Record<string, unknown>> = [];
  const created: Array<Record<string, unknown>> = [];
  const findTenantGovernanceApprovalSource = vi.fn(async () => (
    options.tenantFound === false ? null : { ...source, status }
  ));
  const findGovernanceApprovalSource = vi.fn(async () => null);
  const repo = {
    transaction: async (callback: (ctx: Record<string, unknown>) => Promise<unknown>) => {
      const decisions = {
        findTenantGovernanceApprovalSource,
        findGovernanceApprovalSource,
        applyGovernanceDecision: vi.fn(async (input: Record<string, unknown>) => {
          applied.push(input);
          status = input['status'] as string;
          return { ...source, status };
        }),
        findByIdempotencyKey: vi.fn(async () => null),
        create: vi.fn(async (row: Record<string, unknown>) => {
          created.push(row);
          return { ...row, decided_at: new Date(1_766_000_000_000) };
        }),
        createSources: vi.fn(async () => undefined),
      };
      return callback({ decisions, claimPersistence: { insert: vi.fn() }, transaction: { tx: true } });
    },
  };
  const registerClaim = vi.fn(async (input: { payload: unknown }) => {
    OperatorDecisionClaim.parse(input.payload);
    return { claimId: 'pc_tenant_decision' };
  });
  const auditWrite = vi.fn(async () => 'ae');
  const service = new OperatorDecisionService({
    repo: repo as never,
    claimRegistry: { registerClaim } as never,
    claimVerifier: { verifyClaim: vi.fn() } as never,
    audit: { write: auditWrite } as never,
    now: () => 1_766_000_000_000,
    generateId: () => 'odec_tenant',
  });
  return { service, applied, created, registerClaim, auditWrite, findTenantGovernanceApprovalSource, findGovernanceApprovalSource };
}

const auditContext = { trace_id: 'req_one', span_id: 'gvr_tenant', operator_id: PARTNER, agent_id: 'system', passport_jti: 'none' };

describe('OperatorDecisionService.decideGovernanceForTenant', () => {
  beforeEach(() => assertBrowserDecisionSession.mockClear());

  it('lets the partner owner decide a tenant approval and records it on both chains', async () => {
    const f = fixture();
    const result = await f.service.decideGovernanceForTenant({
      partnerOperatorId: PARTNER,
      approvalId: 'gvr_tenant',
      decision: 'approve',
      authoredBy: { kind: 'partner_admin', partner_operator_id: PARTNER, member_id: null },
      browserSession: ownerSession,
      auditContext,
    });

    expect(result.tenant_operator_id).toBe(TENANT);
    expect(result.approval.status).toBe('approved');
    // The partner session is rechecked against the PARTNER, never the tenant.
    expect(assertBrowserDecisionSession).toHaveBeenCalledWith({ tx: true }, PARTNER, ownerSession);
    expect(f.findTenantGovernanceApprovalSource).toHaveBeenCalledWith('gvr_tenant', PARTNER);
    expect(f.findGovernanceApprovalSource).not.toHaveBeenCalled();
    expect(f.applied[0]).toMatchObject({
      operatorId: TENANT,
      decidedByMemberId: null,
      decidedByPartnerOperatorId: PARTNER,
    });
    expect(f.auditWrite).toHaveBeenCalledTimes(2);
    const calls = f.auditWrite.mock.calls as unknown as Array<[Record<string, any>]>;
    expect(calls[0]![0]).toMatchObject({
      action: 'governance.approval.approve',
      actor_partner_operator_id: PARTNER,
      ctx: { operator_id: TENANT },
    });
    expect(calls[1]![0]).toMatchObject({
      action: 'governance.tenant_approval.approve',
      ctx: { operator_id: PARTNER, span_id: 'gvr_tenant' },
    });
    expect(typeof calls[1]![0]['payload_hash']).toBe('string');
    expect(calls[1]![0]['actor_partner_operator_id']).toBeUndefined();
  });

  it('records a partner admin member and signs a mission-bound decision under the tenant', async () => {
    const f = fixture({ missionId: 'ms_one' });
    const result = await f.service.decideGovernanceForTenant({
      partnerOperatorId: PARTNER,
      approvalId: 'gvr_tenant',
      decision: 'reject',
      authoredBy: { kind: 'partner_admin', partner_operator_id: PARTNER, member_id: 'mem_admin' },
      browserSession: memberSession,
      auditContext,
    });
    expect(result.operator_decision?.claim_id).toBe('pc_tenant_decision');
    expect(f.registerClaim).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: TENANT,
      payload: expect.objectContaining({
        operator_id: TENANT,
        authored_by: { kind: 'partner_admin', partner_operator_id: PARTNER, member_id: 'mem_admin' },
        action: 'governance_rejected',
      }),
    }), expect.any(Object));
    expect(f.created[0]).toMatchObject({
      operator_id: TENANT,
      author_kind: 'partner_admin',
      author_member_id: 'mem_admin',
      author_role: 'admin',
      author_partner_operator_id: PARTNER,
    });
    expect(f.applied[0]).toMatchObject({ decidedByMemberId: 'mem_admin', decidedByPartnerOperatorId: PARTNER });
  });

  it('answers not found for an approval that is not an active tenant approval of this partner', async () => {
    const f = fixture({ tenantFound: false });
    await expect(f.service.decideGovernanceForTenant({
      partnerOperatorId: PARTNER,
      approvalId: 'gvr_foreign',
      decision: 'approve',
      authoredBy: { kind: 'partner_admin', partner_operator_id: PARTNER, member_id: null },
      browserSession: ownerSession,
    })).rejects.toMatchObject({ statusCode: 404 });
    expect(f.applied).toHaveLength(0);
    expect(f.auditWrite).not.toHaveBeenCalled();
  });

  it('refuses an author that does not match the partner or the session', async () => {
    const f = fixture();
    for (const [authoredBy, browserSession] of [
      [{ kind: 'partner_admin', partner_operator_id: 'op_other', member_id: null }, ownerSession],
      [{ kind: 'partner_admin', partner_operator_id: PARTNER, member_id: 'mem_admin' }, ownerSession],
      [{ kind: 'partner_admin', partner_operator_id: PARTNER, member_id: null }, memberSession],
      [{ kind: 'partner_admin', partner_operator_id: PARTNER, member_id: 'mem_other' }, memberSession],
    ] as const) {
      await expect(f.service.decideGovernanceForTenant({
        partnerOperatorId: PARTNER,
        approvalId: 'gvr_tenant',
        decision: 'approve',
        authoredBy: authoredBy as never,
        browserSession,
      })).rejects.toMatchObject({ statusCode: 403 });
    }
    expect(f.applied).toHaveLength(0);
  });

  it('never accepts a partner author on the operator path', async () => {
    const f = fixture();
    await expect(f.service.decideGovernance({
      operatorId: TENANT,
      approvalId: 'gvr_tenant',
      decision: 'approve',
      authoredBy: { kind: 'partner_admin', partner_operator_id: PARTNER, member_id: null } as never,
    })).rejects.toThrow();
    expect(f.applied).toHaveLength(0);
  });
});

describe('OperatorDecisionClaim partner author', () => {
  const base = {
    type: 'operator_decision',
    decision_id: 'odec_one',
    mission_ref: 'ms_one',
    operator_id: TENANT,
    authored_by: { kind: 'partner_admin', partner_operator_id: PARTNER, member_id: null },
    effect_scope: 'mission',
    target_agent_id: 'agt_one',
    decided_at_ms: 1,
  };
  it('is valid on a governance decision', () => {
    expect(OperatorDecisionClaim.safeParse({
      ...base,
      action: 'governance_approved',
      effect: 'governance_approval_approved',
      source_refs: { approval_ids: ['gvr_one'] },
    }).success).toBe(true);
  });
  it('is refused on any other decision', () => {
    expect(OperatorDecisionClaim.safeParse({
      ...base,
      action: 'checkout_approved',
      effect: 'checkout_released',
      source_refs: { checkout_ids: ['cout_one'] },
    }).success).toBe(false);
  });
});
