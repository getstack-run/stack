import { fakeEntitlements } from '../test/entitlements.js';
import { fakeBrowserSessions } from '../test/browser-sessions.js';
import { describe, expect, it, vi } from 'vitest';
import { NotFoundError, OperatorSuspendedError } from '@stack/shared';
import { registerGovernancePublicRoutes, registerGovernanceRoutes } from './governance.js';
import { denyAgentContexts } from '../middleware/require-platform.js';

// a white-label partner's admin decides its tenants' governance
// approvals through the existing cookie-only decide endpoint. The tenant
// relation, partner status and member role are re-proven in the deciding
// transaction (operator-decision-partner-tenant tests + the PostgreSQL test);
// this file pins the route's own rules.

type Handler = (request: unknown, reply: unknown) => Promise<unknown>;

const PARTNER = 'op_partner';
const TENANT_APPROVAL = 'gvr_tenant';

function partnerOperator(overrides: Record<string, unknown> = {}) {
  return { id: PARTNER, email: 'partner@example.invalid', owner_session_revision: '0', status: 'active', is_partner: true, ...overrides };
}

function decideFixture(options: {
  session?: Record<string, unknown> | null;
  operator?: Record<string, unknown>;
  member?: Record<string, unknown> | null;
  ownApproval?: boolean;
  tenantDecision?: () => Promise<unknown>;
} = {}) {
  let handler: Handler | undefined;
  const app = { post(_path: string, routeHandler: Handler) { handler = routeHandler; } };
  const decideGovernance = vi.fn(async () => ({ approval: { id: 'gvr_own', status: 'approved' }, operator_decision: null }));
  const decideGovernanceForTenant = vi.fn(options.tenantDecision ?? (async () => ({
    approval: { id: TENANT_APPROVAL, status: 'approved' }, operator_decision: null, tenant_operator_id: 'op_tenant',
  })));
  const belongsTo = vi.fn(async () => options.ownApproval ?? false);
  const session = options.session === undefined
    ? { aud: 'stack:dashboard', sub: PARTNER, payload: { email: 'partner@example.invalid', owner_session_revision: '0' } }
    : options.session;
  registerGovernancePublicRoutes(app as never, {
    entitlements: fakeEntitlements(),
    signer: { verifyAccessOrSession: vi.fn(async () => { if (!session) throw new Error('bad token'); return session; }) },
    operator: { getById: vi.fn(async () => partnerOperator(options.operator)) },
    member: { findById: vi.fn(async () => options.member ?? null) },
    dashboardSessions: { assertActive: vi.fn(async () => undefined) },
    get browserSessions() { return fakeBrowserSessions(this); },
    governanceApprovals: { belongsTo },
    operatorDecision: { decideGovernance, decideGovernanceForTenant },
  } as never);
  const send = vi.fn((body: unknown) => body);
  const call = (headers: Record<string, string> = { cookie: 'stack_session=session' }, id = TENANT_APPROVAL) => handler!({
    id: 'req_one', headers, params: { id }, body: { decision: 'approve' },
  }, { send });
  return { call, decideGovernance, decideGovernanceForTenant, belongsTo, send };
}

describe('POST /v1/governance/approvals/:id/decide — partner for tenant', () => {
  it('a partner owner session decides its tenant approval as partner_admin', async () => {
    const f = decideFixture();
    const body = await f.call();
    expect(body).toMatchObject({ decision: 'approve', approval: { id: TENANT_APPROVAL } });
    expect(f.belongsTo).toHaveBeenCalledWith(TENANT_APPROVAL, PARTNER);
    expect(f.decideGovernance).not.toHaveBeenCalled();
    expect(f.decideGovernanceForTenant).toHaveBeenCalledWith(expect.objectContaining({
      partnerOperatorId: PARTNER,
      approvalId: TENANT_APPROVAL,
      decision: 'approve',
      authoredBy: { kind: 'partner_admin', partner_operator_id: PARTNER, member_id: null },
      browserSession: expect.objectContaining({ email: 'partner@example.invalid' }),
    }));
  });

  it('a partner admin member decides with its member id recorded', async () => {
    const f = decideFixture({
      session: { aud: 'stack:dashboard', sub: PARTNER, payload: { email: 'admin@example.invalid', member_id: 'mem_admin', is_member: true } },
      member: { id: 'mem_admin', operator_id: PARTNER, status: 'active', role: 'admin', email: 'admin@example.invalid' },
    });
    await f.call();
    expect(f.decideGovernanceForTenant).toHaveBeenCalledWith(expect.objectContaining({
      authoredBy: { kind: 'partner_admin', partner_operator_id: PARTNER, member_id: 'mem_admin' },
      browserSession: expect.objectContaining({ memberId: 'mem_admin' }),
    }));
  });

  it('refuses a non-admin partner member before any approval lookup', async () => {
    const f = decideFixture({
      session: { aud: 'stack:dashboard', sub: PARTNER, payload: { email: 'std@example.invalid', member_id: 'mem_std', is_member: true } },
      member: { id: 'mem_std', operator_id: PARTNER, status: 'active', role: 'standard', email: 'std@example.invalid' },
    });
    await expect(f.call()).rejects.toMatchObject({ statusCode: 403 });
    expect(f.belongsTo).not.toHaveBeenCalled();
    expect(f.decideGovernanceForTenant).not.toHaveBeenCalled();
  });

  it('refuses a partner API key or any Bearer credential: no cookie session, no decision', async () => {
    const f = decideFixture({ session: null });
    await expect(f.call({ authorization: 'Bearer sk_live_partner' })).rejects.toMatchObject({ statusCode: 401 });
    await expect(f.call({ cookie: 'stack_session=sk_live_partner' })).rejects.toMatchObject({ statusCode: 401 });
    expect(f.decideGovernanceForTenant).not.toHaveBeenCalled();
    expect(f.decideGovernance).not.toHaveBeenCalled();
  });

  it('refuses an OAuth access token smuggled into the cookie', async () => {
    const f = decideFixture({ session: { aud: 'stack:api', sub: PARTNER, payload: {} } });
    await expect(f.call()).rejects.toMatchObject({ statusCode: 401 });
    expect(f.decideGovernanceForTenant).not.toHaveBeenCalled();
  });

  it("answers 404 when another partner's session names this approval", async () => {
    const f = decideFixture({
      session: { aud: 'stack:dashboard', sub: 'op_other_partner', payload: { email: 'partner@example.invalid', owner_session_revision: '0' } },
      operator: { id: 'op_other_partner' },
      tenantDecision: async () => { throw new NotFoundError('governance approval', TENANT_APPROVAL); },
    });
    await expect(f.call()).rejects.toMatchObject({ statusCode: 404 });
    expect(f.decideGovernanceForTenant).toHaveBeenCalledWith(expect.objectContaining({ partnerOperatorId: 'op_other_partner' }));
  });

  it('refuses an inactive partner before any approval lookup', async () => {
    const f = decideFixture({ operator: { status: 'suspended', suspended_reason: 'hold' } });
    await expect(f.call()).rejects.toBeInstanceOf(OperatorSuspendedError);
    expect(f.belongsTo).not.toHaveBeenCalled();
    expect(f.decideGovernanceForTenant).not.toHaveBeenCalled();
  });

  it("keeps the partner's own approvals on the operator path", async () => {
    const f = decideFixture({ ownApproval: true });
    await f.call(undefined, 'gvr_own');
    expect(f.decideGovernance).toHaveBeenCalledWith(expect.objectContaining({ operatorId: PARTNER, approvalId: 'gvr_own' }));
    expect(f.decideGovernanceForTenant).not.toHaveBeenCalled();
  });

  it("a non-partner operator (a tenant has no human; a tenant session would be one) never takes the partner path", async () => {
    const f = decideFixture({ operator: { is_partner: false } });
    await f.call();
    expect(f.belongsTo).not.toHaveBeenCalled();
    expect(f.decideGovernanceForTenant).not.toHaveBeenCalled();
    expect(f.decideGovernance).toHaveBeenCalledWith(expect.objectContaining({ operatorId: PARTNER }));
  });
});

describe('GET /v1/governance/approvals — partner sees its tenants', () => {
  function listFixture() {
    let route: { preHandler: unknown[]; handler: Handler } | undefined;
    let detail: Handler | undefined;
    const app = {
      get(path: string, opts: { preHandler: unknown[] }, handler: Handler) {
        if (path === '/v1/governance/approvals') route = { preHandler: opts.preHandler, handler };
        else detail = handler;
      },
      post() { /* the chat decision route */ },
    };
    const listForPartner = vi.fn(async () => [{ id: 'gvr_tenant', tenant: { operator_id: 'op_tenant', name: 'acme' } }]);
    const listForOperator = vi.fn(async () => [{ id: 'gvr_own' }]);
    const belongsTo = vi.fn(async () => false);
    const getDetailForPartnerTenant = vi.fn(async () => ({ approval: { id: 'gvr_tenant', tenant: { operator_id: 'op_tenant', name: 'acme' } }, payload_hash: 'h', approval_url: 'u' }));
    const getDetailForOperator = vi.fn(async () => ({ approval: { id: 'gvr_own' }, payload_hash: 'h', approval_url: 'u' }));
    registerGovernanceRoutes(app as never, {
      governanceApprovals: { listForPartner, listForOperator, belongsTo, getDetailForPartnerTenant, getDetailForOperator },
    } as never);
    return { route: route!, detail: detail!, listForPartner, listForOperator, belongsTo, getDetailForPartnerTenant, getDetailForOperator };
  }

  it('reads a tenant approval for its partner, and only the own approval for everyone else', async () => {
    const f = listFixture();
    await f.detail({ operatorId: PARTNER, isPartner: true, params: { id: 'gvr_tenant' } }, {});
    expect(f.getDetailForPartnerTenant).toHaveBeenCalledWith('gvr_tenant', PARTNER);
    await f.detail({ operatorId: 'op_tenant', isPartner: false, params: { id: 'gvr_own' } }, {});
    expect(f.getDetailForOperator).toHaveBeenCalledWith('gvr_own', 'op_tenant');
    expect(f.getDetailForPartnerTenant).toHaveBeenCalledTimes(1);
    f.belongsTo.mockResolvedValueOnce(true);
    await f.detail({ operatorId: PARTNER, isPartner: true, params: { id: 'gvr_own' } }, {});
    expect(f.getDetailForOperator).toHaveBeenCalledWith('gvr_own', PARTNER);
  });

  it('lists tenant items for a partner', async () => {
    const f = listFixture();
    const body = await f.route.handler({ operatorId: PARTNER, isPartner: true }, {});
    expect(f.listForPartner).toHaveBeenCalledWith(PARTNER);
    expect(f.listForOperator).not.toHaveBeenCalled();
    expect(body).toEqual({ approvals: [{ id: 'gvr_tenant', tenant: { operator_id: 'op_tenant', name: 'acme' } }] });
  });

  it("a tenant's API key lists only its own approvals", async () => {
    const f = listFixture();
    await f.route.handler({ operatorId: 'op_tenant', isPartner: false }, {});
    expect(f.listForOperator).toHaveBeenCalledWith('op_tenant');
    expect(f.listForPartner).not.toHaveBeenCalled();
  });

  it('keeps agent contexts denied', () => {
    const f = listFixture();
    expect(f.route.preHandler).toContain(denyAgentContexts);
  });
});
