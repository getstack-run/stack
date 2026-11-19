import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq, inArray } from 'drizzle-orm';
import { auditLog, createDb, governanceApprovals, operators, teamMembers } from '@stack/shared';
import {
  AuditService,
  GovernanceApprovalRepository,
  GovernanceApprovalService,
  OperatorDecisionRepository,
  OperatorDecisionService,
} from '@stack/vault';
import { isDedicatedStackTestDatabase } from '../test/dedicated-test-database.js';

/**
 * against real PostgreSQL: a white-label partner's admin decides its
 * tenant's governance approval. The tenant relation, the partner's status and
 * the member's role all come from the database inside the deciding
 * transaction, and the decision lands on both audit chains, each still valid.
 */

const databaseUrl = process.env['DATABASE_URL'];

describe.runIf(isDedicatedStackTestDatabase(databaseUrl))('partner decides tenant governance approvals (PostgreSQL)', () => {
  const db = createDb(databaseUrl!);
  const audit = new AuditService(db);
  const decisions = new OperatorDecisionService({
    repo: new OperatorDecisionRepository(db),
    claimRegistry: { registerClaim: async () => { throw new Error('fleet approvals are not mission-bound'); } } as never,
    claimVerifier: { verifyClaim: async () => { throw new Error('unused'); } } as never,
    audit,
  });
  const approvals = new GovernanceApprovalService({
    repo: new GovernanceApprovalRepository(db),
    notification: null,
    dashboardUrl: 'https://dashboard.example.invalid',
  });

  const s = randomUUID().replace(/-/g, '').slice(0, 12);
  const partner = `op_gp_partner_${s}`;
  const tenant = `op_gp_tenant_${s}`;
  const revokedTenant = `op_gp_revoked_${s}`;
  const otherPartner = `op_gp_other_${s}`;
  const otherTenant = `op_gp_other_tenant_${s}`;
  const suspendedPartner = `op_gp_suspended_${s}`;
  const suspendedTenant = `op_gp_suspended_tenant_${s}`;
  const stranger = `op_gp_stranger_${s}`;
  const allOperators = [tenant, revokedTenant, otherTenant, suspendedTenant, partner, otherPartner, suspendedPartner, stranger];
  const admin = `mem_gp_admin_${s}`;
  const standard = `mem_gp_std_${s}`;
  const email = (id: string) => `${id}@gp.invalid`;
  const owner = (id: string) => ({ email: email(id), ownerSessionRevision: '0' });
  const ownerAuthor = (id: string) => ({ kind: 'partner_admin' as const, partner_operator_id: id, member_id: null });

  async function approval(operatorId: string): Promise<string> {
    const id = `gvr_gp_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    await db.insert(governanceApprovals).values({
      id,
      operator_id: operatorId,
      action: 'fleet_policy_activate',
      resource_id: `flp_${s}`,
      payload_hash: id,
      summary: 'Tenant support fleet',
      requested_via: 'operator_key',
      expires_at: new Date(Date.now() + 10 * 60_000),
    });
    return id;
  }

  beforeAll(async () => {
    await db.insert(operators).values([
      { id: partner, email: email(partner), api_key_hash: `h_${partner}`, tier: 'enterprise', is_partner: true },
      { id: otherPartner, email: email(otherPartner), api_key_hash: `h_${otherPartner}`, tier: 'enterprise', is_partner: true },
      { id: suspendedPartner, email: email(suspendedPartner), api_key_hash: `h_${suspendedPartner}`, tier: 'enterprise', is_partner: true, status: 'suspended' },
      { id: stranger, email: email(stranger), api_key_hash: `h_${stranger}` },
    ]);
    await db.insert(operators).values([
      { id: tenant, email: email(tenant), api_key_hash: `h_${tenant}`, parent_operator_id: partner, external_customer_id: `acme-${s}` },
      { id: revokedTenant, email: email(revokedTenant), api_key_hash: `h_${revokedTenant}`, parent_operator_id: partner, status: 'deleted' },
      { id: otherTenant, email: email(otherTenant), api_key_hash: `h_${otherTenant}`, parent_operator_id: otherPartner },
      { id: suspendedTenant, email: email(suspendedTenant), api_key_hash: `h_${suspendedTenant}`, parent_operator_id: suspendedPartner },
    ]);
    await db.insert(teamMembers).values([
      { id: admin, operator_id: partner, email: email(admin), name: 'Admin', status: 'active', role: 'admin' },
      { id: standard, operator_id: partner, email: email(standard), name: 'Standard', status: 'active', role: 'standard' },
    ]);
  });

  afterAll(async () => {
    await db.delete(auditLog).where(inArray(auditLog.operator_id, allOperators));
    await db.delete(governanceApprovals).where(inArray(governanceApprovals.operator_id, allOperators));
    await db.delete(teamMembers).where(inArray(teamMembers.id, [admin, standard]));
    await db.delete(operators).where(inArray(operators.id, allOperators.slice(0, 4)));
    await db.delete(operators).where(inArray(operators.id, allOperators.slice(4)));
    await db.$client.end();
  });

  it('the partner owner approves; both chains record it and still verify', async () => {
    const id = await approval(tenant);
    const result = await decisions.decideGovernanceForTenant({
      partnerOperatorId: partner,
      approvalId: id,
      decision: 'approve',
      authoredBy: ownerAuthor(partner),
      browserSession: owner(partner),
      auditContext: { trace_id: `req_${s}`, span_id: id, operator_id: partner, agent_id: 'system', passport_jti: 'none' },
    });
    expect(result.tenant_operator_id).toBe(tenant);
    const [row] = await db.select().from(governanceApprovals).where(eq(governanceApprovals.id, id));
    expect(row).toMatchObject({ status: 'approved', decided_by_partner_operator_id: partner, decided_by_member_id: null });

    const tenantEntries = await db.select().from(auditLog)
      .where(and(eq(auditLog.operator_id, tenant), eq(auditLog.span_id, id)));
    expect(tenantEntries).toHaveLength(1);
    expect(tenantEntries[0]).toMatchObject({ action: 'governance.approval.approve', actor_partner_operator_id: partner });
    const partnerEntries = await db.select().from(auditLog)
      .where(and(eq(auditLog.operator_id, partner), eq(auditLog.span_id, id)));
    expect(partnerEntries).toHaveLength(1);
    expect(partnerEntries[0]!.action).toBe('governance.tenant_approval.approve');
    expect(partnerEntries[0]!.payload_hash).toMatch(/^[0-9a-f]{64}$/);
    expect((await audit.verifyChain(tenant)).valid).toBe(true);
    expect((await audit.verifyChain(partner)).valid).toBe(true);
  });

  it('an admin member of the partner rejects, recorded by member id', async () => {
    const id = await approval(tenant);
    await decisions.decideGovernanceForTenant({
      partnerOperatorId: partner,
      approvalId: id,
      decision: 'reject',
      authoredBy: { kind: 'partner_admin', partner_operator_id: partner, member_id: admin },
      browserSession: { email: email(admin), memberId: admin },
    });
    const [row] = await db.select().from(governanceApprovals).where(eq(governanceApprovals.id, id));
    expect(row).toMatchObject({ status: 'rejected', decided_by_partner_operator_id: partner, decided_by_member_id: admin });
  });

  it('a standard (non-admin) member of the partner is refused', async () => {
    const id = await approval(tenant);
    await expect(decisions.decideGovernanceForTenant({
      partnerOperatorId: partner,
      approvalId: id,
      decision: 'approve',
      authoredBy: { kind: 'partner_admin', partner_operator_id: partner, member_id: standard },
      browserSession: { email: email(standard), memberId: standard },
    })).rejects.toMatchObject({ statusCode: 403 });
    const [row] = await db.select().from(governanceApprovals).where(eq(governanceApprovals.id, id));
    expect(row!.status).toBe('pending');
  });

  it("another partner's session cannot decide this partner's tenant approval, nor learn it exists", async () => {
    const id = await approval(tenant);
    const attempt = decisions.decideGovernanceForTenant({
      partnerOperatorId: otherPartner,
      approvalId: id,
      decision: 'approve',
      authoredBy: ownerAuthor(otherPartner),
      browserSession: owner(otherPartner),
    });
    await expect(attempt).rejects.toMatchObject({ statusCode: 404 });
    const missing = decisions.decideGovernanceForTenant({
      partnerOperatorId: otherPartner,
      approvalId: 'gvr_gp_does_not_exist',
      decision: 'approve',
      authoredBy: ownerAuthor(otherPartner),
      browserSession: owner(otherPartner),
    });
    await expect(missing).rejects.toMatchObject({ statusCode: 404 });
    const [row] = await db.select().from(governanceApprovals).where(eq(governanceApprovals.id, id));
    expect(row!.status).toBe('pending');
  });

  it("the partner path cannot reach a non-tenant operator's approval or a revoked tenant's", async () => {
    for (const operatorId of [stranger, revokedTenant]) {
      const id = await approval(operatorId);
      await expect(decisions.decideGovernanceForTenant({
        partnerOperatorId: partner,
        approvalId: id,
        decision: 'approve',
        authoredBy: ownerAuthor(partner),
        browserSession: owner(partner),
      })).rejects.toMatchObject({ statusCode: 404 });
    }
  });

  it('an inactive partner is refused', async () => {
    const id = await approval(suspendedTenant);
    await expect(decisions.decideGovernanceForTenant({
      partnerOperatorId: suspendedPartner,
      approvalId: id,
      decision: 'approve',
      authoredBy: ownerAuthor(suspendedPartner),
      browserSession: owner(suspendedPartner),
    })).rejects.toMatchObject({ statusCode: 403 });
    const [row] = await db.select().from(governanceApprovals).where(eq(governanceApprovals.id, id));
    expect(row!.status).toBe('pending');
  });

  it("the tenant itself has no partner path: the operator path can't author as a partner", async () => {
    const id = await approval(tenant);
    await expect(decisions.decideGovernance({
      operatorId: tenant,
      approvalId: id,
      decision: 'approve',
      authoredBy: ownerAuthor(partner) as never,
    })).rejects.toBeDefined();
  });

  it("lists the partner's tenant items with the tenant named, and only its own tenants'", async () => {
    const id = await approval(tenant);
    const foreign = await approval(otherTenant);
    const list = await approvals.listForPartner(partner);
    const item = list.find((entry) => entry.id === id);
    expect(item?.tenant).toEqual({ operator_id: tenant, name: `acme-${s}` });
    expect(list.some((entry) => entry.id === foreign)).toBe(false);
    expect(list.some((entry) => entry.tenant?.operator_id === revokedTenant)).toBe(false);

    const tenantOwn = await approvals.listForOperator(tenant);
    expect(tenantOwn.every((entry) => entry.tenant === undefined)).toBe(true);
    expect(tenantOwn.some((entry) => entry.id === foreign)).toBe(false);
    const otherTenantName = (await approvals.listForPartner(otherPartner)).find((entry) => entry.id === foreign)?.tenant;
    expect(otherTenantName).toEqual({ operator_id: otherTenant, name: otherTenant });
  });

  it("names the active partner whose channels hear a tenant's pending approvals, and no one else", async () => {
    const repo = new GovernanceApprovalRepository(db);
    expect(await repo.findActivePartnerOf(tenant)).toEqual({ partner_operator_id: partner, external_customer_id: `acme-${s}` });
    expect(await repo.findActivePartnerOf(otherTenant)).toEqual({ partner_operator_id: otherPartner, external_customer_id: null });
    expect(await repo.findActivePartnerOf(revokedTenant)).toBeUndefined();
    expect(await repo.findActivePartnerOf(suspendedTenant)).toBeUndefined();
    expect(await repo.findActivePartnerOf(partner)).toBeUndefined();
    expect(await repo.findActivePartnerOf(stranger)).toBeUndefined();
  });
});
