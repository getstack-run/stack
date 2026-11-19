import { describe, it, expect } from 'vitest';
import { PartnerTenantService } from './partner-tenant-service.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import { contractPlanLimits } from './entitlements/plan-limits.js';

/**
 * PartnerTenantService invariants — hardening.
 *
 *   P1: createTenant generates child operator + returns plaintext API key once
 *   P2: createTenant is idempotent on the partner's own reference; a closed account's reference is not reused
 *   P3: createTenant refuses non-partner caller (ForbiddenError)
 *   P4: listTenants returns metadata only (no audit/intent bodies)
 *   P5: revokeTenant idempotent on repeat call
 *   P6: assertTenantOwnership rejects cross-partner access (NotFoundError)
 */

let refCount = 0;
const ref = () => ({ external_ref: `ref_${++refCount}` });

const PARTNER_OP = 'op_partner';
const PARTNER_OP_OTHER = 'op_partner_other';

interface FakeOperatorRow {
  id: string;
  email: string;
  tier: string;
  status: string;
  is_partner: boolean;
  parent_operator_id: string | null;
  external_customer_id: string | null;
  api_key_hash: string;
  created_at: Date;
  deleted_at: Date | null;
  limit_overrides?: unknown;
}

function makeRepoStub(initial: FakeOperatorRow[] = []): {
  repo: OperatorRepository;
  rows: FakeOperatorRow[];
} {
  const rows: FakeOperatorRow[] = [...initial];
  const repo = {
    async findById(id: string) {
      return rows.find((r) => r.id === id) ?? null;
    },
    async insertChild(input: {
      id: string;
      email: string;
      api_key_hash: string;
      parent_operator_id: string;
      external_customer_id: string | null;
      tier?: string;
    }) {
      const row: FakeOperatorRow = {
        id: input.id,
        email: input.email,
        tier: input.tier ?? 'free',
        status: 'active',
        is_partner: false,
        parent_operator_id: input.parent_operator_id,
        external_customer_id: input.external_customer_id,
        api_key_hash: input.api_key_hash,
        created_at: new Date(),
        deleted_at: null,
      };
      rows.push(row);
      return row;
    },
    async listChildren(parentOperatorId: string) {
      return rows.filter((r) => r.parent_operator_id === parentOperatorId);
    },
    async findChildScoped(childId: string, parentOperatorId: string) {
      return rows.find((r) => r.id === childId && r.parent_operator_id === parentOperatorId) ?? null;
    },
    async replaceChildApiKey(childId: string, parentOperatorId: string, hash: string) {
      const row = rows.find((r) => r.id === childId && r.parent_operator_id === parentOperatorId);
      if (!row) throw new Error('no child');
      row.api_key_hash = hash;
    },
    async revokeChild(childId: string, parentOperatorId: string) {
      const row = rows.find((r) => r.id === childId && r.parent_operator_id === parentOperatorId);
      if (!row || row.status === 'deleted') return false;
      row.status = 'deleted';
      row.deleted_at = new Date();
      return true;
    },
  } as unknown as OperatorRepository;
  return { repo, rows };
}

function partnerRow(id: string): FakeOperatorRow {
  return {
    id,
    email: `${id}@partner.local`,
    tier: 'enterprise',
    status: 'active',
    is_partner: true,
    parent_operator_id: null,
    external_customer_id: null,
    api_key_hash: 'partner-hash-' + id,
    created_at: new Date(),
    deleted_at: null,
  };
}

// A deployment's plans name how many tenants a deal allows; here the deal's own number, as a plan reader gives it.
const dealLimits = (_tier: unknown, overrides?: { maxTenants?: number } | null) =>
  ({ ...contractPlanLimits('enterprise'), maxTenants: overrides?.maxTenants ?? Infinity });

function makeService(operatorRepo: OperatorRepository, accountPlans?: unknown): PartnerTenantService {
  const db = {
    async transaction<T>(callback: (tx: { execute: () => Promise<unknown> }) => Promise<T>) {
      return callback({ execute: async () => undefined });
    },
  };
  return new PartnerTenantService({ db, operatorRepo, planLimits: dealLimits, ...(accountPlans ? { accountPlans } : {}) } as never);
}

describe('PartnerTenantService hardening', () => {
  it('P1 createTenant generates child + returns plaintext API key once', async () => {
    const { repo, rows } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    const result = await svc.createTenant(PARTNER_OP, {
      external_ref: 'cust_42',
    });
    expect(result.account_id).toMatch(/^op_/);
    expect(result.api_key).toMatch(/^sk_live_/);
    expect(result.external_ref).toBe('cust_42');
    expect(result.created).toBe(true);
    // Accounts have no plan of their own; they draw from the partner's.
    expect(result.billing).toBe('partner');
    // Child row created with correct parent + flags
    const child = rows.find((r) => r.id === result.account_id);
    expect(child).toBeDefined();
    expect(child!.parent_operator_id).toBe(PARTNER_OP);
    expect(child!.is_partner).toBe(false);
    // Plaintext key NEVER stored in the row (only the hash)
    expect(child!.api_key_hash).not.toBe(result.api_key);
  });

  it('P2 createTenant under a reference the partner already has returns that account, with no second key', async () => {
    const { repo, rows } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    const first = await svc.createTenant(PARTNER_OP, { external_ref: 'cust_dup' });
    const again = await svc.createTenant(PARTNER_OP, { external_ref: 'cust_dup' });
    expect(again).toMatchObject({ account_id: first.account_id, created: false, external_ref: 'cust_dup' });
    expect(again).not.toHaveProperty('api_key');
    expect(rows.filter((r) => r.parent_operator_id === PARTNER_OP)).toHaveLength(1);
  });

  it('P2b a reference of a closed account is a conflict, never reused', async () => {
    const { repo } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    const first = await svc.createTenant(PARTNER_OP, { external_ref: 'cust_closed' });
    await svc.revokeTenant(first.account_id, PARTNER_OP);
    await expect(svc.createTenant(PARTNER_OP, { external_ref: 'cust_closed' })).rejects.toMatchObject({ statusCode: 409 });
  });

  it('P2c the account carries a placeholder address under the reserved domain, never an address of the customer', async () => {
    const { repo, rows } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    const made = await svc.createTenant(PARTNER_OP, { external_ref: 'cust_ph' });
    expect(rows.find((r) => r.id === made.account_id)!.email).toMatch(/\.stack-tenant\.local$/);
  });

  it('P2d a new key replaces the old one and the old one stops matching', async () => {
    const { repo, rows } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    const made = await svc.createTenant(PARTNER_OP, { external_ref: 'cust_key' });
    const before = rows.find((r) => r.id === made.account_id)!.api_key_hash;
    const rotated = await svc.rotateKey(made.account_id, PARTNER_OP);
    expect(rotated.api_key).toMatch(/^sk_live_/);
    expect(rotated.api_key).not.toBe(made.api_key);
    expect(rows.find((r) => r.id === made.account_id)!.api_key_hash).not.toBe(before);
    await expect(svc.rotateKey(made.account_id, PARTNER_OP_OTHER)).rejects.toThrow();
  });

  it('P3 createTenant refuses non-partner caller (is_partner=false)', async () => {
    const nonPartner = { ...partnerRow(PARTNER_OP), is_partner: false };
    const { repo } = makeRepoStub([nonPartner]);
    const svc = makeService(repo);
    await expect(
      svc.createTenant(PARTNER_OP, { external_ref: 'cust_x' }),
    ).rejects.toThrow(/not a partner/);
  });

  it('P4 listTenants returns metadata only (no body fields)', async () => {
    const { repo } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    await svc.createTenant(PARTNER_OP, { external_ref: 'cust_a' });
    await svc.createTenant(PARTNER_OP, { external_ref: 'cust_b' });
    const list = await svc.listTenants(PARTNER_OP);
    expect(list).toHaveLength(2);
    const view = list[0]!;
    // View shape carries metadata, NOT audit content
    expect(view).toHaveProperty('account_id');
    expect(view).toHaveProperty('external_ref');
    expect(view).toHaveProperty('invite');
    expect(view).toHaveProperty('status');
    expect(view).toHaveProperty('created_at');
    // No audit body fields on the view
    expect(view).not.toHaveProperty('audit_log');
    expect(view).not.toHaveProperty('intent_claims');
    expect(view).not.toHaveProperty('security_events');
    expect(view).not.toHaveProperty('api_key_hash');
  });

  it('P5 revokeTenant idempotent on repeat call', async () => {
    const { repo } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    const tenant = await svc.createTenant(PARTNER_OP, { external_ref: 'cust_revoke' });
    const first = await svc.revokeTenant(tenant.account_id, PARTNER_OP);
    expect(first.transitioned).toBe(true);
    const second = await svc.revokeTenant(tenant.account_id, PARTNER_OP);
    expect(second.transitioned).toBe(false); // already revoked
  });

  it('P6 assertTenantOwnership rejects cross-partner access', async () => {
    const { repo } = makeRepoStub([partnerRow(PARTNER_OP), partnerRow(PARTNER_OP_OTHER)]);
    const svc = makeService(repo);
    const tenant = await svc.createTenant(PARTNER_OP, { external_ref: 'cust_x' });
    // Partner A's tenant cannot be accessed by Partner B
    await expect(
      svc.assertTenantOwnership(tenant.account_id, PARTNER_OP_OTHER),
    ).rejects.toThrow(/account/);
    // But the rightful owner can
    const own = await svc.assertTenantOwnership(tenant.account_id, PARTNER_OP);
    expect(own.id).toBe(tenant.account_id);
  });
});

describe('PartnerTenantService — tenants share the partner plan (2026-09-29)', () => {
  it('T1 refuses a tier on create instead of granting a free paid plan', async () => {
    const { repo, rows } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    await expect(
      svc.createTenant(PARTNER_OP, { external_ref: 'c', tier: 'enterprise' } as never),
    ).rejects.toMatchObject({ code: 'TENANT_TIER_NOT_ALLOWED', statusCode: 400 });
    expect(rows.filter((r) => r.parent_operator_id === PARTNER_OP)).toHaveLength(0);
  });

  it('T2 stores every account on the fail-closed free tier', async () => {
    const { repo, rows } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    const created = await svc.createTenant(PARTNER_OP, ref());
    expect(rows.find((r) => r.id === created.account_id)!.tier).toBe('free');
  });

  it('T2b opens an account with its controls on only when asked, and passes the choice to the opening charge', async () => {
    const calls: Array<{ partnerId: string; accountId: string; controls?: boolean }> = [];
    const plans = { chargeOpening: async (_tx: unknown, input: { partnerId: string; accountId: string; controls?: boolean }) => { calls.push(input); }, views: async () => new Map() };
    const { repo } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo, plans);
    await svc.createTenant(PARTNER_OP, ref());
    await svc.createTenant(PARTNER_OP, { ...ref(), controls: false });
    await svc.createTenant(PARTNER_OP, { ...ref(), controls: true });
    expect(calls.map((c) => c.controls ?? false)).toEqual([false, false, true]);
  });

  it('T2c refuses controls on a deployment that has no hosted controls to switch on, and makes nothing', async () => {
    const { repo, rows } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const svc = makeService(repo);
    await expect(svc.createTenant(PARTNER_OP, { ...ref(), controls: true })).rejects.toMatchObject({ statusCode: 400 });
    expect(rows.filter((r) => r.parent_operator_id === PARTNER_OP)).toHaveLength(0);
    // Without the option the same deployment opens the account.
    await expect(svc.createTenant(PARTNER_OP, ref())).resolves.toMatchObject({ created: true });
  });

  it('T3 enforces the deal maxTenants on active tenants only', async () => {
    const partner = { ...partnerRow(PARTNER_OP), limit_overrides: { maxTenants: 2 } };
    const { repo } = makeRepoStub([partner]);
    const svc = makeService(repo);
    const first = await svc.createTenant(PARTNER_OP, ref());
    await svc.createTenant(PARTNER_OP, ref());
    await expect(svc.createTenant(PARTNER_OP, ref()))
      .rejects.toMatchObject({ code: 'TENANT_LIMIT_REACHED', statusCode: 409 });
    await svc.revokeTenant(first.account_id, PARTNER_OP);
    await expect(svc.createTenant(PARTNER_OP, ref())).resolves.toMatchObject({ billing: 'partner' });
  });

  it('T4 reports each tenant share of the pool when usage is wired', async () => {
    const { repo } = makeRepoStub([partnerRow(PARTNER_OP)]);
    const db = {
      async transaction<T>(callback: (tx: { execute: () => Promise<unknown> }) => Promise<T>) {
        return callback({ execute: async () => undefined });
      },
    };
    let created = '';
    const svc = new PartnerTenantService({
      db,
      operatorRepo: repo,
      poolUsage: {
        getPoolMeteredTotals: async () => ({ total: 12, byOperator: { [created]: 7 }, tenantCount: 1 }),
      },
    } as never);
    created = (await svc.createTenant(PARTNER_OP, ref())).account_id;
    const [view] = await svc.listTenants(PARTNER_OP);
    expect(view!.usage).toMatchObject({ actions: 7 });
    expect(view!.usage!.period).toMatch(/^\d{4}-\d{2}$/);
  });
});
