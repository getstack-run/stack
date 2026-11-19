import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { LimitOverrides, TierLimitExceededError, createDb, operators, teamMembers, type OperatorTier } from '@stack/shared';
import { MemberRepository } from '../repositories/member-repo.js';
import type { AgentRepository } from '../repositories/agent-repo.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import { AgentService } from './agent-service.js';
import { MemberService } from './member-service.js';
import { PartnerTenantService } from './partner-tenant-service.js';
import { ServiceConnectionService, standaloneServiceConnectionHooks } from './service-connection-service.js';
import { contractPlanLimits, type PlanLimitsReader } from './entitlements/plan-limits.js';

/**
 * The counts the engine refuses past come from the plan reader a deployment injects; an engine alone is on the
 * contract plan and caps none of them. Each service below enforces the number its reader names.
 */

/** A reader that names the counts under test and leaves everything else at the contract plan. */
function reader(counts: { agents?: number; services?: number; maxTenants?: (overrides: LimitOverrides | null | undefined) => number }): PlanLimitsReader {
  return (tier: OperatorTier, overrides) => ({
    ...contractPlanLimits(tier, overrides),
    ...(counts.agents !== undefined ? { agents: counts.agents } : {}),
    ...(counts.services !== undefined ? { services: counts.services } : {}),
    ...(counts.maxTenants ? { maxTenants: counts.maxTenants(overrides) } : {}),
  });
}

describe('the agents a tier may register', () => {
  function agentRepo(count: number) {
    return {
      countByOperator: vi.fn(async () => count),
      findByOperatorAndName: vi.fn(async () => ({ id: 'agt_existing' })),
    } as unknown as AgentRepository;
  }

  it('refuses at the count the reader names', async () => {
    const service = new AgentService(agentRepo(3), undefined, reader({ agents: 3 }));
    await expect(service.register('op_x', 'free', { name: 'bot' } as never)).rejects.toMatchObject({
      constructor: TierLimitExceededError,
      code: 'TIER_LIMIT_EXCEEDED',
    });
  });

  it('admits one below it', async () => {
    const service = new AgentService(agentRepo(2), undefined, reader({ agents: 3 }));
    // It gets past the limit to the name check, which the stub answers with a clash.
    await expect(service.register('op_x', 'free', { name: 'bot' } as never)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('caps nothing for an engine alone', async () => {
    const service = new AgentService(agentRepo(1_000_000));
    await expect(service.register('op_x', 'free', { name: 'bot' } as never)).rejects.toMatchObject({ code: 'CONFLICT' });
  });
});

describe('the service connections a tier may hold', () => {
  function connections(count: number, planLimits?: PlanLimitsReader) {
    const repo = {
      findAccessibleServiceById: vi.fn(async () => ({ id: 'svc_x', provider: 'agentmail', name: 'x', scopes_available: ['*'] })),
      findConfigurationByOperatorAndProvider: vi.fn(async () => undefined),
      findActiveConnectionsForPrincipal: vi.fn(async () => []),
      findActiveConnectionsByOperatorAndProvider: vi.fn(async () => []),
      countConnectionsByOperator: vi.fn(async () => count),
      createConnection: vi.fn(async (row: unknown) => row),
    };
    const kms = { encrypt: vi.fn(async () => ({ ciphertext: 'ciphertext', keyRef: 'kms:key' })), decrypt: vi.fn() };
    const service = new ServiceConnectionService(repo as never, {} as never, kms as never, undefined, {
      ...standaloneServiceConnectionHooks,
      ...(planLimits ? { planLimits } : {}),
    });
    return { service, repo, kms };
  }
  const input = { service_id: 'svc_x', credential: { api_key: 'secret' } };

  it('refuses at the count the reader names, before anything is encrypted', async () => {
    const { service, kms } = connections(2, reader({ services: 2 }));
    await expect(service.connectApplication('op_x', 'free', input)).rejects.toBeInstanceOf(TierLimitExceededError);
    expect(kms.encrypt).not.toHaveBeenCalled();
  });

  it('admits one below it', async () => {
    const { service, repo } = connections(1, reader({ services: 2 }));
    await service.connectApplication('op_x', 'free', input);
    expect(repo.createConnection).toHaveBeenCalledTimes(1);
  });

  it('caps nothing for an engine alone', async () => {
    const { service, repo } = connections(1_000_000);
    await service.connectApplication('op_x', 'free', input);
    expect(repo.createConnection).toHaveBeenCalledTimes(1);
  });
});

describe('the tenants a partner may have', () => {
  function partner(overrides: unknown) {
    const rows: Array<Record<string, unknown>> = [
      { id: 'op_partner', email: 'p@test.invalid', tier: 'enterprise', status: 'active', is_partner: true, parent_operator_id: null, external_customer_id: null, limit_overrides: overrides },
    ];
    const operatorRepo = {
      findById: async (id: string) => rows.find((r) => r['id'] === id) ?? null,
      insertChild: async (input: Record<string, unknown>) => {
        const row = { ...input, tier: input['tier'] ?? 'free', status: 'active', is_partner: false, created_at: new Date() };
        rows.push(row);
        return row;
      },
      listChildren: async (parent: string) => rows.filter((r) => r['parent_operator_id'] === parent),
    } as unknown as OperatorRepository;
    const db = { transaction: async <T>(work: (tx: { execute: () => Promise<unknown> }) => Promise<T>) => work({ execute: async () => undefined }) };
    return { operatorRepo, db };
  }

  it('refuses at the count the reader names for the deal', async () => {
    const { operatorRepo, db } = partner({ maxTenants: 1 });
    const planLimits = reader({ maxTenants: (overrides) => overrides?.maxTenants ?? Infinity });
    const service = new PartnerTenantService({ db, operatorRepo, planLimits } as never);
    await service.createTenant('op_partner', { external_ref: 'r1' });
    await expect(service.createTenant('op_partner', { external_ref: 'r2' })).rejects.toMatchObject({ code: 'TENANT_LIMIT_REACHED' });
  });

  it('caps nothing for an engine alone', async () => {
    const { operatorRepo, db } = partner({ maxTenants: 1 });
    const service = new PartnerTenantService({ db, operatorRepo } as never);
    await service.createTenant('op_partner', { external_ref: 'r3' });
    await expect(service.createTenant('op_partner', { external_ref: 'r4' })).resolves.toMatchObject({ billing: 'partner' });
  });
});

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('team members', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_seats_${suffix}`;

  beforeAll(async () => {
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${operatorId}` });
  });

  afterAll(async () => {
    await db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await (db as unknown as { $client: { end(o: { timeout: number }): Promise<void> } }).$client.end({ timeout: 5 });
  });

  it('caps nothing: an account invites as many members as it wants', async () => {
    const service = new MemberService(new MemberRepository(db));
    service.setDb(db);
    for (let i = 0; i < 12; i += 1) {
      await expect(service.invite(operatorId, { email: `member${i}_${suffix}@test.invalid`, name: 'Next' } as never)).resolves.toBeDefined();
    }
  });
});
