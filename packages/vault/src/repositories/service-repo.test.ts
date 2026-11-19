import { ConflictError, createDb, operators, serviceConnections, services, teamMembers } from '@stack/shared';
import { eq, sql } from 'drizzle-orm';
import { describe, expect, it, vi } from 'vitest';
import { ServiceRepository } from './service-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describe('ServiceRepository grant transaction', () => {
  it('acquires the operator advisory lock before running replacement work', async () => {
    const order: string[] = [];
    const tx = {
      execute: vi.fn(async () => { order.push('lock'); }),
    };
    const db = {
      transaction: vi.fn(async (work: (transaction: typeof tx) => Promise<unknown>) => {
        order.push('transaction');
        return work(tx);
      }),
    };
    const repo = new ServiceRepository(db as never);

    await repo.withOperatorGrantLock('op_test', async (received) => {
      expect(received).toBe(tx);
      order.push('work');
    });

    expect(order).toEqual(['transaction', 'lock', 'work']);
  });
});

describeWithDb('ServiceRepository active principal integrity', () => {
  const db = createDb(DATABASE_URL!);
  const repo = new ServiceRepository(db);

  it('enforces race-safe uniqueness and selects a shared connection deterministically', async () => {
    const suffix = Math.random().toString(36).slice(2);
    const operatorId = `op_scon_${suffix}`;
    const otherOperatorId = `op_scon_other_${suffix}`;
    const serviceId = `svc_scon_${suffix}`;
    const provider = `provider_scon_${suffix}`;
    const firstMemberId = `member_a_${suffix}`;
    const secondMemberId = `member_b_${suffix}`;

    await db.insert(operators).values([
      { id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${operatorId}` },
      { id: otherOperatorId, email: `${otherOperatorId}@test.invalid`, api_key_hash: `hash_${otherOperatorId}` },
    ]);
    await db.insert(services).values({
      id: serviceId,
      provider,
      name: 'Principal race test',
      description: 'Test service',
      oauth_auth_url: '',
      oauth_token_url: '',
      scopes_available: ['*'],
      available: false,
    });
    await db.insert(teamMembers).values([
      { id: firstMemberId, operator_id: operatorId, email: `${firstMemberId}@test.invalid`, name: 'A' },
      { id: secondMemberId, operator_id: operatorId, email: `${secondMemberId}@test.invalid`, name: 'B' },
    ]);

    const row = (id: string, principalOperatorId = operatorId, memberId: string | null = null) => ({
      id,
      operator_id: principalOperatorId,
      service_id: serviceId,
      provider,
      scopes: ['*'],
      credential_ref: 'kms:test',
      credential_encrypted: 'encrypted',
      member_id: memberId,
      status: 'active',
    });

    try {
      const sharedRace = await Promise.allSettled([
        repo.createConnection(row(`scon_shared_a_${suffix}`)),
        repo.createConnection(row(`scon_shared_b_${suffix}`)),
      ]);
      expect(sharedRace.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      const sharedFailure = sharedRace.find((result) => result.status === 'rejected');
      expect(sharedFailure).toMatchObject({ reason: expect.any(ConflictError) });

      const memberRace = await Promise.allSettled([
        repo.createConnection(row(`scon_member_a_${suffix}`, operatorId, firstMemberId)),
        repo.createConnection(row(`scon_member_b_${suffix}`, operatorId, firstMemberId)),
      ]);
      expect(memberRace.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      const memberFailure = memberRace.find((result) => result.status === 'rejected');
      expect(memberFailure).toMatchObject({ reason: expect.any(ConflictError) });

      await expect(repo.createConnection(
        row(`scon_member_second_${suffix}`, operatorId, secondMemberId),
      )).resolves.toMatchObject({ member_id: secondMemberId });
      await expect(repo.createConnection(
        row(`scon_other_operator_${suffix}`, otherOperatorId),
      )).resolves.toMatchObject({ operator_id: otherOperatorId });

      const selected = await repo.findActiveConnectionByOperatorAndProvider(operatorId, provider);
      expect(selected?.member_id).toBeNull();

      const listed = await repo.findConnectionsByOperator(operatorId);
      expect(listed).toHaveLength(3);
      expect(listed.map((connection) => connection.id)).toEqual(
        [...listed]
          .sort((left, right) =>
            left.provider.localeCompare(right.provider)
            || (left.member_id ?? '\uffff').localeCompare(right.member_id ?? '\uffff')
            || left.id.localeCompare(right.id))
          .map((connection) => connection.id),
      );
    } finally {
      await db.delete(serviceConnections).where(eq(serviceConnections.service_id, serviceId));
      await db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId));
      await db.delete(services).where(eq(services.id, serviceId));
      await db.delete(operators).where(eq(operators.id, operatorId));
      await db.delete(operators).where(eq(operators.id, otherOperatorId));
    }
  });
});

describeWithDb('ServiceRepository connection names', () => {
  const db = createDb(DATABASE_URL!);
  const repo = new ServiceRepository(db);

  it('lets differently named active connections of one provider coexist and refuses a taken name in any case', async () => {
    const suffix = Math.random().toString(36).slice(2);
    const operatorId = `op_scon_name_${suffix}`;
    const serviceId = `svc_scon_name_${suffix}`;
    const provider = `provider_scon_name_${suffix}`;
    const memberId = `member_name_${suffix}`;

    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${operatorId}` });
    await db.insert(services).values({
      id: serviceId, provider, name: 'Name test', description: 'Test service',
      oauth_auth_url: '', oauth_token_url: '', scopes_available: ['*'], available: false,
    });
    await db.insert(teamMembers).values({ id: memberId, operator_id: operatorId, email: `${memberId}@test.invalid`, name: 'M' });

    const row = (id: string, name?: string, member: string | null = null) => ({
      id,
      operator_id: operatorId,
      service_id: serviceId,
      provider,
      ...(name === undefined ? {} : { name }),
      scopes: ['*'],
      credential_ref: 'kms:test',
      credential_encrypted: 'encrypted',
      member_id: member,
      status: 'active',
    });

    try {
      // A row written the way every row was before names existed takes the default.
      await expect(repo.createConnection(row(`scon_n_default_${suffix}`))).resolves.toMatchObject({ name: 'default' });
      await expect(repo.createConnection(row(`scon_n_work_${suffix}`, 'work'))).resolves.toMatchObject({ name: 'work' });
      await expect(repo.createConnection(row(`scon_n_member_${suffix}`, 'work', memberId))).resolves.toMatchObject({ member_id: memberId });

      await expect(repo.createConnection(row(`scon_n_dup_${suffix}`, 'WORK'))).rejects.toBeInstanceOf(ConflictError);
      await expect(repo.createConnection(row(`scon_n_dup2_${suffix}`))).rejects.toBeInstanceOf(ConflictError);
      await expect(repo.createConnection(row(`scon_n_member_dup_${suffix}`, 'Work', memberId))).rejects.toBeInstanceOf(ConflictError);

      expect((await repo.findActiveConnectionsForPrincipal(operatorId, provider, null)).map((c) => c.name).sort())
        .toEqual(['default', 'work']);
      expect((await repo.findActiveConnectionsForPrincipal(operatorId, provider, memberId)).map((c) => c.name))
        .toEqual(['work']);

      // The eligible query: shared rows, a member's own plus shared, narrowed by ids, nothing for an empty list.
      const shared = await repo.findEligibleProxyConnections(operatorId, provider, 'shared');
      expect(shared.map((c) => c.id).sort()).toEqual([`scon_n_default_${suffix}`, `scon_n_work_${suffix}`]);
      const asMember = await repo.findEligibleProxyConnections(operatorId, provider, { memberId });
      expect(asMember).toHaveLength(3);
      const narrowed = await repo.findEligibleProxyConnections(operatorId, provider, { memberId }, [`scon_n_member_${suffix}`]);
      expect(narrowed.map((c) => c.id)).toEqual([`scon_n_member_${suffix}`]);
      await expect(repo.findEligibleProxyConnections(operatorId, provider, 'shared', [])).resolves.toEqual([]);
      await expect(repo.findEligibleProxyConnections(`${operatorId}_x`, provider, 'shared')).resolves.toEqual([]);

      // A revoked connection frees its name; a rename refuses a name another active one holds.
      await repo.revokeConnection(`scon_n_work_${suffix}`);
      await expect(repo.createConnection(row(`scon_n_again_${suffix}`, 'work'))).resolves.toMatchObject({ name: 'work' });
      await expect(repo.renameConnection(`scon_n_again_${suffix}`, operatorId, 'DEFAULT')).rejects.toBeInstanceOf(ConflictError);
      await expect(repo.renameConnection(`scon_n_again_${suffix}`, operatorId, 'personal')).resolves.toMatchObject({ name: 'personal' });
      await expect(repo.renameConnection(`scon_n_work_${suffix}`, operatorId, 'x')).resolves.toBeUndefined();
      await expect(repo.renameConnection(`scon_n_again_${suffix}`, `${operatorId}_x`, 'x')).resolves.toBeUndefined();
    } finally {
      await db.delete(serviceConnections).where(eq(serviceConnections.service_id, serviceId));
      await db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId));
      await db.delete(services).where(eq(services.id, serviceId));
      await db.delete(operators).where(eq(operators.id, operatorId));
    }
  });
});

class ExpectedTenantRollback extends Error {}

describeWithDb('ServiceRepository custom definition tenancy', () => {
  const db = createDb(DATABASE_URL!);

  it('keeps catalog rows global while isolating the same custom provider per operator', async () => {
    const suffix = Math.random().toString(36).slice(2);
    const schemaName = `service_repo_tenant_${suffix}`;
    const operatorA = `op_repo_a_${suffix}`;
    const operatorB = `op_repo_b_${suffix}`;
    const provider = `custom_fixture_${suffix}`;
    const catalogProvider = `catalog_fixture_${suffix}`;

    await expect(db.transaction(async (tx) => {
      await tx.execute(sql.raw(`CREATE SCHEMA "${schemaName}"`));
      await tx.execute(sql.raw(`SET LOCAL search_path TO "${schemaName}"`));
      await tx.execute(sql.raw(`
        CREATE TABLE operators (id text PRIMARY KEY);
        CREATE TABLE services (
          id text PRIMARY KEY,
          operator_id text REFERENCES operators(id) ON DELETE CASCADE,
          provider text NOT NULL,
          name text NOT NULL,
          description text NOT NULL,
          oauth_auth_url text NOT NULL,
          oauth_token_url text NOT NULL,
          scopes_available jsonb NOT NULL,
          available boolean NOT NULL DEFAULT true,
          CONSTRAINT services_owner_shape_check CHECK (
            (operator_id IS NULL AND left(provider, 7) <> 'custom_')
            OR (operator_id IS NOT NULL AND left(provider, 7) = 'custom_' AND available = false)
          )
        );
        CREATE UNIQUE INDEX services_catalog_provider_unique
          ON services(provider) WHERE operator_id IS NULL;
        CREATE UNIQUE INDEX services_custom_operator_provider_unique
          ON services(operator_id, provider) WHERE operator_id IS NOT NULL;
      `));
      await tx.execute(sql`INSERT INTO operators (id) VALUES (${operatorA}), (${operatorB})`);

      const repo = new ServiceRepository(tx as never);
      const catalog = await repo.upsertCatalogService({
        id: `svc_catalog_${suffix}`,
        provider: catalogProvider,
        name: 'Catalog fixture',
        description: 'Synthetic catalog service',
        oauth_auth_url: '',
        oauth_token_url: '',
        scopes_available: ['read'],
        available: true,
      });
      const ownedA = await repo.upsertCustomService(operatorA, {
        id: `svc_custom_a_${suffix}`,
        provider,
        name: 'Operator A service',
        description: 'Synthetic A',
        oauth_auth_url: 'https://a.example.invalid/authorize',
        oauth_token_url: 'https://a.example.invalid/token',
        scopes_available: ['read:a'],
      });
      const ownedB = await repo.upsertCustomService(operatorB, {
        id: `svc_custom_b_${suffix}`,
        provider,
        name: 'Operator B service',
        description: 'Synthetic B',
        oauth_auth_url: 'https://b.example.invalid/authorize',
        oauth_token_url: 'https://b.example.invalid/token',
        scopes_available: ['read:b'],
      });

      expect(ownedA.id).not.toBe(ownedB.id);
      expect(ownedA.operator_id).toBe(operatorA);
      expect(ownedB.operator_id).toBe(operatorB);
      await expect(repo.findAccessibleServiceById(ownedA.id, operatorA)).resolves.toMatchObject({ id: ownedA.id });
      await expect(repo.findAccessibleServiceById(ownedA.id, operatorB)).resolves.toBeUndefined();
      await expect(repo.findAccessibleServiceById(catalog.id, operatorB)).resolves.toMatchObject({ id: catalog.id });

      const updatedA = await repo.upsertCustomService(operatorA, {
        id: `svc_ignored_${suffix}`,
        provider,
        name: 'Operator A updated',
        description: 'Synthetic A updated',
        oauth_auth_url: 'https://updated-a.example.invalid/authorize',
        oauth_token_url: 'https://updated-a.example.invalid/token',
        scopes_available: ['write:a'],
      });
      expect(updatedA.id).toBe(ownedA.id);
      await expect(repo.findOwnedCustomServiceByProvider(operatorB, provider)).resolves.toMatchObject({
        id: ownedB.id,
        name: 'Operator B service',
        oauth_token_url: 'https://b.example.invalid/token',
      });

      const listed = await repo.listCatalogServices();
      expect(listed.map((row) => row.id)).toContain(catalog.id);
      expect(listed.map((row) => row.id)).not.toContain(ownedA.id);
      expect(listed.map((row) => row.id)).not.toContain(ownedB.id);

      await expect(repo.upsertCustomService(operatorA, {
        id: `svc_invalid_${suffix}`,
        provider: `invalid_${suffix}`,
        name: 'Invalid',
        description: 'Synthetic invalid row',
        oauth_auth_url: '',
        oauth_token_url: '',
        scopes_available: ['*'],
      })).rejects.toThrow('custom_ prefix');

      throw new ExpectedTenantRollback('rollback isolated repository fixture');
    })).rejects.toBeInstanceOf(ExpectedTenantRollback);
  });
});
