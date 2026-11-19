import { afterAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  acquireOAuthOperatorLock,
  createDb,
  operatorErasureJobs,
  operators,
} from '@stack/shared';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { OperatorErasureService } from './operator-erasure-service.js';
import { PartnerTenantService } from './partner-tenant-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('PartnerTenantService create and erasure race', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const partnerId = `op_partner_tenant_race_${suffix}`;
  const revokePartnerId = `op_partner_revoke_race_${suffix}`;
  const childId = `op_child_revoke_race_${suffix}`;

  afterAll(async () => {
    await db.delete(operatorErasureJobs)
      .where(eq(operatorErasureJobs.operator_id, partnerId))
      .catch(() => undefined);
    await db.delete(operators)
      .where(eq(operators.parent_operator_id, partnerId))
      .catch(() => undefined);
    await db.delete(operators)
      .where(eq(operators.id, partnerId))
      .catch(() => undefined);
    await db.delete(operatorErasureJobs)
      .where(eq(operatorErasureJobs.operator_id, childId))
      .catch(() => undefined);
    await db.delete(operators)
      .where(eq(operators.id, childId))
      .catch(() => undefined);
    await db.delete(operators)
      .where(eq(operators.id, revokePartnerId))
      .catch(() => undefined);
  });

  it('serializes child creation behind partner erasure', async () => {
    await db.insert(operators).values({
      id: partnerId,
      email: `${partnerId}@test.invalid`,
      api_key_hash: `hash_${partnerId}`,
      is_partner: true,
    });
    const operatorRepo = new OperatorRepository(db);
    const tenantService = new PartnerTenantService({ db, operatorRepo } as never);
    const erasure = new OperatorErasureService({
      db,
      operatorRepo,
      archive: { eraseOperatorArchive: async () => undefined },
    });
    let releaseLock!: () => void;
    let lockHeld!: () => void;
    const releaseLockPromise = new Promise<void>((resolve) => { releaseLock = resolve; });
    const lockHeldPromise = new Promise<void>((resolve) => { lockHeld = resolve; });

    const erase = db.transaction((tx) => erasure.beginErasureInTransaction(partnerId, tx, {
      afterLock: async () => {
        lockHeld();
        await releaseLockPromise;
      },
    }));
    await lockHeldPromise;

    const create = tenantService.createTenant(partnerId, {
      external_ref: `customer_${suffix}`,
    });
    const stateBeforeRelease = await Promise.race([
      create.then(() => 'settled' as const, () => 'settled' as const),
      new Promise<'blocked'>((resolve) => setTimeout(() => resolve('blocked'), 100)),
    ]);

    releaseLock();
    await expect(erase).resolves.toBeUndefined();
    await expect(create).rejects.toThrow(/not active/i);
    expect(stateBeforeRelease).toBe('blocked');
    expect(await db.query.operators.findFirst({
      where: eq(operators.parent_operator_id, partnerId),
    })).toBeUndefined();
  });

  it('serializes child revocation with the child lifecycle lock', async () => {
    await db.insert(operators).values([
      {
        id: revokePartnerId,
        email: `${revokePartnerId}@test.invalid`,
        api_key_hash: `hash_${revokePartnerId}`,
        is_partner: true,
      },
      {
        id: childId,
        email: `${childId}@test.invalid`,
        api_key_hash: `hash_${childId}`,
        parent_operator_id: revokePartnerId,
      },
    ]);
    const tenantService = new PartnerTenantService({
      db,
      operatorRepo: new OperatorRepository(db),
    });
    let releaseLock!: () => void;
    let lockHeld!: () => void;
    const releaseLockPromise = new Promise<void>((resolve) => { releaseLock = resolve; });
    const lockHeldPromise = new Promise<void>((resolve) => { lockHeld = resolve; });

    const lifecycle = db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, childId);
      lockHeld();
      await releaseLockPromise;
    });
    await lockHeldPromise;

    const revoke = tenantService.revokeTenant(childId, revokePartnerId);
    const stateBeforeRelease = await Promise.race([
      revoke.then(() => 'settled' as const, () => 'settled' as const),
      new Promise<'blocked'>((resolve) => setTimeout(() => resolve('blocked'), 100)),
    ]);

    releaseLock();
    await lifecycle;
    await expect(revoke).resolves.toEqual({ transitioned: true });
    expect(stateBeforeRelease).toBe('blocked');
    expect(await db.query.operatorErasureJobs.findFirst({
      where: eq(operatorErasureJobs.operator_id, childId),
    })).toBeUndefined();
  });
});
