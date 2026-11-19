import { afterAll, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { createDb, hashApiKey, operatorErasureJobs, operators } from '@stack/shared';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';
import { OperatorService } from './operator-service.js';
import { OperatorErasureService } from './operator-erasure-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = isDedicatedVaultTestDatabase(DATABASE_URL) ? describe : describe.skip;

describeWithDb('OperatorErasureService durable saga', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_erasure_partial_${suffix}`;
  const email = `${operatorId}@test.invalid`;
  const cleanupIds = new Set([operatorId]);

  afterAll(async () => {
    for (const id of [...cleanupIds].reverse()) {
      await db
        .delete(operators)
        .where(eq(operators.id, id))
        .catch(() => undefined);
    }
  });

  it('partial object failure commits deleted status and returns pending', async () => {
    const apiKey = `sk_live_erasure_${suffix}`;
    await db.insert(operators).values({
      id: operatorId,
      email,
      api_key_hash: hashApiKey(apiKey),
    });
    const service = new OperatorService(new OperatorRepository(db));
    service.setDb(db);
    const erasure = new OperatorErasureService({
      db,
      operatorRepo: new OperatorRepository(db),
      archive: {
        async eraseOperatorArchive() {
          throw new Error('synthetic object deletion failure');
        },
      },
    });
    service.setErasureService(erasure);

    const result = await service.deleteAccount(operatorId, email);

    expect(result).toEqual({ status: 'pending' });
    const operator = await db.query.operators.findFirst({
      where: eq(operators.id, operatorId),
    });
    expect(operator?.status).toBe('deleted');
    expect(
      await db.query.operatorErasureJobs.findFirst({
        where: eq(operatorErasureJobs.operator_id, operatorId),
      }),
    ).toMatchObject({
      status: 'pending',
      attempt_count: 1,
      last_error_code: 'database_delete_failed',
    });
    await expect(service.authenticateByApiKey(apiKey)).rejects.toMatchObject({
      code: 'OPERATOR_DELETED',
    });
  });

  it("runs a deployment's own erasure steps first and in order, and does not go on when one fails", async () => {
    const id = `op_erasure_steps_${suffix}`;
    cleanupIds.add(id);
    await db.insert(operators).values({ id, email: `${id}@test.invalid`, api_key_hash: `hash_${id}` });
    const order: string[] = [];
    const eraseOperatorArchive = vi.fn(async () => {
      order.push('archive');
    });
    const first = vi.fn(async () => {
      order.push('first');
    });
    const second = vi
      .fn<(operatorId: string) => Promise<unknown>>()
      .mockRejectedValueOnce(new Error('outside store down'))
      .mockImplementation(async () => {
        order.push('second');
      });
    const erasure = new OperatorErasureService({
      db,
      operatorRepo: new OperatorRepository(db),
      archive: { eraseOperatorArchive },
      before: [
        { code: 'database_delete_failed', run: first },
        { code: 'archive_delete_failed', run: second },
      ],
    });

    expect(await erasure.requestErasure(id)).toEqual({ status: 'pending' });
    expect(first).toHaveBeenCalledWith(id);
    // The failing step names itself on the job, and nothing after it ran: not the archive, not the delete.
    expect(
      await db.query.operatorErasureJobs.findFirst({ where: eq(operatorErasureJobs.operator_id, id) }),
    ).toMatchObject({ status: 'pending', last_error_code: 'archive_delete_failed' });
    expect(eraseOperatorArchive).not.toHaveBeenCalled();

    await db.update(operatorErasureJobs).set({ next_attempt_at: new Date(0) }).where(eq(operatorErasureJobs.operator_id, id));
    const claim = (await erasure.claimDueJobs(10)).find((c) => c.operator_id === id)!;
    expect(await erasure.finalizeClaim(claim)).toEqual({ status: 'completed' });
    expect(order).toEqual(['first', 'first', 'second', 'archive']);
    expect(await db.query.operators.findFirst({ where: eq(operators.id, id) })).toBeUndefined();
  });

  it('rejects a stale worker claim without touching the archive', async () => {
    const id = `op_erasure_stale_${suffix}`;
    cleanupIds.add(id);
    await db.insert(operators).values({
      id,
      email: `${id}@test.invalid`,
      api_key_hash: `hash_${id}`,
    });
    const eraseOperatorArchive = vi.fn(async () => undefined);
    const erasure = new OperatorErasureService({
      db,
      operatorRepo: new OperatorRepository(db),
      archive: { eraseOperatorArchive },
    });
    await db.transaction((tx) => erasure.beginErasureInTransaction(id, tx));
    // Other PostgreSQL suites create due erasure jobs in parallel. Pin this
    // fixture first so the global worker claim cannot select another test's row.
    await db
      .update(operatorErasureJobs)
      .set({ next_attempt_at: new Date(0) })
      .where(eq(operatorErasureJobs.operator_id, id));
    const [first] = await erasure.claimDueJobs(1);
    expect(first?.operator_id).toBe(id);
    expect(first).toBeDefined();
    await db
      .update(operatorErasureJobs)
      .set({ next_attempt_at: new Date(0) })
      .where(eq(operatorErasureJobs.operator_id, id));
    const [second] = await erasure.claimDueJobs(1);
    expect(second?.claim_id).not.toBe(first?.claim_id);

    await expect(erasure.finalizeClaim(first!)).resolves.toEqual({ status: 'pending' });
    expect(eraseOperatorArchive).not.toHaveBeenCalled();
    expect(
      await db.query.operatorErasureJobs.findFirst({
        where: eq(operatorErasureJobs.operator_id, id),
      }),
    ).toMatchObject({ claim_id: second!.claim_id, status: 'processing' });
  });

  it('refuses a partner with a child before status or job changes', async () => {
    const parentId = `op_erasure_parent_${suffix}`;
    const childId = `op_erasure_child_${suffix}`;
    cleanupIds.add(parentId);
    cleanupIds.add(childId);
    await db.insert(operators).values([
      {
        id: parentId,
        email: `${parentId}@test.invalid`,
        api_key_hash: `hash_${parentId}`,
      },
      {
        id: childId,
        email: `${childId}@test.invalid`,
        api_key_hash: `hash_${childId}`,
        parent_operator_id: parentId,
      },
    ]);
    const erasure = new OperatorErasureService({
      db,
      operatorRepo: new OperatorRepository(db),
      archive: { eraseOperatorArchive: async () => undefined },
    });

    await expect(
      db.transaction((tx) => erasure.beginErasureInTransaction(parentId, tx)),
    ).rejects.toThrow(/child tenant/i);
    expect(await db.query.operators.findFirst({ where: eq(operators.id, parentId) })).toMatchObject(
      { status: 'active' },
    );
    expect(
      await db.query.operatorErasureJobs.findFirst({
        where: eq(operatorErasureJobs.operator_id, parentId),
      }),
    ).toBeUndefined();
  });
});
