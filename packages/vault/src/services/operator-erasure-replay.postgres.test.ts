// An account that was erased and comes back with a restore is erased again from the list of erased accounts.

import { afterAll, describe, expect, it, vi } from 'vitest';
import { eq, sql } from 'drizzle-orm';
import { createDb, erasedOperators, operators } from '@stack/shared';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';
import { OperatorErasureService, type ErasureStep } from './operator-erasure-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = isDedicatedVaultTestDatabase(DATABASE_URL) ? describe : describe.skip;

const STEP = 'outside_erase_failed';

/** Something an account keeps outside the database, which a restore can bring back. */
class OutsideStore {
  readonly held = new Set<string>();
  private failures = 0;
  failNext(times = 1): void {
    this.failures += times;
  }
  step(): ErasureStep {
    return {
      code: STEP,
      run: async (id) => {
        if (this.failures > 0) {
          this.failures -= 1;
          throw new Error('store down');
        }
        return { removed: this.held.delete(id) ? 1 : 0 };
      },
      found: (result) => (result as { removed: number }).removed > 0,
    };
  }
}

describeWithDb('erasures after a restore', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const created = new Set<string>();

  afterAll(async () => {
    for (const id of created) await db.delete(operators).where(eq(operators.id, id)).catch(() => undefined);
    await (db as unknown as { $client: { end(o: { timeout: number }): Promise<void> } }).$client.end({ timeout: 5 });
  });

  async function newOperator(tag: string): Promise<string> {
    const id = `op_replay_${tag}_${suffix}`;
    created.add(id);
    await db.insert(operators).values({ id, email: `${id}@test.invalid`, api_key_hash: `hash_${id}` });
    return id;
  }

  function service(outside: OutsideStore) {
    return new OperatorErasureService({
      db,
      operatorRepo: new OperatorRepository(db),
      archive: { eraseOperatorArchive: vi.fn(async () => undefined) },
      before: [outside.step()],
    });
  }

  it('writes the erased account to the list in the transaction that deletes it, and nowhere else', async () => {
    const erasure = service(new OutsideStore());
    const id = await newOperator('listed');
    const bystander = await newOperator('bystander');
    expect(await erasure.requestErasure(id)).toEqual({ status: 'completed' });
    const listed = await db.select().from(erasedOperators).where(eq(erasedOperators.operator_id, id));
    expect(listed).toHaveLength(1);
    expect(Object.keys(listed[0]!).sort()).toEqual(['erased_at', 'operator_id']);
    expect(await db.select().from(erasedOperators).where(eq(erasedOperators.operator_id, bystander))).toEqual([]);

    // A delete that rolls back leaves no entry: the account is still there and was not erased.
    const failing = await newOperator('rolledback');
    await expect(
      db.transaction(async (tx) => {
        await new OperatorRepository(db).deleteById(failing, tx);
        throw new Error('rolled back');
      }),
    ).rejects.toThrow('rolled back');
    expect(await db.select().from(erasedOperators).where(eq(erasedOperators.operator_id, failing))).toEqual([]);
    expect(await db.query.operators.findFirst({ where: eq(operators.id, failing) })).toBeDefined();
  });

  it('refuses to change or remove a row of the list', async () => {
    const id = await newOperator('append');
    await service(new OutsideStore()).requestErasure(id);
    await expect(db.update(erasedOperators).set({ erased_at: new Date(0) }).where(eq(erasedOperators.operator_id, id))).rejects.toThrow();
    await expect(db.delete(erasedOperators).where(eq(erasedOperators.operator_id, id))).rejects.toThrow();
    // Erasing the same account again changes nothing.
    await db.insert(erasedOperators).values({ operator_id: id }).onConflictDoNothing();
    expect(await db.select().from(erasedOperators).where(eq(erasedOperators.operator_id, id))).toHaveLength(1);
  });

  it('removes again what a restore brought back outside the database, and leaves live accounts alone', async () => {
    const outside = new OutsideStore();
    const erasure = service(outside);
    const gone = await newOperator('outside');
    const live = await newOperator('live');
    outside.held.add(gone);
    outside.held.add(live);
    expect(await erasure.requestErasure(gone)).toEqual({ status: 'completed' });
    expect(outside.held.has(gone)).toBe(false);

    // The store is restored from a snapshot taken before the erasure.
    outside.held.add(gone);

    const report = await erasure.reapplyErasures();
    expect(report.removed[STEP]).toBeGreaterThanOrEqual(1);
    expect(report.failed).toEqual([]);
    expect(outside.held.has(gone)).toBe(false);
    expect(outside.held.has(live)).toBe(true);

    // Run again: nothing is left to remove.
    expect((await erasure.reapplyErasures()).removed[STEP] ?? 0).toBe(0);
  });

  it('erases an account that is back in the database only when told to, and then through the whole erasure', async () => {
    const outside = new OutsideStore();
    const erasure = service(outside);
    const id = await newOperator('restored');
    outside.held.add(id);
    expect(await erasure.requestErasure(id)).toEqual({ status: 'completed' });

    // The database and the store are both restored from before the erasure: the operator row and what it kept are
    // back, while the list (kept beyond the restore point) still has the account.
    await db.insert(operators).values({ id, email: `${id}@test.invalid`, api_key_hash: `hash_${id}` });
    outside.held.add(id);

    const check = await erasure.reapplyErasures();
    expect(check.present).toContain(id);
    expect(check.reerased).toBe(0);
    expect(await db.query.operators.findFirst({ where: eq(operators.id, id) })).toBeDefined();
    expect(outside.held.has(id)).toBe(true);

    const applied = await erasure.reapplyErasures({ apply: true });
    expect(applied.present).toContain(id);
    expect(applied.reerased).toBeGreaterThanOrEqual(1);
    expect(applied.pending).not.toContain(id);
    expect(await db.query.operators.findFirst({ where: eq(operators.id, id) })).toBeUndefined();
    expect(outside.held.has(id)).toBe(false);

    expect((await erasure.reapplyErasures({ apply: true })).present).not.toContain(id);
  });

  it('reports an account it could not reach the store for and goes on with the rest', async () => {
    const outside = new OutsideStore();
    const erasure = service(outside);
    const first = await newOperator('down1');
    const second = await newOperator('down2');
    for (const id of [first, second]) {
      outside.held.add(id);
      await erasure.requestErasure(id);
      outside.held.add(id);
    }
    outside.failNext(1);
    const report = await erasure.reapplyErasures();
    expect(report.failed.length).toBeGreaterThanOrEqual(1);
    expect(report.failed.every((f) => f.code === STEP)).toBe(true);
    // Everything else on the list was still looked at, and a second run finishes what the first could not.
    expect(report.checked).toBeGreaterThanOrEqual(2);
    expect((await erasure.reapplyErasures()).failed).toEqual([]);
    expect(outside.held.has(first)).toBe(false);
    expect(outside.held.has(second)).toBe(false);
  });

  it('pages through a list longer than a page', async () => {
    const outside = new OutsideStore();
    const erasure = service(outside);
    const ids = [await newOperator('page1'), await newOperator('page2'), await newOperator('page3')];
    for (const id of ids) {
      outside.held.add(id);
      await erasure.requestErasure(id);
      outside.held.add(id);
    }
    const before = (await db.execute(sql`select count(*)::int as n from erased_operators`)) as unknown as Array<{ n: number }>;
    const report = await erasure.reapplyErasures({ pageSize: 2 });
    expect(report.checked).toBe(before[0]!.n);
    for (const id of ids) expect(outside.held.has(id)).toBe(false);
  });
});
