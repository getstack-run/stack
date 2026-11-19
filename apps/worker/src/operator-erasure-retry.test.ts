import { afterAll, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  auditArchiveSegments,
  createDb,
  operatorErasureJobs,
  operators,
} from '@stack/shared';
import {
  AuditArchiveService,
  OperatorErasureService,
  OperatorRepository,
  type ObjectStore,
} from '@stack/vault';
import { createOperatorErasureRetryGate } from './operator-erasure-retry.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

class RetryStore implements ObjectStore {
  readonly durable = true;
  readonly description = 'operator erasure retry test';
  readonly objects = new Map<string, Buffer>();
  failOnce = true;

  async put(key: string, body: Buffer) { this.objects.set(key, Buffer.from(body)); }
  async get(key: string) { return this.objects.get(key) ?? null; }
  async exists(key: string) { return this.objects.has(key); }
  async list(prefix: string) {
    return { keys: [...this.objects.keys()].filter((key) => key.startsWith(prefix)).sort() };
  }
  async check() {}
  async delete(key: string) {
    if (this.failOnce) {
      this.failOnce = false;
      throw new Error('synthetic transient object failure');
    }
    this.objects.delete(key);
  }
}

describeWithDb('operator erasure worker retry', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_erasure_worker_${suffix}`;

  afterAll(async () => {
    await db.delete(auditArchiveSegments).where(eq(auditArchiveSegments.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operatorErasureJobs).where(eq(operatorErasureJobs.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('claims one due job and completes a partial object-deletion retry', async () => {
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${suffix}`,
    });
    const prefix = `audit/${operatorId}/`;
    const store = new RetryStore();
    await store.put(`${prefix}indexed.ndjson.gz`, Buffer.from('indexed'));
    await store.put(`${prefix}unindexed.tmp`, Buffer.from('unindexed'));
    await db.insert(auditArchiveSegments).values({
      id: `aseg_erasure_worker_${suffix}`,
      operator_id: operatorId,
      from_timestamp: 1,
      to_timestamp: 2,
      row_count: 1,
      object_key: `${prefix}indexed.ndjson.gz`,
      byte_size: 7,
      content_hash: 'a'.repeat(64),
      first_entry_hash: 'b'.repeat(64),
      first_prev_entry_hash: null,
      last_entry_hash: 'c'.repeat(64),
    });
    const operatorRepo = new OperatorRepository(db);
    const erasure = new OperatorErasureService({
      db,
      operatorRepo,
      archive: new AuditArchiveService({ db, store }),
    });
    await expect(erasure.requestErasure(operatorId)).resolves.toEqual({ status: 'pending' });
    await db.update(operatorErasureJobs)
      .set({ next_attempt_at: new Date(0) })
      .where(eq(operatorErasureJobs.operator_id, operatorId));

    const run = createOperatorErasureRetryGate(erasure);
    await expect(run()).resolves.toEqual({ claimed: 1, completed: 1, pending: 0 });

    expect([...store.objects.keys()].filter((key) => key.startsWith(prefix))).toEqual([]);
    expect(await db.query.operators.findFirst({ where: eq(operators.id, operatorId) }))
      .toBeUndefined();
    expect(await db.query.operatorErasureJobs.findFirst({
      where: eq(operatorErasureJobs.operator_id, operatorId),
    })).toBeUndefined();
  });
});

describe('operator erasure worker cadence', () => {
  it('queries due jobs at most once every five minutes', async () => {
    let now = 1_000_000;
    const claimDueJobs = vi.fn(async () => []);
    const run = createOperatorErasureRetryGate(
      { claimDueJobs, finalizeClaim: vi.fn() } as never,
      () => now,
    );

    await run();
    await run();
    now += 299_999;
    await run();
    expect(claimDueJobs).toHaveBeenCalledOnce();

    now += 1;
    await run();
    expect(claimDueJobs).toHaveBeenCalledTimes(2);
  });
});
