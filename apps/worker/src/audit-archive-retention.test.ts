import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { eq, sql } from 'drizzle-orm';
import {
  acquireOAuthOperatorLock,
  AUDIT_RETENTION_DAYS,
  auditArchiveSegments,
  createDb,
  hashApiKey,
  operators,
} from '@stack/shared';
import {
  AuditArchiveService,
  MemoryObjectStore,
  type ObjectStore,
} from '@stack/vault';

const DAY_MS = 86_400_000;
/** Past the year every account keeps its record. */
const EXPIRED_DAYS = AUDIT_RETENTION_DAYS + 1;
const OPERATOR_ID = `op_archive_retention_${Date.now()}`;
const DATABASE_URL = process.env['DATABASE_URL'];
// Nothing is connected to when DATABASE_URL is unset: the suite skips itself.
const db = createDb(DATABASE_URL ?? 'postgresql://unset.invalid/unset');
const available = DATABASE_URL
  ? await db
    .execute(sql`select 1`)
    .then(() => true)
    .catch(() => false)
  : false;

function durableStore(): MemoryObjectStore {
  const store = new MemoryObjectStore();
  (store as { durable: boolean }).durable = true;
  return store;
}

async function seedSegment(params: {
  id: string;
  key: string;
  toTimestamp: number;
  store: ObjectStore;
}) {
  await params.store.put(params.key, Buffer.from(params.id));
  await db.insert(auditArchiveSegments).values({
    id: params.id,
    operator_id: OPERATOR_ID,
    from_timestamp: params.toTimestamp - DAY_MS,
    to_timestamp: params.toTimestamp,
    row_count: 1,
    object_key: params.key,
    byte_size: params.id.length,
    content_hash: 'a'.repeat(64),
    first_entry_hash: 'b'.repeat(64),
    first_prev_entry_hash: null,
    last_entry_hash: 'b'.repeat(64),
  });
}

beforeAll(async () => {
  if (!available) return;
  await db.insert(operators).values({
    id: OPERATOR_ID,
    email: `${OPERATOR_ID}@test.local`,
    api_key_hash: hashApiKey(`sk_live_${OPERATOR_ID}`),
    tier: 'free',
  } as never);
});

beforeEach(async () => {
  if (!available) return;
  await db.delete(auditArchiveSegments).where(eq(auditArchiveSegments.operator_id, OPERATOR_ID));
  await db
    .update(operators)
    .set({ status: 'active', tier: 'free', audit_retention_days_override: null })
    .where(eq(operators.id, OPERATOR_ID));
});

afterAll(async () => {
  if (!available) return;
  await db.delete(auditArchiveSegments).where(eq(auditArchiveSegments.operator_id, OPERATOR_ID));
  await db.delete(operators).where(eq(operators.id, OPERATOR_ID));
});

describe.skipIf(!available)('cold audit retention', () => {
  it('deletes an expired object before its segment row', async () => {
    const now = new Date('2026-08-10T12:00:00.000Z');
    const store = durableStore();
    const key = `audit/${OPERATOR_ID}/expired.ndjson.gz`;
    await seedSegment({
      id: 'aseg_retention_expired',
      key,
      // Past the year every account keeps.
      toTimestamp: now.getTime() - EXPIRED_DAYS * DAY_MS,
      store,
    });
    const archive = new AuditArchiveService({ db, store });

    const result = await archive.pruneExpiredSegments(AUDIT_RETENTION_DAYS, now);

    expect(result).toEqual({ deleted: 1, failed: 0 });
    expect(await store.exists(key)).toBe(false);
    const rows = await db
      .select()
      .from(auditArchiveSegments)
      .where(eq(auditArchiveSegments.id, 'aseg_retention_expired'));
    expect(rows).toHaveLength(0);
  });

  it('keeps a year of record for an account on any tier, the free tier included', async () => {
    const now = new Date('2026-08-10T12:00:00.000Z');
    const store = durableStore();
    const key = `audit/${OPERATOR_ID}/inside-the-year.ndjson.gz`;
    await seedSegment({
      id: 'aseg_retention_inside_year',
      key,
      // Younger than a year.
      toTimestamp: now.getTime() - 100 * DAY_MS,
      store,
    });
    const archive = new AuditArchiveService({ db, store });

    const result = await archive.pruneExpiredSegments(AUDIT_RETENTION_DAYS, now);

    expect(result).toEqual({ deleted: 0, failed: 0 });
    expect(await store.exists(key)).toBe(true);
  });

  it('uses the operator retention override', async () => {
    const now = new Date('2026-08-10T12:00:00.000Z');
    const store = durableStore();
    const key = `audit/${OPERATOR_ID}/override.ndjson.gz`;
    await db
      .update(operators)
      .set({ audit_retention_days_override: 400 })
      .where(eq(operators.id, OPERATOR_ID));
    await seedSegment({
      id: 'aseg_retention_override',
      key,
      // Past the year every account keeps, inside the override's 400 days.
      toTimestamp: now.getTime() - 380 * DAY_MS,
      store,
    });
    const archive = new AuditArchiveService({ db, store });

    const result = await archive.pruneExpiredSegments(AUDIT_RETENTION_DAYS, now);

    expect(result).toEqual({ deleted: 0, failed: 0 });
    expect(await store.exists(key)).toBe(true);
  });

  it('keeps durable retry state after an object-store failure', async () => {
    const now = new Date('2026-08-10T12:00:00.000Z');
    const store = durableStore();
    const key = `audit/${OPERATOR_ID}/retry.ndjson.gz`;
    await seedSegment({
      id: 'aseg_retention_retry',
      key,
      toTimestamp: now.getTime() - EXPIRED_DAYS * DAY_MS,
      store,
    });
    const originalDelete = store.delete.bind(store);
    store.delete = async () => {
      throw new Error('synthetic object-store failure');
    };
    const archive = new AuditArchiveService({ db, store });

    const failed = await archive.pruneExpiredSegments(AUDIT_RETENTION_DAYS, now);

    expect(failed).toEqual({ deleted: 0, failed: 1 });
    const [pending] = await db
      .select()
      .from(auditArchiveSegments)
      .where(eq(auditArchiveSegments.id, 'aseg_retention_retry'));
    expect(pending?.retention_attempt_count).toBe(1);
    expect(pending?.retention_last_error_code).toBe('archive_retention_delete_failed');
    expect(pending?.retention_next_attempt_at?.getTime()).toBeGreaterThan(now.getTime());

    store.delete = originalDelete;
    const beforeRetry = await archive.pruneExpiredSegments(
      AUDIT_RETENTION_DAYS,
      new Date(now.getTime() + 1_000),
    );
    expect(beforeRetry).toEqual({ deleted: 0, failed: 0 });
    expect(await store.exists(key)).toBe(true);

    const afterRetry = await archive.pruneExpiredSegments(
      AUDIT_RETENTION_DAYS,
      new Date(now.getTime() + DAY_MS),
    );
    expect(afterRetry).toEqual({ deleted: 1, failed: 0 });
    expect(await store.exists(key)).toBe(false);
  });

  it('waits for the operator lifecycle lock', async () => {
    const now = new Date('2026-08-10T12:00:00.000Z');
    const store = durableStore();
    const key = `audit/${OPERATOR_ID}/locked.ndjson.gz`;
    await seedSegment({
      id: 'aseg_retention_locked',
      key,
      toTimestamp: now.getTime() - EXPIRED_DAYS * DAY_MS,
      store,
    });
    const archive = new AuditArchiveService({ db, store });
    let releaseLock!: () => void;
    const held = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });
    let lockReady!: () => void;
    const ready = new Promise<void>((resolve) => {
      lockReady = resolve;
    });
    const blocker = db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, OPERATOR_ID);
      lockReady();
      await held;
    });
    await ready;

    let settled = false;
    const pruning = archive
      .pruneExpiredSegments(AUDIT_RETENTION_DAYS, now)
      .finally(() => {
        settled = true;
      });
    await new Promise((resolve) => setTimeout(resolve, 75));
    expect(settled).toBe(false);

    releaseLock();
    await blocker;
    expect(await pruning).toEqual({ deleted: 1, failed: 0 });
  });
});
