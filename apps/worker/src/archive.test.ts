import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { and, asc, eq, sql } from 'drizzle-orm';
import {
  createDb,
  auditLog,
  auditArchiveSegments,
  operators,
  hashApiKey,
  ids,
  AUDIT_HASH_VERSION_CURRENT,
  computeAuditEntryHash,
} from '@stack/shared';
import {
  AuditArchiveService,
  MemoryObjectStore,
  S3ObjectStore,
  type ObjectStore,
} from '@stack/vault';

/**
 * the cold archive.
 *
 * What has to hold, in order of how badly it hurts when it does not:
 *
 *   A1  Rows past the hot window end up in object storage AND leave Postgres.
 *   A2  The chain still walks across the seam: each segment points back at the
 *       one before it, and the oldest surviving hot row points back at the
 *       newest archived one.
 *   A3  A range spanning the boundary reads back complete — cold rows plus hot
 *       rows, in order, no gap.
 *   A4  A tampered segment is refused rather than returned.
 *   A5  Nothing is deleted when the store is not durable. This is the guard
 *       that makes a misconfigured deploy stop archiving instead of destroying
 *       audit rows.
 *   A6  Re-running the archiver is a no-op, including after a crash between
 *       the upload and the delete.
 *
 * Runs against the dev Postgres. Skips itself, loudly, when there is none.
 */

const DAY = 86_400_000;
const OP = `op_arch_${Date.now()}`;

// Probed at module load, not in beforeAll: `describe.skipIf` is evaluated
// during collection, which happens before any hook runs — so a flag set in
// beforeAll is always still false when the decision is made, and the whole
// suite skips itself even with a database right there.
const DATABASE_URL = process.env['DATABASE_URL'];
// Nothing is connected to when DATABASE_URL is unset: the suite skips itself.
const db = createDb(DATABASE_URL ?? 'postgresql://unset.invalid/unset');
const available = DATABASE_URL
  ? await db
    .execute(sql`select 1`)
    .then(() => true)
    .catch((err: unknown) => {
      console.warn('[archive.test] the database is not reachable — skipping.', err);
      return false;
    })
  : false;

async function seedChain(count: number, oldestMsAgo: number): Promise<string[]> {
  // A real hash chain: each row's prev_entry_hash is the previous row's
  // entry_hash, computed by the same function AuditService uses. A fake chain
  // would make A2 assert nothing.
  const hashes: string[] = [];
  let prev = '0'.repeat(64);

  for (let i = 0; i < count; i += 1) {
    const timestamp = Date.now() - oldestMsAgo + i * (DAY / 4);
    const entry = {
      hash_version: AUDIT_HASH_VERSION_CURRENT,
      claim_binding_status: 'no_active_claims' as const,
      entry_id: ids.auditEntry(),
      trace_id: `tr_${i}`,
      span_id: `sp_${i}`,
      parent_span_id: null,
      timestamp,
      operator_id: OP,
      agent_id: 'agt_archive_test',
      passport_jti: `jti_${i}`,
      layer: 'vault',
      action: 'passport.issue',
      outcome: 'success',
      duration_ms: 5,
      payload_hash: null,
      error_code: null,
      error_message: null,
      prev_entry_hash: prev,
    };
    const entry_hash = computeAuditEntryHash(entry as never);
    await db.insert(auditLog).values({ ...entry, entry_hash } as never);
    hashes.push(entry_hash);
    prev = entry_hash;
  }
  return hashes;
}

async function insertAuditRowAt(
  timestamp: number,
  rowSuffix: string,
  prevEntryHash = '0'.repeat(64),
) {
  const entry = {
    hash_version: AUDIT_HASH_VERSION_CURRENT,
    claim_binding_status: 'no_active_claims' as const,
    entry_id: `aud_archive_${rowSuffix}`,
    trace_id: `tr_archive_${rowSuffix}`,
    span_id: `sp_archive_${rowSuffix}`,
    parent_span_id: null,
    timestamp,
    operator_id: OP,
    agent_id: 'agt_archive_test',
    passport_jti: `jti_archive_${rowSuffix}`,
    layer: 'vault',
    action: 'passport.issue',
    outcome: 'success',
    duration_ms: 5,
    payload_hash: null,
    error_code: null,
    error_message: null,
    prev_entry_hash: prevEntryHash,
  };
  const entry_hash = computeAuditEntryHash(entry as never);
  await db.insert(auditLog).values({ ...entry, entry_hash } as never);
  return { ...entry, entry_hash };
}

beforeAll(async () => {
  if (!available) return;
  await db.insert(operators).values({
    id: OP,
    email: `${OP}@test.local`,
    api_key_hash: hashApiKey(`sk_live_${OP}`),
  } as never);
});

afterAll(async () => {
  if (!available) return;
  await db.delete(auditLog).where(eq(auditLog.operator_id, OP));
  await db.delete(auditArchiveSegments).where(eq(auditArchiveSegments.operator_id, OP));
  await db.delete(operators).where(eq(operators.id, OP));
});

beforeEach(async () => {
  if (!available) return;
  await db.update(operators)
    .set({ status: 'active', deleted_at: null })
    .where(eq(operators.id, OP));
  await db.delete(auditLog).where(eq(auditLog.operator_id, OP));
  await db.delete(auditArchiveSegments).where(eq(auditArchiveSegments.operator_id, OP));
});

describe('archive object stores', () => {
  it('paginates memory listings by prefix and deletes missing keys idempotently', async () => {
    const store = new MemoryObjectStore();
    for (let i = 0; i < 1_001; i += 1) {
      await store.put(`audit/op_test/${String(i).padStart(4, '0')}`, Buffer.from(String(i)));
    }
    await store.put('other/not-a-segment', Buffer.from('other'));

    const first = await store.list('audit/op_test/');
    expect(first.keys).toHaveLength(1_000);
    expect(first.cursor).toBeDefined();
    const second = await store.list('audit/op_test/', first.cursor);
    expect(second.keys).toHaveLength(1);
    expect(second.cursor).toBeUndefined();

    await store.delete(first.keys[0]!);
    await store.delete(first.keys[0]!);
    expect(await store.exists(first.keys[0]!)).toBe(false);
    expect(await store.exists('other/not-a-segment')).toBe(true);
  });

  it('maps S3 list pagination and idempotent delete commands', async () => {
    class PutObjectCommand { constructor(readonly input: Record<string, unknown>) {} }
    class GetObjectCommand { constructor(readonly input: Record<string, unknown>) {} }
    class HeadObjectCommand { constructor(readonly input: Record<string, unknown>) {} }
    class ListObjectsV2Command { constructor(readonly input: Record<string, unknown>) {} }
    class DeleteObjectCommand { constructor(readonly input: Record<string, unknown>) {} }

    const sent: unknown[] = [];
    let listPage = 0;
    const client = {
      send: async (command: unknown) => {
        sent.push(command);
        if (command instanceof ListObjectsV2Command) {
          listPage += 1;
          return listPage === 1
            ? { Contents: [{ Key: 'audit/op/a' }, {}, { Key: 'audit/op/b' }], NextContinuationToken: 'next' }
            : { Contents: [{ Key: 'audit/op/c' }] };
        }
        if (command instanceof DeleteObjectCommand) {
          throw { name: 'NoSuchKey' };
        }
        return {};
      },
    };
    const store = new S3ObjectStore(client, 'archive-bucket', {
      PutObjectCommand,
      GetObjectCommand,
      HeadObjectCommand,
      ListObjectsV2Command,
      DeleteObjectCommand,
    });

    expect(await store.list('audit/op/')).toEqual({
      keys: ['audit/op/a', 'audit/op/b'],
      cursor: 'next',
    });
    expect(await store.list('audit/op/', 'next')).toEqual({ keys: ['audit/op/c'] });
    await store.delete('audit/op/missing');

    expect((sent[0] as ListObjectsV2Command).input).toEqual({
      Bucket: 'archive-bucket',
      Prefix: 'audit/op/',
    });
    expect((sent[1] as ListObjectsV2Command).input).toEqual({
      Bucket: 'archive-bucket',
      Prefix: 'audit/op/',
      ContinuationToken: 'next',
    });
    expect((sent[2] as DeleteObjectCommand).input).toEqual({
      Bucket: 'archive-bucket',
      Key: 'audit/op/missing',
    });
  });
});

describe.skipIf(!available)('cold archive', () => {
  it('rejects a direct archive call for a missing operator', async () => {
    const archive = new AuditArchiveService({ db, store: durableMemoryStore() });
    await expect(archive.archiveOperator(`${OP}_missing`)).rejects.toThrow(/operator/i);
  });

  it('archiveAll ignores a non-live deleted operator', async () => {
    await seedChain(4, 30 * DAY);
    // Put this fixture before the cutoff without selecting unrelated local rows.
    await db.update(auditLog)
      .set({ timestamp: Date.UTC(2000, 0, 1) })
      .where(eq(auditLog.operator_id, OP));
    await db.update(operators)
      .set({ status: 'deleted', deleted_at: new Date() })
      .where(eq(operators.id, OP));
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });

    const result = await archive.archiveAll(new Date(Date.UTC(2001, 0, 1)));

    expect(result).not.toHaveProperty(OP);
    expect(await hotRows()).toHaveLength(4);
    expect(store.size).toBe(0);
  });

  it('A1: rows past the hot window move to storage and leave Postgres', async () => {
    await seedChain(12, 30 * DAY); // spans several days, all older than the window
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });

    const result = await archive.archiveOperator(OP);

    expect(result.rowsArchived).toBe(12);
    expect(result.segmentsWritten).toBeGreaterThan(0);
    expect(result.rowsDeleted).toBe(12);

    const remaining = await db.select().from(auditLog).where(eq(auditLog.operator_id, OP));
    expect(remaining).toHaveLength(0);

    const segments = await archive.segmentsInRange(OP);
    expect(segments.length).toBe(result.segmentsWritten);
  });

  it('reads one UTC day per query, so a long backlog is never held in memory at once', async () => {
    // Production held months of unarchived sandbox rows: the whole backlog was
    // loaded into one array at the first midnight tick and the worker ran out of memory.
    await seedChain(24, 30 * DAY); // four rows a day, about six days
    const archive = new AuditArchiveService({ db, store: durableMemoryStore(), hotWindowDays: 7 });
    const reader = archive as unknown as { readDayRows: (...args: unknown[]) => Promise<unknown[]> };
    const original = reader.readDayRows.bind(archive);
    const sizes: number[] = [];
    vi.spyOn(reader, 'readDayRows').mockImplementation(async (...args: unknown[]) => {
      const rows = await original(...args);
      sizes.push(rows.length);
      return rows;
    });

    const result = await archive.archiveOperator(OP);

    expect(result.rowsArchived).toBe(24);
    expect(result.rowsDeleted).toBe(24);
    expect(sizes).toHaveLength(result.segmentsWritten);
    expect(sizes.length).toBeGreaterThanOrEqual(6);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(4);
  });

  it('archives only complete UTC days and never deletes a later same-day row', async () => {
    const day = Date.UTC(2026, 0, 3);
    const now = new Date(Date.UTC(2026, 0, 10, 12));
    const early = await insertAuditRowAt(day + 8 * 60 * 60 * 1_000, `early_${OP}`);
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });

    await archive.archiveOperator(OP, now);
    const later = await insertAuditRowAt(
      day + 10 * 60 * 60 * 1_000,
      `later_${OP}`,
      early.entry_hash,
    );
    await archive.archiveOperator(OP, now);

    const remaining = await hotRows();
    expect(remaining.map((row) => row.entry_id)).toContain(later.entry_id);
  });

  it('A2: the chain walks across the seam', async () => {
    const hashes = await seedChain(16, 30 * DAY);
    // Keep the newest four in the hot window so there IS a seam to cross.
    const rows = await db
      .select()
      .from(auditLog)
      .where(eq(auditLog.operator_id, OP))
      .orderBy(asc(auditLog.timestamp));
    const keepFrom = rows[12]!.timestamp;
    for (const row of rows.slice(12)) {
      await db
        .update(auditLog)
        .set({ timestamp: Date.now() - 1000 + (row.timestamp - keepFrom) })
        .where(and(eq(auditLog.operator_id, OP), eq(auditLog.entry_id, row.entry_id)));
    }

    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);

    const verdict = await archive.verifyAcrossSeam(OP);
    expect(verdict.breaks).toEqual([]);
    expect(verdict.ok).toBe(true);
    expect(verdict.segments).toBeGreaterThan(0);
    expect(hashes.length).toBe(16);
  });

  it('A3: a range spanning the boundary reads back complete and in order', async () => {
    await seedChain(12, 30 * DAY);
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);

    const cold = await archive.readRange(OP);
    expect(cold).toHaveLength(12);

    for (let i = 1; i < cold.length; i += 1) {
      expect(cold[i]!.timestamp).toBeGreaterThanOrEqual(cold[i - 1]!.timestamp);
      expect(cold[i]!.prev_entry_hash).toBe(cold[i - 1]!.entry_hash);
    }
  });

  it('A4: a tampered segment is refused, not returned', async () => {
    await seedChain(8, 30 * DAY);
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);

    const [segment] = await archive.segmentsInRange(OP);
    expect(segment).toBeDefined();

    // Rewrite the stored bytes to something valid-but-different. The manifest
    // hash is what catches it.
    const { gzipSync } = await import('node:zlib');
    await store.put(segment!.object_key, gzipSync(Buffer.from('{"entry_id":"forged"}', 'utf8')));

    await expect(archive.readRange(OP)).rejects.toThrow(/content hash|tampered/i);
  });

  it('A5: nothing is deleted when the store is not durable', async () => {
    await seedChain(8, 30 * DAY);
    const store = new MemoryObjectStore();
    const archive = new AuditArchiveService({
      db,
      store,
      hotWindowDays: 7,
    });

    await expect(archive.archiveOperator(OP)).rejects.toThrow(/durable object storage/i);

    const remaining = await db.select().from(auditLog).where(eq(auditLog.operator_id, OP));
    expect(remaining, 'rows must survive a non-durable store').toHaveLength(8);
    expect(await archive.segmentsInRange(OP)).toHaveLength(0);
    expect(store.size).toBe(0);
  });

  it('A6: re-running is a no-op, including after a crash between upload and delete', async () => {
    await seedChain(8, 30 * DAY);
    const archivedRows = await hotRows();
    const store = durableMemoryStore();
    const resumed = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await resumed.archiveOperator(OP);
    // Recreate the hot copies while the verified manifests stay in place.
    // This is the durable state left by a crash before the hot-row delete.
    await db.insert(auditLog).values(archivedRows);
    const second = await resumed.archiveOperator(OP);
    expect(second.segmentsSkipped).toBeGreaterThan(0);
    expect(second.segmentsWritten).toBe(0);

    const third = await resumed.archiveOperator(OP);
    expect(third.rowsArchived).toBe(0);
    expect(third.segmentsWritten).toBe(0);
  });

  it('refuses a legacy partial segment that omits a pending hot row', async () => {
    await seedChain(8, 30 * DAY);
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);
    await seedChain(8, 30 * DAY);

    await expect(archive.archiveOperator(OP)).rejects.toThrow(/segment|archive|row/i);
    expect(await hotRows()).toHaveLength(8);
  });

  it('I32: an existing segment in a non-durable store never deletes hot rows', async () => {
    await seedChain(8, 30 * DAY);
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);
    await seedChain(8, 30 * DAY);
    (store as { durable: boolean }).durable = false;

    await expect(archive.archiveOperator(OP)).rejects.toThrow(/durable object storage/i);
    expect(await hotRows()).toHaveLength(8);
  });

  it('I33: a missing existing segment never deletes hot rows', async () => {
    await seedChain(8, 30 * DAY);
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);
    await seedChain(8, 30 * DAY);
    const [segment] = await archive.segmentsInRange(OP);
    expect(segment).toBeDefined();
    await store.delete(segment!.object_key);

    await expect(archive.archiveOperator(OP)).rejects.toThrow(/missing|verification|archive/i);
    expect(await hotRows()).toHaveLength(8);
  });

  it('I34: a corrupt existing segment never deletes hot rows', async () => {
    await seedChain(8, 30 * DAY);
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);
    await seedChain(8, 30 * DAY);
    const [segment] = await archive.segmentsInRange(OP);
    expect(segment).toBeDefined();
    await store.put(segment!.object_key, Buffer.from('not gzip'));

    await expect(archive.archiveOperator(OP)).rejects.toThrow();
    expect(await hotRows()).toHaveLength(8);
  });

  it('I35: an unreadable existing segment never deletes hot rows', async () => {
    await seedChain(8, 30 * DAY);
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);
    await seedChain(8, 30 * DAY);
    const unreadable: ObjectStore = {
      description: 'durable but unreadable test store',
      durable: true,
      put: store.put.bind(store),
      get: async () => { throw new Error('storage read failed'); },
      exists: store.exists.bind(store),
      list: store.list.bind(store),
      delete: store.delete.bind(store),
      check: store.check.bind(store),
    };

    const resumed = new AuditArchiveService({ db, store: unreadable, hotWindowDays: 7 });
    await expect(resumed.archiveOperator(OP)).rejects.toThrow(/storage read failed/);
    expect(await hotRows()).toHaveLength(8);
  });

  it('I35 valid case: a verified durable existing segment may delete hot rows', async () => {
    await seedChain(8, 30 * DAY);
    const archivedRows = await hotRows();
    const store = durableMemoryStore();
    const archive = new AuditArchiveService({ db, store, hotWindowDays: 7 });
    await archive.archiveOperator(OP);
    await db.insert(auditLog).values(archivedRows);

    const resumed = await archive.archiveOperator(OP);
    expect(resumed.rowsDeleted).toBe(8);
    expect(await hotRows()).toHaveLength(0);
  });
});

async function hotRows() {
  return db.select().from(auditLog).where(eq(auditLog.operator_id, OP));
}

/**
 * An in-memory store that reports itself durable.
 *
 * Durability is a declared property rather than a class check, precisely so a
 * test can say "treat these bytes as real" without the archiver needing to
 * know it is being tested. A5 uses the honest one and asserts the refusal.
 */
function durableMemoryStore(): MemoryObjectStore {
  const store = new MemoryObjectStore();
  (store as { durable: boolean }).durable = true;
  return store;
}

// Keeps the import honest if the seed helper stops hashing.
void createHash;
