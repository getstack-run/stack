import { gzipSync, gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { and, asc, desc, eq, gte, inArray, isNull, lt, lte, or, sql } from 'drizzle-orm';
import {
  type Database,
  acquireOAuthOperatorLock,
  auditLog,
  auditArchiveSegments,
  ids,
  NotFoundError,
  operators,
} from '@stack/shared';
import type { ObjectStore } from './object-store.js';
import { isDurable } from './object-store.js';

/**
 * Cold storage for the audit chain.
 *
 * Long retention windows make Postgres the wrong place to keep old audit
 * rows: they are large, rarely read, and cost the same to hold as the hot
 * ones.
 *
 * So the retention job stops being prune-then-delete and becomes
 * archive-then-delete. Rows past the hot window are written to object storage
 * as gzipped NDJSON, one segment per (operator, UTC day), and only then
 * removed from Postgres.
 *
 * THE CHAIN SURVIVES THE SEAM. Each segment records the hash its oldest row
 * points back to and the hash of its newest row, so a verifier can walk
 * cold → cold → hot without a gap and without trusting us about what used to
 * be there. `verifyAcrossSeam` is that walk.
 *
 * TWO REFUSALS, both deliberate:
 *   - Nothing is deleted unless the store is durable. An in-memory store in
 *     dev would otherwise mean rows deleted from Postgres and evaporated on
 *     restart, which is worse than never archiving.
 *   - Nothing is deleted unless the segment reads back and hashes to what we
 *     wrote. A successful PUT is not evidence the bytes are retrievable.
 */

/** One audit row as it appears inside a segment. Column-for-column. */
export type ArchivedRow = typeof auditLog.$inferSelect;

export interface ArchiveSegment {
  id: string;
  operator_id: string;
  from_timestamp: number;
  to_timestamp: number;
  row_count: number;
  object_key: string;
  content_hash: string;
  first_entry_hash: string;
  first_prev_entry_hash: string | null;
  last_entry_hash: string;
}

export interface ArchiveResult {
  segmentsWritten: number;
  rowsArchived: number;
  rowsDeleted: number;
  /** Days skipped because a segment already existed. */
  segmentsSkipped: number;
}

export interface AuditArchiveServiceDeps {
  db: Database;
  store: ObjectStore;
  /**
   * Days of audit kept in Postgres. Everything older lives in cold storage and
   * is read back on demand. Seven is a working window, not a retention
   * policy — retention is the tier's number and is enforced separately.
   */
  hotWindowDays?: number;
  /**
   * The object-store prefixes of an operator's data a deployment keeps beside the audit record. Erasing an operator
   * deletes and verifies each, so what lives in the same store is gone with the account.
   */
  extraErasePrefixes?: readonly ArchiveErasePrefix[];
}

/** The object-store prefixes of one operator's data, as a deployment names them. */
export type ArchiveErasePrefix = (operatorId: string) => string[];

export interface ArchiveRetentionResult {
  deleted: number;
  failed: number;
}

type ArchiveRetentionErrorCode =
  | 'archive_retention_delete_failed'
  | 'archive_retention_verify_failed';

export type ArchiveErasureErrorCode =
  | 'archive_store_not_durable'
  | 'archive_list_failed'
  | 'archive_delete_failed'
  | 'archive_verify_failed';

export class ArchiveErasureError extends Error {
  constructor(readonly code: ArchiveErasureErrorCode) {
    super(code);
    this.name = 'ArchiveErasureError';
  }
}

const DEFAULT_HOT_WINDOW_DAYS = 7;
const DAY_MS = 86_400_000;
const RETENTION_RETRY_BASE_MS = 5 * 60_000;
const RETENTION_RETRY_MAX_MS = DAY_MS;
type DbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

function utcDayKey(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function objectKeyFor(operatorId: string, day: string): string {
  return `audit/${operatorId}/${day}.ndjson.gz`;
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function isValidRetentionDays(days: number | undefined): days is number {
  return typeof days === 'number' && Number.isFinite(days) && days > 0;
}

/** NDJSON, one row per line, key order fixed by JSON.stringify of the row. */
function serialize(rows: ArchivedRow[]): Buffer {
  return Buffer.from(rows.map((r) => JSON.stringify(r)).join('\n'), 'utf8');
}

function deserialize(buf: Buffer): ArchivedRow[] {
  const text = buf.toString('utf8');
  if (text.length === 0) return [];
  return text.split('\n').map((line) => JSON.parse(line) as ArchivedRow);
}

export class AuditArchiveService {
  private readonly hotWindowDays: number;

  constructor(private readonly deps: AuditArchiveServiceDeps) {
    this.hotWindowDays = deps.hotWindowDays ?? DEFAULT_HOT_WINDOW_DAYS;
  }

  /** The UTC-day boundary. Rows from this day or later stay in Postgres. */
  hotWindowStart(now = new Date()): number {
    const rollingBoundary = new Date(now.getTime() - this.hotWindowDays * DAY_MS);
    return Date.UTC(
      rollingBoundary.getUTCFullYear(),
      rollingBoundary.getUTCMonth(),
      rollingBoundary.getUTCDate(),
    );
  }

  /**
   * Archive one operator's rows older than the hot window, one segment per UTC
   * day, oldest first. Returns what moved.
   *
   * Ordering within a segment is (timestamp, entry_id) ascending — the same
   * order the chain was written in, and the same tiebreaker `AuditService`
   * uses, so a segment read back walks in chain order without re-sorting.
   */
  async archiveOperator(operatorId: string, now = new Date()): Promise<ArchiveResult> {
    return this.deps.db.transaction(async (tx) => {
      // Archive and account deletion share this lock. Keep it through the
      // object-store write and every database change so deletion cannot leave
      // a new cold object behind after it verifies an empty prefix.
      await acquireOAuthOperatorLock(tx, operatorId);
      const [operator] = await tx
        .select({ id: operators.id, status: operators.status })
        .from(operators)
        .where(eq(operators.id, operatorId))
        .for('update');
      if (!operator) throw new NotFoundError('Operator', operatorId);
      if (operator.status !== 'active') {
        throw new Error('Cold archive requires an active operator');
      }
      if (!isDurable(this.deps.store)) {
        throw new Error('Cold archive requires durable object storage');
      }

      return this.archiveOperatorInTransaction(tx, operatorId, now);
    });
  }

  private async archiveOperatorInTransaction(
    tx: DbTransaction,
    operatorId: string,
    now: Date,
  ): Promise<ArchiveResult> {
    const cutoff = this.hotWindowStart(now);
    const result: ArchiveResult = {
      segmentsWritten: 0,
      rowsArchived: 0,
      rowsDeleted: 0,
      segmentsSkipped: 0,
    };

    // A segment is one UTC day, a stable, addressable unit: the same day
    // archived twice resolves to the same key and is skipped rather than
    // duplicated. The days are listed first and each day's rows are read on
    // their own, oldest day first, so memory is bounded by the busiest single
    // day however long the backlog is. (The first version read every row past
    // the window into one array, which a backlog of months turned into an
    // out-of-memory kill of the worker at the midnight tick.)
    const dayExpression = sql<string>`(${auditLog.timestamp} / 86400000)`;
    const days = await tx
      .select({ day: dayExpression })
      .from(auditLog)
      .where(and(eq(auditLog.operator_id, operatorId), lt(auditLog.timestamp, cutoff)))
      .groupBy(dayExpression)
      .orderBy(dayExpression);

    for (const { day: dayNumber } of days) {
      const dayStart = Number(dayNumber) * DAY_MS;
      const dayRows = await this.readDayRows(tx, operatorId, dayStart, cutoff);
      if (dayRows.length === 0) continue;
      const day = utcDayKey(dayStart);
      const objectKey = objectKeyFor(operatorId, day);

      const existing = await tx
        .select({
          id: auditArchiveSegments.id,
          content_hash: auditArchiveSegments.content_hash,
        })
        .from(auditArchiveSegments)
        .where(
          and(
            eq(auditArchiveSegments.operator_id, operatorId),
            eq(auditArchiveSegments.object_key, objectKey),
          ),
        )
        .limit(1);

      if (existing.length > 0) {
        // Already out there. Delete the hot copies and move on — this is the
        // resume path after a crash between PUT and DELETE.
        result.segmentsSkipped += 1;
        if (!isDurable(this.deps.store)) continue;

        // This is the resume path after a crash between segment insert and
        // hot-row delete. Re-read and verify the persisted bytes before the
        // irreversible delete. Any error rolls back this complete operation.
        const compressed = await this.deps.store.get(objectKey);
        if (!compressed) {
          throw new Error('Archive resume failed: persisted segment is missing');
        }
        const plain = gunzipSync(compressed);
        if (sha256Hex(plain) !== existing[0]!.content_hash) {
          throw new Error('Archive resume failed: persisted segment content hash is invalid');
        }
        this.assertRowsPresentInSegment(dayRows, deserialize(plain));
        result.rowsDeleted += await this.deleteRows(tx, operatorId, dayRows);
        continue;
      }

      const plain = serialize(dayRows);
      const contentHash = sha256Hex(plain);
      const compressed = gzipSync(plain, { level: 9 });

      await this.deps.store.put(objectKey, compressed, { contentType: 'application/gzip' });

      // Read it back before deleting anything. A PUT that returned 200 is not
      // proof the bytes are retrievable, and the delete is irreversible.
      const readBack = await this.deps.store.get(objectKey);
      if (!readBack || sha256Hex(gunzipSync(readBack)) !== contentHash) {
        throw new Error(
          `Archive verification failed for ${objectKey}: stored bytes do not match what was written. ` +
            'Nothing deleted.',
        );
      }

      const first = dayRows[0]!;
      const last = dayRows[dayRows.length - 1]!;

      await tx.insert(auditArchiveSegments).values({
        id: ids.auditArchiveSegment(),
        operator_id: operatorId,
        from_timestamp: first.timestamp,
        to_timestamp: last.timestamp,
        row_count: dayRows.length,
        object_key: objectKey,
        byte_size: compressed.length,
        content_hash: contentHash,
        first_entry_hash: first.entry_hash,
        first_prev_entry_hash: first.prev_entry_hash,
        last_entry_hash: last.entry_hash,
      });

      result.segmentsWritten += 1;
      result.rowsArchived += dayRows.length;

      if (isDurable(this.deps.store)) {
        result.rowsDeleted += await this.deleteRows(tx, operatorId, dayRows);
      }
    }

    return result;
  }

  /** One operator's rows of the UTC day starting at `dayStart`, in chain order, none at or after `cutoff`. */
  private async readDayRows(
    tx: DbTransaction,
    operatorId: string,
    dayStart: number,
    cutoff: number,
  ): Promise<ArchivedRow[]> {
    return tx
      .select()
      .from(auditLog)
      .where(and(
        eq(auditLog.operator_id, operatorId),
        gte(auditLog.timestamp, dayStart),
        lt(auditLog.timestamp, Math.min(dayStart + DAY_MS, cutoff)),
      ))
      .orderBy(asc(auditLog.timestamp), asc(auditLog.entry_id));
  }

  /** Every operator with rows past the hot window, oldest work first. */
  async archiveAll(now = new Date()): Promise<Record<string, ArchiveResult>> {
    const cutoff = this.hotWindowStart(now);
    // The inner join excludes legacy audit rows whose operator no longer
    // exists. Migration 0045 keeps those historical orphans in place.
    const operatorRows = await this.deps.db
      .selectDistinct({ operator_id: operators.id })
      .from(operators)
      .innerJoin(auditLog, eq(auditLog.operator_id, operators.id))
      .where(and(eq(operators.status, 'active'), lt(auditLog.timestamp, cutoff)));

    const out: Record<string, ArchiveResult> = {};
    for (const { operator_id } of operatorRows) {
      out[operator_id] = await this.archiveOperator(operator_id, now);
    }
    return out;
  }

  /**
   * Delete cold segments after the operator's published retention period.
   *
   * The segment row is the durable retry job. The row stays in PostgreSQL
   * until object storage confirms that its object is absent. Archive writes,
   * account erasure, and this prune share the operator lifecycle lock.
   */
  async pruneExpiredSegments(
    retentionDays: number,
    now = new Date(),
  ): Promise<ArchiveRetentionResult> {
    if (!isDurable(this.deps.store)) {
      throw new Error('Cold audit retention requires durable object storage');
    }
    if (!isValidRetentionDays(retentionDays)) {
      throw new Error('Cold audit retention found an invalid retention period');
    }

    const candidateOperatorIds = new Set<string>();
    const retryDue = or(
      isNull(auditArchiveSegments.retention_next_attempt_at),
      lte(auditArchiveSegments.retention_next_attempt_at, now),
    );

    const cutoff = now.getTime() - retentionDays * DAY_MS;
    const rows = await this.deps.db
      .selectDistinct({ operator_id: auditArchiveSegments.operator_id })
      .from(auditArchiveSegments)
      .innerJoin(operators, eq(operators.id, auditArchiveSegments.operator_id))
      .where(
        and(
          eq(operators.status, 'active'),
          isNull(operators.audit_retention_days_override),
          lt(auditArchiveSegments.to_timestamp, cutoff),
          retryDue,
        ),
      );
    for (const row of rows) candidateOperatorIds.add(row.operator_id);

    const overridden = await this.deps.db
      .select({
        operator_id: auditArchiveSegments.operator_id,
        to_timestamp: auditArchiveSegments.to_timestamp,
        retention_days: operators.audit_retention_days_override,
      })
      .from(auditArchiveSegments)
      .innerJoin(operators, eq(operators.id, auditArchiveSegments.operator_id))
      .where(
        and(
          eq(operators.status, 'active'),
          sql`${operators.audit_retention_days_override} IS NOT NULL`,
          sql`${operators.audit_retention_days_override} > 0`,
          retryDue,
        ),
      );
    for (const row of overridden) {
      const retentionDays = row.retention_days ?? undefined;
      if (
        isValidRetentionDays(retentionDays) &&
        row.to_timestamp < now.getTime() - retentionDays * DAY_MS
      ) {
        candidateOperatorIds.add(row.operator_id);
      }
    }

    const result: ArchiveRetentionResult = { deleted: 0, failed: 0 };
    for (const operatorId of candidateOperatorIds) {
      const operatorResult = await this.pruneExpiredSegmentsForOperator(
        operatorId,
        retentionDays,
        now,
      );
      result.deleted += operatorResult.deleted;
      result.failed += operatorResult.failed;
    }
    return result;
  }

  private async pruneExpiredSegmentsForOperator(
    operatorId: string,
    defaultRetentionDays: number,
    now: Date,
  ): Promise<ArchiveRetentionResult> {
    return this.deps.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, operatorId);
      const [operator] = await tx
        .select({
          status: operators.status,
          retentionDaysOverride: operators.audit_retention_days_override,
        })
        .from(operators)
        .where(eq(operators.id, operatorId))
        .for('update');
      if (!operator || operator.status !== 'active') return { deleted: 0, failed: 0 };

      const retentionDays = operator.retentionDaysOverride ?? defaultRetentionDays;
      if (!isValidRetentionDays(retentionDays)) {
        throw new Error('Cold audit retention found an invalid retention period');
      }
      const cutoff = now.getTime() - retentionDays * DAY_MS;
      const segments = await tx
        .select()
        .from(auditArchiveSegments)
        .where(
          and(
            eq(auditArchiveSegments.operator_id, operatorId),
            lt(auditArchiveSegments.to_timestamp, cutoff),
            or(
              isNull(auditArchiveSegments.retention_next_attempt_at),
              lte(auditArchiveSegments.retention_next_attempt_at, now),
            ),
          ),
        )
        .orderBy(asc(auditArchiveSegments.to_timestamp))
        .for('update');

      const result: ArchiveRetentionResult = { deleted: 0, failed: 0 };
      for (const segment of segments) {
        try {
          await this.deps.store.delete(segment.object_key);
        } catch {
          await this.recordRetentionFailure(
            tx,
            segment.id,
            segment.retention_attempt_count,
            'archive_retention_delete_failed',
            now,
          );
          result.failed += 1;
          continue;
        }

        let stillPresent: boolean;
        try {
          stillPresent = (await this.deps.store.get(segment.object_key)) !== null;
        } catch {
          stillPresent = true;
        }
        if (stillPresent) {
          await this.recordRetentionFailure(
            tx,
            segment.id,
            segment.retention_attempt_count,
            'archive_retention_verify_failed',
            now,
          );
          result.failed += 1;
          continue;
        }

        await tx
          .delete(auditArchiveSegments)
          .where(eq(auditArchiveSegments.id, segment.id));
        result.deleted += 1;
      }
      return result;
    });
  }

  private async recordRetentionFailure(
    tx: DbTransaction,
    segmentId: string,
    previousAttempts: number,
    errorCode: ArchiveRetentionErrorCode,
    now: Date,
  ): Promise<void> {
    const attemptCount = previousAttempts + 1;
    const retryDelay = Math.min(
      RETENTION_RETRY_MAX_MS,
      RETENTION_RETRY_BASE_MS * 2 ** Math.min(attemptCount - 1, 12),
    );
    await tx
      .update(auditArchiveSegments)
      .set({
        retention_attempt_count: attemptCount,
        retention_next_attempt_at: new Date(now.getTime() + retryDelay),
        retention_last_error_code: errorCode,
      })
      .where(eq(auditArchiveSegments.id, segmentId));
  }

  /**
   * Delete every cold object for one operator, including objects that have no
   * segment row after an interrupted archive, and whatever else a deployment
   * keeps under the same store (`extraErasePrefixes`: the agent drive's files).
   * The caller must hold the shared operator
   * lifecycle lock in the transaction supplied here.
   */
  async eraseOperatorArchive(operatorId: string, tx: DbTransaction): Promise<void> {
    if (!isDurable(this.deps.store)) {
      throw new ArchiveErasureError('archive_store_not_durable');
    }
    const prefixes = [`audit/${operatorId}/`, ...(this.deps.extraErasePrefixes ?? []).flatMap((prefix) => prefix(operatorId))];
    for (const prefix of prefixes) {
      let keys: string[];
      try {
        keys = await this.listArchiveKeys(prefix);
      } catch {
        throw new ArchiveErasureError('archive_list_failed');
      }

      for (const key of keys) {
        try {
          await this.deps.store.delete(key);
        } catch {
          throw new ArchiveErasureError('archive_delete_failed');
        }
      }

      let remaining: string[];
      try {
        remaining = await this.listArchiveKeys(prefix);
      } catch {
        throw new ArchiveErasureError('archive_list_failed');
      }
      if (remaining.length > 0) {
        throw new ArchiveErasureError('archive_verify_failed');
      }
    }

    // Keep the index until external deletion succeeds. A retry then retains
    // the exact list of known segments even after a partial object deletion.
    await tx
      .delete(auditArchiveSegments)
      .where(eq(auditArchiveSegments.operator_id, operatorId));
  }

  /** Segments overlapping [from, to], oldest first. */
  async segmentsInRange(operatorId: string, from?: number, to?: number): Promise<ArchiveSegment[]> {
    const conditions = [eq(auditArchiveSegments.operator_id, operatorId)];
    if (to !== undefined) conditions.push(lte(auditArchiveSegments.from_timestamp, to));
    if (from !== undefined) conditions.push(gte(auditArchiveSegments.to_timestamp, from));

    const rows = await this.deps.db
      .select()
      .from(auditArchiveSegments)
      .where(and(...conditions))
      .orderBy(asc(auditArchiveSegments.from_timestamp));

    return rows as ArchiveSegment[];
  }

  /**
   * Rows from cold storage for a time range.
   *
   * Every fetched segment is hashed against the manifest before its rows are
   * returned. Cold storage is a different trust domain from the database, and
   * an audit product that hands back unverified bytes has stopped being one.
   */
  async readRange(operatorId: string, from?: number, to?: number): Promise<ArchivedRow[]> {
    const segments = await this.segmentsInRange(operatorId, from, to);
    const out: ArchivedRow[] = [];

    for (const segment of segments) {
      const compressed = await this.deps.store.get(segment.object_key);
      if (!compressed) {
        throw new Error(
          `Archive segment ${segment.object_key} is indexed but missing from the store. ` +
            'The chain has a hole; do not report this range as complete.',
        );
      }
      const plain = gunzipSync(compressed);
      if (sha256Hex(plain) !== segment.content_hash) {
        throw new Error(
          `Archive segment ${segment.object_key} does not match its recorded content hash. ` +
            'Treat as tampered.',
        );
      }
      for (const row of deserialize(plain)) {
        if (from !== undefined && row.timestamp < from) continue;
        if (to !== undefined && row.timestamp > to) continue;
        out.push(row);
      }
    }

    return out;
  }

  /**
   * Walk the chain across the cold/hot boundary.
   *
   * The property being checked is continuity: each segment's oldest row must
   * point back at the previous segment's newest row, and the oldest surviving
   * hot row must point back at the last segment's newest row. A break here
   * means either the archive lost a segment or somebody deleted hot rows
   * without archiving them, and both are the same answer to a customer — we
   * cannot prove this range.
   */
  async verifyAcrossSeam(operatorId: string): Promise<{
    ok: boolean;
    segments: number;
    breaks: Array<{ at: string; expected: string; found: string }>;
  }> {
    const segments = await this.segmentsInRange(operatorId);
    const breaks: Array<{ at: string; expected: string; found: string }> = [];

    for (let i = 1; i < segments.length; i += 1) {
      const prev = segments[i - 1]!;
      const cur = segments[i]!;
      if (cur.first_prev_entry_hash !== prev.last_entry_hash) {
        breaks.push({
          at: cur.object_key,
          expected: prev.last_entry_hash,
          found: cur.first_prev_entry_hash ?? '(null)',
        });
      }
    }

    // The seam itself: oldest hot row → newest archived row.
    const last = segments[segments.length - 1];
    if (last) {
      const [oldestHot] = await this.deps.db
        .select({ prev_entry_hash: auditLog.prev_entry_hash, entry_id: auditLog.entry_id })
        .from(auditLog)
        .where(and(eq(auditLog.operator_id, operatorId), sql`true`))
        .orderBy(asc(auditLog.timestamp), asc(auditLog.entry_id))
        .limit(1);

      if (oldestHot && oldestHot.prev_entry_hash !== last.last_entry_hash) {
        breaks.push({
          at: `hot:${oldestHot.entry_id}`,
          expected: last.last_entry_hash,
          found: oldestHot.prev_entry_hash,
        });
      }
    }

    return { ok: breaks.length === 0, segments: segments.length, breaks };
  }

  private async listArchiveKeys(prefix: string): Promise<string[]> {
    const keys: string[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;

    for (;;) {
      const page = await this.deps.store.list(prefix, cursor);
      for (const key of page.keys) {
        if (!key.startsWith(prefix)) {
          throw new Error('Object store returned a key outside the operator archive prefix');
        }
        keys.push(key);
      }
      if (page.cursor === undefined) return keys;
      if (seenCursors.has(page.cursor)) {
        throw new Error('Object store repeated an archive listing cursor');
      }
      seenCursors.add(page.cursor);
      cursor = page.cursor;
    }
  }

  private async deleteRows(
    tx: DbTransaction,
    operatorId: string,
    rows: ArchivedRow[],
  ): Promise<number> {
    if (rows.length === 0) return 0;
    let deletedCount = 0;
    const chunkSize = 5_000;
    for (let offset = 0; offset < rows.length; offset += chunkSize) {
      const entryIds = rows
        .slice(offset, offset + chunkSize)
        .map((row) => row.entry_id);
      const deleted = await tx
        .delete(auditLog)
        .where(
          and(
            eq(auditLog.operator_id, operatorId),
            inArray(auditLog.entry_id, entryIds),
          ),
        )
        .returning({ entry_id: auditLog.entry_id });
      deletedCount += deleted.length;
    }
    return deletedCount;
  }

  private assertRowsPresentInSegment(
    hotRows: ArchivedRow[],
    archivedRows: ArchivedRow[],
  ): void {
    const archivedById = new Map(archivedRows.map((row) => [row.entry_id, row]));
    for (const hotRow of hotRows) {
      const archivedRow = archivedById.get(hotRow.entry_id);
      if (
        !archivedRow
        || archivedRow.operator_id !== hotRow.operator_id
        || archivedRow.timestamp !== hotRow.timestamp
        || archivedRow.entry_hash !== hotRow.entry_hash
        || archivedRow.prev_entry_hash !== hotRow.prev_entry_hash
        || archivedRow.payload_hash !== hotRow.payload_hash
      ) {
        throw new Error('Archive resume failed: persisted segment does not contain every pending hot row');
      }
    }
  }
}

// Unused-import suppressor — `desc` kept for the reverse-order reads the
// evidence-pack path will want.
void desc;
