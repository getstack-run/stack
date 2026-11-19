import { afterAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  acquireOAuthOperatorLock,
  auditArchiveSegments,
  auditLog,
  computeAuditEntryHash,
  createDb,
  NotFoundError,
  operatorErasureJobs,
  operators,
} from '@stack/shared';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { AuditArchiveService } from './audit-archive-service.js';
import { OperatorService } from './operator-service.js';
import { OperatorErasureService } from './operator-erasure-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

class ListingStore {
  readonly description = 'archive deletion test store';
  readonly durable = true;
  readonly objects = new Map<string, Buffer>();
  failDeleteOnceFor: string | null = null;
  private failed = false;
  putBarrier: { reached: () => void; wait: Promise<void> } | null = null;

  async put(key: string, body: Buffer): Promise<void> {
    this.objects.set(key, Buffer.from(body));
    if (this.putBarrier) {
      this.putBarrier.reached();
      await this.putBarrier.wait;
    }
  }

  async get(key: string): Promise<Buffer | null> {
    return this.objects.get(key) ?? null;
  }

  async exists(key: string): Promise<boolean> {
    return this.objects.has(key);
  }

  async list(prefix: string, cursor?: string): Promise<{ keys: string[]; cursor?: string }> {
    const keys = [...this.objects.keys()].filter((key) => key.startsWith(prefix)).sort();
    const offset = cursor ? Number(cursor) : 0;
    const page = keys.slice(offset, offset + 1);
    const next = offset + page.length;
    return next < keys.length ? { keys: page, cursor: String(next) } : { keys: page };
  }

  async delete(key: string): Promise<void> {
    if (key === this.failDeleteOnceFor && !this.failed) {
      this.failed = true;
      throw new Error('synthetic object delete failure');
    }
    this.objects.delete(key);
  }
}

function auditRow(entryId: string, operatorId: string) {
  const row = {
    hash_version: 2 as const,
    entry_id: entryId,
    trace_id: `trace_${entryId}`,
    span_id: `span_${entryId}`,
    timestamp: Date.now() - 30 * 86_400_000,
    operator_id: operatorId,
    agent_id: 'system',
    passport_jti: 'none',
    layer: 'vault',
    action: 'archive.deletion_test',
    outcome: 'success',
    prev_entry_hash: '0'.repeat(64),
    claim_binding_status: 'no_active_claims' as const,
  };
  return { ...row, entry_hash: computeAuditEntryHash(row) };
}

describeWithDb('audit archive lifecycle and account deletion', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const createdOperators = new Set<string>();

  async function createOperator(label: string) {
    const id = `op_archive_${label}_${suffix}`;
    const email = `${id}@test.invalid`;
    createdOperators.add(id);
    await db.insert(operators).values({ id, email, api_key_hash: `hash_${id}` });
    return { id, email };
  }

  async function seedSegment(operatorId: string, objectKey: string) {
    await db.insert(auditArchiveSegments).values({
      id: `aaseg_${Math.random().toString(36).slice(2)}`,
      operator_id: operatorId,
      from_timestamp: 1,
      to_timestamp: 2,
      row_count: 1,
      object_key: objectKey,
      byte_size: 10,
      content_hash: 'a'.repeat(64),
      first_entry_hash: 'b'.repeat(64),
      first_prev_entry_hash: null,
      last_entry_hash: 'c'.repeat(64),
    });
  }

  afterAll(async () => {
    for (const id of createdOperators) {
      await db.delete(auditLog).where(eq(auditLog.operator_id, id)).catch(() => undefined);
      await db.delete(auditArchiveSegments).where(eq(auditArchiveSegments.operator_id, id)).catch(() => undefined);
      await db.delete(operators).where(eq(operators.id, id)).catch(() => undefined);
    }
  });

  it('refuses to archive a missing operator', async () => {
    const archive = new AuditArchiveService({ db, store: new ListingStore() as never });
    await expect(archive.archiveOperator(`op_missing_archive_${suffix}`)).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('holds the operator lifecycle lock until object storage work finishes', async () => {
    const op = await createOperator('lock');
    await db.insert(auditLog).values(auditRow(`aud_archive_lock_${suffix}`, op.id));
    let releasePut!: () => void;
    let putReached!: () => void;
    const store = new ListingStore();
    store.putBarrier = {
      reached: () => putReached(),
      wait: new Promise<void>((resolve) => { releasePut = resolve; }),
    };
    const reached = new Promise<void>((resolve) => { putReached = resolve; });
    const archive = new AuditArchiveService({ db, store: store as never, hotWindowDays: 7 });
    const archiving = archive.archiveOperator(op.id);
    await reached;

    const competingLock = db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, op.id);
    });
    const state = await Promise.race([
      competingLock.then(() => 'settled' as const),
      new Promise<'blocked'>((resolve) => setTimeout(() => resolve('blocked'), 100)),
    ]);
    releasePut();
    await archiving;
    await competingLock;

    expect(state).toBe('blocked');
  });

  it('fails closed when normal deletion has no archive eraser', async () => {
    const op = await createOperator('missing_wiring');
    const service = new OperatorService(new OperatorRepository(db));
    service.setDb(db);

    await expect(service.deleteAccount(op.id, op.email)).rejects.toThrow(/erasure service/i);
    expect(await db.query.operators.findFirst({ where: eq(operators.id, op.id) })).toBeDefined();
  });

  it('deletes indexed and unindexed archive objects before normal account deletion', async () => {
    const op = await createOperator('normal_delete');
    const prefix = `audit/${op.id}/`;
    const store = new ListingStore();
    await store.put(`${prefix}indexed.ndjson.gz`, Buffer.from('indexed'));
    await store.put(`${prefix}unindexed.tmp`, Buffer.from('unindexed'));
    await store.put('audit/another-operator/keep', Buffer.from('keep'));
    await seedSegment(op.id, `${prefix}indexed.ndjson.gz`);
    const archive = new AuditArchiveService({ db, store: store as never });
    const service = new OperatorService(new OperatorRepository(db));
    service.setDb(db);
    const erasure = new OperatorErasureService({
      db,
      operatorRepo: new OperatorRepository(db),
      archive,
    });
    service.setErasureService(erasure);

    await expect(service.deleteAccount(op.id, op.email)).resolves.toEqual({ status: 'completed' });

    expect([...store.objects.keys()]).toEqual(['audit/another-operator/keep']);
    expect(await db.query.auditArchiveSegments.findFirst({
      where: eq(auditArchiveSegments.operator_id, op.id),
    })).toBeUndefined();
  });

  it('retries external deletion without losing the operator or segment index', async () => {
    const op = await createOperator('retry');
    const prefix = `audit/${op.id}/`;
    const store = new ListingStore();
    await store.put(`${prefix}a.ndjson.gz`, Buffer.from('a'));
    await store.put(`${prefix}b.unindexed`, Buffer.from('b'));
    store.failDeleteOnceFor = `${prefix}b.unindexed`;
    await seedSegment(op.id, `${prefix}a.ndjson.gz`);
    const archive = new AuditArchiveService({ db, store: store as never });
    const service = new OperatorService(new OperatorRepository(db));
    service.setDb(db);
    const erasure = new OperatorErasureService({
      db,
      operatorRepo: new OperatorRepository(db),
      archive,
    });
    service.setErasureService(erasure);

    await expect(service.deleteAccount(op.id, op.email)).resolves.toEqual({ status: 'pending' });
    expect(await db.query.operators.findFirst({ where: eq(operators.id, op.id) }))
      .toMatchObject({ status: 'deleted' });
    expect(await db.query.auditArchiveSegments.findFirst({
      where: eq(auditArchiveSegments.operator_id, op.id),
    })).toBeDefined();
    expect(await db.query.operatorErasureJobs.findFirst({
      where: eq(operatorErasureJobs.operator_id, op.id),
    })).toMatchObject({ status: 'pending', last_error_code: 'archive_delete_failed' });

    await db
      .update(operatorErasureJobs)
      .set({ next_attempt_at: new Date(0) })
      .where(eq(operatorErasureJobs.operator_id, op.id));
    await expect(erasure.attemptRequestedErasure(op.id)).resolves.toEqual({ status: 'completed' });
    expect([...store.objects.keys()].filter((key) => key.startsWith(prefix))).toEqual([]);
  });
});
