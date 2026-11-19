import {
  AuditArchiveService,
  AuditService,
  OperatorErasureService,
  type ArchiveErasePrefix,
  type ErasureStep,
  type OperatorRepository,
} from '@stack/vault';
import { createObjectStore } from '../config/object-store.js';
import type { WorkerDb } from '../redis.js';

/**
 * The audit service and its cold archive. `AuditArchiveService` refuses all
 * archive and erasure work when the object store is not durable, and production
 * refuses to boot without a durable store (`AUDIT_ARCHIVE_BUCKET`). The
 * archive-before-prune rule itself lives in `AuditArchiveService`
 * (`packages/vault/src/services/audit-archive-service.ts`).
 */
export async function buildAuditArchive(deps: {
  db: WorkerDb;
  operatorRepo: OperatorRepository;
  erasureSteps: readonly ErasureStep[];
  /** What a deployment keeps in the archive's store besides the audit segments: an erasure the worker finishes deletes these too. */
  extraErasePrefixes?: readonly ArchiveErasePrefix[];
}) {
  const { db, operatorRepo, erasureSteps, extraErasePrefixes } = deps;
  const audit = new AuditService(db);

  const archiveStore = await createObjectStore();
  if (process.env['NODE_ENV'] === 'production' && !archiveStore.durable) {
    throw new Error('AUDIT_ARCHIVE_BUCKET is required in production for durable account erasure');
  }
  const archive = new AuditArchiveService({
    db,
    store: archiveStore,
    ...(extraErasePrefixes && extraErasePrefixes.length > 0 ? { extraErasePrefixes } : {}),
    ...(process.env['AUDIT_HOT_WINDOW_DAYS']
      ? { hotWindowDays: Number(process.env['AUDIT_HOT_WINDOW_DAYS']) }
      : {}),
  });
  // What a deployment keeps outside the database goes with the account, and the erasure waits until it has.
  const operatorErasure = new OperatorErasureService({
    db,
    operatorRepo,
    archive,
    before: erasureSteps,
  });

  // Exports and evidence packs must see the whole chain, not just the hot
  // window — the terms promise audit export always works, and a truncated
  // answer on an audit product is worse than an error.
  audit.setArchive(archive);
  await audit.initChain();

  return { audit, archive, operatorErasure, archiveStore };
}
