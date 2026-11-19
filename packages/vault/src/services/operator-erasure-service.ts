import { randomUUID } from 'node:crypto';
import { and, asc, eq, gt, inArray, lte, sql } from 'drizzle-orm';
import {
  acquireOAuthOperatorLock,
  erasedOperators,
  operatorErasureJobs,
  operators,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  type Database,
} from '@stack/shared';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import {
  ArchiveErasureError,
  type ArchiveErasureErrorCode,
  type AuditArchiveService,
} from './audit-archive-service.js';

/**
 * What a failed erasure records on its job. The archive's and the database's codes, and the code of any step a
 * deployment adds (`ErasureStep`); the job table's check constraint lists the codes it accepts.
 */
export type OperatorErasureErrorCode = ArchiveErasureErrorCode | 'database_delete_failed' | (string & {});

/**
 * A step a deployment runs on an account's data held outside the database, before anything of the account is
 * deleted. It fails closed: when it cannot do its work the erasure waits (and is retried with backoff) rather than
 * go on without it.
 */
export interface ErasureStep {
  /** Recorded on the job when the step fails. */
  code: string;
  /**
   * The longest `run` may take, in seconds, when it waits or calls something slow. The job's claim lasts that long on top of
   * its own base, so the claim cannot run out while the step is still working (a second claimant would run it again). A
   * step with no wait leaves it out.
   */
  maxSeconds?: number;
  run(operatorId: string): Promise<unknown>;
  /** Whether what `run` returned says it removed something. `reapplyErasures` counts those, after a restore. */
  found?(result: unknown): boolean;
}

/** An erasure step could not do its work. The erasure does not go on without it. */
class ErasureStepError extends Error {
  constructor(readonly code: string) {
    super(`erasure step failed: ${code}`);
  }
}
/** What `reapplyErasures` found and did. Ids appear only where a person has to act on them. */
export interface ErasureReplayReport {
  /** Accounts on the erased list that were looked at. */
  checked: number;
  /** Per step code: how many accounts it found something left of, and removed. */
  removed: Record<string, number>;
  /** Accounts a step could not run for: run the command again. */
  failed: Array<{ operator_id: string; code: string }>;
  /** Erased accounts whose operator row is back in the database: the database was restored to before the erasure. */
  present: string[];
  /** Of those, how many this run erased again (only with `apply`). */
  reerased: number;
  /** Of those, how many were started but wait to finish (the saga retries them by itself). */
  pending: string[];
}

export type OperatorErasureResult = { status: 'completed' } | { status: 'pending' };
export type OperatorErasureTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export interface OperatorErasureClaim {
  operator_id: string;
  attempt_count: number;
  claim_id: string;
}

export interface BeginOperatorErasureOptions {
  confirmEmail?: string;
  /** Runs after the advisory lock and before the operator row lock. */
  afterLock?: (tx: OperatorErasureTransaction) => Promise<void>;
  /** Runs after the shared lock and operator row lock are held. */
  prepare?: (
    tx: OperatorErasureTransaction,
    operator: { id: string; email: string; status: string; claimed_at: Date | null },
  ) => Promise<void>;
}

export interface OperatorErasureServiceDeps {
  db: Database;
  operatorRepo: OperatorRepository;
  archive: Pick<AuditArchiveService, 'eraseOperatorArchive'>;
  /** Steps on data outside the database, run first and in order; each fails closed. */
  before?: readonly ErasureStep[];
}

const CLAIM_LEASE_MS = 5 * 60_000;
const RETRY_BASE_MS = 30_000;
const RETRY_MAX_MS = 60 * 60_000;

/** The only production coordinator allowed to hard-delete an operator. */
export class OperatorErasureService {
  /** How long a claim on an erasure job lasts: the base, and the longest the steps declare they may take. */
  private readonly claimLeaseMs: number;

  constructor(private readonly deps: OperatorErasureServiceDeps) {
    const steps = (deps.before ?? []).reduce((sum, step) => sum + Math.max(0, step.maxSeconds ?? 0), 0);
    this.claimLeaseMs = CLAIM_LEASE_MS + Math.ceil(steps * 1000);
  }

  async requestAccountErasure(
    operatorId: string,
    confirmEmail: string,
  ): Promise<OperatorErasureResult> {
    await this.deps.db.transaction((tx) =>
      this.beginErasureInTransaction(operatorId, tx, { confirmEmail }),
    );
    return this.attemptRequestedErasure(operatorId);
  }

  async requestErasure(operatorId: string): Promise<OperatorErasureResult> {
    await this.deps.db.transaction((tx) =>
      this.beginErasureInTransaction(operatorId, tx),
    );
    return this.attemptRequestedErasure(operatorId);
  }

  /**
   * Commit the inaccessible state and durable job in the caller transaction.
   * The caller must invoke attemptRequestedErasure only after this commits.
   */
  async beginErasureInTransaction(
    operatorId: string,
    tx: OperatorErasureTransaction,
    options: BeginOperatorErasureOptions = {},
  ): Promise<void> {
    await acquireOAuthOperatorLock(tx, operatorId);
    await options.afterLock?.(tx);
    const [operator] = await tx
      .select({
        id: operators.id,
        email: operators.email,
        status: operators.status,
        claimed_at: operators.claimed_at,
      })
      .from(operators)
      .where(eq(operators.id, operatorId))
      .for('update');
    if (!operator) throw new NotFoundError('Operator', operatorId);
    if (options.confirmEmail !== undefined && operator.email !== options.confirmEmail) {
      throw new ForbiddenError('Email confirmation does not match');
    }

    const children = await tx
      .select({ id: operators.id })
      .from(operators)
      .where(eq(operators.parent_operator_id, operatorId))
      .limit(1);
    if (children.length > 0) {
      throw new ConflictError('Operator still has a child tenant');
    }

    await options.prepare?.(tx, operator);

    await tx
      .update(operators)
      .set({
        status: 'deleted',
        deleted_at: sql`clock_timestamp()`,
        updated_at: sql`clock_timestamp()`,
      })
      .where(eq(operators.id, operatorId));
    await tx
      .insert(operatorErasureJobs)
      .values({
        operator_id: operatorId,
        status: 'pending',
        claim_id: null,
        attempt_count: 0,
        next_attempt_at: sql`clock_timestamp()`,
        last_error_code: null,
        updated_at: sql`clock_timestamp()`,
      })
      .onConflictDoNothing({ target: operatorErasureJobs.operator_id });
  }

  async attemptRequestedErasure(operatorId: string): Promise<OperatorErasureResult> {
    const claim = await this.claimOperator(operatorId);
    if (!claim) return { status: 'pending' };
    return this.finalizeClaim(claim);
  }

  /** Claim due jobs only. Never infer erasure work from operator status. */
  async claimDueJobs(limit = 10): Promise<OperatorErasureClaim[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new RangeError('Erasure claim limit must be an integer from 1 to 100');
    }
    return this.deps.db.transaction(async (tx) => {
      const candidates = await tx
        .select({ operator_id: operatorErasureJobs.operator_id })
        .from(operatorErasureJobs)
        .where(lte(operatorErasureJobs.next_attempt_at, sql`clock_timestamp()`))
        .orderBy(asc(operatorErasureJobs.next_attempt_at))
        .limit(limit)
        .for('update', { skipLocked: true });
      if (candidates.length === 0) return [];

      const claims: OperatorErasureClaim[] = [];
      for (const candidate of candidates) {
        const claimId = randomUUID();
        const [claimed] = await tx
          .update(operatorErasureJobs)
          .set({
            status: 'processing',
            claim_id: claimId,
            attempt_count: sql`${operatorErasureJobs.attempt_count} + 1`,
            next_attempt_at: sql`clock_timestamp() + (${this.claimLeaseMs} * interval '1 millisecond')`,
            last_error_code: null,
            updated_at: sql`clock_timestamp()`,
          })
          .where(eq(operatorErasureJobs.operator_id, candidate.operator_id))
          .returning({
            operator_id: operatorErasureJobs.operator_id,
            attempt_count: operatorErasureJobs.attempt_count,
            claim_id: operatorErasureJobs.claim_id,
          });
        if (claimed?.claim_id) claims.push({ ...claimed, claim_id: claimed.claim_id });
      }
      return claims;
    });
  }

  async finalizeClaim(claim: OperatorErasureClaim): Promise<OperatorErasureResult> {
    try {
      const outcome = await this.deps.db.transaction(async (tx) => {
        await acquireOAuthOperatorLock(tx, claim.operator_id);
        const [job] = await tx
          .select({ operator_id: operatorErasureJobs.operator_id })
          .from(operatorErasureJobs)
          .where(
            and(
              eq(operatorErasureJobs.operator_id, claim.operator_id),
              eq(operatorErasureJobs.status, 'processing'),
              eq(operatorErasureJobs.claim_id, claim.claim_id),
              eq(operatorErasureJobs.attempt_count, claim.attempt_count),
            ),
          )
          .for('update');
        if (!job) {
          const [current] = await tx
            .select({ operator_id: operatorErasureJobs.operator_id })
            .from(operatorErasureJobs)
            .where(eq(operatorErasureJobs.operator_id, claim.operator_id));
          return current ? 'stale' as const : 'completed' as const;
        }

        const [operator] = await tx
          .select({ status: operators.status })
          .from(operators)
          .where(eq(operators.id, claim.operator_id))
          .for('update');
        if (!operator) return 'completed' as const;
        if (operator.status !== 'deleted') {
          throw new Error('erasure_job_operator_not_deleted');
        }

        // What lives outside the database goes before anything that records the account.
        for (const step of this.deps.before ?? []) {
          try {
            await step.run(claim.operator_id);
          } catch {
            throw new ErasureStepError(step.code);
          }
        }
        await this.deps.archive.eraseOperatorArchive(claim.operator_id, tx);
        // This is the only production call to the repository hard delete.
        // Deleting the operator cascades the completed erasure job.
        await this.deps.operatorRepo.deleteById(claim.operator_id, tx);
        return 'completed' as const;
      });
      return { status: outcome === 'completed' ? 'completed' : 'pending' };
    } catch (error) {
      const code: OperatorErasureErrorCode =
        error instanceof ArchiveErasureError || error instanceof ErasureStepError ? error.code : 'database_delete_failed';
      try {
        await this.recordFailure(claim, code);
      } catch {
        // The processing lease is itself a bounded retry. Keep this log static.
        // Operator ids and object keys are personal or security-sensitive.
        console.error('[operator-erasure] retry scheduling failed');
      }
      return { status: 'pending' };
    }
  }

  /**
   * After a restore: put every erasure on the list back in force. A snapshot older than an erasure brings the
   * account back, in the database (when that was restored too) and in whatever lives outside it, and nothing in
   * either says it should not be there; `erased_operators` does.
   *
   * For each account on the list, each step runs again (the memory graph is deleted again: deleting what is not
   * there is a no-op) and the report counts the ones that found something to remove. An account whose operator
   * row is back in the database is listed in `present`; with `apply` it is erased again through the whole saga
   * (steps, archive, rows), which is what the person asked for when they erased it. Without `apply` nothing in the
   * database is touched. A step that cannot run (the engine is down) is reported and the run goes on; run it again.
   */
  async reapplyErasures(options: { apply?: boolean; pageSize?: number } = {}): Promise<ErasureReplayReport> {
    const pageSize = options.pageSize ?? 200;
    const report: ErasureReplayReport = { checked: 0, removed: {}, failed: [], present: [], reerased: 0, pending: [] };
    let after = '';
    for (;;) {
      const page = await this.deps.db
        .select({ operator_id: erasedOperators.operator_id })
        .from(erasedOperators)
        .where(gt(erasedOperators.operator_id, after))
        .orderBy(asc(erasedOperators.operator_id))
        .limit(pageSize);
      if (page.length === 0) return report;
      after = page[page.length - 1]!.operator_id;
      const ids = page.map((row) => row.operator_id);
      const back = new Set(
        (await this.deps.db.select({ id: operators.id }).from(operators).where(inArray(operators.id, ids))).map((row) => row.id),
      );
      for (const id of ids) {
        report.checked += 1;
        // An account that is back in the database is erased by the saga below, which runs the steps itself.
        if (back.has(id)) {
          report.present.push(id);
          if (options.apply) {
            const result = await this.requestErasure(id).catch(() => ({ status: 'pending' as const }));
            if (result.status === 'completed') report.reerased += 1;
            else report.pending.push(id);
          }
          continue;
        }
        for (const step of this.deps.before ?? []) {
          try {
            const result = await step.run(id);
            if (step.found?.(result)) report.removed[step.code] = (report.removed[step.code] ?? 0) + 1;
          } catch {
            report.failed.push({ operator_id: id, code: step.code });
          }
        }
      }
    }
  }

  private async claimOperator(operatorId: string): Promise<OperatorErasureClaim | null> {
    return this.deps.db.transaction(async (tx) => {
      const [candidate] = await tx
        .select({ operator_id: operatorErasureJobs.operator_id })
        .from(operatorErasureJobs)
        .where(
          and(
            eq(operatorErasureJobs.operator_id, operatorId),
            lte(operatorErasureJobs.next_attempt_at, sql`clock_timestamp()`),
          ),
        )
        .for('update', { skipLocked: true });
      if (!candidate) return null;

      const [claimed] = await tx
        .update(operatorErasureJobs)
        .set({
          status: 'processing',
          claim_id: randomUUID(),
          attempt_count: sql`${operatorErasureJobs.attempt_count} + 1`,
          next_attempt_at: sql`clock_timestamp() + (${this.claimLeaseMs} * interval '1 millisecond')`,
          last_error_code: null,
          updated_at: sql`clock_timestamp()`,
        })
        .where(eq(operatorErasureJobs.operator_id, operatorId))
        .returning({
          operator_id: operatorErasureJobs.operator_id,
          attempt_count: operatorErasureJobs.attempt_count,
          claim_id: operatorErasureJobs.claim_id,
        });
      return claimed?.claim_id ? { ...claimed, claim_id: claimed.claim_id } : null;
    });
  }

  private async recordFailure(
    claim: OperatorErasureClaim,
    code: OperatorErasureErrorCode,
  ): Promise<void> {
    const exponent = Math.max(0, Math.min(claim.attempt_count - 1, 16));
    const retryMs = Math.min(RETRY_BASE_MS * (2 ** exponent), RETRY_MAX_MS);
    await this.deps.db
      .update(operatorErasureJobs)
      .set({
        status: 'pending',
        claim_id: null,
        next_attempt_at: sql`clock_timestamp() + (${retryMs} * interval '1 millisecond')`,
        last_error_code: code,
        updated_at: sql`clock_timestamp()`,
      })
      .where(
        and(
          eq(operatorErasureJobs.operator_id, claim.operator_id),
          eq(operatorErasureJobs.status, 'processing'),
          eq(operatorErasureJobs.claim_id, claim.claim_id),
          eq(operatorErasureJobs.attempt_count, claim.attempt_count),
        ),
      );
  }
}
