import type { Redis } from 'ioredis';
import { NotFoundError, ServiceUnavailableError, acquireOAuthOperatorLock, safeErrorSummary } from '@stack/shared';
import {
  revokeMissionPassportChain,
  type PassportRepository,
  type RevokedPassportRow,
} from '../../repositories/passport-repo.js';
import type { PassportClaimsRepository } from '../../repositories/passport-claims-repo.js';
import type { MissionPassportRevoker } from '../mission-service.js';
import { withOperatorLock } from './context.js';
import {
  REVOCATION_CHANNEL,
  type PassportAuthorityTransaction,
  type PassportContext,
  type RevocationEvent,
} from './types.js';

/** Commands in one revocation pipeline: each carries its own command timeout, so a batch stays well inside a request's patience. */
const REVOKED_FLAGS_PER_PIPELINE = 1_000;

/**
 * Write the `revoked:<jti>` flags for rows the database has already revoked.
 * `Pipeline.exec()` never rejects for a command that failed: it resolves with
 * one `[error, result]` entry per command, so a flag that timed out would be
 * reported as written. Every entry is read here. A command that carried an
 * error is sent once more in a second pipeline (the writes are idempotent
 * `SET`s); any flag still unwritten fails the call (`ServiceUnavailableError`,
 * 503) after every batch has been tried. The database is the authority and
 * `isRevoked` falls through to it on a missing flag, so a flag that is missing
 * is not a bypass; but the revoke itself has committed and a retry of a bulk
 * call finds no rows left to flag, which is why the bulk paths announce the
 * revocation (`announceAfterFlags`) before the failure reaches the caller.
 */
async function writeRevokedFlags(
  redis: Pick<Redis, 'pipeline'>,
  rows: ReadonlyArray<{ jti: string; expires_at: Date }>,
): Promise<void> {
  const flags = rows
    .map((row) => ({ jti: row.jti, ttl: Math.ceil((row.expires_at.getTime() - Date.now()) / 1000) }))
    .filter((flag) => flag.ttl > 0);
  let unwritten = 0;
  for (let start = 0; start < flags.length; start += REVOKED_FLAGS_PER_PIPELINE) {
    let pending = flags.slice(start, start + REVOKED_FLAGS_PER_PIPELINE);
    for (let attempt = 0; attempt < 2 && pending.length > 0; attempt += 1) {
      const pipeline = redis.pipeline();
      for (const flag of pending) {
        pipeline.set(`revoked:${flag.jti}`, '1', 'EX', flag.ttl);
      }
      // A pipeline that rejects (the connection closed under it) is a batch that did not land, like one that
      // answered with nothing: the whole batch is tried once more, and the end is the same typed 503.
      const results = await pipeline.exec().catch(() => null);
      pending = results ? pending.filter((_, index) => results[index]?.[0]) : pending;
    }
    unwritten += pending.length;
  }
  if (unwritten > 0) {
    throw new ServiceUnavailableError('Revocation flags temporarily unavailable, please retry');
  }
}

/**
 * Write the flags, then announce the revocation with its real count, then
 * surface a flag failure. The rows are already revoked in the database, so the
 * event is true whether or not every flag landed, and a retry of a bulk revoke
 * would find nothing to revoke and announce a count of zero.
 */
async function announceAfterFlags(
  redis: Pick<Redis, 'pipeline' | 'publish'>,
  rows: ReadonlyArray<{ jti: string; expires_at: Date }>,
  event: RevocationEvent,
): Promise<void> {
  let flagFailure: unknown;
  try {
    await writeRevokedFlags(redis, rows);
  } catch (error) {
    flagFailure = error;
  }
  await publishRevocationEvent(redis, event);
  if (flagFailure) throw flagFailure;
}

/** What a single revoke did, for the audit rows its caller writes. */
export interface PassportRevokeOutcome {
  operator_id: string;
  cascaded: string[];
  revoked_claims: { claim_id: string; claim_hash: string }[];
}

/**
 * The revoke committed and was announced, but a flag was not written (503, retriable). It carries what the revoke did,
 * so the caller still writes the audit rows of a revoke that cannot be repeated: a retry finds the Passport and its
 * children already revoked and has no cascade to report.
 */
export class PassportRevokeFlagsError extends ServiceUnavailableError {
  constructor(message: string, readonly outcome: PassportRevokeOutcome) {
    super(message);
  }
}

/**
 * Revoke passports by carried claim through one DB, Redis, and event path.
 * The API and the expiry worker both use this function.
 */
export async function revokePassportsByCarriedClaim(args: {
  passportRepo: PassportRepository;
  redis: Redis;
  operatorId: string;
  claimId: string;
  reason: string;
}): Promise<{ revoked_count: number }> {
  const result = await args.passportRepo.revokeByCarriedClaim(
    args.operatorId,
    args.claimId,
    args.reason,
  );
  const rows = Array.isArray(result)
    ? (result as unknown as { jti: string; expires_at: Date }[])
    : ((result as { rows?: { jti: string; expires_at: Date }[] }).rows ?? []);

  const event: RevocationEvent = {
    type: 'bulk_claim',
    operator_id: args.operatorId,
    claim_id: args.claimId,
    revoked_count: rows.length,
    reason: args.reason,
    at: Date.now(),
  };
  await announceAfterFlags(
    args.redis,
    rows.map((passport) => ({ jti: passport.jti, expires_at: new Date(passport.expires_at) })),
    event,
  );

  return { revoked_count: rows.length };
}

/**
 * The Passport half of "a Mission's end kills its Passports", injected into
 * MissionService as `passportRevoker`. The database revoke runs in the
 * Mission's terminal transaction (operator lock held), so it commits or rolls
 * back with the Mission's state change. Redis flags are written after commit;
 * verify() falls back to the database on a miss.
 */
export function createMissionPassportRevoker(deps: {
  redis: Pick<Redis, 'pipeline'>;
  passportClaimsRepo?: Pick<PassportClaimsRepository, 'markAllRevokedByPassportId'>;
}): MissionPassportRevoker {
  return {
    async revokeInTransaction(tx, input) {
      const revokedAt = new Date();
      const rows = await revokeMissionPassportChain(tx, {
        operatorId: input.operatorId,
        missionId: input.missionId,
        reason: input.reason,
        revokedAt,
      });
      if (input.revokeAttachedClaims && deps.passportClaimsRepo) {
        for (const row of rows) {
          await deps.passportClaimsRepo.markAllRevokedByPassportId(
            row.jti,
            'passport_revoked',
            revokedAt,
            tx,
          );
        }
      }
      return rows.map((row) => ({ jti: row.jti, expires_at: row.expires_at }));
    },
    async afterCommit(rows) {
      await writeRevokedFlags(deps.redis, rows);
    },
  };
}

/**
 * Revoke a Passport and everything delegated from it. Every caller names the
 * operator it acts for; a Passport owned by any other operator is reported as
 * not found, so a jti never reveals whether another tenant holds it.
 */
export async function revokePassport(
  ctx: PassportContext,
  input: { jti: string; operatorId: string; reason: string },
) {
  const { jti, operatorId, reason: revokeReason } = input;

  const record = await ctx.passportRepo.findByJti(jti);
  if (!record || !operatorId || record.operator_id !== operatorId) {
    throw new NotFoundError('Passport', jti);
  }

  const { revokedClaims, cascadeResult } = await withOperatorLock(
    ctx,
    record.operator_id,
    async (tx) => {
      await ctx.passportRepo.revoke(jti, revokeReason, tx);
      const revokedClaims = await ctx.passportClaimsRepo.markAllRevokedByPassportId(
        jti,
        'passport_revoked',
        new Date(),
        tx,
      );
      const cascadeResult = await cascadeRevokeChildren(ctx, jti, revokeReason, tx);
      return { revokedClaims, cascadeResult };
    },
  );
  const outcome: PassportRevokeOutcome = {
    operator_id: record.operator_id,
    cascaded: cascadeResult.passports,
    revoked_claims: [...revokedClaims, ...cascadeResult.claims],
  };
  try {
    await announceAfterFlags(ctx.redis, [record, ...cascadeResult.rows], {
      type: 'single',
      operator_id: record.operator_id,
      jti,
      cascaded: cascadeResult.passports,
      reason: revokeReason,
      at: Date.now(),
    });
  } catch (error) {
    if (error instanceof ServiceUnavailableError) throw new PassportRevokeFlagsError(error.message, outcome);
    throw error;
  }

  // Revoking a Passport never ends its Mission. The Mission is the task; the
  // operator can issue a fresh Passport for it, or end it explicitly.

  // The caller (route handler) uses these to write per-cascade audit entries:
  // one passport.revoke audit row per cascaded child and one claim.revoke audit
  // row per cascaded claim, so the audit log records the cascade rather than
  // burying it inside the parent's single revoke.
  return outcome;
}

/**
 * Cache and broadcast revocations already committed by the authority
 * repository. The authority transaction owns the database cascade; this
 * must not mutate it or traverse descendants a second time.
 */
export async function syncAuthorityRevocations(
  ctx: PassportContext,
  jtis: string[],
  reason: string,
): Promise<void> {
  for (const jti of [...new Set(jtis)]) {
    const record = await ctx.passportRepo.findByJti(jti);
    if (!record?.revoked_at) {
      throw new Error(`authority revocation is not durable for Passport ${jti}`);
    }
    await markRevokedInRedis(ctx, jti, record.expires_at);
    await publishRevocation(ctx, {
      type: 'single',
      operator_id: record.operator_id,
      jti,
      cascaded: [],
      reason: `authority:${reason}`,
      at: Date.now(),
    });
  }
}

/** Write a revoked:<jti> flag with TTL matching the passport's remaining life. */
async function markRevokedInRedis(ctx: PassportContext, jti: string, expiresAt: Date): Promise<void> {
  const ttl = Math.max(0, Math.ceil((expiresAt.getTime() - Date.now()) / 1000));
  if (ttl > 0) {
    await ctx.redis.set(`revoked:${jti}`, '1', 'EX', ttl);
  }
}

/**
 * Revoke every unrevoked descendant, including expired refresh sources.
 * The caller synchronizes Redis after commit. Returns the list of jtis revoked
 * (excluding the root). Safe against diamond-shape or cyclic parent
 * pointers via the `seen` guard.
 */
async function cascadeRevokeChildren(
  ctx: PassportContext,
  rootJti: string,
  reason: string,
  transaction: PassportAuthorityTransaction,
): Promise<{
  passports: string[];
  claims: { claim_id: string; claim_hash: string }[];
  rows: { jti: string; expires_at: Date }[];
}> {
  const revokedPassports: string[] = [];
  const revokedClaims: { claim_id: string; claim_hash: string }[] = [];
  const rows: { jti: string; expires_at: Date }[] = [];
  const seen = new Set<string>([rootJti]);
  const queue: string[] = [rootJti];

  while (queue.length > 0) {
    const next = queue.shift()!;
    const children = await ctx.passportRepo.findActiveChildren(next, transaction);
    if (children.length === 0) continue;

    for (const child of children) {
      if (seen.has(child.jti)) continue;
      seen.add(child.jti);
      await ctx.passportRepo.revoke(child.jti, `${reason} (cascade from ${rootJti})`, transaction);
      rows.push(child);
      // Also revoke attached claims for the cascaded child.
      const childClaims = await ctx.passportClaimsRepo.markAllRevokedByPassportId(
        child.jti,
        'parent_passport_revoked',
        new Date(),
        transaction,
      );
      revokedClaims.push(...childClaims);
      queue.push(child.jti);
      revokedPassports.push(child.jti);
    }
  }

  return { passports: revokedPassports, claims: revokedClaims, rows };
}

/**
 * Broadcast a revocation event. Subscribers (e.g. proxy workers with in-memory
 * verify caches) can listen for these to invalidate eagerly rather than wait
 * for the next Redis GET on `revoked:<jti>`.
 */
async function publishRevocation(ctx: PassportContext, event: RevocationEvent): Promise<void> {
  await publishRevocationEvent(ctx.redis, event);
}

async function publishRevocationEvent(redis: Pick<Redis, 'publish'>, event: RevocationEvent): Promise<void> {
  try {
    await redis.publish(REVOCATION_CHANNEL, JSON.stringify(event));
  } catch {
    // Never let a publish failure mask a successful revoke. The
    // `revoked:<jti>` key is already written; verify() will catch it.
  }
}

export async function revokeAllForAgent(ctx: PassportContext, agentId: string, reason: string) {
  const agent = await ctx.agentRepo.findById(agentId);
  if (!agent) throw new NotFoundError('Agent', agentId);
  const operatorId = agent.operator_id;
  let publish: () => Promise<void> = async () => {};
  const result = await withOperatorLock(ctx, operatorId, async (tx) => {
    const revoked = await revokeAllForAgentIn(ctx, agentId, operatorId, reason, tx);
    publish = revoked.publish;
    return { revoked_count: revoked.revoked_count };
  });
  await publish();
  return result;
}

/**
 * The same revocation inside a transaction the caller already holds, with the operator lock taken: a caller that
 * holds the lock cannot call `revokeAllForAgent`, which takes it again on another connection and would wait for
 * the caller forever. The database writes happen here; the Redis flags and the event are `publish`, which the
 * caller runs after its transaction commits (a rollback then leaves nothing announced).
 */
export async function revokeAllForAgentIn(
  ctx: PassportContext,
  agentId: string,
  operatorId: string,
  reason: string,
  tx: PassportAuthorityTransaction,
): Promise<{ revoked_count: number; publish: () => Promise<void> }> {
  const cascadedAll: string[] = [];
  const rows: { jti: string; expires_at: Date }[] = [];
  const roots = await ctx.passportRepo.revokeAllForAgent(agentId, reason, tx);
  rows.push(...roots);
  for (const passport of roots) {
    await ctx.passportClaimsRepo.markAllRevokedByPassportId(passport.jti, reason, new Date(), tx);
    const cascaded = await cascadeRevokeChildren(ctx, passport.jti, reason, tx);
    cascadedAll.push(...cascaded.passports);
    rows.push(...cascaded.rows);
  }
  return {
    revoked_count: roots.length + cascadedAll.length,
    publish: async () => {
      await announceAfterFlags(ctx.redis, rows, {
        type: 'bulk_agent',
        operator_id: operatorId,
        agent_id: agentId,
        revoked_count: roots.length,
        cascaded_count: cascadedAll.length,
        reason,
        at: Date.now(),
      });
    },
  };
}

/**
 * Block future issuance and revoke the agent's entire unrevoked Passport chain
 * in one database transaction. Redis is a post-commit accelerator only;
 * online verification still checks the authoritative database on a miss.
 */
export async function blockAgent(
  ctx: PassportContext,
  operatorId: string,
  agentId: string,
  reason: string,
  blockedAt: Date = new Date(),
): Promise<{ revoked_count: number }> {
  const revoked = await ctx.passportRepo.blockAgentAndRevokeChain({
    operatorId,
    agentId,
    reason,
    blockedAt,
  });
  await syncBlockedAgentRevocations(ctx, operatorId, agentId, reason, revoked);
  return { revoked_count: revoked.length };
}

/** Post-commit Redis/event synchronization for transaction owners elsewhere. */
export async function syncBlockedAgentRevocations(
  ctx: PassportContext,
  operatorId: string,
  agentId: string,
  reason: string,
  revoked: RevokedPassportRow[],
): Promise<void> {
  try {
    await writeRevokedFlags(ctx.redis, revoked);
  } catch (error) {
    console.error('[PASSPORT_BLOCK] Redis revocation marker sync failed:', safeErrorSummary(error));
  }

  const directlyOwned = revoked.filter((passport) => passport.agent_id === agentId).length;
  await publishRevocation(ctx, {
    type: 'bulk_agent',
    operator_id: operatorId,
    agent_id: agentId,
    revoked_count: directlyOwned,
    cascaded_count: revoked.length - directlyOwned,
    reason,
    at: Date.now(),
  });
}

export async function revokeBySession(
  ctx: PassportContext,
  operatorId: string,
  sessionId: string,
  reason: string,
) {
  const revoked = await withOperatorLock(ctx, operatorId, async (tx) => {
    const rows = await ctx.passportRepo.revokeBySession(sessionId, operatorId, reason, tx);
    for (const row of rows) {
      await ctx.passportClaimsRepo.markAllRevokedByPassportId(row.jti, reason, new Date(), tx);
    }
    return rows;
  });
  // Children inherit session_id from the parent at delegate() time, so a
  // session-scoped revoke already catches every descendant. Skip cascade here;
  // just broadcast the event.
  await announceAfterFlags(ctx.redis, revoked, {
    type: 'bulk_session',
    operator_id: operatorId,
    session_id: sessionId,
    revoked_count: revoked.length,
    reason,
    at: Date.now(),
  });

  return { revoked_count: revoked.length };
}

/** Revoke only passports carrying a specific identity claim (smart revoke). */
export async function revokeByCarriedClaim(
  ctx: PassportContext,
  operatorId: string,
  claimId: string,
  reason: string,
) {
  // Children inherit identity_claim_ids from parent at delegate time, so a
  // claim-scoped revoke also catches descendants carrying the same claim set.
  // No cascade needed.
  return revokePassportsByCarriedClaim({
    passportRepo: ctx.passportRepo,
    redis: ctx.redis,
    operatorId,
    claimId,
    reason,
  });
}

/**
 * Revoke every Passport of an account being suspended, inside the transaction that sets the suspension: the operator
 * lock is taken here, so a Passport being issued or refreshed meets either the suspension or the revocation, never
 * neither. Run `publish` after the transaction commits.
 */
export async function revokeAllForSuspendedOperatorIn(
  ctx: PassportContext,
  operatorId: string,
  reason: string,
  tx: PassportAuthorityTransaction,
): Promise<{ revoked_count: number; publish: () => Promise<void> }> {
  await acquireOAuthOperatorLock(tx, operatorId);
  return revokeAllForOperatorIn(ctx, operatorId, reason, tx);
}

export async function revokeAllForOperator(ctx: PassportContext, operatorId: string, reason: string) {
  const revoked = await withOperatorLock(ctx, operatorId, (tx) => revokeAllForOperatorIn(ctx, operatorId, reason, tx));
  await revoked.publish();
  return { revoked_count: revoked.revoked_count };
}

/**
 * Revoke every Passport of an operator inside a transaction the caller holds, with the operator lock taken
 * (`acquireOAuthOperatorLock`). Descendants share operator_id, so the operator-scoped update catches every unrevoked
 * Passport of the tenant. Run `publish` after the transaction commits.
 */
export async function revokeAllForOperatorIn(
  ctx: PassportContext,
  operatorId: string,
  reason: string,
  tx: PassportAuthorityTransaction,
): Promise<{ revoked_count: number; publish: () => Promise<void> }> {
  const rows = await ctx.passportRepo.revokeAllForOperator(operatorId, reason, tx);
  for (const row of rows) {
    await ctx.passportClaimsRepo.markAllRevokedByPassportId(row.jti, reason, new Date(), tx);
  }
  return {
    revoked_count: rows.length,
    publish: async () => {
      await announceAfterFlags(ctx.redis, rows, {
        type: 'bulk_operator',
        operator_id: operatorId,
        revoked_count: rows.length,
        reason,
        at: Date.now(),
      });
    },
  };
}
