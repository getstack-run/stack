import {
  acquireOAuthOperatorLock,
  PASSPORT_MAX_DELEGATION_DEPTH,
  PassportExpiredError,
  PassportRevokedError,
  ServiceUnavailableError,
  isRedisUnavailableError,
} from '@stack/shared';
import type { PassportRepository } from '../../repositories/passport-repo.js';
import type { OperatorRepository } from '../../repositories/operator-repo.js';
import type {
  PassportAuthorityTransaction,
  PassportContext,
  PassportJWTPayload,
  PassportServiceDependencies,
} from './types.js';

const REQUIRED_DEPENDENCIES: ReadonlyArray<{
  key: keyof PassportServiceDependencies;
  kind: 'object' | 'function';
}> = [
  { key: 'identityVerification', kind: 'object' },
  { key: 'claimMatcher', kind: 'object' },
  { key: 'identityRepo', kind: 'object' },
  { key: 'passportClaimsRepo', kind: 'object' },
  { key: 'missionLookup', kind: 'function' },
  { key: 'securityEvent', kind: 'function' },
  { key: 'authorityLookup', kind: 'function' },
  { key: 'fleetLookup', kind: 'function' },
];

/**
 * Refuse to build a PassportService that is missing a dependency. The types
 * already require each one; this covers a caller that casts around them, so a
 * half-wired service fails at boot instead of skipping a check at request time.
 */
export function assertPassportDependencies(dependencies: PassportServiceDependencies): void {
  for (const { key, kind } of REQUIRED_DEPENDENCIES) {
    const value: unknown = dependencies?.[key];
    const present =
      kind === 'function' ? typeof value === 'function' : typeof value === 'object' && value !== null;
    if (!present) {
      throw new Error(`PassportService requires its ${key} dependency at construction`);
    }
  }
}

type ActiveOperator = NonNullable<Awaited<ReturnType<OperatorRepository['findById']>>>;

/** Run `work` in a transaction holding the operator lock, with the operator known to be active. */
export async function withActiveOperatorLock<T>(
  ctx: PassportContext,
  operatorId: string,
  work: (tx: PassportAuthorityTransaction, operator: ActiveOperator) => Promise<T>,
): Promise<T> {
  return ctx.db.transaction(async (tx) => {
    await acquireOAuthOperatorLock(tx, operatorId);
    const operator = await ctx.operatorRepo.findById(operatorId, tx);
    if (!operator || operator.status !== 'active') {
      throw new PassportRevokedError();
    }
    return work(tx, operator);
  });
}

/** Run `work` in a transaction holding the operator lock. */
export async function withOperatorLock<T>(
  ctx: PassportContext,
  operatorId: string,
  work: (tx: PassportAuthorityTransaction) => Promise<T>,
): Promise<T> {
  return ctx.db.transaction(async (tx) => {
    await acquireOAuthOperatorLock(tx, operatorId);
    return work(tx);
  });
}

export async function requireActiveAgent(
  ctx: PassportContext,
  operatorId: string,
  agentId: string,
  tx?: PassportAuthorityTransaction,
) {
  const agent = await ctx.agentRepo.findById(agentId, tx);
  if (
    !agent ||
    agent.operator_id !== operatorId ||
    agent.status !== 'active' ||
    agent.passport_blocked
  ) {
    throw new PassportRevokedError();
  }
  return agent;
}

/** Recheck persisted authority; admission callers hold the lifecycle lock. */
export async function loadPassportLineage(
  ctx: PassportContext,
  claims: PassportJWTPayload,
  tx?: PassportAuthorityTransaction,
  allowExpiredSource = false,
) {
  const lineage: NonNullable<Awaited<ReturnType<PassportRepository['findByJti']>>>[] = [];
  const seen = new Set<string>();
  let jti: string | null = claims.jti;
  let expectedDepth = claims.stk.delegation_depth;
  while (jti) {
    if (seen.has(jti) || lineage.length > PASSPORT_MAX_DELEGATION_DEPTH)
      throw new PassportRevokedError();
    seen.add(jti);
    const record = await ctx.passportRepo.findByJti(jti, tx);
    if (
      !record ||
      record.operator_id !== claims.stk.operator_id ||
      record.revoked_at ||
      record.session_id !== claims.stk.session_id ||
      record.delegation_depth !== expectedDepth ||
      (lineage.length === 0 &&
        (record.agent_id !== claims.stk.agent_id ||
          (record.parent_passport_id ?? null) !== (claims.stk.parent_passport_id ?? null)))
    ) {
      throw new PassportRevokedError();
    }
    if (
      (!allowExpiredSource || lineage.length > 0) &&
      record.expires_at.getTime() <= Date.now()
    ) {
      throw new PassportExpiredError();
    }
    await requireActiveAgent(ctx, claims.stk.operator_id, record.agent_id, tx);
    lineage.push(record);
    jti = record.parent_passport_id;
    expectedDepth -= 1;
  }
  if (expectedDepth !== -1) throw new PassportRevokedError();
  return lineage;
}

/**
 * Redis revocation flag first (fast), then the database. A Redis outage fails
 * closed and retriable: the flag is not readable, so the Passport is neither
 * accepted nor reported revoked, and the caller gets a 503 it can retry.
 */
export async function isRevoked(ctx: PassportContext, jti: string): Promise<boolean> {
  let cached: string | null;
  try {
    cached = await ctx.redis.get(`revoked:${jti}`);
  } catch (err) {
    if (isRedisUnavailableError(err)) {
      throw new ServiceUnavailableError('Revocation check temporarily unavailable, please retry');
    }
    throw err;
  }
  if (cached === '1') return true;
  return ctx.passportRepo.isRevoked(jti);
}
