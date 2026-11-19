import { and, eq, isNull, lt } from 'drizzle-orm';
import { identityClaims, ids, operators } from '@stack/shared';
import { revokePassportsByCarriedClaim } from '@stack/vault';
import type { AuditService, PassportRepository } from '@stack/vault';
import type { WorkerDb } from '../redis.js';

/**
 * Auto-revoke: find expired, non-revoked claims for operators with identity_auto_revoke = true.
 * Revoke the claims and any active passports carrying them.
 */
export async function autoRevokeExpiredClaims(
  db: WorkerDb,
  deps: {
    passportRepo: PassportRepository;
    redis: import('ioredis').Redis;
    audit: AuditService;
    now?: Date;
  },
) {
  const now = deps.now ?? new Date();

  // Find expired claims belonging to operators with auto_revoke enabled
  const expiredClaims = await db
    .select({ id: identityClaims.id, operator_id: identityClaims.operator_id })
    .from(identityClaims)
    .innerJoin(operators, eq(identityClaims.operator_id, operators.id))
    .where(
      and(
        eq(operators.identity_auto_revoke, true),
        lt(identityClaims.expires_at, now),
        isNull(identityClaims.revoked_at),
      ),
    );

  for (const claim of expiredClaims) {
    // Claim the work atomically. Only one worker writes revocation state,
    // Redis flags, the event, and the audit entry.
    const [revokedClaim] = await db
      .update(identityClaims)
      .set({ revoked_at: now })
      .where(and(eq(identityClaims.id, claim.id), isNull(identityClaims.revoked_at)))
      .returning({ id: identityClaims.id, operator_id: identityClaims.operator_id });
    if (!revokedClaim) continue;

    const reason = 'Claim expired (auto-revoke)';
    const start = Date.now();
    const result = await revokePassportsByCarriedClaim({
      passportRepo: deps.passportRepo,
      redis: deps.redis,
      operatorId: revokedClaim.operator_id,
      claimId: revokedClaim.id,
      reason,
    });

    await deps.audit.write({
      ctx: {
        trace_id: ids.session(),
        span_id: ids.session(),
        operator_id: revokedClaim.operator_id,
        agent_id: 'system',
        passport_jti: 'none',
      },
      layer: 'vault',
      action: 'identity.claim.auto_revoke',
      outcome: 'success',
      duration_ms: Date.now() - start,
      payload_hash: revokedClaim.id,
    });

    console.log(
      `Auto-revoke: claim ${revokedClaim.id} expired, revoked ${result.revoked_count} passports`,
    );
  }
}
