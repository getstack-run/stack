import {
  hashApiKey,
  verifyApiKeyHash,
  sha256,
  InvalidApiKeyError,
  NotFoundError,
  OperatorSuspendedError,
  OperatorDeletedError,
  UpdateIdentitySettingsInput,
  oauthRefreshTokens,
  oauthClients,
  teamMembers,
  acquireOAuthOperatorLock,
  acquireOAuthRefreshFamilyLocks,
  type Database,
  type LimitOverrides,
} from '@stack/shared';
import { and, eq, gt, isNull, desc } from 'drizzle-orm';
import {
  OperatorRepository,
} from '../repositories/operator-repo.js';
import type { OperatorErasureService } from './operator-erasure-service.js';

/**
 * Throws if the operator is not authenticatable. Active operators pass
 * through silently; suspended ones throw a 403 with reason; deleted
 * (soft) ones throw a 403 with code OPERATOR_DELETED.
 *
 * Call sites: anywhere we hand an operator to a request principal
 * (authenticateByApiKey and session JWT middleware).
 * Do NOT call from /admin operator-listing paths — admins must be able
 * to see suspended/deleted rows to act on them.
 */
/** An operator row as the repository reads it. */
export type OperatorRecord = NonNullable<Awaited<ReturnType<OperatorRepository['findById']>>>;

export function assertOperatorActive(op: {
  status: string;
  suspended_reason: string | null;
}): void {
  if (op.status === 'active') return;
  if (op.status === 'suspended') throw new OperatorSuspendedError(op.suspended_reason ?? undefined);
  if (op.status === 'deleted') throw new OperatorDeletedError();
  // Defensive: unknown status value -> deny rather than allow.
  throw new OperatorSuspendedError('unknown status');
}

export class OperatorService {
  /**
   * Optional db handle for MCP-session listing + revocation. The OAuth
   * refresh-token tables are owned by the OAuth surface; routing those
   * queries through OperatorService keeps the route handlers thin and
   * matches the MemberService.setDb pattern.
   */
  protected db: Database | null = null;
  private erasure: Pick<OperatorErasureService, 'requestAccountErasure'> | null = null;
  private billingChanged: ((operatorId: string) => Promise<void>) | null = null;

  constructor(protected repo: OperatorRepository) {}

  setDb(db: Database): void {
    this.db = db;
  }

  setErasureService(erasure: Pick<OperatorErasureService, 'requestAccountErasure'>): void {
    this.erasure = erasure;
  }

  /**
   * Called after a plan change lands (Stripe subscription sync, evaluation
   * grants) so cached billing accounts — the account's own and every
   * white-label tenant billed to it — refresh on every machine at once.
   */
  setBillingChangedHook(hook: (operatorId: string) => Promise<void>): void {
    this.billingChanged = hook;
  }

  protected async notifyBillingChanged(operatorId: string): Promise<void> {
    // The cache TTL is the backstop; a failed publish must not fail billing.
    await this.billingChanged?.(operatorId).catch(() => {});
  }

  async authenticateByApiKey(apiKey: string) {
    // dual-verify window. Look up under the CURRENT scheme first
    // (peppered once the pepper is set). On a miss, a legacy row may still
    // be stored as plain SHA-256 — look that up too, and if it hits,
    // upgrade the row in place. Both lookups are indexed equality on
    // api_key_hash; the fallback runs only for not-yet-migrated keys.
    const currentHash = hashApiKey(apiKey);
    let operator = await this.repo.findByApiKeyHash(currentHash);

    if (!operator) {
      const legacyHash = sha256(apiKey);
      // If the pepper is unset (dev), currentHash === legacyHash, so this
      // is a redundant lookup — skip it to avoid a duplicate query.
      if (legacyHash !== currentHash) {
        const legacyOperator = await this.repo.findByApiKeyHash(legacyHash);
        if (legacyOperator) {
          // Confirm via the constant-time verifier, then upgrade the row.
          const { matches, needsRehash } = verifyApiKeyHash(apiKey, legacyOperator.api_key_hash);
          if (matches) {
            operator = legacyOperator;
            if (needsRehash) {
              this.repo
                .updateApiKeyHash(legacyOperator.id, legacyHash, currentHash)
                .catch(() => {});
            }
          }
        }
      }
    }

    if (!operator) throw new InvalidApiKeyError();
    assertOperatorActive(operator);
    return this.reconcileOnRead(operator);
  }

  /** Staff-only: negotiated limits on a billing account. See OperatorRepository. */
  setLimitOverrides(id: string, overrides: LimitOverrides | null) {
    return this.repo.setLimitOverrides(id, overrides);
  }

  /** Staff-only: the partner flag and its provider allowlist. */
  setPartner(id: string, input: { isPartner: boolean; providers: string[] | null }) {
    return this.repo.setPartner(id, input);
  }

  async getById(id: string) {
    const op = await this.repo.findById(id);
    if (!op) throw new NotFoundError('Operator', id);
    return this.reconcileOnRead(op);
  }

  /**
   * Called on every row an authenticated read hands out, before the caller sees it. A deployment whose account
   * rows can change by the clock (a plan with an end date) overrides this to bring the row up to date; the
   * engine's rows do not.
   */
  protected async reconcileOnRead(op: OperatorRecord): Promise<OperatorRecord> {
    return op;
  }

  async deleteAccount(operatorId: string, confirmEmail: string) {
    if (!this.db || !this.erasure) {
      throw new Error('Operator account deletion requires wired database and erasure service');
    }
    return this.erasure.requestAccountErasure(operatorId, confirmEmail);
  }

  async getIdentitySettings(operatorId: string) {
    const op = await this.repo.findById(operatorId);
    if (!op) throw new NotFoundError('Operator', operatorId);
    return {
      identity_claim_ttl: op.identity_claim_ttl,
      identity_claim_inheritance: op.identity_claim_inheritance,
      identity_auto_revoke: op.identity_auto_revoke,
    };
  }

  async updateIdentitySettings(operatorId: string, input: unknown) {
    const parsed = UpdateIdentitySettingsInput.parse(input);
    const op = await this.repo.findById(operatorId);
    if (!op) throw new NotFoundError('Operator', operatorId);
    await this.repo.updateIdentitySettings(operatorId, parsed);
    return this.getIdentitySettings(operatorId);
  }

  // ─── MCP session management ─────────────
  //
  // An "MCP session" is the user-facing rendering of an OAuth refresh-
  // token family. One family = one /authorize grant + all its rotations.
  // The active session for a family is the most recent unreplaced,
  // unrevoked, unexpired refresh token in it. Revocation flips every
  // row in the family. A live family check rejects the access token on
  // the next STACK-verified call. The token also has a one-hour hard TTL.
  //
  // member_id semantics:
  //   - undefined (the route passes request.memberId, which is undefined
  //     when the authed principal is the operator themselves) → only show
  //     sessions where member_id IS NULL (the operator's own sessions).
  //   - set → only show sessions for that specific member.
  //
  // This matches the symmetry of OAuth token issuance: when a team
  // member approves consent, the access + refresh tokens carry their
  // member_id; when the operator approves consent directly, the tokens
  // have member_id NULL. Listing must respect the same partition.

  async listMcpSessions(operatorId: string, memberId: string | undefined) {
    if (!this.db) throw new Error('OperatorService.db not wired (call setDb on bootstrap)');

    const memberCondition = memberId
      ? eq(oauthRefreshTokens.member_id, memberId)
      : isNull(oauthRefreshTokens.member_id);

    const rows = await this.db
      .select({
        token_family_id: oauthRefreshTokens.token_family_id,
        member_id: oauthRefreshTokens.member_id,
        member_name: teamMembers.name,
        member_email: teamMembers.email,
        client_id: oauthRefreshTokens.client_id,
        client_name: oauthClients.client_name,
        software_id: oauthClients.software_id,
        resource: oauthRefreshTokens.resource,
        scope: oauthRefreshTokens.scope,
        issued_at: oauthRefreshTokens.issued_at,
        expires_at: oauthRefreshTokens.expires_at,
        last_used_at: oauthRefreshTokens.last_used_at,
        last_used_ip: oauthRefreshTokens.last_used_ip,
        last_used_ua: oauthRefreshTokens.last_used_ua,
      })
      .from(oauthRefreshTokens)
      .innerJoin(oauthClients, eq(oauthRefreshTokens.client_id, oauthClients.id))
      .leftJoin(teamMembers, eq(oauthRefreshTokens.member_id, teamMembers.id))
      .where(
        and(
          eq(oauthRefreshTokens.operator_id, operatorId),
          memberId ? memberCondition : undefined,
          isNull(oauthRefreshTokens.revoked_at),
          isNull(oauthRefreshTokens.replaced_by_hash),
          gt(oauthRefreshTokens.expires_at, new Date()),
        ),
      )
      .orderBy(desc(oauthRefreshTokens.last_used_at), desc(oauthRefreshTokens.issued_at));

    // A refresh retry can leave more than one active database row in the
    // same family. The Settings contract is one client row per family. The
    // query is newest-first, so preserve the newest row and suppress older
    // retries from this account-management view.
    const families = new Map<string, (typeof rows)[number]>();
    for (const row of rows) {
      if (!families.has(row.token_family_id)) families.set(row.token_family_id, row);
    }
    return [...families.values()];
  }

  async revokeMcpSession(
    operatorId: string,
    memberId: string | undefined,
    familyId: string,
  ): Promise<{ revoked: number }> {
    if (!this.db) throw new Error('OperatorService.db not wired (call setDb on bootstrap)');

    // Refuse to revoke a family that doesn't belong to this caller. The
    // operator_id + member_id partition is the cross-tenant boundary.
    // Without this, a member could revoke another member's sessions, or
    // a member could revoke the operator's sessions, by guessing a
    // family id.
    const memberCondition = memberId
      ? eq(oauthRefreshTokens.member_id, memberId)
      : isNull(oauthRefreshTokens.member_id);

    return this.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, operatorId);
      await acquireOAuthRefreshFamilyLocks(tx, [familyId]);

      const ownership = await tx
        .select({ token_hash: oauthRefreshTokens.token_hash })
        .from(oauthRefreshTokens)
        .where(
          and(
            eq(oauthRefreshTokens.token_family_id, familyId),
            eq(oauthRefreshTokens.operator_id, operatorId),
            memberId ? memberCondition : undefined,
          ),
        )
        .limit(1);

      if (ownership.length === 0) {
        throw new NotFoundError('McpSession', familyId);
      }

      const result = await tx
        .update(oauthRefreshTokens)
        .set({
          revoked_at: new Date(),
          revoked_reason: 'operator_revoked',
          replacement_token_encrypted: null,
          replacement_retry_expires_at: null,
        })
        .where(
          and(
            eq(oauthRefreshTokens.token_family_id, familyId),
            eq(oauthRefreshTokens.operator_id, operatorId),
            memberId ? memberCondition : undefined,
            isNull(oauthRefreshTokens.revoked_at),
          ),
        )
        .returning({ token_hash: oauthRefreshTokens.token_hash });

      await tx
        .update(oauthRefreshTokens)
        .set({
          replacement_token_encrypted: null,
          replacement_retry_expires_at: null,
        })
        .where(
          and(
            eq(oauthRefreshTokens.token_family_id, familyId),
            eq(oauthRefreshTokens.operator_id, operatorId),
            memberId ? memberCondition : undefined,
          ),
        );

      return { revoked: result.length };
    });
  }
}
