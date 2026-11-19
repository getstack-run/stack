import { and, eq, gte, isNull, sql } from 'drizzle-orm';
import {
  ids,
  oauthAuthorizationCodes,
  oauthDeviceCodes,
  oauthRefreshTokens,
  operators,
  teamMembers,
  OAUTH_AUTHORIZATION_CODE_TTL_SECONDS,
  OAUTH_REFRESH_ROTATION_GRACE_SECONDS,
  OAUTH_REFRESH_TOKEN_TTL_SECONDS,
  acquireOAuthOperatorLock,
  acquireOAuthRefreshFamilyLocks,
  type Database,
} from '@stack/shared';
import type { KmsService } from '@stack/vault';
import { hashToken, stripRetiredScopes, verifyPkceS256 } from '../routes/oauth-helpers.js';

type RefreshRow = typeof oauthRefreshTokens.$inferSelect;

type RefreshDeps = {
  db: Database;
  kms: KmsService;
};

export type AuthorizationCodeIssueResult =
  | { kind: 'success'; code: string; expiresAt: Date }
  | { kind: 'operator_inactive' }
  | { kind: 'member_inactive' };

/**
 * Issue one authorization code under the same operator lock as account
 * deletion. The active-state check and insert share one transaction. A
 * deletion that wins the lock leaves no code for the removed operator.
 */
export async function issueAuthorizationCode(
  db: Database,
  input: {
    operatorId: string;
    clientId: string;
    memberId: string | null;
    /** Required by browser callers; internal API-key issuance has no mailbox proof. */
    sessionEmail?: string;
    ownerSessionRevision?: string;
    redirectUri: string;
    scope: string;
    resource: string;
    codeChallenge: string;
    codeChallengeMethod: string;
    nonce?: string | null;
  },
): Promise<AuthorizationCodeIssueResult> {
  const code = ids.oauthCode();
  const codeHash = hashToken(code);
  return db.transaction(async (tx) => {
    await acquireOAuthOperatorLock(tx, input.operatorId);
    const [operator] = await tx
      .select({ status: operators.status, email: operators.email, owner_session_revision: operators.owner_session_revision })
      .from(operators)
      .where(eq(operators.id, input.operatorId))
      .for('update');
    if (!operator || operator.status !== 'active') return { kind: 'operator_inactive' };
    if (!input.memberId && input.sessionEmail !== undefined
      && (operator.email.trim().toLowerCase() !== input.sessionEmail.trim().toLowerCase()
        || operator.owner_session_revision !== (input.ownerSessionRevision ?? '0'))) {
      return { kind: 'operator_inactive' };
    }
    if (input.memberId) {
      const [member] = await tx
        .select({ operator_id: teamMembers.operator_id, status: teamMembers.status, email: teamMembers.email })
        .from(teamMembers)
        .where(eq(teamMembers.id, input.memberId))
        .for('update');
      if (
        !member
        || member.operator_id !== input.operatorId
        || member.status !== 'active'
        || (input.sessionEmail !== undefined && member.email.trim().toLowerCase() !== input.sessionEmail.trim().toLowerCase())
      ) {
        return { kind: 'member_inactive' };
      }
    }

    const now = await transactionNow(tx);
    const expiresAt = new Date(
      now.getTime() + OAUTH_AUTHORIZATION_CODE_TTL_SECONDS * 1000,
    );
    await tx.insert(oauthAuthorizationCodes).values({
      code_hash: codeHash,
      client_id: input.clientId,
      operator_id: input.operatorId,
      member_id: input.memberId,
      redirect_uri: input.redirectUri,
      scope: input.scope,
      resource: input.resource,
      code_challenge: input.codeChallenge,
      code_challenge_method: input.codeChallengeMethod,
      nonce: input.nonce ?? null,
      expires_at: expiresAt,
    });
    return { kind: 'success', code, expiresAt };
  });
}

export type RefreshGrantResult =
  | { kind: 'success'; refreshToken: string; row: RefreshRow; retry: boolean }
  | { kind: 'invalid_grant'; description: string }
  | { kind: 'invalid_scope'; description: string }
  | { kind: 'temporarily_unavailable' }
  | { kind: 'reuse'; row: RefreshRow; reason: 'stale_replay' | 'integrity_failure' };

/** RFC 6749 refresh scope: omitted preserves; supplied may only narrow. */
export function resolveRefreshScope(
  grantedScope: string,
  requestedScope: string | undefined,
): string | null {
  if (requestedScope === undefined) return grantedScope;
  const granted = new Set(grantedScope.split(/\s+/).filter(Boolean));
  const requested = [...new Set(requestedScope.split(/\s+/).filter(Boolean))];
  if (requested.length === 0 || requested.some((scope) => !granted.has(scope))) return null;
  return requested.join(' ');
}

function sameScopeSet(left: string, right: string): boolean {
  const leftSet = new Set(left.split(/\s+/).filter(Boolean));
  const rightSet = new Set(right.split(/\s+/).filter(Boolean));
  return leftSet.size === rightSet.size && [...leftSet].every((scope) => rightSet.has(scope));
}

function retryContext(row: RefreshRow, replacementHash: string): Record<string, string> {
  return {
    operator_id: row.operator_id,
    store: 'oauth_refresh_tokens',
    token_family_id: row.token_family_id,
    client_id: row.client_id,
    parent_token_hash: row.token_hash,
    replacement_token_hash: replacementHash,
  };
}

async function transactionNow(
  tx: Parameters<Parameters<Database['transaction']>[0]>[0],
): Promise<Date> {
  const result = await tx.execute(sql`select clock_timestamp() as now`);
  const value = (result as unknown as Array<{ now: Date | string }>)[0]?.now;
  if (!value) throw new Error('PostgreSQL did not return clock_timestamp()');
  return value instanceof Date ? value : new Date(value);
}

function isCiphertextIntegrityError(err: unknown): boolean {
  if (err instanceof SyntaxError) return true;
  const name = err && typeof err === 'object' && 'name' in err
    ? String((err as { name?: unknown }).name)
    : '';
  const message = err instanceof Error ? err.message : String(err);
  return name === 'InvalidCiphertextException'
    || /envelope|context.*match|authenticate data|authentication tag|invalid ciphertext/i.test(message);
}

function sameLineage(parent: RefreshRow, child: RefreshRow): boolean {
  const childScope = resolveRefreshScope(parent.scope, child.scope);
  return child.token_family_id === parent.token_family_id
    && child.client_id === parent.client_id
    && child.operator_id === parent.operator_id
    && child.member_id === parent.member_id
    && childScope === child.scope
    && child.resource === parent.resource;
}

async function revokeFamily(
  tx: Parameters<Parameters<Database['transaction']>[0]>[0],
  familyId: string,
  now: Date,
  reason: string,
): Promise<void> {
  await tx
    .update(oauthRefreshTokens)
    .set({
      revoked_at: now,
      revoked_reason: reason,
      replacement_token_encrypted: null,
      replacement_retry_expires_at: null,
    })
    .where(and(
      eq(oauthRefreshTokens.token_family_id, familyId),
      isNull(oauthRefreshTokens.revoked_at),
    ));
  await tx
    .update(oauthRefreshTokens)
    .set({
      replacement_token_encrypted: null,
      replacement_retry_expires_at: null,
    })
    .where(eq(oauthRefreshTokens.token_family_id, familyId));
}

/**
 * Rotate one refresh-token family under a PostgreSQL transaction lock.
 *
 * The family advisory lock serializes requests that present different rows
 * from the same family. The row lock protects the exact presented token.
 * A retry receives the exact KMS-encrypted successor. It never advances the
 * chain. This keeps one linear family across API machines and process races.
 */
export async function rotateRefreshGrant(
  deps: RefreshDeps,
  input: {
    refreshToken: string;
    clientId: string;
    ip: string;
    userAgent: string | null;
    requestedScope?: string;
    now?: Date;
  },
): Promise<RefreshGrantResult> {
  const presentedHash = hashToken(input.refreshToken);
  return deps.db.transaction(async (tx) => {
    const initial = await tx.query.oauthRefreshTokens.findFirst({
      where: eq(oauthRefreshTokens.token_hash, presentedHash),
    });
    if (!initial) return { kind: 'invalid_grant', description: 'unknown refresh' };

    // Account deletion takes the operator lock. Family mutation takes it
    // first, then takes sorted family locks. This order prevents deadlocks.
    await acquireOAuthOperatorLock(tx, initial.operator_id);
    await acquireOAuthRefreshFamilyLocks(tx, [initial.token_family_id]);

    const [operator] = await tx
      .select({ status: operators.status })
      .from(operators)
      .where(eq(operators.id, initial.operator_id))
      .for('update');
    if (!operator || operator.status !== 'active') {
      return { kind: 'invalid_grant', description: 'operator not active' };
    }

    const [row] = await tx
      .select()
      .from(oauthRefreshTokens)
      .where(eq(oauthRefreshTokens.token_hash, presentedHash))
      .for('update');
    const now = input.now ?? await transactionNow(tx);
    if (!row) return { kind: 'invalid_grant', description: 'unknown refresh' };
    if (row.revoked_at) return { kind: 'invalid_grant', description: 'refresh revoked' };
    if (row.client_id !== input.clientId) {
      return { kind: 'invalid_grant', description: 'client_id mismatch' };
    }
    if (row.expires_at.getTime() < now.getTime()) {
      return { kind: 'invalid_grant', description: 'refresh expired' };
    }
    const nextScope = resolveRefreshScope(stripRetiredScopes(row.scope), input.requestedScope);
    if (!nextScope) {
      return { kind: 'invalid_scope', description: 'refresh scope may only narrow' };
    }

    if (row.replaced_by_hash) {
      // Rows rotated before migration 0045 have no recoverable successor.
      // Reject them without treating missing migration data as an attack.
      if (!row.replacement_token_encrypted && !row.replacement_retry_expires_at) {
        return { kind: 'invalid_grant', description: 'refresh retry unavailable' };
      }
      // A ciphertext without a deadline cannot be legitimate. Fail closed.
      if (row.replacement_token_encrypted && !row.replacement_retry_expires_at) {
        await revokeFamily(tx, row.token_family_id, now, 'refresh_integrity_failure');
        return { kind: 'reuse', row, reason: 'integrity_failure' };
      }
      // A missing ciphertext with a durable deadline means the retry window
      // expired or the child already advanced. This is a real stale replay.
      if (!row.replacement_token_encrypted && row.replacement_retry_expires_at) {
        await revokeFamily(tx, row.token_family_id, now, 'reuse_detected');
        return { kind: 'reuse', row, reason: 'stale_replay' };
      }
      // Public client_id is not proof of the calling process. Bind retry
      // recovery to the exact network and client fingerprint that rotated it.
      if (row.last_used_ip !== input.ip || row.last_used_ua !== input.userAgent) {
        await revokeFamily(tx, row.token_family_id, now, 'reuse_detected');
        return { kind: 'reuse', row, reason: 'stale_replay' };
      }
      const [child] = await tx
        .select()
        .from(oauthRefreshTokens)
        .where(eq(oauthRefreshTokens.token_hash, row.replaced_by_hash))
        .for('update');
      const withinRetryWindow = !!row.replacement_retry_expires_at
        && row.replacement_retry_expires_at.getTime() >= now.getTime();
      const childIsLiveHead = !!child
        && !child.revoked_at
        && !child.replaced_by_hash
        && sameLineage(row, child);

      if (withinRetryWindow && childIsLiveHead && row.replacement_token_encrypted) {
        if (input.requestedScope !== undefined && !sameScopeSet(child.scope, nextScope)) {
          return { kind: 'invalid_scope', description: 'refresh retry scope does not match' };
        }
        let replacement: string;
        try {
          replacement = await deps.kms.decrypt(
            row.replacement_token_encrypted,
            retryContext(row, row.replaced_by_hash),
          );
        } catch (err) {
          if (!isCiphertextIntegrityError(err)) return { kind: 'temporarily_unavailable' };
          await revokeFamily(tx, row.token_family_id, now, 'refresh_integrity_failure');
          return { kind: 'reuse', row, reason: 'integrity_failure' };
        }
        if (hashToken(replacement) !== row.replaced_by_hash) {
          await revokeFamily(tx, row.token_family_id, now, 'refresh_integrity_failure');
          return { kind: 'reuse', row, reason: 'integrity_failure' };
        }
        return { kind: 'success', refreshToken: replacement, row: child, retry: true };
      }

      await revokeFamily(tx, row.token_family_id, now, 'reuse_detected');
      return { kind: 'reuse', row, reason: 'stale_replay' };
    }

    const replacement = ids.oauthRefreshToken();
    const replacementHash = hashToken(replacement);
    const retryExpiresAt = new Date(
      now.getTime() + OAUTH_REFRESH_ROTATION_GRACE_SECONDS * 1000,
    );
    let ciphertext: string;
    try {
      ({ ciphertext } = await deps.kms.encrypt(
        replacement,
        retryContext(row, replacementHash),
      ));
    } catch {
      return { kind: 'temporarily_unavailable' };
    }

    // The presented row stops being the head before the child is inserted.
    // Both changes commit together. A failed insert rolls the update back.
    await tx
      .update(oauthRefreshTokens)
      .set({
        replaced_by_hash: replacementHash,
        replacement_token_encrypted: ciphertext,
        replacement_retry_expires_at: retryExpiresAt,
        last_used_at: now,
        last_used_ip: input.ip,
        last_used_ua: input.userAgent,
      })
      .where(and(
        eq(oauthRefreshTokens.token_hash, row.token_hash),
        isNull(oauthRefreshTokens.replaced_by_hash),
        isNull(oauthRefreshTokens.revoked_at),
      ));

    await tx.insert(oauthRefreshTokens).values({
      token_hash: replacementHash,
      token_family_id: row.token_family_id,
      client_id: row.client_id,
      operator_id: row.operator_id,
      member_id: row.member_id,
      scope: nextScope,
      resource: row.resource,
      expires_at: new Date(now.getTime() + OAUTH_REFRESH_TOKEN_TTL_SECONDS * 1000),
    });

    // Once a child rotates, its predecessor can no longer be retried. Remove
    // the recoverable ciphertext immediately instead of keeping it at rest.
    await tx
      .update(oauthRefreshTokens)
      .set({
        replacement_token_encrypted: null,
      })
      .where(and(
        eq(oauthRefreshTokens.replaced_by_hash, row.token_hash),
        isNull(oauthRefreshTokens.revoked_at),
      ));

    const child: RefreshRow = {
      ...row,
      token_hash: replacementHash,
      issued_at: now,
      expires_at: new Date(now.getTime() + OAUTH_REFRESH_TOKEN_TTL_SECONDS * 1000),
      replaced_by_hash: null,
      replacement_token_encrypted: null,
      replacement_retry_expires_at: null,
      revoked_at: null,
      revoked_reason: null,
      last_used_at: null,
      last_used_ip: null,
      last_used_ua: null,
      scope: nextScope,
    };
    return { kind: 'success', refreshToken: replacement, row: child, retry: false };
  });
}

export async function revokeRefreshFamilyByToken(
  db: Database,
  input: { refreshToken: string; reason: string },
): Promise<RefreshRow | null> {
  const tokenHash = hashToken(input.refreshToken);
  return db.transaction(async (tx) => {
    const initial = await tx.query.oauthRefreshTokens.findFirst({
      where: eq(oauthRefreshTokens.token_hash, tokenHash),
    });
    if (!initial) return null;
    await acquireOAuthOperatorLock(tx, initial.operator_id);
    await acquireOAuthRefreshFamilyLocks(tx, [initial.token_family_id]);
    const [row] = await tx
      .select()
      .from(oauthRefreshTokens)
      .where(eq(oauthRefreshTokens.token_hash, tokenHash))
      .for('update');
    if (!row) return null;
    const now = await transactionNow(tx);
    await revokeFamily(tx, row.token_family_id, now, input.reason);
    return row;
  });
}

export type AuthorizationCodeClaim =
  | { kind: 'success'; row: typeof oauthAuthorizationCodes.$inferSelect }
  | { kind: 'invalid_grant'; description: string; row?: typeof oauthAuthorizationCodes.$inferSelect }
  | { kind: 'invalid_pkce'; row: typeof oauthAuthorizationCodes.$inferSelect };

export async function consumeAuthorizationCode(
  db: Database,
  input: {
    codeHash: string;
    clientId: string;
    redirectUri: string;
    codeVerifier: string;
    refreshToken: string;
    tokenFamilyId: string;
    now?: Date;
  },
): Promise<AuthorizationCodeClaim> {
  return db.transaction(async (tx) => {
    const initial = await tx.query.oauthAuthorizationCodes.findFirst({
      where: eq(oauthAuthorizationCodes.code_hash, input.codeHash),
    });
    if (!initial) return { kind: 'invalid_grant', description: 'unknown code' };
    await acquireOAuthOperatorLock(tx, initial.operator_id);
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${input.codeHash}, 241))`);
    const [operator] = await tx
      .select({ status: operators.status })
      .from(operators)
      .where(eq(operators.id, initial.operator_id))
      .for('update');
    if (!operator || operator.status !== 'active') {
      return { kind: 'invalid_grant', description: 'operator not active' };
    }
    const [row] = await tx
      .select()
      .from(oauthAuthorizationCodes)
      .where(eq(oauthAuthorizationCodes.code_hash, input.codeHash))
      .for('update');
    const now = input.now ?? await transactionNow(tx);
    if (!row) return { kind: 'invalid_grant', description: 'unknown code' };
    if (row.consumed_at) return { kind: 'invalid_grant', description: 'code already used', row };
    if (row.expires_at.getTime() < now.getTime()) {
      return { kind: 'invalid_grant', description: 'code expired', row };
    }
    if (row.client_id !== input.clientId) {
      return { kind: 'invalid_grant', description: 'client_id mismatch', row };
    }
    if (row.redirect_uri !== input.redirectUri) {
      return { kind: 'invalid_grant', description: 'redirect_uri mismatch', row };
    }
    if (!verifyPkceS256(input.codeVerifier, row.code_challenge)) {
      return { kind: 'invalid_pkce', row };
    }
    if (row.member_id) {
      const [member] = await tx
        .select({ status: teamMembers.status })
        .from(teamMembers)
        .where(eq(teamMembers.id, row.member_id))
        .for('update');
      if (!member || member.status !== 'active') {
        return { kind: 'invalid_grant', description: 'member not active', row };
      }
    }
    await tx
      .update(oauthAuthorizationCodes)
      .set({ consumed_at: now })
      .where(and(
        eq(oauthAuthorizationCodes.code_hash, input.codeHash),
        isNull(oauthAuthorizationCodes.consumed_at),
      ));
    await tx.insert(oauthRefreshTokens).values({
      token_hash: hashToken(input.refreshToken),
      token_family_id: input.tokenFamilyId,
      client_id: row.client_id,
      operator_id: row.operator_id,
      member_id: row.member_id,
      scope: row.scope,
      resource: row.resource,
      expires_at: new Date(now.getTime() + OAUTH_REFRESH_TOKEN_TTL_SECONDS * 1000),
    });
    return { kind: 'success', row };
  });
}

export type DeviceCodeClaim =
  | { kind: 'success'; row: typeof oauthDeviceCodes.$inferSelect }
  | { kind: 'invalid_grant'; description: string };

export type DeviceCodeDecision =
  | { kind: 'success'; row: typeof oauthDeviceCodes.$inferSelect }
  | { kind: 'not_found' }
  | { kind: 'already_decided'; row: typeof oauthDeviceCodes.$inferSelect }
  | { kind: 'expired'; row: typeof oauthDeviceCodes.$inferSelect }
  | { kind: 'operator_inactive' }
  | { kind: 'member_inactive' };

export async function decideDeviceCode(
  db: Database,
  input: {
    userCode: string;
    decision: 'approve' | 'deny';
    operatorId: string;
    memberId: string | null;
    sessionEmail?: string;
    ownerSessionRevision?: string;
    now?: Date;
  },
): Promise<DeviceCodeDecision> {
  return db.transaction(async (tx) => {
    await acquireOAuthOperatorLock(tx, input.operatorId);
    const [operator] = await tx
      .select({ status: operators.status, email: operators.email, owner_session_revision: operators.owner_session_revision })
      .from(operators)
      .where(eq(operators.id, input.operatorId))
      .for('update');
    if (!operator || operator.status !== 'active') return { kind: 'operator_inactive' };
    if (!input.memberId && input.sessionEmail !== undefined
      && (operator.email.trim().toLowerCase() !== input.sessionEmail.trim().toLowerCase()
        || operator.owner_session_revision !== (input.ownerSessionRevision ?? '0'))) {
      return { kind: 'operator_inactive' };
    }
    if (input.memberId) {
      const [member] = await tx
        .select({ operator_id: teamMembers.operator_id, status: teamMembers.status, email: teamMembers.email })
        .from(teamMembers)
        .where(eq(teamMembers.id, input.memberId))
        .for('update');
      if (!member || member.operator_id !== input.operatorId || member.status !== 'active'
        || (input.sessionEmail !== undefined && member.email.trim().toLowerCase() !== input.sessionEmail.trim().toLowerCase())) {
        return { kind: 'member_inactive' };
      }
    }
    const now = input.now ?? await transactionNow(tx);
    const approved = input.decision === 'approve';
    const [row] = await tx
      .update(oauthDeviceCodes)
      .set({
        status: approved ? 'approved' : 'denied',
        operator_id: input.operatorId,
        member_id: input.memberId,
        approved_at: approved ? now : null,
        denied_at: approved ? null : now,
      })
      .where(and(
        eq(oauthDeviceCodes.user_code, input.userCode),
        eq(oauthDeviceCodes.status, 'pending'),
        gte(oauthDeviceCodes.expires_at, now),
      ))
      .returning();
    if (row) return { kind: 'success', row };

    const current = await tx.query.oauthDeviceCodes.findFirst({
      where: eq(oauthDeviceCodes.user_code, input.userCode),
    });
    if (!current) return { kind: 'not_found' };
    if (current.expires_at.getTime() < now.getTime()) {
      return { kind: 'expired', row: current };
    }
    return { kind: 'already_decided', row: current };
  });
}

export async function consumeApprovedDeviceCode(
  db: Database,
  input: {
    deviceCodeHash: string;
    clientId: string;
    refreshToken: string;
    tokenFamilyId: string;
    now?: Date;
  },
): Promise<DeviceCodeClaim> {
  return db.transaction(async (tx) => {
    const initial = await tx.query.oauthDeviceCodes.findFirst({
      where: eq(oauthDeviceCodes.device_code_hash, input.deviceCodeHash),
    });
    if (!initial) return { kind: 'invalid_grant', description: 'unknown device_code' };
    if (!initial.operator_id) {
      return { kind: 'invalid_grant', description: 'authorization_pending' };
    }
    await acquireOAuthOperatorLock(tx, initial.operator_id);
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${input.deviceCodeHash}, 242))`);
    const [operator] = await tx
      .select({ status: operators.status })
      .from(operators)
      .where(eq(operators.id, initial.operator_id))
      .for('update');
    if (!operator || operator.status !== 'active') {
      return { kind: 'invalid_grant', description: 'operator not active' };
    }
    const [row] = await tx
      .select()
      .from(oauthDeviceCodes)
      .where(eq(oauthDeviceCodes.device_code_hash, input.deviceCodeHash))
      .for('update');
    const now = input.now ?? await transactionNow(tx);
    if (!row) return { kind: 'invalid_grant', description: 'unknown device_code' };
    if (row.client_id !== input.clientId) {
      return { kind: 'invalid_grant', description: 'client_id mismatch' };
    }
    if (row.expires_at.getTime() < now.getTime()) {
      return { kind: 'invalid_grant', description: 'expired_token' };
    }
    if (row.status !== 'approved' || !row.operator_id) {
      return { kind: 'invalid_grant', description: 'authorization_pending' };
    }
    if (row.member_id) {
      const [member] = await tx
        .select({ status: teamMembers.status })
        .from(teamMembers)
        .where(eq(teamMembers.id, row.member_id))
        .for('update');
      if (!member || member.status !== 'active') {
        return { kind: 'invalid_grant', description: 'member not active' };
      }
    }
    await tx
      .update(oauthDeviceCodes)
      .set({ status: 'expired', expires_at: new Date(0) })
      .where(and(
        eq(oauthDeviceCodes.device_code_hash, row.device_code_hash),
        eq(oauthDeviceCodes.status, 'approved'),
      ));
    await tx.insert(oauthRefreshTokens).values({
      token_hash: hashToken(input.refreshToken),
      token_family_id: input.tokenFamilyId,
      client_id: row.client_id,
      operator_id: row.operator_id,
      member_id: row.member_id,
      scope: row.scope,
      resource: row.resource,
      expires_at: new Date(now.getTime() + OAUTH_REFRESH_TOKEN_TTL_SECONDS * 1000),
    });
    return { kind: 'success', row };
  });
}
