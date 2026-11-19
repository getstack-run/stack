import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { and, asc, eq, isNotNull, isNull, lte, or, sql } from 'drizzle-orm';
import {
  acquireOAuthOperatorLock,
  acquireOAuthRefreshFamilyLocks,
  oauthRefreshTokens,
  oauthAuthorizationCodes,
  oauthDeviceCodes,
  operatorEmailChanges,
  magicLinkTokens,
  operatorEmailDeliveryJobs,
  operators,
  ids,
  emailChangeConfirmEmail,
  emailChangeNoticeEmail,
  emailChangeCompletedEmail,
  type Database,
} from '@stack/shared';
import { ConflictError, signinAllowed, StackError } from '@stack/shared';
import type { AuditService } from './audit-service.js';

type DbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

/**
 * Transferring the address an operator signs in with.
 *
 * STACK has no passwords. A magic link to the account email is the whole
 * authentication story, which makes the email the credential and this flow a
 * transfer of control rather than a profile edit. It is built accordingly.
 *
 * THREAT MODEL
 *
 * 1. Stolen dashboard session moves the account away from its owner.
 *    The dangerous one, because the attacker already has a valid session and
 *    every "are you sure" prompt answers itself. Mitigation is not another
 *    prompt: the OLD address is emailed the instant a transfer is requested,
 *    with a single-use cancel link. The owner finds out before the attacker
 *    can confirm, and cancelling is one click with no login required (they may
 *    not be able to log in — that is the situation they are in).
 *
 * 2. Transfer to an address the requester does not control (typo, or
 *    deliberately stranding an account). Nothing changes until the NEW address
 *    proves itself by using its own single-use link.
 *
 * 3. Token guessing. 32 random bytes, compared in constant time, stored only
 *    as sha256 — the same posture as magic links. 30-minute TTL.
 *
 * 4. Takeover of an address already in use. Rejected before anything is sent;
 *    operators.email is unique and a silent collision at confirm time would
 *    leave a pending transfer that can never complete.
 *
 * 5. An agent doing any of this. The routes carry denyAgentContexts
 *    makes account identity a governance action, and agents never hold
 *    governance authority.
 *
 * 6. Request flooding as a way to spam a third party. Rate limited per
 *    operator, and only one transfer is ever in flight.
 */

const TOKEN_BYTES = 32;
const TTL_MINUTES = 30;
const MAX_REQUESTS_PER_HOUR = 3;
const DELIVERY_CLAIM_LEASE_MS = 5 * 60_000;
const DELIVERY_RETRY_BASE_MS = 30_000;
const DELIVERY_RETRY_MAX_MS = 60 * 60_000;

export interface RateLimitStore {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
}

export interface EmailSender {
  sendEmail(
    to: string,
    subject: string,
    text: string,
    html?: string,
    options?: { skipSignature?: boolean },
  ): Promise<{ id: string }>;
}

export interface EmailChangeDeps {
  db: Database;
  email: EmailSender | null;
  rateLimitStore: RateLimitStore | null;
  audit: Pick<AuditService, 'write'>;
  /** Base URL the confirm / cancel links point at. */
  dashboardUrl: string;
}

export interface EmailChangeAuditContext {
  traceId: string;
  spanId: string;
  startedAtMs?: number;
}

export interface EmailChangeDeliveryClaim {
  id: string;
  emailChangeId: string;
  claimId: string;
  attemptCount: number;
  oldEmail: string;
  newEmail: string;
}

function sha256(v: string): string {
  return createHash('sha256').update(v).digest('hex');
}

/** Constant-time compare of two hex digests of equal length. */
function hashesEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ba.length !== bb.length || ba.length === 0) return false;
  return timingSafeEqual(ba, bb);
}

function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

/** Deliberately strict-but-simple: one @, something either side, a dot in the
 * domain. Real validation is whether the confirm link is ever clicked. */
function looksLikeEmail(v: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

export class EmailChangeService {
  constructor(private deps: EmailChangeDeps) {}

  /**
   * Start a transfer. Emails the new address a confirm link and the old
   * address a cancel link, then returns without changing anything.
   */
  async request(
    input: {
      operatorId: string;
      newEmail: string;
      requestedByMemberId?: string | null;
    },
    auditContext: EmailChangeAuditContext,
  ): Promise<{ id: string; newEmail: string; expiresAt: Date }> {
    const newEmail = normalizeEmail(input.newEmail);
    if (!looksLikeEmail(newEmail)) {
      throw new StackError('That does not look like an email address.', 'INVALID_EMAIL', 400);
    }
    // A staging deployment moves an account only to an address on its allow-list: the new address is mailed a link
    // and then signs in, so it is a way in like any other.
    if (!signinAllowed(newEmail)) {
      throw new StackError('This address cannot be used on this deployment.', 'INVALID_EMAIL', 400);
    }
    await this.checkRate(input.operatorId);
    const confirmToken = randomBytes(TOKEN_BYTES).toString('base64url');
    const cancelToken = randomBytes(TOKEN_BYTES).toString('base64url');
    const expiresAt = new Date(Date.now() + TTL_MINUTES * 60_000);
    const id = ids.emailChange();

    const operator = await this.deps.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, input.operatorId);
      const [locked] = await tx
        .select({ id: operators.id, email: operators.email, status: operators.status })
        .from(operators)
        .where(eq(operators.id, input.operatorId))
        .for('update');
      if (!locked || locked.status !== 'active') throw this.invalidToken();
      if (normalizeEmail(locked.email) === newEmail) {
        throw new ConflictError('That is already the account email.');
      }
      const [taken] = await tx
        .select({ id: operators.id })
        .from(operators)
        .where(eq(operators.email, newEmail))
        .limit(1);
      if (taken) {
        throw new ConflictError('That address is already used by another STACK account.');
      }

      await tx
        .update(operatorEmailChanges)
        .set({ cancelled_at: sql`clock_timestamp()` })
        .where(
          and(
            eq(operatorEmailChanges.operator_id, input.operatorId),
            isNull(operatorEmailChanges.confirmed_at),
            isNull(operatorEmailChanges.cancelled_at),
          ),
        );
      await tx.insert(operatorEmailChanges).values({
        id,
        operator_id: input.operatorId,
        new_email: newEmail,
        old_email: locked.email,
        confirm_token_hash: sha256(confirmToken),
        cancel_token_hash: sha256(cancelToken),
        requested_by_member_id: input.requestedByMemberId ?? null,
        expires_at: expiresAt,
        delivery_ready_at: null,
      });
      return locked;
    });

    await this.sendConfirm(newEmail, operator.email, confirmToken);
    await this.sendNotice(operator.email, newEmail, cancelToken);

    await this.deps.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, input.operatorId);
      const [lockedOperator] = await tx
        .select({ id: operators.id, status: operators.status })
        .from(operators)
        .where(eq(operators.id, input.operatorId))
        .for('update');
      const [change] = await tx
        .select({ id: operatorEmailChanges.id })
        .from(operatorEmailChanges)
        .where(
          and(
            eq(operatorEmailChanges.id, id),
            isNull(operatorEmailChanges.delivery_ready_at),
            isNull(operatorEmailChanges.confirmed_at),
            isNull(operatorEmailChanges.cancelled_at),
          ),
        )
        .for('update');
      if (!lockedOperator || lockedOperator.status !== 'active' || !change) {
        throw this.invalidToken();
      }
      await tx
        .update(operatorEmailChanges)
        .set({ delivery_ready_at: sql`clock_timestamp()` })
        .where(eq(operatorEmailChanges.id, id));
      await this.writeAudit(tx, input.operatorId, 'operator.email_change.request', auditContext);
    });

    return { id, newEmail, expiresAt };
  }

  /** The new address proves itself. This is the only path that writes the
   * operator's email. */
  async confirm(
    token: string,
    auditContext: EmailChangeAuditContext,
  ): Promise<{ operatorId: string; email: string }> {
    const tokenHash = sha256(token);
    const discovered = await this.findPending(tokenHash, 'confirm');
    const result = await this.deps.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, discovered.operator_id);
      const row = await this.findPending(tokenHash, 'confirm', tx, true);
      const [operator] = await tx
        .select({ id: operators.id, status: operators.status })
        .from(operators)
        .where(eq(operators.id, discovered.operator_id))
        .for('update');
      if (!operator || operator.status !== 'active') throw this.invalidToken();

      const [taken] = await tx
        .select({ id: operators.id })
        .from(operators)
        .where(eq(operators.email, row.new_email))
        .limit(1);
      if (taken) {
        throw new ConflictError(
          'That address was taken by another account while this was pending.',
        );
      }

      const [updated] = await tx
        .update(operatorEmailChanges)
        .set({ confirmed_at: sql`clock_timestamp()` })
        .where(
          and(
            eq(operatorEmailChanges.id, row.id),
            isNull(operatorEmailChanges.confirmed_at),
            isNull(operatorEmailChanges.cancelled_at),
          ),
        )
        .returning({ id: operatorEmailChanges.id });
      if (!updated) throw this.invalidToken();
      await tx
        .update(operators)
        .set({ email: row.new_email, owner_session_revision: randomUUID(), updated_at: sql`clock_timestamp()` })
        .where(eq(operators.id, row.operator_id));
      // Consume every owner challenge for this account, including historical
      // email-only rows. Changing the mailbox back must not revive them.
      await tx.update(magicLinkTokens).set({ used: true }).where(and(
        isNull(magicLinkTokens.member_id),
        or(eq(magicLinkTokens.operator_id, row.operator_id), and(isNull(magicLinkTokens.operator_id), eq(magicLinkTokens.email, row.old_email))),
      ));
      // OAuth tokens carry an account identity rather than a mailbox. Revoke
      // the old owner's grants while holding the same lock used by refresh,
      // authorization-code issuance and device-code approval. Member grants
      // remain bound to their own unchanged identity.
      const ownerRefresh = and(eq(oauthRefreshTokens.operator_id, row.operator_id), isNull(oauthRefreshTokens.member_id));
      const families = await tx.selectDistinct({ id: oauthRefreshTokens.token_family_id })
        .from(oauthRefreshTokens).where(ownerRefresh);
      await acquireOAuthRefreshFamilyLocks(tx, families.map(family => family.id));
      await tx.update(oauthRefreshTokens).set({
        revoked_at: sql`clock_timestamp()`, revoked_reason: 'owner_email_changed',
      }).where(and(ownerRefresh, isNull(oauthRefreshTokens.revoked_at)));
      await tx.update(oauthRefreshTokens).set({
        replacement_token_encrypted: null, replacement_retry_expires_at: null,
      }).where(ownerRefresh);
      await tx.update(oauthAuthorizationCodes).set({ consumed_at: sql`clock_timestamp()` }).where(and(
        eq(oauthAuthorizationCodes.operator_id, row.operator_id), isNull(oauthAuthorizationCodes.member_id),
        isNull(oauthAuthorizationCodes.consumed_at),
      ));
      await tx.update(oauthDeviceCodes).set({ status: 'denied', denied_at: sql`clock_timestamp()` }).where(and(
        eq(oauthDeviceCodes.operator_id, row.operator_id), isNull(oauthDeviceCodes.member_id),
        eq(oauthDeviceCodes.status, 'approved'),
      ));
      await this.writeAudit(tx, row.operator_id, 'operator.email_change.confirm', auditContext);
      await tx
        .insert(operatorEmailDeliveryJobs)
        .values({
          id: randomUUID(),
          operator_id: row.operator_id,
          email_change_id: row.id,
          kind: 'completion_notice',
          status: 'pending',
          next_attempt_at: sql`clock_timestamp()`,
        })
        .onConflictDoNothing({
          target: [operatorEmailDeliveryJobs.email_change_id, operatorEmailDeliveryJobs.kind],
        });
      return { operatorId: row.operator_id, email: row.new_email, changeId: row.id };
    });

    try {
      await this.deliverCompletionForChange(result.changeId);
    } catch {
      // The durable job committed with the email change. A failed immediate
      // attempt must not turn the completed transfer into an API error.
      console.error('[EMAIL-CHANGE] Immediate completion notice attempt failed');
    }
    return { operatorId: result.operatorId, email: result.email };
  }

  /** The old address says no. No login required — the owner of a hijacked
   * account may not be able to get in, which is the whole point. */
  async cancel(
    token: string,
    auditContext: EmailChangeAuditContext,
  ): Promise<{ operatorId: string }> {
    const tokenHash = sha256(token);
    const discovered = await this.findPending(tokenHash, 'cancel');
    return this.deps.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, discovered.operator_id);
      const row = await this.findPending(tokenHash, 'cancel', tx, true);
      const [operator] = await tx
        .select({ id: operators.id, status: operators.status })
        .from(operators)
        .where(eq(operators.id, row.operator_id))
        .for('update');
      if (!operator || operator.status !== 'active') throw this.invalidToken();
      const [updated] = await tx
        .update(operatorEmailChanges)
        .set({ cancelled_at: sql`clock_timestamp()` })
        .where(
          and(
            eq(operatorEmailChanges.id, row.id),
            isNull(operatorEmailChanges.confirmed_at),
            isNull(operatorEmailChanges.cancelled_at),
          ),
        )
        .returning({ id: operatorEmailChanges.id });
      if (!updated) throw this.invalidToken();
      await this.writeAudit(tx, row.operator_id, 'operator.email_change.cancel', auditContext);
      return { operatorId: row.operator_id };
    });
  }

  /** What the console shows: is a transfer waiting, and to where. */
  async pendingFor(operatorId: string) {
    const [row] = await this.deps.db
      .select({
        id: operatorEmailChanges.id,
        new_email: operatorEmailChanges.new_email,
        expires_at: operatorEmailChanges.expires_at,
        created_at: operatorEmailChanges.created_at,
      })
      .from(operatorEmailChanges)
      .where(
        and(
          eq(operatorEmailChanges.operator_id, operatorId),
          isNotNull(operatorEmailChanges.delivery_ready_at),
          isNull(operatorEmailChanges.confirmed_at),
          isNull(operatorEmailChanges.cancelled_at),
        ),
      )
      .limit(1);
    if (!row || new Date(row.expires_at).getTime() < Date.now()) return null;
    return row;
  }

  // ─── internals ────────────────────────────────────────────────────

  private async findPending(
    tokenHash: string,
    kind: 'confirm' | 'cancel',
    transaction?: DbTransaction,
    lock = false,
  ) {
    const col =
      kind === 'confirm'
        ? operatorEmailChanges.confirm_token_hash
        : operatorEmailChanges.cancel_token_hash;
    const executor = transaction ?? this.deps.db;
    const query = executor.select().from(operatorEmailChanges).where(eq(col, tokenHash)).limit(1);
    const [row] = lock ? await query.for('update') : await query;

    // One message for every failure mode: unknown, already used, cancelled,
    // expired. Distinguishing them tells a guesser which half they got right.
    const dead = !row || !row.delivery_ready_at || row.confirmed_at || row.cancelled_at;
    if (dead || new Date(row.expires_at).getTime() < Date.now()) {
      throw new StackError('This link is no longer valid.', 'INVALID_TOKEN', 400);
    }
    const stored = kind === 'confirm' ? row.confirm_token_hash : row.cancel_token_hash;
    if (!hashesEqual(stored, tokenHash)) {
      throw new StackError('This link is no longer valid.', 'INVALID_TOKEN', 400);
    }
    return row;
  }

  private invalidToken(): StackError {
    return new StackError('This link is no longer valid.', 'INVALID_TOKEN', 400);
  }

  private async writeAudit(
    tx: DbTransaction,
    operatorId: string,
    action: string,
    context: EmailChangeAuditContext,
  ): Promise<void> {
    await this.deps.audit.write(
      {
        ctx: {
          trace_id: context.traceId,
          span_id: context.spanId,
          operator_id: operatorId,
          agent_id: 'system',
          passport_jti: 'none',
        },
        layer: 'vault',
        action,
        outcome: 'success',
        duration_ms:
          context.startedAtMs === undefined ? undefined : Date.now() - context.startedAtMs,
      },
      tx,
    );
  }

  async claimDueDeliveryJobs(limit = 10): Promise<EmailChangeDeliveryClaim[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new RangeError('Delivery claim limit must be an integer from 1 to 100');
    }
    return this.deps.db.transaction(async (tx) => {
      const candidates = await tx
        .select({ id: operatorEmailDeliveryJobs.id })
        .from(operatorEmailDeliveryJobs)
        .where(lte(operatorEmailDeliveryJobs.next_attempt_at, sql`clock_timestamp()`))
        .orderBy(asc(operatorEmailDeliveryJobs.next_attempt_at))
        .limit(limit)
        .for('update', { skipLocked: true });
      const claims: EmailChangeDeliveryClaim[] = [];
      for (const candidate of candidates) {
        const claim = await this.claimDeliveryRow(tx, candidate.id);
        if (claim) claims.push(claim);
      }
      return claims;
    });
  }

  async finalizeDeliveryClaim(claim: EmailChangeDeliveryClaim): Promise<'completed' | 'pending'> {
    try {
      await this.sendCompleted(claim.oldEmail, claim.newEmail);
      await this.deps.db
        .delete(operatorEmailDeliveryJobs)
        .where(
          and(
            eq(operatorEmailDeliveryJobs.id, claim.id),
            eq(operatorEmailDeliveryJobs.status, 'processing'),
            eq(operatorEmailDeliveryJobs.claim_id, claim.claimId),
            eq(operatorEmailDeliveryJobs.attempt_count, claim.attemptCount),
          ),
        );
      return 'completed';
    } catch {
      const exponent = Math.max(0, Math.min(claim.attemptCount - 1, 16));
      const retryMs = Math.min(DELIVERY_RETRY_BASE_MS * 2 ** exponent, DELIVERY_RETRY_MAX_MS);
      await this.deps.db
        .update(operatorEmailDeliveryJobs)
        .set({
          status: 'pending',
          claim_id: null,
          next_attempt_at: sql`clock_timestamp() + (${retryMs} * interval '1 millisecond')`,
          last_error_code: 'delivery_failed',
          updated_at: sql`clock_timestamp()`,
        })
        .where(
          and(
            eq(operatorEmailDeliveryJobs.id, claim.id),
            eq(operatorEmailDeliveryJobs.status, 'processing'),
            eq(operatorEmailDeliveryJobs.claim_id, claim.claimId),
            eq(operatorEmailDeliveryJobs.attempt_count, claim.attemptCount),
          ),
        );
      return 'pending';
    }
  }

  private async deliverCompletionForChange(emailChangeId: string): Promise<void> {
    const claim = await this.deps.db.transaction(async (tx) => {
      const [job] = await tx
        .select({ id: operatorEmailDeliveryJobs.id })
        .from(operatorEmailDeliveryJobs)
        .where(
          and(
            eq(operatorEmailDeliveryJobs.email_change_id, emailChangeId),
            lte(operatorEmailDeliveryJobs.next_attempt_at, sql`clock_timestamp()`),
          ),
        )
        .for('update', { skipLocked: true });
      return job ? this.claimDeliveryRow(tx, job.id) : null;
    });
    if (claim) await this.finalizeDeliveryClaim(claim);
  }

  private async claimDeliveryRow(
    tx: DbTransaction,
    jobId: string,
  ): Promise<EmailChangeDeliveryClaim | null> {
    const claimId = randomUUID();
    const [claimed] = await tx
      .update(operatorEmailDeliveryJobs)
      .set({
        status: 'processing',
        claim_id: claimId,
        attempt_count: sql`${operatorEmailDeliveryJobs.attempt_count} + 1`,
        next_attempt_at: sql`clock_timestamp() + (${DELIVERY_CLAIM_LEASE_MS} * interval '1 millisecond')`,
        last_error_code: null,
        updated_at: sql`clock_timestamp()`,
      })
      .where(eq(operatorEmailDeliveryJobs.id, jobId))
      .returning({
        id: operatorEmailDeliveryJobs.id,
        emailChangeId: operatorEmailDeliveryJobs.email_change_id,
        attemptCount: operatorEmailDeliveryJobs.attempt_count,
      });
    if (!claimed) return null;
    const [change] = await tx
      .select({
        oldEmail: operatorEmailChanges.old_email,
        newEmail: operatorEmailChanges.new_email,
      })
      .from(operatorEmailChanges)
      .where(eq(operatorEmailChanges.id, claimed.emailChangeId));
    if (!change) return null;
    return {
      id: claimed.id,
      emailChangeId: claimed.emailChangeId,
      claimId,
      attemptCount: claimed.attemptCount,
      oldEmail: change.oldEmail,
      newEmail: change.newEmail,
    };
  }

  private async checkRate(operatorId: string): Promise<void> {
    if (!this.deps.rateLimitStore) return;
    const key = `stack:email_change_rate:${operatorId}`;
    let count: number;
    try {
      count = await this.deps.rateLimitStore.incr(key);
      if (count === 1) await this.deps.rateLimitStore.expire(key, 3600);
    } catch {
      // A rate limiter that is down must not block an account owner from
      // recovering their own address.
      return;
    }
    if (count > MAX_REQUESTS_PER_HOUR) {
      throw new StackError(
        'Too many email-change requests. Try again in an hour.',
        'RATE_LIMITED',
        429,
      );
    }
  }

  private async sendConfirm(to: string, from: string, token: string): Promise<void> {
    const url = `${this.deps.dashboardUrl}/account/email-change/confirm?token=${encodeURIComponent(token)}`;
    const email = emailChangeConfirmEmail({
      currentEmail: from,
      confirmUrl: url,
      ttlMinutes: TTL_MINUTES,
    });
    await this.deliver(to, email.subject, email.text, email.html);
  }

  private async sendNotice(to: string, newEmail: string, cancelToken: string): Promise<void> {
    const url = `${this.deps.dashboardUrl}/account/email-change/cancel?token=${encodeURIComponent(cancelToken)}`;
    const email = emailChangeNoticeEmail({ newEmail, cancelUrl: url, ttlMinutes: TTL_MINUTES });
    await this.deliver(to, email.subject, email.text, email.html);
  }

  private async sendCompleted(oldEmail: string, newEmail: string): Promise<void> {
    const email = emailChangeCompletedEmail({ newEmail });
    await this.deliver(oldEmail, email.subject, email.text, email.html);
  }

  private async deliver(to: string, subject: string, text: string, html?: string): Promise<void> {
    if (!this.deps.email) {
      console.warn('[EMAIL-CHANGE] Email service unavailable');
      throw new StackError(
        'Could not send the confirmation email. Nothing has changed; try again.',
        'EMAIL_SEND_FAILED',
        502,
      );
    }
    try {
      await this.deps.email.sendEmail(to, subject, text, html, {
        skipSignature: html !== undefined,
      });
    } catch {
      console.error('[EMAIL-CHANGE] Email delivery failed');
      throw new StackError(
        'Could not send the confirmation email. Nothing has changed; try again.',
        'EMAIL_SEND_FAILED',
        502,
      );
    }
  }
}
