import {
  type Database,
  auditLog,
  ids,
  nowMs,
  AUDIT_CHAIN_GENESIS,
  AUDIT_HASH_VERSION_CURRENT,
  computeAuditEntryHash,
  type AuditClaimBindingStatus,
} from '@stack/shared';
import type { AuditLayer, AuditOutcome } from '@stack/shared';
import { eq, and, gt, gte, inArray, lt, or, sql, desc, asc, like } from 'drizzle-orm';
import { createHash } from 'node:crypto';

/**
 * Convert an operator id (e.g. "op_-Ex4mpleOperatorId012") to a deterministic
 * 64-bit signed integer suitable for `pg_advisory_xact_lock(bigint)`.
 *
 * MD5 first-8-bytes is non-cryptographic but stable + uniform — exactly what
 * we need for lock-key partitioning. Postgres advisory locks expect signed
 * int8, so we map unsigned > 2^63 to negative range.
 */
function operatorLockKey(operatorId: string): string {
  const hex = createHash('md5').update(operatorId).digest('hex').slice(0, 16);
  const unsigned = BigInt('0x' + hex);
  const max = (1n << 63n) - 1n;
  const signed = unsigned > max ? unsigned - (1n << 64n) : unsigned;
  return signed.toString();
}

export interface AuditContext {
  trace_id: string;
  span_id: string;
  parent_span_id?: string;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
}

export interface AuditInput {
  ctx: AuditContext;
  layer: AuditLayer;
  action: string;
  outcome: AuditOutcome;
  duration_ms?: number;
  payload_hash?: string;
  error?: { code: string; message: string };
  /**
   * sorted set of attached-claim hashes captured at audit-write
   * time. When set, this exact list is hashed into the chain entry via
   * computeAuditEntryHash + persisted to audit_log.passport_claims_at_event.
   * When unset (most callers), AuditService auto-resolves it from the
   * claims repo using ctx.passport_jti, so callers don't have to think
   * about it. Pass an empty array to assert "no claims" explicitly
   * (rare; used when a claim has just been revoked and the caller wants
   * the chain to bind that revocation moment).
   */
  passport_claims_at_event?: string[];
  /**
   * body metrics for the behavioral_genome producer.
   * Populated by the proxy at audit-write time for HTTP-shape calls.
   * Other audit writers (skills, drop-off, mcp, accountability) omit
   * these — fields are null in the row, dropped from the chain hash
   * canonical input (legacy parity preserved).
   *
   * Entropy is Shannon entropy in bits per byte, computed via
   * `shannonEntropy()` over the raw body bytes.
   */
  request_bytes?: number;
  response_bytes?: number;
  request_entropy?: number;
  response_entropy?: number;
  /**
   * partner-acting-for-user attribution, kept for rows written before partner
   * grants were removed (a grant, sk_grant_*, acted for the user). Nothing
   * sets it now. The entry landed on the USER's chain; these two fields
   * hash-bind the acting partner so re-attribution to the user breaks
   * the chain. Omitted by every other writer (fields null in the row,
   * dropped from the canonical hash input — legacy parity preserved).
   */
  actor_grant_id?: string;
  actor_partner_operator_id?: string;
  /**
   * A small allowlist the customer's events stream carries beside the row:
   * the account, the control decision, the settled amount and, for a refusal by
   * a hosted policy, which rule refused (never a value from the call). Not part
   * of the hash and never stored on the audit row.
   */
  event_details?: {
    account_id?: string;
    decision_id?: string;
    amount_cents?: number;
    refusal?: { policy_id: string; policy_revision: number; section: string; rule: string; code: string };
  };
}

/**
 * Called inside the audit write's transaction, with the operator's audit lock
 * held, after the row is inserted. It must not throw (the control socket's
 * sink isolates itself): a failure here would fail the write.
 */
export type AuditOutboxSink = (tx: AuditTransaction, row: {
  entryId: string;
  operatorId: string;
  agentId: string;
  layer: string;
  action: string;
  outcome: string;
  timestampMs: number;
  errorCode: string | null;
  entryHash: string;
  prevEntryHash: string;
  details?: { account_id?: string; decision_id?: string; amount_cents?: number };
}) => Promise<void>;

export type AuditNotifyCallback = (operatorId: string, action: string, outcome: AuditOutcome, agentId: string) => void;
export type AuditTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export interface ChainVerificationResult {
  valid: boolean;
  total_checked: number;
  head_entry_hash: string | null;
  first_break?: {
    entry_id: string;
    timestamp: number;
    reason: 'hash_mismatch' | 'prev_hash_mismatch';
    expected: string;
    actual: string;
  };
}

export interface ChainHead {
  latest_entry_hash: string | null;
  latest_timestamp: number | null;
  total_entries: number;
}

/**
 * resolver shape for the audit chain's claim binding. The
 * passport_claims repo implements this; the audit service uses it
 * (when set) to auto-fetch attached-claim hashes for the request's
 * passport_jti at audit-write time.
 *
 * Kept as a narrow interface (one method) so the audit service does
 * not depend on the full repo. Wired via setter in services.ts.
 */
export interface AttachedClaimHashResolver {
  findActiveHashesByPassportId(passportId: string): Promise<string[]>;
}

export interface AuditClaimBindingFailure {
  operatorId: string;
  agentId: string;
  passportJti: string;
  reason: 'resolver_unavailable' | 'resolver_failed';
}

export class AuditClaimBindingError extends Error {
  readonly code = 'AUDIT_CLAIM_BINDING_UNAVAILABLE';
  constructor(readonly reason: AuditClaimBindingFailure['reason']) {
    super('Audit evidence claim binding is unavailable');
    this.name = 'AuditClaimBindingError';
  }
}

export class AuditService {
  private archive?: {
    readRange(operatorId: string, from?: number, to?: number): Promise<Array<typeof auditLog.$inferSelect>>;
  };

  private notifyCallback: AuditNotifyCallback | null = null;
  private outboxSink: AuditOutboxSink | null = null;
  private claimHashResolver: AttachedClaimHashResolver | null = null;
  private claimBindingFailureCallback:
    | ((failure: AuditClaimBindingFailure) => Promise<void> | void)
    | null = null;

  constructor(private db: Database) {}

  /**
   * Set a callback that fires after every successful audit write.
   * Used to trigger notification dispatch without coupling audit to notifications.
   */
  onWrite(callback: AuditNotifyCallback): void {
    this.notifyCallback = callback;
  }

  /**
   * The customer's events stream: every appended row is offered to the sink in
   * the same transaction, so an event commits or rolls back with its row.
   */
  setOutboxSink(sink: AuditOutboxSink): void {
    this.outboxSink = sink;
  }

  /**
   * Wire the passport_claims repo for auto-resolution of
   * passport_claims_at_event at audit-write time. Required before writing any
   * passport-bound v2 entry; missing or failed resolution denies the write.
   */
  setPassportClaimHashResolver(resolver: AttachedClaimHashResolver): void {
    this.claimHashResolver = resolver;
  }

  onClaimBindingFailure(
    callback: (failure: AuditClaimBindingFailure) => Promise<void> | void,
  ): void {
    this.claimBindingFailureCallback = callback;
  }

  /**
   * Append an audit entry. Per-operator hash chain is preserved under
   * concurrent writes from multiple processes:
   *
   *   1. Open a transaction.
   *   2. Take a Postgres advisory lock keyed on the operator id —
   *      serializes writes for the same operator across all machines.
   *   3. Read the latest entry's hash inside the locked transaction.
   *   4. Compute new entry's hash from the just-read prev_hash.
   *   5. Insert. Commit releases the lock.
   *
   * Previously this used an in-memory `headByOperator` cache that two
   * API machines could read concurrently and both write entries with
   * the same `prev_entry_hash`, breaking the chain ( audit
   * finding F23). The cache is gone; the DB is the single source of
   * truth, and the advisory lock prevents the race at its root.
   */
  async write(input: AuditInput, transaction?: AuditTransaction): Promise<string> {
    const entryId = ids.auditEntry();
    const lockKey = operatorLockKey(input.ctx.operator_id);
    // `timestamp` is captured INSIDE the locked transaction below, NOT
    // here. Capturing before the lock allows writers to race in JS
    // scheduling: W1 captures ts=1000, W2 captures ts=1001, but W2
    // may acquire the lock first and write row(ts=1001, prev=GENESIS);
    // W1 then writes row(ts=1000, prev=W2.hash). The verifier walks
    // in (timestamp, entry_id) order so it sees W1's row first, then
    // expects W2 to chain from W1 — but W2 has prev=GENESIS, producing
    // a false break that c40b502's entry_id tiebreaker cannot resolve
    // because timestamps are NOT equal here. stress test
    // surfaced this 2026-05-12.

    // resolve attached-claim hashes for the chain binding.
    // Caller-provided takes precedence; otherwise auto-fetch from the
    // repo when a passport_jti is present and a resolver is wired.
    let claimHashes: string[] | undefined = input.passport_claims_at_event;
    let claimBindingStatus: AuditClaimBindingStatus;
    const evidenceCriticalPassport =
      input.ctx.passport_jti.length > 0 && input.ctx.passport_jti !== 'none';
    if (!evidenceCriticalPassport) {
      claimBindingStatus = 'not_applicable';
    } else if (claimHashes !== undefined) {
      claimBindingStatus = claimHashes.length > 0 ? 'bound' : 'no_active_claims';
    } else if (!this.claimHashResolver) {
      await this.reportClaimBindingFailure(input, 'resolver_unavailable');
      throw new AuditClaimBindingError('resolver_unavailable');
    } else {
      try {
        claimHashes = await this.claimHashResolver.findActiveHashesByPassportId(
          input.ctx.passport_jti,
        );
      } catch {
        await this.reportClaimBindingFailure(input, 'resolver_failed');
        throw new AuditClaimBindingError('resolver_failed');
      }
      claimBindingStatus = claimHashes.length > 0 ? 'bound' : 'no_active_claims';
    }
    const sortedHashes =
      claimHashes && claimHashes.length > 0 ? [...claimHashes].sort() : undefined;

    let entryHash: string;
    let prevHash: string;

    let timestamp = 0;

    const append = async (tx: AuditTransaction) => {
      // Serialize concurrent audit-writes for this operator. Auto-released on commit.
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${sql.raw(lockKey)})`);

      // Capture timestamp INSIDE the lock so the (timestamp, entry_id)
      // chain order matches the lock-acquisition order. See the
      // explanatory comment at the top of this method for the race
      // shape that capturing before the lock produced.
      timestamp = nowMs();

      // Read latest entry hash INSIDE the locked transaction — no race possible.
      // Tiebreaker on entry_id (lexicographic) when timestamps collide at the
      // same millisecond. Without this, two writes with the same ms could pick
      // different "latest" rows non-deterministically, breaking the chain even
      // under the advisory lock. The diagnostic on the public sandbox operator surfaced
      // 147 same-millisecond breaks that match this pattern (2026-04-29).
      const latest = await tx.query.auditLog.findFirst({
        where: eq(auditLog.operator_id, input.ctx.operator_id),
        orderBy: (log, { desc }) => [desc(log.timestamp), desc(log.entry_id)],
        columns: { entry_hash: true },
      });
      prevHash = latest?.entry_hash ?? AUDIT_CHAIN_GENESIS;

      entryHash = computeAuditEntryHash({
        hash_version: AUDIT_HASH_VERSION_CURRENT,
        entry_id: entryId,
        trace_id: input.ctx.trace_id,
        span_id: input.ctx.span_id,
        parent_span_id: input.ctx.parent_span_id ?? null,
        timestamp,
        operator_id: input.ctx.operator_id,
        agent_id: input.ctx.agent_id,
        passport_jti: input.ctx.passport_jti,
        layer: input.layer,
        action: input.action,
        outcome: input.outcome,
        duration_ms: input.duration_ms ?? null,
        payload_hash: input.payload_hash ?? null,
        error_code: input.error?.code ?? null,
        error_message: input.error?.message ?? null,
        prev_entry_hash: prevHash,
        claim_binding_status: claimBindingStatus,
        passport_claims_at_event: sortedHashes,
        request_bytes: input.request_bytes ?? null,
        response_bytes: input.response_bytes ?? null,
        request_entropy: input.request_entropy ?? null,
        response_entropy: input.response_entropy ?? null,
        actor_grant_id: input.actor_grant_id ?? null,
        actor_partner_operator_id: input.actor_partner_operator_id ?? null,
      });

      await tx.insert(auditLog).values({
        entry_id: entryId,
        trace_id: input.ctx.trace_id,
        span_id: input.ctx.span_id,
        parent_span_id: input.ctx.parent_span_id ?? null,
        timestamp,
        operator_id: input.ctx.operator_id,
        agent_id: input.ctx.agent_id,
        passport_jti: input.ctx.passport_jti,
        layer: input.layer,
        action: input.action,
        outcome: input.outcome,
        duration_ms: input.duration_ms ?? null,
        payload_hash: input.payload_hash ?? null,
        error_code: input.error?.code ?? null,
        error_message: input.error?.message ?? null,
        prev_entry_hash: prevHash,
        entry_hash: entryHash,
        passport_claims_at_event: sortedHashes ?? null,
        request_bytes: input.request_bytes ?? null,
        response_bytes: input.response_bytes ?? null,
        request_entropy: input.request_entropy ?? null,
        response_entropy: input.response_entropy ?? null,
        actor_grant_id: input.actor_grant_id ?? null,
        actor_partner_operator_id: input.actor_partner_operator_id ?? null,
        hash_version: AUDIT_HASH_VERSION_CURRENT,
        claim_binding_status: claimBindingStatus,
      });

      if (this.outboxSink) {
        await this.outboxSink(tx, {
          entryId,
          operatorId: input.ctx.operator_id,
          agentId: input.ctx.agent_id,
          layer: input.layer,
          action: input.action,
          outcome: input.outcome,
          timestampMs: timestamp,
          errorCode: input.error?.code ?? null,
          entryHash,
          prevEntryHash: prevHash,
          ...(input.event_details ? { details: input.event_details } : {}),
        });
      }
    };

    if (transaction) {
      await append(transaction);
    } else {
      await this.db.transaction(append);
    }

    // A caller-owned transaction can still roll back after this method returns.
    // Do not emit a notification until that caller has committed.
    if (!transaction && this.notifyCallback && input.outcome === 'success') {
      try {
        this.notifyCallback(input.ctx.operator_id, input.action, input.outcome, input.ctx.agent_id);
      } catch {
        // Never let notification failures break audit logging
      }
    }

    return entryId;
  }

  private async reportClaimBindingFailure(
    input: AuditInput,
    reason: AuditClaimBindingFailure['reason'],
  ): Promise<void> {
    if (!this.claimBindingFailureCallback) return;
    try {
      await this.claimBindingFailureCallback({
        operatorId: input.ctx.operator_id,
        agentId: input.ctx.agent_id,
        passportJti: input.ctx.passport_jti,
        reason,
      });
    } catch {
      // The original evidence-critical action still fails closed even if the
      // independent security-event sink is unavailable.
    }
  }

  /**
   * Count audit entries for a specific operator, action, and time range.
   * Used for usage metering on the dashboard.
   */
  /**
   * Count several actions at once, over a window.
   *
   * The recorded-action allowance is enforced from a Redis counter, which is a
   * fast approximation: it is keyed per calendar month, it is not durable, and
   * an operator whose key is missing reads as zero. The audit log is the
   * durable record of the same events, so it is what a customer should be
   * SHOWN they used. Enforcement keeps its counter; display gets the truth.
   */
  async countByActions(
    operatorId: string,
    actions: string[],
    sinceMs: number,
    untilMs?: number,
  ): Promise<number> {
    if (actions.length === 0) return 0;
    const conditions = [
      eq(auditLog.operator_id, operatorId),
      inArray(auditLog.action, actions),
      gte(auditLog.timestamp, sinceMs),
    ];
    if (untilMs !== undefined) conditions.push(lt(auditLog.timestamp, untilMs));

    const result = await this.db
      .select({ count: sql<number>`count(*)::int` })
      .from(auditLog)
      .where(and(...conditions));
    return result[0]?.count ?? 0;
  }

  /**
   * The same count, split per action. One query answers "how many" and
   * "of what" together, so a total can never sit beside a breakdown that
   * does not sum to it - which is exactly what happened when the usage
   * drawer listed four hand-picked kinds under a meter that bills
   * eighteen: an evidence-pack export read as "1 action" over four zeros.
   */
  async countGroupedByActions(
    operatorId: string,
    actions: string[],
    sinceMs: number,
    untilMs?: number,
  ): Promise<Record<string, number>> {
    if (actions.length === 0) return {};
    const conditions = [
      eq(auditLog.operator_id, operatorId),
      inArray(auditLog.action, actions),
      gte(auditLog.timestamp, sinceMs),
    ];
    if (untilMs !== undefined) conditions.push(lt(auditLog.timestamp, untilMs));

    const rows = await this.db
      .select({ action: auditLog.action, count: sql<number>`count(*)::int` })
      .from(auditLog)
      .where(and(...conditions))
      .groupBy(auditLog.action);
    return Object.fromEntries(rows.map((r) => [r.action, r.count]));
  }

  async countByAction(
    operatorId: string,
    action: string,
    sinceMs: number,
    untilMs?: number,
  ): Promise<number> {
    const result = await this.db
      .select({ count: sql<number>`count(*)::int` })
      .from(auditLog)
      .where(
        and(
          eq(auditLog.operator_id, operatorId),
          eq(auditLog.action, action),
          eq(auditLog.outcome, 'success'),
          gte(auditLog.timestamp, sinceMs),
          untilMs !== undefined ? lt(auditLog.timestamp, untilMs) : undefined,
        ),
      );
    return result[0]?.count ?? 0;
  }

  /**
   * Lifetime counts of passports issued + credential proxy calls for
   * a single agent. Used by the agent overview's SETUP card so the
   * "passports" + "calls" rows show all-time totals instead of being
   * limited by the audit-tail page size. Two parallel COUNTs; both
   * gated by operator_id to prevent cross-tenant inference.
   */
  async getAgentStats(agentId: string, operatorId: string): Promise<{
    lifetime_passports: number;
    lifetime_calls: number;
  }> {
    const [passports, calls] = await Promise.all([
      this.db
        .select({ count: sql<number>`count(*)::int` })
        .from(auditLog)
        .where(and(
          eq(auditLog.operator_id, operatorId),
          eq(auditLog.agent_id, agentId),
          eq(auditLog.action, 'passport.issue'),
          eq(auditLog.outcome, 'success'),
        )),
      this.db
        .select({ count: sql<number>`count(*)::int` })
        .from(auditLog)
        .where(and(
          eq(auditLog.operator_id, operatorId),
          eq(auditLog.agent_id, agentId),
          like(auditLog.action, 'credential.%'),
          eq(auditLog.outcome, 'success'),
        )),
    ]);
    return {
      lifetime_passports: passports[0]?.count ?? 0,
      lifetime_calls: calls[0]?.count ?? 0,
    };
  }

  /**
   * No-op kept for backward compat with bootstrap code that called
   * `audit.initChain()` to clear in-memory caches at startup. The cache
   * is gone — chain head now lives in the DB and is read transactionally
   * on every write — so there's nothing to initialize.
   */
  async initChain(): Promise<void> {
    // intentionally empty
  }

  /**
   * Return the latest entry hash for an operator along with total entry
   * count. An external party can record this head daily and later
   * replay the export to confirm no row has been retroactively altered.
   */
  async getChainHead(operatorId: string): Promise<ChainHead> {
    const latest = await this.db.query.auditLog.findFirst({
      where: eq(auditLog.operator_id, operatorId),
      orderBy: (log, { desc }) => [desc(log.timestamp)],
      columns: { entry_hash: true, timestamp: true },
    });

    const [totalRow] = await this.db
      .select({ count: sql<number>`count(*)::int` })
      .from(auditLog)
      .where(eq(auditLog.operator_id, operatorId));

    return {
      latest_entry_hash: latest?.entry_hash ?? null,
      latest_timestamp: latest ? Number(latest.timestamp) : null,
      total_entries: totalRow?.count ?? 0,
    };
  }

  /**
   * Walk an operator's audit rows in chain order and verify:
   *   (1) each entry_hash matches a freshly-computed hash of its fields
   *       (catches any in-row content tampering), and
   *   (2) each row's prev_entry_hash equals the prior row's entry_hash
   *       (catches insertions, deletions, or re-ordering of rows).
   *
   * The walk uses keyset pagination on (timestamp, entry_id) so a chain
   * of any size walks in bounded memory. Without pagination, a chain of
   * 200K+ rows (the sandbox is 214K today) either exceeded the prior
   * 100K row hard ceiling — a false-negative if the break sat past the
   * cap — or risked OOM if the cap was removed naively.
   *
   * Ordering matches the write path's chain order: timestamp ascending,
   * with entry_id as the tiebreaker for same-millisecond writes. The
   * write path (audit-service.append) uses pg_advisory_xact_lock plus
   * an entry_id tiebreaker since commit c40b502; the verifier must
   * order identically or false breaks appear when two writes land in
   * the same millisecond.
   *
   * The first row of the scanned range seeds the walk — its
   * prev_entry_hash is accepted as-is, because the row preceding it
   * may sit outside the from/to window (or may have been pruned under
   * tier retention). For end-to-end integrity, scan from the earliest
   * retained row.
   *
   * `limit` semantics: when set, caps the total rows walked (single-
   * batch preview for admin / cheap previews). When unset, walks the
   * entire chain via pagination.
   */
  async verifyChain(
    operatorId: string,
    opts?: { from?: Date; to?: Date; limit?: number },
  ): Promise<ChainVerificationResult> {
    const baseConditions = [eq(auditLog.operator_id, operatorId)];
    if (opts?.from) baseConditions.push(gte(auditLog.timestamp, opts.from.getTime()));
    if (opts?.to) baseConditions.push(lt(auditLog.timestamp, opts.to.getTime()));

    const PAGE_SIZE = 5000;
    const maxRowsToWalk = opts?.limit ?? Number.POSITIVE_INFINITY;

    let lastTs = 0;
    let lastEntryId = '';
    let firstPage = true;
    let expectedPrev: string | null = null;
    let checked = 0;
    let head: string | null = null;

    while (checked < maxRowsToWalk) {
      const conditions = [...baseConditions];
      if (!firstPage) {
        // Keyset cursor on (timestamp, entry_id) so pagination matches
        // the write path's chain order. Tuple comparison avoids the
        // off-by-one risk of using strictly-greater on timestamp alone.
        conditions.push(
          or(
            gt(auditLog.timestamp, lastTs),
            and(eq(auditLog.timestamp, lastTs), gt(auditLog.entry_id, lastEntryId)),
          )!,
        );
      }
      const remainingBudget = maxRowsToWalk === Number.POSITIVE_INFINITY
        ? PAGE_SIZE
        : Math.max(0, maxRowsToWalk - checked);
      const pageLimit = Math.min(PAGE_SIZE, remainingBudget || PAGE_SIZE);

      const rows = await this.db
        .select()
        .from(auditLog)
        .where(and(...conditions))
        .orderBy(asc(auditLog.timestamp), asc(auditLog.entry_id))
        .limit(pageLimit);

      if (rows.length === 0) break;
      firstPage = false;

      for (const row of rows) {
        // Link check — skipped on the very first row of the entire walk.
        if (expectedPrev !== null && row.prev_entry_hash !== expectedPrev) {
          return {
            valid: false,
            total_checked: checked,
            head_entry_hash: head,
            first_break: {
              entry_id: row.entry_id,
              timestamp: Number(row.timestamp),
              reason: 'prev_hash_mismatch',
              expected: expectedPrev,
              actual: row.prev_entry_hash,
            },
          };
        }

        // Content check — recompute the hash from stored fields.
        // passport_claims_at_event is hashed when present non-empty
        // dropped from the canonical input when null/empty (legacy parity).
        // bytes/entropy hashed when non-null; dropped when null.
        const storedClaims = row.passport_claims_at_event;
        // Cold segments written before migration 0069 do not carry either
        // version field. Treat only that absent shape as v1 legacy; explicit
        // unknown versions remain a hard verification failure.
        const hashVersion = row.hash_version ?? 1;
        const claimBindingStatus = row.claim_binding_status ?? 'legacy_unbound';
        if (hashVersion !== 1 && hashVersion !== 2) {
          return {
            valid: false,
            total_checked: checked,
            head_entry_hash: head,
            first_break: {
              entry_id: row.entry_id,
              timestamp: Number(row.timestamp),
              reason: 'hash_mismatch',
              expected: 'supported hash version (1 or 2)',
              actual: String(hashVersion),
            },
          };
        }
        const recomputed = computeAuditEntryHash({
          hash_version: hashVersion,
          entry_id: row.entry_id,
          trace_id: row.trace_id,
          span_id: row.span_id,
          parent_span_id: row.parent_span_id,
          timestamp: Number(row.timestamp),
          operator_id: row.operator_id,
          agent_id: row.agent_id,
          passport_jti: row.passport_jti,
          layer: row.layer,
          action: row.action,
          outcome: row.outcome,
          duration_ms: row.duration_ms,
          payload_hash: row.payload_hash,
          error_code: row.error_code,
          error_message: row.error_message,
          prev_entry_hash: row.prev_entry_hash,
          claim_binding_status: claimBindingStatus as AuditClaimBindingStatus,
          passport_claims_at_event: storedClaims ?? undefined,
          request_bytes: row.request_bytes,
          response_bytes: row.response_bytes,
          request_entropy: row.request_entropy,
          response_entropy: row.response_entropy,
          actor_grant_id: row.actor_grant_id,
          actor_partner_operator_id: row.actor_partner_operator_id,
        });
        if (recomputed !== row.entry_hash) {
          return {
            valid: false,
            total_checked: checked,
            head_entry_hash: head,
            first_break: {
              entry_id: row.entry_id,
              timestamp: Number(row.timestamp),
              reason: 'hash_mismatch',
              expected: recomputed,
              actual: row.entry_hash,
            },
          };
        }

        expectedPrev = row.entry_hash;
        head = row.entry_hash;
        lastTs = Number(row.timestamp);
        lastEntryId = row.entry_id;
        checked++;

        if (checked >= maxRowsToWalk) break;
      }

      // Page returned fewer rows than asked = end of chain (and break out
      // even if the user budget would have allowed more).
      if (rows.length < pageLimit) break;
    }

    return {
      valid: true,
      total_checked: checked,
      head_entry_hash: head,
    };
  }

  /**
   * Delete audit_log rows older than the retention window (`AUDIT_RETENTION_DAYS`
   * for every account, or an account's negotiated override). Returns the counts
   * for logging: `default` and, when any, `_negotiated`.
   *
   * Note: the audit hash chain's prev_entry_hash references are broken by
   * retention pruning, but validation always walks forward from the oldest
   * retained row. Tamper-evidence is preserved for all retained rows.
   */
  async pruneExpired(retentionDays: number): Promise<Record<string, number>> {
    if (!(retentionDays > 0) || !Number.isFinite(retentionDays)) {
      throw new Error('Retention prune needs a positive, finite number of days');
    }
    const counts: Record<string, number> = {};
    const cutoffMs = Date.now() - retentionDays * 86400 * 1000;
    // Operators with a negotiated override are excluded here and pruned
    // below against their own window.
    const result = await this.db.execute(sql`
      DELETE FROM audit_log
      WHERE timestamp < ${cutoffMs}
      AND operator_id IN (
        SELECT id FROM operators WHERE audit_retention_days_override IS NULL
      )
    `);
    counts['default'] = (result as unknown as { rowCount?: number }).rowCount ?? 0;

    // Negotiated retention, per operator. Enterprise contracts sell a number
    // that is not on the rate card; without this the override column is
    // decoration and the tier default silently deletes data we promised to
    // keep.
    const overridden = await this.db.execute(sql`
      SELECT id, audit_retention_days_override AS days
      FROM operators
      WHERE audit_retention_days_override IS NOT NULL
    `);
    let overrideDeleted = 0;
    for (const row of overridden as unknown as Array<{ id: string; days: number }>) {
      if (!row.days || row.days <= 0) continue;
      const cutoffMs = Date.now() - row.days * 86400 * 1000;
      const result = await this.db.execute(sql`
        DELETE FROM audit_log
        WHERE timestamp < ${cutoffMs} AND operator_id = ${row.id}
      `);
      overrideDeleted += (result as unknown as { rowCount?: number }).rowCount ?? 0;
    }
    if (overrideDeleted > 0) counts['_negotiated'] = overrideDeleted;

    return counts;
  }

  /**
   * Paginated read for export. Returns audit rows for an operator within a
   * date range, ordered newest-first. Capped at `limit` rows.
   */
  async listForExport(params: {
    operatorId: string;
    from?: Date;
    to?: Date;
    limit?: number;
    offset?: number;
  }) {
    const conditions = [eq(auditLog.operator_id, params.operatorId)];
    if (params.from) conditions.push(gte(auditLog.timestamp, params.from.getTime()));
    if (params.to) conditions.push(lt(auditLog.timestamp, params.to.getTime()));

    const limit = Math.min(params.limit ?? 10_000, 50_000);
    const offset = params.offset ?? 0;

    const hot = await this.db
      .select()
      .from(auditLog)
      .where(and(...conditions))
      .orderBy(desc(auditLog.timestamp))
      .limit(limit)
      .offset(offset);

    // Cold fallback. Once the archive is running, most of a customer's history
    // is not in Postgres — and export is the one thing the terms promise
    // always works. Returning only the hot window would mean silently handing
    // back a truncated chain, which on an audit product is the worst possible
    // failure: it looks like an answer.
    if (!this.archive) return hot;

    const cold = await this.archive.readRange(
      params.operatorId,
      params.from?.getTime(),
      params.to?.getTime(),
    );
    if (cold.length === 0) return hot;

    const merged = [...hot, ...cold].sort((a, b) => b.timestamp - a.timestamp);
    return merged.slice(offset, offset + limit);
  }

  /**
   * Read-through to cold storage.
   *
   * Late-wired for the same reason the security services are: the archive
   * needs a database and an object store that do not exist when AuditService
   * is constructed. Unset means hot-only, which is correct before the archive
   * is configured and wrong afterwards — so the worker sets it at boot.
   */
  setArchive(archive: { readRange(operatorId: string, from?: number, to?: number): Promise<Array<typeof auditLog.$inferSelect>> }): void {
    this.archive = archive;
  }

  /**
   * Tail read: latest N audit entries for one operator, ordered newest-first.
   * Optional `sinceMs` watermark returns only rows newer than that timestamp —
   * used by polling clients (CLI --follow, dashboard tail) to incrementally
   * append rather than re-render the full window. Optional `agentId` and
   * `passportJti` narrow to a single agent or single passport — the typical
   * "tail what THIS agent is doing right now" workflow.
   */
  async listRecent(params: {
    operatorId: string;
    limit?: number;
    sinceMs?: number;
    agentId?: string;
    passportJti?: string;
    /** Any-of variant. One passport is one working session, so a caller that
     *  wants a whole session's rows (the public challenge board filtering to
     *  one visitor's code) passes the session's jtis rather than N queries. */
    passportJtis?: string[];
  }) {
    const conditions = [eq(auditLog.operator_id, params.operatorId)];
    if (params.sinceMs && Number.isFinite(params.sinceMs)) {
      conditions.push(gte(auditLog.timestamp, params.sinceMs));
    }
    if (params.agentId) {
      conditions.push(eq(auditLog.agent_id, params.agentId));
    }
    if (params.passportJti) {
      conditions.push(eq(auditLog.passport_jti, params.passportJti));
    }
    if (params.passportJtis) {
      // Empty list = match nothing. Fail closed: a filter that resolves to no
      // sessions must not quietly return the whole operator's log.
      conditions.push(
        params.passportJtis.length > 0
          ? inArray(auditLog.passport_jti, params.passportJtis)
          : sql`false`,
      );
    }

    return this.db
      .select()
      .from(auditLog)
      .where(and(...conditions))
      .orderBy(desc(auditLog.timestamp))
      .limit(Math.min(params.limit ?? 20, 100));
  }
}
