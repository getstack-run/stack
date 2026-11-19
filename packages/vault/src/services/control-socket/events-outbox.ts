// The customer's record, streamed to their events address.
//
// Source: a transactional outbox inside the audit write. The audit service
// calls `ControlEventsSink.write` in the transaction that appends the row, with
// the operator's audit lock held, so an event commits or rolls back with the
// audit row it describes, and its sequence number is gapless and in chain
// order. An operator with no delivering events address costs one in-memory
// lookup per audit write.
//
// The stream is the record, and reading the record is a controls feature: an
// operator without controls has nothing enqueued (the audit row itself is
// written all the same, and the audit export reads it once controls are on).
// A controls status that cannot be read enqueues nothing either.
//
// Delivery: `ControlEventsDelivery.deliverDue` takes the sockets that are due
// (leased one machine at a time, on the database clock) and posts signed
// batches in order. At least once: a batch is deleted only after a 2xx. A 5xx,
// 408, 429, timeout or unreachable address backs off from 1 s to 1 h; after 72 h
// of failure delivery pauses (`failing`): the owner is told once, the outbox stops
// growing (a paused address stores nothing), and the next successful setup check
// announces what was skipped with one gap marker. Any other 4xx three times in a row
// turns the batch into a dead letter, announced once by a `stack.events.gap`
// event. Nothing here is on an action's path.
//
// What an event holds: the audit row's own public fields and chain hashes. Never
// an error message, a payload, a secret or a card number: the audit row has none.

import {
  assertPublicUrl,
  CONTROL_EVENTS_BACKOFF_BASE_MS,
  CONTROL_EVENTS_BACKOFF_MAX_MS,
  CONTROL_EVENTS_BATCH_MAX_BYTES,
  CONTROL_EVENTS_BATCH_MAX_EVENTS,
  CONTROL_EVENTS_CLIENT_ERROR_LIMIT,
  CONTROL_EVENTS_GIVE_UP_MS,
  CONTROL_EVENTS_RESPONSE_MAX_BYTES,
  CONTROL_EVENTS_RETENTION_DAYS,
  CONTROL_EVENTS_TIMEOUT_MS,
  ids,
  publicFetch,
  safeErrorSummary,
  signStandardWebhook,
  UnsafeUrlError,
  type ControlEvent,
  type ControlEventsBatch,
  type ControlSocketRow,
  type Database,
} from '@stack/shared';
import type { ControlSocketRepository } from '../../repositories/control-socket-repo.js';
import type { ControlSocketService } from './control-socket-service.js';

type Tx = Parameters<Parameters<Database['transaction']>[0]>[0];

/** What the audit write hands the sink: the row's public fields and where it sits in the chain. */
export interface AuditOutboxRow {
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
  /** A small allowlist passed by the writer, outside the hash. */
  details?: {
    account_id?: string;
    decision_id?: string;
    amount_cents?: number;
    refusal?: { policy_id: string; policy_revision: number; section: string; rule: string; code: string };
  };
}

export interface ControlEventsSinkOptions {
  /** How long "this operator has no events address" is trusted before asking again. */
  negativeTtlMs?: number;
  now?: () => number;
  /**
   * Whether the operator has controls (the stream is a controls feature). Absent: every operator streams, as on an
   * install, where every account has every controls feature.
   */
  controlsEnabled?: (operatorId: string) => Promise<boolean>;
  /**
   * Whether the operator's own server decides for them (the customer's own control socket). Such an account streams its
   * record whatever `controlsEnabled` says: hosted controls need the subscription, a self-hosted decider does not. Absent:
   * no account is treated as remote.
   */
  decidesRemotely?: (operatorId: string) => Promise<boolean>;
}

export class ControlEventsSink {
  private readonly noAddress = new Map<string, number>();
  private readonly negativeTtlMs: number;
  private readonly now: () => number;
  private readonly controlsEnabled: ((operatorId: string) => Promise<boolean>) | undefined;
  private readonly decidesRemotely: ((operatorId: string) => Promise<boolean>) | undefined;

  constructor(
    private readonly repo: ControlSocketRepository,
    options: ControlEventsSinkOptions = {},
  ) {
    this.negativeTtlMs = options.negativeTtlMs ?? 5_000;
    this.now = options.now ?? Date.now;
    this.controlsEnabled = options.controlsEnabled;
    this.decidesRemotely = options.decidesRemotely;
  }

  /** A customer's socket changed: forget that they had no events address. */
  forget(operatorId: string): void {
    this.noAddress.delete(operatorId);
  }

  /**
   * Enqueue the event for one audit row, inside its transaction. Isolated in a
   * savepoint: a failure here is logged and the audit write goes on, so the
   * record's delivery can never fail an action.
   */
  async write(tx: Tx, row: AuditOutboxRow): Promise<void> {
    const until = this.noAddress.get(row.operatorId);
    if (until !== undefined && until > this.now()) return;
    if (this.controlsEnabled) {
      try {
        const streams = (await this.controlsEnabled(row.operatorId))
          || (this.decidesRemotely !== undefined && (await this.decidesRemotely(row.operatorId)));
        if (!streams) return;
      } catch (error) {
        console.error('[CONTROL_EVENTS] controls status or decider unreadable so nothing enqueued:', safeErrorSummary(error));
        return;
      }
    }
    try {
      await tx.transaction(async (savepoint) => {
        const seq = await this.repo.enqueue(savepoint, row.operatorId, row.entryId, (n) => toEvent(row, n));
        if (seq === null) this.noAddress.set(row.operatorId, this.now() + this.negativeTtlMs);
      });
    } catch (error) {
      console.error('[CONTROL_EVENTS] outbox insert failed', safeErrorSummary(error));
    }
  }
}

function toEvent(row: AuditOutboxRow, seq: number): Record<string, unknown> {
  const event: ControlEvent = {
    id: row.entryId,
    seq,
    type: row.action,
    occurred_at: new Date(row.timestampMs).toISOString(),
    operator_id: row.operatorId,
    agent_id: row.agentId || null,
    account_id: row.details?.account_id ?? null,
    outcome: row.outcome,
    layer: row.layer,
    error_code: row.errorCode,
    decision_id: row.details?.decision_id ?? null,
    amount_cents: row.details?.amount_cents ?? null,
    chain: { entry_hash: row.entryHash, prev_entry_hash: row.prevEntryHash },
    ...(row.details?.refusal ? { refusal: row.details.refusal } : {}),
  };
  return event;
}

// ─── delivery ──────────────────────────────────────────────────────

export interface ControlEventsDeliveryDeps {
  repo: ControlSocketRepository;
  sockets: Pick<ControlSocketService, 'secrets'>;
  /** Tests inject an inert transport; production uses bounded publicFetch. */
  fetchFn?: typeof globalThis.fetch;
  /** Tests inject a guard; production runs the shared one, at the moment of the call. */
  urlGuard?: (url: string) => Promise<unknown> | unknown;
  /** https only, except in a development build. */
  allowHttp?: boolean;
  now?: () => number;
  leaseSeconds?: number;
  /** Called once when an address is paused after 72 hours of failed deliveries; tells the owner. Never throws into delivery. */
  onFailing?: (operatorId: string) => Promise<void>;
}

export interface DeliveryProbe {
  ok: boolean;
  cause: 'unsafe_address' | 'timeout' | 'unreachable' | 'http_status' | 'secret_unavailable' | null;
  latencyMs: number;
}

export interface DeliveryRun {
  claimed: number;
  delivered: number;
  retrying: number;
  deadLettered: number;
  failing: number;
  idle: number;
}

export class ControlEventsDelivery {
  private readonly now: () => number;

  constructor(private readonly deps: ControlEventsDeliveryDeps) {
    this.now = deps.now ?? Date.now;
  }

  /** One pass over the sockets that are due (or just one customer's). The runner calls this on a timer; tests call it directly. */
  async deliverDue(limit = 25, only: { operatorId?: string } = {}): Promise<DeliveryRun> {
    const run: DeliveryRun = { claimed: 0, delivered: 0, retrying: 0, deadLettered: 0, failing: 0, idle: 0 };
    const sockets = await this.deps.repo.claimDue(this.deps.leaseSeconds ?? 30, limit, only.operatorId);
    run.claimed = sockets.length;
    for (const socket of sockets) {
      try {
        const outcome = await this.deliverOne(socket);
        run[outcome] += 1;
      } catch (error) {
        console.error('[CONTROL_EVENTS] delivery pass failed', safeErrorSummary(error));
        await this.deps.repo.releaseLease(socket.operator_id).catch(() => {});
      }
    }
    return run;
  }

  private async deliverOne(socket: ControlSocketRow): Promise<keyof Omit<DeliveryRun, 'claimed'>> {
    const operatorId = socket.operator_id;
    await this.deps.repo.expireStale(operatorId, CONTROL_EVENTS_RETENTION_DAYS);
    const { dead, pending } = await this.deps.repo.nextBatch(operatorId, CONTROL_EVENTS_BATCH_MAX_EVENTS);
    if (dead.length === 0 && pending.length === 0) {
      await this.deps.repo.releaseLease(operatorId);
      return 'idle';
    }
    const batchId = ids.controlEventBatch();
    const included = packBatch(operatorId, socket.socket_id, batchId, dead, pending);
    const secrets = await this.deps.sockets.secrets(operatorId, 'events');
    if (!socket.events_url || !secrets) {
      await this.deps.repo.recordRetry(operatorId, {
        backoffMs: CONTROL_EVENTS_BACKOFF_MAX_MS, error: 'secret_unavailable', giveUpAfterMs: CONTROL_EVENTS_GIVE_UP_MS,
      });
      return 'retrying';
    }

    const result = await this.post(socket.events_url, included.body, batchId, secrets);
    if (result.kind === 'ok') {
      await this.deps.repo.acknowledge(operatorId, { throughSeq: included.throughSeq, deadSeqs: included.deadSeqs });
      return 'delivered';
    }
    if (result.kind === 'refused') {
      const refusals = await this.deps.repo.recordClientError(operatorId, `http_${result.status}`);
      if (refusals >= CONTROL_EVENTS_CLIENT_ERROR_LIMIT) {
        await this.deps.repo.markBatchDead(operatorId, included.throughPendingSeq);
        return 'deadLettered';
      }
      return 'retrying';
    }
    const backoffMs = Math.min(CONTROL_EVENTS_BACKOFF_MAX_MS, CONTROL_EVENTS_BACKOFF_BASE_MS * 2 ** Math.min(socket.events_attempts, 20));
    const { failing } = await this.deps.repo.recordRetry(operatorId, {
      backoffMs, error: result.error, giveUpAfterMs: CONTROL_EVENTS_GIVE_UP_MS,
    });
    if (failing) await this.alertOwner(operatorId);
    return failing ? 'failing' : 'retrying';
  }

  private async alertOwner(operatorId: string): Promise<void> {
    try {
      await this.deps.onFailing?.(operatorId);
    } catch (error) {
      console.error('[CONTROL_EVENTS] could not tell the owner delivery paused', safeErrorSummary(error));
    }
  }

  /**
   * Retention that does not depend on a socket being claimed: pending events
   * past their age become dead for every customer, and the dead events of a
   * socket nobody delivers are folded into one row. The runner calls this on a
   * timer, beside the delivery pass.
   */
  async sweep(): Promise<{ expired: number; folded: number }> {
    const expired = await this.deps.repo.expireAllStale(CONTROL_EVENTS_RETENTION_DAYS);
    const folded = await this.deps.repo.compactDead();
    return { expired, folded };
  }

  /**
   * The setup check and the test button: one signed, empty `test: true` batch.
   * Any 2xx counts. Guarded and bounded exactly like a delivery.
   */
  async probe(operatorId: string, socketId: string, url: string): Promise<DeliveryProbe> {
    const secrets = await this.deps.sockets.secrets(operatorId, 'events');
    if (!secrets) return { ok: false, cause: 'secret_unavailable', latencyMs: 0 };
    const batch: ControlEventsBatch = {
      type: 'stack.events.batch', version: '1', batch_id: ids.controlEventBatch(), test: true,
      operator_id: operatorId, socket_id: socketId, events: [],
    };
    const started = this.now();
    const result = await this.post(url, JSON.stringify(batch), batch.batch_id, secrets);
    const latencyMs = Math.max(0, this.now() - started);
    if (result.kind === 'ok') return { ok: true, cause: null, latencyMs };
    if (result.kind === 'refused') return { ok: false, cause: 'http_status', latencyMs };
    return { ok: false, cause: result.cause, latencyMs };
  }

  private async post(
    url: string,
    body: string,
    batchId: string,
    secrets: readonly string[],
  ): Promise<
    | { kind: 'ok' }
    | { kind: 'refused'; status: number }
    | { kind: 'retry'; error: string; cause: 'unsafe_address' | 'timeout' | 'unreachable' | 'http_status' }
  > {
    const allowedProtocols = this.deps.allowHttp ? ['https:', 'http:'] : ['https:'];
    try {
      await (this.deps.urlGuard ?? ((u: string) => assertPublicUrl(u, { allowedProtocols })))(url);
    } catch {
      return { kind: 'retry', error: 'unsafe_address', cause: 'unsafe_address' };
    }
    const headers = {
      'content-type': 'application/json',
      ...signStandardWebhook({ id: batchId, body, secrets }),
    };
    const init: RequestInit = {
      method: 'POST', headers, body, redirect: 'manual', signal: AbortSignal.timeout(CONTROL_EVENTS_TIMEOUT_MS),
    };
    try {
      const response = this.deps.fetchFn
        ? await this.deps.fetchFn(url, init)
        : await publicFetch(url, init, {
          timeoutMs: CONTROL_EVENTS_TIMEOUT_MS,
          maxResponseBytes: CONTROL_EVENTS_RESPONSE_MAX_BYTES,
          allowedProtocols,
        });
      await response.arrayBuffer().catch(() => undefined);
      const status = response.status;
      if (status >= 200 && status < 300) return { kind: 'ok' };
      if (status >= 500 || status === 408 || status === 429) return { kind: 'retry', error: `http_${status}`, cause: 'http_status' };
      return { kind: 'refused', status };
    } catch (error) {
      if (error instanceof UnsafeUrlError) return { kind: 'retry', error: 'unsafe_address', cause: 'unsafe_address' };
      const name = error instanceof Error ? error.name : '';
      if (name === 'TimeoutError' || name === 'AbortError') return { kind: 'retry', error: 'timeout', cause: 'timeout' };
      return { kind: 'retry', error: 'unreachable', cause: 'unreachable' };
    }
  }
}

interface PackedBatch {
  body: string;
  /** Highest sequence number in the batch, dead or pending. */
  throughSeq: number;
  /** Highest pending sequence number in the batch (the dead-letter boundary). */
  throughPendingSeq: number;
  deadSeqs: number[];
}

type OutboxRow = { seq: number; event: Record<string, unknown> };

/**
 * Merge the unannounced dead events (as gap markers over contiguous runs) and
 * the pending ones in sequence order, and cut at the batch's count and size.
 */
function packBatch(operatorId: string, socketId: string, batchId: string, dead: OutboxRow[], pending: OutboxRow[]): PackedBatch {
  const entries: Array<{ seq: number; event: ControlEvent; dead: boolean; deadSeqs: number[] }> = [];
  let run: number[] = [];
  let runFrom = 0;
  const flush = () => {
    if (run.length === 0) return;
    const [first, last] = [runFrom, run[run.length - 1]!];
    entries.push({
      seq: last, dead: true, deadSeqs: run,
      event: {
        id: `gap_${first}_${last}`, seq: last, type: 'stack.events.gap', occurred_at: new Date().toISOString(),
        operator_id: operatorId, agent_id: null, account_id: null, outcome: 'failure', layer: 'system',
        error_code: null, decision_id: null, amount_cents: null, chain: null, gap: { from_seq: first, to_seq: last },
      },
    });
    run = [];
  };
  for (const row of dead) {
    // A folded row stands for the whole range it announces; a plain one for its own number.
    const from = (row.event as { gap?: { from_seq?: number } }).gap?.from_seq ?? row.seq;
    if (run.length > 0 && from !== run[run.length - 1]! + 1) flush();
    if (run.length === 0) runFrom = from;
    run.push(row.seq);
  }
  flush();
  for (const row of pending) entries.push({ seq: row.seq, event: row.event as unknown as ControlEvent, dead: false, deadSeqs: [] });
  entries.sort((a, b) => a.seq - b.seq);

  const events: ControlEvent[] = [];
  const deadSeqs: number[] = [];
  let throughSeq = 0;
  let throughPendingSeq = 0;
  let size = 512;
  for (const entry of entries) {
    const entrySize = Buffer.byteLength(JSON.stringify(entry.event));
    if (events.length > 0 && (events.length >= CONTROL_EVENTS_BATCH_MAX_EVENTS || size + entrySize > CONTROL_EVENTS_BATCH_MAX_BYTES)) break;
    events.push(entry.event);
    size += entrySize;
    throughSeq = Math.max(throughSeq, entry.seq);
    if (entry.dead) deadSeqs.push(...entry.deadSeqs);
    else throughPendingSeq = Math.max(throughPendingSeq, entry.seq);
  }
  const batch: ControlEventsBatch = {
    type: 'stack.events.batch', version: '1', batch_id: batchId, test: false, operator_id: operatorId, socket_id: socketId, events,
  };
  return { body: JSON.stringify(batch), throughSeq, throughPendingSeq, deadSeqs };
}
