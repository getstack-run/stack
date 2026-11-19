// A customer's own control server as the decider.
//
// STACK posts the decision request, signed (Standard Webhooks, HMAC-SHA256 with
// the customer's decision secret), and expects a signed allow or deny within the
// decision timeout (2 s at most). Anything else is "no usable answer" and the
// action is refused: no answer, an error, a bad or missing signature, an answer
// for another request, an oversized or malformed body, an open breaker. A
// configured broken socket never falls back to no controls.
//
// The address is guarded twice: when it is set, and here at the moment of every
// call (DNS rebinding): the host is resolved, every address must be public, and
// the connection is pinned to the checked answer. https only (http in a
// development build), no redirects, no cookies, the response capped at 16 KB.
//
// Per customer on this machine: at most 64 decisions in flight (more queue, up to
// their deadline), and a circuit breaker that opens after 5 failures in a row or
// over half of the last 20 calls within 30 s, refuses for 15 s, then lets one
// probe through.

import {
  CONTROL_BREAKER_CONSECUTIVE_FAILURES,
  CONTROL_BREAKER_OPEN_MS,
  CONTROL_BREAKER_WINDOW_CALLS,
  CONTROL_BREAKER_WINDOW_MS,
  CONTROL_DECISION_MAX_IN_FLIGHT,
  CONTROL_DECISION_RESPONSE_MAX_BYTES,
  CONTROL_DECISION_TIMEOUT_MAX_MS,
  CONTROL_REASON_MESSAGE_MAX_CHARS,
  CONTROL_SIGNATURE_TOLERANCE_SECONDS,
  ControlDecisionAnswer,
  publicFetch,
  resolvePublicUrl,
  signStandardWebhook,
  UnsafeUrlError,
  verifyStandardWebhook,
  type ControlUnavailableCause,
} from '@stack/shared';
import type { ControlSocketService } from '@stack/vault';
import type { Decider, DecisionContext, DecisionResult } from './types.js';

type FetchFn = (url: string, init: RequestInit) => Promise<Response>;

export interface RemoteDeciderDeps {
  sockets: Pick<ControlSocketService, 'secrets' | 'noteAnswer'>;
  /** Tests inject an inert transport; production uses bounded, pinned publicFetch. */
  fetchFn?: FetchFn;
  /** Tests inject a guard; production resolves and checks the host (see `DNS_REFRESH_AFTER_MS`). */
  urlGuard?: (url: string) => Promise<unknown> | unknown;
  /** https only, except in a development build. */
  allowHttp?: boolean;
  now?: () => number;
}

/**
 * A checked answer is used as it is for this long. After it, the next decision is
 * still answered from it and a refresh runs beside it, so a lookup (up to five
 * seconds) is never paid inside the decision's own two seconds once an address is
 * known.
 */
const DNS_REFRESH_AFTER_MS = 45_000;
/** The longest a checked answer is used without a fresh one (a refresh that keeps failing). Past it, the lookup is the decision's. */
const DNS_STALE_MAX_MS = 5 * 60_000;
const DNS_MAX_ENTRIES = 512;

class Breaker {
  private consecutive = 0;
  private openedAt: number | null = null;
  private probing = false;
  private readonly window: Array<{ at: number; ok: boolean }> = [];

  /** Whether a call may go out now. After the open period exactly one probe may. */
  admit(now: number): boolean {
    if (this.openedAt === null) return true;
    if (now - this.openedAt < CONTROL_BREAKER_OPEN_MS) return false;
    if (this.probing) return false;
    this.probing = true;
    return true;
  }

  /** A call that never went out says nothing about the server; do not leave a probe pending. */
  cancel(): void {
    this.probing = false;
  }

  record(ok: boolean, now: number): void {
    this.probing = false;
    this.window.push({ at: now, ok });
    while (this.window.length > CONTROL_BREAKER_WINDOW_CALLS) this.window.shift();
    if (ok) {
      this.consecutive = 0;
      this.openedAt = null;
      return;
    }
    this.consecutive += 1;
    const recent = this.window.filter((entry) => now - entry.at <= CONTROL_BREAKER_WINDOW_MS);
    const failed = recent.filter((entry) => !entry.ok).length;
    const overHalf = recent.length >= CONTROL_BREAKER_WINDOW_CALLS && failed / recent.length > 0.5;
    if (this.consecutive >= CONTROL_BREAKER_CONSECUTIVE_FAILURES || overHalf || this.openedAt !== null) {
      this.openedAt = now;
    }
  }
}

class Gate {
  private inFlight = 0;
  private readonly waiters: Array<() => void> = [];

  /** Take a slot, waiting for one until `waitMs` is up. Returns false when none freed in time. */
  async acquire(waitMs: number): Promise<boolean> {
    if (this.inFlight < CONTROL_DECISION_MAX_IN_FLIGHT) {
      this.inFlight += 1;
      return true;
    }
    return new Promise<boolean>((resolve) => {
      const grant = () => {
        clearTimeout(timer);
        resolve(true);
      };
      const timer = setTimeout(() => {
        const at = this.waiters.indexOf(grant);
        if (at !== -1) this.waiters.splice(at, 1);
        resolve(false);
      }, Math.max(0, waitMs));
      this.waiters.push(grant);
    });
  }

  release(): void {
    const next = this.waiters.shift();
    if (next) next();
    else this.inFlight = Math.max(0, this.inFlight - 1);
  }
}

/** The customer's answer, trimmed to what the agent may be told. */
function cleanMessage(raw: string | undefined): string | null {
  if (!raw) return null;
  // eslint-disable-next-line no-control-regex -- stripping them is the point
  const cleaned = raw.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, CONTROL_REASON_MESSAGE_MAX_CHARS);
  return cleaned.length > 0 ? cleaned : null;
}

export class RemoteDecider implements Decider {
  readonly kind = 'remote' as const;
  private readonly breakers = new Map<string, Breaker>();
  private readonly gates = new Map<string, Gate>();
  private readonly dns = new Map<string, { addresses: string[]; resolvedAt: number }>();
  private readonly refreshing = new Map<string, Promise<void>>();
  private readonly hadBadAnswer = new Set<string>();
  private readonly now: () => number;

  constructor(private readonly deps: RemoteDeciderDeps) {
    this.now = deps.now ?? Date.now;
  }

  async decide(context: DecisionContext): Promise<DecisionResult> {
    const { socket, operatorId } = context;
    if (socket.decisionStatus === 'paused') return { verdict: 'unavailable', cause: 'paused' };
    if (socket.decisionStatus !== 'enforcing' || !socket.decisionUrl) return { verdict: 'unavailable', cause: 'unverified' };
    const started = this.now();
    const breaker = this.breakers.get(operatorId) ?? this.newBreaker(operatorId);
    if (!breaker.admit(started)) return { verdict: 'unavailable', cause: 'breaker_open' };

    let secrets: string[] | null;
    try {
      secrets = await this.deps.sockets.secrets(operatorId, 'decision');
    } catch {
      breaker.cancel();
      return { verdict: 'unavailable', cause: 'secret_unavailable' };
    }
    if (!secrets) {
      breaker.cancel();
      return { verdict: 'unavailable', cause: 'secret_unavailable' };
    }

    const timeoutMs = Math.min(socket.timeoutMs, CONTROL_DECISION_TIMEOUT_MAX_MS);
    const gate = this.gates.get(operatorId) ?? this.newGate(operatorId);
    const waited = await gate.acquire(timeoutMs - (this.now() - started));
    if (!waited) {
      breaker.cancel();
      return { verdict: 'unavailable', cause: 'busy' };
    }
    let result: DecisionResult;
    try {
      result = await this.exchange(socket.decisionUrl, secrets, context, timeoutMs - (this.now() - started));
    } finally {
      gate.release();
    }
    this.afterAnswer(operatorId, breaker, result);
    return result;
  }

  /**
   * The setup check and the test button: one real exchange with a `test: true`
   * request, with no breaker, no queue and no effect on the answer count. The
   * caller (verify) decides what to do with the result.
   */
  async probe(url: string, context: DecisionContext, timeoutMs: number): Promise<DecisionResult> {
    const secrets = await this.deps.sockets.secrets(context.operatorId, 'decision').catch(() => null);
    if (!secrets) return { verdict: 'unavailable', cause: 'secret_unavailable' };
    return this.exchange(url, secrets, context, Math.min(timeoutMs, CONTROL_DECISION_TIMEOUT_MAX_MS));
  }

  private newBreaker(operatorId: string): Breaker {
    const breaker = new Breaker();
    this.breakers.set(operatorId, breaker);
    return breaker;
  }

  private newGate(operatorId: string): Gate {
    const gate = new Gate();
    this.gates.set(operatorId, gate);
    return gate;
  }

  /** Feed the breaker and the bad-answer count. A busy queue says nothing about the server. */
  private afterAnswer(operatorId: string, breaker: Breaker, result: DecisionResult): void {
    const failed = result.verdict === 'unavailable';
    breaker.record(!failed, this.now());
    if (failed && result.cause === 'bad_signature') {
      this.hadBadAnswer.add(operatorId);
      void this.deps.sockets.noteAnswer(operatorId, false).catch(() => undefined);
    } else if (!failed && this.hadBadAnswer.delete(operatorId)) {
      void this.deps.sockets.noteAnswer(operatorId, true).catch(() => undefined);
    }
  }

  /** One signed request and one verified answer, inside `timeoutMs` in total. */
  private async exchange(
    url: string,
    secrets: readonly string[],
    context: DecisionContext,
    timeoutMs: number,
  ): Promise<DecisionResult> {
    if (timeoutMs <= 0) return { verdict: 'unavailable', cause: 'timeout' };
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<DecisionResult>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve({ verdict: 'unavailable', cause: 'timeout' });
      }, timeoutMs);
    });
    try {
      return await Promise.race([this.send(url, secrets, context, controller.signal, timeoutMs), deadline]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async send(
    url: string,
    secrets: readonly string[],
    context: DecisionContext,
    signal: AbortSignal,
    timeoutMs: number,
  ): Promise<DecisionResult> {
    const allowedProtocols = this.deps.allowHttp ? ['https:', 'http:'] : ['https:'];
    const decisionId = context.request.decision_id;
    const init: RequestInit = {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...signStandardWebhook({ id: decisionId, body: context.body, secrets }),
      },
      body: context.body,
      redirect: 'manual',
      signal,
    };

    let response: Response;
    let text: string;
    try {
      if (this.deps.fetchFn) {
        await this.deps.urlGuard?.(url);
        response = await this.deps.fetchFn(url, init);
      } else {
        const addresses = await this.resolve(url, allowedProtocols);
        response = await publicFetch(url, init, {
          timeoutMs,
          maxResponseBytes: CONTROL_DECISION_RESPONSE_MAX_BYTES,
          maxRequestBytes: 64 * 1024,
          allowedProtocols,
          resolvedAddresses: addresses,
          keepAlive: true,
        });
      }
      if (response.status !== 200) return { verdict: 'unavailable', cause: 'http_status' };
      const declared = Number(response.headers.get('content-length'));
      if (declared > CONTROL_DECISION_RESPONSE_MAX_BYTES) return { verdict: 'unavailable', cause: 'bad_body' };
      text = await response.text();
    } catch (error) {
      return { verdict: 'unavailable', cause: this.failureCause(error, signal) };
    }
    if (Buffer.byteLength(text) > CONTROL_DECISION_RESPONSE_MAX_BYTES) return { verdict: 'unavailable', cause: 'bad_body' };

    const verified = verifyStandardWebhook({
      headers: response.headers,
      body: text,
      secrets,
      toleranceSeconds: CONTROL_SIGNATURE_TOLERANCE_SECONDS,
    });
    if (!verified.ok) return { verdict: 'unavailable', cause: 'bad_signature' };
    if (verified.id !== decisionId) return { verdict: 'unavailable', cause: 'mismatch' };

    let parsed: ControlDecisionAnswer;
    try {
      const result = ControlDecisionAnswer.safeParse(JSON.parse(text));
      if (!result.success) return { verdict: 'unavailable', cause: 'bad_body' };
      parsed = result.data;
    } catch {
      return { verdict: 'unavailable', cause: 'bad_body' };
    }
    if (parsed.decision_id !== decisionId || parsed.request_digest !== context.request.request_digest) {
      return { verdict: 'unavailable', cause: 'mismatch' };
    }
    if (parsed.verdict === 'allow') {
      return { verdict: 'allow', policyRef: parsed.policy_ref ?? null };
    }
    return {
      verdict: 'deny',
      reason: { code: parsed.reason?.code ?? 'denied', message: cleanMessage(parsed.reason?.message) },
      ...(parsed.retry ? { retry: parsed.retry } : {}),
      policyRef: parsed.policy_ref ?? null,
    };
  }

  private failureCause(error: unknown, signal: AbortSignal): ControlUnavailableCause {
    if (signal.aborted) return 'timeout';
    if (error instanceof UnsafeUrlError) return 'unsafe_address';
    const name = error instanceof Error ? error.name : '';
    if (name === 'TimeoutError' || name === 'AbortError') return 'timeout';
    if (name === 'PublicFetchLimitError') return 'bad_body';
    return 'unreachable';
  }

  /**
   * The checked addresses for a host. A host is resolved and every address must
   * be public; the connection is then pinned to those addresses (and publicFetch
   * checks them again on every connect), so a DNS answer that changes in between
   * cannot redirect it.
   *
   * The lookup is off the decision path whenever it can be. The first decision
   * for an address has nothing checked to use and pays for it. After that the
   * last checked answer is used, and once it is getting old a refresh runs in the
   * background (one at a time): a refresh that fails keeps the last answer, one
   * that finds the host now points at a non-public address drops it, so the next
   * decision looks again and is refused. An answer older than `DNS_STALE_MAX_MS`
   * is not trusted and is looked up on the path.
   */
  private async resolve(url: string, allowedProtocols: string[]): Promise<string[]> {
    const hit = this.dns.get(url);
    if (hit) {
      const age = this.now() - hit.resolvedAt;
      if (age < DNS_REFRESH_AFTER_MS) return hit.addresses;
      if (age < DNS_STALE_MAX_MS) {
        this.refreshInBackground(url, allowedProtocols);
        return hit.addresses;
      }
    }
    return this.lookup(url, allowedProtocols);
  }

  private async lookup(url: string, allowedProtocols: string[]): Promise<string[]> {
    const { addresses } = await resolvePublicUrl(url, { allowedProtocols });
    const resolved = addresses.map(({ address }) => address);
    if (this.dns.size >= DNS_MAX_ENTRIES) this.dns.clear();
    this.dns.set(url, { addresses: resolved, resolvedAt: this.now() });
    return resolved;
  }

  private refreshInBackground(url: string, allowedProtocols: string[]): void {
    if (this.refreshing.has(url)) return;
    const refresh = this.lookup(url, allowedProtocols)
      .then(() => undefined)
      .catch((error: unknown) => {
        // The host now points somewhere it must not: nothing checked is left to use.
        if (error instanceof UnsafeUrlError) this.dns.delete(url);
      })
      .finally(() => {
        this.refreshing.delete(url);
      });
    this.refreshing.set(url, refresh);
  }
}
