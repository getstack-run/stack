/**
 * DetectorService — orchestrates the prompt-injection chain (L1+L2+L3
 * input, L6 output) for any call site that proxies an agent's traffic.
 *
 * CR5 extract per ADR Design
 * Decision 14. Before this service, the chain ran inline inside
 * `apps/api/src/routes/proxy-call/`.
 * (Shroud-LITE, the LLM proxy) needs the same chain on its own hot
 * path; having two implementations is how detector behavior drifts.
 *
 * Architecture: dependency inversion. The scanner FUNCTIONS (regex
 * matchers, L3 LLM funnel, output-injection patterns, response
 * redactor) stay where they are in `apps/api/src/detectors/` — moving
 * 2,700 LOC of pattern catalogs is out of scope for 1.13 and would
 * not change behavior. The SERVICE in this file is the
 * orchestration layer: it fetches L7 overrides, calls the injected
 * scanner functions, records security events at the right severity,
 * and returns the caller's enforcement decisions (deny / redact).
 *
 * Callers (today proxy.ts shroud service.ts) construct
 * one DetectorService at bootstrap and pass it on the Services
 * bundle. Adding a new call site means one method invocation, not a
 * copy-paste of the 50-line block.
 *
 * Invariants:
 *   - Every non-clean verdict on input emits exactly one
 *     `prompt_injection` security event.
 *   - L3 degraded path emits one separate `prompt_injection` info-
 *     level event with `metadata.l3_degraded = true`.
 *   - Output match emits one `prompt_injection_output` event; the
 *     `redacted` boolean in metadata reflects whether enforced-mode-
 *     critical policy applied.
 *   - Caller decides enforcement: scanInput returns `denyReason`
 *     (non-null only when enforced + critical), scanOutput returns
 *     `redactedBody` (non-null only when enforced + critical).
 *     The service NEVER throws on a detector verdict — that policy
 *     belongs to the caller's request lifecycle.
 *   - Best-effort on `securityEvent.record` failures: a logged event
 *     that fails to write must not prevent the request from being
 *     allowed/denied per the verdict. The service swallows event-
 *     emit errors (await but no rethrow). This matches the previous
 *     inline behavior — block 6a + 9a didn't wrap emit in try/catch.
 */
import { safeErrorSummary, type OperatorCustomPattern, type OperatorWhitelistPattern } from '@stack/shared';
import type { OperatorDetectorConfigService } from './operator-detector-config-service.js';
import type { SecurityEventService } from './security-event-service.js';

// ─── Public types ───────────────────────────────────────────────────

/**
 * Operator-side detector overrides as fetched from
 * OperatorDetectorConfigService.getForDetector. The shape mirrors the
 * `OperatorDetectorOverrides` interface in
 * `apps/api/src/detectors/prompt-injection.ts` so the injected
 * scanner function consumes it directly.
 */
export interface DetectorOperatorOverrides {
  enabled: boolean;
  custom_patterns: OperatorCustomPattern[];
  whitelist_patterns: OperatorWhitelistPattern[];
  severity_overrides: Record<string, 'warning' | 'critical'>;
}

/**
 * A single L1+L2 prompt-injection match, as produced by the injected
 * input scanner. Re-declared here (rather than imported from
 * apps/api/src/detectors) because the SERVICE is in vault and must
 * not import upward from apps/api. The injected function returns
 * this shape; the service uses it to populate security-event metadata.
 */
export interface PromptInjectionMatch {
  pattern_id: string;
  field_path: string;
  matched_text: string;
  severity: 'warning' | 'critical';
  encoding?: string;
}

/**
 * L3 LLM classification result. Shape mirrors what the injected L3
 * funnel returns. The `degraded` flag is set when the LLM call timed
 * out / errored — the service routes that to a separate info-level
 * event so operators see when L3 isn't contributing.
 */
export interface PromptInjectionLlmResult {
  /**
   * 'suspicious' is the L3 classifier's mid-tier verdict; matches the
   * hosted LLM funnel's verdict union. The service folds
   * 'suspicious' into the merged verdict as 'warning' upstream of
   * scanInput — by the time the merged-verdict path runs, this field
   * only carries the raw classifier output for metadata purposes.
   */
  verdict: 'clean' | 'suspicious' | 'warning' | 'critical';
  confidence?: number;
  reasoning?: string;
  cost_cents?: number;
  duration_ms?: number;
  model?: string;
  degraded: boolean;
  /** Served from the verdict cache: no provider call ran. */
  cached?: boolean;
}

/**
 * Combined input-scan result. The merged `verdict` is what the
 * service routes on: clean → no event; warning/critical → one event
 * at that severity (or 'critical' on enforced-mode + verdict ===
 * 'critical'). callers should NOT inspect match/llm directly — use
 * the `denyReason` return value.
 */
export interface InputScanResult {
  match: PromptInjectionMatch | null;
  llm: PromptInjectionLlmResult | null;
  verdict: 'clean' | 'warning' | 'critical';
}

/**
 * A started input scan: L1+L2 are done, L3 may still be in flight.
 * Produced by the injected `inputScanStarter` (today
 * `startPromptInjectionScan` in apps/api/src/detectors/prompt-injection.ts).
 */
export interface InputScanHandle {
  /** L1+L2 result. Final when `l3` is null. */
  l1l2: InputScanResult;
  /** Merged L1+L2+L3 result, or null when L3 does not run. */
  l3: Promise<InputScanResult> | null;
  /** Cancel an in-flight L3 call and release its budget hold. Idempotent. */
  abort(): void;
}

/** Same inputs as `InputScanner`, returning a handle instead of a verdict. */
export type InputScanStarter = (args: Parameters<InputScanner>[0]) => InputScanHandle;

/**
 * A scan that has been started but whose verdict has not been acted on.
 * Exactly one of `finish` or `abort` should be called.
 */
export interface PendingInputScan {
  /**
   * Wait for the verdict, record its security events and return the caller's
   * decision. With `deferL3`, a caller whose mode cannot block (anything but
   * `enforced`) gets the L1+L2 decision immediately and the L3 verdict is
   * recorded when it lands. `deferL3` is ignored in enforced mode and on
   * dry runs, where the full verdict is the point.
   */
  finish(options?: { deferL3?: boolean }): Promise<ScanInputResult>;
  /** Abandon the scan: cancel L3, release its hold, record nothing. */
  abort(): void;
}

/**
 * Injected input scanner. Today this is
 * `scanForPromptInjectionAsync` from
 * `apps/api/src/detectors/prompt-injection.ts`. Shroud-LITE
 * wires the same function; the override path (`overrides`) is
 * forwarded so L7 customization still works on the LLM proxy path.
 */
export type InputScanner = (args: {
  body: unknown;
  fieldPath: string;
  overrides?: DetectorOperatorOverrides;
  /** skip the L3 LLM call (eval-traffic agents). */
  skipL3?: boolean;
  /** Who to bill the L3 classification to. The scanner resolves the
   * operator's included allowance and wallet from this; without it the
   * L3 call would run unbudgeted, which is how the LLM-gateway path
   * escaped metering entirely. */
  operatorId?: string;
  tier?: string;
  agentId?: string;
  passportJti?: string;
}) => Promise<InputScanResult>;

/**
 * Single output-side match. Field shape mirrors the apps/api
 * `OutputInjectionMatch` interface so the injected scanner function
 * returns it unmodified.
 */
export interface OutputInjectionMatch {
  pattern_id: string;
  severity: 'warning' | 'critical';
  matched_text: string;
  field_path: string;
}

/**
 * Injected output scanner. Today this is `scanResponseForOutputInjection`.
 * Synchronous because the underlying check is regex-only — no LLM
 * cost on the output side in v1.
 */
export type OutputScanner = (
  body: string,
  headers: Record<string, string>,
) => OutputInjectionMatch | null;

/**
 * Injected output redactor. Produces the synthetic body that
 * replaces the original when the response carries a credential-shape
 * leak under enforced mode. The returned shape MUST be JSON-encodable
 * — proxy.ts plumbs it into `result.body` which is later serialised
 * for the agent.
 */
export type OutputRedactor = (match: OutputInjectionMatch) => unknown;

export interface DetectorServiceDeps {
  securityEvent: SecurityEventService;
  operatorDetectorConfig: OperatorDetectorConfigService;
  inputScanner: InputScanner;
  /**
   * Two-phase form of `inputScanner`. When present, scans can start
   * L3 early and callers whose mode cannot block need not wait for it. When
   * absent the service falls back to `inputScanner` and always waits.
   */
  inputScanStarter?: InputScanStarter;
  outputScanner: OutputScanner;
  outputRedactor: OutputRedactor;
}

/** Caller context for a single detector pass. */
export interface DetectorCtx {
  operatorId: string;
  agentId: string;
  passportJti?: string;
  /**
   * Operator tier, for resolving the L3 classifier allowance.
   *
   * REQUIRED: a caller that omits it does not get a louder detector, it gets
   * a quieter one, so the compiler asks.
   */
  tier: string;
  /**
   * set true by callers that hold the agent row and see
   * eval_traffic=true. Skips the L3 LLM call; L1/L2 + event recording
   * (quiet-routed at SecurityEventService) proceed normally. Callers
   * without the agent row omit it — detection stays full-strength.
   */
  evalTraffic?: boolean;
  /**
   * Skip the paid L3 classifier: L1 and L2 run and record as usual. Set on an
   * agent account's traffic while its owner's controls are off
   * (the hosted account detector policy), where nothing is withheld and the flag travels
   * with the content.
   */
  skipL3?: boolean;
  /**
   * The accountability mode the caller's passport is operating under.
   * `enforced` is the only mode that triggers deny / redact policy;
   * `logged` and `standard` (and undefined) still emit events but the
   * caller forwards the request as-is.
   */
  mode?: string;
}

export interface ScanInputResult {
  /** The merged L1+L2+L3 verdict. */
  verdict: 'clean' | 'warning' | 'critical';
  /** L1/L2 match (if any). Surfaced for callers that want to log
   * pattern_id alongside their own request metadata. */
  match: PromptInjectionMatch | null;
  /** L3 result (if it ran). */
  llm: PromptInjectionLlmResult | null;
  /**
   * Set to a non-empty string ONLY when the caller should refuse the
   * request — enforced-mode AND verdict='critical'. The string is the
   * human-readable reason for the 403; the caller throws ForbiddenError
   * (or equivalent) with this message.
   *
   * `null` means: forward the request. Either the scan was clean, or
   * the mode is `logged`/`standard` (events fired, request continues),
   * or the verdict was non-critical.
   */
  denyReason: string | null;
  /**
   * True when the L3 classifier was still running when this decision was
   * returned (non-enforced mode with `deferL3`). Its verdict is recorded as
   * its own event when it lands; it can never change this decision.
   */
  l3Deferred?: boolean;
  /**
   * The security event recorded for this verdict. Null for a clean scan, a dry
   * run, or when recording failed (the decision stands either way).
   */
  securityEventId?: string | null;
}

export interface ScanOutputResult {
  /** The match (if any). Null = scan came up clean. */
  match: OutputInjectionMatch | null;
  /**
   * Set to a non-null body ONLY when the caller should swap the
   * response body — enforced-mode AND severity='critical'. The
   * shape is whatever the injected outputRedactor returns
   * (typically a structured refusal envelope).
   *
   * `null` means: forward the response unchanged. Either no match,
   * or the mode is `logged`/`standard`, or severity was `warning`.
   */
  redactedBody: unknown | null;
}

// ─── Service ────────────────────────────────────────────────────────

/** Arguments for one input scan. */
export interface ScanInputArgs {
  ctx: DetectorCtx;
  body: unknown;
  /** Field path passed to the underlying scanner. Defaults to 'body'. */
  fieldPath?: string;
  /**
   * Additional fields to merge into the recorded event's metadata.
   * Useful for caller-specific context (request_method,
   * request_service, etc.) without leaking caller types into the
   * service signature.
   */
  metadata?: Record<string, unknown>;
  /**
   * when true, skip the
   * `securityEvent.record(...)` side effects (both the L3-degraded
   * info event AND the main verdict event). The scanner output is
   * still returned to the caller so `IntentSimulationService` can
   * project `predicted_detector_fires` + populate the
   * `detector_block` denial reason without creating false security
   * events on simulation runs. Default false preserves existing
   * runtime behaviour at every proxy.ts call site.
   */
  dryRun?: boolean;
  /**
   * The body was written by a third party (inbound mail, SMS, a transcript),
   * not by the agent. A hit then never triggers the agent's on_critical
   * auto-block, since the agent did nothing and anyone could otherwise block
   * it by sending it a message, and the event keeps the match's position and
   * length but not the sender's words, which outlive the message otherwise.
   */
  thirdPartyContent?: boolean;
}

export class DetectorService {
  /** L3 verdicts still being recorded after their request was answered. */
  private readonly background = new Set<Promise<void>>();

  constructor(private deps: DetectorServiceDeps) {}

  /**
   * Run the L1+L2+L3 prompt-injection chain on inbound content,
   * record any signals, and return the caller's enforcement
   * decision. Equivalent to the inline block at
   * `apps/api/src/routes/proxy.ts` block 6a before this service
   * existed — same events, same metadata, same enforce-mode policy.
   *
   * `deferL3`: in a mode that cannot block, return the L1+L2
   * decision without waiting for the L3 classifier. See `beginInputScan`.
   */
  async scanInput(args: ScanInputArgs & { deferL3?: boolean }): Promise<ScanInputResult> {
    const { deferL3, ...scan } = args;
    return this.beginInputScan(scan).finish(deferL3 ? { deferL3 } : {});
  }

  /**
   * Start a scan now and act on it later.
   *
   * L1+L2 run as soon as the operator's overrides are loaded; L3, when the
   * gate sends the body to it, starts immediately and runs while the caller
   * does other work. Nothing is recorded until `finish`, so a request that a
   * later gate refuses (and `abort`s) leaves no detector events behind, exactly
   * as if the scan had never started.
   *
   * Enforcement is unchanged: `finish` in enforced mode always waits for the
   * full L1+L2+L3 verdict before returning a decision.
   */
  beginInputScan(args: ScanInputArgs): PendingInputScan {
    const dryRun = args.dryRun === true;
    const fieldPath = args.fieldPath ?? 'body';
    let abandoned = false;

    const started = (async (): Promise<InputScanHandle> => {
      // L7 — operator's per-detector overrides. Cache-fronted (~60s
      // TTL on Redis) so this is one cheap GET on the hot path.
      const overrideRow = await this.deps.operatorDetectorConfig.getForDetector(
        args.ctx.operatorId,
        'prompt_injection',
      );
      const overrides: DetectorOperatorOverrides | undefined = overrideRow
        ? {
            enabled: overrideRow.enabled,
            custom_patterns: overrideRow.custom_patterns ?? [],
            whitelist_patterns: overrideRow.whitelist_patterns ?? [],
            severity_overrides: overrideRow.severity_overrides ?? {},
          }
        : undefined;
      const scannerArgs: Parameters<InputScanner>[0] = {
        body: args.body,
        fieldPath,
        operatorId: args.ctx.operatorId,
        agentId: args.ctx.agentId,
        ...(args.ctx.passportJti ? { passportJti: args.ctx.passportJti } : {}),
        ...(args.ctx.tier ? { tier: args.ctx.tier } : {}),
        ...(overrides ? { overrides } : {}),
        ...(args.ctx.evalTraffic === true || args.ctx.skipL3 === true ? { skipL3: true } : {}),
      };
      if (abandoned) {
        // Refused before the scanner ran: nothing to start, nothing to cancel.
        return { l1l2: { match: null, llm: null, verdict: 'clean' }, l3: null, abort: () => {} };
      }
      if (this.deps.inputScanStarter) return this.deps.inputScanStarter(scannerArgs);
      // A scanner without a two-phase form is one opaque call: always waited.
      const full = await this.deps.inputScanner(scannerArgs);
      return { l1l2: full, l3: null, abort: () => {} };
    })();
    // A refused request may never call finish(); its failure must not surface
    // as an unhandled rejection. finish() still receives the original error.
    started.catch(() => undefined);

    return {
      abort: () => {
        abandoned = true;
        void started.then((handle) => handle.abort(), () => undefined);
      },
      finish: async (options = {}) => {
        const handle = await started;
        if (!handle.l3) return this.recordAndDecide(args, handle.l1l2);
        const defer = options.deferL3 === true && !dryRun && args.ctx.mode !== 'enforced';
        if (!defer) return this.recordAndDecide(args, await handle.l3);

        // Non-enforced: the L3 verdict can be recorded but can never block, so
        // the caller does not wait for it. L1+L2 are recorded now; L3 is
        // recorded when it lands, and only if it changes the verdict (or
        // degraded), so a request never yields two events saying the same
        // thing. If the process dies first, that L3 event is lost; the L1+L2
        // event, the audit row and the request itself are not.
        const l1l2 = handle.l1l2;
        const decision = await this.recordAndDecide(args, l1l2, { l3_pending: true });
        const deferred = handle.l3
          .then((full) => this.recordAndDecide(args, full, { l3_deferred: true }, {
            skipVerdictEvent: full.verdict === l1l2.verdict,
          }))
          .then(() => undefined)
          .catch((error: unknown) => {
            console.error('[detector] deferred layer three verdict could not be recorded:', safeErrorSummary(error));
          });
        this.trackBackground(deferred);
        return { ...decision, l3Deferred: true };
      },
    };
  }

  /** Number of deferred L3 verdicts not yet recorded. */
  get pendingBackgroundScans(): number {
    return this.background.size;
  }

  /**
   * Wait (bounded) for deferred L3 verdicts to be recorded. Called on graceful
   * shutdown so a deploy does not drop them. Returns how many were still
   * pending when the wait ended.
   */
  async drainBackground(timeoutMs = 5_000): Promise<number> {
    if (this.background.size === 0) return 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      Promise.allSettled([...this.background]),
      new Promise<void>((resolve) => { timer = setTimeout(resolve, timeoutMs); }),
    ]);
    if (timer) clearTimeout(timer);
    return this.background.size;
  }

  /**
   * Register follow-up work that records a verdict after its request was
   * answered, so `drainBackground` waits for it on shutdown. The promise must
   * not reject (log inside it).
   */
  trackBackground(work: Promise<void>): void {
    this.background.add(work);
    void work.finally(() => this.background.delete(work));
  }

  /**
   * Record the events for one verdict and return the caller's decision.
   * Shared by the waited path and the deferred path so both record the same
   * events with the same metadata.
   */
  private async recordAndDecide(
    args: ScanInputArgs,
    result: InputScanResult,
    extraMetadata: Record<string, unknown> = {},
    options: { skipVerdictEvent?: boolean } = {},
  ): Promise<ScanInputResult> {
    const dryRun = args.dryRun === true;
    const { match, llm, verdict } = result;

    // L3 degraded fallback — separate info-level signal so operators
    // see when the LLM funnel isn't contributing.
    if (llm?.degraded && !dryRun) {
      await this.deps.securityEvent
        .record({
          operatorId: args.ctx.operatorId,
          agentId: args.ctx.agentId,
          ...(args.ctx.passportJti ? { passportJti: args.ctx.passportJti } : {}),
          signalType: 'prompt_injection',
          severity: 'info',
          message: `L3 LLM classifier degraded: ${llm.reasoning ?? '(no reason)'}`,
          metadata: {
            l3_degraded: true,
            l3_duration_ms: llm.duration_ms,
            l3_model: llm.model,
          },
        })
        .catch(() => undefined);
    }

    if (verdict === 'clean') {
      return { verdict, match, llm, denyReason: null, securityEventId: null };
    }
    const thirdParty = args.thirdPartyContent === true;

    const mode = args.ctx.mode;
    const eventSeverity = mode === 'enforced' && verdict === 'critical' ? 'critical' : verdict;

    // Enforced + critical is the one combination every recording caller
    // refuses (proxy throws, inbound webhook does not forward). Stamped on
    // the event so a reader gets what the platform DID as recorded fact —
    // reconstructing it later from the agent's mode breaks the moment the
    // mode changes. Mirrors scanOutput's `redacted`.
    const blocked = mode === 'enforced' && verdict === 'critical';

    const causeBits: string[] = [];
    if (match) {
      causeBits.push(
        `L1/L2 ${match.pattern_id}@${match.field_path}${match.encoding ? '/' + match.encoding : ''}`,
      );
    }
    if (llm && !llm.degraded && llm.verdict !== 'clean') {
      causeBits.push(`L3 ${llm.verdict}@${llm.confidence ?? '?'}`);
    }

    let securityEventId: string | null = null;
    if (!dryRun && !options.skipVerdictEvent) {
      const event = await this.deps.securityEvent
        .record({
          operatorId: args.ctx.operatorId,
          agentId: args.ctx.agentId,
          ...(args.ctx.passportJti ? { passportJti: args.ctx.passportJti } : {}),
          signalType: 'prompt_injection',
          severity: eventSeverity,
          message: `Body caught injection: ${causeBits.join(' + ')}`,
          ...(thirdParty ? { skipAgentAutoBlock: true } : {}),
          metadata: {
            blocked,
            ...(match
              ? {
                  pattern_id: match.pattern_id,
                  field_path: match.field_path,
                  ...(thirdParty
                    ? { matched_length: match.matched_text.length }
                    : { matched_excerpt: match.matched_text }),
                  ...(match.encoding ? { encoding: match.encoding } : {}),
                }
              : {}),
            ...(llm && !llm.degraded
              ? {
                  l3_verdict: llm.verdict,
                  l3_confidence: llm.confidence,
                  ...(thirdParty ? {} : { l3_reasoning: llm.reasoning }),
                  l3_cost_cents: llm.cost_cents,
                  l3_duration_ms: llm.duration_ms,
                  ...(llm.cached ? { l3_cached: true } : {}),
                }
              : {}),
            ...(thirdParty ? { third_party_content: true } : {}),
            ...extraMetadata,
            ...(args.metadata ?? {}),
          },
        })
        .catch(() => undefined);
      securityEventId = event?.id ?? null;
    }

    const denyReason = blocked
      ? `Body matched prompt-injection chain (${causeBits.join(' + ')})`
      : null;

    return { verdict, match, llm, denyReason, securityEventId };
  }

  /**
   * Run the L6 output-side scan on a response body + headers. Same
   * mechanism as `apps/api/src/routes/proxy.ts` block 9a before this
   * service existed.
   *
   * Enforcement policy:
   *   - logged   → record event, no redaction
   *   - enforced → record event; on critical severity, ALSO return
   *                the redacted body (caller swaps it into the
   *                response).
   *   - standard → record event, no redaction
   *
   * Deliberately NOT auto-revoking: a leaked credential in an upstream
   * response is suspicious but does NOT mean THIS agent did something
   * wrong. Operators decide via the security event review.
   */
  async scanOutput(args: {
    ctx: DetectorCtx;
    body: string;
    headers: Record<string, string>;
    metadata?: Record<string, unknown>;
    /**
     * skip the
     * `securityEvent.record(...)` side effect when true. The match
     * result + redaction envelope are still returned so the caller
     * can make policy decisions without polluting security events.
     * Default false preserves existing runtime behaviour.
     */
    dryRun?: boolean;
  }): Promise<ScanOutputResult> {
    const match = this.deps.outputScanner(args.body, args.headers);
    if (!match) return { match: null, redactedBody: null };

    const sev = match.severity;
    const mode = args.ctx.mode;
    const shouldRedact = mode === 'enforced' && sev === 'critical';

    if (args.dryRun !== true) {
      await this.deps.securityEvent
        .record({
          operatorId: args.ctx.operatorId,
          agentId: args.ctx.agentId,
          ...(args.ctx.passportJti ? { passportJti: args.ctx.passportJti } : {}),
          signalType: 'prompt_injection_output',
          severity: sev,
          message: `Output-side detector caught ${match.pattern_id} on ${match.field_path}`,
          metadata: {
            pattern_id: match.pattern_id,
            field_path: match.field_path,
            // Output can contain the very credential we are trying to keep
            // out of the agent runtime. Persist the classification, never the
            // matched bytes themselves.
            matched_length: match.matched_text.length,
            redacted: shouldRedact,
            ...(args.metadata ?? {}),
          },
        })
        .catch(() => undefined);
    }

    return {
      match,
      redactedBody: shouldRedact ? this.deps.outputRedactor(match) : null,
    };
  }
}
