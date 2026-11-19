import { z } from 'zod';

/**
 * behavioral_genome — passport-scoped behavioral fingerprint over a
 * fixed time window. Each genome is a rolling snapshot of how a
 * passport behaved during the window, expressed as scalar aggregates
 * plus two histograms.
 *
 * of the Signed Primitive epic. Pillar 2 of
 * the Mission Layer (the Mission layer design). Schema lands
 * in 5.1.1; producer in 5.1.2; rollup worker in 5.1.3; drift detector +
 * `behavioral_anomaly` catalog promotion in 5.1.4; mission-baseline
 * integration in 5.1.5.
 *
 * How genomes get produced:
 *   - Daily UTC rollup over the last 24h per active passport (enterprise
 *     tier), via the worker's `maybeRunBehavioralGenomeRollup` job.
 *   - Checkpoint-driven fire-and-forget emission inside
 *     `AccountabilityService.submitCheckpoint` for immediate drift
 *     detection on enforced agents.
 *
 * How genomes get consumed:
 *   - `BehavioralDriftDetector` (5.1.4) reads `prior_genome_ref` to
 *     fetch the previous genome on the same passport, computes z-score
 *     per scalar dimension + L1 distance for histograms, fires
 *     `behavioral_anomaly` (severity by dimension) when any scalar
 *     z-score crosses 3σ.
 *   - `MissionService.open` (5.1.5) calls
 *     `behavioralGenome.getLatestForPassport(passportJti)` and snapshots
 *     the metric payload into `mission.baseline_profile`.
 *   - `MissionService.complete` (5.1.5) computes a mission-window genome
 *     and diffs against the mission's baseline_profile, attaching the
 *     diff as `behavioral_diff` on the terminal-state mission claim.
 *
 * Cold start convention: when no prior genome exists for a passport,
 * `prior_genome_ref` is null and the producer is free to emit
 * call_count=0 with zero-valued means/stddevs. The drift detector
 * skips diff math on cold-start genomes (z-score against empty baseline
 * is undefined).
 *
 * Wire-shape invariant: this schema's field set is additive-only for
 * 24 months per envelope.ts:21-25. Every metric here will be on the
 * wire forever. The 5 LLM-token fields ship in v1 with `.default()`
 * so they parse for pre-5.2.5 producers; 5.2.5 lights up the producer
 * without a schema edit.
 *
 * Field set rationale (18 metrics across 8 dimensions of drift):
 *   - Volume: call_count
 *   - Latency: mean + stddev of audit_log.duration_ms
 *   - Request size: mean + stddev of per-call request bytes
 *       (exfil-shape signal — agent suddenly POSTing large blobs)
 *   - Response size: mean + stddev of per-call response bytes
 *       (data-pull-shape signal — agent suddenly downloading large
 *       payloads)
 *   - Request entropy: mean + stddev of Shannon entropy of request
 *       bodies (exfil-shape signal masked under similar sizes —
 *       structured JSON vs base64 vs raw binary)
 *   - Response entropy: mean + stddev of Shannon entropy of response
 *       bodies (different data-pull shape than baseline)
 *   - Error rate: 4xx/5xx fraction (outcome != 'success' in audit_log)
 *   - LLM tokens: mean + stddev of prompt & completion token counts,
 *       plus model_distribution histogram (5.2.5 producer; default 0/{})
 *   - Scope: per-service call count histogram
 *   - Time of day: 24-bucket UTC hour-of-day distribution
 *
 * Derived dimensions intentionally NOT stored (computable from above):
 *   - distinct_services_count = Object.keys(scope_histogram).length
 *   - error_count = error_rate * call_count
 *   - distinct_models_count = Object.keys(model_distribution).length
 *   - mean_tokens_per_call = mean_prompt_tokens + mean_completion_tokens
 *
 * Producer data sources (5.1.2 picks the exact join):
 *   - Latency / error_rate / scope_histogram / time_of_day_histogram /
 *     entropy → audit_log filtered by (passport_jti, timestamp range).
 *   - Request/response bytes → audit_log needs `request_bytes` +
 *     `response_bytes` columns (DB migration in 5.1.2) OR a join with
 *     the proxy-layer per-call ledger if one exists.
 *   - LLM tokens / model_distribution → `llm_usage` table (5.2.4
 *     producer); empty until that table exists.
 *
 * A controls feature: the daily rollup in the worker signs one only for
 * the passports of an account with controls on.
 */
export const BehavioralGenomeClaim = z.object({
  type: z.literal('behavioral_genome'),

  // ── Bindings — what passport + window this fingerprint covers ──

  /** The passport this genome describes. Mirrors envelope.subject's jti. */
  passport_jti: z.string().min(1),

  /** unix ms — inclusive window start. */
  window_start_ms: z.number().int(),

  /** unix ms — exclusive window end. Refined to be > window_start_ms. */
  window_end_ms: z.number().int(),

  // ── Audit-log-derived metrics ──

  /** Total proxied calls in the window. Zero on cold start. */
  call_count: z.number().int().nonnegative(),

  /** Mean of audit_log.duration_ms across calls. Zero on cold start. */
  mean_latency_ms: z.number().nonnegative(),

  /** Within-window stddev of latency. Zero when call_count <= 1. */
  stddev_latency_ms: z.number().nonnegative(),

  /**
   * Mean request body bytes per call. Exfil-shape signal — agent
   * suddenly POSTing large blobs spikes this. Zero on cold start or
   * when the producer can't source byte data (pre-5.1.2 migration).
   */
  mean_request_bytes: z.number().nonnegative(),

  /** Within-window stddev of request bytes. */
  stddev_request_bytes: z.number().nonnegative(),

  /**
   * Mean response body bytes per call. Data-pull-shape signal — agent
   * suddenly downloading large payloads spikes this.
   */
  mean_response_bytes: z.number().nonnegative(),

  /** Within-window stddev of response bytes. */
  stddev_response_bytes: z.number().nonnegative(),

  /**
   * Mean Shannon entropy of request body content across calls. Catches
   * "agent suddenly POSTing structured vs. opaque payloads" — e.g.
   * shift from JSON to base64-encoded blobs (exfil shape masking) or
   * raw binary. Unit: bits per byte (0..8). Independent of size.
   */
  mean_request_entropy: z.number().nonnegative(),

  /** Within-window stddev of request body entropy. */
  stddev_request_entropy: z.number().nonnegative(),

  /**
   * Mean Shannon entropy of response body content across calls.
   * Catches "agent suddenly downloading binary blobs vs structured
   * JSON" — different data-pull shape than baseline. Unit: bits per
   * byte (0..8). Independent of size.
   */
  mean_response_entropy: z.number().nonnegative(),

  /** Within-window stddev of response body entropy. */
  stddev_response_entropy: z.number().nonnegative(),

  /**
   * Fraction of calls with audit_log.outcome != 'success'. Range
   * [0, 1]. Zero on cold start or when all calls succeeded.
   */
  error_rate: z.number().min(0).max(1),

  /**
   * service-slug → call count. Missing services = 0 calls. Drift
   * detector inspects keyset for "new service appeared" and per-value
   * counts for "service load shifted."
   */
  scope_histogram: z.record(z.string(), z.number().int().nonnegative()).default({}),

  /**
   * 24-bucket distribution of call counts by UTC hour-of-day. Index 0
   * = UTC 00:00-00:59. Catches "agent suddenly operates at unusual
   * hours" — useful when an account is compromised and the attacker
   * lives in a different timezone.
   */
  time_of_day_histogram: z.array(z.number().int().nonnegative()).length(24),

  // ── LLM-usage-derived metrics ──
  // Producer lights up in 5.2.5 (model gateway). Defaults make the
  // schema parse-clean for pre-5.2.5 producers without a v2 schema.

  /** Mean prompt tokens per LLM call. Zero until 5.2.5 producer wires. */
  mean_prompt_tokens: z.number().nonnegative().default(0),

  /** Within-window stddev of prompt tokens. */
  stddev_prompt_tokens: z.number().nonnegative().default(0),

  /** Mean completion tokens per LLM call. */
  mean_completion_tokens: z.number().nonnegative().default(0),

  /** Within-window stddev of completion tokens. */
  stddev_completion_tokens: z.number().nonnegative().default(0),

  /**
   * model-slug → call count. Key shape is producer-defined
   * (e.g. 'anthropic/claude-sonnet-4-6'). Drift detector inspects
   * keyset for "model changed" and per-value counts for "model
   * mix shifted."
   */
  model_distribution: z.record(z.string(), z.number().int().nonnegative()).default({}),

  // ── Chain pointer ──

  /**
   * Claim id (`pc_*`) of the previous genome on the same passport.
   * Null = cold start (this is the first genome for the passport).
   * The drift detector follows this pointer to fetch the prior genome
   * for diff math; the rollup worker sets it from
   * `behavioralGenome.getLatestForPassport(passportJti)?.claim_id`
   * before emitting.
   */
  prior_genome_ref: z.string().regex(/^pc_[\w-]+$/, 'prior_genome_ref must be a passport-claim id (pc_*)').nullable(),
})
.refine(
  (d) => d.window_end_ms > d.window_start_ms,
  { message: 'window_end_ms must be > window_start_ms' },
);

export type BehavioralGenomeClaim = z.infer<typeof BehavioralGenomeClaim>;
