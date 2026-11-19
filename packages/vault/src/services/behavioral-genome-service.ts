// BehavioralGenomeService.
//
// Producer + diff utility for `behavioral_genome` passport claims.
// Turns a passport's recent activity (audit_log rows) into a signed
// claim whose payload matches BehavioralGenomeClaim
// (packages/shared/src/schemas/passport-claims/behavioral-genome.ts).
//
// Pillar 2 of the Mission Layer — passport-scoped behavioral
// fingerprint. Schema locked in 5.1.1; this is the producer.
//
// Lifecycle:
//   1. computeGenome(jti, windowStart, windowEnd) → BehavioralGenomeClaim
//        Aggregates audit_log over the window; resolves prior_genome_ref
//        from the previous active genome on the same passport.
//   2. emitGenome(operatorId, jti, payload) → claimId
//        Dual-writes the claim via ClaimRegistryService. Tier-gated at
//        the registry (enterprise-only).
//   3. computeDiff(currentClaimId, priorClaimId) → DiffResult
//        z-score per scalar dimension (using prior's within-window
//        stddev as variance estimate); L1 distance for histograms.
//        Drives the 5.1.4 BehavioralDriftDetector.
//   4. getLatestForPassport(jti) → most recent active genome row, used
//        for chain-pointer resolution + mission baseline snapshots.
//   5. computeMissionWindowGenome(jti, startedAtMs) → BehavioralGenomeClaim
//        Convenience for MissionService.complete (5.1.5): computes a
//        genome over (mission.started_at, now). One-line wrapper that
//        keeps the dep graph clean (no MissionRepository import here).
//
// Window semantics:
//   - windowStartMs inclusive, windowEndMs exclusive
//   - audit_log.timestamp is unix ms (bigint mode: number)
//   - Cold start: zero rows in window → call_count=0, all means/stddevs
//     0, histograms empty, prior_genome_ref null. Schema accepts.
//
// Data sources (5.1.2 + 5.2.5):
//   - audit_log: latency / error_rate / scope_histogram /
//     time_of_day_histogram / call_count / bytes / entropy (bytes +
//     entropy populated only for HTTP-proxy entries; NULL for skills /
//     drop-off / mcp / accountability — producer aggregates over the
//     WHERE-NOT-NULL subset)
//   - llm_usage (5.2.5): prompt_tokens / completion_tokens means +
//     stddevs + model_distribution histogram. Captures /v1/llm/* gateway
//     calls only. Sealed-skill LLM usage is NOT in this table (lives on
//     skill invocation rows with a different cost-debit semantic) — folding
// it in is a separate change if/when warranted.

import {
  type Database,
  auditLog,
  llmUsage,
  BehavioralGenomeClaim as BehavioralGenomeClaimSchema,
  type BehavioralGenomeClaim,
} from '@stack/shared';
import { and, eq, gte, lt } from 'drizzle-orm';
import type { ClaimRegistryService } from './claim-registry-service.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';

export interface BehavioralGenomeServiceDeps {
  db: Database;
  claimRegistry: ClaimRegistryService;
  passportClaimsRepo: PassportClaimsRepository;
}

/**
 * Result of computeDiff. `max_z` and `l2_norm` are the scalar-dimension
 * drift summaries; `per_dimension` carries the individual z-scores and
 * histogram L1 distances. The 5.1.4 drift detector fires when
 * `max_z >= 3` or `l2_norm` exceeds its configured threshold.
 */
export interface BehavioralDiffResult {
  max_z: number;
  l2_norm: number;
  per_dimension: Record<string, number>;
}

/**
 * Sentinel z-score for "prior had zero variance but current value
 * differs." Mathematically z would be ±Infinity; we saturate at 10 so
 * downstream sums (l2_norm) stay finite.
 */
const Z_SATURATION = 10;

export class BehavioralGenomeService {
  constructor(private deps: BehavioralGenomeServiceDeps) {}

  /**
   * Aggregate audit_log over (windowStartMs, windowEndMs) for a single
   * passport into a BehavioralGenomeClaim payload. Resolves
   * prior_genome_ref from the most recent active genome on the same
   * passport before returning. Validates against the schema before
   * returning (catches producer-side regressions early).
   */
  async computeGenome(
    passportJti: string,
    windowStartMs: number,
    windowEndMs: number,
  ): Promise<BehavioralGenomeClaim> {
    const rows = await this.deps.db
      .select({
        timestamp: auditLog.timestamp,
        action: auditLog.action,
        outcome: auditLog.outcome,
        duration_ms: auditLog.duration_ms,
        request_bytes: auditLog.request_bytes,
        response_bytes: auditLog.response_bytes,
        request_entropy: auditLog.request_entropy,
        response_entropy: auditLog.response_entropy,
      })
      .from(auditLog)
      .where(
        and(
          eq(auditLog.passport_jti, passportJti),
          gte(auditLog.timestamp, windowStartMs),
          lt(auditLog.timestamp, windowEndMs),
        ),
      );

    const callCount = rows.length;

    // Latency — over all rows that recorded duration_ms (NULL on
    // failure-before-duration-known paths).
    const latencies = rows
      .map((r) => r.duration_ms)
      .filter((v): v is number => v != null);
    const { mean: meanLatency, stddev: stddevLatency } = meanStddev(latencies);

    // Bytes / entropy — only HTTP-proxy entries record these; others
    // are NULL. Aggregate over the non-null subset.
    const requestByteVals = rows
      .map((r) => r.request_bytes)
      .filter((v): v is number => v != null);
    const responseByteVals = rows
      .map((r) => r.response_bytes)
      .filter((v): v is number => v != null);
    const requestEntropyVals = rows
      .map((r) => r.request_entropy)
      .filter((v): v is number => v != null);
    const responseEntropyVals = rows
      .map((r) => r.response_entropy)
      .filter((v): v is number => v != null);

    const { mean: meanRequestBytes, stddev: stddevRequestBytes } = meanStddev(requestByteVals);
    const { mean: meanResponseBytes, stddev: stddevResponseBytes } = meanStddev(responseByteVals);
    const { mean: meanRequestEntropy, stddev: stddevRequestEntropy } = meanStddev(requestEntropyVals);
    const { mean: meanResponseEntropy, stddev: stddevResponseEntropy } = meanStddev(responseEntropyVals);

    // Error rate — fraction with outcome != 'success'. 0 when no calls.
    const errorCount = rows.filter((r) => r.outcome !== 'success').length;
    const errorRate = callCount === 0 ? 0 : errorCount / callCount;

    // Scope histogram — service slug extracted from the action string.
    // Format convention: 'credential.proxy' or 'skill.invoke:foo' etc.
    // Use the part before the first '.' as the service bucket. Producer
    // is conservative — unknown action shapes fall into their full
    // action string as the bucket.
    const scopeHistogram: Record<string, number> = {};
    for (const r of rows) {
      const service = extractServiceFromAction(r.action);
      scopeHistogram[service] = (scopeHistogram[service] ?? 0) + 1;
    }

    // Time-of-day histogram — 24 UTC-hour buckets.
    const todHistogram = new Array<number>(24).fill(0);
    for (const r of rows) {
      const hour = new Date(Number(r.timestamp)).getUTCHours();
      todHistogram[hour] = (todHistogram[hour] ?? 0) + 1;
    }

    // token-field metrics from llm_usage table.
    // Same window as the audit_log query above; separate select rather
    // than JOIN because (i) audit_log uses bigint unix-ms while
    // llm_usage uses timestamptz so a join needs cross-type conversion,
    // (ii) audit_log carries many non-LLM rows that would dilute the
    // join, (iii) the llm_usage_passport_time_idx is selective enough
    // that the standalone query is cheap (~ms).
    // Empty result → all five token fields gracefully fall to
    // {mean: 0, stddev: 0, distribution: {}}.
    const llmRows = await this.deps.db
      .select({
        prompt_tokens: llmUsage.prompt_tokens,
        completion_tokens: llmUsage.completion_tokens,
        model: llmUsage.model,
      })
      .from(llmUsage)
      .where(
        and(
          eq(llmUsage.passport_jti, passportJti),
          gte(llmUsage.created_at, new Date(windowStartMs)),
          lt(llmUsage.created_at, new Date(windowEndMs)),
        ),
      );

    const promptTokenVals = llmRows.map((r) => r.prompt_tokens);
    const completionTokenVals = llmRows.map((r) => r.completion_tokens);
    const { mean: meanPromptTokens, stddev: stddevPromptTokens } = meanStddev(promptTokenVals);
    const { mean: meanCompletionTokens, stddev: stddevCompletionTokens } = meanStddev(completionTokenVals);

    const modelDistribution: Record<string, number> = {};
    for (const r of llmRows) {
      modelDistribution[r.model] = (modelDistribution[r.model] ?? 0) + 1;
    }

    // Prior genome — chain pointer for diff lookup. Null on cold start.
    const prior = await this.getLatestForPassport(passportJti);
    const priorGenomeRef = prior?.claim_id ?? null;

    const payload: BehavioralGenomeClaim = {
      type: 'behavioral_genome',
      passport_jti: passportJti,
      window_start_ms: windowStartMs,
      window_end_ms: windowEndMs,
      call_count: callCount,
      mean_latency_ms: meanLatency,
      stddev_latency_ms: stddevLatency,
      mean_request_bytes: meanRequestBytes,
      stddev_request_bytes: stddevRequestBytes,
      mean_response_bytes: meanResponseBytes,
      stddev_response_bytes: stddevResponseBytes,
      mean_request_entropy: meanRequestEntropy,
      stddev_request_entropy: stddevRequestEntropy,
      mean_response_entropy: meanResponseEntropy,
      stddev_response_entropy: stddevResponseEntropy,
      error_rate: errorRate,
      scope_histogram: scopeHistogram,
      time_of_day_histogram: todHistogram,
      // token-field metrics aggregated from llm_usage above.
      mean_prompt_tokens: meanPromptTokens,
      stddev_prompt_tokens: stddevPromptTokens,
      mean_completion_tokens: meanCompletionTokens,
      stddev_completion_tokens: stddevCompletionTokens,
      model_distribution: modelDistribution,
      prior_genome_ref: priorGenomeRef,
    };

    // Validate against the schema before returning — catches producer
    // regressions (e.g. NaN/Infinity slipping through, missing field)
    // at the producer boundary, not at registry insertion time.
    return BehavioralGenomeClaimSchema.parse(payload);
  }

  /**
   * Convenience for MissionService.complete (5.1.5): compute a genome
   * over (mission.started_at, now). The caller passes the mission's
   * started_at timestamp; this service does not depend on
   * MissionRepository (keeps the dep graph one-way:
   * MissionService → BehavioralGenomeService, not the reverse).
   */
  async computeMissionWindowGenome(
    passportJti: string,
    missionStartedAtMs: number,
  ): Promise<BehavioralGenomeClaim> {
    return this.computeGenome(passportJti, missionStartedAtMs, Date.now());
  }

  /**
   * Dual-write the genome claim via ClaimRegistryService. A controls
   * feature: the daily rollup asks for the passports of accounts with
   * controls on only.
   */
  async emitGenome(
    operatorId: string,
    passportJti: string,
    payload: BehavioralGenomeClaim,
  ): Promise<{ claim_id: string }> {
    const res = await this.deps.claimRegistry.registerClaim({
      operatorId,
      passportJti,
      claimType: 'behavioral_genome',
      payload,
    });
    return { claim_id: res.claimId };
  }

  /**
   * canonical producer-side entry point. Single helper
   * used by BOTH 5.1.3 call sites (worker daily rollup +
   * AccountabilityService.submitCheckpoint hook). Encapsulates the
   * 3-step pattern: dedupe → compute → skip-if-empty → emit.
   *
   * Idempotent across crashes: the dedupe check uses
   * findActiveByTypeAndWindow(passportJti, 'behavioral_genome',
   * windowStartMs), so a worker restart that re-enters the rollup loop
   * does not produce duplicate claims.
   *
   * Error semantics — throws on hard errors (DB, KMS, registry write,
   * ForbiddenError from the registry tier gate if called for a
   * non-enterprise operator). Callers decide whether to swallow or
   * propagate. No internal try/catch — the service reports failures up
   * the stack rather than hiding them.
   *
   * Return shape — discriminates three outcomes for caller logging:
   *   - { emitted: true }                → new claim landed
   *   - { deduped: true, claimId: ... }  → existing claim for window
   *   - { emitted: false, callCount: 0 } → empty window, nothing to do
   */
  async emitForWindow(
    operatorId: string,
    passportJti: string,
    windowStartMs: number,
    windowEndMs: number,
  ): Promise<{
    claimId: string | null;
    callCount: number;
    emitted: boolean;
    deduped: boolean;
  }> {
    const existing = await this.deps.passportClaimsRepo.findActiveByTypeAndWindow(
      passportJti,
      'behavioral_genome',
      windowStartMs,
    );
    if (existing) {
      return {
        claimId: existing.claim_id,
        callCount: 0,
        emitted: false,
        deduped: true,
      };
    }

    const payload = await this.computeGenome(passportJti, windowStartMs, windowEndMs);
    if (payload.call_count === 0) {
      return { claimId: null, callCount: 0, emitted: false, deduped: false };
    }
    const { claim_id } = await this.emitGenome(operatorId, passportJti, payload);
    return {
      claimId: claim_id,
      callCount: payload.call_count,
      emitted: true,
      deduped: false,
    };
  }

  /**
   * Most recent active (non-revoked) behavioral_genome claim for the
   * passport. Returns null on cold start. Used by:
   *   - computeGenome (for prior_genome_ref resolution before emit)
   *   - MissionService.open (5.1.5) for baseline_profile snapshot
   *   - BehavioralDriftDetector (5.1.4) for diff math
   */
  async getLatestForPassport(passportJti: string) {
    const row = await this.deps.passportClaimsRepo.getLatestByType(
      passportJti,
      'behavioral_genome',
    );
    return row ?? null;
  }

  /**
   * Diff two genomes by claim_id. Returns scalar z-scores for every
   * mean+stddev pair (z = (current - prior_mean) / prior_stddev,
   * saturating at ±Z_SATURATION when prior_stddev is 0 but means
   * differ), plus L1 distance for the two histograms. `max_z` is the
   * max absolute z across scalar dims; `l2_norm` is sqrt(Σ z_i^2).
   *
   * Throws if either claim cannot be found OR if either body fails
   * schema re-parse (catches storage corruption / wire-shape drift).
   *
   * Math lives in the private diffPayloads helper; both this and
   * computeDiffFromPayloads delegate so the per-dimension semantics
   * stay identical across the two entry points.
   */
  async computeDiff(
    currentClaimId: string,
    priorClaimId: string,
  ): Promise<BehavioralDiffResult> {
    const [currentRow, priorRow] = await Promise.all([
      this.deps.passportClaimsRepo.findByClaimId(currentClaimId),
      this.deps.passportClaimsRepo.findByClaimId(priorClaimId),
    ]);
    if (!currentRow) throw new Error(`computeDiff: current claim ${currentClaimId} not found`);
    if (!priorRow) throw new Error(`computeDiff: prior claim ${priorClaimId} not found`);

    const current = BehavioralGenomeClaimSchema.parse(currentRow.body_json);
    const prior = BehavioralGenomeClaimSchema.parse(priorRow.body_json);
    return this.diffPayloads(current, prior);
  }

  /**
   * per-payload diff. Used by MissionService.complete
   * and revoke() where the mission-window genome is computed transiently
   * via computeMissionWindowGenome (never persisted as a claim — that
   * would pollute the chain semantics with non-standard windows). The
   * baseline side is a stored BehavioralGenomeClaim payload from
   * mission.baseline_profile (snapshotted at open()). Math is identical
   * to computeDiff; the only difference is the lookup step is skipped.
   *
   * Package-internal — NOT exposed via SDK / MCP. The transient-payload
   * use case is the only legitimate caller; broader exposure would
   * dilute the diff's semantic meaning (callers might compare arbitrary
   * payloads from unrelated passports).
   */
  computeDiffFromPayloads(
    current: BehavioralGenomeClaim,
    prior: BehavioralGenomeClaim,
  ): BehavioralDiffResult {
    return this.diffPayloads(current, prior);
  }

  private diffPayloads(
    current: BehavioralGenomeClaim,
    prior: BehavioralGenomeClaim,
  ): BehavioralDiffResult {
    const perDimension: Record<string, number> = {};

    // Pairs of (mean field, stddev field) — z-score uses the prior's
    // within-window stddev as the variance estimate.
    const pairs: Array<[keyof BehavioralGenomeClaim, keyof BehavioralGenomeClaim]> = [
      ['mean_latency_ms', 'stddev_latency_ms'],
      ['mean_request_bytes', 'stddev_request_bytes'],
      ['mean_response_bytes', 'stddev_response_bytes'],
      ['mean_request_entropy', 'stddev_request_entropy'],
      ['mean_response_entropy', 'stddev_response_entropy'],
      ['mean_prompt_tokens', 'stddev_prompt_tokens'],
      ['mean_completion_tokens', 'stddev_completion_tokens'],
    ];

    for (const [meanKey, stddevKey] of pairs) {
      // guard — skip token z-score when prior's mean is
      // zero. This dual-purpose check covers (a) pre-5.2.5 prior
      // genomes which carry the schema sentinel of all-zero token
      // fields, and (b) post-5.2.5 priors whose window had zero LLM
      // calls (also legitimately zero). Without this guard, the very
      // first post-5.2.5 diff on every active passport would z-score
      // saturate to ±10 against the pre-5.2.5 zero baseline and fire
      // genome_drift across the entire fleet on first rollup.
      // Trade-off: a passport that goes from zero-LLM in window N to
      // heavy-LLM in window N+1 will NOT trigger drift on that
      // transition. Acceptable — the next window's diff (heavy →
      // heavy with realistic stddev) catches outliers normally, and
      // "agent started using LLM at all" isn't an adversarial-shape
      // signal worth alerting on.
      if (
        (meanKey === 'mean_prompt_tokens' || meanKey === 'mean_completion_tokens') &&
        (prior[meanKey] as number) === 0
      ) {
        continue;
      }
      const z = zScore(
        current[meanKey] as number,
        prior[meanKey] as number,
        prior[stddevKey] as number,
      );
      perDimension[`z_${String(meanKey)}`] = z;
    }

    // call_count — no stddev; use Poisson approx (sqrt(prior)) when
    // prior > 0, sentinel otherwise.
    perDimension.z_call_count = poissonZ(current.call_count, prior.call_count);

    // error_rate — Bernoulli stddev = sqrt(p(1-p)/n); use prior's
    // call_count for n. Falls through to sentinel when n=0.
    perDimension.z_error_rate = bernoulliZ(
      current.error_rate,
      prior.error_rate,
      prior.call_count,
    );

    // Histograms — L1 distance normalized by total call count.
    perDimension.l1_scope_histogram = histogramL1(current.scope_histogram, prior.scope_histogram);
    perDimension.l1_time_of_day_histogram = histogramL1(
      indexedHistogramToRecord(current.time_of_day_histogram),
      indexedHistogramToRecord(prior.time_of_day_histogram),
    );
    perDimension.l1_model_distribution = histogramL1(
      current.model_distribution,
      prior.model_distribution,
    );

    // max_z + l2_norm summarize the scalar dimensions only (histograms
    // are on a different scale and would dominate L2 if mixed in).
    const zValues = Object.entries(perDimension)
      .filter(([k]) => k.startsWith('z_'))
      .map(([, v]) => v);
    const max_z = zValues.reduce((m, v) => Math.max(m, Math.abs(v)), 0);
    const l2_norm = Math.sqrt(zValues.reduce((s, v) => s + v * v, 0));

    return { max_z, l2_norm, per_dimension: perDimension };
  }
}

// ── Helpers ────────────────────────────────────────────────────────

/**
 * Population mean + stddev over a numeric array. Returns {mean: 0,
 * stddev: 0} for empty input (cold-start convention matches the
 * schema's nonnegative default). Single-element arrays have stddev = 0
 * (no within-array variance).
 */
function meanStddev(values: number[]): { mean: number; stddev: number } {
  if (values.length === 0) return { mean: 0, stddev: 0 };
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  if (values.length === 1) return { mean, stddev: 0 };
  const variance =
    values.reduce((s, v) => s + (v - mean) * (v - mean), 0) / values.length;
  return { mean, stddev: Math.sqrt(variance) };
}

function extractServiceFromAction(action: string): string {
  // Common shapes: 'credential.proxy', 'skill.invoke', 'passport.issue',
  // 'dropoff.deposit'. The substring before the first '.' is the
  // service-or-layer bucket. When no '.' exists, fall back to the full
  // action string.
  const dot = action.indexOf('.');
  return dot === -1 ? action : action.slice(0, dot);
}

function zScore(current: number, priorMean: number, priorStddev: number): number {
  if (priorStddev === 0) {
    return current === priorMean ? 0 : Math.sign(current - priorMean) * Z_SATURATION;
  }
  return (current - priorMean) / priorStddev;
}

function poissonZ(current: number, priorMean: number): number {
  if (priorMean === 0) {
    return current === 0 ? 0 : Math.sign(current) * Z_SATURATION;
  }
  return (current - priorMean) / Math.sqrt(priorMean);
}

function bernoulliZ(current: number, priorMean: number, priorN: number): number {
  if (priorN === 0) {
    return current === priorMean ? 0 : Math.sign(current - priorMean) * Z_SATURATION;
  }
  const variance = (priorMean * (1 - priorMean)) / priorN;
  if (variance === 0) {
    return current === priorMean ? 0 : Math.sign(current - priorMean) * Z_SATURATION;
  }
  return (current - priorMean) / Math.sqrt(variance);
}

/**
 * L1 distance between two histograms, normalized by the larger total.
 * Range [0, 2]: 0 = identical distributions (also identical totals), 2
 * = fully disjoint keysets with equal totals. Catches both "service
 * mix shifted" and "new service appeared" drift in one scalar.
 */
function histogramL1(
  current: Record<string, number>,
  prior: Record<string, number>,
): number {
  const keys = new Set([...Object.keys(current), ...Object.keys(prior)]);
  if (keys.size === 0) return 0;
  const totalCurrent = Object.values(current).reduce((s, v) => s + v, 0);
  const totalPrior = Object.values(prior).reduce((s, v) => s + v, 0);
  if (totalCurrent === 0 && totalPrior === 0) return 0;
  let l1 = 0;
  for (const k of keys) {
    const c = totalCurrent === 0 ? 0 : (current[k] ?? 0) / totalCurrent;
    const p = totalPrior === 0 ? 0 : (prior[k] ?? 0) / totalPrior;
    l1 += Math.abs(c - p);
  }
  return l1;
}

function indexedHistogramToRecord(arr: number[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (let i = 0; i < arr.length; i++) {
    out[String(i)] = arr[i] ?? 0;
  }
  return out;
}
