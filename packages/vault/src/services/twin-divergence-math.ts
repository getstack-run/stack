// Twin divergence math.
//
// Pure compute helper: given paired (real, twin) intent_outcome claims
// + per-side detector_signal keys, computes the per-dimension
// divergence_dimensions array + diff_summary string that get packed
// into a TwinDivergenceClaim by TwinOrchestrationService.
//
// Four canonical dimensions per the 5.3.1 schema:
//   1. output_shape  — per-pair hash compare of the output envelope
//   2. counterparty  — set diff of the actual_target / actual_skill_id /
//                      actual_tool_name / actual_contract / actual_method per side
//   3. cost          — sum of cost_actual.wallet_cents per side, ratio compared
//   4. detector_signal_set — set diff of detector_signal.detector_key per side
//
// Thresholds are hard-coded v1 (exported as constants for test
// assertion + future tuning). Macro spec calls them "configurable"
// but doesn't specify values; defaults below are reasonable starting
// points that produce non-trivial divergence_dimensions on real
// disagreement and stay quiet on noise.
//
// Pure / stateless / no I/O. Mirror of the resolveTwinPolicy pattern
// from 5.3.3 — exported as a standalone function in its own file
// rather than a class so the math is testable in isolation.

import type {
  IntentOutcomeClaim,
  TwinDivergenceDimension,
  TwinDivergenceEntry,
  TwinDivergenceSeverity,
} from '@stack/shared';

// ─── Thresholds (v1) ────────────────────────────────────────────────

/**
 * output_shape: classify by mismatch_ratio = mismatches / total_pairs.
 * 0% → no entry. Each boundary is inclusive of the upper bound.
 */
export const OUTPUT_SHAPE_THRESHOLDS = {
  low: 0.25,
  medium: 0.50,
  high: 0.80,
} as const;

/**
 * counterparty: classify by symmetric_diff_size (|real_only| + |twin_only|).
 * 0 → no entry.
 */
export const COUNTERPARTY_THRESHOLDS = {
  medium: 2,
  high: 5,
} as const;

/**
 * cost: ratio = max(realTotal, twinTotal) / max(min(realTotal, twinTotal), 1).
 * Ratio at or under `none` → no entry. ratio in (none, medium] → medium, etc.
 */
export const COST_RATIO_THRESHOLDS = {
  none: 1.2,
  medium: 2.0,
  high: 5.0,
} as const;

/**
 * detector_signal_set: classify by symmetric_diff_size of detector_keys.
 * 0 → no entry. v1 caps severity at 'high' — promoting to 'critical' on
 * safety-critical detector keys (e.g. prompt_injection_output) is a v2
 * carve-out once those keys settle.
 */
export const DETECTOR_SET_THRESHOLDS = {
  medium: 2,
} as const;

// ─── Public API ─────────────────────────────────────────────────────

export interface OutcomeEntry {
  claim_id: string;
  outcome: IntentOutcomeClaim;
}

export interface ComputeDivergenceArgs {
  realOutcomes: OutcomeEntry[];
  twinOutcomes: OutcomeEntry[];
  realDetectorKeys: string[];
  twinDetectorKeys: string[];
}

export interface ComputeDivergenceResult {
  divergenceDimensions: TwinDivergenceEntry[];
  diffSummary: string;
}

/**
 * Compute per-dimension divergence between the real chain and the
 * twin chain. Returns the entries the producer (TwinOrchestrationService)
 * packs into TwinDivergenceClaim.divergence_dimensions + a short
 * human-readable diff_summary.
 *
 * Dimensions with zero divergence are OMITTED from the returned array
 * (empty array = real and twin agreed on every measured dimension =
 * the desired outcome — the proof the twin schema docs reference).
 */
export function computeDivergence(args: ComputeDivergenceArgs): ComputeDivergenceResult {
  const entries: TwinDivergenceEntry[] = [];

  const outputShape = computeOutputShape(args.realOutcomes, args.twinOutcomes);
  if (outputShape) entries.push(outputShape);

  const counterparty = computeCounterparty(args.realOutcomes, args.twinOutcomes);
  if (counterparty) entries.push(counterparty);

  const cost = computeCost(args.realOutcomes, args.twinOutcomes);
  if (cost) entries.push(cost);

  const detectors = computeDetectorSet(args.realDetectorKeys, args.twinDetectorKeys);
  if (detectors) entries.push(detectors);

  const criticalCount = entries.filter((e) => e.severity === 'critical').length;
  const summaryParts = entries.map((e) => `${e.dimension}=${e.severity}`);
  let diffSummary: string;
  if (entries.length === 0) {
    diffSummary = 'No divergence observed.';
  } else {
    const joined = summaryParts.join(', ');
    diffSummary = criticalCount >= 2
      ? `MULTIPLE CRITICAL DIVERGENCES — ${joined}`
      : joined;
  }

  return { divergenceDimensions: entries, diffSummary };
}

// ─── Per-dimension compute ──────────────────────────────────────────

function computeOutputShape(
  real: OutcomeEntry[],
  twin: OutcomeEntry[],
): TwinDivergenceEntry | null {
  const totalPairs = Math.max(real.length, twin.length);
  if (totalPairs === 0) return null;

  let mismatches = 0;
  const mismatchDetails: Array<{ index: number; real_hash: string | null; twin_hash: string | null; note?: string }> = [];

  for (let i = 0; i < totalPairs; i++) {
    const r = real[i];
    const t = twin[i];

    if (!r || !t) {
      // Chain length mismatch — count missing entry as a mismatch.
      mismatches += 1;
      mismatchDetails.push({
        index: i,
        real_hash: r ? extractOutputHash(r.outcome) : null,
        twin_hash: t ? extractOutputHash(t.outcome) : null,
        note: 'chain length mismatch',
      });
      continue;
    }

    // Outcome_type mismatch is itself a mismatch (and the severity
    // classifier will catch the divergence ratio — but flag the note).
    if (r.outcome.outcome_type !== t.outcome.outcome_type) {
      mismatches += 1;
      mismatchDetails.push({
        index: i,
        real_hash: extractOutputHash(r.outcome),
        twin_hash: extractOutputHash(t.outcome),
        note: 'outcome_type mismatch',
      });
      continue;
    }

    const rHash = extractOutputHash(r.outcome);
    const tHash = extractOutputHash(t.outcome);
    // Both null → can't compare, treat as match (e.g. paired task_complete).
    if (rHash === null && tHash === null) continue;
    if (rHash !== tHash) {
      mismatches += 1;
      mismatchDetails.push({ index: i, real_hash: rHash, twin_hash: tHash });
    }
  }

  const mismatchRatio = mismatches / totalPairs;
  const severity = classifyOutputShape(mismatchRatio);
  if (severity === null) return null;

  return {
    dimension: 'output_shape' as TwinDivergenceDimension,
    severity,
    diff: {
      mismatch_ratio: mismatchRatio,
      total_pairs: totalPairs,
      mismatches: mismatchDetails,
    },
  };
}

function computeCounterparty(
  real: OutcomeEntry[],
  twin: OutcomeEntry[],
): TwinDivergenceEntry | null {
  const realSet = new Set<string>();
  const twinSet = new Set<string>();
  for (const r of real) {
    const cp = extractCounterparty(r.outcome);
    if (cp !== null) realSet.add(cp);
  }
  for (const t of twin) {
    const cp = extractCounterparty(t.outcome);
    if (cp !== null) twinSet.add(cp);
  }

  const realOnly = [...realSet].filter((x) => !twinSet.has(x)).sort();
  const twinOnly = [...twinSet].filter((x) => !realSet.has(x)).sort();
  const diffSize = realOnly.length + twinOnly.length;
  const severity = classifyCounterparty(diffSize);
  if (severity === null) return null;

  return {
    dimension: 'counterparty' as TwinDivergenceDimension,
    severity,
    diff: {
      real_only: realOnly,
      twin_only: twinOnly,
      diff_size: diffSize,
    },
  };
}

function computeCost(
  real: OutcomeEntry[],
  twin: OutcomeEntry[],
): TwinDivergenceEntry | null {
  const realTotal = real.reduce((s, e) => s + (e.outcome.cost_actual.wallet_cents ?? 0), 0);
  const twinTotal = twin.reduce((s, e) => s + (e.outcome.cost_actual.wallet_cents ?? 0), 0);

  // Both zero → no signal, no entry.
  if (realTotal === 0 && twinTotal === 0) return null;

  const max = Math.max(realTotal, twinTotal);
  const min = Math.max(Math.min(realTotal, twinTotal), 1);
  const ratio = max / min;
  const severity = classifyCost(ratio);
  if (severity === null) return null;

  return {
    dimension: 'cost' as TwinDivergenceDimension,
    severity,
    diff: {
      real_total_cents: realTotal,
      twin_total_cents: twinTotal,
      ratio,
    },
  };
}

function computeDetectorSet(
  realKeys: string[],
  twinKeys: string[],
): TwinDivergenceEntry | null {
  const realSet = new Set(realKeys);
  const twinSet = new Set(twinKeys);
  const realOnly = [...realSet].filter((k) => !twinSet.has(k)).sort();
  const twinOnly = [...twinSet].filter((k) => !realSet.has(k)).sort();
  const diffSize = realOnly.length + twinOnly.length;
  const severity = classifyDetectorSet(diffSize);
  if (severity === null) return null;

  return {
    dimension: 'detector_signal_set' as TwinDivergenceDimension,
    severity,
    diff: {
      real_only_keys: realOnly,
      twin_only_keys: twinOnly,
      diff_size: diffSize,
    },
  };
}

// ─── Helpers (exported for unit testing) ────────────────────────────

/**
 * Extract the per-outcome output hash for output_shape comparison.
 * Each outcome_type carries a different "output envelope" field:
 *   - http_call          → response_body_hash
 *   - skill_invocation   → output_envelope_hash
 *   - mcp_tool           → tool_result_envelope_hash
 *   - a2a_dispatch       → task_result_envelope_hash
 *   - onchain_tx         → tx_hash (lowercase compare; ignore 0x case)
 *   - task_complete      → null (no external output)
 */
export function extractOutputHash(outcome: IntentOutcomeClaim): string | null {
  switch (outcome.outcome_type) {
    case 'http_call': return outcome.response_body_hash;
    case 'skill_invocation': return outcome.output_envelope_hash;
    case 'mcp_tool': return outcome.tool_result_envelope_hash;
    case 'a2a_dispatch': return outcome.task_result_envelope_hash;
    case 'onchain_tx': return outcome.tx_hash;
    case 'task_complete': return null;
  }
}

/**
 * Extract the per-outcome counterparty identifier for the counterparty
 * dimension. Each outcome_type's counterparty is a different field:
 *   - http_call          → actual_target (hostname)
 *   - skill_invocation   → actual_skill_id
 *   - mcp_tool           → actual_tool_name
 *   - a2a_dispatch       → actual_target_agent
 *   - onchain_tx         → actual_contract
 *   - task_complete      → null
 */
export function extractCounterparty(outcome: IntentOutcomeClaim): string | null {
  switch (outcome.outcome_type) {
    case 'http_call': return outcome.actual_target;
    case 'skill_invocation': return outcome.actual_skill_id;
    case 'mcp_tool': return outcome.actual_tool_name;
    case 'a2a_dispatch': return outcome.actual_target_agent;
    case 'onchain_tx': return outcome.actual_contract;
    case 'task_complete': return null;
  }
}

export function classifyOutputShape(mismatchRatio: number): TwinDivergenceSeverity | null {
  if (mismatchRatio <= 0) return null;
  if (mismatchRatio <= OUTPUT_SHAPE_THRESHOLDS.low) return 'low';
  if (mismatchRatio <= OUTPUT_SHAPE_THRESHOLDS.medium) return 'medium';
  if (mismatchRatio <= OUTPUT_SHAPE_THRESHOLDS.high) return 'high';
  return 'critical';
}

export function classifyCounterparty(diffSize: number): TwinDivergenceSeverity | null {
  if (diffSize <= 0) return null;
  if (diffSize <= COUNTERPARTY_THRESHOLDS.medium) return 'medium';
  if (diffSize <= COUNTERPARTY_THRESHOLDS.high) return 'high';
  return 'critical';
}

export function classifyCost(ratio: number): TwinDivergenceSeverity | null {
  if (ratio <= COST_RATIO_THRESHOLDS.none) return null;
  if (ratio <= COST_RATIO_THRESHOLDS.medium) return 'medium';
  if (ratio <= COST_RATIO_THRESHOLDS.high) return 'high';
  return 'critical';
}

export function classifyDetectorSet(diffSize: number): TwinDivergenceSeverity | null {
  if (diffSize <= 0) return null;
  if (diffSize <= DETECTOR_SET_THRESHOLDS.medium) return 'medium';
  return 'high';
}
