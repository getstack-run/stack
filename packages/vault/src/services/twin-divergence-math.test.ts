import { describe, it, expect } from 'vitest';
import type { IntentOutcomeClaim } from '@stack/shared';
import {
  computeDivergence,
  extractOutputHash,
  extractCounterparty,
  classifyOutputShape,
  classifyCounterparty,
  classifyCost,
  classifyDetectorSet,
  OUTPUT_SHAPE_THRESHOLDS,
  COUNTERPARTY_THRESHOLDS,
  COST_RATIO_THRESHOLDS,
  DETECTOR_SET_THRESHOLDS,
} from './twin-divergence-math.js';

/**
 * twin-divergence-math invariants.
 *
 * Goal: lock the per-dimension severity classification + the diff
 * payload shape so downstream consumers (operator dashboard, MCP read
 * tool, replay) can rely on the entry shape without re-running the
 * math. Tests cover:
 *
 *   M1-M4   classifier boundary tests per dimension
 *   M5-M7   output_shape: empty / all match / partial
 *   M8-M10  counterparty: identical / small / large diff
 *   M11-M13 cost: zero / within band / above each threshold
 *   M14-M15 detector_signal_set: identical / small / large
 *   M16     outcome_type mismatch in output_shape pairs
 *   M17     extract helpers handle all 6 outcome_types
 *   M18     multiple critical dimensions surface the MULTIPLE prefix
 *   M19     diff_summary stays compact when zero divergence
 */

// ─── Fixtures ───────────────────────────────────────────────────────

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);
const HASH_D = 'd'.repeat(64);

function httpCall(opts: { hash: string | null; target: string | null; cents?: number }): IntentOutcomeClaim {
  return {
    type: 'intent_outcome',
    outcome_type: 'http_call',
    intent_claim_ref: 'pc_intent_x',
    status: 'succeeded',
    duration_ms: 100,
    cost_actual: { wallet_cents: opts.cents ?? 0, tokens: null, gas_gwei: null },
    recorded_at: 0,
    actual_target: opts.target,
    actual_method_path: 'GET /x',
    actual_parameters_hash: HASH_A,
    status_code: 200,
    response_body_hash: opts.hash,
    latency_ms: 50,
    redactions_count: 0,
    detector_fires_count: 0,
  } as IntentOutcomeClaim;
}

function skillInv(opts: { hash: string | null; skill: string | null; cents?: number }): IntentOutcomeClaim {
  return {
    type: 'intent_outcome',
    outcome_type: 'skill_invocation',
    intent_claim_ref: 'pc_intent_x',
    status: 'succeeded',
    duration_ms: 100,
    cost_actual: { wallet_cents: opts.cents ?? 0, tokens: null, gas_gwei: null },
    recorded_at: 0,
    actual_skill_id: opts.skill,
    actual_input_hash: HASH_A,
    output_envelope_hash: opts.hash,
    exit_code: 0,
  } as IntentOutcomeClaim;
}

function entry(claimId: string, outcome: IntentOutcomeClaim) {
  return { claim_id: claimId, outcome };
}

// ─── Classifier boundary tests ──────────────────────────────────────

describe('classifyOutputShape', () => {
  it('M1: 0% → null', () => {
    expect(classifyOutputShape(0)).toBeNull();
  });
  it('M1b: just above 0% → low', () => {
    expect(classifyOutputShape(0.01)).toBe('low');
  });
  it('M1c: at low threshold (0.25) → low', () => {
    expect(classifyOutputShape(OUTPUT_SHAPE_THRESHOLDS.low)).toBe('low');
  });
  it('M1d: just above low → medium', () => {
    expect(classifyOutputShape(OUTPUT_SHAPE_THRESHOLDS.low + 0.001)).toBe('medium');
  });
  it('M1e: at medium (0.50) → medium; just above → high', () => {
    expect(classifyOutputShape(OUTPUT_SHAPE_THRESHOLDS.medium)).toBe('medium');
    expect(classifyOutputShape(OUTPUT_SHAPE_THRESHOLDS.medium + 0.001)).toBe('high');
  });
  it('M1f: at high (0.80) → high; just above → critical', () => {
    expect(classifyOutputShape(OUTPUT_SHAPE_THRESHOLDS.high)).toBe('high');
    expect(classifyOutputShape(OUTPUT_SHAPE_THRESHOLDS.high + 0.001)).toBe('critical');
  });
  it('M1g: 1.0 → critical', () => {
    expect(classifyOutputShape(1)).toBe('critical');
  });
});

describe('classifyCounterparty', () => {
  it('M2: 0 → null; 1 → medium; 2 → medium; 3 → high; 5 → high; 6 → critical', () => {
    expect(classifyCounterparty(0)).toBeNull();
    expect(classifyCounterparty(1)).toBe('medium');
    expect(classifyCounterparty(2)).toBe('medium');
    expect(classifyCounterparty(3)).toBe('high');
    expect(classifyCounterparty(COUNTERPARTY_THRESHOLDS.high)).toBe('high');
    expect(classifyCounterparty(COUNTERPARTY_THRESHOLDS.high + 1)).toBe('critical');
  });
});

describe('classifyCost', () => {
  it('M3: under none-threshold → null', () => {
    expect(classifyCost(1.0)).toBeNull();
    expect(classifyCost(COST_RATIO_THRESHOLDS.none)).toBeNull();
  });
  it('M3b: ratio just above none → medium', () => {
    expect(classifyCost(COST_RATIO_THRESHOLDS.none + 0.001)).toBe('medium');
  });
  it('M3c: at medium → medium; just above → high', () => {
    expect(classifyCost(COST_RATIO_THRESHOLDS.medium)).toBe('medium');
    expect(classifyCost(COST_RATIO_THRESHOLDS.medium + 0.001)).toBe('high');
  });
  it('M3d: at high → high; just above → critical', () => {
    expect(classifyCost(COST_RATIO_THRESHOLDS.high)).toBe('high');
    expect(classifyCost(COST_RATIO_THRESHOLDS.high + 0.001)).toBe('critical');
  });
});

describe('classifyDetectorSet', () => {
  it('M4: 0 → null; 1 → medium; 2 → medium; 3 → high', () => {
    expect(classifyDetectorSet(0)).toBeNull();
    expect(classifyDetectorSet(1)).toBe('medium');
    expect(classifyDetectorSet(DETECTOR_SET_THRESHOLDS.medium)).toBe('medium');
    expect(classifyDetectorSet(DETECTOR_SET_THRESHOLDS.medium + 1)).toBe('high');
    expect(classifyDetectorSet(100)).toBe('high');
  });
});

// ─── output_shape dimension ────────────────────────────────────────

describe('computeDivergence output_shape', () => {
  it('M5: empty outcome arrays + empty detector arrays → no divergence', () => {
    const res = computeDivergence({
      realOutcomes: [], twinOutcomes: [], realDetectorKeys: [], twinDetectorKeys: [],
    });
    expect(res.divergenceDimensions).toEqual([]);
    expect(res.diffSummary).toBe('No divergence observed.');
  });

  it('M6: all hashes match → no output_shape entry', () => {
    const res = computeDivergence({
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com' }))],
      twinOutcomes: [entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com' }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const shape = res.divergenceDimensions.find((d) => d.dimension === 'output_shape');
    expect(shape).toBeUndefined();
  });

  it('M7: 1 of 2 pairs diverge → medium output_shape entry', () => {
    const res = computeDivergence({
      realOutcomes: [
        entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com' })),
        entry('pc_r2', httpCall({ hash: HASH_B, target: 'api.foo.com' })),
      ],
      twinOutcomes: [
        entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com' })),
        entry('pc_t2', httpCall({ hash: HASH_C, target: 'api.foo.com' })),
      ],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const shape = res.divergenceDimensions.find((d) => d.dimension === 'output_shape');
    expect(shape).toBeDefined();
    expect(shape!.severity).toBe('medium');
    expect((shape!.diff as { mismatch_ratio: number }).mismatch_ratio).toBe(0.5);
    expect((shape!.diff as { total_pairs: number }).total_pairs).toBe(2);
  });

  it('M7b: chain length mismatch counts as mismatch', () => {
    const res = computeDivergence({
      realOutcomes: [
        entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com' })),
        entry('pc_r2', httpCall({ hash: HASH_B, target: 'api.foo.com' })),
        entry('pc_r3', httpCall({ hash: HASH_C, target: 'api.foo.com' })),
      ],
      twinOutcomes: [
        entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com' })),
      ],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const shape = res.divergenceDimensions.find((d) => d.dimension === 'output_shape');
    expect(shape).toBeDefined();
    // 2 of 3 mismatched (the two trailing real outcomes have no twin pair).
    expect((shape!.diff as { mismatch_ratio: number }).mismatch_ratio).toBeCloseTo(2 / 3);
    expect(shape!.severity).toBe('high');
  });
});

// ─── counterparty dimension ────────────────────────────────────────

describe('computeDivergence counterparty', () => {
  it('M8: identical counterparty sets → no entry', () => {
    const res = computeDivergence({
      realOutcomes: [
        entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com' })),
        entry('pc_r2', httpCall({ hash: HASH_B, target: 'api.bar.com' })),
      ],
      twinOutcomes: [
        entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com' })),
        entry('pc_t2', httpCall({ hash: HASH_B, target: 'api.bar.com' })),
      ],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    expect(res.divergenceDimensions.find((d) => d.dimension === 'counterparty')).toBeUndefined();
  });

  it('M9: small diff (real had api.foo, twin had api.bar) → medium', () => {
    const res = computeDivergence({
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com' }))],
      twinOutcomes: [entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.bar.com' }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const cp = res.divergenceDimensions.find((d) => d.dimension === 'counterparty');
    expect(cp).toBeDefined();
    expect(cp!.severity).toBe('medium');
    expect((cp!.diff as { real_only: string[] }).real_only).toEqual(['api.foo.com']);
    expect((cp!.diff as { twin_only: string[] }).twin_only).toEqual(['api.bar.com']);
  });

  it('M10: 6 different hosts → critical', () => {
    const res = computeDivergence({
      realOutcomes: Array.from({ length: 3 }, (_, i) =>
        entry(`pc_r${i}`, httpCall({ hash: HASH_A, target: `r${i}.com` })),
      ),
      twinOutcomes: Array.from({ length: 3 }, (_, i) =>
        entry(`pc_t${i}`, httpCall({ hash: HASH_A, target: `t${i}.com` })),
      ),
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const cp = res.divergenceDimensions.find((d) => d.dimension === 'counterparty');
    expect(cp).toBeDefined();
    expect(cp!.severity).toBe('critical');
    expect((cp!.diff as { diff_size: number }).diff_size).toBe(6);
  });
});

// ─── cost dimension ─────────────────────────────────────────────────

describe('computeDivergence cost', () => {
  it('M11: both zero totals → no entry', () => {
    const res = computeDivergence({
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 0 }))],
      twinOutcomes: [entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 0 }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    expect(res.divergenceDimensions.find((d) => d.dimension === 'cost')).toBeUndefined();
  });

  it('M12: ratio within band (real=100, twin=110, ratio=1.1) → no entry', () => {
    const res = computeDivergence({
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 100 }))],
      twinOutcomes: [entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 110 }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    expect(res.divergenceDimensions.find((d) => d.dimension === 'cost')).toBeUndefined();
  });

  it('M13: ratio 1.5 → medium', () => {
    const res = computeDivergence({
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 100 }))],
      twinOutcomes: [entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 150 }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const cost = res.divergenceDimensions.find((d) => d.dimension === 'cost');
    expect(cost).toBeDefined();
    expect(cost!.severity).toBe('medium');
    expect((cost!.diff as { ratio: number }).ratio).toBeCloseTo(1.5);
  });

  it('M13b: ratio 10 → critical', () => {
    const res = computeDivergence({
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 10 }))],
      twinOutcomes: [entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 100 }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const cost = res.divergenceDimensions.find((d) => d.dimension === 'cost');
    expect(cost).toBeDefined();
    expect(cost!.severity).toBe('critical');
  });

  it('M13c: NULL cost contributes 0 — one-side zero → critical (ratio = max / 1)', () => {
    const res = computeDivergence({
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 0 }))],
      twinOutcomes: [entry('pc_t1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 100 }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const cost = res.divergenceDimensions.find((d) => d.dimension === 'cost');
    expect(cost).toBeDefined();
    expect((cost!.diff as { real_total_cents: number; twin_total_cents: number }).real_total_cents).toBe(0);
    expect((cost!.diff as { real_total_cents: number; twin_total_cents: number }).twin_total_cents).toBe(100);
    expect(cost!.severity).toBe('critical');
  });
});

// ─── detector_signal_set dimension ──────────────────────────────────

describe('computeDivergence detector_signal_set', () => {
  it('M14: identical detector keys → no entry', () => {
    const res = computeDivergence({
      realOutcomes: [], twinOutcomes: [],
      realDetectorKeys: ['prompt_injection_output', 'high_value_action'],
      twinDetectorKeys: ['high_value_action', 'prompt_injection_output'],
    });
    expect(res.divergenceDimensions.find((d) => d.dimension === 'detector_signal_set')).toBeUndefined();
  });

  it('M15: small diff (1 detector unique each side) → medium', () => {
    const res = computeDivergence({
      realOutcomes: [], twinOutcomes: [],
      realDetectorKeys: ['prompt_injection_output'],
      twinDetectorKeys: ['high_value_action'],
    });
    const det = res.divergenceDimensions.find((d) => d.dimension === 'detector_signal_set');
    expect(det).toBeDefined();
    expect(det!.severity).toBe('medium');
    expect((det!.diff as { real_only_keys: string[] }).real_only_keys).toEqual(['prompt_injection_output']);
    expect((det!.diff as { twin_only_keys: string[] }).twin_only_keys).toEqual(['high_value_action']);
  });

  it('M15b: 3-key diff → high', () => {
    const res = computeDivergence({
      realOutcomes: [], twinOutcomes: [],
      realDetectorKeys: ['a', 'b'],
      twinDetectorKeys: ['c', 'd'],
    });
    const det = res.divergenceDimensions.find((d) => d.dimension === 'detector_signal_set');
    expect(det!.severity).toBe('high');
  });
});

// ─── outcome_type mismatch in pairs ─────────────────────────────────

describe('computeDivergence outcome_type mismatch', () => {
  it('M16: real http_call paired with twin skill_invocation → counted as mismatch + noted', () => {
    const res = computeDivergence({
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com' }))],
      twinOutcomes: [entry('pc_t1', skillInv({ hash: HASH_A, skill: 'sk_x' }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    const shape = res.divergenceDimensions.find((d) => d.dimension === 'output_shape');
    expect(shape).toBeDefined();
    expect(shape!.severity).toBe('critical'); // 1/1 mismatch
    const mismatches = (shape!.diff as { mismatches: Array<{ note?: string }> }).mismatches;
    expect(mismatches[0]?.note).toBe('outcome_type mismatch');
  });
});

// ─── extract helpers per outcome_type ───────────────────────────────

describe('extract helpers', () => {
  it('M17a: extractOutputHash handles all 6 outcome_types', () => {
    expect(extractOutputHash({ outcome_type: 'http_call', response_body_hash: HASH_A } as IntentOutcomeClaim)).toBe(HASH_A);
    expect(extractOutputHash({ outcome_type: 'skill_invocation', output_envelope_hash: HASH_B } as IntentOutcomeClaim)).toBe(HASH_B);
    expect(extractOutputHash({ outcome_type: 'mcp_tool', tool_result_envelope_hash: HASH_C } as IntentOutcomeClaim)).toBe(HASH_C);
    expect(extractOutputHash({ outcome_type: 'a2a_dispatch', task_result_envelope_hash: HASH_D } as IntentOutcomeClaim)).toBe(HASH_D);
    expect(extractOutputHash({ outcome_type: 'onchain_tx', tx_hash: '0x' + HASH_A } as unknown as IntentOutcomeClaim)).toBe('0x' + HASH_A);
    expect(extractOutputHash({ outcome_type: 'task_complete' } as IntentOutcomeClaim)).toBeNull();
  });

  it('M17b: extractCounterparty handles all 6 outcome_types', () => {
    expect(extractCounterparty({ outcome_type: 'http_call', actual_target: 'api.foo.com' } as IntentOutcomeClaim)).toBe('api.foo.com');
    expect(extractCounterparty({ outcome_type: 'skill_invocation', actual_skill_id: 'sk_x' } as IntentOutcomeClaim)).toBe('sk_x');
    expect(extractCounterparty({ outcome_type: 'mcp_tool', actual_tool_name: 'tool_x' } as IntentOutcomeClaim)).toBe('tool_x');
    expect(extractCounterparty({ outcome_type: 'a2a_dispatch', actual_target_agent: 'agt_x' } as IntentOutcomeClaim)).toBe('agt_x');
    expect(extractCounterparty({ outcome_type: 'onchain_tx', actual_contract: '0x' + 'a'.repeat(40) } as unknown as IntentOutcomeClaim)).toBe('0x' + 'a'.repeat(40));
    expect(extractCounterparty({ outcome_type: 'task_complete' } as IntentOutcomeClaim)).toBeNull();
  });
});

// ─── Multiple critical dimensions ──────────────────────────────────

describe('computeDivergence multi-critical summary', () => {
  it('M18: 2 critical dimensions → diff_summary prefixed with MULTIPLE CRITICAL', () => {
    const res = computeDivergence({
      // 100% output_shape mismatch → critical
      realOutcomes: [entry('pc_r1', httpCall({ hash: HASH_A, target: 'api.foo.com', cents: 1 }))],
      // huge cost ratio → critical (1 vs 1000 → ratio 1000)
      twinOutcomes: [entry('pc_t1', httpCall({ hash: HASH_B, target: 'api.foo.com', cents: 1000 }))],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    expect(res.diffSummary).toMatch(/^MULTIPLE CRITICAL DIVERGENCES/);
    const criticalEntries = res.divergenceDimensions.filter((e) => e.severity === 'critical');
    expect(criticalEntries.length).toBeGreaterThanOrEqual(2);
  });

  it('M19: zero divergence → "No divergence observed."', () => {
    const res = computeDivergence({
      realOutcomes: [], twinOutcomes: [],
      realDetectorKeys: [], twinDetectorKeys: [],
    });
    expect(res.diffSummary).toBe('No divergence observed.');
  });
});
