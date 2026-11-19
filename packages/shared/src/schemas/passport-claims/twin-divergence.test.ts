import { describe, it, expect } from 'vitest';
import {
  TwinDivergenceClaim,
  TwinDivergenceEntry,
  TwinDivergenceSeverity,
  TwinDivergenceDimension,
} from './twin-divergence.js';

/**
 * TwinDivergenceClaim schema invariants.
 *
 *   T1: zero-divergence valid claim parses (empty arrays)
 *   T2: multi-dimension claim parses (3 entries, mixed severities)
 *   T3: mission_ref REQUIRED (non-nullable) — rejects when absent
 *   T4: mission_ref rejects non-ms_* shape
 *   T5: real_intent_outcomes rejects non-pc_* claim_id
 *   T6: divergence_dimensions rejects unknown dimension
 *   T7: divergence_dimensions rejects unknown severity (e.g. SecurityEventSeverity values)
 *   T8: divergence_dimensions[].diff accepts arbitrary jsonb shape
 *   T9: diff_summary rejects > 2048 chars
 *   T10: evaluated_at_ms rejects negative
 */

const VALID_BASE = {
  type: 'twin_divergence' as const,
  passport_jti: 'pas_test',
  mission_ref: 'ms_smoke',
  real_intent_outcomes: ['pc_real_a', 'pc_real_b'],
  twin_intent_outcomes: ['pc_twin_a', 'pc_twin_b'],
  divergence_dimensions: [],
  diff_summary: 'No divergence observed across 2 real / 2 twin outcomes.',
  evaluated_at_ms: 1779500000000,
};

describe('TwinDivergenceClaim — parse positives', () => {
  it('T1 zero-divergence (empty arrays + empty divergence_dimensions) parses', () => {
    const parsed = TwinDivergenceClaim.parse({
      ...VALID_BASE,
      real_intent_outcomes: [],
      twin_intent_outcomes: [],
      divergence_dimensions: [],
    });
    expect(parsed.type).toBe('twin_divergence');
    expect(parsed.divergence_dimensions).toEqual([]);
  });

  it('T2 multi-dimension claim with mixed severities parses', () => {
    const parsed = TwinDivergenceClaim.parse({
      ...VALID_BASE,
      divergence_dimensions: [
        {
          dimension: 'output_shape',
          severity: 'low',
          diff: { real: { text: 'hi' }, twin: { text: 'hello' } },
        },
        {
          dimension: 'counterparty',
          severity: 'high',
          diff: { real_endpoint: 'api.x.com', twin_endpoint: 'api.y.com' },
        },
        {
          dimension: 'cost',
          severity: 'medium',
          diff: { real_cents: 100, twin_cents: 130, delta_pct: 30 },
        },
      ],
      diff_summary: '3 divergences: low/output_shape, high/counterparty, medium/cost',
    });
    expect(parsed.divergence_dimensions).toHaveLength(3);
    expect(parsed.divergence_dimensions[0]!.dimension).toBe('output_shape');
    expect(parsed.divergence_dimensions[1]!.severity).toBe('high');
  });

  it('T2b detector_signal_set dimension + critical severity parses', () => {
    const parsed = TwinDivergenceClaim.parse({
      ...VALID_BASE,
      divergence_dimensions: [
        {
          dimension: 'detector_signal_set',
          severity: 'critical',
          diff: { real_signals: ['prompt_injection_output'], twin_signals: [] },
        },
      ],
    });
    expect(parsed.divergence_dimensions[0]!.severity).toBe('critical');
  });
});

describe('TwinDivergenceClaim — parse negatives', () => {
  it('T3 rejects missing mission_ref (required non-nullable)', () => {
    const { mission_ref: _omit, ...withoutMission } = VALID_BASE;
    expect(() => TwinDivergenceClaim.parse(withoutMission)).toThrow();
  });

  it('T3b rejects null mission_ref (non-nullable)', () => {
    expect(() =>
      TwinDivergenceClaim.parse({ ...VALID_BASE, mission_ref: null }),
    ).toThrow();
  });

  it('T4 rejects mission_ref not matching ms_* shape', () => {
    expect(() =>
      TwinDivergenceClaim.parse({ ...VALID_BASE, mission_ref: 'pas_wrong' }),
    ).toThrow(/mission_ref must be a mission id/);
  });

  it('T5 rejects real_intent_outcomes[i] not matching pc_* shape', () => {
    expect(() =>
      TwinDivergenceClaim.parse({
        ...VALID_BASE,
        real_intent_outcomes: ['pc_ok', 'ms_wrong'],
      }),
    ).toThrow(/passport-claim id/);
  });

  it('T5b rejects twin_intent_outcomes[i] not matching pc_* shape', () => {
    expect(() =>
      TwinDivergenceClaim.parse({
        ...VALID_BASE,
        twin_intent_outcomes: ['not_a_pc'],
      }),
    ).toThrow();
  });

  it('T6 rejects unknown divergence dimension', () => {
    expect(() =>
      TwinDivergenceClaim.parse({
        ...VALID_BASE,
        divergence_dimensions: [
          { dimension: 'latency', severity: 'low', diff: {} },
        ],
      }),
    ).toThrow();
  });

  it('T7 rejects severity outside TwinDivergenceSeverity (e.g. SecurityEventSeverity values)', () => {
    expect(() =>
      TwinDivergenceClaim.parse({
        ...VALID_BASE,
        divergence_dimensions: [
          // 'info' / 'warning' belong to SecurityEventSeverity, NOT this enum
          { dimension: 'cost', severity: 'info', diff: {} },
        ],
      }),
    ).toThrow();
  });

  it('T9 rejects diff_summary > 2048 chars', () => {
    expect(() =>
      TwinDivergenceClaim.parse({
        ...VALID_BASE,
        diff_summary: 'x'.repeat(2049),
      }),
    ).toThrow();
  });

  it('T10 rejects negative evaluated_at_ms', () => {
    expect(() =>
      TwinDivergenceClaim.parse({ ...VALID_BASE, evaluated_at_ms: -1 }),
    ).toThrow();
  });

  it('T10b rejects non-integer evaluated_at_ms', () => {
    expect(() =>
      TwinDivergenceClaim.parse({ ...VALID_BASE, evaluated_at_ms: 1.5 }),
    ).toThrow();
  });
});

describe('TwinDivergenceClaim — free-form diff jsonb', () => {
  it('T8 accepts arbitrary diff shape (string-keyed record of unknown)', () => {
    const shapes: Array<Record<string, unknown>> = [
      { simple: 'value' },
      { nested: { a: 1, b: [2, 3, 4] } },
      { mixed: null, arr: [{ x: 1 }, { y: 2 }] },
      {}, // empty diff is allowed
    ];
    for (const diff of shapes) {
      const parsed = TwinDivergenceClaim.parse({
        ...VALID_BASE,
        divergence_dimensions: [
          { dimension: 'output_shape', severity: 'medium', diff },
        ],
      });
      expect(parsed.divergence_dimensions[0]!.diff).toEqual(diff);
    }
  });
});

describe('TwinDivergenceClaim — default-fill behaviour', () => {
  it('arrays default to empty when omitted', () => {
    const parsed = TwinDivergenceClaim.parse({
      type: 'twin_divergence',
      passport_jti: 'pas_x',
      mission_ref: 'ms_x',
      diff_summary: 'minimal',
      evaluated_at_ms: 0,
    });
    expect(parsed.real_intent_outcomes).toEqual([]);
    expect(parsed.twin_intent_outcomes).toEqual([]);
    expect(parsed.divergence_dimensions).toEqual([]);
  });
});

describe('TwinDivergenceClaim — enum catalogs', () => {
  it('TwinDivergenceSeverity is locked to 4 levels', () => {
    expect(TwinDivergenceSeverity.options).toEqual(['low', 'medium', 'high', 'critical']);
  });

  it('TwinDivergenceDimension is locked to 4 axes', () => {
    expect(TwinDivergenceDimension.options).toEqual([
      'output_shape',
      'counterparty',
      'cost',
      'detector_signal_set',
    ]);
  });

  it('TwinDivergenceEntry standalone parse', () => {
    const parsed = TwinDivergenceEntry.parse({
      dimension: 'output_shape',
      severity: 'low',
      diff: {},
    });
    expect(parsed.dimension).toBe('output_shape');
  });
});
