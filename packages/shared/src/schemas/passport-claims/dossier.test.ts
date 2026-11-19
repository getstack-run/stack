import { describe, it, expect } from 'vitest';
import {
  DossierClaim,
  DossierDecisionEntry,
  DossierAlertEntry,
  IncidentClassification,
} from './dossier.js';

/**
 * DossierClaim schema invariants.
 *
 *   D1: minimal-valid claim parses (empty arrays + empty lessons_learned)
 *   D2: full-shape claim parses (multi-entry decision_tree + alerts_walkthrough)
 *   D3: mission_ref REQUIRED (non-nullable) — rejects when absent
 *   D4: mission_ref rejects non-ms_* shape
 *   D5: authored_by_member_id rejects non-mem_* shape
 *   D6: authored_at_ms rejects negative
 *   D7: narrative rejects > 50,000 chars
 *   D8: lessons_learned rejects > 50,000 chars
 *   D9: decision_tree[].checkpoint_id rejects non-chk_* shape
 *   D10: decision_tree[].decision rejects empty string
 *   D11: decision_tree[].rationale rejects > 4096 chars
 *   D12: alerts_walkthrough[].detector_signal_claim_id rejects non-pc_* shape
 *   D13: alerts_walkthrough[].severity rejects values outside the 4-level enum
 *   D14: alerts_walkthrough[].narrative rejects > 8192 chars
 *   D15: incident_classification rejects unknown values
 *   D16: prior_dossier_ref rejects non-pc_* shape (when non-null)
 *   D17: prior_dossier_ref accepts null (cold-start)
 *   D18: arrays default to empty when omitted
 *   D19: IncidentClassification enum locked to 4 values
 */

const VALID_BASE = {
  type: 'dossier' as const,
  mission_ref: 'ms_smoke',
  authored_by_member_id: 'mem_alice',
  authored_at_ms: 1779500000000,
  narrative: 'Mission ran clean. No surprises.',
  decision_tree: [],
  alerts_walkthrough: [],
  lessons_learned: '',
  incident_classification: 'false_positive' as const,
  prior_dossier_ref: null,
};

describe('DossierClaim — parse positives', () => {
  it('D1 minimal-valid claim parses', () => {
    const parsed = DossierClaim.parse(VALID_BASE);
    expect(parsed.type).toBe('dossier');
    expect(parsed.decision_tree).toEqual([]);
    expect(parsed.alerts_walkthrough).toEqual([]);
    expect(parsed.prior_dossier_ref).toBeNull();
  });

  it('D2 full-shape claim with multi-entry decision_tree + alerts_walkthrough parses', () => {
    const parsed = DossierClaim.parse({
      ...VALID_BASE,
      narrative: '## Incident summary\n\nAgent attempted unscoped call at T+5m. Operator revoked passport.',
      decision_tree: [
        {
          checkpoint_id: 'chk_one',
          decision: 'auto-approved',
          rationale: 'Within scope and within wallet cap.',
        },
        {
          checkpoint_id: 'chk_two',
          decision: 'rejected and revoked',
          rationale: 'Out-of-scope service request; treated as adversarial.',
        },
      ],
      alerts_walkthrough: [
        {
          detector_signal_claim_id: 'pc_det_a',
          severity: 'critical',
          narrative: 'Prompt-injection signature in tool output. Confirmed true positive.',
        },
        {
          detector_signal_claim_id: 'pc_det_b',
          severity: 'low',
          narrative: 'Behavioral drift z-score 2.1 against baseline. False positive after review.',
        },
      ],
      lessons_learned: 'Tighten scope on services that emit JSON to the agent. Add a heuristic for the specific signature.',
      incident_classification: 'true_positive_escalated',
      prior_dossier_ref: 'pc_dossier_v1',
    });
    expect(parsed.decision_tree).toHaveLength(2);
    expect(parsed.alerts_walkthrough).toHaveLength(2);
    expect(parsed.alerts_walkthrough[0]!.severity).toBe('critical');
    expect(parsed.prior_dossier_ref).toBe('pc_dossier_v1');
  });
});

describe('DossierClaim — parse negatives', () => {
  it('D3 rejects missing mission_ref (required non-nullable)', () => {
    const { mission_ref: _omit, ...withoutMission } = VALID_BASE;
    expect(() => DossierClaim.parse(withoutMission)).toThrow();
  });

  it('D4 rejects mission_ref not matching ms_* shape', () => {
    expect(() =>
      DossierClaim.parse({ ...VALID_BASE, mission_ref: 'pas_wrong' }),
    ).toThrow(/mission_ref must be a mission id/);
  });

  it('D5 rejects authored_by_member_id not matching mem_* shape', () => {
    expect(() =>
      DossierClaim.parse({ ...VALID_BASE, authored_by_member_id: 'op_wrong' }),
    ).toThrow(/authored_by_member_id/);
  });

  it('D6 rejects negative authored_at_ms', () => {
    expect(() =>
      DossierClaim.parse({ ...VALID_BASE, authored_at_ms: -1 }),
    ).toThrow();
  });

  it('D6b rejects non-integer authored_at_ms', () => {
    expect(() =>
      DossierClaim.parse({ ...VALID_BASE, authored_at_ms: 1.5 }),
    ).toThrow();
  });

  it('D7 rejects narrative > 50,000 chars', () => {
    expect(() =>
      DossierClaim.parse({ ...VALID_BASE, narrative: 'x'.repeat(50_001) }),
    ).toThrow(/narrative must be <= 50,000/);
  });

  it('D8 rejects lessons_learned > 50,000 chars', () => {
    expect(() =>
      DossierClaim.parse({ ...VALID_BASE, lessons_learned: 'y'.repeat(50_001) }),
    ).toThrow(/lessons_learned must be <= 50,000/);
  });

  it('D9 rejects decision_tree[].checkpoint_id not matching chk_* shape', () => {
    expect(() =>
      DossierClaim.parse({
        ...VALID_BASE,
        decision_tree: [{ checkpoint_id: 'pc_wrong', decision: 'ok', rationale: '' }],
      }),
    ).toThrow(/checkpoint_id must be/);
  });

  it('D10 rejects decision_tree[].decision empty string', () => {
    expect(() =>
      DossierClaim.parse({
        ...VALID_BASE,
        decision_tree: [{ checkpoint_id: 'chk_ok', decision: '', rationale: 'no decision' }],
      }),
    ).toThrow();
  });

  it('D11 rejects decision_tree[].rationale > 4096 chars', () => {
    expect(() =>
      DossierClaim.parse({
        ...VALID_BASE,
        decision_tree: [{ checkpoint_id: 'chk_ok', decision: 'ok', rationale: 'z'.repeat(4097) }],
      }),
    ).toThrow();
  });

  it('D12 rejects alerts_walkthrough[].detector_signal_claim_id not matching pc_* shape', () => {
    expect(() =>
      DossierClaim.parse({
        ...VALID_BASE,
        alerts_walkthrough: [
          { detector_signal_claim_id: 'sevt_wrong', severity: 'low', narrative: '' },
        ],
      }),
    ).toThrow(/detector_signal_claim_id/);
  });

  it('D13 rejects alerts_walkthrough[].severity outside the 4-level enum', () => {
    expect(() =>
      DossierClaim.parse({
        ...VALID_BASE,
        alerts_walkthrough: [
          { detector_signal_claim_id: 'pc_x', severity: 'info', narrative: '' },
        ],
      }),
    ).toThrow();
  });

  it('D14 rejects alerts_walkthrough[].narrative > 8192 chars', () => {
    expect(() =>
      DossierClaim.parse({
        ...VALID_BASE,
        alerts_walkthrough: [
          { detector_signal_claim_id: 'pc_x', severity: 'low', narrative: 'q'.repeat(8193) },
        ],
      }),
    ).toThrow();
  });

  it('D15 rejects unknown incident_classification', () => {
    expect(() =>
      DossierClaim.parse({ ...VALID_BASE, incident_classification: 'undetermined' }),
    ).toThrow();
  });

  it('D16 rejects prior_dossier_ref not matching pc_* shape', () => {
    expect(() =>
      DossierClaim.parse({ ...VALID_BASE, prior_dossier_ref: 'ms_wrong' }),
    ).toThrow(/prior_dossier_ref/);
  });
});

describe('DossierClaim — chain pointer + defaults', () => {
  it('D17 accepts null prior_dossier_ref (cold-start)', () => {
    const parsed = DossierClaim.parse({ ...VALID_BASE, prior_dossier_ref: null });
    expect(parsed.prior_dossier_ref).toBeNull();
  });

  it('D18 decision_tree + alerts_walkthrough default to empty when omitted', () => {
    const parsed = DossierClaim.parse({
      type: 'dossier',
      mission_ref: 'ms_minimal',
      authored_by_member_id: 'mem_minimal',
      authored_at_ms: 0,
      narrative: 'minimal',
      lessons_learned: '',
      incident_classification: 'inconclusive',
      prior_dossier_ref: null,
    });
    expect(parsed.decision_tree).toEqual([]);
    expect(parsed.alerts_walkthrough).toEqual([]);
  });
});

describe('DossierClaim — enum catalogs', () => {
  it('D19 IncidentClassification locked to 4 values', () => {
    expect(IncidentClassification.options).toEqual([
      'false_positive',
      'true_positive_handled',
      'true_positive_escalated',
      'inconclusive',
    ]);
  });

  it('DossierDecisionEntry standalone parse', () => {
    const parsed = DossierDecisionEntry.parse({
      checkpoint_id: 'chk_one',
      decision: 'ok',
      rationale: '',
    });
    expect(parsed.checkpoint_id).toBe('chk_one');
  });

  it('DossierAlertEntry standalone parse', () => {
    const parsed = DossierAlertEntry.parse({
      detector_signal_claim_id: 'pc_det_a',
      severity: 'medium',
      narrative: 'reviewed and dismissed',
    });
    expect(parsed.severity).toBe('medium');
  });
});
