import { describe, it, expect } from 'vitest';
import { DetectorSignalClaim, PASSPORT_CLAIM_SCHEMAS } from './index.js';

const baseValid = {
  type: 'detector_signal' as const,
  detector_key: 'prompt_injection_llm',
  severity: 'high' as const,
  pipeline: 'llm' as const,
  intent_claim_ref: 'pc_abc123',
  agent_id: 'ag_test1',
  metadata: { confidence_score: 0.92, model: 'claude-haiku-4.5' },
  detected_at: 1_726_000_000_000,
};

describe('DetectorSignalClaim', () => {
  it('accepts a full valid payload', () => {
    expect(() => DetectorSignalClaim.parse(baseValid)).not.toThrow();
  });

  it('accepts minimum required fields (no intent_claim_ref, no agent_id)', () => {
    expect(() =>
      DetectorSignalClaim.parse({
        type: 'detector_signal',
        detector_key: 'scope_drift',
        severity: 'medium',
        pipeline: 'heuristic',
        detected_at: 1_726_000_000_000,
      }),
    ).not.toThrow();
  });

  it('defaults metadata to empty object when omitted', () => {
    const { metadata: _omit, ...rest } = baseValid;
    const parsed = DetectorSignalClaim.parse(rest);
    expect(parsed.metadata).toEqual({});
  });

  it('accepts each pipeline value', () => {
    for (const p of ['heuristic', 'llm', 'detection-chain'] as const) {
      expect(() =>
        DetectorSignalClaim.parse({ ...baseValid, pipeline: p }),
      ).not.toThrow();
    }
  });

  it('accepts each severity value', () => {
    for (const s of ['low', 'medium', 'high', 'critical'] as const) {
      expect(() =>
        DetectorSignalClaim.parse({ ...baseValid, severity: s }),
      ).not.toThrow();
    }
  });

  it('rejects malformed detector_key (uppercase, non-snake_case)', () => {
    expect(() =>
      DetectorSignalClaim.parse({ ...baseValid, detector_key: 'PromptInjection' }),
    ).toThrow();
    expect(() =>
      DetectorSignalClaim.parse({ ...baseValid, detector_key: 'prompt-injection' }),
    ).toThrow();
  });

  it('rejects unknown severity', () => {
    expect(() =>
      DetectorSignalClaim.parse({ ...baseValid, severity: 'urgent' as never }),
    ).toThrow();
  });

  it('rejects unknown pipeline', () => {
    expect(() =>
      DetectorSignalClaim.parse({ ...baseValid, pipeline: 'regex' as never }),
    ).toThrow();
  });

  it('rejects malformed intent_claim_ref', () => {
    expect(() =>
      DetectorSignalClaim.parse({ ...baseValid, intent_claim_ref: 'not-a-claim' }),
    ).toThrow();
  });

  it('rejects malformed agent_id', () => {
    expect(() =>
      DetectorSignalClaim.parse({ ...baseValid, agent_id: 'agent_123' }),
    ).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.detector_signal).toBe(DetectorSignalClaim);
  });

  // mission_ref retrofit
  it('accepts mission_ref as a valid mission_id', () => {
    expect(() =>
      DetectorSignalClaim.parse({ ...baseValid, mission_ref: 'ms_run_42' }),
    ).not.toThrow();
  });

  it('accepts mission_ref omitted (additive nullable optional)', () => {
    expect(() => DetectorSignalClaim.parse({ ...baseValid })).not.toThrow();
  });

  it('rejects mission_ref with wrong prefix', () => {
    expect(() =>
      DetectorSignalClaim.parse({ ...baseValid, mission_ref: 'pc_old_shape' }),
    ).toThrow();
  });
});
