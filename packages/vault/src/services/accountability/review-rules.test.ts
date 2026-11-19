import { describe, expect, it } from 'vitest';
import {
  behavioralAnomalyFlags,
  checkpointGapFlags,
  credentialUnreportedFlags,
  determineReviewStatus,
  highActionVolumeFlags,
  missingCheckpointFlags,
  scopeEscalationPatternFlags,
  undeclaredDelegationFlags,
  undeclaredServiceFlags,
} from './review-rules.js';

const passport = (overrides: Record<string, unknown> = {}) =>
  ({
    jti: 'ppt_now',
    intent_services: ['slack'],
    intent_delegates: false,
    checkpoint_interval_seconds: 60,
    issued_at: new Date(Date.now() - 60_000),
    ...overrides,
  }) as never;

const checkout = (overrides: Record<string, unknown> = {}) =>
  ({ services_used: ['slack'], actions_count: 3, ...overrides }) as never;

const baselineRow = (jti: string) => ({
  passport_jti: jti,
  actions_count: 10,
  services_used: ['slack'],
  issued_at: new Date(0),
  submitted_at: new Date(60_000),
});

describe('review rules', () => {
  it('flags a service the declared intent did not name', () => {
    expect(undeclaredServiceFlags(passport(), checkout({ services_used: ['slack', 'stripe'] }))).toEqual([
      { type: 'undeclared_service', severity: 'warning', message: 'Accessed stripe (not in declared intent)' },
    ]);
    expect(undeclaredServiceFlags(passport({ intent_services: null }), checkout())).toEqual([]);
  });

  it('flags delegation the intent did not declare, as critical', () => {
    expect(undeclaredDelegationFlags(passport(), checkout({ delegated_to: ['agt_a'] }))[0]).toMatchObject({
      type: 'undeclared_delegation',
      severity: 'critical',
    });
    expect(
      undeclaredDelegationFlags(passport({ intent_delegates: true }), checkout({ delegated_to: ['agt_a'] })),
    ).toEqual([]);
  });

  it('flags missing checkpoints and gaps only for enforced missions', () => {
    expect(missingCheckpointFlags(true, [])[0]?.type).toBe('no_checkpoints');
    expect(missingCheckpointFlags(false, [])).toEqual([]);
    const at = (seconds: number) => ({ submitted_at: new Date(seconds * 1000) }) as never;
    expect(checkpointGapFlags(true, passport(), [at(0), at(500)])[0]).toMatchObject({
      type: 'checkpoint_gap',
      severity: 'info',
    });
    expect(checkpointGapFlags(true, passport(), [at(0), at(100)])).toEqual([]);
    expect(checkpointGapFlags(false, passport(), [at(0), at(500)])).toEqual([]);
  });

  it('grades action volume by two thresholds', () => {
    expect(highActionVolumeFlags(checkout({ actions_count: 501 }))[0]?.severity).toBe('warning');
    expect(highActionVolumeFlags(checkout({ actions_count: 101 }))[0]?.severity).toBe('info');
    expect(highActionVolumeFlags(checkout({ actions_count: 100 }))).toEqual([]);
  });

  it('flags monotonic growth in declared services across recent passports', () => {
    const recent = (counts: number[]) =>
      counts.map((n) => ({ intent_services: Array.from({ length: n }, (_, i) => `s${i}`) }) as never);
    expect(scopeEscalationPatternFlags(recent([1, 2, 3]))[0]?.type).toBe('scope_escalation_pattern');
    expect(scopeEscalationPatternFlags(recent([3, 1, 3]))).toEqual([]);
    expect(scopeEscalationPatternFlags(recent([1, 1]))).toEqual([]);
  });

  it('reports credentials retrieved but not reported, ignoring connection-based access', () => {
    const checkpoints = [{ services_used: ['slack'] }] as never;
    const flags = credentialUnreportedFlags(['slack', 'github', 'conn:scon_x'], checkpoints, checkout());
    expect(flags).toHaveLength(1);
    expect(flags[0]?.message).toContain('github');
    expect(flags[0]?.message).not.toContain('slack');
    expect(credentialUnreportedFlags([], checkpoints, checkout())).toEqual([]);
  });

  it('needs five baseline checkouts before it calls anything anomalous', () => {
    const history = (n: number) => Array.from({ length: n }, (_, i) => baselineRow(`ppt_${i}`)) as never;
    const big = checkout({ actions_count: 1000 });
    expect(behavioralAnomalyFlags(passport(), big, history(4))).toEqual([]);
    expect(behavioralAnomalyFlags(passport(), big, history(5))[0]?.type).toBe('behavioral_anomaly');
    // The mission's own checkout is not part of its baseline.
    const withOwn = [...Array.from({ length: 4 }, (_, i) => baselineRow(`ppt_${i}`)), baselineRow('ppt_now')];
    expect(behavioralAnomalyFlags(passport(), big, withOwn as never)).toEqual([]);
  });

  it('decides status from severities and the agent escalation settings', () => {
    const agent = { on_warning: 'flag', on_critical: 'block' };
    const flag = (type: string, severity: 'info' | 'warning' | 'critical') =>
      ({ type, severity, message: '' }) as never;
    expect(determineReviewStatus([], agent)).toBe('clean');
    expect(determineReviewStatus([flag('high_action_volume', 'info')], agent)).toBe('clean');
    expect(determineReviewStatus([flag('no_checkpoints', 'warning')], agent)).toBe('flagged');
    expect(determineReviewStatus([flag('undeclared_delegation', 'critical')], agent)).toBe('blocked');
    expect(determineReviewStatus([flag('no_checkpoints', 'warning')], { ...agent, on_warning: 'block' })).toBe(
      'blocked',
    );
  });
});
