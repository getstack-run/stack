import { describe, it, expect } from 'vitest';
import {
  reconstructTimeline,
  type ReconstructClaimInput,
} from './reconstruct-timeline.js';

/**
 * reconstructTimeline invariants.
 *
 *   R1: empty claims → empty timeline with cap_usage zeros
 *   R2: single MissionClaim (open only) → mission.open set, mission.closed=false
 *   R3: two MissionClaims (open + close with terminal_state) → mission_open + mission_close events, closed=true
 *   R4: events ordered by at_ms ascending; ties resolve by claim_id
 *   R5: intent_claim → kind='intent_submitted'
 *   R6: intent_outcome → kind='intent_outcome' AND increments observed_wallet_cents + observed_action_count
 *   R7: detector_signal → kind='detector_signal'
 *   R8: checkpoint_approval → kind='checkpoint_approval'
 *   R9: skill_invocation → kind='skill_invocation'
 *   R10: entity_observation → kind='entity_observation'
 *   R11: intent_denial / intent_simulation / behavioral_genome all map correctly
 *   R12: dossier claims surface only in `dossiers[]` (not in `events`)
 *   R13: twin_divergence claims surface only in `twin_divergence` slot
 *   R14: multiple dossiers ordered by authored_at_ms; latest twin_divergence wins
 *   R15: behavioral_diff lifted from the LATEST mission claim's body
 *   R16: behavioral_diff null when missing OR malformed
 *   R17: cap_usage caps come from latest mission claim
 *   R18: cap_usage observed_wallet_cents sums intent_outcome wallets, ignoring non-numbers
 *   R19: cross-mission claims filtered out (defensive on pack scope)
 *   R20: unknown claim types silently skipped (not in events; no throw)
 *   R21: dossier without authored_at_ms falls back to issued_at_ms for ordering
 *   R22: twin_divergence claim_id surfaces on the result
 */

function claim(input: Partial<ReconstructClaimInput> & { type: string }): ReconstructClaimInput {
  return {
    type: input.type,
    body: input.body ?? {},
    issued_at_ms: input.issued_at_ms ?? 0,
    claim_id: input.claim_id ?? null,
    claim_hash: input.claim_hash ?? null,
  };
}

describe('reconstructTimeline — base shape', () => {
  it('R1 empty claims returns empty timeline', () => {
    const r = reconstructTimeline('ms_x', 'op_x', []);
    expect(r.events).toEqual([]);
    expect(r.dossiers).toEqual([]);
    expect(r.twin_divergence).toBeNull();
    expect(r.behavioral_diff).toBeNull();
    expect(r.cap_usage.observed_wallet_cents).toBe(0);
    expect(r.cap_usage.observed_action_count).toBe(0);
    expect(r.mission.closed).toBe(false);
  });

  it('R2 single open MissionClaim → mission.open set, not closed', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({
        type: 'mission',
        body: { mission_id: 'ms_x', operator_id: 'op_x', terminal_state: null },
        issued_at_ms: 1000,
        claim_id: 'pc_open',
      }),
    ]);
    expect(r.mission.open).toBeDefined();
    expect(r.mission.closed).toBe(false);
    expect(r.events).toHaveLength(1);
    expect(r.events[0]!.kind).toBe('mission_open');
  });

  it('R3 open + close mission claims → both events, closed=true', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({
        type: 'mission',
        body: { mission_id: 'ms_x', terminal_state: null },
        issued_at_ms: 1000,
        claim_id: 'pc_open',
      }),
      claim({
        type: 'mission',
        body: { mission_id: 'ms_x', terminal_state: 'completed_successful' },
        issued_at_ms: 2000,
        claim_id: 'pc_close',
      }),
    ]);
    expect(r.events.map((e) => e.kind)).toEqual(['mission_open', 'mission_close']);
    expect(r.mission.closed).toBe(true);
  });
});

describe('reconstructTimeline — event ordering + kinds', () => {
  it('R4 events ordered by at_ms ascending; ties resolve by claim_id', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'intent_outcome', body: {}, issued_at_ms: 100, claim_id: 'pc_b' }),
      claim({ type: 'intent_claim', body: {}, issued_at_ms: 100, claim_id: 'pc_a' }),
      claim({ type: 'detector_signal', body: {}, issued_at_ms: 200, claim_id: 'pc_c' }),
    ]);
    expect(r.events.map((e) => e.claim_id)).toEqual(['pc_a', 'pc_b', 'pc_c']);
  });

  it('R5 intent_claim → intent_submitted', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'intent_claim', issued_at_ms: 1 }),
    ]);
    expect(r.events[0]!.kind).toBe('intent_submitted');
  });

  it('R6 intent_outcome → intent_outcome kind + wallet_cents accrues', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'intent_outcome', body: { wallet_cents: 50 }, issued_at_ms: 1 }),
      claim({ type: 'intent_outcome', body: { wallet_cents: 75 }, issued_at_ms: 2 }),
    ]);
    expect(r.events.map((e) => e.kind)).toEqual(['intent_outcome', 'intent_outcome']);
    expect(r.cap_usage.observed_wallet_cents).toBe(125);
    expect(r.cap_usage.observed_action_count).toBe(2);
  });

  it('R7 detector_signal → detector_signal', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'detector_signal', issued_at_ms: 1 }),
    ]);
    expect(r.events[0]!.kind).toBe('detector_signal');
  });

  it('R8 checkpoint_approval → checkpoint_approval', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'checkpoint_approval', issued_at_ms: 1 }),
    ]);
    expect(r.events[0]!.kind).toBe('checkpoint_approval');
  });

  it('R9 skill_invocation → skill_invocation', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'skill_invocation', issued_at_ms: 1 }),
    ]);
    expect(r.events[0]!.kind).toBe('skill_invocation');
  });

  it('R10 entity_observation → entity_observation', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'entity_observation', issued_at_ms: 1 }),
    ]);
    expect(r.events[0]!.kind).toBe('entity_observation');
  });

  it('R11 intent_denial / intent_simulation / behavioral_genome all map', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'intent_denial', issued_at_ms: 1 }),
      claim({ type: 'intent_simulation', issued_at_ms: 2 }),
      claim({ type: 'behavioral_genome', issued_at_ms: 3 }),
    ]);
    expect(r.events.map((e) => e.kind)).toEqual([
      'intent_denial',
      'intent_simulation',
      'behavioral_genome',
    ]);
  });

  it('R11b operator_decision is a chronological activity event', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({
        type: 'operator_decision',
        issued_at_ms: 4,
        claim_id: 'pc_decision',
        body: { mission_ref: 'ms_x', action: 'stop' },
      }),
    ]);
    expect(r.events[0]).toMatchObject({
      kind: 'operator_decision',
      claim_id: 'pc_decision',
    });
  });
});

describe('reconstructTimeline — dossiers + twin_divergence', () => {
  it('surfaces legacy dossiers and new operator reviews in one review chain', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'dossier', body: { authored_at_ms: 20 }, issued_at_ms: 20, claim_id: 'pc_old' }),
      claim({ type: 'operator_review', body: { authored_at_ms: 30 }, issued_at_ms: 30, claim_id: 'pc_new' }),
    ]);
    expect(r.operator_reviews.map((review) => review.claim_id)).toEqual(['pc_old', 'pc_new']);
    expect(r.events).toEqual([]);
  });

  it('R12 dossier surfaces in dossiers[] only, not events[]', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({
        type: 'dossier',
        body: { authored_at_ms: 5 },
        issued_at_ms: 5,
        claim_id: 'pc_dossier',
      }),
    ]);
    expect(r.events).toEqual([]);
    expect(r.dossiers).toHaveLength(1);
    expect(r.dossiers[0]!.kind).toBe('dossier');
    expect(r.dossiers[0]!.claim_id).toBe('pc_dossier');
  });

  it('R13 twin_divergence surfaces in slot, not events[]', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({
        type: 'twin_divergence',
        body: { mission_ref: 'ms_x' },
        issued_at_ms: 10,
        claim_id: 'pc_twin',
      }),
    ]);
    expect(r.events).toEqual([]);
    expect(r.twin_divergence?.kind).toBe('twin_divergence');
    expect(r.twin_divergence?.claim_id).toBe('pc_twin');
  });

  it('R14 multiple dossiers ordered chronologically; latest twin wins', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'dossier', body: { authored_at_ms: 200 }, issued_at_ms: 200, claim_id: 'pc_b' }),
      claim({ type: 'dossier', body: { authored_at_ms: 100 }, issued_at_ms: 100, claim_id: 'pc_a' }),
      claim({ type: 'twin_divergence', body: {}, issued_at_ms: 10, claim_id: 'pc_twin_old' }),
      claim({ type: 'twin_divergence', body: {}, issued_at_ms: 20, claim_id: 'pc_twin_new' }),
    ]);
    expect(r.dossiers.map((d) => d.claim_id)).toEqual(['pc_a', 'pc_b']);
    expect(r.twin_divergence?.claim_id).toBe('pc_twin_new');
  });

  it('R21 dossier without authored_at_ms falls back to issued_at_ms', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'dossier', body: {}, issued_at_ms: 42, claim_id: 'pc_d' }),
    ]);
    expect(r.dossiers[0]!.at_ms).toBe(42);
  });

  it('R22 twin_divergence claim_id surfaces on result', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'twin_divergence', issued_at_ms: 1, claim_id: 'pc_twin' }),
    ]);
    expect(r.twin_divergence?.claim_id).toBe('pc_twin');
  });
});

describe('reconstructTimeline — behavioral_diff + cap_usage', () => {
  it('R15 behavioral_diff lifted from latest mission claim', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({
        type: 'mission',
        body: { mission_id: 'ms_x' },
        issued_at_ms: 1000,
      }),
      claim({
        type: 'mission',
        body: {
          mission_id: 'ms_x',
          terminal_state: 'completed_successful',
          behavioral_diff: { max_z: 1.5, l2_norm: 3.2, per_dimension: { latency: 0.4 } },
        },
        issued_at_ms: 2000,
      }),
    ]);
    expect(r.behavioral_diff).toEqual({
      max_z: 1.5,
      l2_norm: 3.2,
      per_dimension: { latency: 0.4 },
    });
  });

  it('R16 behavioral_diff null when missing', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'mission', body: { mission_id: 'ms_x' }, issued_at_ms: 1 }),
    ]);
    expect(r.behavioral_diff).toBeNull();
  });

  it('R16b behavioral_diff null when malformed', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({
        type: 'mission',
        body: { mission_id: 'ms_x', behavioral_diff: 'not_an_object' },
        issued_at_ms: 1,
      }),
    ]);
    expect(r.behavioral_diff).toBeNull();
  });

  it('R17 cap_usage caps come from latest mission claim', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({
        type: 'mission',
        body: {
          mission_id: 'ms_x',
          max_actions: 10,
          max_dropoff_bytes: 1_000_000,
          coverage_cap_cents: 50,
        },
        issued_at_ms: 1,
      }),
    ]);
    expect(r.cap_usage.max_actions).toBe(10);
    expect(r.cap_usage.max_dropoff_bytes).toBe(1_000_000);
    expect(r.cap_usage.coverage_cap_cents).toBe(50);
  });

  it('R18 cap_usage ignores non-number wallet_cents', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'intent_outcome', body: { wallet_cents: 10 }, issued_at_ms: 1 }),
      claim({ type: 'intent_outcome', body: { wallet_cents: 'fifty' }, issued_at_ms: 2 }),
      claim({ type: 'intent_outcome', body: {}, issued_at_ms: 3 }),
    ]);
    expect(r.cap_usage.observed_wallet_cents).toBe(10);
    expect(r.cap_usage.observed_action_count).toBe(3);
  });
});

describe('reconstructTimeline — defensive filters', () => {
  it('R19 cross-mission claims filtered out', () => {
    const r = reconstructTimeline('ms_target', 'op_x', [
      claim({
        type: 'mission',
        body: { mission_id: 'ms_other' },
        issued_at_ms: 1,
      }),
    ]);
    expect(r.mission.open).toBeUndefined();
    expect(r.events).toEqual([]);
  });

  it('R20 unknown claim types silently skipped', () => {
    const r = reconstructTimeline('ms_x', 'op_x', [
      claim({ type: 'svid_attestation', issued_at_ms: 1 }),
      claim({ type: 'invented_type', issued_at_ms: 2 }),
      claim({ type: 'intent_claim', issued_at_ms: 3 }),
    ]);
    expect(r.events).toHaveLength(1);
    expect(r.events[0]!.kind).toBe('intent_submitted');
  });
});
