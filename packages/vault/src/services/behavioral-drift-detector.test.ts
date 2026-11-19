import { describe, it, expect } from 'vitest';
import type { Redis } from 'ioredis';
import type { BehavioralGenomeClaim } from '@stack/shared';
import {
  BehavioralDriftDetector,
  type BehavioralDriftDetectorDeps,
  BEHAVIORAL_DRIFT_FIRE_ONCE_TTL_SECONDS,
} from './behavioral-drift-detector.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { PassportRepository } from '../repositories/passport-repo.js';
import type { SecurityEventService, RecordEventInput } from './security-event-service.js';
import type { BehavioralGenomeService } from './behavioral-genome-service.js';

/**
 * BehavioralDriftDetector invariants:
 *
 *  D1: cold-start (prior_genome_ref=null) → silent skip, no record call
 *  D2: prior call_count < MIN_PRIOR_CALL_COUNT → silent skip
 *  D3: drift below threshold (max_z < 3, l2_norm < 5) → no record call
 *  D4: max_z >= 3 → record called with severity=warning, breached_dimensions populated
 *  D5: l2_norm >= 5 (max_z < 3) → record called, L2 breach reflected in metadata
 *  D6: fire-once guard (Redis flag set) → silent skip, no record call
 *  D7: metadata shape locked — current_genome_id, prior_genome_id, max_z,
 *      l2_norm, per_dimension, breached_dimensions, z_threshold, l2_threshold
 *  D8: prior claim missing (pruned/revoked) → silent skip
 */

const TEST_OP = 'op_drift_test';
const TEST_AGENT = 'agt_drift_test';
const TEST_PASSPORT = 'pas_drift_test';

function makeGenome(overrides: Partial<BehavioralGenomeClaim> = {}): BehavioralGenomeClaim {
  return {
    type: 'behavioral_genome',
    passport_jti: TEST_PASSPORT,
    window_start_ms: 1_000_000,
    window_end_ms: 2_000_000,
    call_count: 10,
    mean_latency_ms: 200,
    stddev_latency_ms: 50,
    mean_request_bytes: 500,
    stddev_request_bytes: 100,
    mean_response_bytes: 2000,
    stddev_response_bytes: 400,
    mean_request_entropy: 4.5,
    stddev_request_entropy: 0.5,
    mean_response_entropy: 5.0,
    stddev_response_entropy: 0.5,
    mean_prompt_tokens: 0,
    stddev_prompt_tokens: 0,
    mean_completion_tokens: 0,
    stddev_completion_tokens: 0,
    error_rate: 0,
    scope_histogram: { 'credential.proxy': 10 },
    time_of_day_histogram: new Array(24).fill(0) as number[],
    model_distribution: {},
    prior_genome_ref: 'pc_prior_test',
    ...overrides,
  };
}

interface Stubs {
  claimsByClaimId: Map<string, { type: string; body_json: unknown } | undefined>;
  passportByJti: Map<string, { agent_id: string } | undefined>;
  recordCalls: RecordEventInput[];
  redisGet: Map<string, string>;
  diffResult: { max_z: number; l2_norm: number; per_dimension: Record<string, number> };
}

function makeDetector(stubs: Stubs): BehavioralDriftDetector {
  const passportClaimsRepo = {
    async findByClaimId(claimId: string) {
      return stubs.claimsByClaimId.get(claimId) as never;
    },
  } as unknown as PassportClaimsRepository;

  const passportRepo = {
    async findByJti(jti: string) {
      return stubs.passportByJti.get(jti) as never;
    },
  } as unknown as PassportRepository;

  const securityEvent = {
    async record(input: RecordEventInput) {
      stubs.recordCalls.push(input);
      return { id: 'sevt_stub' } as never;
    },
  } as unknown as SecurityEventService;

  const behavioralGenome = {
    async computeDiff(_currentId: string, _priorId: string) {
      return stubs.diffResult;
    },
  } as unknown as BehavioralGenomeService;

  const redis = {
    async get(key: string) {
      return stubs.redisGet.get(key) ?? null;
    },
    async set(_key: string, _value: string, _ex: string, _ttl: number, _flag?: string) {
      return 'OK' as const;
    },
  } as unknown as Redis;

  const deps: BehavioralDriftDetectorDeps = {
    passportClaimsRepo,
    passportRepo,
    securityEvent,
    behavioralGenome,
    redis,
  };
  return new BehavioralDriftDetector(deps);
}

function freshStubs(overrides: Partial<Stubs> = {}): Stubs {
  return {
    claimsByClaimId: new Map(),
    passportByJti: new Map([[TEST_PASSPORT, { agent_id: TEST_AGENT }]]),
    recordCalls: [],
    redisGet: new Map(),
    diffResult: { max_z: 0, l2_norm: 0, per_dimension: {} },
    ...overrides,
  };
}

describe('BehavioralDriftDetector.check', () => {
  it('D1 cold-start (prior_genome_ref=null) returns silently, no record call', async () => {
    const stubs = freshStubs();
    stubs.claimsByClaimId.set('pc_current', {
      type: 'behavioral_genome',
      body_json: makeGenome({ prior_genome_ref: null }),
    });
    const detector = makeDetector(stubs);
    await detector.check({
      operatorId: TEST_OP,
      passportJti: TEST_PASSPORT,
      claimId: 'pc_current',
    });
    expect(stubs.recordCalls).toHaveLength(0);
  });

  it('D2 prior call_count < MIN_PRIOR_CALL_COUNT returns silently', async () => {
    const stubs = freshStubs();
    stubs.claimsByClaimId.set('pc_current', {
      type: 'behavioral_genome',
      body_json: makeGenome({ prior_genome_ref: 'pc_prior' }),
    });
    stubs.claimsByClaimId.set('pc_prior', {
      type: 'behavioral_genome',
      body_json: makeGenome({ call_count: 3 }), // below MIN_PRIOR_CALL_COUNT=5
    });
    // Even though diff would breach, small-sample guard fires first.
    stubs.diffResult = { max_z: 99, l2_norm: 99, per_dimension: { z_x: 99 } };
    const detector = makeDetector(stubs);
    await detector.check({
      operatorId: TEST_OP,
      passportJti: TEST_PASSPORT,
      claimId: 'pc_current',
    });
    expect(stubs.recordCalls).toHaveLength(0);
  });

  it('D3 drift below threshold returns silently, no record call', async () => {
    const stubs = freshStubs();
    stubs.claimsByClaimId.set('pc_current', {
      type: 'behavioral_genome',
      body_json: makeGenome({ prior_genome_ref: 'pc_prior' }),
    });
    stubs.claimsByClaimId.set('pc_prior', {
      type: 'behavioral_genome',
      body_json: makeGenome({ call_count: 10 }),
    });
    stubs.diffResult = {
      max_z: 1.5, // < 3.0
      l2_norm: 2.0, // < 5.0
      per_dimension: { z_latency: 1.5, z_call_count: 0.3 },
    };
    const detector = makeDetector(stubs);
    await detector.check({
      operatorId: TEST_OP,
      passportJti: TEST_PASSPORT,
      claimId: 'pc_current',
    });
    expect(stubs.recordCalls).toHaveLength(0);
  });

  it('D4 max_z >= 3 fires warning with breached_dimensions populated', async () => {
    const stubs = freshStubs();
    stubs.claimsByClaimId.set('pc_current', {
      type: 'behavioral_genome',
      body_json: makeGenome({ prior_genome_ref: 'pc_prior' }),
    });
    stubs.claimsByClaimId.set('pc_prior', {
      type: 'behavioral_genome',
      body_json: makeGenome({ call_count: 10 }),
    });
    stubs.diffResult = {
      max_z: 4.5,
      l2_norm: 2.0,
      per_dimension: { z_latency: 4.5, z_call_count: 0.3, z_response_bytes: 3.2 },
    };
    const detector = makeDetector(stubs);
    await detector.check({
      operatorId: TEST_OP,
      passportJti: TEST_PASSPORT,
      claimId: 'pc_current',
    });
    expect(stubs.recordCalls).toHaveLength(1);
    const call = stubs.recordCalls[0]!;
    expect(call.signalType).toBe('genome_drift');
    expect(call.severity).toBe('warning');
    expect(call.agentId).toBe(TEST_AGENT);
    expect(call.passportJti).toBe(TEST_PASSPORT);
    const md = call.metadata as Record<string, unknown>;
    expect(md.breached_dimensions).toEqual(
      expect.arrayContaining(['z_latency', 'z_response_bytes']),
    );
  });

  it('D5 l2_norm >= 5 fires even when max_z < 3', async () => {
    const stubs = freshStubs();
    stubs.claimsByClaimId.set('pc_current', {
      type: 'behavioral_genome',
      body_json: makeGenome({ prior_genome_ref: 'pc_prior' }),
    });
    stubs.claimsByClaimId.set('pc_prior', {
      type: 'behavioral_genome',
      body_json: makeGenome({ call_count: 10 }),
    });
    // All dims at 2.5σ — no single dim breaches 3, but composite L2 does
    stubs.diffResult = {
      max_z: 2.5,
      l2_norm: 5.5,
      per_dimension: { z_a: 2.5, z_b: 2.5, z_c: 2.5, z_d: 2.5, z_e: 2.5 },
    };
    const detector = makeDetector(stubs);
    await detector.check({
      operatorId: TEST_OP,
      passportJti: TEST_PASSPORT,
      claimId: 'pc_current',
    });
    expect(stubs.recordCalls).toHaveLength(1);
    const call = stubs.recordCalls[0]!;
    const md = call.metadata as Record<string, unknown>;
    expect(md.l2_norm).toBe(5.5);
    expect(md.max_z).toBe(2.5);
    // No single dim breaches z threshold, so breached_dimensions is empty
    expect(md.breached_dimensions).toEqual([]);
  });

  it('D6 fire-once guard prevents back-to-back firings', async () => {
    const stubs = freshStubs();
    stubs.claimsByClaimId.set('pc_current', {
      type: 'behavioral_genome',
      body_json: makeGenome({ prior_genome_ref: 'pc_prior' }),
    });
    stubs.claimsByClaimId.set('pc_prior', {
      type: 'behavioral_genome',
      body_json: makeGenome({ call_count: 10 }),
    });
    stubs.diffResult = {
      max_z: 4.0,
      l2_norm: 4.5,
      per_dimension: { z_latency: 4.0 },
    };
    // Simulate the fire-once flag already set in Redis
    stubs.redisGet.set(`genome_drift_fired:${TEST_PASSPORT}`, '1');
    const detector = makeDetector(stubs);
    await detector.check({
      operatorId: TEST_OP,
      passportJti: TEST_PASSPORT,
      claimId: 'pc_current',
    });
    expect(stubs.recordCalls).toHaveLength(0);
  });

  it('D7 metadata shape locked', async () => {
    const stubs = freshStubs();
    stubs.claimsByClaimId.set('pc_current', {
      type: 'behavioral_genome',
      body_json: makeGenome({ prior_genome_ref: 'pc_prior_xyz' }),
    });
    stubs.claimsByClaimId.set('pc_prior_xyz', {
      type: 'behavioral_genome',
      body_json: makeGenome({ call_count: 10 }),
    });
    stubs.diffResult = {
      max_z: 3.1,
      l2_norm: 3.5,
      per_dimension: { z_latency: 3.1, z_call_count: 0.5 },
    };
    const detector = makeDetector(stubs);
    await detector.check({
      operatorId: TEST_OP,
      passportJti: TEST_PASSPORT,
      claimId: 'pc_current',
    });
    expect(stubs.recordCalls).toHaveLength(1);
    const md = stubs.recordCalls[0]!.metadata as Record<string, unknown>;
    expect(md).toHaveProperty('current_genome_id', 'pc_current');
    expect(md).toHaveProperty('prior_genome_id', 'pc_prior_xyz');
    expect(md).toHaveProperty('max_z', 3.1);
    expect(md).toHaveProperty('l2_norm', 3.5);
    expect(md).toHaveProperty('per_dimension');
    expect(md).toHaveProperty('breached_dimensions');
    expect(md).toHaveProperty('z_threshold', 3.0);
    expect(md).toHaveProperty('l2_threshold', 5.0);
  });

  it('D8 prior claim missing (pruned/revoked) returns silently', async () => {
    const stubs = freshStubs();
    stubs.claimsByClaimId.set('pc_current', {
      type: 'behavioral_genome',
      body_json: makeGenome({ prior_genome_ref: 'pc_pruned' }),
    });
    // pc_pruned NOT set in stub map → findByClaimId returns undefined
    stubs.diffResult = { max_z: 99, l2_norm: 99, per_dimension: { z_x: 99 } };
    const detector = makeDetector(stubs);
    await detector.check({
      operatorId: TEST_OP,
      passportJti: TEST_PASSPORT,
      claimId: 'pc_current',
    });
    expect(stubs.recordCalls).toHaveLength(0);
  });
});

describe('BehavioralDriftDetector constants', () => {
  it('FIRE_ONCE_TTL_SECONDS is 24 hours', () => {
    expect(BEHAVIORAL_DRIFT_FIRE_ONCE_TTL_SECONDS).toBe(86_400);
  });
});
