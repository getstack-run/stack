import { describe, it, expect } from 'vitest';
import { llmUsage, type BehavioralGenomeClaim } from '@stack/shared';
import {
  BehavioralGenomeService,
  type BehavioralGenomeServiceDeps,
} from './behavioral-genome-service.js';
import type {
  ClaimRegistryService,
  RegisterClaimInput,
  RegisterClaimResult,
} from './claim-registry-service.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';

/**
 * BehavioralGenomeService invariants:
 *
 *  G1: computeGenome aggregates latency means/stddevs from audit_log
 *  G2: computeGenome aggregates bytes/entropy ONLY over non-null rows
 *  G3: computeGenome computes error_rate as (outcome != 'success') / total
 *  G4: computeGenome builds scope_histogram from action prefix
 *  G5: computeGenome builds 24-bucket time_of_day_histogram by UTC hour
 *  G6: computeGenome cold-start (zero rows) returns all-zeros + null prior
 *  G7: computeGenome resolves prior_genome_ref from repo
 *  G8: computeGenome validates payload against schema before returning
 *  G9: computeMissionWindowGenome calls computeGenome over (startedAt, now)
 *
 *  E1: emitGenome calls claimRegistry.registerClaim with behavioral_genome
 *  E2: emitGenome returns the claim_id from the registry
 *
 *  D1: computeDiff returns 0 z-scores for identical genomes
 *  D2: computeDiff returns expected z-score for known shift
 *  D3: computeDiff saturates at Z_SATURATION when prior_stddev=0 and mean differs
 *  D4: computeDiff returns 0 z-score when prior_stddev=0 and mean unchanged
 *  D5: computeDiff l1_scope_histogram catches added/removed services
 *  D6: computeDiff l1_time_of_day_histogram catches hour shifts
 *  D7: computeDiff max_z reflects max abs of all z dimensions
 *  D8: computeDiff l2_norm = sqrt(Σ z_i^2)
 *  D9: computeDiff throws when current or prior claim_id not found
 *
 *  L1: getLatestForPassport returns row from repo
 *  L2: getLatestForPassport returns null when repo returns undefined
 */

type AuditRow = {
  timestamp: number;
  action: string;
  outcome: string;
  duration_ms: number | null;
  request_bytes: number | null;
  response_bytes: number | null;
  request_entropy: number | null;
  response_entropy: number | null;
};

type LlmUsageRow = {
  prompt_tokens: number;
  completion_tokens: number;
  model: string;
};

/**
 * Dispatches the .from(table) call to either the audit-log row set or
 * the llm_usage row set. Legacy callers passing a plain AuditRow[]
 * stay backward-compatible: audit rows back the audit query and the
 * llm_usage query gets `[]` (5.2.5 token fields fall to zeros, schema
 * still validates).
 */
function makeDbStub(
  arg: AuditRow[] | { audit?: AuditRow[]; llmUsage?: LlmUsageRow[] },
) {
  const auditRows = Array.isArray(arg) ? arg : (arg.audit ?? []);
  const llmRows: LlmUsageRow[] = Array.isArray(arg) ? [] : (arg.llmUsage ?? []);
  return {
    select: () => ({
      from: (table: unknown) => ({
        where: () =>
          Promise.resolve(table === llmUsage ? llmRows : auditRows),
      }),
    }),
  } as unknown as BehavioralGenomeServiceDeps['db'];
}

function makeRegistryStub(): ClaimRegistryService & {
  calls: RegisterClaimInput[];
} {
  const calls: RegisterClaimInput[] = [];
  return {
    calls,
    async registerClaim(input: RegisterClaimInput): Promise<RegisterClaimResult> {
      calls.push(input);
      return {
        claimId: `pc_genome_${calls.length}`,
        envelopeCose: 'fake_cose',
        subject: `stack://operator/${input.operatorId}/passport/${input.passportJti}`,
      } as RegisterClaimResult;
    },
  } as unknown as ClaimRegistryService & { calls: RegisterClaimInput[] };
}

type StoredClaim = { claim_id: string; body_json: unknown };

function makeRepoStub(opts?: {
  latestByType?: Record<string, StoredClaim | undefined>;
  byClaimId?: Record<string, StoredClaim | undefined>;
  /**
   * findActiveByTypeAndWindow lookups for emitForWindow
   * dedupe tests. Keyed by `${claimType}:${windowStartMs}`.
   */
  byTypeAndWindow?: Record<string, StoredClaim | undefined>;
}): PassportClaimsRepository {
  return {
    async getLatestByType(_passportId: string, claimType: string) {
      return opts?.latestByType?.[claimType] as never;
    },
    async findByClaimId(claimId: string) {
      return opts?.byClaimId?.[claimId] as never;
    },
    async findActiveByTypeAndWindow(
      _passportId: string,
      claimType: string,
      windowStartMs: number,
    ) {
      const key = `${claimType}:${windowStartMs}`;
      return opts?.byTypeAndWindow?.[key] as never;
    },
  } as unknown as PassportClaimsRepository;
}

// 2026-05-21T12:00:00Z — UTC hour 12. Used as the canonical fixture
// timestamp so time_of_day_histogram tests are deterministic.
const FIXTURE_TS_NOON = Date.UTC(2026, 4, 21, 12, 0, 0);
const FIXTURE_TS_MIDNIGHT = Date.UTC(2026, 4, 21, 0, 0, 0);
const WINDOW_START = Date.UTC(2026, 4, 20, 0, 0, 0);
const WINDOW_END = Date.UTC(2026, 4, 22, 0, 0, 0);

const PASSPORT_JTI = 'jti_test_genome';

describe('BehavioralGenomeService.computeGenome', () => {
  it('G6 cold-start (zero rows) returns all-zeros + null prior', async () => {
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.call_count).toBe(0);
    expect(g.mean_latency_ms).toBe(0);
    expect(g.stddev_latency_ms).toBe(0);
    expect(g.mean_request_bytes).toBe(0);
    expect(g.mean_response_bytes).toBe(0);
    expect(g.mean_request_entropy).toBe(0);
    expect(g.mean_response_entropy).toBe(0);
    expect(g.error_rate).toBe(0);
    expect(g.scope_histogram).toEqual({});
    expect(g.time_of_day_histogram).toEqual(new Array(24).fill(0));
    expect(g.prior_genome_ref).toBeNull();
  });

  it('G1 aggregates latency mean + stddev across calls', async () => {
    const rows: AuditRow[] = [
      auditRow({ duration_ms: 100, timestamp: FIXTURE_TS_NOON }),
      auditRow({ duration_ms: 200, timestamp: FIXTURE_TS_NOON }),
      auditRow({ duration_ms: 300, timestamp: FIXTURE_TS_NOON }),
    ];
    const svc = new BehavioralGenomeService({
      db: makeDbStub(rows),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.call_count).toBe(3);
    expect(g.mean_latency_ms).toBeCloseTo(200, 10);
    // population stddev of [100, 200, 300] = sqrt((10000+0+10000)/3) ≈ 81.65
    expect(g.stddev_latency_ms).toBeCloseTo(Math.sqrt((10000 + 0 + 10000) / 3), 6);
  });

  it('G2 aggregates bytes/entropy ONLY over non-null rows', async () => {
    const rows: AuditRow[] = [
      auditRow({ request_bytes: 100, response_bytes: 1000, request_entropy: 4, response_entropy: 6, timestamp: FIXTURE_TS_NOON }),
      // Non-HTTP audit row (e.g. skill invocation) — bytes/entropy null
      auditRow({ request_bytes: null, response_bytes: null, request_entropy: null, response_entropy: null, timestamp: FIXTURE_TS_NOON }),
      auditRow({ request_bytes: 200, response_bytes: 2000, request_entropy: 5, response_entropy: 7, timestamp: FIXTURE_TS_NOON }),
    ];
    const svc = new BehavioralGenomeService({
      db: makeDbStub(rows),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.call_count).toBe(3);
    // Means over the 2 non-null rows only
    expect(g.mean_request_bytes).toBeCloseTo(150, 10);
    expect(g.mean_response_bytes).toBeCloseTo(1500, 10);
    expect(g.mean_request_entropy).toBeCloseTo(4.5, 10);
    expect(g.mean_response_entropy).toBeCloseTo(6.5, 10);
  });

  it('G3 error_rate is (outcome != success) / total', async () => {
    const rows: AuditRow[] = [
      auditRow({ outcome: 'success', timestamp: FIXTURE_TS_NOON }),
      auditRow({ outcome: 'success', timestamp: FIXTURE_TS_NOON }),
      auditRow({ outcome: 'failure', timestamp: FIXTURE_TS_NOON }),
      auditRow({ outcome: 'blocked', timestamp: FIXTURE_TS_NOON }),
    ];
    const svc = new BehavioralGenomeService({
      db: makeDbStub(rows),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.error_rate).toBeCloseTo(0.5, 10);
  });

  it('G4 scope_histogram groups by action prefix before the first dot', async () => {
    const rows: AuditRow[] = [
      auditRow({ action: 'credential.proxy', timestamp: FIXTURE_TS_NOON }),
      auditRow({ action: 'credential.proxy', timestamp: FIXTURE_TS_NOON }),
      auditRow({ action: 'skill.invoke', timestamp: FIXTURE_TS_NOON }),
      auditRow({ action: 'dropoff.deposit', timestamp: FIXTURE_TS_NOON }),
    ];
    const svc = new BehavioralGenomeService({
      db: makeDbStub(rows),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.scope_histogram).toEqual({
      credential: 2,
      skill: 1,
      dropoff: 1,
    });
  });

  it('G5 time_of_day_histogram buckets by UTC hour', async () => {
    const rows: AuditRow[] = [
      auditRow({ timestamp: FIXTURE_TS_MIDNIGHT }), // hour 0
      auditRow({ timestamp: FIXTURE_TS_MIDNIGHT + 3600_000 }), // hour 1
      auditRow({ timestamp: FIXTURE_TS_NOON }), // hour 12
      auditRow({ timestamp: FIXTURE_TS_NOON + 3600_000 }), // hour 13
      auditRow({ timestamp: FIXTURE_TS_NOON }), // hour 12 again
    ];
    const svc = new BehavioralGenomeService({
      db: makeDbStub(rows),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.time_of_day_histogram).toHaveLength(24);
    expect(g.time_of_day_histogram[0]).toBe(1);
    expect(g.time_of_day_histogram[1]).toBe(1);
    expect(g.time_of_day_histogram[12]).toBe(2);
    expect(g.time_of_day_histogram[13]).toBe(1);
    // All other hours zero
    for (let h = 0; h < 24; h++) {
      if (h !== 0 && h !== 1 && h !== 12 && h !== 13) {
        expect(g.time_of_day_histogram[h]).toBe(0);
      }
    }
  });

  it('G7 resolves prior_genome_ref from repo', async () => {
    const repo = makeRepoStub({
      latestByType: {
        behavioral_genome: { claim_id: 'pc_prev_xyz', body_json: {} },
      },
    });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: repo,
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.prior_genome_ref).toBe('pc_prev_xyz');
  });

  it('G8 validates payload against schema (token defaults populate)', async () => {
    const svc = new BehavioralGenomeService({
      db: makeDbStub([auditRow({ duration_ms: 100, timestamp: FIXTURE_TS_NOON })]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    // Schema validation should have populated defaults
    expect(g.mean_prompt_tokens).toBe(0);
    expect(g.stddev_prompt_tokens).toBe(0);
    expect(g.mean_completion_tokens).toBe(0);
    expect(g.stddev_completion_tokens).toBe(0);
    expect(g.model_distribution).toEqual({});
  });
});

describe('BehavioralGenomeService.computeMissionWindowGenome', () => {
  it('G9 computes genome over (startedAt, now)', async () => {
    const svc = new BehavioralGenomeService({
      db: makeDbStub([auditRow({ duration_ms: 50, timestamp: FIXTURE_TS_NOON })]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const startedAt = Date.now() - 60_000;
    const g = await svc.computeMissionWindowGenome(PASSPORT_JTI, startedAt);
    expect(g.window_start_ms).toBe(startedAt);
    expect(g.window_end_ms).toBeGreaterThan(startedAt);
    expect(g.window_end_ms).toBeLessThanOrEqual(Date.now() + 1);
  });
});

describe('BehavioralGenomeService.emitGenome', () => {
  it('E1 calls claimRegistry.registerClaim with behavioral_genome', async () => {
    const registry = makeRegistryStub();
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: registry,
      passportClaimsRepo: makeRepoStub(),
    });
    const payload = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    await svc.emitGenome('op_test', PASSPORT_JTI, payload);
    expect(registry.calls).toHaveLength(1);
    expect(registry.calls[0]!.claimType).toBe('behavioral_genome');
    expect(registry.calls[0]!.operatorId).toBe('op_test');
    expect(registry.calls[0]!.passportJti).toBe(PASSPORT_JTI);
  });

  it('E2 returns the claim_id from the registry', async () => {
    const registry = makeRegistryStub();
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: registry,
      passportClaimsRepo: makeRepoStub(),
    });
    const payload = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    const res = await svc.emitGenome('op_test', PASSPORT_JTI, payload);
    expect(res.claim_id).toMatch(/^pc_genome_\d+$/);
  });
});

describe('BehavioralGenomeService.computeDiff', () => {
  function makeFixtureGenome(overrides: Partial<BehavioralGenomeClaim> = {}): BehavioralGenomeClaim {
    return {
      type: 'behavioral_genome',
      passport_jti: PASSPORT_JTI,
      window_start_ms: WINDOW_START,
      window_end_ms: WINDOW_END,
      call_count: 100,
      mean_latency_ms: 200,
      stddev_latency_ms: 50,
      mean_request_bytes: 500,
      stddev_request_bytes: 100,
      mean_response_bytes: 2000,
      stddev_response_bytes: 400,
      mean_request_entropy: 4.5,
      stddev_request_entropy: 0.5,
      mean_response_entropy: 6.0,
      stddev_response_entropy: 0.8,
      error_rate: 0.02,
      scope_histogram: { credential: 80, skill: 20 },
      time_of_day_histogram: Array.from({ length: 24 }, (_, i) => (i >= 8 && i < 18 ? 10 : 0)),
      mean_prompt_tokens: 0,
      stddev_prompt_tokens: 0,
      mean_completion_tokens: 0,
      stddev_completion_tokens: 0,
      model_distribution: {},
      prior_genome_ref: null,
      ...overrides,
    };
  }

  it('D1 returns 0 z-scores for identical genomes', async () => {
    const genome = makeFixtureGenome();
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({
        byClaimId: {
          pc_current: { claim_id: 'pc_current', body_json: genome },
          pc_prior: { claim_id: 'pc_prior', body_json: genome },
        },
      }),
    });
    const diff = await svc.computeDiff('pc_current', 'pc_prior');
    expect(diff.max_z).toBe(0);
    expect(diff.l2_norm).toBe(0);
  });

  it('D2 returns expected z-score for known latency shift', async () => {
    // prior: mean=200, stddev=50. current: mean=350. z = (350-200)/50 = 3.0
    const prior = makeFixtureGenome();
    const current = makeFixtureGenome({ mean_latency_ms: 350 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({
        byClaimId: {
          pc_current: { claim_id: 'pc_current', body_json: current },
          pc_prior: { claim_id: 'pc_prior', body_json: prior },
        },
      }),
    });
    const diff = await svc.computeDiff('pc_current', 'pc_prior');
    expect(diff.per_dimension.z_mean_latency_ms).toBeCloseTo(3.0, 6);
    expect(diff.max_z).toBeGreaterThanOrEqual(3.0);
  });

  it('D3 saturates at Z_SATURATION when prior_stddev=0 and mean differs', async () => {
    const prior = makeFixtureGenome({ mean_latency_ms: 100, stddev_latency_ms: 0 });
    const current = makeFixtureGenome({ mean_latency_ms: 200, stddev_latency_ms: 50 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({
        byClaimId: {
          pc_current: { claim_id: 'pc_current', body_json: current },
          pc_prior: { claim_id: 'pc_prior', body_json: prior },
        },
      }),
    });
    const diff = await svc.computeDiff('pc_current', 'pc_prior');
    expect(diff.per_dimension.z_mean_latency_ms).toBe(10); // Z_SATURATION
  });

  it('D4 returns 0 z when prior_stddev=0 and mean unchanged', async () => {
    const same = makeFixtureGenome({ mean_latency_ms: 100, stddev_latency_ms: 0 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({
        byClaimId: {
          pc_current: { claim_id: 'pc_current', body_json: same },
          pc_prior: { claim_id: 'pc_prior', body_json: same },
        },
      }),
    });
    const diff = await svc.computeDiff('pc_current', 'pc_prior');
    expect(diff.per_dimension.z_mean_latency_ms).toBe(0);
  });

  it('D5 l1_scope_histogram catches added service', async () => {
    const prior = makeFixtureGenome({ scope_histogram: { credential: 100 } });
    const current = makeFixtureGenome({ scope_histogram: { credential: 50, stripe: 50 } });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({
        byClaimId: {
          pc_current: { claim_id: 'pc_current', body_json: current },
          pc_prior: { claim_id: 'pc_prior', body_json: prior },
        },
      }),
    });
    const diff = await svc.computeDiff('pc_current', 'pc_prior');
    // prior: credential=1.0, stripe=0. current: credential=0.5, stripe=0.5
    // L1 = |0.5-1.0| + |0.5-0| = 1.0
    expect(diff.per_dimension.l1_scope_histogram).toBeCloseTo(1.0, 6);
  });

  it('D9 throws when current or prior claim_id not found', async () => {
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({ byClaimId: {} }),
    });
    await expect(svc.computeDiff('pc_missing', 'pc_other')).rejects.toThrow(/not found/);
  });
});

describe('BehavioralGenomeService.computeDiffFromPayloads', () => {
  function makeFixtureGenome(overrides: Partial<BehavioralGenomeClaim> = {}): BehavioralGenomeClaim {
    return {
      type: 'behavioral_genome',
      passport_jti: PASSPORT_JTI,
      window_start_ms: WINDOW_START,
      window_end_ms: WINDOW_END,
      call_count: 100,
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
      scope_histogram: { credential: 100 },
      time_of_day_histogram: new Array(24).fill(0) as number[],
      model_distribution: {},
      prior_genome_ref: null,
      ...overrides,
    };
  }

  it('DP1 matches computeDiff output for identical inputs (no-drift)', async () => {
    const genome = makeFixtureGenome();
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({
        byClaimId: {
          pc_a: { claim_id: 'pc_a', body_json: genome },
          pc_b: { claim_id: 'pc_b', body_json: genome },
        },
      }),
    });
    const byId = await svc.computeDiff('pc_a', 'pc_b');
    const byPayload = svc.computeDiffFromPayloads(genome, genome);
    expect(byPayload).toEqual(byId);
    expect(byPayload.max_z).toBe(0);
    expect(byPayload.l2_norm).toBe(0);
  });

  it('DP2 computes z-score correctly for known shift (3σ on latency)', () => {
    const prior = makeFixtureGenome();
    const current = makeFixtureGenome({ mean_latency_ms: 350 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const diff = svc.computeDiffFromPayloads(current, prior);
    expect(diff.per_dimension.z_mean_latency_ms).toBeCloseTo(3.0, 6);
  });

  it('DP3 saturates at Z_SATURATION when prior_stddev=0 and mean differs', () => {
    const prior = makeFixtureGenome({ mean_latency_ms: 100, stddev_latency_ms: 0 });
    const current = makeFixtureGenome({ mean_latency_ms: 200, stddev_latency_ms: 50 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const diff = svc.computeDiffFromPayloads(current, prior);
    expect(diff.per_dimension.z_mean_latency_ms).toBe(10);
  });

  it('DP4 histogram L1 distance matches by-id variant', () => {
    const prior = makeFixtureGenome({ scope_histogram: { credential: 100 } });
    const current = makeFixtureGenome({ scope_histogram: { credential: 50, stripe: 50 } });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const diff = svc.computeDiffFromPayloads(current, prior);
    expect(diff.per_dimension.l1_scope_histogram).toBeCloseTo(1.0, 6);
  });

  it('DP5 does not throw on payloads (no claim_id lookups)', () => {
    const prior = makeFixtureGenome();
    const current = makeFixtureGenome({ mean_latency_ms: 250 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({ byClaimId: {} }),
    });
    // The by-id variant would throw 'not found' here; the by-payload
    // variant skips the lookup entirely.
    expect(() => svc.computeDiffFromPayloads(current, prior)).not.toThrow();
  });
});

describe('BehavioralGenomeService.emitForWindow', () => {
  it('EW1 returns {emitted:false, callCount:0} for an empty window (no audit rows)', async () => {
    const registry = makeRegistryStub();
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: registry,
      passportClaimsRepo: makeRepoStub(),
    });
    const res = await svc.emitForWindow('op_test', PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(res.emitted).toBe(false);
    expect(res.callCount).toBe(0);
    expect(res.claimId).toBeNull();
    expect(res.deduped).toBe(false);
    expect(registry.calls).toHaveLength(0);
  });

  it('EW2 returns {emitted:true, claimId, callCount} for a populated window', async () => {
    const registry = makeRegistryStub();
    const svc = new BehavioralGenomeService({
      db: makeDbStub([auditRow(), auditRow(), auditRow()]),
      claimRegistry: registry,
      passportClaimsRepo: makeRepoStub(),
    });
    const res = await svc.emitForWindow('op_test', PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(res.emitted).toBe(true);
    expect(res.callCount).toBe(3);
    expect(res.claimId).toMatch(/^pc_genome_\d+$/);
    expect(res.deduped).toBe(false);
    expect(registry.calls).toHaveLength(1);
    expect(registry.calls[0]!.claimType).toBe('behavioral_genome');
  });

  it('EW3 returns {deduped:true} on second call for the same window (crash-recovery)', async () => {
    // First call: no existing genome → compute + emit
    const registry = makeRegistryStub();
    const svc = new BehavioralGenomeService({
      db: makeDbStub([auditRow()]),
      claimRegistry: registry,
      passportClaimsRepo: makeRepoStub({
        // Simulate the row landed in the registry from the first call.
        byTypeAndWindow: {
          [`behavioral_genome:${WINDOW_START}`]: {
            claim_id: 'pc_genome_existing',
            body_json: {},
          },
        },
      }),
    });
    const res = await svc.emitForWindow('op_test', PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(res.deduped).toBe(true);
    expect(res.emitted).toBe(false);
    expect(res.claimId).toBe('pc_genome_existing');
    expect(res.callCount).toBe(0);
    // Registry NOT called on dedupe hit.
    expect(registry.calls).toHaveLength(0);
  });

  it('EW4 propagates registry errors (e.g. ForbiddenError on non-enterprise tier)', async () => {
    const throwingRegistry = {
      async registerClaim(_input: RegisterClaimInput): Promise<RegisterClaimResult> {
        throw new Error('claim type "behavioral_genome" is not permitted for tier "developer"');
      },
    } as unknown as ClaimRegistryService;
    const svc = new BehavioralGenomeService({
      db: makeDbStub([auditRow()]),
      claimRegistry: throwingRegistry,
      passportClaimsRepo: makeRepoStub(),
    });
    await expect(
      svc.emitForWindow('op_developer', PASSPORT_JTI, WINDOW_START, WINDOW_END),
    ).rejects.toThrow(/not permitted for tier/);
  });
});

describe('BehavioralGenomeService.getLatestForPassport', () => {
  it('L1 returns row from repo', async () => {
    const row = { claim_id: 'pc_abc', body_json: {} };
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub({
        latestByType: { behavioral_genome: row as never },
      }),
    });
    const got = await svc.getLatestForPassport(PASSPORT_JTI);
    expect(got).toBe(row);
  });

  it('L2 returns null when repo returns undefined', async () => {
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const got = await svc.getLatestForPassport(PASSPORT_JTI);
    expect(got).toBeNull();
  });
});

// ── token-field producer + diff guard ──────────────────
//
// T1-T4 cover the producer side (computeGenome now reads llm_usage).
// D-guard-1 + D-guard-2 cover the diffPayloads skip when prior token
// mean is zero — the false-positive guard against pre-5.2.5 priors.

describe('BehavioralGenomeService.computeGenome — token fields', () => {
  it('T1 populates mean + stddev of prompt + completion tokens from llm_usage', async () => {
    // Three calls: prompt_tokens [100, 200, 300], completion [50, 100, 150].
    // mean prompt = 200, stddev = sqrt((10000+0+10000)/3) ≈ 81.65
    // mean completion = 100, stddev = sqrt((2500+0+2500)/3) ≈ 40.82
    const svc = new BehavioralGenomeService({
      db: makeDbStub({
        audit: [auditRow({ duration_ms: 50, timestamp: FIXTURE_TS_NOON })],
        llmUsage: [
          { prompt_tokens: 100, completion_tokens: 50, model: 'anthropic/claude-opus-4-7' },
          { prompt_tokens: 200, completion_tokens: 100, model: 'anthropic/claude-opus-4-7' },
          { prompt_tokens: 300, completion_tokens: 150, model: 'anthropic/claude-opus-4-7' },
        ],
      }),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.mean_prompt_tokens).toBeCloseTo(200, 6);
    expect(g.stddev_prompt_tokens).toBeCloseTo(Math.sqrt((10000 + 0 + 10000) / 3), 6);
    expect(g.mean_completion_tokens).toBeCloseTo(100, 6);
    expect(g.stddev_completion_tokens).toBeCloseTo(Math.sqrt((2500 + 0 + 2500) / 3), 6);
  });

  it('T2 token fields stay at zero when llm_usage has no rows in window', async () => {
    const svc = new BehavioralGenomeService({
      db: makeDbStub({
        audit: [auditRow({ duration_ms: 100, timestamp: FIXTURE_TS_NOON })],
        llmUsage: [],
      }),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.mean_prompt_tokens).toBe(0);
    expect(g.stddev_prompt_tokens).toBe(0);
    expect(g.mean_completion_tokens).toBe(0);
    expect(g.stddev_completion_tokens).toBe(0);
    expect(g.model_distribution).toEqual({});
  });

  it('T3 model_distribution histograms by llm_usage.model', async () => {
    const svc = new BehavioralGenomeService({
      db: makeDbStub({
        audit: [auditRow({ timestamp: FIXTURE_TS_NOON })],
        llmUsage: [
          { prompt_tokens: 100, completion_tokens: 50, model: 'anthropic/claude-opus-4-7' },
          { prompt_tokens: 200, completion_tokens: 100, model: 'anthropic/claude-opus-4-7' },
          { prompt_tokens: 50, completion_tokens: 25, model: 'openai/gpt-4o' },
        ],
      }),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.model_distribution).toEqual({
      'anthropic/claude-opus-4-7': 2,
      'openai/gpt-4o': 1,
    });
  });

  it('T4 wire-shape validates: token fields parse through BehavioralGenomeClaim schema', async () => {
    // Defense-in-depth — confirm the schema validation at the end of
    // computeGenome doesn't reject non-default token values.
    const svc = new BehavioralGenomeService({
      db: makeDbStub({
        audit: [auditRow({ timestamp: FIXTURE_TS_NOON })],
        llmUsage: [
          { prompt_tokens: 12345, completion_tokens: 6789, model: 'openrouter/meta-llama/llama-3.1-70b' },
        ],
      }),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const g = await svc.computeGenome(PASSPORT_JTI, WINDOW_START, WINDOW_END);
    expect(g.mean_prompt_tokens).toBe(12345);
    expect(g.mean_completion_tokens).toBe(6789);
    // Single sample → stddev=0 by convention.
    expect(g.stddev_prompt_tokens).toBe(0);
    expect(g.stddev_completion_tokens).toBe(0);
    expect(g.model_distribution).toEqual({ 'openrouter/meta-llama/llama-3.1-70b': 1 });
  });
});

describe('BehavioralGenomeService.computeDiffFromPayloads — token guard', () => {
  // Use the same fixture shape as computeDiffFromPayloads' existing tests
  // (lines 466-494 above). Inline a minimal builder here so the guard
  // tests stay self-contained.
  function makeGenome(overrides: Partial<BehavioralGenomeClaim> = {}): BehavioralGenomeClaim {
    return {
      type: 'behavioral_genome',
      passport_jti: PASSPORT_JTI,
      window_start_ms: WINDOW_START,
      window_end_ms: WINDOW_END,
      call_count: 100,
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
      scope_histogram: { credential: 100 },
      time_of_day_histogram: new Array(24).fill(0) as number[],
      model_distribution: {},
      prior_genome_ref: null,
      ...overrides,
    };
  }

  it('D-guard-1 skips z_mean_prompt_tokens when prior mean is zero', () => {
    // Prior is pre-5.2.5 sentinel (all token fields zero). Current
    // has real LLM activity (12000 mean prompt). Without the guard
    // this would saturate to ±10 and fire genome_drift.
    const prior = makeGenome(); // mean_prompt_tokens=0
    const current = makeGenome({ mean_prompt_tokens: 12000, stddev_prompt_tokens: 2000 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const diff = svc.computeDiffFromPayloads(current, prior);
    expect(diff.per_dimension.z_mean_prompt_tokens).toBeUndefined();
    // max_z must NOT be inflated by the skipped dimension.
    expect(diff.max_z).toBeLessThan(3);
  });

  it('D-guard-2 skips z_mean_completion_tokens when prior mean is zero', () => {
    const prior = makeGenome(); // mean_completion_tokens=0
    const current = makeGenome({ mean_completion_tokens: 5000, stddev_completion_tokens: 1000 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const diff = svc.computeDiffFromPayloads(current, prior);
    expect(diff.per_dimension.z_mean_completion_tokens).toBeUndefined();
    expect(diff.max_z).toBeLessThan(3);
  });

  it('D-guard-3 token z-score DOES compute when prior mean is non-zero (guard is asymmetric)', () => {
    // Prior carries real token activity; the guard does NOT skip the
    // diff in this case — drift detection works normally.
    const prior = makeGenome({ mean_prompt_tokens: 100, stddev_prompt_tokens: 10 });
    const current = makeGenome({ mean_prompt_tokens: 400, stddev_prompt_tokens: 50 });
    const svc = new BehavioralGenomeService({
      db: makeDbStub([]),
      claimRegistry: makeRegistryStub(),
      passportClaimsRepo: makeRepoStub(),
    });
    const diff = svc.computeDiffFromPayloads(current, prior);
    // Raw z = (400-100) / 10 = 30 (no Z_SATURATION when prior stddev>0).
    // The point is that the guard did NOT skip — dimension is present.
    expect(diff.per_dimension.z_mean_prompt_tokens).toBe(30);
  });
});

// ── Test helpers ───────────────────────────────────────────────────

function auditRow(overrides: Partial<AuditRow> = {}): AuditRow {
  return {
    timestamp: FIXTURE_TS_NOON,
    action: 'credential.proxy',
    outcome: 'success',
    duration_ms: 100,
    request_bytes: 200,
    response_bytes: 1000,
    request_entropy: 4.0,
    response_entropy: 6.0,
    ...overrides,
  };
}
