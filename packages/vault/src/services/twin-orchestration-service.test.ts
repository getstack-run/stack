import { describe, it, expect, vi } from 'vitest';
import type { IntentClaim, IntentOutcomeClaim } from '@stack/shared';
import { TwinOrchestrationService } from './twin-orchestration-service.js';
import type { TwinRunsRepository, TwinRunRow } from '../repositories/twin-runs-repo.js';
import type { PassportService } from './passport-service.js';
import type { PassportRepository } from '../repositories/passport-repo.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { ClaimRegistryService } from './claim-registry-service.js';

/**
 * TwinOrchestrationService invariants.
 *
 *   T1: startTwinForMission issues twin passport + inserts twin_runs row
 *   T2: startTwinForMission idempotent on mission_id — returns existing
 *   T3: twin passport carries '[TWIN]' summary prefix + mirrored services + ttl from remaining
 *   T4: startTwinForMission throws when real passport not found
 *   T5: mirrorIntent registers twin intent_claim under twin passport + appends to claim_pairs
 *   T6: mirrorIntent returns null + logs on claimRegistry failure (best-effort)
 *   T7: mirrorOutcome appends to claim_pairs (no throw on repo failure)
 *   T8: evaluateDivergence stub emits TwinDivergenceClaim with empty divergence_dimensions
 *   T9: evaluateDivergence idempotent — already-evaluated returns prior divergence_claim_id
 *   T10: evaluateDivergence no-twin-run returns { divergenceClaimId: null }
 */

const REAL_OP = 'op_real';
interface FakePassportRow {
  jti: string;
  operator_id: string;
  agent_id: string;
  expires_at: Date;
  intent_summary: string;
  intent_services: string[];
}
const REAL_PASSPORT: FakePassportRow = {
  jti: 'pas_real',
  operator_id: REAL_OP,
  agent_id: 'agt_real',
  expires_at: new Date(Date.now() + 600_000), // 10 min from now
  intent_summary: 'Process inbox',
  intent_services: ['slack', 'gmail'],
};

function makeRepoStub(initial?: TwinRunRow): {
  repo: TwinRunsRepository;
  rows: TwinRunRow[];
  pairs: Array<{ runId: string; realClaimId: string; twinClaimId: string; kind: 'intent' | 'outcome' }>;
  evaluatedMarks: Array<{ runId: string; divergenceClaimId: string }>;
} {
  const rows: TwinRunRow[] = initial ? [structuredClone(initial)] : [];
  const pairs: Array<{ runId: string; realClaimId: string; twinClaimId: string; kind: 'intent' | 'outcome' }> = [];
  const evaluatedMarks: Array<{ runId: string; divergenceClaimId: string }> = [];
  const repo = {
    async insert(input: {
      id: string; mission_id: string; real_passport_jti: string; twin_passport_jti: string;
    }) {
      rows.push({
        id: input.id,
        mission_id: input.mission_id,
        real_passport_jti: input.real_passport_jti,
        twin_passport_jti: input.twin_passport_jti,
        started_at: new Date(),
        evaluated_at: null,
        divergence_claim_id: null,
        status: 'running',
        claim_pairs: [],
      } as TwinRunRow);
    },
    async findByMissionId(missionId: string) {
      return rows.find((r) => r.mission_id === missionId) ?? null;
    },
    async findByRealPassportJti(jti: string) {
      return rows.find((r) => r.real_passport_jti === jti) ?? null;
    },
    async appendClaimPair(args: { twinRunId: string; realClaimId: string; twinClaimId: string; kind: 'intent' | 'outcome' }) {
      pairs.push({ runId: args.twinRunId, realClaimId: args.realClaimId, twinClaimId: args.twinClaimId, kind: args.kind });
      const row = rows.find((r) => r.id === args.twinRunId);
      if (row) {
        // Idempotent on (real_claim_id, kind) — mirror the SQL semantics
        const exists = row.claim_pairs.some(
          (p) => p.real_claim_id === args.realClaimId && p.kind === args.kind,
        );
        if (!exists) {
          row.claim_pairs.push({
            real_claim_id: args.realClaimId,
            twin_claim_id: args.twinClaimId,
            kind: args.kind,
          });
        }
      }
    },
    async markEvaluated(args: { twinRunId: string; divergenceClaimId: string }) {
      const row = rows.find((r) => r.id === args.twinRunId);
      if (!row || row.status !== 'running') return false;
      row.status = 'evaluated';
      row.divergence_claim_id = args.divergenceClaimId;
      row.evaluated_at = new Date();
      evaluatedMarks.push({ runId: args.twinRunId, divergenceClaimId: args.divergenceClaimId });
      return true;
    },
    async markFailed(twinRunId: string) {
      const row = rows.find((r) => r.id === twinRunId);
      if (!row || row.status !== 'running') return false;
      row.status = 'failed';
      row.evaluated_at = new Date();
      return true;
    },
  } as unknown as TwinRunsRepository;
  return { repo, rows, pairs, evaluatedMarks };
}

function makePassportServiceStub(opts?: { issueOverride?: (input: unknown) => unknown }): PassportService {
  return {
    async issue(_operatorId: string, input: unknown) {
      if (opts?.issueOverride) return opts.issueOverride(input) as never;
      return {
        token: 'token.fake',
        jti: 'pas_twin',
        expires_at: new Date(Date.now() + 600_000),
      } as never;
    },
  } as unknown as PassportService;
}

function makePassportRepoStub(passport: FakePassportRow | null = REAL_PASSPORT): PassportRepository {
  return {
    async findByJti(jti: string) {
      if (!passport) return null;
      return passport.jti === jti ? (passport as never) : null;
    },
  } as unknown as PassportRepository;
}

/**
 * passport_claims repo stub.. Returns the seeded
 * IntentOutcomeClaim bodies on findByClaimId (used by loadOutcomes)
 * + detector_signal lookup by intent_claim_ref (used by the
 * detector_signal_set dimension).
 */
function makePassportClaimsRepoStub(seed?: {
  outcomes?: Record<string, IntentOutcomeClaim>;
  detectorsByIntentRef?: Record<string, Array<{ detector_key: string }>>;
}): PassportClaimsRepository {
  const outcomes = seed?.outcomes ?? {};
  const detectors = seed?.detectorsByIntentRef ?? {};
  return {
    async findByClaimId(claimId: string) {
      const outcome = outcomes[claimId];
      if (!outcome) return null;
      return { claim_id: claimId, body_json: outcome } as never;
    },
    async findDetectorSignalsByIntentRefs(intentClaimIds: string[]) {
      const out: Array<{ claim_id: string; body_json: { detector_key: string; intent_claim_ref: string } }> = [];
      for (const id of intentClaimIds) {
        const fires = detectors[id] ?? [];
        for (const f of fires) {
          out.push({
            claim_id: `pc_det_${id}_${f.detector_key}`,
            body_json: { detector_key: f.detector_key, intent_claim_ref: id },
          });
        }
      }
      return out;
    },
  } as unknown as PassportClaimsRepository;
}

function makeClaimRegistryStub(opts?: { throwOnce?: boolean }): ClaimRegistryService & { calls: Array<{ claimType: string; passportJti?: string; operatorId: string }> } {
  const calls: Array<{ claimType: string; passportJti?: string; operatorId: string }> = [];
  let threw = false;
  return {
    calls,
    async registerClaim(input: { operatorId: string; passportJti?: string; claimType: string; payload: unknown }) {
      if (opts?.throwOnce && !threw) {
        threw = true;
        throw new Error('claim registry failure');
      }
      calls.push({ claimType: input.claimType, passportJti: input.passportJti, operatorId: input.operatorId });
      return {
        claimId: `pc_${input.claimType}_${calls.length}`,
        envelopeCose: 'fake',
        subject: 'stack://x',
      } as never;
    },
  } as unknown as ClaimRegistryService & { calls: typeof calls };
}

describe('TwinOrchestrationService.startTwinForMission', () => {
  it('T1 issues twin passport + inserts twin_runs row + returns jti', async () => {
    const { repo, rows } = makeRepoStub();
    const passportService = makePassportServiceStub();
    const passportRepo = makePassportRepoStub();
    const claimRegistry = makeClaimRegistryStub();
    const svc = new TwinOrchestrationService({
      repo, passportService, passportRepo, claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    const result = await svc.startTwinForMission({
      missionId: 'ms_x',
      realPassportJti: 'pas_real',
    });
    expect(result.twinPassportJti).toBe('pas_twin');
    expect(result.twinRunId).toMatch(/^twr_/);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.mission_id).toBe('ms_x');
    expect(rows[0]!.real_passport_jti).toBe('pas_real');
    expect(rows[0]!.twin_passport_jti).toBe('pas_twin');
  });

  it('T2 idempotent on mission_id — second call returns existing without re-issuing', async () => {
    const { repo } = makeRepoStub();
    let issuedCount = 0;
    const passportService = makePassportServiceStub({
      issueOverride: () => {
        issuedCount++;
        return { token: 't', jti: 'pas_twin', expires_at: new Date(Date.now() + 60_000) };
      },
    });
    const passportRepo = makePassportRepoStub();
    const claimRegistry = makeClaimRegistryStub();
    const svc = new TwinOrchestrationService({
      repo, passportService, passportRepo, claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    const first = await svc.startTwinForMission({
      missionId: 'ms_idempotent', realPassportJti: 'pas_real',
    });
    const second = await svc.startTwinForMission({
      missionId: 'ms_idempotent', realPassportJti: 'pas_real',
    });
    expect(second.twinPassportJti).toBe(first.twinPassportJti);
    expect(second.twinRunId).toBe(first.twinRunId);
    expect(issuedCount).toBe(1);
  });

  it('T3 twin passport intent carries [TWIN] prefix + mirrored services + ttl from remaining', async () => {
    const { repo } = makeRepoStub();
    let capturedInput: { intent?: { summary: string; services: string[] }; ttl_seconds?: number; mission_ids?: string[] } | null = null;
    const passportService = makePassportServiceStub({
      issueOverride: (input: unknown) => {
        capturedInput = input as typeof capturedInput;
        return { token: 't', jti: 'pas_twin', expires_at: new Date(Date.now() + 60_000) };
      },
    });
    const passportRepo = makePassportRepoStub();
    const claimRegistry = makeClaimRegistryStub();
    const svc = new TwinOrchestrationService({
      repo, passportService, passportRepo, claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    await svc.startTwinForMission({ missionId: 'ms_x', realPassportJti: 'pas_real' });

    expect(capturedInput!.intent!.summary).toBe('[TWIN] Process inbox');
    expect(capturedInput!.intent!.services).toEqual(['slack', 'gmail']);
    expect(capturedInput!.mission_ids).toEqual(['ms_x']);
    // TTL should be roughly the remaining time on REAL_PASSPORT (~10min)
    expect(capturedInput!.ttl_seconds).toBeGreaterThan(300);
    expect(capturedInput!.ttl_seconds).toBeLessThanOrEqual(600);
  });

  it('T4 throws when real passport not found', async () => {
    const { repo } = makeRepoStub();
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(null),
      claimRegistry: makeClaimRegistryStub(),
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    await expect(svc.startTwinForMission({
      missionId: 'ms_missing', realPassportJti: 'pas_does_not_exist',
    })).rejects.toThrow(/real passport.*not found/);
  });
});

const FAKE_INTENT_CLAIM: IntentClaim = {
  type: 'intent_claim',
  intent_type: 'http_call',
  agent_id: 'agt_real',
  named_intent: 'slack:read:channel',
  target: 'slack',
  action: 'read',
  parameters: {},
  estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
  accountability: 'logged',
  reason: null,
  requires: [],
  user_subject: null,
  mission_ref: 'ms_x',
  submitted_at: 0,
};

describe('TwinOrchestrationService.mirrorIntent', () => {
  it('T5 registers twin intent_claim under twin passport + appends to claim_pairs', async () => {
    const { repo, rows } = makeRepoStub({
      id: 'twr_existing',
      mission_id: 'ms_x',
      real_passport_jti: 'pas_real',
      twin_passport_jti: 'pas_twin',
      started_at: new Date(),
      evaluated_at: null,
      divergence_claim_id: null,
      status: 'running',
      claim_pairs: [],
    });
    const passportService = makePassportServiceStub();
    const passportRepo = makePassportRepoStub();
    const claimRegistry = makeClaimRegistryStub();
    const svc = new TwinOrchestrationService({
      repo, passportService, passportRepo, claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    const result = await svc.mirrorIntent({
      twinRunId: 'twr_existing',
      operatorId: REAL_OP,
      twinPassportJti: 'pas_twin',
      realIntentClaim: FAKE_INTENT_CLAIM,
      realClaimId: 'pc_real_intent_1',
    });
    expect(result?.twinClaimId).toMatch(/^pc_intent_claim_/);
    expect(claimRegistry.calls).toHaveLength(1);
    expect(claimRegistry.calls[0]!.claimType).toBe('intent_claim');
    expect(claimRegistry.calls[0]!.passportJti).toBe('pas_twin');
    expect(claimRegistry.calls[0]!.operatorId).toBe(REAL_OP);
    expect(rows[0]!.claim_pairs).toHaveLength(1);
    expect(rows[0]!.claim_pairs[0]).toMatchObject({
      real_claim_id: 'pc_real_intent_1',
      kind: 'intent',
    });
  });

  it('T6 returns null + logs on claimRegistry failure (best-effort)', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running', claim_pairs: [],
    });
    const claimRegistry = makeClaimRegistryStub({ throwOnce: true });
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    const result = await svc.mirrorIntent({
      twinRunId: 'twr_x',
      operatorId: REAL_OP,
      twinPassportJti: 'pas_twin',
      realIntentClaim: FAKE_INTENT_CLAIM,
      realClaimId: 'pc_real_intent_1',
    });
    expect(result).toBeNull();
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});

describe('TwinOrchestrationService.mirrorOutcome', () => {
  it('T7 appends to claim_pairs', async () => {
    const { repo, rows } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running', claim_pairs: [],
    });
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry: makeClaimRegistryStub(),
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    await svc.mirrorOutcome({
      twinRunId: 'twr_x',
      realOutcomeClaimId: 'pc_real_outcome_1',
      twinOutcomeClaimId: 'pc_twin_outcome_1',
    });
    expect(rows[0]!.claim_pairs).toHaveLength(1);
    expect(rows[0]!.claim_pairs[0]!.kind).toBe('outcome');
  });
});

describe('TwinOrchestrationService.evaluateDivergence', () => {
  it('T8 emits TwinDivergenceClaim with empty divergence_dimensions when outcome bodies are missing (5.3.5 hasn\'t lit up yet)', async () => {
    // baseline. 5.3.3 only populates intent pairs via the
    // mirrorIntent hook — outcome pairs depend on 5.3.5 (sealed-exec
    // twin runtime). Until 5.3.5 lands, evaluateDivergence runs
    // cleanly with zero outcome bodies → No divergence observed.
    const { repo, rows } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running',
      claim_pairs: [
        { real_claim_id: 'pc_real_o1', twin_claim_id: 'pc_twin_o1', kind: 'outcome' },
        { real_claim_id: 'pc_real_o2', twin_claim_id: 'pc_twin_o2', kind: 'outcome' },
      ],
    });
    const claimRegistry = makeClaimRegistryStub();
    let capturedPayload: { divergence_dimensions?: unknown[]; diff_summary?: string; real_intent_outcomes?: string[]; twin_intent_outcomes?: string[] } | null = null;
    (claimRegistry as unknown as { registerClaim: typeof claimRegistry.registerClaim }).registerClaim = (async (input: { claimType: string; payload: unknown; passportJti?: string; operatorId: string }) => {
      capturedPayload = input.payload as typeof capturedPayload;
      claimRegistry.calls.push({ claimType: input.claimType, passportJti: input.passportJti, operatorId: input.operatorId });
      return { claimId: 'pc_divergence_1', envelopeCose: 'fake', subject: 'stack://x' } as never;
    }) as never;

    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(), // no outcomes seeded
    });
    const result = await svc.evaluateDivergence({ missionId: 'ms_x', operatorId: REAL_OP });

    expect(result.divergenceClaimId).toBe('pc_divergence_1');
    expect(capturedPayload!.divergence_dimensions).toEqual([]);
    expect(capturedPayload!.diff_summary).toBe('No divergence observed.');
    expect(capturedPayload!.real_intent_outcomes).toEqual(['pc_real_o1', 'pc_real_o2']);
    expect(capturedPayload!.twin_intent_outcomes).toEqual(['pc_twin_o1', 'pc_twin_o2']);
    expect(rows[0]!.status).toBe('evaluated');
    expect(rows[0]!.divergence_claim_id).toBe('pc_divergence_1');
  });

  it('T9 idempotent — already-evaluated returns prior divergence_claim_id', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: new Date(), divergence_claim_id: 'pc_prior_div',
      status: 'evaluated', claim_pairs: [],
    });
    const claimRegistry = makeClaimRegistryStub();
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    const result = await svc.evaluateDivergence({ missionId: 'ms_x', operatorId: REAL_OP });
    expect(result.divergenceClaimId).toBe('pc_prior_div');
    // No new claim emitted
    expect(claimRegistry.calls).toHaveLength(0);
  });

  it('T10 no-twin-run returns { divergenceClaimId: null } cleanly', async () => {
    const { repo } = makeRepoStub(); // empty
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry: makeClaimRegistryStub(),
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    const result = await svc.evaluateDivergence({ missionId: 'ms_never_opened', operatorId: REAL_OP });
    expect(result.divergenceClaimId).toBeNull();
  });

  it('T11 failed status returns { divergenceClaimId: null } without re-emitting', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: new Date(), divergence_claim_id: null,
      status: 'failed', claim_pairs: [],
    });
    const claimRegistry = makeClaimRegistryStub();
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(),
    });
    const result = await svc.evaluateDivergence({ missionId: 'ms_x', operatorId: REAL_OP });
    expect(result.divergenceClaimId).toBeNull();
    expect(claimRegistry.calls).toHaveLength(0);
  });

  // ─── math-substrate integration ─────────────────────

  /**
   * Seed helper: build a minimal IntentOutcomeClaim of type http_call
   * with the given hash + target + cost. Mirrors the fixture pattern
   * used in twin-divergence-math.test.ts but inline here since the
   * orchestration service test isn't supposed to depend on the
   * math-test fixtures.
   */
  function makeHttpOutcome(opts: {
    hash: string;
    target: string;
    cents?: number;
  }): IntentOutcomeClaim {
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
      actual_parameters_hash: 'a'.repeat(64),
      status_code: 200,
      response_body_hash: opts.hash,
      latency_ms: 50,
      redactions_count: 0,
      detector_fires_count: 0,
    } as IntentOutcomeClaim;
  }

  it('T12 outcome bodies present with hash mismatch → output_shape entry surfaces', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running',
      claim_pairs: [
        { real_claim_id: 'pc_real_o1', twin_claim_id: 'pc_twin_o1', kind: 'outcome' },
      ],
    });
    const claimRegistry = makeClaimRegistryStub();
    let capturedPayload: { divergence_dimensions?: Array<{ dimension: string; severity: string }>; diff_summary?: string } | null = null;
    (claimRegistry as unknown as { registerClaim: typeof claimRegistry.registerClaim }).registerClaim = (async (input: { claimType: string; payload: unknown; passportJti?: string; operatorId: string }) => {
      capturedPayload = input.payload as typeof capturedPayload;
      claimRegistry.calls.push({ claimType: input.claimType, passportJti: input.passportJti, operatorId: input.operatorId });
      return { claimId: 'pc_divergence_1', envelopeCose: 'fake', subject: 'stack://x' } as never;
    }) as never;

    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub({
        outcomes: {
          pc_real_o1: makeHttpOutcome({ hash: 'a'.repeat(64), target: 'api.foo.com' }),
          pc_twin_o1: makeHttpOutcome({ hash: 'b'.repeat(64), target: 'api.foo.com' }),
        },
      }),
    });
    const result = await svc.evaluateDivergence({ missionId: 'ms_x', operatorId: REAL_OP });
    expect(result.divergenceClaimId).toBe('pc_divergence_1');
    const dims = capturedPayload!.divergence_dimensions!;
    expect(dims.length).toBeGreaterThanOrEqual(1);
    const shape = dims.find((d) => d.dimension === 'output_shape');
    expect(shape).toBeDefined();
    expect(shape!.severity).toBe('critical'); // 100% mismatch on 1/1
    expect(capturedPayload!.diff_summary).toMatch(/output_shape=critical/);
  });

  it('T13 detector_signal_set divergence surfaces via intent_claim_ref lookup', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running',
      claim_pairs: [
        { real_claim_id: 'pc_real_i1', twin_claim_id: 'pc_twin_i1', kind: 'intent' },
      ],
    });
    const claimRegistry = makeClaimRegistryStub();
    let capturedPayload: { divergence_dimensions?: Array<{ dimension: string; severity: string; diff: Record<string, unknown> }> } | null = null;
    (claimRegistry as unknown as { registerClaim: typeof claimRegistry.registerClaim }).registerClaim = (async (input: { claimType: string; payload: unknown; passportJti?: string; operatorId: string }) => {
      capturedPayload = input.payload as typeof capturedPayload;
      claimRegistry.calls.push({ claimType: input.claimType, passportJti: input.passportJti, operatorId: input.operatorId });
      return { claimId: 'pc_divergence_2', envelopeCose: 'fake', subject: 'stack://x' } as never;
    }) as never;

    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub({
        detectorsByIntentRef: {
          pc_real_i1: [{ detector_key: 'prompt_injection_output' }],
          pc_twin_i1: [{ detector_key: 'high_value_action' }],
        },
      }),
      // this fixture is intent-only (no outcome pairs), so
      // the 5.3.7 settling wait would block until timeout otherwise.
      // The test exercises detector-signal lookup, not the wait.
      twinSettleTimeoutMs: 0,
    });
    await svc.evaluateDivergence({ missionId: 'ms_x', operatorId: REAL_OP });
    const dims = capturedPayload!.divergence_dimensions!;
    const det = dims.find((d) => d.dimension === 'detector_signal_set');
    expect(det).toBeDefined();
    expect(det!.severity).toBe('medium');
    expect((det!.diff as { real_only_keys: string[] }).real_only_keys).toEqual(['prompt_injection_output']);
    expect((det!.diff as { twin_only_keys: string[] }).twin_only_keys).toEqual(['high_value_action']);
  });

  // ─── resolveTwinInvocationContext ───────────────

  function makeAgentRepoStub(twin_llm_model: string | null = null) {
    return {
      async findById(id: string) {
        return { id, twin_llm_model };
      },
    };
  }

  it('T15 resolveTwinInvocationContext returns null when no twin run for mission', async () => {
    const { repo } = makeRepoStub(); // empty
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry: makeClaimRegistryStub(),
      passportClaimsRepo: makePassportClaimsRepoStub(),
      agentRepo: makeAgentRepoStub('openai/gpt-5') as never,
    });
    const ctx = await svc.resolveTwinInvocationContext({
      realPassportJti: 'pas_real',
      missionId: 'ms_does_not_exist',
    });
    expect(ctx).toBeNull();
  });

  it('T16 resolveTwinInvocationContext returns null when realPassportJti IS the twin passport (anti-recursion)', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running', claim_pairs: [],
    });
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry: makeClaimRegistryStub(),
      passportClaimsRepo: makePassportClaimsRepoStub(),
      agentRepo: makeAgentRepoStub('openai/gpt-5') as never,
    });
    const ctx = await svc.resolveTwinInvocationContext({
      realPassportJti: 'pas_twin', // passing twin's jti as real → anti-recursion fires
      missionId: 'ms_x',
    });
    expect(ctx).toBeNull();
  });

  it('T17 resolveTwinInvocationContext returns context when twin run active + agent has twin_llm_model', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running',
      claim_pairs: [
        { real_claim_id: 'pc_real_i1', twin_claim_id: 'pc_twin_i1', kind: 'intent' },
        { real_claim_id: 'pc_real_i2', twin_claim_id: 'pc_twin_i2', kind: 'intent' },
      ],
    });
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry: makeClaimRegistryStub(),
      passportClaimsRepo: makePassportClaimsRepoStub(),
      agentRepo: makeAgentRepoStub('openai/gpt-5') as never,
    });
    const ctx = await svc.resolveTwinInvocationContext({
      realPassportJti: 'pas_real',
      missionId: 'ms_x',
    });
    expect(ctx).not.toBeNull();
    expect(ctx!.twinPassportJti).toBe('pas_twin');
    expect(ctx!.twinLlmModel).toBe('openai/gpt-5');
    expect(ctx!.twinRunId).toBe('twr_x');
    expect(ctx!.agentId).toBe('agt_real');
    expect(ctx!.realIntentClaimToTwinIntentClaim.get('pc_real_i1')).toBe('pc_twin_i1');
    expect(ctx!.realIntentClaimToTwinIntentClaim.get('pc_real_i2')).toBe('pc_twin_i2');
  });

  it('T18 resolveTwinInvocationContext returns null when missionId is null (no twin without mission)', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running', claim_pairs: [],
    });
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry: makeClaimRegistryStub(),
      passportClaimsRepo: makePassportClaimsRepoStub(),
      agentRepo: makeAgentRepoStub(null) as never,
    });
    const ctx = await svc.resolveTwinInvocationContext({
      realPassportJti: 'pas_real',
      missionId: null,
    });
    expect(ctx).toBeNull();
  });

  it('T18b resolveTwinInvocationContext returns null twinLlmModel when agent has none configured (back-compat path)', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running', claim_pairs: [],
    });
    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry: makeClaimRegistryStub(),
      passportClaimsRepo: makePassportClaimsRepoStub(),
      agentRepo: makeAgentRepoStub(null) as never, // explicit null
    });
    const ctx = await svc.resolveTwinInvocationContext({
      realPassportJti: 'pas_real',
      missionId: 'ms_x',
    });
    expect(ctx).not.toBeNull();
    expect(ctx!.twinLlmModel).toBeNull();
  });

  // ─── cost dimension (continues) ─────────────────

  it('T14 cost dimension surfaces from summed wallet_cents across outcomes', async () => {
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running',
      claim_pairs: [
        { real_claim_id: 'pc_real_o1', twin_claim_id: 'pc_twin_o1', kind: 'outcome' },
      ],
    });
    const claimRegistry = makeClaimRegistryStub();
    let capturedPayload: { divergence_dimensions?: Array<{ dimension: string; severity: string; diff: Record<string, unknown> }> } | null = null;
    (claimRegistry as unknown as { registerClaim: typeof claimRegistry.registerClaim }).registerClaim = (async (input: { claimType: string; payload: unknown; passportJti?: string; operatorId: string }) => {
      capturedPayload = input.payload as typeof capturedPayload;
      claimRegistry.calls.push({ claimType: input.claimType, passportJti: input.passportJti, operatorId: input.operatorId });
      return { claimId: 'pc_divergence_3', envelopeCose: 'fake', subject: 'stack://x' } as never;
    }) as never;

    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub({
        outcomes: {
          // identical body hash + target → no output_shape / counterparty
          // entry; only cost dimension surfaces (10x ratio → critical).
          pc_real_o1: makeHttpOutcome({ hash: 'a'.repeat(64), target: 'api.foo.com', cents: 10 }),
          pc_twin_o1: makeHttpOutcome({ hash: 'a'.repeat(64), target: 'api.foo.com', cents: 100 }),
        },
      }),
    });
    await svc.evaluateDivergence({ missionId: 'ms_x', operatorId: REAL_OP });
    const dims = capturedPayload!.divergence_dimensions!;
    const cost = dims.find((d) => d.dimension === 'cost');
    expect(cost).toBeDefined();
    expect(cost!.severity).toBe('critical'); // ratio 10 > 5
    expect((cost!.diff as { real_total_cents: number; twin_total_cents: number; ratio: number }).ratio).toBe(10);
    expect(dims.find((d) => d.dimension === 'output_shape')).toBeUndefined();
    expect(dims.find((d) => d.dimension === 'counterparty')).toBeUndefined();
  });

  // ─── late-outcome settling window ──────────────────

  it('T_late_twin late mirrorOutcome lands during settling window → divergence claim includes the late pair', async () => {
    // Race shape: twin invocations are fire-and-forget from the skills
    // route. MissionService.complete fires evaluateDivergence
    // fire-and-forget. If evaluateDivergence reads claim_pairs before
    // the late mirrorOutcome lands, the outcome pair is invisible to
    // the divergence math AND the markEvaluated CAS locks the row, so
    // even when the late twin lands, no re-evaluation happens.
    //
    // 5.3.7 fix: waitForOutcomePairSettlement polls claim_pairs until
    // intent count == outcome count, or timeout. This test seeds an
    // intent pair with no matching outcome, then schedules a late
    // appendClaimPair via setTimeout, and asserts the divergence claim
    // sees the late outcome pair.
    const { repo, rows } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running',
      claim_pairs: [
        // 1 intent pair, 0 outcome pairs at evaluation start.
        { real_claim_id: 'pc_real_i1', twin_claim_id: 'pc_twin_i1', kind: 'intent' },
      ],
    });
    const claimRegistry = makeClaimRegistryStub();
    let capturedPayload: { real_intent_outcomes?: string[]; twin_intent_outcomes?: string[] } | null = null;
    (claimRegistry as unknown as { registerClaim: typeof claimRegistry.registerClaim }).registerClaim = (async (input: { claimType: string; payload: unknown; passportJti?: string; operatorId: string }) => {
      capturedPayload = input.payload as typeof capturedPayload;
      claimRegistry.calls.push({ claimType: input.claimType, passportJti: input.passportJti, operatorId: input.operatorId });
      return { claimId: 'pc_divergence_late', envelopeCose: 'fake', subject: 'stack://x' } as never;
    }) as never;

    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub({
        outcomes: {
          pc_real_o1: makeHttpOutcome({ hash: 'a'.repeat(64), target: 'api.foo.com' }),
          pc_twin_o1: makeHttpOutcome({ hash: 'a'.repeat(64), target: 'api.foo.com' }),
        },
      }),
      // Tight test polling: 500ms total budget, 20ms poll.
      twinSettleTimeoutMs: 500,
      twinSettlePollMs: 20,
    });

    // Schedule the late mirrorOutcome to land ~50ms into the poll.
    // evaluateDivergence will see intent>outcome on iteration 1, sleep
    // 20ms, see the same gap on iteration 2, sleep 20ms, then by
    // iteration 3 the late pair is in and the wait exits.
    setTimeout(() => {
      rows[0]!.claim_pairs.push({
        real_claim_id: 'pc_real_o1',
        twin_claim_id: 'pc_twin_o1',
        kind: 'outcome',
      });
    }, 50);

    const result = await svc.evaluateDivergence({ missionId: 'ms_x', operatorId: REAL_OP });

    expect(result.divergenceClaimId).toBe('pc_divergence_late');
    expect(capturedPayload!.real_intent_outcomes).toEqual(['pc_real_o1']);
    expect(capturedPayload!.twin_intent_outcomes).toEqual(['pc_twin_o1']);
  });

  it('T_late_twin_timeout settling wait expires → falls back to best-effort partial eval (v1 parity)', async () => {
    // If the late mirrorOutcome never lands, settling times out and
    // evaluation proceeds with whatever's persisted. Identical fallback
    // behaviour to v1, just bounded by timeout instead of zero wait.
    // Ensures a stuck twin never blocks the divergence claim entirely.
    const { repo } = makeRepoStub({
      id: 'twr_x', mission_id: 'ms_x', real_passport_jti: 'pas_real', twin_passport_jti: 'pas_twin',
      started_at: new Date(), evaluated_at: null, divergence_claim_id: null,
      status: 'running',
      claim_pairs: [
        { real_claim_id: 'pc_real_i1', twin_claim_id: 'pc_twin_i1', kind: 'intent' },
      ],
    });
    const claimRegistry = makeClaimRegistryStub();
    let capturedPayload: { real_intent_outcomes?: string[]; twin_intent_outcomes?: string[] } | null = null;
    (claimRegistry as unknown as { registerClaim: typeof claimRegistry.registerClaim }).registerClaim = (async (input: { claimType: string; payload: unknown; passportJti?: string; operatorId: string }) => {
      capturedPayload = input.payload as typeof capturedPayload;
      claimRegistry.calls.push({ claimType: input.claimType, passportJti: input.passportJti, operatorId: input.operatorId });
      return { claimId: 'pc_divergence_timeout', envelopeCose: 'fake', subject: 'stack://x' } as never;
    }) as never;

    const svc = new TwinOrchestrationService({
      repo,
      passportService: makePassportServiceStub(),
      passportRepo: makePassportRepoStub(),
      claimRegistry,
      passportClaimsRepo: makePassportClaimsRepoStub(),
      // 100ms timeout, no late outcome ever lands.
      twinSettleTimeoutMs: 100,
      twinSettlePollMs: 20,
    });

    const start = Date.now();
    const result = await svc.evaluateDivergence({ missionId: 'ms_x', operatorId: REAL_OP });
    const elapsed = Date.now() - start;

    // Divergence claim still emits even with no outcome pairs (v1 parity).
    expect(result.divergenceClaimId).toBe('pc_divergence_timeout');
    expect(capturedPayload!.real_intent_outcomes).toEqual([]);
    expect(capturedPayload!.twin_intent_outcomes).toEqual([]);
    // Bounded wait — should NOT exceed timeout meaningfully.
    expect(elapsed).toBeLessThan(500);
    expect(elapsed).toBeGreaterThanOrEqual(100);
  });
});
