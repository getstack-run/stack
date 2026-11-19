import { describe, it, expect } from 'vitest';
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  SchemaValidationError,
  type DossierClaim,
  type IncidentClassification,
} from '@stack/shared';
import {
  DossierService,
  type DossierServiceDeps,
  type DossierMissionLookup,
  type CreateDossierInput,
} from './dossier-service.js';
import type { ClaimRegistryService, RegisterClaimInput, RegisterClaimResult } from './claim-registry-service.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';

/**
 * DossierService invariants.
 *
 *   C1: create on terminal-completed mission → success, claim_id returned
 *   C2: create on terminal-revoked mission → success
 *   C3: create on missing mission → NotFoundError
 *   C4: create on still-active mission → ConflictError
 *   C5: create on tier-gated operator → ForbiddenError propagated from claimRegistry
 *   C6: create normalises optional arrays (decision_tree + alerts_walkthrough default to [])
 *   C7: create persists with subjectOverride='operator' (operator-scoped envelope)
 *   C8: create stamps authored_at_ms at registration time
 *
 *   F1: findByMission returns rows mapped to DossierEnvelope ordered as repo returns
 *   F2: findByMission returns empty array when repo is empty
 *   F3: findByMission passes (claimType, missionId, operatorId) verbatim to repo
 *
 *   U1: update merges input into prior body; omitted fields carry forward
 *   U2: update sets prior_dossier_ref = priorClaimId
 *   U3: update on missing claim_id → NotFoundError
 *   U4: update on wrong type (non-dossier claim_id) → NotFoundError
 *   U5: update on malformed body_json → SchemaValidationError
 *   U6: update derives operatorId from the prior claim (NOT from the caller)
 *   U7: update stamps fresh authored_at_ms + authored_by_member_id
 */

type PassportClaimRow = {
  claim_id: string;
  operator_id: string;
  passport_id: string | null;
  type: string;
  body_json: unknown;
  issued_at_ms: number | null;
  revoked_at: Date | null;
};

let claimSeq = 0;

function makeStubMissionRepo(
  rows: Map<string, { mission_id: string; operator_id: string; completed_at: Date | null; revoked_at: Date | null }>,
): DossierMissionLookup {
  return {
    findById: async (id) => rows.get(id) ?? null,
  };
}

function makeStubClaimRegistry(): {
  service: ClaimRegistryService;
  calls: RegisterClaimInput[];
  fail: { value: Error | null };
} {
  const calls: RegisterClaimInput[] = [];
  const fail = { value: null as Error | null };
  const service = {
    async registerClaim(input: RegisterClaimInput): Promise<RegisterClaimResult> {
      calls.push(input);
      if (fail.value) throw fail.value;
      const id = `pc_dossier_${++claimSeq}`;
      return {
        claimId: id,
        envelopeCose: 'fake_cose_bytes',
      } as unknown as RegisterClaimResult;
    },
  } as unknown as ClaimRegistryService;
  return { service, calls, fail };
}

function makeStubClaimsRepo(rows: Map<string, PassportClaimRow>): {
  repo: PassportClaimsRepository;
  findCalls: Array<{ claimType: string; missionRef: string; operatorId: string }>;
  sourceRows: PassportClaimRow[];
} {
  const findCalls: Array<{ claimType: string; missionRef: string; operatorId: string }> = [];
  const sourceRows: PassportClaimRow[] = [];
  const repo = {
    findByClaimId: async (id: string) => rows.get(id) ?? null,
    findActiveByTypeAndMissionRef: async (claimType: string, missionRef: string, operatorId: string) => {
      findCalls.push({ claimType, missionRef, operatorId });
      return Array.from(rows.values()).filter(
        (r) =>
          r.type === claimType &&
          r.operator_id === operatorId &&
          r.revoked_at === null &&
          (r.body_json as { mission_ref?: string })?.mission_ref === missionRef,
      );
    },
    findDossierSourceClaims: async (
      operatorId: string,
      missionId: string,
      checkpointIds: string[],
      detectorSignalClaimIds: string[],
    ) => sourceRows.filter((row) => {
      if (row.operator_id !== operatorId) return false;
      const body = row.body_json as { mission_ref?: string; checkpoint_id?: string };
      if (body.mission_ref !== missionId) return false;
      return (
        (row.type === 'checkpoint_approval' && checkpointIds.includes(body.checkpoint_id ?? '')) ||
        (row.type === 'detector_signal' && detectorSignalClaimIds.includes(row.claim_id))
      );
    }),
  } as unknown as PassportClaimsRepository;
  return { repo, findCalls, sourceRows };
}

function makeService(): {
  service: DossierService;
  missionRows: Map<string, { mission_id: string; operator_id: string; completed_at: Date | null; revoked_at: Date | null }>;
  claimRows: Map<string, PassportClaimRow>;
  registry: ReturnType<typeof makeStubClaimRegistry>;
  claimsRepo: ReturnType<typeof makeStubClaimsRepo>;
  memberRows: Map<string, { id: string; operator_id: string; status: string }>;
} {
  const missionRows = new Map<string, { mission_id: string; operator_id: string; completed_at: Date | null; revoked_at: Date | null }>();
  const claimRows = new Map<string, PassportClaimRow>();
  const registry = makeStubClaimRegistry();
  const claimsRepo = makeStubClaimsRepo(claimRows);
  claimsRepo.sourceRows.push({
    claim_id: 'pc_checkpoint_one',
    operator_id: 'op_abc',
    passport_id: 'pas_source',
    type: 'checkpoint_approval',
    body_json: { type: 'checkpoint_approval', checkpoint_id: 'chk_one', mission_ref: 'ms_done' },
    issued_at_ms: 900,
    revoked_at: null,
  });
  claimsRepo.sourceRows.push({
    claim_id: 'pc_checkpoint_one_revoked_mission',
    operator_id: 'op_abc',
    passport_id: 'pas_source',
    type: 'checkpoint_approval',
    body_json: { type: 'checkpoint_approval', checkpoint_id: 'chk_one', mission_ref: 'ms_revoked' },
    issued_at_ms: 900,
    revoked_at: null,
  });
  const memberRows = new Map<string, { id: string; operator_id: string; status: string }>();
  const deps: DossierServiceDeps = {
    claimRegistry: registry.service,
    missionRepo: makeStubMissionRepo(missionRows),
    passportClaimsRepo: claimsRepo.repo,
    memberRepo: {
      findById: async (id: string) =>
        memberRows.get(id) ?? (id.startsWith('mem_') && !id.startsWith('mem_op_')
          ? { id, operator_id: 'op_abc', status: 'active' }
          : null),
    },
  } as DossierServiceDeps;
  return { service: new DossierService(deps), missionRows, claimRows, registry, claimsRepo, memberRows };
}

const VALID_INPUT: CreateDossierInput = {
  narrative: 'Mission ran without incident.',
  decision_tree: [{ checkpoint_id: 'chk_one', decision: 'auto-approved', rationale: 'within scope' }],
  alerts_walkthrough: [],
  lessons_learned: 'None.',
  incident_classification: 'false_positive' as IncidentClassification,
};

describe('DossierService — create', () => {
  it('C1 success on terminal-completed mission', async () => {
    const { service, missionRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    const result = await service.create('ms_done', VALID_INPUT, 'mem_alice');
    expect(result.claim_id).toMatch(/^pc_dossier_/);
    expect(result.claim.mission_ref).toBe('ms_done');
    expect(result.claim.authored_by_member_id).toBe('mem_alice');
    expect(registry.calls).toHaveLength(1);
    expect(registry.calls[0]!.operatorId).toBe('op_abc');
    expect(registry.calls[0]!.claimType).toBe('dossier');
  });

  it('C2 success on terminal-revoked mission', async () => {
    const { service, missionRows } = makeService();
    missionRows.set('ms_revoked', {
      mission_id: 'ms_revoked',
      operator_id: 'op_abc',
      completed_at: null,
      revoked_at: new Date(),
    });
    const result = await service.create('ms_revoked', VALID_INPUT, 'mem_bob');
    expect(result.claim_id).toMatch(/^pc_dossier_/);
  });

  it('C3 NotFoundError on missing mission', async () => {
    const { service } = makeService();
    await expect(service.create('ms_missing', VALID_INPUT, 'mem_alice')).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('C4 ConflictError on still-active mission', async () => {
    const { service, missionRows } = makeService();
    missionRows.set('ms_active', {
      mission_id: 'ms_active',
      operator_id: 'op_abc',
      completed_at: null,
      revoked_at: null,
    });
    await expect(service.create('ms_active', VALID_INPUT, 'mem_alice')).rejects.toBeInstanceOf(
      ConflictError,
    );
  });

  it('C5 propagates ForbiddenError from tier gate at claimRegistry', async () => {
    const { service, missionRows, registry, memberRows } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_free_tier',
      completed_at: new Date(),
      revoked_at: null,
    });
    memberRows.set('mem_alice', {
      id: 'mem_alice',
      operator_id: 'op_free_tier',
      status: 'active',
    });
    registry.fail.value = new ForbiddenError("claim type 'dossier' is not permitted for tier 'free'");
    await expect(service.create('ms_done', {
      ...VALID_INPUT,
      decision_tree: [],
    }, 'mem_alice')).rejects.toBeInstanceOf(
      ForbiddenError,
    );
    expect(registry.calls).toHaveLength(1);
  });

  it('C6 omitted decision_tree + alerts_walkthrough default to []', async () => {
    const { service, missionRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    const minimalInput: CreateDossierInput = {
      narrative: 'short',
      lessons_learned: '',
      incident_classification: 'inconclusive',
    };
    await service.create('ms_done', minimalInput, 'mem_alice');
    const payload = registry.calls[0]!.payload as DossierClaim;
    expect(payload.decision_tree).toEqual([]);
    expect(payload.alerts_walkthrough).toEqual([]);
  });

  it('C7 uses subjectOverride=operator (operator-scoped envelope)', async () => {
    const { service, missionRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    await service.create('ms_done', VALID_INPUT, 'mem_alice');
    expect(registry.calls[0]!.subjectOverride).toBe('operator');
  });

  it('C8 stamps authored_at_ms at registration time', async () => {
    const { service, missionRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    const before = Date.now();
    await service.create('ms_done', VALID_INPUT, 'mem_alice');
    const after = Date.now();
    const payload = registry.calls[0]!.payload as DossierClaim;
    expect(payload.authored_at_ms).toBeGreaterThanOrEqual(before);
    expect(payload.authored_at_ms).toBeLessThanOrEqual(after);
  });

  it('C9 rejects a synthetic member id that has no active member row', async () => {
    const { service, missionRows } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });

    await expect(
      service.create('ms_done', VALID_INPUT, 'mem_op_op_abc'),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('C10 rejects a member from a different operator', async () => {
    const { service, missionRows, memberRows } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    memberRows.set('mem_foreign', {
      id: 'mem_foreign',
      operator_id: 'op_other',
      status: 'active',
    });

    await expect(
      service.create('ms_done', VALID_INPUT, 'mem_foreign'),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('C11 rejects a checkpoint that is not signed under the mission and operator', async () => {
    const { service, missionRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });

    await expect(service.create('ms_done', {
      ...VALID_INPUT,
      decision_tree: [{ checkpoint_id: 'chk_fabricated', decision: 'approved', rationale: '' }],
    }, 'mem_alice')).rejects.toBeInstanceOf(ForbiddenError);
    expect(registry.calls).toHaveLength(0);
  });

  it('C12 rejects a detector claim from another mission', async () => {
    const { service, missionRows, claimsRepo, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    claimsRepo.sourceRows.push({
      claim_id: 'pc_detector_other_mission',
      operator_id: 'op_abc',
      passport_id: 'pas_source',
      type: 'detector_signal',
      body_json: { type: 'detector_signal', mission_ref: 'ms_other' },
      issued_at_ms: 1_000,
      revoked_at: null,
    });

    await expect(service.create('ms_done', {
      ...VALID_INPUT,
      alerts_walkthrough: [{
        detector_signal_claim_id: 'pc_detector_other_mission',
        severity: 'high',
        narrative: 'Reviewed.',
      }],
    }, 'mem_alice')).rejects.toBeInstanceOf(ForbiddenError);
    expect(registry.calls).toHaveLength(0);
  });

  it('C13 rejects a detector claim from another operator', async () => {
    const { service, missionRows, claimsRepo, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    claimsRepo.sourceRows.push({
      claim_id: 'pc_detector_foreign',
      operator_id: 'op_other',
      passport_id: 'pas_foreign',
      type: 'detector_signal',
      body_json: { type: 'detector_signal', mission_ref: 'ms_done', severity: 'medium' },
      issued_at_ms: 1_000,
      revoked_at: null,
    });

    await expect(service.create('ms_done', {
      ...VALID_INPUT,
      alerts_walkthrough: [{
        detector_signal_claim_id: 'pc_detector_foreign',
        severity: 'critical',
        narrative: 'Reviewed.',
      }],
    }, 'mem_alice')).rejects.toBeInstanceOf(ForbiddenError);
    expect(registry.calls).toHaveLength(0);
  });

  it('C14 accepts checkpoint and detector sources from the same mission and operator', async () => {
    const { service, missionRows, claimsRepo, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    claimsRepo.sourceRows.push({
      claim_id: 'pc_detector_same_scope',
      operator_id: 'op_abc',
      passport_id: 'pas_source',
      type: 'detector_signal',
      body_json: { type: 'detector_signal', mission_ref: 'ms_done', severity: 'medium' },
      issued_at_ms: 1_000,
      revoked_at: null,
    });

    await service.create('ms_done', {
      ...VALID_INPUT,
      alerts_walkthrough: [{
        detector_signal_claim_id: 'pc_detector_same_scope',
        severity: 'medium',
        narrative: 'Reviewed.',
      }],
    }, 'mem_alice');
    expect(registry.calls).toHaveLength(1);
  });

  it('C15 rejects a detector severity that differs from the signed source', async () => {
    const { service, missionRows, claimsRepo, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done',
      operator_id: 'op_abc',
      completed_at: new Date(),
      revoked_at: null,
    });
    claimsRepo.sourceRows.push({
      claim_id: 'pc_detector_severity',
      operator_id: 'op_abc',
      passport_id: 'pas_source',
      type: 'detector_signal',
      body_json: { type: 'detector_signal', mission_ref: 'ms_done', severity: 'critical' },
      issued_at_ms: 1_000,
      revoked_at: null,
    });

    await expect(service.create('ms_done', {
      ...VALID_INPUT,
      alerts_walkthrough: [{
        detector_signal_claim_id: 'pc_detector_severity',
        severity: 'low',
        narrative: 'Reviewed.',
      }],
    }, 'mem_alice')).rejects.toBeInstanceOf(ForbiddenError);
    expect(registry.calls).toHaveLength(0);
  });
});

describe('DossierService — findByMission', () => {
  it('F1 returns rows mapped to DossierEnvelope', async () => {
    const { service, claimRows } = makeService();
    claimRows.set('pc_d1', {
      claim_id: 'pc_d1',
      operator_id: 'op_abc',
      passport_id: null,
      type: 'dossier',
      body_json: { type: 'dossier', mission_ref: 'ms_done', narrative: 'first' } as Partial<DossierClaim>,
      issued_at_ms: 1000,
      revoked_at: null,
    });
    claimRows.set('pc_d2', {
      claim_id: 'pc_d2',
      operator_id: 'op_abc',
      passport_id: null,
      type: 'dossier',
      body_json: { type: 'dossier', mission_ref: 'ms_done', narrative: 'second' } as Partial<DossierClaim>,
      issued_at_ms: 2000,
      revoked_at: null,
    });
    const envelopes = await service.findByMission('ms_done', 'op_abc');
    expect(envelopes).toHaveLength(2);
    expect(envelopes.map((e) => e.claim_id).sort()).toEqual(['pc_d1', 'pc_d2']);
    expect(envelopes[0]!.body.mission_ref).toBe('ms_done');
  });

  it('F2 returns empty array when no dossier exists', async () => {
    const { service } = makeService();
    const envelopes = await service.findByMission('ms_lonely', 'op_abc');
    expect(envelopes).toEqual([]);
  });

  it('F3 passes claimType + missionRef + operatorId to repo', async () => {
    const { service, claimsRepo } = makeService();
    await service.findByMission('ms_x', 'op_y');
    expect(claimsRepo.findCalls).toEqual([{ claimType: 'dossier', missionRef: 'ms_x', operatorId: 'op_y' }]);
  });

  it('F4 ignores rows from a different mission (mission_ref mismatch)', async () => {
    const { service, claimRows } = makeService();
    claimRows.set('pc_other', {
      claim_id: 'pc_other',
      operator_id: 'op_abc',
      passport_id: null,
      type: 'dossier',
      body_json: { type: 'dossier', mission_ref: 'ms_other', narrative: 'unrelated' } as Partial<DossierClaim>,
      issued_at_ms: 1000,
      revoked_at: null,
    });
    const envelopes = await service.findByMission('ms_target', 'op_abc');
    expect(envelopes).toEqual([]);
  });
});

describe('DossierService — update', () => {
  function seedPriorClaim(claimRows: Map<string, PassportClaimRow>): void {
    claimRows.set('pc_dossier_prior', {
      claim_id: 'pc_dossier_prior',
      operator_id: 'op_abc',
      passport_id: null,
      type: 'dossier',
      body_json: {
        type: 'dossier',
        mission_ref: 'ms_done',
        authored_by_member_id: 'mem_alice',
        authored_at_ms: 1000,
        narrative: 'original narrative',
        decision_tree: [{ checkpoint_id: 'chk_one', decision: 'old', rationale: 'r1' }],
        alerts_walkthrough: [],
        lessons_learned: 'original lessons',
        incident_classification: 'inconclusive',
        prior_dossier_ref: null,
      } satisfies DossierClaim,
      issued_at_ms: 1000,
      revoked_at: null,
    });
  }

  it('U1 merges input over prior body; omitted fields carry forward', async () => {
    const { service, missionRows, claimRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done', operator_id: 'op_abc', completed_at: new Date(), revoked_at: null,
    });
    seedPriorClaim(claimRows);
    const result = await service.update(
      'pc_dossier_prior',
      { narrative: 'edited narrative' },
      'mem_bob',
    );
    const payload = registry.calls[0]!.payload as DossierClaim;
    expect(payload.narrative).toBe('edited narrative');
    expect(payload.lessons_learned).toBe('original lessons'); // carried
    expect(payload.decision_tree).toHaveLength(1);
    expect(payload.decision_tree[0]!.decision).toBe('old'); // carried
    expect(result.claim_id).toMatch(/^pc_dossier_/);
  });

  it('U2 sets prior_dossier_ref = priorClaimId', async () => {
    const { service, missionRows, claimRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done', operator_id: 'op_abc', completed_at: new Date(), revoked_at: null,
    });
    seedPriorClaim(claimRows);
    await service.update('pc_dossier_prior', { lessons_learned: 'updated' }, 'mem_bob');
    const payload = registry.calls[0]!.payload as DossierClaim;
    expect(payload.prior_dossier_ref).toBe('pc_dossier_prior');
  });

  it('U3 NotFoundError on missing claim_id', async () => {
    const { service } = makeService();
    await expect(service.update('pc_missing', {}, 'mem_bob')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('U4 NotFoundError on non-dossier claim_id (probe-resistance)', async () => {
    const { service, claimRows } = makeService();
    claimRows.set('pc_det', {
      claim_id: 'pc_det',
      operator_id: 'op_abc',
      passport_id: 'pas_x',
      type: 'detector_signal',
      body_json: {},
      issued_at_ms: 1,
      revoked_at: null,
    });
    await expect(service.update('pc_det', {}, 'mem_bob')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('U5 SchemaValidationError on malformed prior body_json', async () => {
    const { service, claimRows } = makeService();
    claimRows.set('pc_bad', {
      claim_id: 'pc_bad',
      operator_id: 'op_abc',
      passport_id: null,
      type: 'dossier',
      body_json: { type: 'dossier' }, // missing mission_ref
      issued_at_ms: 1,
      revoked_at: null,
    });
    await expect(service.update('pc_bad', {}, 'mem_bob')).rejects.toBeInstanceOf(
      SchemaValidationError,
    );
  });

  it('U6 derives operatorId from prior claim (not caller-supplied)', async () => {
    const { service, missionRows, claimRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done', operator_id: 'op_abc', completed_at: new Date(), revoked_at: null,
    });
    seedPriorClaim(claimRows);
    await service.update('pc_dossier_prior', {}, 'mem_bob');
    expect(registry.calls[0]!.operatorId).toBe('op_abc');
  });

  it('U7 stamps fresh authored_at_ms + authored_by_member_id', async () => {
    const { service, missionRows, claimRows, registry } = makeService();
    missionRows.set('ms_done', {
      mission_id: 'ms_done', operator_id: 'op_abc', completed_at: new Date(), revoked_at: null,
    });
    seedPriorClaim(claimRows);
    const before = Date.now();
    await service.update('pc_dossier_prior', {}, 'mem_bob');
    const after = Date.now();
    const payload = registry.calls[0]!.payload as DossierClaim;
    expect(payload.authored_by_member_id).toBe('mem_bob');
    expect(payload.authored_at_ms).toBeGreaterThanOrEqual(before);
    expect(payload.authored_at_ms).toBeLessThanOrEqual(after);
  });

  it('U8 rejects an update when the source mission is active', async () => {
    const { service, missionRows, claimRows, registry } = makeService();
    seedPriorClaim(claimRows);
    missionRows.set('ms_done', {
      mission_id: 'ms_done', operator_id: 'op_abc', completed_at: null, revoked_at: null,
    });

    await expect(service.update('pc_dossier_prior', {}, 'mem_bob'))
      .rejects.toBeInstanceOf(ConflictError);
    expect(registry.calls).toHaveLength(0);
  });

  it('U9 validates source references after merging an update', async () => {
    const { service, missionRows, claimRows, registry } = makeService();
    seedPriorClaim(claimRows);
    missionRows.set('ms_done', {
      mission_id: 'ms_done', operator_id: 'op_abc', completed_at: new Date(), revoked_at: null,
    });

    await expect(service.update('pc_dossier_prior', {
      alerts_walkthrough: [{
        detector_signal_claim_id: 'pc_fabricated',
        severity: 'low',
        narrative: '',
      }],
    }, 'mem_bob')).rejects.toBeInstanceOf(ForbiddenError);
    expect(registry.calls).toHaveLength(0);
  });
});
