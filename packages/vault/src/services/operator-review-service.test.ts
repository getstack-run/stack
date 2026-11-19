import { describe, expect, it, vi } from 'vitest';
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  type HumanOperatorAuthor,
} from '@stack/shared';
import { OperatorReviewService } from './operator-review-service.js';

const owner: HumanOperatorAuthor = { kind: 'operator_owner', operator_id: 'op_one' };
const member: HumanOperatorAuthor = {
  kind: 'team_member',
  member_id: 'mem_one',
  role_at_signing: 'standard',
};

function envelope(
  claimType: string,
  payload: Record<string, unknown>,
  issuer = 'op_one',
  issuedAt = 1_766_000_000_000,
) {
  return {
    valid: true,
    envelope: {
      envelope_version: 1,
      issuer,
      subject: 'stack://operator/op_one',
      issued_at: issuedAt,
      claim_type: claimType,
      claim_version: 1,
      payload,
      receipt: null,
      co_signatures: [],
    },
  };
}

const decision = {
  type: 'operator_decision',
  decision_id: 'odec_one',
  mission_ref: 'ms_one',
  operator_id: 'op_one',
  authored_by: owner,
  action: 'checkout_approved',
  effect: 'checkout_released',
  effect_scope: 'mission',
  source_refs: {
    checkout_ids: ['cout_one'],
    security_event_ids: [],
    detector_claim_ids: [],
    approval_ids: [],
  },
  target_agent_id: 'agt_one',
  decided_at_ms: 1_766_000_000_000,
};

const checkpoint = {
  type: 'checkpoint_approval',
  checkpoint_id: 'chk_one',
  interval_seconds: 60,
  services_used: ['github'],
  actions_count: 2,
  has_summary: true,
  delegated_to: [],
  submitted_by: 'agt_one',
  submitted_at: 1_766_000_000_100,
  mission_ref: 'ms_one',
};

const detector = {
  type: 'detector_signal',
  detector_key: 'prompt_injection',
  severity: 'high',
  pipeline: 'heuristic',
  metadata: { prompt: 'must never leave the service' },
  detected_at: 1_766_000_000_200,
  mission_ref: 'ms_one',
};

const input = {
  overall_judgment: 'The operator handled the mission correctly.',
  checkpoint_notes: [{ checkpoint_claim_id: 'pc_checkpoint', note: 'Normal progress.' }],
  decision_rationales: [{ operator_decision_claim_id: 'pc_decision', rationale: 'The request was safe.' }],
  alert_explanations: [{ detector_claim_id: 'pc_detector', explanation: 'The alert was contained.' }],
  incident_classification: 'true_positive_handled' as const,
  lessons_learned: 'Keep the current policy.',
};

const legacyDossier = {
  type: 'dossier',
  mission_ref: 'ms_one',
  authored_by_member_id: 'mem_one',
  authored_at_ms: 1,
  narrative: 'Legacy review.',
  decision_tree: [],
  alerts_walkthrough: [],
  lessons_learned: '',
  incident_classification: 'false_positive',
  prior_dossier_ref: null,
};

function storedReview(priorReviewRef: string | null, authoredAtMs = 1) {
  return {
    ...input,
    type: 'operator_review',
    mission_ref: 'ms_one',
    operator_id: 'op_one',
    authored_by: owner,
    authored_at_ms: authoredAtMs,
    prior_review_ref: priorReviewRef,
    assessment_basis: 'operator_organization_assessment',
  };
}

function fixture(options: {
  terminal?: boolean;
  existingReviews?: Array<Record<string, unknown>>;
  legacyDossiers?: Array<Record<string, unknown>>;
  overrides?: Record<string, ReturnType<typeof envelope>>;
  memberStatus?: string;
  memberRole?: string;
  auditFailsOnce?: boolean;
} = {}) {
  const rows = [
    { claim_id: 'pc_decision', type: 'operator_decision', envelope_cose: 'ZA', issued_at_ms: 1 },
    { claim_id: 'pc_checkpoint', type: 'checkpoint_approval', envelope_cose: 'Y2s', issued_at_ms: 2 },
    { claim_id: 'pc_detector', type: 'detector_signal', envelope_cose: 'ZGV0', issued_at_ms: 3 },
  ];
  const existingReviews = options.existingReviews ?? [];
  const legacyDossiers = options.legacyDossiers ?? [];
  const verified: Record<string, ReturnType<typeof envelope>> = {
    pc_decision: envelope('operator_decision', decision),
    pc_checkpoint: envelope('checkpoint_approval', checkpoint),
    pc_detector: envelope('detector_signal', detector),
  };
  for (const [index, row] of existingReviews.entries()) {
    verified[String(row.claim_id)] = envelope(
      'operator_review',
      row.claim as Record<string, unknown>,
      'op_one',
      Number(row.issued_at_ms ?? 1_766_000_000_010 + index),
    );
  }
  for (const row of legacyDossiers) {
    verified[String(row.claim_id)] = envelope('dossier', row.claim as Record<string, unknown>);
  }
  Object.assign(verified, options.overrides ?? {});
  const registerClaim = vi.fn(async (request: { payload: Record<string, unknown> }) => {
    const claimId = existingReviews.length === 0 ? 'pc_review_one' : `pc_review_${existingReviews.length + 1}`;
    existingReviews.push({ claim_id: claimId, claim: request.payload });
    verified[claimId] = envelope('operator_review', request.payload);
    return {
      claimId,
      envelopeCose: 'cmV2aWV3',
      subject: 'stack://operator/op_one',
    };
  });
  let auditAttempts = 0;
  const auditWrite = vi.fn(async () => {
    auditAttempts += 1;
    if (options.auditFailsOnce && auditAttempts === 1) throw new Error('audit failed');
    return 'ae_review';
  });
  const passportClaimsRepo = {
    findActiveByTypeAndMissionRef: vi.fn(async (type: string) =>
      type === 'operator_review'
        ? existingReviews.map((row) => ({
            claim_id: row.claim_id,
            type: 'operator_review',
            envelope_cose: 'cmV2aWV3',
            operator_id: 'op_one',
            issued_at_ms: Number(row.issued_at_ms ?? 5),
          }))
        : type === 'dossier'
          ? legacyDossiers.map((row) => ({
              claim_id: row.claim_id,
              type: 'dossier',
              envelope_cose: 'ZG9zc2llcg',
              operator_id: 'op_one',
              issued_at_ms: 4,
            }))
          : []),
    findInMissionScope: vi.fn(async () => rows),
    findByClaimId: vi.fn(async (claimId: string) => {
      const review = existingReviews.find((row) => row.claim_id === claimId);
      if (review) return {
        claim_id: claimId,
        type: 'operator_review',
        operator_id: 'op_one',
        envelope_cose: 'cmV2aWV3',
        };
      const dossier = legacyDossiers.find((row) => row.claim_id === claimId);
      if (dossier) return {
        claim_id: claimId,
        type: 'dossier',
        operator_id: 'op_one',
        envelope_cose: 'ZG9zc2llcg',
      };
      return rows.find((row) => row.claim_id === claimId) ?? null;
    }),
    insert: vi.fn(),
  };
  let transactionTail = Promise.resolve();
  const reviewRepo = {
    transaction: vi.fn(async (_operatorId: string, _missionId: string, callback: (repo: unknown) => Promise<unknown>) => {
      const previous = transactionTail;
      let release: () => void = () => {};
      transactionTail = new Promise<void>((resolve) => { release = resolve; });
      await previous;
      const reviewCountBefore = existingReviews.length;
      try {
        return await callback(passportClaimsRepo);
      } catch (error) {
        for (const row of existingReviews.splice(reviewCountBefore)) {
          delete verified[String(row.claim_id)];
        }
        throw error;
      } finally {
        release();
      }
    }),
  };
  const service = new OperatorReviewService({
    claimRegistry: { registerClaim } as never,
    claimVerifier: { verifyClaim: vi.fn(async (claimId: string) => verified[claimId] ?? { valid: false }) } as never,
    missionRepo: {
      findById: vi.fn(async () => ({
        mission_id: 'ms_one',
        operator_id: 'op_one',
        completed_at: options.terminal === false ? null : new Date(),
        revoked_at: null,
      })),
    },
    memberRepo: {
      findById: vi.fn(async () => ({
        id: 'mem_one',
        operator_id: 'op_one',
        status: options.memberStatus ?? 'active',
        role: options.memberRole ?? 'standard',
      })),
    },
    passportClaimsRepo: passportClaimsRepo as never,
    reviewRepo: reviewRepo as never,
    audit: { write: auditWrite } as never,
    now: () => 1_766_000_000_500,
  });
  return { service, registerClaim, auditWrite };
}

describe('OperatorReviewService', () => {
  it('creates an owner-authored review from exact verified sources', async () => {
    const { service, registerClaim } = fixture();
    const result = await service.create('ms_one', 'op_one', input, owner);
    expect(result).toMatchObject({ claim_id: 'pc_review_one', envelope_cose: 'cmV2aWV3' });
    expect(registerClaim).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_one',
      claimType: 'operator_review',
      payload: expect.objectContaining({
        mission_ref: 'ms_one',
        operator_id: 'op_one',
        authored_by: owner,
        prior_review_ref: null,
      }),
    }), expect.any(Object));
  });

  it('lists legacy dossiers and still permits one new Operator review root', async () => {
    const { service } = fixture({
      legacyDossiers: [{ claim_id: 'pc_dossier_one', claim: legacyDossier }],
    });
    const listed = await service.list('ms_one', 'op_one');
    expect(listed).toEqual([expect.objectContaining({
      claim_id: 'pc_dossier_one',
      claim_type: 'dossier',
      claim: expect.objectContaining({ narrative: 'Legacy review.' }),
    })]);
    await expect(service.create('ms_one', 'op_one', input, owner)).resolves.toBeDefined();
  });

  it('fails closed when an exact stored review fails signature verification', async () => {
    const stored = {
      ...input,
      type: 'operator_review',
      mission_ref: 'ms_one',
      operator_id: 'op_one',
      authored_by: owner,
      authored_at_ms: 1,
      prior_review_ref: null,
      assessment_basis: 'operator_organization_assessment',
    };
    const { service } = fixture({
      existingReviews: [{ claim_id: 'pc_review_one', claim: stored }],
      overrides: { pc_review_one: { valid: false } as never },
    });
    await expect(service.list('ms_one', 'op_one')).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('allows an active standard member and rejects inactive or readonly members', async () => {
    await expect(fixture().service.create('ms_one', 'op_one', input, member)).resolves.toBeDefined();
    await expect(fixture({ memberStatus: 'invited' }).service.create('ms_one', 'op_one', input, member))
      .rejects.toBeInstanceOf(ForbiddenError);
    await expect(fixture({ memberRole: 'readonly' }).service.create('ms_one', 'op_one', input, member))
      .rejects.toBeInstanceOf(ForbiddenError);
  });

  it('rejects active missions and a second root review', async () => {
    await expect(fixture({ terminal: false }).service.create('ms_one', 'op_one', input, owner))
      .rejects.toBeInstanceOf(ConflictError);
    const priorClaim = {
      ...input,
      type: 'operator_review',
      mission_ref: 'ms_one',
      operator_id: 'op_one',
      authored_by: owner,
      authored_at_ms: 1,
      prior_review_ref: null,
      assessment_basis: 'operator_organization_assessment',
    };
    await expect(fixture({ existingReviews: [{ claim_id: 'pc_review_one', claim: priorClaim }] })
      .service.create('ms_one', 'op_one', input, owner)).rejects.toBeInstanceOf(ConflictError);
  });

  it.each([
    ['missing', { pc_decision: { valid: false } }],
    ['foreign', { pc_decision: envelope('operator_decision', decision, 'op_other') }],
    ['wrong mission', { pc_decision: envelope('operator_decision', { ...decision, mission_ref: 'ms_other' }) }],
    ['wrong type', { pc_decision: envelope('detector_signal', detector) }],
    ['changed', { pc_decision: envelope('operator_decision', { ...decision, operator_id: 'op_other' }) }],
  ])('rejects a %s decision reference', async (_name, overrides) => {
    await expect(fixture({ overrides: overrides as never }).service.create('ms_one', 'op_one', input, owner))
      .rejects.toBeInstanceOf(ForbiddenError);
  });

  it('rejects duplicate references before signing', async () => {
    const { service, registerClaim } = fixture();
    await expect(service.create('ms_one', 'op_one', {
      ...input,
      decision_rationales: [...input.decision_rationales, ...input.decision_rationales],
    }, owner)).rejects.toBeDefined();
    expect(registerClaim).not.toHaveBeenCalled();
  });

  it('creates an immutable revision linked to the current review', async () => {
    const priorClaim = {
      ...input,
      type: 'operator_review',
      mission_ref: 'ms_one',
      operator_id: 'op_one',
      authored_by: owner,
      authored_at_ms: 1,
      prior_review_ref: null,
      assessment_basis: 'operator_organization_assessment',
    };
    const { service, registerClaim } = fixture({
      existingReviews: [{ claim_id: 'pc_review_one', claim: priorClaim }],
    });
    const result = await service.revise('ms_one', 'pc_review_one', 'op_one', input, owner);
    expect(result.claim.prior_review_ref).toBe('pc_review_one');
    expect(registerClaim).toHaveBeenCalledTimes(1);
  });

  it('serializes concurrent root creation so only one claim is signed', async () => {
    const { service, registerClaim } = fixture();
    const settled = await Promise.allSettled([
      service.create('ms_one', 'op_one', input, owner),
      service.create('ms_one', 'op_one', input, owner),
    ]);
    expect(settled.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(settled.filter((result) => result.status === 'rejected')).toHaveLength(1);
    expect((settled.find((result) => result.status === 'rejected') as PromiseRejectedResult).reason)
      .toBeInstanceOf(ConflictError);
    expect(registerClaim).toHaveBeenCalledTimes(1);
  });

  it('serializes concurrent revisions so one stale branch is rejected', async () => {
    const priorClaim = {
      ...input,
      type: 'operator_review',
      mission_ref: 'ms_one',
      operator_id: 'op_one',
      authored_by: owner,
      authored_at_ms: 1,
      prior_review_ref: null,
      assessment_basis: 'operator_organization_assessment',
    };
    const { service, registerClaim } = fixture({
      existingReviews: [{ claim_id: 'pc_review_one', claim: priorClaim }],
    });
    const settled = await Promise.allSettled([
      service.revise('ms_one', 'pc_review_one', 'op_one', input, owner),
      service.revise('ms_one', 'pc_review_one', 'op_one', input, owner),
    ]);
    expect(settled.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(settled.filter((result) => result.status === 'rejected')).toHaveLength(1);
    expect(registerClaim).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a fork', [
      { claim_id: 'pc_review_one', claim: storedReview(null), issued_at_ms: 10 },
      { claim_id: 'pc_review_two', claim: storedReview('pc_review_one', 2), issued_at_ms: 20 },
      { claim_id: 'pc_review_three', claim: storedReview('pc_review_one', 3), issued_at_ms: 30 },
    ]],
    ['a missing prior link', [
      { claim_id: 'pc_review_two', claim: storedReview('pc_review_missing'), issued_at_ms: 20 },
    ]],
    ['a cycle', [
      { claim_id: 'pc_review_one', claim: storedReview('pc_review_two'), issued_at_ms: 10 },
      { claim_id: 'pc_review_two', claim: storedReview('pc_review_one', 2), issued_at_ms: 20 },
    ]],
    ['same-millisecond review ordering', [
      { claim_id: 'pc_review_one', claim: storedReview(null), issued_at_ms: 10 },
      { claim_id: 'pc_review_two', claim: storedReview('pc_review_one', 2), issued_at_ms: 10 },
    ]],
  ] as const)('fails closed for %s', async (_name, existingReviews) => {
    const { service, registerClaim } = fixture({ existingReviews: [...existingReviews] as never });
    await expect(service.revise(
      'ms_one',
      String(existingReviews.at(-1)!.claim_id),
      'op_one',
      input,
      owner,
    )).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(registerClaim).not.toHaveBeenCalled();
  });

  it('derives the current leaf from prior references instead of timestamp order', async () => {
    const root = { claim_id: 'pc_review_one', claim: storedReview(null), issued_at_ms: 30 };
    const leaf = { claim_id: 'pc_review_two', claim: storedReview('pc_review_one', 2), issued_at_ms: 20 };
    const { service } = fixture({ existingReviews: [leaf, root] });
    await expect(service.revise('ms_one', 'pc_review_two', 'op_one', input, owner)).resolves.toBeDefined();
  });

  it('rolls back a signed review when audit fails and permits a clean retry', async () => {
    const { service, registerClaim, auditWrite } = fixture({ auditFailsOnce: true });
    await expect(service.create('ms_one', 'op_one', input, owner)).rejects.toThrow('audit failed');
    await expect(service.create('ms_one', 'op_one', input, owner)).resolves.toBeDefined();
    expect(registerClaim).toHaveBeenCalledTimes(2);
    expect(auditWrite).toHaveBeenCalledTimes(2);
  });

  it('rejects revisions from a stale or foreign prior claim', async () => {
    const priorClaim = {
      ...input,
      type: 'operator_review',
      mission_ref: 'ms_one',
      operator_id: 'op_one',
      authored_by: owner,
      authored_at_ms: 1,
      prior_review_ref: null,
      assessment_basis: 'operator_organization_assessment',
    };
    const secondClaim = { ...priorClaim, prior_review_ref: 'pc_review_one', authored_at_ms: 2 };
    const service = fixture({ existingReviews: [
      { claim_id: 'pc_review_one', claim: priorClaim },
      { claim_id: 'pc_review_two', claim: secondClaim },
    ] }).service;
    await expect(service.revise('ms_one', 'pc_review_one', 'op_one', input, owner))
      .rejects.toBeInstanceOf(ConflictError);
    await expect(service.revise('ms_one', 'pc_missing', 'op_one', input, owner))
      .rejects.toBeInstanceOf(NotFoundError);
  });

  it('returns only verified and sanitized source fields', async () => {
    const source = await fixture().service.source('ms_one', 'op_one');
    expect(source.operator_decisions[0]).toEqual(expect.objectContaining({ claim_id: 'pc_decision' }));
    expect(source.checkpoints[0]).toEqual({
      claim_id: 'pc_checkpoint',
      submitted_at: checkpoint.submitted_at,
      services_used: ['github'],
      actions_count: 2,
    });
    expect(source.alerts[0]).toEqual({
      claim_id: 'pc_detector',
      detector_key: 'prompt_injection',
      severity: 'high',
      pipeline: 'heuristic',
      detected_at: detector.detected_at,
    });
    expect(JSON.stringify(source)).not.toContain('must never leave the service');
    expect(JSON.stringify(source)).not.toContain('metadata');
  });

  it('fails closed when a recognized mission source is damaged', async () => {
    const { service } = fixture({
      overrides: { pc_decision: { valid: false } as never },
    });
    await expect(service.source('ms_one', 'op_one')).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('returns exact COSE bytes and hides foreign or wrong-type lookups', async () => {
    const { service } = fixture({ existingReviews: [{ claim_id: 'pc_review_one', claim: {
      ...input,
      type: 'operator_review',
      mission_ref: 'ms_one',
      operator_id: 'op_one',
      authored_by: owner,
      authored_at_ms: 1,
      prior_review_ref: null,
      assessment_basis: 'operator_organization_assessment',
    } }] });
    const download = await service.download('ms_one', 'pc_review_one', 'op_one');
    expect(download.bytes).toEqual(Buffer.from('cmV2aWV3', 'base64url'));
    expect(download.digest_sha256_base64).toMatch(/^[A-Za-z0-9+/]+=*$/);
    await expect(service.download('ms_other', 'pc_review_one', 'op_one')).rejects.toBeInstanceOf(NotFoundError);
    await expect(fixture().service.download('ms_one', 'pc_decision', 'op_one')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('downloads the exact signed bytes of a legacy dossier', async () => {
    const { service } = fixture({
      legacyDossiers: [{ claim_id: 'pc_dossier_one', claim: legacyDossier }],
    });
    const download = await service.download('ms_one', 'pc_dossier_one', 'op_one');
    expect(download.bytes).toEqual(Buffer.from('ZG9zc2llcg', 'base64url'));
  });
});
