import { createHash } from 'node:crypto';
import {
  CheckpointApprovalClaim,
  ConflictError,
  DetectorSignalClaim,
  DossierClaim,
  ForbiddenError,
  HumanOperatorAuthor,
  ids,
  NotFoundError,
  OperatorDecisionClaim,
  OperatorReviewClaim,
  OperatorReviewInput,
  ServiceUnavailableError,
  type DossierClaim as DossierClaimType,
  type HumanOperatorAuthor as HumanOperatorAuthorType,
  type OperatorReviewClaim as OperatorReviewClaimType,
  type OperatorReviewInput as OperatorReviewInputType,
} from '@stack/shared';
import type { ClaimVerifyResult } from '../crypto/claim-signer.js';
import type { AuditContext, AuditService, AuditTransaction } from './audit-service.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { OperatorReviewRepository } from '../repositories/operator-review-repo.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import { assertBrowserDecisionSession, type BrowserDecisionSession } from './browser-decision-session.js';

export interface OperatorReviewMissionLookup {
  findById(missionId: string): Promise<{
    mission_id: string;
    operator_id: string;
    completed_at: Date | null;
    revoked_at: Date | null;
  } | null | undefined>;
}

export interface OperatorReviewMemberLookup {
  findById(memberId: string): Promise<{
    id: string;
    operator_id: string;
    status: string;
    role: string;
  } | null | undefined>;
}

export interface OperatorReviewServiceDeps {
  claimRegistry: Pick<ClaimRegistryService, 'registerClaim'>;
  claimVerifier: { verifyClaim(claimId: string): Promise<ClaimVerifyResult> };
  missionRepo: OperatorReviewMissionLookup;
  memberRepo: OperatorReviewMemberLookup;
  passportClaimsRepo: PassportClaimsRepository;
  reviewRepo: OperatorReviewRepository;
  audit: Pick<AuditService, 'write'>;
  now?: () => number;
}

export interface OperatorReviewEnvelope {
  claim_id: string;
  issued_at_ms: number;
  claim_type: 'dossier' | 'operator_review';
  claim: DossierClaimType | OperatorReviewClaimType;
}

export interface OperatorReviewWriteResult {
  claim_id: string;
  envelope_cose: string;
  claim: OperatorReviewClaimType;
}

export interface OperatorReviewSource {
  mission_id: string;
  operator_decisions: Array<{
    claim_id: string;
    action: string;
    effect: string;
    effect_scope: string;
    target_agent_id: string | null;
    decided_at_ms: number;
    source_refs: {
      checkout_ids: string[];
      security_event_ids: string[];
      detector_claim_ids: string[];
      approval_ids: string[];
    };
  }>;
  checkpoints: Array<{
    claim_id: string;
    submitted_at: number;
    services_used: string[];
    actions_count: number;
  }>;
  alerts: Array<{
    claim_id: string;
    detector_key: string;
    severity: string;
    pipeline: string;
    detected_at: number;
  }>;
}

const isTerminal = (mission: { completed_at: Date | null; revoked_at: Date | null }) =>
  mission.completed_at !== null || mission.revoked_at !== null;

function postgresCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  if ('code' in error && typeof error.code === 'string') return error.code;
  if ('cause' in error) return postgresCode(error.cause);
  return undefined;
}

export class OperatorReviewService {
  private readonly now: () => number;

  constructor(private readonly deps: OperatorReviewServiceDeps) {
    this.now = deps.now ?? Date.now;
  }

  async list(missionId: string, operatorId: string): Promise<OperatorReviewEnvelope[]> {
    await this.assertMission(missionId, operatorId);
    return this.listWithRepo(this.deps.passportClaimsRepo, missionId, operatorId);
  }

  private async listWithRepo(
    repo: PassportClaimsRepository,
    missionId: string,
    operatorId: string,
  ): Promise<OperatorReviewEnvelope[]> {
    const rows = [
      ...await repo.findActiveByTypeAndMissionRef('dossier', missionId, operatorId),
      ...await repo.findActiveByTypeAndMissionRef('operator_review', missionId, operatorId),
    ].sort((a, b) => (a.issued_at_ms ?? 0) - (b.issued_at_ms ?? 0));
    const reviews: OperatorReviewEnvelope[] = [];
    for (const row of rows) {
      const claimType = row.type as 'dossier' | 'operator_review';
      const review = await this.verifyTypedClaim(row.claim_id, claimType, missionId, operatorId);
      const parsed = claimType === 'operator_review'
        ? OperatorReviewClaim.safeParse(review?.payload)
        : DossierClaim.safeParse(review?.payload);
      if (!review || !parsed.success) {
        throw new ServiceUnavailableError('A signed mission review failed integrity verification');
      }
      reviews.push({
        claim_id: row.claim_id,
        issued_at_ms: review.issuedAt,
        claim_type: claimType,
        claim: parsed.data,
      });
    }
    return reviews;
  }

  async source(missionId: string, operatorId: string): Promise<OperatorReviewSource> {
    await this.assertMission(missionId, operatorId);
    const rows = await this.deps.passportClaimsRepo.findInMissionScope(missionId, operatorId);
    const result: OperatorReviewSource = {
      mission_id: missionId,
      operator_decisions: [],
      checkpoints: [],
      alerts: [],
    };
    for (const row of rows) {
      if (!['operator_decision', 'checkpoint_approval', 'detector_signal'].includes(row.type)) continue;
      const verified = await this.deps.claimVerifier.verifyClaim(row.claim_id);
      const envelope = verified.envelope;
      if (!verified.valid || !envelope || envelope.issuer !== operatorId || envelope.claim_type !== row.type) {
        throw new ServiceUnavailableError('A signed mission source failed integrity verification');
      }
      const sourcePayload = envelope.payload as Record<string, unknown> | null;
      if (!sourcePayload || sourcePayload['type'] !== row.type) {
        throw new ServiceUnavailableError('A signed mission source failed schema discrimination');
      }
      if (sourcePayload['mission_ref'] !== missionId) continue;
      if (row.type === 'operator_decision' && sourcePayload['operator_id'] !== operatorId) {
        throw new ServiceUnavailableError('A signed operator decision crossed its operator boundary');
      }
      if (row.type === 'operator_decision') {
        const claim = OperatorDecisionClaim.safeParse(sourcePayload);
        if (!claim.success) throw new ServiceUnavailableError('A signed operator decision failed schema validation');
        result.operator_decisions.push({
          claim_id: row.claim_id,
          action: claim.data.action,
          effect: claim.data.effect,
          effect_scope: claim.data.effect_scope,
          target_agent_id: claim.data.target_agent_id,
          decided_at_ms: claim.data.decided_at_ms,
          source_refs: claim.data.source_refs,
        });
      } else if (row.type === 'checkpoint_approval') {
        const claim = CheckpointApprovalClaim.safeParse(sourcePayload);
        if (!claim.success) throw new ServiceUnavailableError('A signed checkpoint failed schema validation');
        result.checkpoints.push({
          claim_id: row.claim_id,
          submitted_at: claim.data.submitted_at,
          services_used: claim.data.services_used,
          actions_count: claim.data.actions_count,
        });
      } else {
        const claim = DetectorSignalClaim.safeParse(sourcePayload);
        if (!claim.success) throw new ServiceUnavailableError('A signed detector alert failed schema validation');
        result.alerts.push({
          claim_id: row.claim_id,
          detector_key: claim.data.detector_key,
          severity: claim.data.severity,
          pipeline: claim.data.pipeline,
          detected_at: claim.data.detected_at,
        });
      }
    }
    return result;
  }

  async create(
    missionId: string,
    operatorId: string,
    input: OperatorReviewInputType,
    authorInput: HumanOperatorAuthorType,
    auditContext?: AuditContext,
    browserSession?: BrowserDecisionSession,
  ): Promise<OperatorReviewWriteResult> {
    const mission = await this.assertMission(missionId, operatorId);
    if (!isTerminal(mission)) throw new ConflictError('Operator reviews require a terminal mission');
    const author = await this.assertAuthor(authorInput, operatorId);
    const parsedInput = OperatorReviewInput.parse(input);
    return this.deps.reviewRepo.transaction(operatorId, missionId, async (claims, transaction) => {
      if (browserSession) await assertBrowserDecisionSession(transaction, operatorId, browserSession, { allowedMemberRoles: author.kind === 'team_member' ? [author.role_at_signing] : [] });
      const reviews = await this.listWithRepo(claims, missionId, operatorId);
      if (reviews.some((review) => review.claim_type === 'operator_review')) {
        throw new ConflictError('This mission already has an Operator review. Create a revision instead.');
      }
      const result = await this.sign(missionId, operatorId, parsedInput, author, null, claims);
      await this.writeAudit('operator_review.create', missionId, operatorId, auditContext, transaction);
      return result;
    });
  }

  async revise(
    missionId: string,
    priorClaimId: string,
    operatorId: string,
    input: OperatorReviewInputType,
    authorInput: HumanOperatorAuthorType,
    auditContext?: AuditContext,
    browserSession?: BrowserDecisionSession,
  ): Promise<OperatorReviewWriteResult> {
    const mission = await this.assertMission(missionId, operatorId);
    if (!isTerminal(mission)) throw new ConflictError('Operator reviews require a terminal mission');
    const author = await this.assertAuthor(authorInput, operatorId);
    const parsedInput = OperatorReviewInput.parse(input);
    return this.deps.reviewRepo.transaction(operatorId, missionId, async (claims, transaction) => {
      if (browserSession) await assertBrowserDecisionSession(transaction, operatorId, browserSession, { allowedMemberRoles: author.kind === 'team_member' ? [author.role_at_signing] : [] });
      const reviews = (await this.listWithRepo(claims, missionId, operatorId))
        .filter((review) => review.claim_type === 'operator_review');
      if (!reviews.some((review) => review.claim_id === priorClaimId)) {
        throw new NotFoundError('operator review', priorClaimId);
      }
      const current = this.currentReview(reviews);
      if (current.claim_id !== priorClaimId) {
        throw new ConflictError('Only the current Operator review can be revised');
      }
      const result = await this.sign(missionId, operatorId, parsedInput, author, priorClaimId, claims);
      await this.writeAudit('operator_review.revise', missionId, operatorId, auditContext, transaction);
      return result;
    });
  }

  private currentReview(reviews: OperatorReviewEnvelope[]): OperatorReviewEnvelope {
    if (reviews.length === 0) throw new ServiceUnavailableError('The Operator review chain has no root');
    const byId = new Map(reviews.map((review) => [review.claim_id, review]));
    if (byId.size !== reviews.length) {
      throw new ServiceUnavailableError('The Operator review chain contains a duplicate claim id');
    }
    if (new Set(reviews.map((review) => review.issued_at_ms)).size !== reviews.length) {
      throw new ServiceUnavailableError('The Operator review chain has ambiguous issuance times');
    }

    const roots = reviews.filter((review) => (
      review.claim as OperatorReviewClaimType
    ).prior_review_ref === null);
    if (roots.length !== 1) {
      throw new ServiceUnavailableError('The Operator review chain must contain exactly one root');
    }

    const childByParent = new Map<string, OperatorReviewEnvelope>();
    for (const review of reviews) {
      const prior = (review.claim as OperatorReviewClaimType).prior_review_ref;
      if (prior === null) continue;
      if (!byId.has(prior)) {
        throw new ServiceUnavailableError('The Operator review chain contains a missing prior link');
      }
      if (childByParent.has(prior)) {
        throw new ServiceUnavailableError('The Operator review chain contains a fork');
      }
      childByParent.set(prior, review);
    }

    const visited = new Set<string>();
    let current = roots[0]!;
    while (true) {
      if (visited.has(current.claim_id)) {
        throw new ServiceUnavailableError('The Operator review chain contains a cycle');
      }
      visited.add(current.claim_id);
      const child = childByParent.get(current.claim_id);
      if (!child) break;
      current = child;
    }
    if (visited.size !== reviews.length) {
      throw new ServiceUnavailableError('The Operator review chain is disconnected or cyclic');
    }
    return current;
  }

  async download(missionId: string, claimId: string, operatorId: string): Promise<{
    bytes: Buffer;
    digest_sha256_base64: string;
  }> {
    const row = await this.deps.passportClaimsRepo.findByClaimId(claimId);
    if (!row || !['dossier', 'operator_review'].includes(row.type) || row.operator_id !== operatorId || !row.envelope_cose) {
      throw new NotFoundError('operator review', claimId);
    }
    const claimType = row.type as 'dossier' | 'operator_review';
    const verified = await this.verifyTypedClaim(claimId, claimType, missionId, operatorId);
    const validPayload = claimType === 'operator_review'
      ? OperatorReviewClaim.safeParse(verified?.payload).success
      : DossierClaim.safeParse(verified?.payload).success;
    if (!verified || !validPayload) {
      throw new NotFoundError('operator review', claimId);
    }
    const bytes = Buffer.from(row.envelope_cose, 'base64url');
    return {
      bytes,
      digest_sha256_base64: createHash('sha256').update(bytes).digest('base64'),
    };
  }

  private async sign(
    missionId: string,
    operatorId: string,
    input: OperatorReviewInputType,
    author: HumanOperatorAuthorType,
    priorReviewRef: string | null,
    persistence: Pick<PassportClaimsRepository, 'insert'>,
  ): Promise<OperatorReviewWriteResult> {
    await this.assertReferences(missionId, operatorId, input);
    const claim = OperatorReviewClaim.parse({
      type: 'operator_review',
      mission_ref: missionId,
      operator_id: operatorId,
      authored_by: author,
      authored_at_ms: this.now(),
      ...input,
      prior_review_ref: priorReviewRef,
      assessment_basis: 'operator_organization_assessment',
    });
    let registered: { claimId: string; envelopeCose: string; subject: string };
    try {
      registered = await this.deps.claimRegistry.registerClaim({
        operatorId,
        subjectOverride: 'operator',
        claimType: 'operator_review',
        payload: claim,
      }, { persistence });
    } catch (error) {
      if (postgresCode(error) === '23505') {
        throw new ConflictError('The Operator review changed while this revision was being signed');
      }
      throw error;
    }
    return { claim_id: registered.claimId, envelope_cose: registered.envelopeCose, claim };
  }

  private async writeAudit(
    action: 'operator_review.create' | 'operator_review.revise',
    missionId: string,
    operatorId: string,
    input: AuditContext | undefined,
    transaction: AuditTransaction,
  ): Promise<void> {
    await this.deps.audit.write({
      ctx: {
        trace_id: input?.trace_id ?? ids.session(),
        span_id: input?.span_id ?? missionId,
        parent_span_id: input?.parent_span_id,
        operator_id: operatorId,
        agent_id: input?.agent_id ?? 'system',
        passport_jti: input?.passport_jti ?? 'none',
      },
      layer: 'vault',
      action,
      outcome: 'success',
    }, transaction);
  }

  private async assertReferences(
    missionId: string,
    operatorId: string,
    input: OperatorReviewInputType,
  ): Promise<void> {
    const refs = [
      ...input.decision_rationales.map((item) => ({ id: item.operator_decision_claim_id, type: 'operator_decision' })),
      ...input.checkpoint_notes.map((item) => ({ id: item.checkpoint_claim_id, type: 'checkpoint_approval' })),
      ...input.alert_explanations.map((item) => ({ id: item.detector_claim_id, type: 'detector_signal' })),
    ];
    for (const ref of refs) {
      const verified = await this.verifyTypedClaim(ref.id, ref.type, missionId, operatorId);
      if (!verified) {
        throw new ForbiddenError('Operator review references must be verified claims from the same mission and operator');
      }
      const parsed = ref.type === 'operator_decision'
        ? OperatorDecisionClaim.safeParse(verified.payload)
        : ref.type === 'checkpoint_approval'
          ? CheckpointApprovalClaim.safeParse(verified.payload)
          : DetectorSignalClaim.safeParse(verified.payload);
      if (!parsed.success) throw new ForbiddenError('Operator review source claim payload failed schema validation');
    }
  }

  private async verifyTypedClaim(
    claimId: string,
    claimType: string,
    missionId: string,
    operatorId: string,
  ): Promise<{ payload: unknown; issuedAt: number } | null> {
    const verified = await this.deps.claimVerifier.verifyClaim(claimId);
    const envelope = verified.envelope;
    if (!verified.valid || !envelope || envelope.issuer !== operatorId || envelope.claim_type !== claimType) return null;
    const payload = envelope.payload as Record<string, unknown> | null;
    if (!payload || payload['type'] !== claimType || payload['mission_ref'] !== missionId) return null;
    if (
      (claimType === 'operator_decision' || claimType === 'operator_review')
      && payload['operator_id'] !== operatorId
    ) return null;
    return { payload, issuedAt: envelope.issued_at };
  }

  private async assertMission(missionId: string, operatorId: string) {
    const mission = await this.deps.missionRepo.findById(missionId);
    if (!mission || mission.operator_id !== operatorId) throw new NotFoundError('mission', missionId);
    return mission;
  }

  private async assertAuthor(authorInput: HumanOperatorAuthorType, operatorId: string) {
    const author = HumanOperatorAuthor.parse(authorInput);
    if (author.kind === 'operator_owner') {
      if (author.operator_id !== operatorId) throw new ForbiddenError('Operator review author is foreign');
      return author;
    }
    const member = await this.deps.memberRepo.findById(author.member_id);
    if (
      !member
      || member.operator_id !== operatorId
      || member.status !== 'active'
      || !['standard', 'admin'].includes(member.role)
      || member.role !== author.role_at_signing
    ) throw new ForbiddenError('Operator review author must be an active standard or admin member');
    return author;
  }
}
