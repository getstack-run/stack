// DossierService.
//
// CRUD-ish operator surface over `DossierClaim` envelopes (schema in
// `packages/shared/src/schemas/passport-claims/dossier.ts`, shipped in
// 5.4.1). Dossiers are mission-scoped human-authored post-mortems —
// operator's voice on what happened during a mission. The service:
//
//   1. create(missionId, input, authoredByMemberId)
//        Validates the mission is in a terminal state (completed_* OR
//        revoked_*) before accepting the claim. Active missions cannot
//        have dossiers — the post-mortem is about a closed event.
//        Registers the claim via ClaimRegistryService. Dossiers are a
//        controls feature: the routes refuse an account without controls.
//
//   2. findByMission(missionId, operatorId)
//        Returns zero-or-more dossier envelopes for the mission, ordered
//        by issued_at_ms ASC. Dossier edits chain via prior_dossier_ref
//        (claims are immutable; an update emits a NEW claim referencing
//        the prior one) so chronological ordering exposes the full edit
//        history. Callers wanting "the latest dossier" take the last
//        element of the returned array.
//
//   3. update(dossierClaimId, input, authoredByMemberId)
//        Emits a NEW dossier claim whose prior_dossier_ref points at
//        the existing claim. Same-mission, same-operator — derived from
//        the existing claim's body_json + operator_id. Partial input is
//        merged into the existing fields. NEVER mutates the prior
//        claim's body_json (claims are tamper-evident by their signed
//        claim_hash; updates are append-only successors).
//
// All three methods route through ClaimRegistryService.registerClaim
// with `subjectOverride: 'operator'`. Dossiers are operator-scoped
// because a mission can span multiple passports (delegated children,
// future A2A flows) and pinning to a single passport would lose
// information. Mission binding lives in the payload's `mission_ref`
// field, queried via JSONB text extract in the new repo method
// `PassportClaimsRepository.findActiveByTypeAndMissionRef`.

import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  SchemaValidationError,
  type DossierClaim,
  type DossierDecisionEntry,
  type DossierAlertEntry,
  type IncidentClassification,
} from '@stack/shared';
import type { ClaimRegistryService } from './claim-registry-service.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';

/**
 * Minimal mission-row shape DossierService needs. Structural so the
 * service does not couple to the full MissionRepository surface — the
 * production wiring passes MissionRepository; tests pass an inline
 * stub.
 */
export interface DossierMissionLookup {
  findById(missionId: string): Promise<{
    mission_id: string;
    operator_id: string;
    completed_at: Date | null;
    revoked_at: Date | null;
  } | null | undefined>;
}

export interface DossierServiceDeps {
  claimRegistry: ClaimRegistryService;
  missionRepo: DossierMissionLookup;
  passportClaimsRepo: PassportClaimsRepository;
  memberRepo: {
    findById(memberId: string): Promise<{
      id: string;
      operator_id: string;
      status: string;
    } | null | undefined>;
  };
}

/** Payload accepted by create(). All fields land verbatim into the claim. */
export interface CreateDossierInput {
  narrative: string;
  decision_tree?: DossierDecisionEntry[];
  alerts_walkthrough?: DossierAlertEntry[];
  lessons_learned: string;
  incident_classification: IncidentClassification;
}

/**
 * Partial overrides accepted by update(). Any field omitted is carried
 * forward from the prior dossier. `authoredByMemberId` is required —
 * an update is a new authored event so the new claim must carry the
 * editor's id (which may or may not be the original author).
 */
export interface UpdateDossierInput {
  narrative?: string;
  decision_tree?: DossierDecisionEntry[];
  alerts_walkthrough?: DossierAlertEntry[];
  lessons_learned?: string;
  incident_classification?: IncidentClassification;
}

export interface CreateDossierResult {
  claim_id: string;
  claim: DossierClaim;
}

export interface UpdateDossierResult {
  claim_id: string;
  claim: DossierClaim;
  prior_claim_id: string;
}

export interface DossierEnvelope {
  claim_id: string;
  /**
   * Source of truth on storage: `passport_claims.operator_id` is
   * nullable per the schema ( an earlier change dropped NOT NULL for
   * operator-scoped envelopes that pre-date the registry write path).
   * Dossier rows written through DossierService always carry a non-null
   * operator_id, but callers reading legacy rows or sibling consumers
   * must handle null defensively.
   */
  operator_id: string | null;
  issued_at_ms: number | null;
  body: DossierClaim;
}

/**
 * Mission must have transitioned out of active before a dossier can be
 * authored. Returns true when either terminal-state column is set.
 */
function isMissionTerminal(row: { completed_at: Date | null; revoked_at: Date | null }): boolean {
  return row.completed_at !== null || row.revoked_at !== null;
}

export class DossierService {
  constructor(private deps: DossierServiceDeps) {}

  /**
   * Author a fresh dossier for a mission. Mission must be in a terminal
   * state. The routes that call this refuse an account without controls.
   */
  async create(
    missionId: string,
    input: CreateDossierInput,
    authoredByMemberId: string,
  ): Promise<CreateDossierResult> {
    const mission = await this.deps.missionRepo.findById(missionId);
    if (!mission) {
      throw new NotFoundError('mission', missionId);
    }
    if (!isMissionTerminal(mission)) {
      throw new ConflictError(
        `mission ${missionId} is still active — dossiers can only be authored on missions in a terminal state (completed_* or revoked_*)`,
      );
    }
    await this.assertActiveMember(authoredByMemberId, mission.operator_id);
    await this.assertSourceReferences(
      missionId,
      mission.operator_id,
      input.decision_tree ?? [],
      input.alerts_walkthrough ?? [],
    );

    const payload: DossierClaim = {
      type: 'dossier',
      mission_ref: missionId,
      authored_by_member_id: authoredByMemberId,
      authored_at_ms: Date.now(),
      narrative: input.narrative,
      decision_tree: input.decision_tree ?? [],
      alerts_walkthrough: input.alerts_walkthrough ?? [],
      lessons_learned: input.lessons_learned,
      incident_classification: input.incident_classification,
      prior_dossier_ref: null,
    };

    const registered = await this.deps.claimRegistry.registerClaim({
      operatorId: mission.operator_id,
      claimType: 'dossier',
      payload,
      subjectOverride: 'operator',
    });

    return { claim_id: registered.claimId, claim: payload };
  }

  /**
   * Return the full dossier chain for a mission, chronological order.
   * Empty array when no dossier exists. Callers wanting "latest" take
   * the last element. Includes superseded dossiers — the edit history
   * IS the artefact, not just the head.
   */
  async findByMission(missionId: string, operatorId: string): Promise<DossierEnvelope[]> {
    const rows = await this.deps.passportClaimsRepo.findActiveByTypeAndMissionRef(
      'dossier',
      missionId,
      operatorId,
    );
    return rows.map((row) => ({
      claim_id: row.claim_id,
      operator_id: row.operator_id,
      issued_at_ms: (row as { issued_at_ms?: number | null }).issued_at_ms ?? null,
      body: row.body_json as DossierClaim,
    }));
  }

  /**
   * Edit a dossier by emitting a new claim that references the prior one
   * via prior_dossier_ref. The signed payload of the existing claim is
   * never mutated (claims are tamper-evident by claim_hash); the new
   * claim merges `input` overrides onto the existing body and carries a
   * fresh `authored_at_ms` + `authored_by_member_id`.
   *
   * Throws:
   *   - NotFoundError when the claim id does not exist OR is not a
   *     dossier type. Cross-type lookups (passing a detector_signal
   *     claim id) get NotFoundError so probing for non-dossier claim
   *     existence is impossible through this surface.
   */
  async update(
    priorDossierClaimId: string,
    input: UpdateDossierInput,
    authoredByMemberId: string,
  ): Promise<UpdateDossierResult> {
    const prior = await this.deps.passportClaimsRepo.findByClaimId(priorDossierClaimId);
    if (!prior || prior.type !== 'dossier') {
      throw new NotFoundError('dossier', priorDossierClaimId);
    }

    const priorBody = prior.body_json as Partial<DossierClaim> | null;
    if (!priorBody || priorBody.type !== 'dossier' || !priorBody.mission_ref) {
      // Defensive — the registry's write-time validation already
      // guarantees a well-formed body, but a hand-rolled SQL or
      // bad-state row should surface as a clear error rather than a
      // silent payload merge.
      throw new SchemaValidationError({
        message: `prior dossier claim ${priorDossierClaimId} has malformed body_json`,
        claim_type: 'dossier',
      });
    }
    if (!prior.operator_id) {
      // passport_claims.operator_id is nullable in storage (legacy
      // rows that were never operator-scoped). Any dossier row written through
      // this service carries operator_id; refusing to chain edits off
      // a null-operator legacy row is correct — without an operator_id
      // we cannot route the new claim through the registry's tier gate
      // + signer factory.
      throw new SchemaValidationError({
        message: `prior dossier claim ${priorDossierClaimId} has null operator_id (legacy row); cannot chain an update`,
        claim_type: 'dossier',
      });
    }
    const mission = await this.deps.missionRepo.findById(priorBody.mission_ref);
    if (!mission || mission.operator_id !== prior.operator_id) {
      throw new NotFoundError('mission', priorBody.mission_ref);
    }
    if (!isMissionTerminal(mission)) {
      throw new ConflictError(
        `mission ${priorBody.mission_ref} is still active â€” dossiers can only be authored on missions in a terminal state (completed_* or revoked_*)`,
      );
    }
    await this.assertActiveMember(authoredByMemberId, prior.operator_id);

    const merged: DossierClaim = {
      type: 'dossier',
      mission_ref: priorBody.mission_ref,
      authored_by_member_id: authoredByMemberId,
      authored_at_ms: Date.now(),
      narrative: input.narrative ?? priorBody.narrative ?? '',
      decision_tree: input.decision_tree ?? priorBody.decision_tree ?? [],
      alerts_walkthrough: input.alerts_walkthrough ?? priorBody.alerts_walkthrough ?? [],
      lessons_learned: input.lessons_learned ?? priorBody.lessons_learned ?? '',
      incident_classification:
        input.incident_classification ?? priorBody.incident_classification ?? 'inconclusive',
      prior_dossier_ref: priorDossierClaimId,
    };
    await this.assertSourceReferences(
      merged.mission_ref,
      prior.operator_id,
      merged.decision_tree,
      merged.alerts_walkthrough,
    );

    const registered = await this.deps.claimRegistry.registerClaim({
      operatorId: prior.operator_id,
      claimType: 'dossier',
      payload: merged,
      subjectOverride: 'operator',
    });

    return {
      claim_id: registered.claimId,
      claim: merged,
      prior_claim_id: priorDossierClaimId,
    };
  }

  async listMissionPage(missionId: string, operatorId: string, pagination: { page: number; limit: number }) {
    const rows = await this.deps.passportClaimsRepo.findActiveByTypeAndMissionRef('dossier', missionId, operatorId, pagination);
    return {
      items: rows.slice(0, pagination.limit).map((row) => ({
        claim_id: row.claim_id, operator_id: row.operator_id,
        issued_at_ms: row.issued_at_ms ?? null, body: row.body_json as DossierClaim,
      })),
      ...pagination,
      has_more: rows.length > pagination.limit,
    };
  }

  private async assertActiveMember(memberId: string, operatorId: string): Promise<void> {
    const member = await this.deps.memberRepo.findById(memberId);
    if (
      !member ||
      member.id !== memberId ||
      member.operator_id !== operatorId ||
      member.status !== 'active'
    ) {
      throw new ForbiddenError('dossier authoring requires an active member of the mission operator');
    }
  }

  private async assertSourceReferences(
    missionId: string,
    operatorId: string,
    decisionTree: DossierDecisionEntry[],
    alertsWalkthrough: DossierAlertEntry[],
  ): Promise<void> {
    const checkpointIds = [...new Set(decisionTree.map((entry) => entry.checkpoint_id))];
    const detectorClaimIds = [
      ...new Set(alertsWalkthrough.map((entry) => entry.detector_signal_claim_id)),
    ];
    if (checkpointIds.length === 0 && detectorClaimIds.length === 0) return;

    const sourceClaims = await this.deps.passportClaimsRepo.findDossierSourceClaims(
      operatorId,
      missionId,
      checkpointIds,
      detectorClaimIds,
    );
    const foundCheckpointIds = new Set<string>();
    const detectorSeverities = new Map<string, unknown>();
    for (const source of sourceClaims) {
      if (source.type === 'checkpoint_approval') {
        const checkpointId = (source.body_json as { checkpoint_id?: unknown }).checkpoint_id;
        if (typeof checkpointId === 'string') foundCheckpointIds.add(checkpointId);
      } else if (source.type === 'detector_signal') {
        detectorSeverities.set(
          source.claim_id,
          (source.body_json as { severity?: unknown }).severity,
        );
      }
    }

    const allCheckpointsFound = checkpointIds.every((id) => foundCheckpointIds.has(id));
    const allDetectorsFound = alertsWalkthrough.every(
      (entry) => detectorSeverities.get(entry.detector_signal_claim_id) === entry.severity,
    );
    if (!allCheckpointsFound || !allDetectorsFound) {
      throw new ForbiddenError(
        'dossier references must identify signed source records from the same mission and operator',
      );
    }
  }
}
