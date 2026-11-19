/**
 * Passport claim registry — typed claims that attach to a passport
 * via the claims-registry. Each claim is wrapped in a SCITT-conformant
 * COSE_Sign1 envelope (see `./envelope.ts`) and registered to the
 * claim_registry table. Cascade semantics: revoking a passport
 * invalidates every claim attached to it (and to its delegated
 * children).
 *
 * Part of the Signed Primitive epic. ADR at
 * the claims registry design.
 *
 * Files in this directory:
 *   - types.ts     — ClaimType enum (active + reserved names)
 *   - subject.ts   — `stack://...` subject scheme + builders + parser
 *   - receipt.ts   — Receipt shape (proof + witnesses), absorbs every
 *                    transparency-log format we may need 2026-2030
 *   - envelope.ts  — ClaimEnvelope shape + buildClaimEnvelope helper
 *   - svid-attestation.ts — SVID attestation claim payload
 *                           first concrete claim type)
 *   - index.ts     — barrel re-exports + PASSPORT_CLAIM_SCHEMAS
 *                    registry used by the service layer to validate
 *                    payload-against-claim-type at attach time
 *
 * Adding a new claim type:
 *   1. Reserve the name in `./types.ts` ClaimType enum (if not
 *      already reserved).
 *   2. Create `./{claim-type-name}.ts` exporting the Zod payload
 *      schema.
 *   3. Register the schema in PASSPORT_CLAIM_SCHEMAS below.
 *   4. Add an additive-only fixture test in
 *      `./{claim-type-name}.test.ts` so future breaking changes fail
 *      CI loudly.
 */
import { z } from 'zod';
import { SvidAttestationClaim } from './svid-attestation.js';
import { WorkloadAttestationClaim } from './workload-attestation.js';
import { RatsEvidenceClaim } from './rats-evidence.js';
import { SlsaProvenanceClaim } from './slsa-provenance.js';
import { AiBomRefClaim } from './ai-bom-ref.js';
import { C2paAssertionClaim } from './c2pa-assertion.js';
import { IntentClaim } from './intent-claim.js';
import { DetectorSignalClaim } from './detector-signal.js';
import { IntentOutcomeClaim } from './intent-outcome.js';
import { IntentDenialClaim } from './intent-denial.js';
import { IntentSimulationClaim } from './intent-simulation.js';
import { EntityObservationClaim } from './entity-observation.js';
import { CheckpointApprovalClaim } from './checkpoint-approval.js';
import { SkillInvocationClaim } from './skill-invocation.js';
import { SandboxRunClaim } from './sandbox-run.js';
import { WorkspaceActionClaim } from './workspace-action.js';
import { IdentityClaim } from './identity-claim.js';
import { MissionClaim } from './mission.js';
import { BehavioralGenomeClaim } from './behavioral-genome.js';
import { TwinDivergenceClaim } from './twin-divergence.js';
import { DossierClaim } from './dossier.js';
import { EvidencePackClaim } from './evidence-pack.js';
import { OperatorDecisionClaim } from './operator-decision.js';
import { OperatorReviewClaim } from './operator-review.js';
import {
  AuthorityApprovalClaim,
  AuthorityBindingClaim,
  AuthorityErasureTombstoneClaim,
  AuthorityUseClaim,
  ExternalProofVerificationClaim,
  ReceiverTransactionReceiptClaim,
} from './authority-claims.js';

export * from './types.js';
export * from './subject.js';
export * from './receipt.js';
export * from './envelope.js';
export * from './svid-attestation.js';
export * from './workload-attestation.js';
export * from './rats-evidence.js';
export * from './slsa-provenance.js';
export * from './ai-bom-ref.js';
export * from './c2pa-assertion.js';
export * from './intent-claim.js';
export * from './detector-signal.js';
export * from './intent-outcome.js';
export * from './intent-denial.js';
export * from './intent-simulation.js';
export * from './entity-observation.js';
export * from './checkpoint-approval.js';
export * from './skill-invocation.js';
export * from './sandbox-run.js';
export * from './workspace-action.js';
export * from './identity-claim.js';
export * from './mission.js';
export * from './behavioral-genome.js';
export * from './twin-divergence.js';
export * from './dossier.js';
export * from './evidence-pack.js';
export * from './operator-decision.js';
export * from './operator-review.js';
export * from './authority-claims.js';

/**
 * Discriminated union over every registered passport-claim shape.
 * Future claim types (detector_signal, checkpoint_approval, ...) extend
 * the union here. The discriminator is `type` (inside the payload
 * body itself, separate from the envelope's `claim_type` field).
 */
export const PassportClaim = z.discriminatedUnion('type', [
  SvidAttestationClaim,
  WorkloadAttestationClaim,
  RatsEvidenceClaim,
  SlsaProvenanceClaim,
  AiBomRefClaim,
  C2paAssertionClaim,
  IntentClaim,
  DetectorSignalClaim,
  IntentDenialClaim,
  IntentSimulationClaim,
  EntityObservationClaim,
  CheckpointApprovalClaim,
  SkillInvocationClaim,
  SandboxRunClaim,
  WorkspaceActionClaim,
  IdentityClaim,
  MissionClaim,
  TwinDivergenceClaim,
  DossierClaim,
  EvidencePackClaim,
  ExternalProofVerificationClaim,
  AuthorityBindingClaim,
  AuthorityApprovalClaim,
  AuthorityUseClaim,
  ReceiverTransactionReceiptClaim,
  // authority_erasure_tombstone is registered below but excluded here because
  // its cross-field target/version validation wraps the object in ZodEffects.
  // behavioral_genome is registered in PASSPORT_CLAIM_SCHEMAS below
  // for ClaimRegistryService dispatch but NOT included in this union.
  // Its top-level `.refine()` (window_end_ms > window_start_ms) wraps
  // the object in ZodEffects, which z.discriminatedUnion does not
  // accept as a member. Same exclusion pattern as intent_outcome
  // (documented below).
]);
export type PassportClaim = z.infer<typeof PassportClaim>;

/**
 * Registry mapping claim_type → Zod payload schema. Used by
 * `ClaimRegistryService.registerClaim()` to validate the payload
 * body against the schema declared by its envelope's claim_type
 * field BEFORE the envelope gets signed.
 *
 * A name reserved in `ClaimType` but absent from this registry is
 * a registered-but-not-yet-implemented claim type. registerClaim()
 * rejects with a clear "claim type X is reserved but not yet
 * implemented" error rather than silently accepting unvalidated
 * payload bytes.
 */
export const PASSPORT_CLAIM_SCHEMAS = {
  svid_attestation: SvidAttestationClaim,
  workload_attestation: WorkloadAttestationClaim,
  rats_evidence: RatsEvidenceClaim,
  slsa_provenance: SlsaProvenanceClaim,
  ai_bom_ref: AiBomRefClaim,
  c2pa_assertion: C2paAssertionClaim,
  intent_claim: IntentClaim,
  detector_signal: DetectorSignalClaim,
  // intent_outcome is a sub-discriminated union (5 variants on
  // outcome_type, all sharing `type: 'intent_outcome'`). It is
  // registered here for ClaimRegistryService dispatch but NOT
  // included in the PassportClaim discriminated union above —
  // z.discriminatedUnion('type', ...) requires unique literals per
  // member at the top level. ClaimRegistryService.registerClaim
  // uses this map (not the union) for dispatch.
  intent_outcome: IntentOutcomeClaim,
  intent_denial: IntentDenialClaim,
  intent_simulation: IntentSimulationClaim,
  entity_observation: EntityObservationClaim,
  checkpoint_approval: CheckpointApprovalClaim,
  skill_invocation: SkillInvocationClaim,
  sandbox_run: SandboxRunClaim,
  workspace_action: WorkspaceActionClaim,
  identity_claim: IdentityClaim,
  mission: MissionClaim,
  behavioral_genome: BehavioralGenomeClaim,
  twin_divergence: TwinDivergenceClaim,
  dossier: DossierClaim,
  evidence_pack: EvidencePackClaim,
  operator_decision: OperatorDecisionClaim,
  operator_review: OperatorReviewClaim,
  external_proof_verification: ExternalProofVerificationClaim,
  authority_binding: AuthorityBindingClaim,
  authority_approval: AuthorityApprovalClaim,
  authority_use: AuthorityUseClaim,
  receiver_transaction_receipt: ReceiverTransactionReceiptClaim,
  authority_erasure_tombstone: AuthorityErasureTombstoneClaim,
} as const;

export type PassportClaimType = keyof typeof PASSPORT_CLAIM_SCHEMAS;
