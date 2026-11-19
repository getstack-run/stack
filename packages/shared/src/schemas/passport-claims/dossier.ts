/**
 * DossierClaim.
 *
 * Human-curated post-mortem narrative for one mission. The operator's
 * voice on what happened, why decisions were made at each checkpoint,
 * how alerts were handled, and what was learned. A dossier is argument
 * and interpretation, NOT evidence. The evidence is the underlying
 * signed claims (intent_claim, intent_outcome, detector_signal,
 * checkpoint_approval). The dossier annotates that evidence with
 * operator narrative.
 *
 * Mission-scoped only — no period dossiers, no operator-level dossiers.
 * The unit of post-mortem is a mission because a mission is the unit
 * of bounded agent activity with a clear terminal state.
 *
 * Authored by a member of the operator's org via the dashboard
 * (`POST v1 missions id dossier`). DossierService
 * validates the mission is in a terminal state
 * (`completed_*` or `revoked_*`) before accepting the claim.
 *
 * Claims are immutable — editing a dossier emits a NEW DossierClaim
 * whose `prior_dossier_ref` points at the previous version. The latest
 * version for a mission is the one with no successor. Same chain
 * pattern as BehavioralGenomeClaim.prior_genome_ref (5.1.1).
 *
 * A controls feature: the dossier routes refuse an account without
 * controls (CONTROLS_REQUIRED); the registry itself signs any type.
 *
 * ADR: the evidence pack design Design decision 1 locks
 * the dossier/evidence-pack/replay distinction. A DossierClaim is one
 * of the claim types that CAN be carried inside an evidence pack
 * . The pack carries the envelope; the verifier treats
 * it structurally the same as any other claim envelope. The verifier
 * does NOT promote the dossier's narrative to evidence — the dossier
 * remains operator-authored interpretation in any forensic context.
 */

import { z } from 'zod';

/**
 * One row in the `decision_tree` array. Each entry annotates one
 * checkpoint inside the mission with the operator's after-the-fact
 * read on the decision made at that checkpoint. The decision field is
 * free-form because checkpoints have varied outcomes (approved /
 * rejected / auto-approved / dropped) and producers may want to record
 * a more specific human label ("approved with caveat", "rejected and
 * follow-up filed").
 *
 * `checkpoint_id` binds the decision to a real
 * `passport_checkpoints.id` row (chk_*). Same prefix shape as
 * CheckpointApprovalClaim.checkpoint_id.
 */
export const DossierDecisionEntry = z.object({
  /** passport_checkpoints.id — the checkpoint this entry annotates. */
  checkpoint_id: z.string().regex(/^chk_[\w-]+$/, 'checkpoint_id must be a passport_checkpoints id (chk_*)'),

  /** Operator's label for the decision made at the checkpoint. */
  decision: z.string().min(1).max(256),

  /**
   * Free-form rationale. Why was the decision made the way it was?
   * What context did the operator have at the time? Max 4096 chars
   * per entry to keep the decision tree readable.
   */
  rationale: z.string().max(4096),
});
export type DossierDecisionEntry = z.infer<typeof DossierDecisionEntry>;

/**
 * One row in the `alerts_walkthrough` array. Walks one detector fire
 * during the mission. `detector_signal_claim_id` binds to the
 * underlying DetectorSignalClaim (pc_*) — the verifier can confirm the
 * dossier's walkthrough actually refers to a real signed claim.
 *
 * Severity duplicates the detector_signal's severity field. Stored on
 * the walkthrough entry so a verifier reading the dossier in isolation
 * does not need to dereference every detector_signal envelope to
 * render the walkthrough. Matches the
 * `'low' | 'medium' | 'high' | 'critical'` shape from
 * DetectorSignalClaim.severity at detector-signal.ts:43.
 */
export const DossierAlertEntry = z.object({
  /** The DetectorSignalClaim being walked through (pc_*). */
  detector_signal_claim_id: z.string().regex(/^pc_[\w-]+$/, 'detector_signal_claim_id must be a passport-claim id (pc_*)'),

  /** Severity duplicated from the referenced detector_signal claim. */
  severity: z.enum(['low', 'medium', 'high', 'critical']),

  /**
   * Operator's narrative on this specific alert. What did it mean,
   * was it handled, was it a false positive, what did the response
   * look like. Max 8192 chars per entry.
   */
  narrative: z.string().max(8192),
});
export type DossierAlertEntry = z.infer<typeof DossierAlertEntry>;

/**
 * IncidentClassification — operator's final read on what happened
 * during the mission.
 *
 *   - `false_positive`: alerts fired but the agent's actions were
 *     legitimate. Useful for detector tuning feedback.
 *   - `true_positive_handled`: real adversarial or anomalous behaviour
 *     occurred and the operator handled it inside the mission lifecycle
 *     (revoke, scope tighten, agent shutdown).
 *   - `true_positive_escalated`: real incident occurred AND was
 *     escalated outside the mission lifecycle (incident-response page,
 *     legal review, regulator notification, customer comms).
 *   - `inconclusive`: not enough evidence to decide either way. Common
 *     when alerts fire on edge-case agent behaviour that COULD be
 *     adversarial but COULD also be a novel legitimate workflow.
 *
 * Additive enum — future incident classifications ship as new values
 * (e.g. a `near_miss` class if the operator wants to distinguish
 * "would-have-fired-but-policy-caught-it" from `true_positive_handled`).
 * Existing consumers MUST default to a graceful handler for unknown
 * values.
 */
export const IncidentClassification = z.enum([
  'false_positive',
  'true_positive_handled',
  'true_positive_escalated',
  'inconclusive',
]);
export type IncidentClassification = z.infer<typeof IncidentClassification>;

/**
 * DossierClaim — mission-scoped human-authored post-mortem.
 */
export const DossierClaim = z.object({
  type: z.literal('dossier'),

  /**
   * REQUIRED — dossiers are mission-scoped only; no period dossiers,
   * no operator-level dossiers. Same prefix shape as
   * TwinDivergenceClaim.mission_ref (ms_*).
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission id (ms_*)'),

  /**
   * team_members.id of the operator-org member who authored this
   * dossier. Bound here so a verifier looking at an exported pack can
   * see who in the org wrote the narrative without dereferencing
   * external state. `mem_*` prefix per shared/utils/index.ts ids.
   */
  authored_by_member_id: z.string().regex(/^mem_[\w-]+$/, 'authored_by_member_id must be a team_members id (mem_*)'),

  /** unix ms when the operator wrote (or last edited) this dossier. */
  authored_at_ms: z.number().int().nonnegative(),

  /**
   * Markdown narrative — the body of the post-mortem. 50 KB
   * (50,000 chars) cap. Bounded so a single dossier cannot bloat a
   * pack or exhaust dashboard renderers. Markdown rendering happens
   * on the consumer side; the schema validates length only.
   */
  narrative: z.string().max(50_000, 'narrative must be <= 50,000 chars (~50 KB)'),

  /**
   * Sequence of checkpoint-level decisions taken during the mission.
   * Default empty for missions with no checkpoints (very short
   * missions, missions on accountability-mode `standard` agents).
   */
  decision_tree: z.array(DossierDecisionEntry).default([]),

  /**
   * Walkthrough of detector fires during the mission. Default empty
   * for missions where no detector fired. The verifier can confirm
   * each entry's `detector_signal_claim_id` resolves to a real
   * DetectorSignalClaim in the pack or the operator's claim registry.
   */
  alerts_walkthrough: z.array(DossierAlertEntry).default([]),

  /**
   * What was learned, what should change, what to look for next time.
   * Required string but empty is allowed for dossiers where the
   * operator has nothing to add beyond the narrative. Max 50 KB
   * matches `narrative`.
   */
  lessons_learned: z.string().max(50_000, 'lessons_learned must be <= 50,000 chars (~50 KB)'),

  /** Operator's final read on the mission. See IncidentClassification. */
  incident_classification: IncidentClassification,

  /**
   * Claim id (pc_*) of the previous dossier for this mission, or null
   * if this is the first. Dossier edits emit a new claim that points
   * at the prior version via this field (DossierService.update in
   * The latest dossier for a mission is the one
   * with no successor in the registry. Same chain-pointer pattern as
   * BehavioralGenomeClaim.prior_genome_ref (5.1.1).
   */
  prior_dossier_ref: z.string().regex(/^pc_[\w-]+$/, 'prior_dossier_ref must be a passport-claim id (pc_*)').nullable(),
});

export type DossierClaim = z.infer<typeof DossierClaim>;
