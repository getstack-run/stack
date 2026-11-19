import { z } from 'zod';
import { HumanOperatorAuthor } from './operator-decision.js';

const uniqueBy = <T>(items: readonly T[], select: (item: T) => string) =>
  new Set(items.map(select)).size === items.length;

const reviewText = z.string().trim().min(1, 'review text is required').max(50_000, 'review text must be <= 50,000 characters');
const noteText = z.string().trim().min(1, 'source note is required').max(10_000, 'source note must be <= 10,000 characters');

export const OperatorReviewCheckpointNote = z.object({
  checkpoint_claim_id: z.string().regex(/^pc_[\w-]+$/, 'checkpoint_claim_id must be pc_*'),
  note: noteText,
});

export const OperatorReviewDecisionRationale = z.object({
  operator_decision_claim_id: z.string().regex(/^pc_[\w-]+$/, 'operator_decision_claim_id must be pc_*'),
  rationale: noteText,
});

export const OperatorReviewAlertExplanation = z.object({
  detector_claim_id: z.string().regex(/^pc_[\w-]+$/, 'detector_claim_id must be pc_*'),
  explanation: noteText,
});

const OperatorReviewClaimFields = z.object({
  type: z.literal('operator_review'),
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be ms_*'),
  operator_id: z.string().regex(/^op_[\w-]+$/, 'operator_id must be op_*'),
  authored_by: HumanOperatorAuthor,
  authored_at_ms: z.number().int().nonnegative(),
  overall_judgment: reviewText,
  checkpoint_notes: z.array(OperatorReviewCheckpointNote).max(500).default([]),
  decision_rationales: z.array(OperatorReviewDecisionRationale).max(500).default([]),
  alert_explanations: z.array(OperatorReviewAlertExplanation).max(500).default([]),
  incident_classification: z.enum([
    'no_incident',
    'false_positive',
    'true_positive_handled',
    'true_positive_escalated',
    'inconclusive',
  ]),
  lessons_learned: reviewText,
  prior_review_ref: z.string().regex(/^pc_[\w-]+$/, 'prior_review_ref must be pc_*').nullable(),
  assessment_basis: z.literal('operator_organization_assessment'),
});

/** The operator organization's immutable post-mission assessment. */
export const OperatorReviewClaim = OperatorReviewClaimFields.superRefine((claim, ctx) => {
  if (!uniqueBy(claim.checkpoint_notes, (item) => item.checkpoint_claim_id)) {
    ctx.addIssue({ code: 'custom', path: ['checkpoint_notes'], message: 'checkpoint references must be unique' });
  }
  if (!uniqueBy(claim.decision_rationales, (item) => item.operator_decision_claim_id)) {
    ctx.addIssue({ code: 'custom', path: ['decision_rationales'], message: 'decision references must be unique' });
  }
  if (!uniqueBy(claim.alert_explanations, (item) => item.detector_claim_id)) {
    ctx.addIssue({ code: 'custom', path: ['alert_explanations'], message: 'detector references must be unique' });
  }
});
export type OperatorReviewClaim = z.infer<typeof OperatorReviewClaim>;

export const OperatorReviewInput = OperatorReviewClaimFields.pick({
  overall_judgment: true,
  checkpoint_notes: true,
  decision_rationales: true,
  alert_explanations: true,
  incident_classification: true,
  lessons_learned: true,
});
export type OperatorReviewInput = z.infer<typeof OperatorReviewInput>;
