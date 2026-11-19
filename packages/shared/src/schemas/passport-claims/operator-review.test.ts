import { describe, expect, it } from 'vitest';
import { OperatorReviewClaim } from './operator-review.js';

const base = {
  type: 'operator_review' as const,
  mission_ref: 'ms_one',
  operator_id: 'op_one',
  authored_by: { kind: 'operator_owner' as const, operator_id: 'op_one' },
  authored_at_ms: 1_766_000_000_000,
  overall_judgment: 'The mission met its declared purpose.',
  checkpoint_notes: [
    { checkpoint_claim_id: 'pc_checkpoint', note: 'The checkpoint matched the signed activity.' },
  ],
  decision_rationales: [
    { operator_decision_claim_id: 'pc_decision', rationale: 'The operator accepted the result.' },
  ],
  alert_explanations: [
    { detector_claim_id: 'pc_detector', explanation: 'The alert was expected and contained.' },
  ],
  incident_classification: 'no_incident' as const,
  lessons_learned: 'Keep the same mission cap.',
  prior_review_ref: null,
  assessment_basis: 'operator_organization_assessment' as const,
};

describe('OperatorReviewClaim', () => {
  it('accepts an owner author and an approved team-member author', () => {
    expect(OperatorReviewClaim.parse(base).authored_by).toEqual(base.authored_by);
    expect(OperatorReviewClaim.parse({
      ...base,
      authored_by: {
        kind: 'team_member',
        member_id: 'mem_admin',
        role_at_signing: 'admin',
      },
    }).authored_by).toEqual({
      kind: 'team_member',
      member_id: 'mem_admin',
      role_at_signing: 'admin',
    });
  });

  it('rejects readonly authors and duplicate exact references', () => {
    expect(OperatorReviewClaim.safeParse({
      ...base,
      authored_by: {
        kind: 'team_member',
        member_id: 'mem_readonly',
        role_at_signing: 'readonly',
      },
    }).success).toBe(false);
    expect(OperatorReviewClaim.safeParse({
      ...base,
      decision_rationales: [
        ...base.decision_rationales,
        base.decision_rationales[0],
      ],
    }).success).toBe(false);
  });

  it('requires typed claim ids for every source reference', () => {
    expect(OperatorReviewClaim.safeParse({
      ...base,
      checkpoint_notes: [{ checkpoint_claim_id: 'chk_row', note: 'Wrong source type.' }],
    }).success).toBe(false);
  });

  it.each(['', '   ', '\n\t'])('rejects blank required review text', (blank) => {
    expect(OperatorReviewClaim.safeParse({ ...base, overall_judgment: blank }).success).toBe(false);
    expect(OperatorReviewClaim.safeParse({ ...base, lessons_learned: blank }).success).toBe(false);
  });

  it.each(['', '   ', '\n\t'])('rejects blank source notes', (blank) => {
    expect(OperatorReviewClaim.safeParse({
      ...base,
      checkpoint_notes: [{ ...base.checkpoint_notes[0], note: blank }],
    }).success).toBe(false);
    expect(OperatorReviewClaim.safeParse({
      ...base,
      decision_rationales: [{ ...base.decision_rationales[0], rationale: blank }],
    }).success).toBe(false);
    expect(OperatorReviewClaim.safeParse({
      ...base,
      alert_explanations: [{ ...base.alert_explanations[0], explanation: blank }],
    }).success).toBe(false);
  });

  it('strips client-supplied author facts and sensitive extras', () => {
    const parsed = OperatorReviewClaim.parse({
      ...base,
      email: 'person@example.com',
      prompt: 'secret prompt',
      private_notes: 'secret notes',
    }) as Record<string, unknown>;
    expect(parsed).not.toHaveProperty('email');
    expect(parsed).not.toHaveProperty('prompt');
    expect(parsed).not.toHaveProperty('private_notes');
  });
});
