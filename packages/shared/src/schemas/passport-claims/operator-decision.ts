import { z } from 'zod';

const unique = (values: readonly string[]) => new Set(values).size === values.length;

/**
 * The authenticated human that authorized a signed operator record.
 *
 * The operator organization signs the COSE claim. This field records the
 * human principal that authorized it. It never contains an email address.
 */
export const HumanOperatorAuthor = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('operator_owner'),
    operator_id: z.string().regex(/^op_[\w-]+$/, 'operator_id must be op_*'),
  }),
  z.object({
    kind: z.literal('team_member'),
    member_id: z.string().regex(/^mem_[\w-]+$/, 'member_id must be mem_*'),
    role_at_signing: z.enum(['standard', 'admin']),
  }),
]);
export type HumanOperatorAuthor = z.infer<typeof HumanOperatorAuthor>;

/**
 * a white-label partner's human deciding for one of its tenants.
 *
 * Tenants never have a human user, so a tenant's governance approvals are
 * decided by its partner's owner (member_id null) or an admin member of the
 * partner (member_id set) in the partner's dashboard session. The tenant's
 * organization still signs the claim; this field names the partner human.
 * Valid only on governance decisions, never on reviews or Home decisions.
 */
export const PartnerAdminAuthor = z.object({
  kind: z.literal('partner_admin'),
  partner_operator_id: z.string().regex(/^op_[\w-]+$/, 'partner_operator_id must be op_*'),
  member_id: z.string().regex(/^mem_[\w-]+$/, 'member_id must be mem_*').nullable(),
});
export type PartnerAdminAuthor = z.infer<typeof PartnerAdminAuthor>;

/** The human authors an operator_decision claim may name. */
export const OperatorDecisionAuthor = z.discriminatedUnion('kind', [
  ...HumanOperatorAuthor.options,
  PartnerAdminAuthor,
]);
export type OperatorDecisionAuthor = z.infer<typeof OperatorDecisionAuthor>;

export const OperatorDecisionAction = z.enum([
  'checkout_approved',
  'checkout_blocked',
  'security_events_dismissed',
  'agent_suspended',
  'future_warning_block_enabled',
  'future_critical_block_enabled',
  'governance_approved',
  'governance_rejected',
]);
export type OperatorDecisionAction = z.infer<typeof OperatorDecisionAction>;

export const OperatorDecisionEffect = z.enum([
  'checkout_released',
  'checkout_blocked_and_agent_blocked',
  'security_events_resolved',
  'agent_suspended_and_events_resolved',
  'checkouts_released_and_agent_warning_policy_set_to_block',
  'checkouts_released_and_agent_critical_policy_set_to_block',
  'governance_approval_approved',
  'governance_approval_rejected',
]);
export type OperatorDecisionEffect = z.infer<typeof OperatorDecisionEffect>;

export const OperatorDecisionSourceRefs = z.object({
  checkout_ids: z.array(z.string().regex(/^cout_[\w-]+$/)).max(100).default([]),
  security_event_ids: z.array(z.string().regex(/^sevt_[\w-]+$/)).max(100).default([]),
  detector_claim_ids: z.array(z.string().regex(/^pc_[\w-]+$/)).max(100).default([]),
  approval_ids: z.array(z.string().regex(/^gvr_[\w-]+$/)).max(100).default([]),
}).superRefine((refs, ctx) => {
  const groups = [
    refs.checkout_ids,
    refs.security_event_ids,
    refs.detector_claim_ids,
    refs.approval_ids,
  ];
  if (groups.every((items) => items.length === 0)) {
    ctx.addIssue({ code: 'custom', message: 'at least one source reference is required' });
  }
  if (groups.some((items) => !unique(items))) {
    ctx.addIssue({ code: 'custom', message: 'source references must not contain duplicates' });
  }
});
export type OperatorDecisionSourceRefs = z.infer<typeof OperatorDecisionSourceRefs>;

const ACTION_EFFECT: Record<OperatorDecisionAction, OperatorDecisionEffect> = {
  checkout_approved: 'checkout_released',
  checkout_blocked: 'checkout_blocked_and_agent_blocked',
  security_events_dismissed: 'security_events_resolved',
  agent_suspended: 'agent_suspended_and_events_resolved',
  future_warning_block_enabled: 'checkouts_released_and_agent_warning_policy_set_to_block',
  future_critical_block_enabled: 'checkouts_released_and_agent_critical_policy_set_to_block',
  governance_approved: 'governance_approval_approved',
  governance_rejected: 'governance_approval_rejected',
};

const ACTION_SCOPE: Record<OperatorDecisionAction, 'mission' | 'agent_global'> = {
  checkout_approved: 'mission',
  checkout_blocked: 'agent_global',
  security_events_dismissed: 'mission',
  agent_suspended: 'agent_global',
  future_warning_block_enabled: 'agent_global',
  future_critical_block_enabled: 'agent_global',
  governance_approved: 'mission',
  governance_rejected: 'mission',
};

/** A mission-bound and organization-signed Home decision. */
export const OperatorDecisionClaim = z.object({
  type: z.literal('operator_decision'),
  decision_id: z.string().regex(/^odec_[\w-]+$/, 'decision_id must be odec_*'),
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be ms_*'),
  operator_id: z.string().regex(/^op_[\w-]+$/, 'operator_id must be op_*'),
  authored_by: OperatorDecisionAuthor,
  action: OperatorDecisionAction,
  effect: OperatorDecisionEffect,
  effect_scope: z.enum(['mission', 'agent_global']),
  source_refs: OperatorDecisionSourceRefs,
  target_agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/).nullable(),
  decided_at_ms: z.number().int().nonnegative(),
}).superRefine((claim, ctx) => {
  if (ACTION_EFFECT[claim.action] !== claim.effect) {
    ctx.addIssue({ code: 'custom', path: ['effect'], message: 'effect does not match action' });
  }
  if (ACTION_SCOPE[claim.action] !== claim.effect_scope) {
    ctx.addIssue({ code: 'custom', path: ['effect_scope'], message: 'effect_scope does not match action' });
  }
  if (claim.target_agent_id === null) {
    ctx.addIssue({ code: 'custom', path: ['target_agent_id'], message: 'target_agent_id is required for this action' });
  }

  const refs = claim.source_refs;
  const checkoutAction = [
    'checkout_approved',
    'checkout_blocked',
    'future_warning_block_enabled',
    'future_critical_block_enabled',
  ].includes(claim.action);
  const securityAction = claim.action === 'security_events_dismissed' || claim.action === 'agent_suspended';
  const governanceAction = claim.action === 'governance_approved' || claim.action === 'governance_rejected';
  if (claim.authored_by.kind === 'partner_admin' && !governanceAction) {
    ctx.addIssue({ code: 'custom', path: ['authored_by'], message: 'a partner may author only governance decisions' });
  }
  if (
    checkoutAction
    && (
      refs.checkout_ids.length === 0
      || refs.security_event_ids.length > 0
      || refs.detector_claim_ids.length > 0
      || refs.approval_ids.length > 0
    )
  ) {
    ctx.addIssue({ code: 'custom', path: ['source_refs'], message: 'checkout action requires only checkout sources' });
  }
  if (
    securityAction
    && (
      refs.checkout_ids.length > 0
      || refs.security_event_ids.length === 0
      || refs.detector_claim_ids.length !== refs.security_event_ids.length
      || refs.approval_ids.length > 0
    )
  ) {
    ctx.addIssue({ code: 'custom', path: ['source_refs'], message: 'security action requires one detector claim per security event' });
  }
  if (
    governanceAction
    && (
      refs.checkout_ids.length > 0
      || refs.security_event_ids.length > 0
      || refs.detector_claim_ids.length > 0
      || refs.approval_ids.length !== 1
    )
  ) {
    ctx.addIssue({ code: 'custom', path: ['source_refs'], message: 'governance action requires one approval source' });
  }
});
export type OperatorDecisionClaim = z.infer<typeof OperatorDecisionClaim>;
