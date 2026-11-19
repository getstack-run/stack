import { describe, expect, it } from 'vitest';
import { OperatorDecisionClaim } from './operator-decision.js';

const base = {
  type: 'operator_decision' as const,
  decision_id: 'odec_one',
  mission_ref: 'ms_one',
  operator_id: 'op_one',
  authored_by: { kind: 'operator_owner' as const, operator_id: 'op_one' },
  action: 'checkout_approved' as const,
  effect: 'checkout_released' as const,
  effect_scope: 'mission' as const,
  source_refs: {
    checkout_ids: ['cout_one'],
    security_event_ids: [],
    detector_claim_ids: [],
    approval_ids: [],
  },
  target_agent_id: 'agt_one',
  decided_at_ms: 1_766_000_000_000,
};

describe('OperatorDecisionClaim', () => {
  it('accepts owner and approved team-member authors', () => {
    expect(OperatorDecisionClaim.parse(base).authored_by).toEqual(base.authored_by);
    expect(OperatorDecisionClaim.parse({
      ...base,
      authored_by: {
        kind: 'team_member',
        member_id: 'mem_one',
        role_at_signing: 'standard',
      },
    }).authored_by).toEqual({
      kind: 'team_member',
      member_id: 'mem_one',
      role_at_signing: 'standard',
    });
  });

  it('rejects readonly authors and duplicate source references', () => {
    expect(OperatorDecisionClaim.safeParse({
      ...base,
      authored_by: {
        kind: 'team_member',
        member_id: 'mem_one',
        role_at_signing: 'readonly',
      },
    }).success).toBe(false);
    expect(OperatorDecisionClaim.safeParse({
      ...base,
      source_refs: {
        ...base.source_refs,
        checkout_ids: ['cout_one', 'cout_one'],
      },
    }).success).toBe(false);
  });

  it('requires at least one exact source reference', () => {
    expect(OperatorDecisionClaim.safeParse({
      ...base,
      source_refs: {
        checkout_ids: [],
        security_event_ids: [],
        detector_claim_ids: [],
        approval_ids: [],
      },
    }).success).toBe(false);
  });

  it('strips sensitive fields that are not part of the signed contract', () => {
    const parsed = OperatorDecisionClaim.parse({
      ...base,
      email: 'person@example.com',
      prompt: 'secret prompt',
      private_notes: 'secret notes',
    }) as Record<string, unknown>;
    expect(parsed).not.toHaveProperty('email');
    expect(parsed).not.toHaveProperty('prompt');
    expect(parsed).not.toHaveProperty('private_notes');
  });

  it('accepts the durable gvr_* governance approval id prefix', () => {
    expect(OperatorDecisionClaim.parse({
      ...base,
      action: 'governance_approved',
      effect: 'governance_approval_approved',
      source_refs: {
        checkout_ids: [],
        security_event_ids: [],
        detector_claim_ids: [],
        approval_ids: ['gvr_one'],
      },
    }).source_refs.approval_ids).toEqual(['gvr_one']);
  });

  it.each([
    ['checkout sources on a security action', {
      ...base,
      action: 'security_events_dismissed',
      effect: 'security_events_resolved',
    }],
    ['security sources on a checkout action', {
      ...base,
      source_refs: {
        checkout_ids: ['cout_one'],
        security_event_ids: ['sevt_one'],
        detector_claim_ids: ['pc_detector'],
        approval_ids: [],
      },
    }],
    ['a security action without its detector claim', {
      ...base,
      action: 'security_events_dismissed',
      effect: 'security_events_resolved',
      source_refs: {
        checkout_ids: [],
        security_event_ids: ['sevt_one'],
        detector_claim_ids: [],
        approval_ids: [],
      },
    }],
    ['a governance action with more than one approval', {
      ...base,
      action: 'governance_approved',
      effect: 'governance_approval_approved',
      source_refs: {
        checkout_ids: [],
        security_event_ids: [],
        detector_claim_ids: [],
        approval_ids: ['gvr_one', 'gvr_two'],
      },
    }],
  ])('rejects %s', (_name, claim) => {
    expect(OperatorDecisionClaim.safeParse(claim).success).toBe(false);
  });

  it.each([
    ['checkout_approved', 'agent_global'],
    ['checkout_blocked', 'mission'],
    ['security_events_dismissed', 'agent_global'],
    ['agent_suspended', 'mission'],
    ['future_warning_block_enabled', 'mission'],
    ['future_critical_block_enabled', 'mission'],
    ['governance_approved', 'agent_global'],
    ['governance_rejected', 'agent_global'],
  ] as const)('rejects the wrong effect scope for %s', (action, effectScope) => {
    const effectByAction = {
      checkout_approved: 'checkout_released',
      checkout_blocked: 'checkout_blocked_and_agent_blocked',
      security_events_dismissed: 'security_events_resolved',
      agent_suspended: 'agent_suspended_and_events_resolved',
      future_warning_block_enabled: 'checkouts_released_and_agent_warning_policy_set_to_block',
      future_critical_block_enabled: 'checkouts_released_and_agent_critical_policy_set_to_block',
      governance_approved: 'governance_approval_approved',
      governance_rejected: 'governance_approval_rejected',
    } as const;
    const sourceRefs = action.startsWith('governance_')
      ? { checkout_ids: [], security_event_ids: [], detector_claim_ids: [], approval_ids: ['gvr_one'] }
      : action === 'security_events_dismissed' || action === 'agent_suspended'
        ? { checkout_ids: [], security_event_ids: ['sevt_one'], detector_claim_ids: ['pc_detector'], approval_ids: [] }
        : base.source_refs;
    expect(OperatorDecisionClaim.safeParse({
      ...base,
      action,
      effect: effectByAction[action],
      effect_scope: effectScope,
      source_refs: sourceRefs,
    }).success).toBe(false);
  });

  it('requires a target agent for every currently supported action', () => {
    expect(OperatorDecisionClaim.safeParse({ ...base, target_agent_id: null }).success).toBe(false);
  });
});
