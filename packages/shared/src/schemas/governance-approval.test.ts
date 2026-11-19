import { describe, expect, it } from 'vitest';
import {
  GOVERNANCE_APPROVAL_TTL_SECONDS,
  GOVERNANCE_BROWSER_ONLY_ACTIONS,
  GovernanceActionEnum,
  GovernanceChatDecisionInput,
} from './governance-approval.js';

describe('governance action identities', () => {
  it('uses distinct auditable actions for authority mutations', () => {
    for (const action of [
      'agent_register',
      'agent_setup',
      'agent_authority_expand',
      'agent_skill_allow',
      'agent_key_enroll',
      'agent_enrollment_ticket_mint',
      'service_grant_expand',
      'service_proxy_disable',
      'service_allowed_hosts_expand',
      'intent_approve',
    ]) {
      expect(GovernanceActionEnum.parse(action)).toBe(action);
    }
    expect(GovernanceActionEnum.safeParse('service_data_flow_expand').success).toBe(false);
  });
});

describe('browser-only governance actions', () => {
  it('pins the exact set that can never be approved from a chat', () => {
    expect([...GOVERNANCE_BROWSER_ONLY_ACTIONS].sort()).toEqual([
      'account_control_loosen',
      'account_delete',
      'account_email_change',
      'billing_mutate',
      'control_review',
      'control_socket_change',
      'intent_approve_payment',
      'member_sso_binding_clear',
      'network_install_key_add',
      'sso_config_change',
      'sso_domain_add',
    ]);
  });

  it('keeps a held action out of the chat: it may be a payment, and a chat client only attests, it does not pay', () => {
    expect(GOVERNANCE_BROWSER_ONLY_ACTIONS.has('control_review')).toBe(true);
  });

  it('widening access to a connected service is confirmed in the chat: a grant, a host list and the combined setup', () => {
    for (const action of ['service_grant_expand', 'service_allowed_hosts_expand', 'agent_setup', 'agent_register', 'agent_authority_expand', 'intent_approve'] as const) {
      expect(GOVERNANCE_BROWSER_ONLY_ACTIONS.has(action), action).toBe(false);
    }
  });

  it('keeps an intent that can move money in the browser, and the other intent, identity and warning approvals in the chat', () => {
    expect(GOVERNANCE_BROWSER_ONLY_ACTIONS.has('intent_approve_payment')).toBe(true);
    for (const action of ['intent_approve', 'identity_settings_loosen', 'service_requirement_loosen', 'agent_warnings_dismiss'] as const) {
      expect(GovernanceActionEnum.safeParse(action).success, action).toBe(true);
      expect(GOVERNANCE_BROWSER_ONLY_ACTIONS.has(action), action).toBe(false);
    }
  });

  it('still keeps billing, a held action and the loosening of controls in the browser', () => {
    for (const action of ['billing_mutate', 'control_review', 'account_control_loosen', 'control_socket_change'] as const) {
      expect(GOVERNANCE_BROWSER_ONLY_ACTIONS.has(action), action).toBe(true);
    }
  });

  it('a print or making order is confirmed in the chat: the approval binds exactly that order and the customer own supplier account pays', () => {
    expect(GOVERNANCE_BROWSER_ONLY_ACTIONS.has('making_order_approve')).toBe(false);
    expect(GovernanceActionEnum.parse('making_order_approve')).toBe('making_order_approve');
  });

  it('names every browser-only action in the governance enum', () => {
    for (const action of GOVERNANCE_BROWSER_ONLY_ACTIONS) {
      expect(GovernanceActionEnum.parse(action)).toBe(action);
    }
  });
});

describe('governance approval lifetime', () => {
  it('gives a person at least a day to act on a link', () => {
    expect(GOVERNANCE_APPROVAL_TTL_SECONDS).toBeGreaterThanOrEqual(24 * 60 * 60);
  });
});

describe('chat decision input', () => {
  const hex = 'a'.repeat(64);

  it('accepts a rejection with no attestation', () => {
    expect(GovernanceChatDecisionInput.parse({ decision: 'reject' })).toEqual({ decision: 'reject' });
  });

  it('refuses unknown fields so nothing rides along unsigned', () => {
    expect(GovernanceChatDecisionInput.safeParse({ decision: 'reject', extra: 1 }).success).toBe(false);
  });

  it('refuses malformed attestation fields', () => {
    const base = {
      decision: 'approve',
      payload_hash: hex,
      mcp_session_hash: hex,
      elicitation_id: '3f2c1a4e-0b7d-4c55-9a1e-2d6f8b9c0a11',
      issued_at: 1_790_000_000,
      attestation: hex,
    };
    expect(GovernanceChatDecisionInput.safeParse(base).success).toBe(true);
    expect(GovernanceChatDecisionInput.safeParse({ ...base, attestation: 'short' }).success).toBe(false);
    expect(GovernanceChatDecisionInput.safeParse({ ...base, elicitation_id: 'not-a-uuid' }).success).toBe(false);
    expect(GovernanceChatDecisionInput.safeParse({ ...base, issued_at: -1 }).success).toBe(false);
  });
});
