import { describe, expect, it } from 'vitest';
import { agentAuthorityWidens, agentWeakenings } from './agents.js';

const current = {
  status: 'active',
  accountability_mode: 'enforced',
  on_warning: 'block',
  on_critical: 'block',
  credential_access: 'proxy_only',
  skill_access_mode: 'custom',
  allowed_skills: ['skill_safe'],
  identity_claim_ids: ['claim_existing'],
  twin_policy: 'always',
  llm_redact_pii: true,
  is_synthetic: false,
  eval_traffic: false,
};

describe('agent authority direction', () => {
  it('classifies reactivation, weaker controls, and staged authority as widening', () => {
    expect(agentAuthorityWidens({ ...current, status: 'suspended' }, { status: 'active' })).toBe(true);
    expect(agentAuthorityWidens(current, { accountability_mode: 'logged' })).toBe(true);
    expect(agentAuthorityWidens(current, { llm_redact_pii: false })).toBe(true);
    expect(agentAuthorityWidens(current, { eval_traffic: true })).toBe(true);
    expect(agentAuthorityWidens(current, { identity_claim_ids: ['claim_existing', 'claim_new'] })).toBe(true);
  });

  it('does not treat adding a skill or widening skill access as a widening: skills need no approval', () => {
    expect(agentAuthorityWidens(current, { allowed_skills: ['skill_safe', 'skill_new'] })).toBe(false);
    expect(agentAuthorityWidens(current, { skill_access_mode: 'all' })).toBe(false);
    expect(agentAuthorityWidens({ ...current, skill_access_mode: 'none' }, { skill_access_mode: 'custom' })).toBe(false);
  });

  it('keeps suspension, stronger controls, and permission removal immediate', () => {
    expect(agentAuthorityWidens(current, { status: 'suspended' })).toBe(false);
    expect(agentAuthorityWidens(current, { allowed_skills: [] })).toBe(false);
    expect(agentAuthorityWidens(current, { identity_claim_ids: [] })).toBe(false);
    expect(agentAuthorityWidens({ ...current, accountability_mode: 'logged' }, {
      accountability_mode: 'enforced',
    })).toBe(false);
  });
});

describe('credential access direction', () => {
  it('treats moving to a looser credential posture as a widening, and to a stricter one as not', () => {
    expect(agentAuthorityWidens(current, { credential_access: 'direct' })).toBe(true);
    expect(agentAuthorityWidens(current, { credential_access: 'proxy_preferred' })).toBe(true);
    expect(agentAuthorityWidens({ ...current, credential_access: 'proxy_preferred' }, { credential_access: 'direct' })).toBe(true);
    expect(agentAuthorityWidens({ ...current, credential_access: 'direct' }, { credential_access: 'proxy_only' })).toBe(false);
    expect(agentAuthorityWidens({ ...current, credential_access: 'direct' }, { credential_access: 'proxy_preferred' })).toBe(false);
    expect(agentAuthorityWidens(current, { credential_access: 'proxy_only' })).toBe(false);
  });
});

describe('agentWeakenings names each weakening in plain words', () => {
  it('is empty exactly when agentAuthorityWidens is false', () => {
    expect(agentWeakenings(current, {})).toEqual([]);
    expect(agentWeakenings(current, { status: 'suspended' })).toEqual([]);
    expect(agentWeakenings(current, { eval_traffic: true })).toHaveLength(1);
    expect(agentAuthorityWidens(current, { eval_traffic: true })).toBe(true);
  });
});

describe('the STACK system prompt setting asks nobody', () => {
  it('is accepted and ignored: switching it off is no weakening', () => {
    expect(agentWeakenings({ ...current, llm_inject_system_prompt: true }, { llm_inject_system_prompt: false })).toEqual([]);
    expect(agentAuthorityWidens({ ...current, llm_inject_system_prompt: true }, { llm_inject_system_prompt: false })).toBe(false);
  });
});
