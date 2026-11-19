import { describe, expect, it } from 'vitest';
import {
  authorityConstraintIsNarrower,
  authorityDelegationViolations,
  authorityScopeIsNarrower,
  disclosurePolicyIsNarrower,
} from './authority-policy.js';

const parentScope = {
  actions: [{
    action_uri: 'urn:example:payments:submit',
    resource_refs: ['acct:a', 'acct:b'],
    constraints: [
      { path: 'amount', op: 'lte' as const, value: 1_000 },
      { path: 'currency', op: 'in' as const, value: ['EUR', 'SEK'] },
    ],
  }],
  limits: { total: 5_000, counterparties: ['alice', 'bob'] },
};

const parentDisclosure = {
  rules: [{
    fact_id: 'person.identifier',
    mode: 'exact_private' as const,
    required: true,
  }],
  principal_confirmation_required: true,
  max_retention_seconds: 86_400,
  live_status_required: true,
};

describe('authority monotonic delegation policy', () => {
  it('accepts stronger numeric and set constraints', () => {
    expect(authorityConstraintIsNarrower(
      { path: 'amount', op: 'lte', value: 500 },
      { path: 'amount', op: 'lte', value: 1_000 },
    )).toBe(true);
    expect(authorityConstraintIsNarrower(
      { path: 'currency', op: 'in', value: ['EUR'] },
      { path: 'currency', op: 'in', value: ['EUR', 'SEK'] },
    )).toBe(true);
  });

  it('refuses constraints it cannot prove are narrower', () => {
    expect(authorityConstraintIsNarrower(
      { path: 'amount', op: 'lte', value: 2_000 },
      { path: 'amount', op: 'lte', value: 1_000 },
    )).toBe(false);
    expect(authorityConstraintIsNarrower(
      { path: 'amount', op: 'lte', value_ref: 'fact:new' },
      { path: 'amount', op: 'lte', value_ref: 'fact:old' },
    )).toBe(false);
  });

  it('accepts narrower actions while inheriting opaque limits exactly', () => {
    expect(authorityScopeIsNarrower({
      actions: [{
        action_uri: 'urn:example:payments:submit',
        resource_refs: ['acct:a'],
        constraints: [
          { path: 'amount', op: 'lte', value: 500 },
          { path: 'currency', op: 'eq', value: 'EUR' },
        ],
      }],
      limits: parentScope.limits,
    }, parentScope)).toBe(true);
  });

  it('refuses an empty child resource set when the parent is restricted', () => {
    expect(authorityScopeIsNarrower({
      actions: [{
        action_uri: 'urn:example:payments:submit',
        resource_refs: [],
        constraints: parentScope.actions[0]!.constraints,
      }],
      limits: parentScope.limits,
    }, parentScope)).toBe(false);
  });

  it('does not infer direction for opaque numeric limits', () => {
    expect(authorityScopeIsNarrower({
      ...parentScope,
      limits: { total: 2_000, counterparties: ['alice', 'bob'] },
    }, parentScope)).toBe(false);
  });

  it('refuses a new action, resource, or larger generic limit', () => {
    expect(authorityScopeIsNarrower({
      actions: [{
        action_uri: 'urn:example:payments:submit',
        resource_refs: ['acct:c'],
        constraints: parentScope.actions[0]!.constraints,
      }],
      limits: { total: 6_000, counterparties: ['alice'] },
    }, parentScope)).toBe(false);
  });

  it('allows less revealing disclosure but preserves confirmation, status, and retention', () => {
    expect(disclosurePolicyIsNarrower({
      rules: [{ fact_id: 'person.identifier', mode: 'predicate', required: true }],
      principal_confirmation_required: true,
      max_retention_seconds: 3_600,
      live_status_required: true,
    }, parentDisclosure)).toBe(true);
    expect(disclosurePolicyIsNarrower({
      ...parentDisclosure,
      principal_confirmation_required: false,
    }, parentDisclosure)).toBe(false);
  });

  it('uses a conservative disclosure-mode matrix and never guesses issuer-evidence transforms', () => {
    const policy = (mode: 'issuer_evidence' | 'exact_private' | 'pairwise' | 'predicate' | 'status_only') => ({
      ...parentDisclosure,
      rules: [{ fact_id: 'person.identifier', mode, required: true }],
    });
    expect(disclosurePolicyIsNarrower(policy('issuer_evidence'), policy('issuer_evidence'))).toBe(true);
    expect(disclosurePolicyIsNarrower(policy('status_only'), policy('issuer_evidence'))).toBe(false);
    expect(disclosurePolicyIsNarrower(policy('pairwise'), policy('exact_private'))).toBe(true);
    expect(disclosurePolicyIsNarrower(policy('predicate'), policy('pairwise'))).toBe(true);
    expect(disclosurePolicyIsNarrower(policy('status_only'), policy('predicate'))).toBe(true);
    expect(disclosurePolicyIsNarrower(policy('exact_private'), policy('predicate'))).toBe(false);
  });

  it('reports every widened delegation dimension', () => {
    const violations = authorityDelegationViolations({
      scope: {
        actions: [{
          action_uri: 'urn:example:payments:submit',
          resource_refs: ['acct:c'],
          constraints: [],
        }],
        limits: { total: 10_000 },
      },
      disclosurePolicy: {
        ...parentDisclosure,
        principal_confirmation_required: false,
      },
      validFrom: new Date('2026-01-01T00:00:00Z'),
      expiresAt: new Date('2028-01-01T00:00:00Z'),
      allowFurtherDelegation: true,
      maxDelegationDepth: 4,
    }, {
      scope: parentScope,
      disclosurePolicy: parentDisclosure,
      validFrom: new Date('2026-06-01T00:00:00Z'),
      expiresAt: new Date('2027-01-01T00:00:00Z'),
      allowFurtherDelegation: false,
      maxDelegationDepth: 1,
    });

    expect(violations).toEqual(expect.arrayContaining([
      'scope_widened',
      'disclosure_widened',
      'validity_started_earlier',
      'validity_extended',
      'delegation_not_allowed',
      'further_delegation_widened',
      'delegation_depth_widened',
    ]));
  });
});
