import { canonicalize, type AuthorityConstraint, type AuthorityDisclosurePolicy, type AuthorityScope } from '@stack/shared';

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function same(a: unknown, b: unknown): boolean {
  return canonicalize(a) === canonicalize(b);
}

function primitiveArray(value: unknown): Array<string | number | boolean> | null {
  if (!Array.isArray(value)) return null;
  return value.every((item) => ['string', 'number', 'boolean'].includes(typeof item))
    ? value as Array<string | number | boolean>
    : null;
}

function arraySubset(child: unknown, parent: unknown): boolean {
  const childValues = primitiveArray(child);
  const parentValues = primitiveArray(parent);
  if (!childValues || !parentValues) return false;
  return childValues.every((item) => parentValues.some((candidate) => same(item, candidate)));
}

function numeric(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/**
 * Returns true when the child constraint accepts no value that the parent
 * would reject. Opaque value references can only be inherited exactly: the
 * service cannot safely reason about plaintext it deliberately cannot see.
 */
export function authorityConstraintIsNarrower(
  child: AuthorityConstraint,
  parent: AuthorityConstraint,
): boolean {
  if (child.path !== parent.path) return false;
  if (child.value_ref !== undefined || parent.value_ref !== undefined) {
    return child.op === parent.op && child.value_ref === parent.value_ref;
  }
  if (same(child, parent)) return true;

  const childNumber = numeric(child.value);
  const parentNumber = numeric(parent.value);

  if (child.op === 'eq') {
    if (parent.op === 'in') return primitiveArray(parent.value)?.some((v) => same(v, child.value)) ?? false;
    if (childNumber !== null && parentNumber !== null) {
      if (parent.op === 'lt') return childNumber < parentNumber;
      if (parent.op === 'lte') return childNumber <= parentNumber;
      if (parent.op === 'gt') return childNumber > parentNumber;
      if (parent.op === 'gte') return childNumber >= parentNumber;
    }
    return false;
  }

  if (child.op === 'in' && parent.op === 'in') return arraySubset(child.value, parent.value);
  if (child.op === 'not_in' && parent.op === 'not_in') return arraySubset(parent.value, child.value);
  if (child.op === 'not_eq' && parent.op === 'not_eq') return same(child.value, parent.value);
  if (child.op === 'not_in' && parent.op === 'not_eq') {
    return primitiveArray(child.value)?.some((v) => same(v, parent.value)) ?? false;
  }

  if (childNumber !== null && parentNumber !== null) {
    if ((child.op === 'lt' || child.op === 'lte') && (parent.op === 'lt' || parent.op === 'lte')) {
      if (childNumber < parentNumber) return true;
      return childNumber === parentNumber && (child.op === 'lt' || parent.op === 'lte');
    }
    if ((child.op === 'gt' || child.op === 'gte') && (parent.op === 'gt' || parent.op === 'gte')) {
      if (childNumber > parentNumber) return true;
      return childNumber === parentNumber && (child.op === 'gt' || parent.op === 'gte');
    }
  }

  return child.op === parent.op
    && (child.op === 'exists' || child.op === 'not_exists');
}

function constraintSetIsNarrower(
  child: AuthorityConstraint[],
  parent: AuthorityConstraint[],
): boolean {
  return parent.every((parentConstraint) =>
    child.some((childConstraint) => authorityConstraintIsNarrower(childConstraint, parentConstraint)));
}

function genericValueIsNarrower(child: JsonValue, parent: JsonValue): boolean {
  // Generic code cannot know whether a smaller number strengthens a maximum
  // or weakens a minimum. Opaque domain limits are inherited exactly.
  return same(child, parent);
}

/** Domain-neutral fail-closed comparison for a delegated authority scope. */
export function authorityScopeIsNarrower(child: AuthorityScope, parent: AuthorityScope): boolean {
  if (!genericValueIsNarrower(child.limits as JsonValue, parent.limits as JsonValue)) return false;

  return child.actions.every((childAction) => {
    const parentAction = parent.actions.find((candidate) => candidate.action_uri === childAction.action_uri);
    if (!parentAction) return false;
    if (
      parentAction.resource_refs.length > 0
      && (childAction.resource_refs.length === 0
        || !childAction.resource_refs.every((resource) => parentAction.resource_refs.includes(resource)))
    ) return false;
    return constraintSetIsNarrower(childAction.constraints, parentAction.constraints);
  });
}

const DISCLOSURE_NARROWING: Record<string, ReadonlySet<string>> = {
  // Native issuer evidence is format-specific. Generic policy cannot prove
  // that transforming it to any other mode preserves its meaning.
  issuer_evidence: new Set(['issuer_evidence']),
  exact_private: new Set(['exact_private', 'pairwise', 'predicate', 'status_only']),
  pairwise: new Set(['pairwise', 'predicate', 'status_only']),
  predicate: new Set(['predicate', 'status_only']),
  status_only: new Set(['status_only']),
};

/** Delegation may remove disclosures or choose a strictly less revealing mode. */
export function disclosurePolicyIsNarrower(
  child: AuthorityDisclosurePolicy,
  parent: AuthorityDisclosurePolicy,
): boolean {
  if (parent.principal_confirmation_required && !child.principal_confirmation_required) return false;
  if (parent.live_status_required && !child.live_status_required) return false;
  if (parent.max_retention_seconds !== null) {
    if (child.max_retention_seconds === null) return false;
    if (child.max_retention_seconds > parent.max_retention_seconds) return false;
  }

  return child.rules.every((childRule) => {
    const parentRule = parent.rules.find((candidate) =>
      candidate.fact_id === childRule.fact_id
      && candidate.profile_version_id === childRule.profile_version_id);
    if (!parentRule) return false;
    if (parentRule.required && !childRule.required) return false;
    return DISCLOSURE_NARROWING[parentRule.mode]?.has(childRule.mode) ?? false;
  });
}

export interface AuthorityDelegationCandidate {
  scope: AuthorityScope;
  disclosurePolicy: AuthorityDisclosurePolicy;
  validFrom: Date;
  expiresAt: Date;
  allowFurtherDelegation: boolean;
  maxDelegationDepth: number;
}

export function authorityDelegationViolations(
  child: AuthorityDelegationCandidate,
  parent: AuthorityDelegationCandidate,
): string[] {
  const violations: string[] = [];
  if (!authorityScopeIsNarrower(child.scope, parent.scope)) violations.push('scope_widened');
  if (!disclosurePolicyIsNarrower(child.disclosurePolicy, parent.disclosurePolicy)) {
    violations.push('disclosure_widened');
  }
  if (child.validFrom < parent.validFrom) violations.push('validity_started_earlier');
  if (child.expiresAt > parent.expiresAt) violations.push('validity_extended');
  if (!parent.allowFurtherDelegation) violations.push('delegation_not_allowed');
  if (child.allowFurtherDelegation && !parent.allowFurtherDelegation) {
    violations.push('further_delegation_widened');
  }
  if (child.maxDelegationDepth > parent.maxDelegationDepth) {
    violations.push('delegation_depth_widened');
  }
  return [...new Set(violations)];
}
