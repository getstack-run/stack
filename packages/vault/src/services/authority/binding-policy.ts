/** Static policy checks applied when a binding is created. */
import {
  ForbiddenError,
  type AuthorityDisclosurePolicy,
  type CreateAuthorityBindingInput,
} from '@stack/shared';
import { parseAuthorityApprovalPolicy } from './approval-policy.js';

export const PROOF_KINDS_BY_ASSIGNMENT_ROLE: Record<
  CreateAuthorityBindingInput['proofs'][number]['role'],
  readonly string[]
> = {
  principal_identity: ['identity'],
  authoriser_identity: ['identity'],
  authoriser_capacity: ['capacity'],
  // A separately-typed consent or signature may itself be the exact-terms
  // authority instrument. Its source semantics remain visible on the proof.
  mandate: ['mandate', 'consent', 'signature'],
  consent: ['consent'],
  domain: ['domain'],
};

export function assertApprovalPolicyAssignments(
  policy: Record<string, unknown>,
  assignments: CreateAuthorityBindingInput['proofs'],
): void {
  const groups = parseAuthorityApprovalPolicy(policy);
  const seen = new Set<string>();
  for (const group of groups) {
    const key = group.group_key;
    const requiredWeight = group.required_weight;
    seen.add(key);
    const eligible = assignments.filter(
      (item) =>
        item.group_key === key &&
        (item.role === 'authoriser_identity' || item.role === 'authoriser_capacity'),
    );
    const authoriserWeights = new Map<string, number>();
    for (const item of eligible) {
      const authoriser = item.authoriser_principal_id!;
      authoriserWeights.set(
        authoriser,
        Math.max(authoriserWeights.get(authoriser) ?? 0, item.weight),
      );
    }
    const availableWeight = [...authoriserWeights.values()].reduce(
      (sum, weight) => sum + weight,
      0,
    );
    if (availableWeight < requiredWeight)
      throw new ForbiddenError('authority approval threshold exceeds assigned authoriser weight');
  }
  if (
    assignments.some((item) => item.group_key && !seen.has(item.group_key)) &&
    groups.length > 0
  ) {
    throw new ForbiddenError('authority proof assignment references an unknown approval group');
  }
}

export function assertReceiverApprovalRequirements(
  bindingPolicy: unknown,
  receiverPolicy: unknown,
): void {
  const bindingGroups = parseAuthorityApprovalPolicy(bindingPolicy);
  const receiverGroups = parseAuthorityApprovalPolicy(receiverPolicy);
  for (const receiver of receiverGroups) {
    const binding = bindingGroups.find(
      (candidate) =>
        candidate.phase === receiver.phase && candidate.group_key === receiver.group_key,
    );
    if (
      !binding ||
      binding.required_weight < receiver.required_weight ||
      (receiver.reject_mode === 'any_reject' && binding.reject_mode !== 'any_reject') ||
      binding.maximum_age_seconds > receiver.maximum_age_seconds ||
      (receiver.final_step && !binding.final_step)
    ) {
      throw new ForbiddenError(
        'binding approval policy does not satisfy the pinned receiver requirements',
      );
    }
  }
}

export function assertDisclosurePolicySatisfiesReceiver(
  disclosurePolicy: AuthorityDisclosurePolicy,
  approvalPolicy: unknown,
  receiverConfig: Record<string, unknown>,
): void {
  const receiverFacts = (receiverConfig.required_facts as Array<Record<string, unknown>>) ?? [];
  const bindingRules = new Map(disclosurePolicy.rules.map((rule) => [rule.fact_id, rule]));
  for (const receiverFact of receiverFacts) {
    const factId = String(receiverFact.fact_id ?? '');
    const bindingRule = bindingRules.get(factId);
    const allowedModes = (receiverFact.allowed_modes as string[]) ?? [];
    if (!bindingRule || !bindingRule.required || !allowedModes.includes(bindingRule.mode)) {
      throw new ForbiddenError(
        'binding disclosure policy does not satisfy the pinned receiver facts',
      );
    }
    const retention = receiverFact.retention_rule;
    if (
      !retention ||
      typeof retention !== 'object' ||
      Array.isArray(retention) ||
      Object.keys(retention).some((key) => key !== 'maximum_seconds')
    ) {
      throw new ForbiddenError('receiver fact retention policy is invalid or unsupported');
    }
    const maximumSeconds = Number((retention as Record<string, unknown>).maximum_seconds);
    if (
      !Number.isSafeInteger(maximumSeconds) ||
      maximumSeconds < 0 ||
      (disclosurePolicy.max_retention_seconds !== null &&
        maximumSeconds > disclosurePolicy.max_retention_seconds)
    ) {
      throw new ForbiddenError('receiver fact retention exceeds the binding disclosure policy');
    }
  }
  if (disclosurePolicy.principal_confirmation_required) {
    const groups = parseAuthorityApprovalPolicy(approvalPolicy);
    if (!groups.some((group) => group.phase === 'presentation' && group.final_step)) {
      throw new ForbiddenError(
        'principal confirmation requires a final presentation approval group',
      );
    }
  }
}
