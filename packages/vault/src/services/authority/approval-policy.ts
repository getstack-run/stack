/** Strict parsing of the approval policy a binding commits to. */
import { ForbiddenError, canonicalize } from '@stack/shared';

export interface StrictApprovalGroup {
  phase: 'activation' | 'action' | 'presentation';
  group_key: string;
  required_weight: number;
  reject_mode: 'any_reject' | 'threshold_reject';
  maximum_age_seconds: number;
  final_step: boolean;
}

export function parseAuthorityApprovalPolicy(value: unknown): StrictApprovalGroup[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ForbiddenError('authority approval policy is invalid');
  }
  const policy = value as Record<string, unknown>;
  if (
    canonicalize(Object.keys(policy).sort()) !== canonicalize(['groups', 'version']) ||
    policy.version !== '1' ||
    !Array.isArray(policy.groups) ||
    policy.groups.length > 64
  ) {
    throw new ForbiddenError('authority approval policy is invalid or unsupported');
  }
  const seen = new Set<string>();
  return policy.groups.map((raw) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new ForbiddenError('authority approval policy group is invalid');
    }
    const group = raw as Record<string, unknown>;
    const allowed = [
      'final_step',
      'group_key',
      'maximum_age_seconds',
      'phase',
      'reject_mode',
      'required_weight',
    ];
    if (canonicalize(Object.keys(group).sort()) !== canonicalize(allowed)) {
      throw new ForbiddenError('authority approval policy group has unknown or missing fields');
    }
    const phase = group.phase;
    const groupKey = group.group_key;
    const requiredWeight = group.required_weight;
    const rejectMode = group.reject_mode;
    const maximumAge = group.maximum_age_seconds;
    if (
      !['activation', 'action', 'presentation'].includes(String(phase)) ||
      typeof groupKey !== 'string' ||
      !groupKey ||
      groupKey.length > 128 ||
      !Number.isInteger(requiredWeight) ||
      Number(requiredWeight) <= 0 ||
      (rejectMode !== 'any_reject' && rejectMode !== 'threshold_reject') ||
      !Number.isInteger(maximumAge) ||
      Number(maximumAge) <= 0 ||
      Number(maximumAge) > 86_400 ||
      typeof group.final_step !== 'boolean'
    ) {
      throw new ForbiddenError('authority approval policy group is invalid');
    }
    const identity = `${phase}:${groupKey}`;
    if (seen.has(identity))
      throw new ForbiddenError('authority approval policy group is duplicated');
    seen.add(identity);
    return {
      phase: phase as StrictApprovalGroup['phase'],
      group_key: groupKey,
      required_weight: Number(requiredWeight),
      reject_mode: rejectMode,
      maximum_age_seconds: Number(maximumAge),
      final_step: group.final_step,
    };
  });
}
