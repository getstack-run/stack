import { createHash } from 'node:crypto';
import type { Constraint } from '../schemas/passport.js';
import type { FleetAccess, FleetLimits, FleetPolicyInput, FleetOperationAccess } from '../schemas/fleet.js';
import { expandIntents } from '../intents/index.js';
import { ForbiddenError } from '../errors/index.js';

export function fleetCanonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(fleetCanonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${fleetCanonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function fleetDigest(value: unknown): string {
  return createHash('sha256').update(fleetCanonicalJson(value)).digest('hex');
}

export function fleetEnrollmentRotationMessage(input: {
  challenge_id: string; challenge: string; policy_id: string;
  idempotency_key: string; public_key_thumbprint: string;
}): string {
  return fleetCanonicalJson({ domain: 'stack:fleet-key-rotation:v1', ...input });
}

// Deliberately incomplete implication: unknown relationships are refused.
// Never infer a permission from prose, regex similarity or a caller's risk score.
export function fleetConstraintNarrows(child: Constraint, parent: Constraint): boolean {
  if (child.path !== parent.path) return false;
  if (child.op === parent.op && fleetCanonicalJson(child.value) === fleetCanonicalJson(parent.value)) return true;
  const finite = child.op === 'eq' ? [child.value] : child.op === 'in' && Array.isArray(child.value) ? child.value : null;
  if (finite) {
    if (parent.op === 'in' && Array.isArray(parent.value)) return finite.every(v => typeof v === 'string' && (parent.value as string[]).includes(v));
    if (parent.op === 'eq') return finite.every(v => v === parent.value);
    if (parent.op === 'not_eq') return finite.every(v => v !== parent.value);
    if (parent.op === 'not_in' && Array.isArray(parent.value)) return finite.every(v => typeof v === 'string' && !(parent.value as string[]).includes(v));
    if (parent.op === 'starts_with' && typeof parent.value === 'string') return finite.every(v => typeof v === 'string' && v.startsWith(parent.value as string));
  }
  if (typeof child.value === 'number' && typeof parent.value === 'number') {
    if (['lt', 'lte'].includes(child.op) && ['lt', 'lte'].includes(parent.op)) {
      return child.value < parent.value || (child.value === parent.value && (parent.op === 'lte' || child.op === 'lt'));
    }
    if (['gt', 'gte'].includes(child.op) && ['gt', 'gte'].includes(parent.op)) {
      return child.value > parent.value || (child.value === parent.value && (parent.op === 'gte' || child.op === 'gt'));
    }
  }
  if (child.op === 'starts_with' && parent.op === 'starts_with' && typeof child.value === 'string' && typeof parent.value === 'string') return child.value.startsWith(parent.value);
  return false;
}

export function fleetAccessConstraints(access: FleetAccess): Constraint[] {
  const all = [...expandIntents(access.intents), ...access.constraints];
  const unique = [...new Map(all.map(c => [fleetCanonicalJson(c), c])).values()];
  if (unique.length > 32) throw new ForbiddenError();
  return unique;
}

export function fleetAccessNarrows(child: FleetAccess, parent: FleetAccess): boolean {
  if (child.connection_id !== parent.connection_id) return false;
  if (!child.scopes.every(s => parent.scopes.includes(s))) return false;
  if (!child.allow_data_from.every(s => parent.allow_data_from.includes(s))) return false;
  const childConstraints = fleetAccessConstraints(child);
  return fleetAccessConstraints(parent).every(p => childConstraints.some(c => fleetConstraintNarrows(c, p)));
}

export function assertFleetLimitsNarrow(child: FleetLimits, parent: FleetLimits): void {
  for (const key of Object.keys(parent) as (keyof FleetLimits)[]) {
    const ceiling = parent[key];
    const requested = child[key];
    if (ceiling !== undefined && (requested === undefined || requested > ceiling)) throw new ForbiddenError();
  }
}

export interface ResolvedFleetAccess {
  access: FleetAccess;
  rule_id: string;
  effect: 'allow' | 'review';
  constraints: Constraint[];
}

export interface ResolvedFleetOperation {
  access: FleetOperationAccess;
  rule_id: string;
  effect: 'allow' | 'review';
}

export function fleetOperationNarrows(child: FleetOperationAccess, parent: FleetOperationAccess): boolean {
  return child.producer === parent.producer && child.target_id === parent.target_id && child.action === parent.action &&
    parent.constraints.every(p => child.constraints.some(c => fleetConstraintNarrows(c, p)));
}

export function resolveFleetOperations(policy: FleetPolicyInput, requested: FleetOperationAccess[]): ResolvedFleetOperation[] {
  return requested.map(access => {
    const matching = policy.operation_rules.filter(rule => fleetOperationNarrows(access, rule.access));
    if (matching.some(rule => rule.effect === 'deny')) throw new ForbiddenError();
    const rule = matching.find(r => r.effect === 'review') ?? matching.find(r => r.effect === 'allow');
    if (!rule || rule.effect === 'deny') throw new ForbiddenError();
    return { access, rule_id: rule.id, effect: rule.effect };
  });
}

export function resolveFleetAccess(policy: FleetPolicyInput, requested: FleetAccess[]): ResolvedFleetAccess[] {
  return requested.map(access => {
    const matches = policy.rules.filter(rule => rule.effect !== 'deny' && fleetAccessNarrows(access, rule.access));
    // A review ceiling takes precedence over an overlapping automatic rule.
    const match = matches.find(rule => rule.effect === 'review') ?? matches.find(rule => rule.effect === 'allow');
    if (!match || match.effect === 'deny') throw new ForbiddenError();
    if (policy.rules.some(rule => rule.effect === 'deny' && fleetAccessNarrows(access, rule.access))) throw new ForbiddenError();
    return { access, rule_id: match.id, effect: match.effect, constraints: fleetAccessConstraints(access) };
  });
}
