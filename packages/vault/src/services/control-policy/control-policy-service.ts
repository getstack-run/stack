// Policies: the configuration behind hosted controls.
//
// A policy is stored server-side, keyed by customer and agent (and one default
// for the customer), and read by the hosted decider on every checked action.
// It is never bound into a Passport. It only narrows: effective access is the
// connection grant intersected with the policy, because a policy is judged
// after the grant and can refuse or hold, never allow what the grant refused.
//
// Writes are planned first (`planSet`, `planDelete`, `planStart`): the plan
// says what the change is, a tightening that applies at once or a loosening
// (including deleting a policy) that needs a person in a signed-in browser.
// The caller does the step-up the plan asks for, then `apply`s it; apply
// checks again that the stored revision is the one the plan judged, so a
// tightening can never become a loosening between the two.
//
// The effective policy is cached in process per agent and dropped on every
// write, here and, across machines, over one Redis channel (plus a short TTL
// that heals a missed message), so a tightening applies on every machine at once.

import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  PolicyDefinition,
  assertPolicyBounded,
  classifyPolicyRevision,
  normalizePolicy,
  policyDigest,
  policyFindings,
  policyNarrows,
  startingPolicyFromGrants,
  type ControlPolicyRow,
  type ControlPolicyView,
  type PolicyChangeKind,
} from '@stack/shared';
import type { ControlPolicyRepository } from '../../repositories/control-policy-repo.js';
import type { EntitlementResolver } from '../entitlements/entitlements.js';

export const CONTROL_POLICY_CACHE_TTL_MS = 10_000;

/** The policy in force for one agent, parsed and ready to evaluate. */
export interface EffectivePolicy {
  id: string;
  /** Null for the customer's default. */
  agentId: string | null;
  revision: number;
  name: string;
  definition: PolicyDefinition;
  source: 'agent' | 'default';
}

export type PolicyPlanChange = Extract<PolicyChangeKind, 'create' | 'start_from_access' | 'tighten' | 'loosen' | 'delete' | 'unchanged'>;

export interface PolicyPlan {
  operatorId: string;
  /** The agent, or null for the customer's default. */
  agentId: string | null;
  /** Null: delete. */
  next: PolicyDefinition | null;
  current: ControlPolicyRow | null;
  /** The revision the plan was judged against (0: no policy). */
  expectedRevision: number;
  change: PolicyPlanChange;
  /** True for a loosening: a person approves it in a signed-in browser before it applies. */
  needsApproval: boolean;
  /** What a person is asked to approve. Never a secret. */
  summary: string;
}

export interface ControlPolicyServiceDeps {
  repo: ControlPolicyRepository;
  /** Whether hosted controls are on for an operator (a tenant follows its partner). */
  controls: Pick<EntitlementResolver, 'controlsEnabled'>;
  /** Tell the other machines to drop their cached view of this customer's policies. */
  publishInvalidation?: (operatorId: string) => Promise<void>;
  now?: () => number;
}

function parseStored(row: ControlPolicyRow): PolicyDefinition {
  // A stored policy that no longer parses is never read as "no policy": the check fails and the action is refused.
  return PolicyDefinition.parse(row.definition);
}

export class ControlPolicyService {
  private readonly cache = new Map<string, Map<string, { at: number; value: EffectivePolicy | null }>>();
  private readonly now: () => number;

  constructor(private readonly deps: ControlPolicyServiceDeps) {
    this.now = deps.now ?? Date.now;
  }

  // ─── the hot path ───────────────────────────────────────────────

  /** The policy in force for an agent: its own, else the customer's default, else none. Cached. */
  async effective(operatorId: string, agentId: string | null): Promise<EffectivePolicy | null> {
    const perOperator = this.cache.get(operatorId);
    const key = agentId ?? '';
    const hit = perOperator?.get(key);
    if (hit && this.now() - hit.at < CONTROL_POLICY_CACHE_TTL_MS) return hit.value;
    const { agent, fallback } = await this.deps.repo.forAgent(operatorId, agentId);
    const row = agent ?? fallback;
    const value: EffectivePolicy | null = row
      ? {
          id: row.id,
          agentId: row.agent_id,
          revision: row.revision,
          name: row.name,
          definition: parseStored(row),
          source: row.agent_id === null ? 'default' : 'agent',
        }
      : null;
    const store = perOperator ?? new Map();
    store.set(key, { at: this.now(), value });
    this.cache.set(operatorId, store);
    return value;
  }

  invalidateLocal(operatorId: string): void {
    this.cache.delete(operatorId);
  }

  private async invalidate(operatorId: string): Promise<void> {
    this.invalidateLocal(operatorId);
    try {
      await this.deps.publishInvalidation?.(operatorId);
    } catch {
      // The other machines' caches expire on their own within CONTROL_POLICY_CACHE_TTL_MS.
    }
  }

  // ─── reads ──────────────────────────────────────────────────────

  async get(operatorId: string, agentId: string | null): Promise<ControlPolicyRow | null> {
    return this.deps.repo.get(operatorId, agentId);
  }

  async list(operatorId: string): Promise<ControlPolicyRow[]> {
    return this.deps.repo.list(operatorId);
  }

  async revisions(operatorId: string, policyId: string) {
    return this.deps.repo.revisions(operatorId, policyId);
  }

  /** A policy as the API shows it, with the sends it allows without naming who receives them. */
  async view(row: ControlPolicyRow): Promise<ControlPolicyView> {
    const definition = parseStored(row);
    const providers = await this.deps.repo.connectionProviders(
      row.operator_id,
      definition.connections.rules.map((rule) => rule.access.connection_id),
    );
    return {
      id: row.id,
      agent_id: row.agent_id,
      name: row.name,
      revision: row.revision,
      definition,
      last_change: row.last_change as ControlPolicyView['last_change'],
      findings: policyFindings(definition, (id) => providers.get(id)),
      created_at: row.created_at.toISOString(),
      updated_at: row.updated_at.toISOString(),
    };
  }

  // ─── planning a change ──────────────────────────────────────────

  private async fallbackDefinition(operatorId: string, agentId: string | null): Promise<PolicyDefinition | null> {
    if (agentId === null) return null;
    const fallback = await this.deps.repo.get(operatorId, null);
    return fallback ? parseStored(fallback) : null;
  }

  private async assertBounded(operatorId: string, definition: PolicyDefinition): Promise<void> {
    const providers = await this.deps.repo.connectionProviders(
      operatorId,
      definition.connections.rules.map((rule) => rule.access.connection_id),
    );
    // Every connection a rule names must be this customer's own.
    for (const rule of definition.connections.rules) {
      if (!providers.has(rule.access.connection_id)) {
        throw new NotFoundError('Service connection', rule.access.connection_id);
      }
    }
    assertPolicyBounded(definition, (id) => providers.get(id));
  }

  /** Create or revise the policy of an agent (or the default, with a null agent). */
  async planSet(input: {
    operatorId: string;
    agentId: string | null;
    definition: unknown;
    expectedRevision?: number | undefined;
  }): Promise<PolicyPlan> {
    const next = normalizePolicy(input.definition);
    await this.assertBounded(input.operatorId, next);
    const current = await this.deps.repo.get(input.operatorId, input.agentId);
    if (current && input.expectedRevision === undefined) {
      throw new ConflictError('This policy exists: read it and send expected_revision to revise it');
    }
    if (!current && input.expectedRevision !== undefined && input.expectedRevision !== 0) {
      throw new ConflictError('There is no policy at that revision');
    }
    const before = current ? parseStored(current) : await this.fallbackDefinition(input.operatorId, input.agentId);
    const kind = classifyPolicyRevision(next, before);
    const scope = input.agentId === null ? 'the default policy' : `the policy of agent ${input.agentId}`;
    if (current) {
      const change: PolicyPlanChange = kind === 'unchanged' ? 'unchanged' : kind;
      return {
        operatorId: input.operatorId,
        agentId: input.agentId,
        next,
        current,
        expectedRevision: input.expectedRevision!,
        change,
        needsApproval: change === 'loosen',
        summary: `Loosen ${scope}: it will allow something it does not allow today.`,
      };
    }
    return {
      operatorId: input.operatorId,
      agentId: input.agentId,
      next,
      current: null,
      expectedRevision: 0,
      change: kind === 'loosen' ? 'loosen' : 'create',
      needsApproval: kind === 'loosen',
      summary: `Set ${scope}: it allows more than the default policy that applies today.`,
    };
  }

  async planDelete(input: {
    operatorId: string;
    agentId: string | null;
    expectedRevision?: number | undefined;
  }): Promise<PolicyPlan> {
    const current = await this.deps.repo.get(input.operatorId, input.agentId);
    if (!current) throw new NotFoundError('Control policy', input.agentId ?? 'default');
    if (input.expectedRevision !== undefined && input.expectedRevision !== current.revision) {
      throw new ConflictError('This policy changed since it was read; read it again and retry');
    }
    const after = await this.fallbackDefinition(input.operatorId, input.agentId);
    const tightens = after !== null && policyNarrows(after, parseStored(current));
    const scope = input.agentId === null ? 'the default policy' : `the policy of agent ${input.agentId}`;
    return {
      operatorId: input.operatorId,
      agentId: input.agentId,
      next: null,
      current,
      expectedRevision: current.revision,
      change: 'delete',
      needsApproval: !tightens,
      summary: `Delete ${scope}: your agent${input.agentId === null ? 's' : ''} will run with fewer limits.`,
    };
  }

  /** A policy equal to the agent's current grants. */
  async planStart(input: { operatorId: string; agentId: string }): Promise<PolicyPlan> {
    const current = await this.deps.repo.get(input.operatorId, input.agentId);
    if (current) throw new ConflictError('This agent already has a policy; revise it instead');
    const grants = await this.deps.repo.grantsOf(input.operatorId, input.agentId);
    const next = startingPolicyFromGrants('Current access', grants);
    const before = await this.fallbackDefinition(input.operatorId, input.agentId);
    const kind = classifyPolicyRevision(next, before);
    return {
      operatorId: input.operatorId,
      agentId: input.agentId,
      next,
      current: null,
      expectedRevision: 0,
      change: kind === 'loosen' ? 'loosen' : 'start_from_access',
      needsApproval: kind === 'loosen',
      summary: `Start the policy of agent ${input.agentId} from its current access: it allows more than the default policy that applies today.`,
    };
  }

  // ─── applying it ────────────────────────────────────────────────

  /**
   * Apply a planned change. `authorized` says the caller has done what the plan
   * asks: a loosening is applied only after a person approved it in a signed-in
   * browser (the governance step-up), and a plan that needs one is refused
   * without it, whatever else is true.
   */
  async apply(
    plan: PolicyPlan,
    context: { actor: string; approvalId?: string | null; authorized: boolean },
  ): Promise<ControlPolicyRow | null> {
    if (plan.change === 'unchanged') return plan.current;
    if (plan.needsApproval && !context.authorized) {
      throw new ForbiddenError('This change needs a person to approve it first');
    }
    const row = await this.deps.repo.apply({
      operatorId: plan.operatorId,
      agentId: plan.agentId,
      expectedRevision: plan.expectedRevision,
      next: plan.next ? { name: plan.next.name, definition: plan.next as unknown as Record<string, unknown>, digest: policyDigest(plan.next) } : null,
      change: plan.change,
      actor: context.actor,
      approvalId: context.approvalId ?? null,
    });
    await this.invalidate(plan.operatorId);
    return row;
  }

  /**
   * Controls were switched on: give every account's agent that has grants a
   * policy equal to them, so nothing changes until the customer tightens it.
   * An agent that already has a policy, and every agent when the customer has
   * a default policy (which already governs them), is left alone. Safe to run
   * again. Returns the agents given a policy.
   */
  async ensureStartingPolicies(operatorId: string, actor: string): Promise<string[]> {
    if (await this.deps.repo.get(operatorId, null)) return [];
    const started: string[] = [];
    for (const agentId of await this.deps.repo.accountAgents(operatorId)) {
      if (await this.deps.repo.get(operatorId, agentId)) continue;
      const grants = await this.deps.repo.grantsOf(operatorId, agentId);
      if (grants.length === 0) continue;
      const next = startingPolicyFromGrants('Current access', grants);
      try {
        await this.deps.repo.apply({
          operatorId,
          agentId,
          expectedRevision: 0,
          next: { name: next.name, definition: next as unknown as Record<string, unknown>, digest: policyDigest(next) },
          change: 'start_from_access',
          actor,
        });
        started.push(agentId);
      } catch (error) {
        // Created at the same moment by another path: it has its policy.
        if (!(error instanceof ConflictError)) throw error;
      }
    }
    if (started.length > 0) await this.invalidate(operatorId);
    return started;
  }

  /**
   * Controls were switched on for a billing account: the operator's own agents
   * get their starting policies, and so do the agents of each of its
   * white-label tenants. Controls follow the partner, but a policy belongs to
   * the customer whose agent it governs, so each tenant is handled as its own
   * customer: its own grants, its own default policy, its own policies. A
   * tenant whose controls cannot be read is skipped without stopping the rest,
   * and the first failure is thrown once every tenant was tried. Safe to run again.
   */
  async ensureStartingPoliciesWithTenants(operatorId: string, actor: string): Promise<string[]> {
    const started = await this.ensureStartingPolicies(operatorId, actor);
    let failure: unknown;
    for (const tenantId of await this.deps.repo.tenantsOf(operatorId)) {
      try {
        if (!(await this.deps.controls.controlsEnabled(tenantId))) continue;
        started.push(...(await this.ensureStartingPolicies(tenantId, actor)));
      } catch (error) {
        failure ??= error;
      }
    }
    if (failure !== undefined) throw failure;
    return started;
  }
}
