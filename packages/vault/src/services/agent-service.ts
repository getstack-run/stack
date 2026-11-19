import {
  ids,
  type RegisterAgentInput,
  resolveAgentProfile,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  type OperatorTier,
  type Database,
  TierLimitExceededError,
} from '@stack/shared';
import { AgentRepository } from '../repositories/agent-repo.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import { contractPlanLimits, type PlanLimitsReader } from './entitlements/plan-limits.js';

/**
 * hardening — late-bound delete-precondition check. Each
 * registered function receives the agent id about to be deleted and
 * returns a list of human-readable references that would orphan if the
 * delete proceeded. Non-empty result triggers a ConflictError before
 * the delete fires. Used by the bootstrap to wire the inbound-webhook
 * cascade-block (agent referenced by an active webhook can't be
 * deleted; revoke the webhook first).
 */
export type AgentDeletePreconditionCheck = (agentId: string, operatorId: string) => Promise<string[]>;

export class AgentService {
  private deletePreconditionChecks: AgentDeletePreconditionCheck[] = [];
  private externalAgentGuard?: (operatorId: string, agentId: string) => Promise<void>;

  /** Policy-owned agents are internal implementation records, never public identities. */
  setExternalAgentGuard(guard: (operatorId: string, agentId: string) => Promise<void>) {
    this.externalAgentGuard = guard;
  }

  // operatorRepo is optional — when present, update() gates
  // identity_claim_ids on the operator's identity_claim_inheritance.
  // Test fixtures that construct AgentService without an OperatorRepository
  // keep working (the gate becomes permissive in that case).
  constructor(
    private repo: AgentRepository,
    private operatorRepo?: OperatorRepository,
    // How many agents a tier may register; absent, the contract plan's (no cap).
    private planLimits: PlanLimitsReader = contractPlanLimits,
  ) {}

  /**
   * The same registration rules with the agent row written inside the caller's
   * transaction, so an agent can be created atomically with what it belongs to.
   */
  forTransaction(tx: Parameters<Parameters<Database['transaction']>[0]>[0]): AgentService {
    const scoped = new AgentService(new AgentRepository(tx as unknown as Database), this.operatorRepo, this.planLimits);
    scoped.deletePreconditionChecks = this.deletePreconditionChecks;
    if (this.externalAgentGuard) scoped.externalAgentGuard = this.externalAgentGuard;
    return scoped;
  }

  /**
   * Register a precondition check that runs before `delete`. Returns
   * the number of checks registered (for diagnostic + test assertions).
   * Multiple registrations stack — each check runs sequentially; the
   * first non-empty result throws ConflictError listing all references.
   */
  registerDeletePreconditionCheck(check: AgentDeletePreconditionCheck): number {
    this.deletePreconditionChecks.push(check);
    return this.deletePreconditionChecks.length;
  }

  /**
   * Whether an agent of this name could be registered now: the plan's agent count and the name's uniqueness.
   * Throws what `register` throws, so a combined request can refuse before anyone is asked to approve it.
   */
  async assertCanRegister(operatorId: string, operatorTier: OperatorTier, name: string): Promise<void> {
    // Check tier limits
    const count = await this.repo.countByOperator(operatorId);
    const limit = this.planLimits(operatorTier).agents;
    if (count >= limit) {
      throw new TierLimitExceededError('agents', limit);
    }

    // Check name uniqueness within operator
    const existing = await this.repo.findByOperatorAndName(operatorId, name);
    if (existing) {
      throw new ConflictError(`Agent "${name}" already exists`);
    }
  }

  async register(
    operatorId: string,
    operatorTier: OperatorTier,
    input: RegisterAgentInput,
  ) {
    await this.assertCanRegister(operatorId, operatorTier, input.name);

    // resolve the registration preset (if any) to its posture
    // defaults. Precedence is: explicit input field > preset > base
    // per-field default below. `preset.<field> ?? undefined` collapses an
    // absent preset key so the `??` chains fall through to the base
    // default, and an explicit `input.<field>` still wins because it's
    // the first operand.
    const preset = resolveAgentProfile(input.profile);

    return this.repo.create({
      id: ids.agent(),
      operator_id: operatorId,
      name: input.name,
      description: input.description ?? null,
      status: 'active',
      // Start loose: a new agent is recorded (logged) and the owner tightens to enforced when they want
      // per-call approval. Agents that already exist keep the mode they have.
      accountability_mode: input.accountability_mode ?? preset.accountability_mode ?? 'logged',
      on_warning: input.on_warning ?? 'notify',
      on_critical: input.on_critical ?? 'notify',
      // 'proxy_only' is the base default. A `direct` agent fetches
      // the raw secret from /v1/credentials/:provider and calls the provider
      // itself, which is the one path that goes around the host binding, the
      // constraint evaluator, the approval gate and the data-flow rule. An
      // operator who wants the secret in the agent's hands says so.
      credential_access: input.credential_access ?? preset.credential_access ?? 'proxy_only',
      icon_url: input.icon_url ?? null,
      skill_access_mode: input.skill_access_mode ?? 'none',
      allowed_skills: input.allowed_skills ?? [],
      // customer-selectable signing model.
      // Omitted (and no preset key_mode) falls through to the DB column
      // default ('stack_managed').
      ...(input.key_mode ?? preset.key_mode
        ? { key_mode: input.key_mode ?? preset.key_mode }
        : {}),
      // twin runtime opt-in. Omitted falls through to
      // 'per_mission' default at the DB column.
      ...(input.twin_policy ? { twin_policy: input.twin_policy } : {}),
      // twin LLM model override. Omitted falls through to
      // NULL (twin uses same model as real).
      ...(input.twin_llm_model !== undefined ? { twin_llm_model: input.twin_llm_model } : {}),
      // 2026-05-25: synthetic-agent flag. Omitted falls through to false.
      ...(input.is_synthetic !== undefined ? { is_synthetic: input.is_synthetic } : {}),
      ...(input.eval_traffic !== undefined ? { eval_traffic: input.eval_traffic } : {}),
      // LLM gateway toggles. Omitted falls through to the DB
      // defaults (both true, fail-closed).
      ...(input.llm_inject_system_prompt !== undefined
        ? { llm_inject_system_prompt: input.llm_inject_system_prompt }
        : {}),
      ...(input.llm_redact_pii !== undefined ? { llm_redact_pii: input.llm_redact_pii } : {}),
    });
  }

  /**
   * Check whether a skill invocation is permitted for this agent.
   * mode='none'  → deny all
   * mode='all'   → allow all
   * mode='custom'→ allow only if skillId is in allowed_skills
   */
  isSkillAllowed(
    agent: { skill_access_mode: string; allowed_skills: string[] },
    skillId: string,
  ): boolean {
    if (agent.skill_access_mode === 'all') return true;
    if (agent.skill_access_mode === 'none') return false;
    return agent.allowed_skills.includes(skillId);
  }

  /** Append a single skill to an agent's allowed_skills list. Idempotent. */
  async allowSkill(agentId: string, operatorId: string, skillId: string) {
    await this.externalAgentGuard?.(operatorId, agentId);
    const agent = await this.repo.findById(agentId);
    if (!agent) throw new NotFoundError('Agent', agentId);
    if (agent.operator_id !== operatorId) throw new NotFoundError('Agent', agentId);

    const current = (agent.allowed_skills ?? []) as string[];
    if (current.includes(skillId)) return agent;
    const next = [...current, skillId];
    return this.repo.update(agentId, { allowed_skills: next });
  }

  /** Remove a single skill from an agent's allowed_skills list. Idempotent. */
  async disallowSkill(agentId: string, operatorId: string, skillId: string) {
    await this.externalAgentGuard?.(operatorId, agentId);
    const agent = await this.repo.findById(agentId);
    if (!agent) throw new NotFoundError('Agent', agentId);
    if (agent.operator_id !== operatorId) throw new NotFoundError('Agent', agentId);

    const current = (agent.allowed_skills ?? []) as string[];
    const next = current.filter((id) => id !== skillId);
    return this.repo.update(agentId, { allowed_skills: next });
  }

  async list(operatorId: string) {
    const agents = await this.repo.findByOperatorId(operatorId);
    if (!this.externalAgentGuard) return agents;
    const visible = await Promise.all(agents.map(async (agent) => {
      try {
        await this.externalAgentGuard!(operatorId, agent.id);
        return agent;
      } catch (error) {
        if (error instanceof ForbiddenError || error instanceof NotFoundError) return null;
        throw error;
      }
    }));
    return visible.filter((agent): agent is NonNullable<typeof agent> => agent !== null);
  }

  async countByOperator(operatorId: string): Promise<number> {
    return this.repo.countByOperator(operatorId);
  }

  /** Count agents created in [since, until) — flow count, not active inventory. */
  async countCreatedBetween(operatorId: string, since: Date, until?: Date): Promise<number> {
    return this.repo.countCreatedBetween(operatorId, since, until);
  }

  async getById(id: string, operatorId?: string) {
    const agent = await this.repo.findById(id);
    if (!agent) throw new NotFoundError('Agent', id);
    if (operatorId && agent.operator_id !== operatorId) throw new NotFoundError('Agent', id);
    await this.externalAgentGuard?.(agent.operator_id, id);
    return agent;
  }

  /**
   * Returns the public signing info for an agent, scoped to fields
   * safe to expose at the unauthenticated `/v1/agents/:id/.well-known/
   * jwks.json` endpoint.
   *
   * Returns null when:
   *  - The agent_id doesn't resolve (treat as 404 at the route layer)
   *  - The agent exists but has no pubkey provisioned yet
   *    (customer_managed pre-enrollment OR stack_managed before
   *    AgentSigner has run on it)
   *
   * Deliberately does NOT include operator_id, name, description, or
   * any other agent-level metadata — the JWKS endpoint should expose
   * ONLY what an external verifier needs to validate a signature.
   * Probing for agent existence via this method's null vs non-null
   * return is acceptable: agent_ids are 21-char nanoids (large space,
   * not enumerable).
   */
  async getPublicSigningInfo(id: string): Promise<{
    kid: string;
    pubkey: { kty: string; crv: string; x: string };
    enrolled_at: Date | null;
    key_mode: string;
  } | null> {
    const agent = await this.repo.findById(id);
    if (!agent || !agent.pubkey) return null;
    await this.externalAgentGuard?.(agent.operator_id, id);
    return {
      kid: `agent:${id}:v1`,
      pubkey: agent.pubkey as { kty: string; crv: string; x: string },
      enrolled_at: agent.enrolled_at ?? null,
      key_mode: agent.key_mode,
    };
  }

  async updateStatus(id: string, status: string) {
    await this.getById(id);
    return this.repo.updateStatus(id, status);
  }

  async update(id: string, operatorId: string, data: {
    status?: string;
    accountability_mode?: string;
    on_warning?: string;
    on_critical?: string;
    credential_access?: string;
    icon_url?: string | null;
    skill_access_mode?: string;
    allowed_skills?: string[];
    identity_claim_ids?: string[];
    twin_policy?: string;
    twin_llm_model?: string | null;
    is_synthetic?: boolean;
    eval_traffic?: boolean;
    llm_inject_system_prompt?: boolean;
    llm_redact_pii?: boolean;
  }) {
    const agent = await this.repo.findById(id);
    if (!agent) throw new NotFoundError('Agent', id);
    if (agent.operator_id !== operatorId) throw new NotFoundError('Agent', id);
    await this.externalAgentGuard?.(operatorId, id);

    // Gate per-agent identity_claim_ids on operator's inheritance mode.
    // In 'auto' mode every agent inherits the full operator claim set —
    // a per-agent override has no effect on passport issuance, so
    // accepting the write silently would mislead the caller. Refuse it
    // here with a clear pointer to /identity/settings. Skipped when
    // operatorRepo wasn't injected (test fixtures + back-compat).
    if (data.identity_claim_ids !== undefined && this.operatorRepo) {
      const operator = await this.operatorRepo.findById(operatorId);
      if (operator && operator.identity_claim_inheritance !== 'opt_in') {
        throw new ForbiddenError(
          'identity_claim_ids can only be set per-agent when the operator is in identity_claim_inheritance="opt_in" mode. ' +
            'Switch the operator setting first at /identity/settings, then assign per-agent claims.',
        );
      }
    }

    const updates: Record<string, unknown> = {};
    if (data.status) updates.status = data.status;
    if (data.accountability_mode) updates.accountability_mode = data.accountability_mode;
    if (data.on_warning) updates.on_warning = data.on_warning;
    if (data.on_critical) updates.on_critical = data.on_critical;
    if (data.credential_access) updates.credential_access = data.credential_access;
    if (data.icon_url !== undefined) updates.icon_url = data.icon_url;
    if (data.skill_access_mode) updates.skill_access_mode = data.skill_access_mode;
    if (data.allowed_skills !== undefined) updates.allowed_skills = data.allowed_skills;
    if (data.identity_claim_ids !== undefined) updates.identity_claim_ids = data.identity_claim_ids;
    if (data.twin_policy) updates.twin_policy = data.twin_policy;
    if (data.twin_llm_model !== undefined) updates.twin_llm_model = data.twin_llm_model;
    if (data.is_synthetic !== undefined) updates.is_synthetic = data.is_synthetic;
    // eval-traffic valve (boolean: explicit check, false is a
    // real write). Caught by the E2E close gate: the PATCH 200'd while
    // this allowlist silently dropped the field.
    if (data.eval_traffic !== undefined) updates.eval_traffic = data.eval_traffic;
    // LLM gateway toggles (boolean: explicit !== undefined check
    // so `false` is a real write, not a skipped falsy).
    if (data.llm_inject_system_prompt !== undefined)
      updates.llm_inject_system_prompt = data.llm_inject_system_prompt;
    if (data.llm_redact_pii !== undefined) updates.llm_redact_pii = data.llm_redact_pii;

    return this.repo.update(id, updates);
  }

  async delete(id: string, operatorId: string) {
    await this.externalAgentGuard?.(operatorId, id);
    const agent = await this.repo.findById(id);
    if (!agent) throw new NotFoundError('Agent', id);
    if (agent.operator_id !== operatorId) throw new NotFoundError('Agent', id);

    // hardening — cascade-block precondition checks. Each
    // registered checker returns descriptions of references that would
    // orphan if the delete proceeded; non-empty throws ConflictError
    // with the list so the operator knows what to revoke first.
    const blockers: string[] = [];
    for (const check of this.deletePreconditionChecks) {
      const refs = await check(id, operatorId);
      blockers.push(...refs);
    }
    if (blockers.length > 0) {
      throw new ConflictError(
        `Agent ${id} cannot be deleted while active references exist: ${blockers.join(', ')}. Revoke these first.`,
      );
    }

    // Retired under its own name: the name is unique among the live agents only, so it is free to register again.
    return this.repo.updateStatus(id, 'revoked');
  }

  /**
   * store the agent's enrolled Ed25519 public key. Caller MUST
   * have already verified the proof-of-possession signature (the route
   * handler at /v1/agents/:id/enroll does this). Idempotency: this
   * unconditionally overwrites; the route enforces re-enrollment policy
   * (refuse without ?force=true + admin role) before calling.
   */
  async setPubkey(id: string, pubkey: { kty: string; crv: string; x: string }) {
    await this.getById(id);
    const updated = await this.repo.update(id, {
      pubkey,
      enrolled_at: new Date(),
    });
    return updated;
  }
}
