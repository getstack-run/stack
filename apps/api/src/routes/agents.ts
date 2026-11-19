import type { FastifyInstance } from 'fastify';
import {
  RegisterAgentInput,
  AgentSetupInput,
  UpdateAgentInput,
  AgentEnrollInput,
  AGENT_ENROLLMENT_CHALLENGE_TTL_SECONDS,
  ENROLLMENT_TICKET_TTL_SECONDS,
  acquireOAuthOperatorLock,
  agents as agentRows,
  operators,
  generateId,
  ConflictError,
  ForbiddenError,
  ServiceUnavailableError,
  StackError,
} from '@stack/shared';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import type { Services } from '../config/services.js';
import {
  claimEnrollmentTicket,
  createAuthMiddleware,
  createEnrollmentAuthMiddleware,
  enrollmentTicketClaimKey,
  releaseEnrollmentTicketClaim,
} from '../middleware/auth.js';
import { requireOperatorAdmin, denyAgentContexts } from '../middleware/require-platform.js';
import { enforceGovernanceStepUp } from '../middleware/governance-stepup.js';
import { auditCtx } from '../middleware/audit.js';
import { requireRole } from '../middleware/require-role.js';
import { buildSetupPreview, setupSummary } from '../lib/setup-preview.js';
import type { OperatorTier } from '@stack/shared';

/**
 * #10 — which key_modes may upload a customer public key via
 * /v1/agents/:id/enroll. ONLY customer_managed (BYO-keypair). stack_managed
 * and co_signed have their keypair auto-provisioned by AgentSigner on first
 * sign, so enrolling a customer pubkey on them is invalid (and used to 500 on
 * the agents_key_material_consistency CHECK). Exported for a direct unit test
 * of the invariant — see agents-enroll-gate.test.ts.
 */
export function enrollAcceptsPubkeyUpload(keyMode: string): boolean {
  return keyMode === 'customer_managed';
}

/** Identity proofs expand agent authority. Only the owner or team admin may assign them. */
export async function requireIdentityClaimAssignmentAuthority(
  request: { memberId?: string; memberRole?: string },
  _reply: unknown,
): Promise<void> {
  if (request.memberId && request.memberRole !== 'admin') {
    throw new ForbiddenError('operator-admin access required for identity_claim_ids');
  }
}

type AgentAuthorityState = Record<string, unknown>;
type AgentPatch = ReturnType<typeof UpdateAgentInput.parse>;

// In every table below a higher rank is a stricter setting, so a request that ranks lower than what is there is weaker.
const ACCOUNTABILITY_RANK: Record<string, number> = { standard: 0, logged: 1, enforced: 2 };
const ESCALATION_RANK: Record<string, number> = { notify: 0, block: 1 };
const CREDENTIAL_RANK: Record<string, number> = { direct: 0, proxy_preferred: 1, proxy_only: 2 };
const TWIN_RANK: Record<string, number> = { never: 0, per_mission: 1, high_stakes_only: 2, always: 3 };

function rankWidens(
  current: unknown,
  requested: unknown,
  ranks: Record<string, number>,
): boolean {
  return typeof requested === 'string'
    && typeof current === 'string'
    && (ranks[requested] ?? -1) < (ranks[current] ?? -1);
}

/**
 * Every way a change to an agent weakens it, each in plain words for the person who is asked. The classifier behind
 * PATCH /agents/:id. Unknown changes fail closed,
 * except skills, which need no approval: allowing a skill, one at a time or by widening the skill access mode, needs no
 * one's yes (the owner's own session or key does it directly, as `POST /v1/agents/:id/allowed-skills` does).
 */
export function agentWeakenings(current: AgentAuthorityState, patch: AgentPatch): string[] {
  const found: string[] = [];
  if (patch.status === 'active' && current['status'] !== 'active') found.push('the agent is switched back on');
  if (rankWidens(current['accountability_mode'], patch.accountability_mode, ACCOUNTABILITY_RANK)) {
    found.push(`accountability mode is lowered to ${patch.accountability_mode}`);
  }
  if (rankWidens(current['on_warning'], patch.on_warning, ESCALATION_RANK)) found.push('a warning only notifies instead of blocking the agent');
  if (rankWidens(current['on_critical'], patch.on_critical, ESCALATION_RANK)) found.push('a critical finding only notifies instead of blocking the agent');
  if (rankWidens(current['credential_access'], patch.credential_access, CREDENTIAL_RANK)) {
    found.push(`credential access is loosened to ${patch.credential_access}`);
  }
  if (rankWidens(current['twin_policy'], patch.twin_policy, TWIN_RANK)) found.push(`twin runs are lowered to ${patch.twin_policy}`);
  if (patch.llm_redact_pii === false && current['llm_redact_pii'] !== false) {
    found.push('PII redaction is switched off, so user text reaches the model provider unredacted');
  }
  if (patch.is_synthetic === true && current['is_synthetic'] !== true) {
    found.push('the agent is marked synthetic, which hides its security events, criticals included, from the list and the daily digest');
  }
  if (patch.eval_traffic === true && current['eval_traffic'] !== true) {
    found.push('the agent is marked as test traffic, which mutes the alerts of the owner for it (criticals stay live)');
  }

  const currentClaims = new Set(Array.isArray(current['identity_claim_ids']) ? current['identity_claim_ids'] as string[] : []);
  if (patch.identity_claim_ids?.some((id) => !currentClaims.has(id))) found.push('identity claims are assigned to the agent');

  return found;
}

/** Pure direction classifier for PATCH /agents/:id: does the change weaken the agent, so that a person says yes. */
export function agentAuthorityWidens(current: AgentAuthorityState, patch: AgentPatch): boolean {
  return agentWeakenings(current, patch).length > 0;
}

export function registerAgentRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);
  // /enrollment-challenge + /enroll accept either an enrollment ticket
  // (browser-mediated approval) OR standard auth (headless/CI). Other
  // routes use `auth` only — tickets cannot be replayed against them.
  const enrollmentAuth = createEnrollmentAuthMiddleware(services);

  // Agent count is deliberately ungated — you register as many agents as your
  // estate has, and none of them cost an action. An unlimited dimension needs
  // an abuse ceiling somewhere, and a rate limit is the honest place for it:
  // it bounds a script, not a real estate. 60/min is far above human or
  // orchestrator use and far below anything that would hurt.
  app.post(
    '/v1/agents/register',
    {
      preHandler: [auth, denyAgentContexts],
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
    // Registering an agent needs no one's yes, whatever settings it starts with: it names a principal and gives it no
    // access (grants, hosts and keys each have their own gate), and only the owner's own session or key gets here, never
    // an agent. A read-only member still may not.
    requireRole(request, 'standard');
    const input = RegisterAgentInput.parse(request.body);
    const start = Date.now();

    const agent = await services.agent.register(
      request.operatorId,
      request.operatorTier as OperatorTier,
      input,
    );

    await services.audit.write({
      ctx: auditCtx(request, { agent_id: agent.id }),
      layer: 'vault',
      action: 'agent.register',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

      return reply.status(201).send(agent);
    },
  );

  // Setting an agent up is one decision: its registration, its first grants on connections the owner already made
  // and the hosts those connections' credentials may go to, asked as one approval whose card lists all of it. The
  // approval binds the whole request, so what runs is exactly what the person saw. It may be confirmed in the chat,
  // as a grant and a host change each may on their own, because the confirmation lists every part. A caller that
  // only needs the agent registers it.
  app.post(
    '/v1/agents/setup',
    {
      preHandler: [auth, denyAgentContexts],
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      requireRole(request, 'standard');
      const input = AgentSetupInput.parse(request.body);
      const tier = request.operatorTier as OperatorTier;
      // Everything that was always going to fail fails before a person is asked: the name and the plan's count,
      // and each grant's scopes, constraints and each host list against the owner's own connections.
      await services.agent.assertCanRegister(request.operatorId, tier, input.agent.name);
      const connections = await services.serviceConnection.checkSetup(request.operatorId, input, request.allowedConnections);
      // A setup always grants a service or widens hosts (`AgentSetupInput` refuses one that does neither: to register
      // an agent alone, register it, which asks no one), so it asks once for the whole request, test traffic included.
      await enforceGovernanceStepUp(services, request, {
        action: 'agent_setup',
        resourceId: input.agent.name,
        payload: input,
        summary: setupSummary(input),
        preview: { ...buildSetupPreview(input, connections) },
      });
      const start = Date.now();

      const agent = await services.agent.register(request.operatorId, tier, input.agent);
      const grants: Array<{ id: string; service_connection_id: string }> = [];
      // What each connection's hosts were before this setup wrote them, so a failure puts them back.
      const widened: Array<{ connectionId: string; previous: string[]; wrote: string[] }> = [];
      try {
        for (const grant of input.grants) {
          const made = await services.serviceConnection.grantAgentAccess(
            request.operatorId,
            { ...grant, agent_id: agent.id },
            // The person approved this grant as part of the setup.
            { authorityExpansionApproved: true, allowedConnections: request.allowedConnections },
          );
          grants.push({ id: made.id, service_connection_id: made.service_connection_id });
        }
        for (const entry of input.allowed_hosts) {
          const previous = await services.serviceConnection.allowedHostsOf(
            entry.service_connection_id,
            request.operatorId,
            request.allowedConnections,
          );
          await services.serviceConnection.setAllowedHosts(
            entry.service_connection_id,
            request.operatorId,
            entry.allowed_hosts,
            request.allowedConnections,
            true,
          );
          widened.push({ connectionId: entry.service_connection_id, previous, wrote: entry.allowed_hosts });
        }
      } catch (err) {
        // Leave nothing half made: the hosts it widened are put back (a connection someone changed since is left as it
        // is), the agent is retired and its name freed, and its grants ended, before the error is shown.
        for (const written of widened) {
          await services.serviceConnection
            .restoreAllowedHosts(written.connectionId, request.operatorId, written.previous, written.wrote, request.allowedConnections)
            .catch(() => undefined);
        }
        await services.serviceConnection.revokeAgentAccess(agent.id, request.operatorId).catch(() => undefined);
        await services.agent.delete(agent.id, request.operatorId).catch(() => undefined);
        throw err;
      }

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: agent.id }),
        layer: 'vault',
        action: 'agent.setup',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.status(201).send({ agent, grants, allowed_hosts: input.allowed_hosts });
    },
  );

  app.get('/v1/agents', { preHandler: auth }, async (request) => {
    return services.agent.list(request.operatorId);
  });

  app.get<{ Params: { id: string } }>('/v1/agents/:id', { preHandler: auth }, async (request) => {
    return services.agent.getById(request.params.id, request.operatorId);
  });

  // Lifetime counts for the agent overview's SETUP card. Returns
  // { lifetime_passports, lifetime_calls } from audit_log. The
  // operator gate is enforced inside the service via operator_id —
  // this route additionally checks ownership via getById to fail
  // fast on cross-tenant id probing with a 404.
  app.get<{ Params: { id: string } }>('/v1/agents/:id/stats', { preHandler: auth }, async (request) => {
    await services.agent.getById(request.params.id, request.operatorId);
    return services.audit.getAgentStats(request.params.id, request.operatorId);
  });

  app.patch<{ Params: { id: string } }>(
    '/v1/agents/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const input = UpdateAgentInput.parse(request.body);
      if (Object.keys(input).length === 0) {
        return reply.status(400).send({ error: { message: 'No fields to update' } });
      }
      if (input.status && !['active', 'suspended'].includes(input.status)) {
        return reply.status(400).send({ error: { message: 'status must be "active" or "suspended"' } });
      }
      if (input.identity_claim_ids !== undefined) {
        await requireIdentityClaimAssignmentAuthority(request, reply);
      }
      // Skills need no approval, so a read-only member (whose own approval used to be the only thing in the way of a
      // member's token adding one) may not change them here, as on the additive route.
      if (input.allowed_skills !== undefined || input.skill_access_mode !== undefined) requireRole(request, 'standard');
      const target = await services.agent.getById(request.params.id, request.operatorId);
      if (agentAuthorityWidens(target as unknown as AgentAuthorityState, input)) {
        await enforceGovernanceStepUp(services, request, {
          action: 'agent_authority_expand',
          resourceId: request.params.id,
          payload: { agent_id: request.params.id, patch: input },
          summary: `Expand authority or weaken controls for agent ${request.params.id}`,
        });
      }
      const start = Date.now();
      const updated = await services.agent.update(request.params.id, request.operatorId, input);

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: request.params.id }),
        layer: 'vault',
        action: 'agent.update',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.send(updated);
    },
  );

  // Unblock agent from passport issuance.: releasing a blocked
  // agent is scope-expanding — Bearer-credential contexts step up.
  app.post<{ Params: { id: string } }>(
    '/v1/agents/:id/unblock',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      await services.agent.getById(request.params.id, request.operatorId);
      await enforceGovernanceStepUp(services, request, {
        action: 'agent_unblock',
        resourceId: request.params.id,
        payload: { agent_id: request.params.id },
        summary: `Unblock agent ${request.params.id} for passport issuance`,
      });
      const start = Date.now();
      const result = await services.accountability.unblockAgent(request.params.id, request.operatorId);

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: request.params.id }),
        layer: 'vault',
        action: 'agent.unblock',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return result;
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/v1/agents/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      // Retiring an agent is permanent and ends its Passports: the owner or any member who may change things (not a
      // read-only member).
      requireRole(request, 'standard');
      const start = Date.now();
      // An agent with an account is deleted by closing the account: that one
      // transaction also ends its Mission, grants and pieces, which a bare
      // agent delete would leave live. Closing needs the same admin role as
      // DELETE /v1/accounts/:id.
      const account = await services.agentAccounts.findOpenAccountByAgent(request.params.id);
      if (account && account.operator_id === request.operatorId) {
        await requireOperatorAdmin(request, reply);
        const closed = await services.agentAccounts.close({ operatorId: request.operatorId, accountId: account.id });
        if (closed.transitioned) {
          await services.audit.write({
            ctx: auditCtx(request, { agent_id: request.params.id }),
            layer: 'vault',
            action: 'account.close',
            outcome: 'success',
            duration_ms: Date.now() - start,
          });
        }
        return services.agent.getById(request.params.id, request.operatorId);
      }

      const result = await services.agent.delete(request.params.id, request.operatorId);

      // Cascade: revoke all active passports for the deleted agent
      await services.passport.revokeAllForAgent(request.params.id, 'Agent deleted');

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: request.params.id }),
        layer: 'vault',
        action: 'agent.delete',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return result;
    },
  );

  // ─── Allowed-skills additive API ─────────────────────────────────
  // These operate on agent.allowed_skills without forcing full-replacement PATCH.
  // Mode enforcement still follows agent.skill_access_mode; these just manage the list.
  app.post<{ Params: { id: string }; Body: { skill_id: string } }>(
    '/v1/agents/:id/allowed-skills',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const { skill_id } = request.body ?? {};
      if (!skill_id || typeof skill_id !== 'string') {
        return reply.status(400).send({ error: { message: 'skill_id required' } });
      }
      // Allowing a skill needs no one's yes: the owner's own session or key does it directly, an agent never
      // reaches this route (`denyAgentContexts`), and a read-only member may not.
      requireRole(request, 'standard');
      const start = Date.now();
      const updated = await services.agent.allowSkill(request.params.id, request.operatorId, skill_id);

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: request.params.id }),
        layer: 'vault',
        action: 'agent.allowed_skill.add',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.send(updated);
    },
  );

  app.delete<{ Params: { id: string; skillId: string } }>(
    '/v1/agents/:id/allowed-skills/:skillId',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      const start = Date.now();
      const updated = await services.agent.disallowSkill(request.params.id, request.operatorId, request.params.skillId);

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: request.params.id }),
        layer: 'vault',
        action: 'agent.allowed_skill.remove',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return updated;
    },
  );

  // ─── agent keypair enrollment ─────────────────────────────
  // Two-step proof-of-possession. The SDK requests a challenge, generates
  // an Ed25519 keypair locally, signs the challenge with the new privkey,
  // and POSTs {public_key, challenge_id, signed_challenge}. Server verifies
  // the signature against the submitted public_key (proves the SDK has the
  // matching privkey), then stores the public_key on the agents row.
  //
  // Auth: standard middleware (operator key, OAuth, or dashboard session).
  // Member role: readonly is denied — same gate as agent.update. The
  // request must come through a channel that proves the human approved
  // (cookie session or OAuth from `stack-cli auth login`).

  app.post<{ Params: { id: string } }>(
    '/v1/agents/:id/enrollment-challenge',
    { preHandler: enrollmentAuth, config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (request, reply) => {
      assertCanEnroll(request);
      assertTicketBindingMatches(request, request.params.id);
      // Confirm agent exists + belongs to caller's operator. Throws
      // NotFoundError if not, which the error-handler maps to 404.
      const agent = await services.agent.getById(request.params.id, request.operatorId);

      const challengeId = generateId('enr', 24);
      const challenge = generateId('chl', 48);
      const key = `stack:enroll:${agent.id}:${challengeId}`;
      const value = JSON.stringify({
        agent_id: agent.id,
        operator_id: request.operatorId,
        member_id: request.memberId ?? null,
        ticket_jti: request.enrollmentTicket?.jti ?? null,
        challenge,
      });
      const stored = await storeEnrollmentChallenge(
        services,
        key,
        value,
        request.enrollmentTicket?.jti ?? null,
      );
      if (!stored) return invalidEnrollment(reply);

      return reply.send({
        challenge_id: challengeId,
        challenge,
        expires_in: AGENT_ENROLLMENT_CHALLENGE_TTL_SECONDS,
      });
    },
  );

  app.post<{
    Params: { id: string };
    Querystring: { force?: string };
  }>(
    '/v1/agents/:id/enroll',
    { preHandler: enrollmentAuth, config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
    async (request, reply) => {
      assertCanEnroll(request);
      assertTicketBindingMatches(request, request.params.id);
      const agent = await services.agent.getById(request.params.id, request.operatorId);
      // A body that is not an Ed25519 key, a challenge id and a signature is a 400 VALIDATION_ERROR.
      const body = AgentEnrollInput.parse(request.body ?? {});

      // key_mode gate. The /enroll route accepts a
      // customer-held pubkey for the agent's signing key. That model is
      // ONLY correct for customer_managed agents (Model B). For
      // stack_managed + co_signed agents, AgentSigner owns the keypair and
      // provisions it (pubkey + signing_key_encrypted + enrolled_at,
      // atomically) on first sign — those agents never enroll a customer
      // pubkey and need no enroll step at all.
      //
      // The previous guard only refused when signing_key_encrypted was
      // ALREADY non-null. That left a hole: a freshly-registered
      // stack_managed agent (default key_mode, signing_key_encrypted NULL)
      // fell THROUGH to setPubkey, which writes pubkey + enrolled_at but
      // not signing_key_encrypted — violating the agents_key_material_
      // consistency CHECK (stack_managed + enrolled_at ⇒ signing_key_
      // encrypted NOT NULL) and surfacing as an unhandled 500 (the
      // FamilyBot dogfooding failure). Refuse for ANY non-customer_managed
      // agent, regardless of signing-key state, with an informative
      // message so the operator isn't pushed toward the wrong verb.
      if (!enrollAcceptsPubkeyUpload(agent.key_mode)) {
        return reply.status(409).send({
          error: {
            code: 'ENROLL_NOT_APPLICABLE',
            message:
              `agent '${agent.name}' is key_mode='${agent.key_mode}', so it does not need enrollment — ` +
              `STACK provisions its signing keypair automatically on first use. Just start issuing ` +
              `passports / signing; no enroll step is required. The /enroll pubkey-upload flow is only ` +
              `for customer_managed agents. To bring your own keypair, register an agent with ` +
              `key_mode='customer_managed'.`,
          },
        });
      }

      // Re-enrollment guard. First-time enrollment (pubkey NULL) is open
      // to readonly-not standard/admin. Re-enrollment (rotation) requires
      // ?force=true AND operator-admin authority (operator-key OR
      // member-with-admin-role; OAuth-with-member-admin OK). Without
      // this, an attacker who phished a standard-role member could
      // overwrite the stored pubkey with their own and silently take
      // over the agent.
      //
      // (auth refactor) — STRUCTURAL-TEST-EXEMPT: this route is
      // mixed-mode (open for first enrollment, admin-gated for rotation),
      // so we cannot put requireOperatorAdmin at the encapsulation
      // scope. The named-helper call below is the documented exception
      // — the structural test allowlists this single use site by file
      // and route.
      const force = request.query.force === 'true';
      if (agent.pubkey != null && !force) {
        throw new ConflictError('agent already enrolled. POST with ?force=true to rotate.');
      }
      if (force) {
        await requireOperatorAdmin(request, reply);
      }

      // Read first so proof verification does not consume an invalid request.
      // Redis compares these exact bytes again when the challenge is claimed.
      const key = `stack:enroll:${agent.id}:${body.challenge_id}`;
      let stored: string | null;
      try {
        stored = await services.redis.get(key);
      } catch {
        throw new ServiceUnavailableError('Enrollment temporarily unavailable, please retry');
      }
      if (!stored) return invalidEnrollment(reply);
      const parsed = parseEnrollmentChallenge(stored);
      const expectedMemberId = request.memberId ?? null;
      const expectedTicketJti = request.enrollmentTicket?.jti ?? null;
      if (
        !parsed
        || parsed.agent_id !== agent.id
        || parsed.operator_id !== request.operatorId
        || parsed.member_id !== expectedMemberId
        || parsed.ticket_jti !== expectedTicketJti
      ) {
        await services.securityEvent.record({
          operatorId: request.operatorId,
          agentId: agent.id,
          signalType: 'oauth_unknown_client',
          severity: 'warning',
          message: 'Enrollment challenge binding mismatch',
        }).catch(() => {});
        return invalidEnrollment(reply);
      }

      // Tighten the public_key shape post-validation so downstream code
      // sees a fully-typed JWK (the route's Body schema accepts partial
      // shapes for friendlier validation errors).
      const validatedJwk = { kty: body.public_key.kty, crv: body.public_key.crv, x: body.public_key.x };

      // Verify the proof-of-possession: the submitted signed_challenge
      // must verify against the submitted public_key over the challenge
      // bytes. This is what proves the SDK actually has the matching
      // privkey — without it, anyone could submit any pubkey.
      if (!verifyEd25519Signature(parsed.challenge, body.signed_challenge, validatedJwk)) {
        return invalidEnrollment(reply);
      }

      if (!request.enrollmentTicket) {
        await enforceGovernanceStepUp(services, request, {
          action: 'agent_key_enroll',
          resourceId: agent.id,
          payload: { agent_id: agent.id, public_key: validatedJwk, force },
          summary: `${force ? 'Rotate' : 'Enroll'} the signing key for agent ${agent.id}`,
        });
      }

      const claimId = generateId('ecl', 24);
      let ticketClaimed = false;
      if (request.enrollmentTicket) {
        ticketClaimed = await claimEnrollmentTicket(services, request.enrollmentTicket, claimId);
        if (!ticketClaimed) return invalidEnrollment(reply);
      }

      let challengeTtlMs: number | null;
      try {
        challengeTtlMs = await claimEnrollmentChallenge(services, key, stored);
      } catch (err) {
        if (ticketClaimed && request.enrollmentTicket) {
          try {
            await releaseEnrollmentTicketClaim(services, request.enrollmentTicket.jti, claimId);
          } catch {
            console.error('[agent-enrollment] ticket claim recovery failed');
          }
        }
        throw err;
      }
      if (challengeTtlMs === null) {
        if (ticketClaimed && request.enrollmentTicket) {
          await releaseEnrollmentTicketClaim(services, request.enrollmentTicket.jti, claimId);
        }
        return invalidEnrollment(reply);
      }

      const start = Date.now();
      let updated: typeof agentRows.$inferSelect;
      let transactionBodyCompleted = false;
      let announceRevocation: () => Promise<void> = async () => {};
      try {
        updated = await services.db.transaction(async (tx) => {
          // Fixed lock order: operator lifecycle, agent row, audit chain.
          await acquireOAuthOperatorLock(tx, request.operatorId);
          const [activeOperator] = await tx
            .select({ id: operators.id, status: operators.status })
            .from(operators)
            .where(eq(operators.id, request.operatorId))
            .for('update');
          if (!activeOperator || activeOperator.status !== 'active') {
            throw new ConflictError('Enrollment request is invalid or expired');
          }

          const [lockedAgent] = await tx
            .select()
            .from(agentRows)
            .where(and(
              eq(agentRows.id, agent.id),
              eq(agentRows.operator_id, request.operatorId),
            ))
            .for('update');
          if (
            !lockedAgent
            || lockedAgent.status !== 'active'
            || lockedAgent.key_mode !== 'customer_managed'
            || lockedAgent.updated_at.getTime() !== agent.updated_at.getTime()
            || (lockedAgent.pubkey !== null && !force)
          ) {
            throw new ConflictError('Enrollment request is invalid or expired');
          }

          // This transaction holds the operator lock, so the revocation runs inside it (taking the lock again
          // on another connection would wait for this request forever) and is announced once it commits.
          if (force && lockedAgent.pubkey !== null) {
            const revoked = await services.passport.revokeAllForAgentIn(agent.id, request.operatorId, 'Agent keypair rotated', tx);
            announceRevocation = revoked.publish;
          }

          const [row] = await tx
            .update(agentRows)
            .set({ pubkey: validatedJwk, enrolled_at: new Date(), updated_at: new Date() })
            .where(eq(agentRows.id, lockedAgent.id))
            .returning();
          if (!row) throw new Error('agent enrollment update returned no row');

          await services.audit.write({
            ctx: auditCtx(request, { agent_id: agent.id }),
            layer: 'vault',
            action: force ? 'agent.enroll.rotate' : 'agent.enroll',
            outcome: 'success',
            duration_ms: Date.now() - start,
          }, tx);
          transactionBodyCompleted = true;
          return row;
        });
      } catch (err) {
        // A rejection after the transaction body completes has an unknown
        // commit result. Keep both one-time claims consumed in that case.
        if (!transactionBodyCompleted) {
          try {
            await restoreEnrollmentAttempt(
              services,
              key,
              stored,
              challengeTtlMs,
              request.enrollmentTicket?.jti ?? null,
              claimId,
            );
          } catch {
            // A failed recovery keeps the ticket claimed. It never makes a
            // possibly-mutated credential reusable.
            console.error('[agent-enrollment] claim recovery failed');
          }
        }
        if (err instanceof StackError) throw err;
        console.error('[agent-enrollment] enrollment transaction failed');
        throw new ServiceUnavailableError('Enrollment temporarily unavailable, please retry');
      }

      // The key is stored: now tell the services that cache a revocation. A failure here cannot undo the
      // rotation, and online verification reads the database when a flag is missing.
      await announceRevocation().catch(() => console.error('[agent-enrollment] revocation announcement failed'));

      return reply.send({
        agent_id: agent.id,
        enrolled_at: updated.enrolled_at,
      });
    },
  );

  // ─── /sdk-bootstrap mint endpoint ──────────────────────────────────
  // The dashboard's /api/sdk-bootstrap/approve route POSTs here after
  // the operator approves an SDK enrollment in the browser. Mints a
  // single-use enrollment ticket bound to (operator, member, agent,
  // machine_label). The dashboard then 302s the browser to the SDK's
  // localhost callback with ?ticket=<jwt>&state=<from request>.
  //
  // Auth: standard middleware. Cookie session OR OAuth bearer OR
  // sk_live_* — anything that proves the operator is real and owns
  // the agent. Member role: readonly cannot enroll (same gate as the
  // enrollment routes themselves).
  app.post<{
    Params: { id: string };
    Body: { machine_label?: string };
  }>(
    '/v1/agents/:id/enrollment-tickets',
    { preHandler: [auth, denyAgentContexts], config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (request, reply) => {
      assertCanEnroll(request);
      const agent = await services.agent.getById(request.params.id, request.operatorId);
      const machineLabel = (request.body?.machine_label ?? '').slice(0, 120) || null;

      await enforceGovernanceStepUp(services, request, {
        action: 'agent_enrollment_ticket_mint',
        resourceId: agent.id,
        payload: { agent_id: agent.id, machine_label: machineLabel },
        summary: `Approve signing-key enrollment for agent ${agent.id}`,
      });

      const { token, jti, expiresAt } = await services.signer.signEnrollmentTicket({
        operatorId: request.operatorId,
        memberId: request.memberId ?? null,
        agentId: agent.id,
        machineLabel,
      });

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: agent.id }),
        layer: 'vault',
        action: 'agent.enrollment_ticket.mint',
        outcome: 'success',
        duration_ms: 0,
      });

      reply.header('Cache-Control', 'private, no-store');
      reply.header('Pragma', 'no-cache');
      return reply.send({
        ticket: token,
        jti,
        expires_at: expiresAt.toISOString(),
        expires_in: ENROLLMENT_TICKET_TTL_SECONDS,
      });
    },
  );
}

type StoredEnrollmentChallenge = {
  agent_id: string;
  operator_id: string;
  member_id: string | null;
  ticket_jti: string | null;
  challenge: string;
};

function invalidEnrollment(reply: import('fastify').FastifyReply) {
  return reply.status(400).send({
    error: {
      code: 'INVALID_ENROLLMENT',
      message: 'Enrollment request is invalid or expired',
    },
  });
}

function parseEnrollmentChallenge(value: string): StoredEnrollmentChallenge | null {
  try {
    const parsed = JSON.parse(value) as Partial<StoredEnrollmentChallenge>;
    if (
      typeof parsed.agent_id !== 'string'
      || typeof parsed.operator_id !== 'string'
      || (parsed.member_id !== null && typeof parsed.member_id !== 'string')
      || (parsed.ticket_jti !== null && typeof parsed.ticket_jti !== 'string')
      || typeof parsed.challenge !== 'string'
    ) {
      return null;
    }
    return parsed as StoredEnrollmentChallenge;
  } catch {
    return null;
  }
}

async function storeEnrollmentChallenge(
  services: Pick<Services, 'redis'>,
  key: string,
  value: string,
  ticketJti: string | null,
): Promise<boolean> {
  try {
    if (!ticketJti) {
      await services.redis.setex(key, AGENT_ENROLLMENT_CHALLENGE_TTL_SECONDS, value);
      return true;
    }
    const result = await services.redis.eval(
      `if redis.call('EXISTS', KEYS[1]) == 1 then
         return 0
       end
       redis.call('SETEX', KEYS[2], ARGV[1], ARGV[2])
       return 1`,
      2,
      enrollmentTicketClaimKey(ticketJti),
      key,
      String(AGENT_ENROLLMENT_CHALLENGE_TTL_SECONDS),
      value,
    );
    return Number(result) === 1;
  } catch {
    throw new ServiceUnavailableError('Enrollment temporarily unavailable, please retry');
  }
}

/** Compare and delete one exact challenge. Returns its remaining TTL. */
async function claimEnrollmentChallenge(
  services: Pick<Services, 'redis'>,
  key: string,
  expectedValue: string,
): Promise<number | null> {
  try {
    const result = await services.redis.eval(
      `local current = redis.call('GET', KEYS[1])
       if not current or current ~= ARGV[1] then
         return 0
       end
       local ttl = redis.call('PTTL', KEYS[1])
       if ttl < 1 then
         return 0
       end
       redis.call('DEL', KEYS[1])
       return ttl`,
      1,
      key,
      expectedValue,
    );
    const ttlMs = Number(result);
    return ttlMs > 0 ? ttlMs : null;
  } catch {
    throw new ServiceUnavailableError('Enrollment temporarily unavailable, please retry');
  }
}

/** Restore a consumed challenge before releasing this request's ticket claim. */
async function restoreEnrollmentAttempt(
  services: Pick<Services, 'redis'>,
  challengeKey: string,
  challengeValue: string,
  challengeTtlMs: number,
  ticketJti: string | null,
  claimId: string,
): Promise<void> {
  if (!ticketJti) {
    await services.redis.eval(
      `if redis.call('EXISTS', KEYS[1]) == 0 then
         redis.call('PSETEX', KEYS[1], ARGV[1], ARGV[2])
       end
       return 1`,
      1,
      challengeKey,
      String(Math.max(1, challengeTtlMs)),
      challengeValue,
    );
    return;
  }

  await services.redis.eval(
    `if redis.call('GET', KEYS[1]) ~= ARGV[1] then
       return 0
     end
     if redis.call('EXISTS', KEYS[2]) == 1 then
       return 0
     end
     redis.call('PSETEX', KEYS[2], ARGV[2], ARGV[3])
     redis.call('DEL', KEYS[1])
     return 1`,
    2,
    enrollmentTicketClaimKey(ticketJti),
    challengeKey,
    claimId,
    String(Math.max(1, challengeTtlMs)),
    challengeValue,
  );
}

/**
 * Member-role gate for enrollment. Readonly cannot enroll an agent.
 * Standard, admin, and operator-level (no memberRole) all pass.
 *
 * An earlier change enforces what documented: enrollment is a write op
 * against the agent record, and read-only members do not get write
 * access by definition. Same gate as agent.update would impose.
 */
function assertCanEnroll(request: import('fastify').FastifyRequest): void {
  if (request.memberRole === 'readonly') {
    throw new ForbiddenError('readonly members cannot enroll agents');
  }
}

/**
 * Enrollment-ticket binding check. The ticket carries the agent_id it
 * was minted for; reject if the SDK tries to use a ticket against a
 * different agent. No-op for the headless OAuth/key path.
 */
function assertTicketBindingMatches(request: import('fastify').FastifyRequest, paramAgentId: string): void {
  if (request.enrollmentTicket && request.enrollmentTicket.agent_id !== paramAgentId) {
    throw new ForbiddenError('enrollment ticket bound to a different agent');
  }
}

/**
 * Ed25519 verification of a base64url-encoded signature over the raw
 * challenge bytes (UTF-8). jose has its own SubtleCrypto wrappers but
 * for a single one-shot verify we use the Node primitives directly —
 * fewer moving parts, no JOSE wrapping/header parsing.
 */
function verifyEd25519Signature(
  challenge: string,
  signatureB64Url: string,
  publicJwk: { kty?: string; crv?: string; x?: string },
): boolean {
  try {
    const keyObject = createPublicKey({ key: publicJwk as { kty: string; crv: string; x: string }, format: 'jwk' });
    const sig = Buffer.from(signatureB64Url, 'base64url');
    // Node's `verify(null, …)` is the Ed25519 entry-point — passing null
    // for the algorithm means "use the algorithm baked into the key
    // (Ed25519)". The challenge is signed as raw UTF-8 bytes; the SDK
    // does the same on its side.
    return cryptoVerify(null, Buffer.from(challenge, 'utf8'), keyObject, sig);
  } catch {
    return false;
  }
}
