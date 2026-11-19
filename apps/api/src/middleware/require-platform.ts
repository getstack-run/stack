import type { FastifyRequest, FastifyReply } from 'fastify';
import { ForbiddenError } from '@stack/shared';

/**
 * (auth refactor): formal scope-hierarchy preHandlers.
 *
 * These middlewares are mounted at the encapsulation-scope level
 * (Fastify register block) so a route registered through that block
 * inherits the gate by virtue of the path it lives at — the developer
 * does not pick the gate, the path does.
 *
 *   /v1/admin/*        →  requirePlatformStaff   (cross-operator,
 *                                                  STACK staff or
 *                                                  platform_intent='staff'
 *                                                  passport)
 *   /v1/admin/monitoring/* →  requirePlatformMonitorOrStaff
 *
 * Why encapsulation, not per-route preHandler:
 *   - A `preHandler: requirePlatformStaff` at the route level can be
 *     forgotten by a developer copying a route file. Same fragility as
 *     the inline `if (!request.isAdmin) throw` we are replacing.
 *   - Routes registered through the encapsulation block carry the gate
 *     in their preHandler chain whether or not the route file mentions
 *     it. Adding `/v1/admin/foo` literally cannot bypass.
 *
 * Threat model (ranked):
 *   1. Privilege escalation via forgotten gate
 *      → encapsulation gate cannot be forgotten.
 *   2. Privilege escalation via wrong gate (requireRole('admin'))
 *      → operator-admin and platform-staff are distinct types in scope
 *        encapsulation; cross-mounting a member-role gate on /v1/admin/*
 *        would surface in the structural test that asserts the chain.
 *   3. Privilege escalation via passport delegation
 *      → passport-service.delegate refuses platform_intent passports.
 *        platform_intent never carries to a child JWT.
 *   4. Privilege persistence after flag removal
 *      → requirePlatformStaff reads request.isPlatformStaff which the
 *        auth middleware re-reads from the operator row at request time
 *        (or re-confirms is_platform_staff=true on the passport issuer).
 *        Removing the flag invalidates every existing platform passport
 *        AND every existing operator-key session at the next request.
 *   5. Cross-operator data exposure on copy-paste
 *      → all /v1/admin/* routes are gated by requirePlatformStaff at
 *        the prefix; a route file accidentally registered there cannot
 *        leak to a non-staff operator regardless of handler logic.
 *
 * The structural test in apps/api/src/middleware/require-platform.test.ts
 * walks app.printRoutes() after server boot and asserts the gate chain
 * matches the path. CI fails any commit that breaks the invariant.
 */

/**
 * Gate for `/v1/admin/*` routes. Pass conditions (any one of):
 *   1. request.isPlatformStaff = true
 *      - Set by auth middleware when:
 *        a. The authenticated operator's row has is_platform_staff=true
 *           (operator API key, session JWT, or OAuth-with-platform-staff-
 *           operator path). Members never inherit platform-staff even on
 *           a platform-staff operator's account.
 *        b. The request authenticated via a passport (aud=stack:passport)
 *           carrying platform_intent='staff' AND the issuing operator is
 *           STILL is_platform_staff=true at verify time.
 *
 * Refusal writes a ForbiddenError; the audit middleware records the
 * failed attempt. There is no reason text leaked to the caller — a
 * platform-staff route refusing a non-staff caller should look like any
 * other 403 to avoid enumeration signal.
 */
export async function requirePlatformStaff(
  request: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
  if (request.isPlatformStaff !== true) {
    throw new ForbiddenError('platform-staff access required');
  }
}

/**
 * Gate for `/v1/admin/monitoring/*` routes. Pass conditions
 * (any one of):
 *   1. request.platformPassport.platform_intent === 'monitor'
 *      AND the auth middleware verified the issuer = op_stack_system at
 *      verify time. This is the future 24/7 monitoring agent's path
 *      (agt_stack_monitor under op_stack_system).
 *   2. request.isPlatformStaff = true
 *      Platform-staff is a strict superset; humans can hit the
 *      monitoring endpoints alongside the agent. Without this branch a
 *      live human triage would need to mint a monitor passport just to
 *      look at the surface, which would defeat the workflow.
 *
 * The platform-monitor passport itself is restricted at issuance to
 * operator_id === STACK_SYSTEM_OPERATOR_ID (passport-service.issue
 * refuses 'monitor' for any other issuer, even one with
 * is_platform_staff=true). This middleware therefore does NOT need to
 * re-check the issuer id — the platform_intent='monitor' claim is by
 * construction system-operator-only.
 */
export async function requirePlatformMonitorOrStaff(
  request: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
  if (request.isPlatformStaff === true) return;
  if (request.platformPassport?.platform_intent === 'monitor') return;
  throw new ForbiddenError('platform-monitor or platform-staff access required');
}

/**
 * Gate for operator-scoped admin actions (member CRUD, OAuth-app CRUD,
 * agent-keypair rotation, skills approve/reject within an operator).
 *
 * Pass conditions:
 *   - For an operator API key: isAdmin (operator's is_admin flag).
 *   - For an OAuth or dashboard member session: memberRole === 'admin'.
 *   - Session JWTs without a member context: depends on operator.is_admin
 *     (matches today's `requireRole(_, 'admin')` behavior — operator =
 *     always allowed for own-data admin).
 *
 * Distinct from requirePlatformStaff: operator-admin authority is
 * scoped to ONE operator's data. A team-member-admin on operator A
 * cannot operate on operator B; a platform-staff on op_stack_system can
 * (subject to the cross-operator routes being mounted under
 * requirePlatformStaff, not this gate).
 *
 * Replaces the per-handler `requireRole(request, 'admin')` calls in
 * members.ts and oauth-apps.ts. Replaces the inline
 * `request.isAdmin || request.memberRole === 'admin'` check in agents.ts
 * (rotation branch).
 */
/**
 * Gate for `/v1/partner/*` routes. The partner-tenancy primitive lets a
 * platform partner create + manage isolated child operators on behalf of
 * their customers. Partner authority is granted at the operators row level
 * via is_partner=true.
 *
 * Pass condition:
 *   - request.isPartner === true  (set by auth middleware when the
 *     authenticated operator's row has is_partner=true).
 *
 * Routes under /v1/partner/* take partner-scoped operations: create
 * child operators, list children, provision webhooks under a child,
 * mint passports under a child. Each route handler additionally checks
 * that the targeted tenant's parent_operator_id matches the partner's
 * operator_id — a partner cannot operate on a non-owned tenant even if
 * they know its id.
 */
export async function requirePartner(
  request: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
  if (request.isPartner !== true) {
    throw new ForbiddenError('partner access required');
  }
}

export async function requireOperatorAdmin(
  request: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
  // agent-bearing contexts (passport-as-inbound-auth or agent
  // JWT) are watched-system principals and never carry governance
  // authority, regardless of the operator row's flags. Without this,
  // the no-member branch below silently admitted them — the
  // no-self-authorization inversion.
  denyAgentContextsSync(request);
  // Member context: role must be admin. (Members on a non-admin operator
  // are NOT auto-admin even if their parent operator is_admin=true; the
  // member's role is the authoritative gate for their context.)
  if (request.memberId) {
    if (request.memberRole !== 'admin') {
      throw new ForbiddenError('operator-admin access required');
    }
    return;
  }
  // Operator context (no member, no agent): operator API key, session
  // JWT, OAuth without member_id. The operator owns their own account,
  // so any route gated by operator-admin is by default callable by the
  // operator themselves. This matches the legacy requireRole behavior:
  //   if (!request.memberId) return; // operator — always allowed
  // We keep that contract — operator-account-admin actions don't need
  // an additional is_admin check on the operator-key path.
}

/**
 * the no-self-authorization gate.
 *
 * Denies any request whose auth context carries an `agentId`: the
 * passport-as-inbound path (aud=stack:passport) and the agent-JWT path
 * (iss=stack-sdk) both stamp it. A context with `agentId` set IS the
 * watched system — it must never reach the controls that govern it
 * (review decisions, detector config, security-event resolution,
 * self-unblock, intent approval, notification rules, scope expansion,
 * identity/billing/CMEK/account mutations).
 *
 * Doctrine: separation of privilege (Saltzer-Schroeder), separation of
 * duties (NIST SP 800-53 AC-5 — the access-control admin must not
 * administer the audit/monitoring functions), OWASP LLM06:2025
 * Excessive Agency. Also load-bearing for EU AI Act Article 14: the
 * oversight measures must be exercisable by natural persons; a surface
 * the overseen system can switch off does not qualify.
 *
 * Deliberately NOT applied to safety-increasing or operational paths:
 * passport lifecycle (incl. every revocation route — the agent-callable
 * kill switch is a feature), checkpoint/checkout, proxy, dropoffs,
 * skill invocation/publishing, missions, intent submit/simulate,
 * evidence export, LLM gateway. The structural test in
 * require-platform.test.ts enforces that every mutating route is
 * either on that operational allowlist or carries this gate.
 *
 * Human paths are unaffected: operator API keys, dashboard sessions,
 * and OAuth tokens never carry agentId. Platform-staff passports pass
 * through requirePlatformStaff on /v1/admin/* — a separate scope that
 * never mounts this gate.
 */
export async function denyAgentContexts(
  request: FastifyRequest,
  _reply: FastifyReply,
): Promise<void> {
  denyAgentContextsSync(request);
}

function denyAgentContextsSync(request: FastifyRequest): void {
  if (request.agentId) {
    // Uniform 403; no reason detail beyond the principal class — the
    // audit middleware records the attempt, and an agent probing its
    // own governance surface is itself a signal worth keeping quiet.
    throw new ForbiddenError('this action requires a non-agent principal');
  }
}
