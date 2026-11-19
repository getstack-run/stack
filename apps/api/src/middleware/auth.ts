import type { FastifyRequest, FastifyReply } from 'fastify';
import {
  InvalidApiKeyError,
  ForbiddenError,
  AgentJwtReplayedError,
  ServiceUnavailableError,
  StackError,
  API_KEY_PREFIX_LIVE,
  SESSION_JWT_AUDIENCE,
  OAUTH_ACCESS_TOKEN_AUDIENCE_API,
  OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
  OAUTH_FAMILY_REVOKED_KEY,
  PASSPORT_JWT_AUDIENCE,
  AGENT_JWT_ISSUER,
  AGENT_JWT_TTL_SECONDS,
  AGENT_JWT_CLOCK_TOLERANCE_SECONDS,
  ENROLLMENT_TICKET_TTL_SECONDS,
  oauthRefreshTokens,
  safeErrorSummary,
  type PlatformIntent,
} from '@stack/shared';
import { assertOperatorActive, type BrowserDecisionSession, type EntitlementAccount } from '@stack/vault';
import { and, eq, isNull } from 'drizzle-orm';
import { decodeJwt, errors as joseErrors } from 'jose';
import type { Services } from '../config/services.js';
import type { AccessRequest } from '../config/registries.js';
import type { FeatureGate } from '../config/licence-service.js';
import { enforceOAuthRouteScope } from './oauth-scope.js';
import { enforceMemberFloorForRequest } from './member-floor.js';

/** Bound decode/signature work below Fastify's general header ceiling. */
export const MAX_BEARER_TOKEN_LENGTH = 4_096;

declare module 'fastify' {
  interface FastifyRequest {
    operatorId: string;
    operatorTier: string;
    /**
     * The account this request is billed to, set by every auth middleware
     * after the operator is known. For a white-label tenant it is the
     * partner, and `operatorTier` is the partner's plan. Unset only on
     * unauthenticated routes.
     */
    billingAccount?: EntitlementAccount;
    /**
     * Operator-account-admin flag (operators.is_admin). Distinct from
     * isPlatformStaff — this gates the dashboard /admin operator-
     * lifecycle surface (suspend, comp, tier-toggle), not platform-wide
     * routes. Set from the authenticated operator's row.
     */
    isAdmin: boolean;
    /**
     * (auth refactor): platform-staff flag (operators.is_platform_staff).
     * Set true when EITHER:
     *   - the authenticated operator's row has is_platform_staff = true, OR
     *   - the request authenticated via a passport with platform_intent
     *     and the issuing operator is_platform_staff = true at verify time.
     * Read by the requirePlatformStaff middleware (mounted on the
     * /v1/admin/* encapsulation scope). Never set by enrollment tickets,
     * agent JWTs, or session JWTs of non-staff operators.
     */
    isPlatformStaff: boolean;
    /**
     * partner-tenancy flag (operators.is_partner). When
     * true, the authenticated operator is a platform partner authorised to create
     * + manage isolated child operators via /v1/partner/* routes. Set only from the operator
     * row at request time; passport / agent-JWT / enrollment-ticket
     * paths never grant partner authority.
     */
    isPartner: boolean;
    stripeCustomerId?: string;
    memberId?: string;
    memberRole?: string;
    allowedConnections?: string[];
    /**
     * OAuth scope (space-separated) when the request authenticated via an
     * OAuth access token. `undefined` for sk_live_* and dashboard session
     * paths — interpreted as "full scope" by any future per-route gate.
     */
    oauthScope?: string;
    /** OAuth client_id when authenticated via an OAuth access token. */
    oauthClientId?: string;
    /**
     * Exact RFC 8707 resource URL signed into an OAuth MCP access token.
     * `undefined` for every other credential and for MCP tokens minted
     * before the claim existed (those were only ever granted for /mcp).
     */
    oauthResource?: string;
    /**
     * set when the request was authenticated by an agent-signed
     * JWT (iss=stack-sdk). The agent's request itself acts on behalf of
     * its parent operator (request.operatorId) but the agent context
     * scopes everything to that one agent's allowed_skills / connections.
     */
    agentId?: string;
    freshAgentProof?: boolean;
    /**
     * set when the request was authenticated by an enrollment
     * ticket (aud=stack:enrollment-ticket). Bound to one agent_id; the
     * enrollment routes assert request.params.id matches before letting
     * the request through. Single-use: /enroll claims the jti in Redis
     * before it mutates the agent key. Other enrollment-ticket routes must
     * refuse this auth source.
     */
    enrollmentTicket?: {
      agent_id: string;
      jti: string;
      machine_label: string | null;
      exp: number;
    };
    /**
     * (auth refactor) — set when the request authenticated via a
     * passport JWT (aud=stack:passport) carrying platform_intent. The
     * passport-service.verify call has already enforced revocation +
     * expiry + issuer is_platform_staff at verify time. Routes do not
     * read this directly — the requirePlatformStaff / requirePlatformMonitor
     * middlewares consume it.
     */
    platformPassport?: {
      jti: string;
      operator_id: string;
      agent_id: string;
      platform_intent: PlatformIntent;
    };
    /**
     * Verified context for every inbound STACK Passport, including regular
     * agent Passports and platform-intent Passports. Handlers must use this
     * server-derived context instead of trusting agent, mission, or service
     * identifiers supplied in a request body.
     */
    passportContext?: {
      jti: string;
      operator_id: string;
      agent_id: string;
      mission_ids: string[];
      intent_services: string[];
      services: Array<{
        service_id: string;
        service_name: string;
        scopes: string[];
        connection_id?: string;
      }>;
    };
    /**
     * true ONLY when this request authenticated via a
     * dashboard cookie-session JWT (aud stack:dashboard). The governance
     * step-up gate lets these pass free (the human at the dashboard IS
     * the approval ceremony); every Bearer credential must step up.
     */
    isDashboardSession?: boolean;
    dashboardBrowserSession?: BrowserDecisionSession;
  }
}

/**
 * classification for auth-path lookup failures.
 *
 * DOMAIN failures mean the presented CREDENTIAL is bad and bucket into
 * the uniform 401 INVALID_API_KEY (no enumeration signal): every typed
 * StackError (NotFound, PassportRevoked/Expired, OperatorSuspended...)
 * plus jose's JW* token errors (JWTExpired, JWSSignatureVerification-
 * Failed, JWTClaimValidationFailed, ...).
 *
 * Anything else is INFRASTRUCTURE — Postgres or Redis unreachable on
 * THIS machine — and must never be labeled INVALID_API_KEY: a degraded
 * database pool on one machine would otherwise read as intermittent 401s on
 * healthy credentials and send the caller chasing auth problems. Infra
 * failures fail CLOSED but RETRIABLE: 503.
 */
export function isAuthDomainError(err: unknown): boolean {
  // A dependency outage reported as a typed error is still OURS, never a 401.
  if (err instanceof ServiceUnavailableError) return false;
  if (err instanceof StackError) return true;
  // A jose error is a refused token: most names start with "JW" (JWTExpired, JWSInvalid, ...), but
  // JOSEAlgNotAllowed (an unsigned token, `alg` none) and JOSENotSupported do not, so test the class too.
  return err instanceof Error && (err.name.startsWith('JW') || err instanceof joseErrors.JOSEError);
}

/** Reject an auth lookup: domain error → 401, infra error → 503 + log. */
function rejectAuthLookup(request: FastifyRequest, err: unknown): never {
  if (isAuthDomainError(err)) {
    // Log WHY a credential was refused (error name/code/claim only, never the
    // token). Domain 401s are otherwise silent: the uniform wire error is
    // deliberate (enumeration posture), so the log is the only place the true
    // reason can live.
    const e = err as Error & { code?: string; claim?: string };
    request.log.info(
      { auth_reject: e.name, code: e.code, claim: e.claim },
      'auth domain rejection - uniform 401 returned',
    );
    throw new InvalidApiKeyError();
  }
  request.log.error(
    { err: safeErrorSummary(err) },
    'auth lookup infrastructure failure - failing 503, not 401',
  );
  if (err instanceof ServiceUnavailableError) throw err;
  throw new ServiceUnavailableError('Authentication backend temporarily unavailable, please retry');
}

/**
 * Load a team member from a token-borne `member_id` and stamp the member
 * context onto the request. The DB row is the authoritative gate — a
 * token's claims are a ceiling, never the grant.
 *
 * Fails closed on: unknown member, non-active member (revoked or still
 * `invited`), or a member belonging to a different operator than the one
 * the token resolved to. That last check is the reason this is a shared
 * helper: three call sites had re-implemented the first two and none
 * bound the member to the operator, so a `member_id` from another
 * account would have been honoured against the operator in `sub`.
 *
 * It also clears the operator-level authority flags. Every path above
 * reads `is_admin` / `is_platform_staff` / `is_partner` off the operator
 * row before it knows whether a member is present, and a member must
 * never inherit them: `is_admin` gates the operator-lifecycle surface
 * (suspend, comp, tier-toggle) and staff/partner gate cross-operator
 * scopes. The sk_live path force-cleared staff and partner but kept
 * is_admin, and the OAuth path cleared none — doing it here instead of
 * at each call site is what stops the next path from forgetting again.
 */
function stampMemberContext(
  request: FastifyRequest,
  member: { id: string; operator_id: string; role: string; status: string; allowed_connections: string[] | null },
  operatorId: string,
  features: Pick<FeatureGate, 'has'> | undefined,
): void {
  // Cleared FIRST so an early throw cannot leave inherited authority
  // standing on the request.
  request.isAdmin = false;
  request.isPlatformStaff = false;
  request.isPartner = false;

  if (member.status !== 'active') {
    // Revoked, deleted, or never accepted between token issue and use.
    throw new InvalidApiKeyError();
  }
  if (member.operator_id !== operatorId) {
    request.log.warn(
      { member_id: member.id, token_operator: operatorId, member_operator: member.operator_id },
      'auth: member_id does not belong to the token operator - refusing',
    );
    throw new InvalidApiKeyError();
  }
  request.memberId = member.id;
  // Without the roles feature an install has an owner and plain members: an
  // admin member acts as a member (narrowing), a read-only one stays read-only
  // (a lapsed licence never widens anyone).
  request.memberRole = member.role === 'admin' && features?.has('roles') === false ? 'standard' : member.role;
  request.allowedConnections = member.allowed_connections ?? undefined;
}

/** Id-taking wrapper for the paths that carry `member_id` in a token. */
async function applyMemberContext(
  services: Services,
  request: FastifyRequest,
  memberId: string,
  operatorId: string,
): Promise<void> {
  const member = await services.member.findById(memberId);
  if (!member) {
    request.isAdmin = false;
    request.isPlatformStaff = false;
    request.isPartner = false;
    throw new InvalidApiKeyError();
  }
  stampMemberContext(request, member, operatorId, services.features);
}

/**
 * Dual auth middleware.
 * Detects token type by prefix:
 *   - sk_live_ → operator API key
 *   - otherwise → session JWT verification
 *
 * Suspended/deleted operators are denied at every entry path —
 * authenticateByApiKey enforces it; the JWT path re-loads the operator
 * row and asserts. Human members authenticate with a session JWT issued by
 * email sign-in or SSO; they never receive bearer API keys.
 */
/**
 * Resolve the billing account once the operator is known and make the
 * request's plan the billing account's plan. A tenant whose partner is
 * suspended, deleted or no longer a partner is refused here, on every route,
 * not only on metered ones.
 */
export async function applyBillingAccount(
  services: Pick<Services, 'entitlements'> & Partial<Pick<Services, 'registries'>>,
  request: FastifyRequest,
): Promise<void> {
  if (!request.operatorId) return;
  const account = await services.entitlements.resolve(request.operatorId);
  request.billingAccount = account;
  request.operatorTier = account.tier;
  await runAccessGates(services, { method: request.method, route: request.routeOptions?.url ?? '', account });
}

/**
 * The deployment's access rule (`registries.accessGates`), run for every route
 * that authenticates and for the flows that read the browser session
 * themselves (OAuth consent, device approval). A gate throws to refuse.
 */
export async function runAccessGates(
  services: Partial<Pick<Services, 'registries'>>,
  access: AccessRequest,
): Promise<void> {
  // A booted deployment always has its registries (assertHostedSeams refuses one that was not sealed);
  // a partial stand-in in a test has none and so no gates.
  for (const gate of services.registries?.accessGates.list() ?? []) await gate(access);
}

/** The same rule for a flow that read the operator from the browser session, on the request it came in on. */
export async function enforceAccessForRequest(
  services: Pick<Services, 'entitlements'> & Partial<Pick<Services, 'registries'>>,
  request: Pick<FastifyRequest, 'method'> & { routeOptions?: { url?: string | undefined } },
  operatorId: string,
): Promise<void> {
  await enforceAccessForOperator(services, { method: request.method, route: request.routeOptions?.url ?? '', operatorId });
}

/** The same rule for a flow that knows the operator from the session cookie, not from a bearer. */
export async function enforceAccessForOperator(
  services: Pick<Services, 'entitlements'> & Partial<Pick<Services, 'registries'>>,
  input: { method: string; route: string; operatorId: string },
): Promise<void> {
  const account = await services.entitlements.resolve(input.operatorId);
  await runAccessGates(services, { method: input.method, route: input.route, account });
}

export function createAuthMiddleware(services: Services) {
  const authenticateCaller = createCallerAuthentication(services);
  return async function authenticate(request: FastifyRequest, reply: FastifyReply) {
    await authenticateCaller(request, reply);
    // A read-only member reads and never acts: refused here, before the billing account is read, before any handler
    // and so before anything is metered (`member-floor.ts`).
    enforceMemberFloorForRequest(services, request);
    await applyBillingAccount(services, request);
  };
}

function createCallerAuthentication(services: Services) {
  return async function authenticateCaller(request: FastifyRequest, _reply: FastifyReply) {
    const authHeader = request.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new InvalidApiKeyError();
    }

    const token = authHeader.slice(7);
    if (token.length === 0 || token.length > MAX_BEARER_TOKEN_LENGTH) {
      throw new InvalidApiKeyError();
    }

    if (token.startsWith(API_KEY_PREFIX_LIVE)) {
      const operator = await services.operator.authenticateByApiKey(token);
      request.operatorId = operator.id;
      request.operatorTier = operator.tier;
      request.isAdmin = operator.is_admin;
      request.isPlatformStaff = operator.is_platform_staff ?? false;
      request.isPartner = operator.is_partner ?? false;
      request.stripeCustomerId = operator.stripe_customer_id ?? undefined;
    } else {
      // Token is one of: dashboard session JWT, OAuth access token, a
      // an agent-signed JWT, or a passport-as-inbound-auth JWT.
      // Peek at the unverified header/claims first to dispatch:
      //   iss = stack-sdk         → agent JWT path (separate pubkey)
      //   aud = stack:passport    → platform-passport-as-inbound path
      //   else                    → session JWT or OAuth access token
      let unverified: ReturnType<typeof decodeJwt> | null;
      try {
        unverified = decodeJwt(token);
      } catch {
        unverified = null;
      }
      if (unverified?.iss === AGENT_JWT_ISSUER && unverified.sub) {
        return await authenticateAgentJwt(
          services,
          request,
          token,
          unverified.sub,
          unverified.jti as string | undefined,
          unverified.exp,
        );
      }
      const peekedAud = Array.isArray(unverified?.aud) ? unverified?.aud[0] : unverified?.aud;
      if (peekedAud === 'stack:fleet-session') {
        try {
          const claims = await services.signer.verifyFleetSession(token);
          const state = await services.fleet.sessionState(claims.operator_id, claims.agent_id,
            claims.principal_kind === 'provisioner' ? claims.policy_id : undefined);
          if (Object.entries(state.claims).some(([key, value]) => claims[key as keyof typeof claims] !== value)) throw new InvalidApiKeyError();
          if (claims.principal_kind === 'provisioner') {
            const path = request.url.split('?')[0];
            if (!(request.method === 'GET' && path === '/v1/auth/context') &&
              !(request.method === 'POST' && [`/v1/fleets/${claims.policy_id}/enrollment-challenges`, `/v1/fleets/${claims.policy_id}/enroll`].includes(path!))) throw new InvalidApiKeyError();
          }
          const operator = await services.operator.getById(claims.operator_id);
          assertOperatorActive(operator);
          request.operatorId = operator.id;
          request.operatorTier = operator.tier;
          request.agentId = claims.agent_id;
          request.isAdmin = false;
          request.isPlatformStaff = false;
          request.isPartner = false;
          request.stripeCustomerId = operator.stripe_customer_id ?? undefined;
          return;
        } catch (err) { rejectAuthLookup(request, err); }
      }
      if (peekedAud === PASSPORT_JWT_AUDIENCE) {
        return await authenticatePlatformPassport(services, request, token);
      }

      // Otherwise: dashboard session JWT or OAuth access token.
      let verified: Awaited<ReturnType<typeof services.signer.verifyAccessOrSession>>;
      try {
        verified = await services.signer.verifyAccessOrSession(token);
      } catch (err) {
        rejectAuthLookup(request, err);
      }
      let operator: Awaited<ReturnType<typeof services.operator.getById>>;
      try {
        operator = await services.operator.getById(verified.sub);
      } catch (err) {
        rejectAuthLookup(request, err);
      }
      assertOperatorActive(operator);
      request.operatorId = operator.id;
      request.operatorTier = operator.tier;
      request.isAdmin = operator.is_admin;
      request.isPlatformStaff = operator.is_platform_staff ?? false;
      request.isPartner = operator.is_partner ?? false;
      request.stripeCustomerId = operator.stripe_customer_id ?? undefined;

      if (verified.aud === OAUTH_ACCESS_TOKEN_AUDIENCE_API || verified.aud === OAUTH_ACCESS_TOKEN_AUDIENCE_MCP) {
        // Live revocation check. OAuth access tokens are stateless JWTs, so
        // without this a revoked token stays usable until its TTL expires.
        // The family id is stamped into the token at mint; a family-revoke
        // (mcp-session revoke or refresh reuse-detection) writes a Redis flag
        // and the DB `revoked_at`. Redis-first, DB-fallback — mirrors the
        // passport `isRevoked` model. Fail closed on a revoked family.
        const familyId = verified.payload['token_family_id'] as string | undefined;
        if (familyId) {
          let familyRevoked: boolean;
          try {
            familyRevoked = (await services.redis.get(OAUTH_FAMILY_REVOKED_KEY(familyId))) === '1';
            if (!familyRevoked) {
              // DB fallback (Redis flag expired or evicted): a family is revoked
              // when it is known but has no non-revoked refresh row left. A live
              // grant always keeps ≥1 non-revoked row (the current head).
              const anyLive = await services.db.query.oauthRefreshTokens.findFirst({
                where: and(eq(oauthRefreshTokens.token_family_id, familyId), isNull(oauthRefreshTokens.revoked_at)),
                columns: { token_hash: true },
              });
              const familyExists = await services.db.query.oauthRefreshTokens.findFirst({
                where: eq(oauthRefreshTokens.token_family_id, familyId),
                columns: { token_hash: true },
              });
              if (familyExists && !anyLive) familyRevoked = true;
            }
          } catch (err) {
            // Redis or Postgres unreachable: fail closed and retriable (503), never a 500.
            rejectAuthLookup(request, err);
          }
          if (familyRevoked) throw new InvalidApiKeyError();
        }
        // OAuth path: carry scope + client_id through to handlers. Per-route
        // scope gating lands; just records.
        request.oauthScope = (verified.payload['scope'] as string | undefined) ?? '';
        request.oauthClientId = verified.payload['client_id'] as string | undefined;
        const resourceClaim = verified.payload['resource'];
        if (verified.aud === OAUTH_ACCESS_TOKEN_AUDIENCE_MCP && typeof resourceClaim === 'string') {
          request.oauthResource = resourceClaim;
        }
        const memberId = verified.payload['member_id'] as string | undefined;
        if (memberId) {
          // Re-load the team_members row to set role + allowed_connections.
          // Token's scope is a ceiling; the DB row is the authoritative gate.
          // Revocation
          // between token issue and use fails closed here — the refresh-
          // rotation cascade in MemberService.revoke catches it proactively,
          // but a token may still be in flight at the moment of revocation.
          await applyMemberContext(services, request, memberId, operator.id);
        }
        enforceOAuthRouteScope(request, _reply, services.registries.routeScopes);
      } else if (verified.aud === SESSION_JWT_AUDIENCE) {
        // Dashboard-session path.: the stamp lets the governance
        // step-up gate distinguish "human at the dashboard" (the ceremony
        // itself — passes free) from Bearer-credential contexts that
        // must present an approval. Only THIS branch may set it.
        //
        // The stamp describes the CHANNEL (a human at a browser), not
        // privilege. Privilege comes from the member context below.
        request.isDashboardSession = true;

        // A member signing in at the dashboard gets a session JWT
        // carrying `member_id` (signMemberSessionToken). Until this
        // block existed the claim was ignored, so a member session
        // authenticated as the bare parent operator: no role gate on
        // requireOperatorAdmin, no allowed_connections scoping, and the
        // operator row's is_admin inherited wholesale. Same authoritative
        // -row contract as the sk_live_* and OAuth member paths.
        if (verified.payload['member_id'] !== undefined || verified.payload['is_member'] === true) {
          request.isAdmin = false;
          request.isPlatformStaff = false;
          request.isPartner = false;
        }
        const identity = await services.browserSessions.identity(verified, operator);
        request.dashboardBrowserSession = services.browserSessions.decisionSession(verified);
        if (identity.member) stampMemberContext(request, identity.member, operator.id, services.features);
      } else {
        throw new InvalidApiKeyError();
      }
    }
  };
}

/**
 * enrollment-ticket-or-standard-auth prehandler.
 *
 * Used ONLY by /v1/agents/:id/enrollment-challenge + /v1/agents/:id/
 * enroll. Tries to verify the bearer as an enrollment ticket first
 * (aud=stack:enrollment-ticket); on success, sets operator/member
 * context from the ticket claims and stamps request.enrollmentTicket
 * so the route handler can assert agent_id binding and claim the jti
 * before it mutates the agent key.
 *
 * If the bearer is not an enrollment ticket (verification fails for
 * any reason — wrong audience, bad signature, expired), falls through
 * to the standard auth middleware. This preserves the headless/CI path
 * where the SDK uses an OAuth bearer or sk_live_* key directly.
 *
 * Important: the ticket is single-use. The /enroll handler claims it
 * after proof-of-possession verifies and before the database mutation.
 * challenge MUST NOT claim it. The SDK calls challenge then enroll, both
 * with the same ticket.
 */
export function createEnrollmentAuthMiddleware(services: Services) {
  const standardAuth = createAuthMiddleware(services);
  return async function enrollmentOrStandardAuth(request: FastifyRequest, reply: FastifyReply) {
    const authHeader = request.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      if (token.length === 0 || token.length > MAX_BEARER_TOKEN_LENGTH) {
        throw new InvalidApiKeyError();
      }
      // Signature and audience failures can still be a standard bearer.
      // After verification, ticket dependency failures stay on this path.
      let ticket: Awaited<ReturnType<Services['signer']['verifyEnrollmentTicket']>>;
      try {
        ticket = await services.signer.verifyEnrollmentTicket(token);
      } catch {
        return standardAuth(request, reply);
      }
      try {
        // A claimed jti is opaque replay. The challenge call happens before
        // the enroll handler takes this claim.
        const burned = await services.redis.get(enrollmentTicketClaimKey(ticket.jti));
        if (burned) {
          throw new InvalidApiKeyError();
        }
        // Resolve operator + member context from claims.
        const operator = await services.operator.getById(ticket.operator_id);
        assertOperatorActive(operator);
        request.operatorId = operator.id;
        request.operatorTier = operator.tier;
        request.isAdmin = false; // enrollment tickets cannot self-promote
        request.isPlatformStaff = false; // enrollment tickets cannot self-promote
        request.isPartner = false; // enrollment tickets cannot self-promote
        request.stripeCustomerId = operator.stripe_customer_id ?? undefined;
        if (ticket.member_id) {
          await applyMemberContext(services, request, ticket.member_id, operator.id);
        }
        request.enrollmentTicket = {
          agent_id: ticket.agent_id,
          jti: ticket.jti,
          machine_label: ticket.machine_label,
          exp: ticket.exp,
        };
      } catch (err) {
        rejectAuthLookup(request, err);
      }
      // The ticket's member is held to the same floor as any other (a member whose role was lowered after the ticket
      // was minted is refused): outside the try above, which would turn the 403 into an invalid credential.
      enforceMemberFloorForRequest(services, request);
      try {
        await applyBillingAccount(services, request);
        return;
      } catch (err) {
        rejectAuthLookup(request, err);
      }
    }
    return standardAuth(request, reply);
  };
}

export function enrollmentTicketClaimKey(jti: string): string {
  return `stack:enroll_ticket_burned:${jti}`;
}

/** Claim one ticket before any agent-key mutation. */
export async function claimEnrollmentTicket(
  services: Pick<Services, 'redis'>,
  ticket: { jti: string; exp: number },
  claimId: string,
): Promise<boolean> {
  const ttlSeconds = Math.max(
    1,
    Math.min(
      ENROLLMENT_TICKET_TTL_SECONDS + 10,
      ticket.exp - Math.floor(Date.now() / 1000) + 10,
    ),
  );
  try {
    const result = await services.redis.set(
      enrollmentTicketClaimKey(ticket.jti),
      claimId,
      'EX',
      ttlSeconds,
      'NX',
    );
    return result === 'OK';
  } catch {
    throw new ServiceUnavailableError('Enrollment temporarily unavailable, please retry');
  }
}

/** Release only this request's claim. A loser cannot release a winner. */
export async function releaseEnrollmentTicketClaim(
  services: Pick<Services, 'redis'>,
  jti: string,
  claimId: string,
): Promise<boolean> {
  try {
    const result = await services.redis.eval(
      `if redis.call('GET', KEYS[1]) == ARGV[1] then
         return redis.call('DEL', KEYS[1])
       end
       return 0`,
      1,
      enrollmentTicketClaimKey(jti),
      claimId,
    );
    return Number(result) === 1;
  } catch {
    throw new ServiceUnavailableError('Enrollment temporarily unavailable, please retry');
  }
}

/**
 * agent JWT verification path.
 *
 * Each request from the agent runtime carries a fresh JWT signed with
 * the agent's locally-generated privkey. We:
 *
 *   1. Look up the stored pubkey by sub (agent_id).
 *   2. Verify the signature, audience, issuer, and TTL bounds via the
 *      signer's verifyAgentJwt helper.
 *   3. Replay-protect: a `jti` is good exactly once. Redis SETNX with
 *      TTL slightly longer than the JWT's max TTL — if the key exists,
 *      this is a replay and we refuse.
 *   4. Resolve operator + member context from the agents row (agents
 *      are operator-scoped; the member context flows from whoever
 *      enrolled the agent if applicable — an earlier change keeps this empty
 *      member→agent linkage is a future iteration).
 *
 * Sets request.agentId in addition to request.operatorId. The proxy +
 * passport routes already gate by agent; downstream handlers can rely
 * on agentId being present when the request was agent-authenticated.
 */
async function authenticateAgentJwt(
  services: Services,
  request: FastifyRequest,
  token: string,
  agentId: string,
  jti: string | undefined,
  exp: number | undefined,
): Promise<void> {
  if (
    !jti ||
    typeof exp !== 'number' ||
    !Number.isSafeInteger(exp) ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(agentId) ||
    !/^[A-Za-z0-9_-]{1,200}$/.test(jti)
  ) {
    throw new InvalidApiKeyError();
  }

  // Look up the agent + verify the signature against the stored pubkey.
  // A lookup failure must not be swallowed into a null: that would turn a
  // database outage on one machine into 401 INVALID_API_KEY. A missing agent
  // throws NotFoundError (domain → 401); anything non-domain is
  // infrastructure → 503.
  let agent: Awaited<ReturnType<typeof services.agent.getById>>;
  try {
    agent = await services.agent.getById(agentId);
  } catch (err) {
    rejectAuthLookup(request, err);
  }
  if (!agent.pubkey || !agent.enrolled_at) {
    // Agent exists but never enrolled — refuse. The SDK should have hit
    // /enroll first.
    throw new InvalidApiKeyError();
  }
  if (agent.status !== 'active' || agent.passport_blocked) {
    // Suspended or revoked agent — fail closed.
    throw new InvalidApiKeyError();
  }
  let verifiedExp: number;
  try {
    verifiedExp = (await services.signer.verifyAgentJwt(token, agent.pubkey)).exp;
  } catch (err) {
    rejectAuthLookup(request, err); // jose errors are domain → 401
  }

  // Resolve operator + tier (status check). Same path as the operator
  // key route — the agent acts on behalf of its parent operator.
  const operator = await services.operator.getById(agent.operator_id);
  assertOperatorActive(operator);

  // Only a cryptographically verified token may allocate a Redis replay
  // entry. The previous order trusted unverified sub/jti values first, which
  // let an attacker fill Redis and pre-burn a legitimate future nonce.
  const replayKey = `stack:agent_jwt:${agent.id}:${jti}`;
  // The jti is remembered until the token can no longer verify: its `exp` plus the clock tolerance
  // (never less than twice the lifetime the SDKs mint). A fixed window shorter than that let a
  // 120 second token be presented again in its last seconds.
  const replayTtlSeconds = Math.max(
    AGENT_JWT_TTL_SECONDS * 2,
    verifiedExp - Math.floor(Date.now() / 1000) + AGENT_JWT_CLOCK_TOLERANCE_SECONDS + 1,
  );
  let ok: unknown;
  try {
    ok = await services.redis.set(replayKey, '1', 'EX', replayTtlSeconds, 'NX');
  } catch (err) {
    rejectAuthLookup(request, err);
  }
  if (!ok) {
    throw new AgentJwtReplayedError();
  }

  request.operatorId = operator.id;
  request.operatorTier = operator.tier;
  request.isAdmin = false; // agent JWTs cannot self-promote to admin
  request.isPlatformStaff = false; // agent JWTs cannot self-promote to platform-staff
  request.isPartner = false; // agent JWTs cannot self-promote to partner
  request.stripeCustomerId = operator.stripe_customer_id ?? undefined;
  request.agentId = agent.id;
  request.freshAgentProof = true;
}

/**
 * (auth refactor) — passport-as-inbound-auth.
 *
 * The 6th auth path. Distinguished from regular session/OAuth tokens by
 * audience (`stack:passport`). Verifies the passport via the live
 * passport-service (revocation-aware), then re-confirms the issuing
 * operator's `is_platform_staff` flag at request time so flag removal
 * invalidates every existing platform passport even before TTL.
 *
 * Sets:
 *   request.operatorId        — passport.operator_id
 *   request.agentId           — passport.agent_id
 *   request.isPlatformStaff   — true iff issuer is_platform_staff = true
 *                               AND passport.platform_intent = 'staff'
 *   request.platformPassport  — full context (consumed by
 *                               requirePlatformStaff / requirePlatformMonitor)
 *
 * A passport WITHOUT `platform_intent` reaches this path only by
 * accident (a regular operator presenting a credential-passport as an
 * inbound bearer). Such requests authenticate as operator-scoped (no
 * isPlatformStaff, no platformPassport stamp) — they get whatever the
 * operator-scope routes give. They cannot pass /v1/admin/* gates.
 */
/**
 * The routes a Passport made for a workspace command may be the bearer of: STACK's proxy, which is how code in the
 * machine reaches the services its command was granted, and the proxy's own reads. Everything else is closed to it,
 * above all the routes that make or renew a Passport and the workspace routes themselves: a process left running in
 * the machine holds this token, and it must not be able to keep itself alive or start another command with it. A
 * route nobody listed here is refused (a Passport made for a command is closed out of a new route until it is opened).
 */
const WORKSPACE_COMMAND_PASSPORT_ROUTES: ReadonlySet<string> = new Set([
  'POST /v1/proxy',
  'GET /v1/proxy/usage',
  'POST /v1/proxy/operations/get',
]);

async function authenticatePlatformPassport(
  services: Services,
  request: FastifyRequest,
  token: string,
): Promise<void> {
  // Live verify through the passport-service: signature + iss + aud +
  // expiry + revocation. Throws PassportRevokedError / PassportExpiredError
  // / signature errors. We bucket every failure into InvalidApiKeyError
  // for a uniform 401 surface — explicit reasons aren't useful to the
  // caller and risk leaking enumeration signal.
  let claims: Awaited<ReturnType<typeof services.passport.verify>>;
  try {
    // check_freshness: false — agent / service-grant freshness is
    // enforced for credential-proxy passports, but a platform passport
    // is inbound auth, not outbound credential. The agent rows for
    // op_stack_system's platform agents are stable; the freshness check
    // would just add DB hits to every /v1/admin/* request.
    claims = await services.passport.verify(token, { check_freshness: false });
  } catch (err) {
    // verify touches Redis + DB for revocation — an infra
    // failure there is 503, not "your passport is invalid".
    rejectAuthLookup(request, err);
  }

  // A command's Passport is a bearer only where WORKSPACE_COMMAND_PASSPORT_ROUTES says.
  if (claims.stk.workspace_command && !WORKSPACE_COMMAND_PASSPORT_ROUTES.has(`${request.method} ${request.routeOptions?.url ?? ''}`)) {
    throw new ForbiddenError("A Passport made for a workspace command reaches STACK's proxy only");
  }

  // Resolve issuer operator + assert active.
  let operator: Awaited<ReturnType<typeof services.operator.getById>>;
  try {
    operator = await services.operator.getById(claims.stk.operator_id);
  } catch (err) {
    rejectAuthLookup(request, err);
  }
  assertOperatorActive(operator);

  request.operatorId = operator.id;
  request.operatorTier = operator.tier;
  // Operator-account-admin from the operator row (matches what API key
  // path would set). Distinct from isPlatformStaff below.
  request.isAdmin = operator.is_admin;
  request.stripeCustomerId = operator.stripe_customer_id ?? undefined;
  request.agentId = claims.stk.agent_id;
  request.passportContext = {
    jti: claims.jti,
    operator_id: claims.stk.operator_id,
    agent_id: claims.stk.agent_id,
    mission_ids: claims.stk.mission_ids ?? [],
    intent_services: claims.stk.intent_services ?? [],
    services: claims.stk.services.map((service) => ({
      service_id: service.service_id,
      service_name: service.service_name,
      scopes: [...service.scopes],
      ...(service.connection_id ? { connection_id: service.connection_id } : {}),
    })),
  };

  const platformIntent = claims.stk.platform_intent;
  if (platformIntent) {
    // Re-confirm issuer is_platform_staff at request time. Removing the
    // flag invalidates every existing platform passport here (even ones
    // already in flight — verify-time gate, not just refresh).
    if (!operator.is_platform_staff) {
      throw new InvalidApiKeyError();
    }
    request.isPlatformStaff = true;
    request.isPartner = false; // platform_intent passports never carry partner authority
    request.platformPassport = {
      jti: claims.jti,
      operator_id: claims.stk.operator_id,
      agent_id: claims.stk.agent_id,
      platform_intent: platformIntent,
    };
  } else {
    // Regular passport presented as inbound bearer (rare; the SDK uses
    // sk_live_* / OAuth tokens for inbound calls). Authenticate as
    // operator-scoped. /v1/admin/* gates will refuse.
    request.isPlatformStaff = false;
    request.isPartner = false;
  }
}
