import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ForbiddenError, MissionPausedError, MissionRefForbidden, fleetDigest, resolveMissionRef, safeErrorSummary, type IntentClaim, type MissionCapName, type NormalizedRequest } from '@stack/shared';
import type { FleetAdmission, MissionGateVerdict as GateVerdict, PrepareFleetAdmission, PassportJWTPayload, ProxyEligibility } from '@stack/vault';
import type { Services } from '../config/services.js';
import { onRequestEnd } from '../middleware/request-end.js';
import { attachMissionAction } from '../middleware/mission-action.js';
import { runtimeAuthorityRequestIdFromHeaders, enforceRuntimeAuthority, markRuntimeAuthorityDispatched,
  completeRuntimeAuthorityUse, type RuntimeAuthorityResult, type LegacyRuntimeAuthorityResult } from './runtime-authority.js';

const pending = new WeakMap<FastifyRequest, { services: Services; admission: FleetAdmission }[]>();
const dropoffAuthorities = new WeakMap<FleetAdmission, RuntimeAuthorityResult | LegacyRuntimeAuthorityResult>();

export async function dispatchFleetDropoff(services: Services, admission: FleetAdmission): Promise<void> {
  await services.fleetAdmission.reserve(admission, 0);
  const authority = dropoffAuthorities.get(admission);
  if (!authority) throw new ForbiddenError();
  await markRuntimeAuthorityDispatched(services.authority, admission.authorization.operatorId, authority);
  await services.fleetAdmission.dispatch(admission);
}

export async function completeFleetDropoff(services: Services, admission: FleetAdmission | null, result: unknown): Promise<void> {
  if (!admission) return;
  const authority = dropoffAuthorities.get(admission);
  if (!authority) throw new ForbiddenError();
  await completeRuntimeAuthorityUse(services.authority, admission.authorization.operatorId, authority, 'succeeded', result,
    { intentClaimId: admission.authorization.intentClaimId });
  dropoffAuthorities.delete(admission);
  await services.fleetAdmission.finish(admission, 0);
}

/**
 * Which connections of `provider` this request may be offered; the one resolver picks among them and never outside
 * them. A Passport's grants for the provider are the set (a grant that names no connection stands for the provider's
 * one shared connection). A fleet Passport must name its connections: a fleet scope without one is refused, never
 * guessed. A team member's request keeps their own-before-shared order and their `allowed_connections`, narrowed to
 * the Passport's grants when every grant names its connection. With no Passport (an owner API key) it is the account's
 * shared connections.
 */
export function connectionEligibility(
  request: Pick<FastifyRequest, 'memberId' | 'allowedConnections'>,
  provider: string,
  claims?: PassportJWTPayload,
): ProxyEligibility {
  if (!claims) {
    return request.memberId
      ? { kind: 'member', memberId: request.memberId, allowedConnections: request.allowedConnections }
      : { kind: 'shared' };
  }
  const scopes = claims.stk.services.filter(service => service.service_name === provider);
  const unpinned = scopes.some(service => !service.connection_id);
  if (claims.stk.fleet && unpinned) throw new ForbiddenError();
  const granted = scopes.flatMap(service => (service.connection_id ? [service.connection_id] : []));
  if (!request.memberId) {
    return { kind: 'connections', connectionIds: granted, ...(unpinned ? { sharedFallback: true } : {}) };
  }
  const allowed = unpinned
    ? request.allowedConnections
    : request.allowedConnections ? granted.filter(id => request.allowedConnections!.includes(id)) : granted;
  return { kind: 'member', memberId: request.memberId, allowedConnections: allowed };
}

/** A fleet admission the request is responsible for: finished or cancelled when the request ends. */
export function trackFleetAdmission(request: FastifyRequest, services: Services, admission: FleetAdmission): void {
  pending.set(request, [...(pending.get(request) ?? []), { services, admission }]);
}

/**
 * Settles every fleet admission a request left open, once, when the request is
 * over however it ended (`onRequestEnd`: the response, the action finishing
 * after its client left, or a streamed answer the client cut). Includes
 * failures after a producer has dispatched.
 */
export function registerFleetRuntimeLifecycle(app: FastifyInstance) {
  onRequestEnd(app, async (request, statusCode) => {
    const work = pending.get(request) ?? [];
    pending.delete(request);
    for (const { services, admission } of work) {
      try {
        const authority = dropoffAuthorities.get(admission);
        if (authority) {
          await completeRuntimeAuthorityUse(services.authority, admission.authorization.operatorId, authority, 'failed',
            { outcome: 'failed', status: statusCode }, { intentClaimId: admission.authorization.intentClaimId });
          dropoffAuthorities.delete(admission);
          await services.fleetAdmission.abort(admission);
          continue;
        }
        if (admission.state === 'dispatched' && statusCode >= 200 && statusCode < 500 && statusCode !== 202) {
          await services.fleetAdmission.finish(admission);
        } else {
          await services.fleetAdmission.abort(admission);
        }
      } catch (err) {
        // The ledger row stays dispatched or reserved; the reservation sweep converges it.
        console.error('[fleet] admission settle failed', safeErrorSummary(err));
      }
    }
  });
}

export function normalizedFleetOperation(action: string, body: unknown): NormalizedRequest {
  return { method: action, url: { origin: 'stack://runtime', host: 'runtime', pathname: '/' }, body, query: {}, headers: {} };
}

/** Producers with a fleet admission ledger. The others are gated but not ledgered. */
type FleetProducer = PrepareFleetAdmission['producer'];
// 'account' is an agent account's own surfaces (its mail and texts, sandbox
// runs, browser, purchases and wallet). It has no fleet rules, so a fleet
// Passport is refused on it. 'self' is an agent reading or acknowledging what is
// its own and acts on nobody (its queue of wake-ups): no fleet rule governs it, so
// a fleet Passport is admitted on it without the fleet ledger.
export type AgentRuntimeProducer = FleetProducer | 'intent' | 'authority' | 'account' | 'self';

export interface AgentRuntimeInput {
  /** The agent the action is performed as. */
  agentId: string;
  /** A stored Passport JTI named by the caller (body field), when no bearer token carries one. */
  passportId?: string | null;
  /** Caller-selected Mission. Must be one the Passport carries; never a free-form id. */
  explicitMissionId?: string | null;
  producer: AgentRuntimeProducer;
  /**
   * The identifier the Mission's caps and scope are checked against.
   * External services (proxy, LLM, an http_call intent) pass the provider
   * name and are narrowed by `mission.intent_services`. STACK-internal
   * operations pass a `stack:<domain>` id with `internal: true`: they are
   * not services a Mission can list (intent_services must be a subset of the
   * Passport's connected services), so scope narrowing does not apply, but
   * lifecycle, duration and every cap still do.
   */
  requestedService: string;
  internal?: boolean;
  connectionId?: string;
  targetId: string;
  action: string;
  normalizedRequest: NormalizedRequest;
  bytes?: number;
  /** Accountability recorded on a denial when the Passport row (not the JWT) is the source. */
  accountability?: 'enforced' | 'logged' | 'standard';
  /**
   * The Passport as this request ALREADY verified it (full verify: signature,
   * expiry, live revocation, owner/agent/lineage and grant freshness), so the
   * admission check does not verify the same token a second time.
   * Used only when `token` is exactly the token this request presents;
   * anything else is ignored and the token is verified here as usual.
   */
  verifiedPassport?: { token: string; claims: PassportJWTPayload };
  /** Shape recorded on the intent_denial claim if the Mission refuses the action. */
  denial: {
    intentType: IntentClaim['intent_type'];
    namedIntent: string;
    parameters: Record<string, unknown>;
  };
}

export interface AgentRuntime {
  passportJti: string;
  /** The one Mission this action runs under. Use it for every attribution downstream. */
  missionId: string;
  missionIds: string[];
  /** The accountability mode of the Passport the action runs under. */
  accountability: 'enforced' | 'logged' | 'standard';
  /** Set only for fleet Passports on fleet producers. */
  fleet: FleetAdmission | null;
}

const FLEET_PRODUCERS = new Set<AgentRuntimeProducer>(['proxy', 'llm', 'skill', 'a2a', 'dropoff']);

interface ResolvedPassport {
  jti: string;
  missionIds: string[];
  accountability: 'enforced' | 'logged' | 'standard';
  claims: PassportJWTPayload | null;
}

function bearerPassportToken(request: FastifyRequest): string | undefined {
  const header = request.headers['x-passport-token'];
  const bearer = request.headers.authorization;
  return typeof header === 'string' ? header
    : request.passportContext && bearer?.startsWith('Bearer ') ? bearer.slice(7) : undefined;
}

async function resolvePassport(services: Services, request: FastifyRequest, input: AgentRuntimeInput): Promise<ResolvedPassport | null> {
  const token = bearerPassportToken(request);
  if (token) {
    const claims = input.verifiedPassport && input.verifiedPassport.token === token
      ? input.verifiedPassport.claims
      : await services.passport.verify(token);
    if (claims.stk.operator_id !== request.operatorId || claims.stk.agent_id !== input.agentId ||
        (request.agentId && request.agentId !== claims.stk.agent_id) || (input.passportId && input.passportId !== claims.jti)) throw new ForbiddenError();
    return { jti: claims.jti, missionIds: [...(claims.stk.mission_ids ?? [])], claims,
      accountability: (claims.stk.accountability as ResolvedPassport['accountability'] | undefined) ?? 'standard' };
  }
  // A fleet member may only act with its fleet Passport token, never a bare JTI.
  await services.fleetAdmission.assertUnboundAgent(request.operatorId, input.agentId);
  if (!input.passportId) return null;
  const row = await services.passport.findByJti(input.passportId);
  if (!row || row.operator_id !== request.operatorId || row.agent_id !== input.agentId ||
      (request.agentId && request.agentId !== row.agent_id) || row.revoked_at || row.expires_at.getTime() <= Date.now()) {
    throw new ForbiddenError('Passport cannot authorize this action');
  }
  return { jti: row.jti, missionIds: [...(row.mission_ids ?? [])], claims: null, accountability: input.accountability ?? 'standard' };
}

/**
 * When the caller is executing an intent it already submitted and had approved,
 * that intent_claim is already counted under the Mission. Counting it again here
 * would refuse the last approved action at the cap. Only an approved approval,
 * bound to this Passport, whose intent carries this Mission qualifies; anything
 * else is simply not discounted (the approval gate then rules on it).
 */
async function alreadyCountedIntent(services: Services, request: FastifyRequest, passport: ResolvedPassport, missionId: string) {
  const approvalId = request.headers['x-intent-approval-id'];
  if (typeof approvalId !== 'string' || passport.accountability !== 'enforced') return undefined;
  const row = await services.intentApproval.findById(approvalId, request.operatorId);
  if (!row || row.passport_jti !== passport.jti || row.status !== 'approved' || row.expires_at.getTime() <= Date.now()) return undefined;
  const claim = await services.claimRegistry.getClaim(row.intent_claim_id);
  const body = claim.body_json as Partial<IntentClaim> | null;
  if (claim.revoked_at || body?.mission_ref !== missionId || typeof body.target !== 'string') return undefined;
  return { target: body.target };
}

async function refuseForMission(services: Services, request: FastifyRequest, input: AgentRuntimeInput, passport: ResolvedPassport,
  missionId: string, verdict: Extract<GateVerdict, { allowed: false }>): Promise<never> {
  // A cap paused the Mission: every action waits for the owner's review, which is the record.
  if (verdict.reason === 'mission_paused') throw new MissionPausedError(missionId, verdict.mission.paused_cap);
  const isCapReason = verdict.reason.startsWith('cap_');
  const cap = isCapReason ? (verdict.reason.slice('cap_'.length) as MissionCapName) : null;
  // The cap's behaviour: pause the Mission for its owner's review (the default), end it, or refuse only this action.
  // It is applied before the denial is recorded, so a Mission that ends has its terminal claim before the denial.
  if (cap && verdict.capBehavior && verdict.capBehavior !== 'refuse_action') {
    try {
      await services.mission.applyCapBehavior(missionId, cap, verdict.capBehavior, verdict.capService ?? null);
    } catch (err) {
      console.error('[mission admission] the cap behaviour failed:', safeErrorSummary(err));
    }
  }
  const metadata = { gate_reason: verdict.reason, mission_id: missionId, producer: input.producer,
    ...(verdict.capBehavior ? { cap_behavior: verdict.capBehavior } : {}) };
  try {
    await services.claimRegistry.recordIntentDenial({
      operatorId: request.operatorId,
      passportJti: passport.jti,
      attemptedIntent: {
        type: 'intent_claim', intent_type: input.denial.intentType, agent_id: input.agentId,
        named_intent: input.denial.namedIntent, target: input.targetId, action: input.action,
        parameters: input.denial.parameters,
        estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
        accountability: passport.accountability, reason: null, requires: [], user_subject: null,
        mission_ref: missionId, submitted_at: Date.now(),
      },
      denialReason: 'scope_mismatch',
      message: verdict.message,
      metadata,
    });
  } catch (err) {
    console.error('[mission admission] intent_denial emission failed:', safeErrorSummary(err));
  }
  if (cap && verdict.capBehavior === 'pause') throw new MissionPausedError(missionId, cap);
  // A cap reached is no security event: the pause and the owner's review are the record.
  if (cap) throw new ForbiddenError(verdict.message);
  try {
    await services.securityEvent.record({
      operatorId: request.operatorId,
      agentId: input.agentId,
      passportJti: passport.jti,
      signalType: 'credential_outside_scope',
      severity: 'critical',
      message: `Mission gate denied request: ${verdict.message}`,
      metadata: { ...metadata, service: input.requestedService },
      missionIds: passport.missionIds,
    });
  } catch (err) {
    console.error('[mission admission] security_event emission failed:', safeErrorSummary(err));
  }
  throw new ForbiddenError(verdict.message);
}

/**
 * The Mission an action runs under: the one the Passport carries, or the one
 * the caller selected from it. Zero, several-without-a-pick, or a pick the
 * Passport does not carry all refuse (403). Routes that need the Mission for
 * attribution BEFORE beginAgentRuntime runs use this, so they fail the same way.
 */
export function requireMissionRef(missionIds: readonly string[] | null | undefined, explicit?: string | null): string {
  let missionId: string | null;
  try {
    missionId = resolveMissionRef(missionIds, explicit, { required: true });
  } catch (err) {
    if (err instanceof MissionRefForbidden) throw err;
    throw new ForbiddenError('Passport must carry exactly one Mission to act');
  }
  if (!missionId) throw new ForbiddenError('Passport must carry exactly one Mission to act');
  return missionId;
}

/**
 * The one Mission admission check for every agent action (proxy, LLM, drop-offs,
 * A2A, skill invocation, intent submit, authority delegation). Fails closed:
 *
 * - An agent principal (request.agentId) must present a Passport.
 * - A Passport must resolve to exactly one Mission it carries, and that Mission
 *   must pass MissionService.checkGate (lifecycle, scope, duration, caps). A
 *   refusal records the intent_denial + security_event and auto-revokes on a
 *   hard cap, then answers 403.
 * - Fleet Passports on fleet producers then enter the fleet admission ledger.
 *
 * Returns null only for a non-agent principal (operator key, member session,
 * OAuth) acting without a Passport; nothing then binds the call to a Mission.
 * Must run before any credential decryption, upstream forward or execution
 * (pinned by routes/mission-admission-coverage.test.ts).
 */
export async function beginAgentRuntime(services: Services, request: FastifyRequest, input: AgentRuntimeInput): Promise<AgentRuntime | null> {
  const passport = await resolvePassport(services, request, input);
  if (!passport) {
    if (request.agentId) throw new ForbiddenError('Agent actions require a live Passport bound to a Mission');
    // A Mission selector without a Passport is attacker-controlled attribution.
    if (input.explicitMissionId) throw new ForbiddenError('A Mission can only be selected through the Passport that carries it');
    return null;
  }
  const fleetBinding = passport.claims?.stk.fleet;
  if (fleetBinding && input.explicitMissionId && input.explicitMissionId !== fleetBinding.mission_id) throw new ForbiddenError();
  const missionId = requireMissionRef(passport.missionIds, fleetBinding?.mission_id ?? input.explicitMissionId);

  const counted = fleetBinding ? undefined : await alreadyCountedIntent(services, request, passport, missionId);
  const verdict = await services.mission.checkGate({
    missionId,
    requestedService: input.requestedService,
    ...(input.internal ? { internal: true } : {}),
    ...(fleetBinding ? { accounting: 'fleet' as const } : {}),
    ...(counted ? { alreadyCounted: counted } : {}),
  });
  if (!verdict.allowed) return refuseForMission(services, request, input, passport, missionId, verdict);
  if (verdict.mission.operator_id !== request.operatorId) {
    await verdict.reservation?.release();
    throw new ForbiddenError();
  }
  // The Mission action this call reserved is committed or given back when the request ends (middleware/mission-action.ts).
  if (verdict.reservation) attachMissionAction(request, verdict.reservation);

  const base = { passportJti: passport.jti, missionId, missionIds: passport.missionIds, accountability: passport.accountability };
  if (!fleetBinding || !passport.claims) return { ...base, fleet: null };
  // What is the agent's own touches no fleet operation.
  if (input.producer === 'self') return { ...base, fleet: null };
  // Fleet policy has rules only for the fleet producers. A fleet Passport on any
  // other action is refused rather than run outside the ledger.
  if (!FLEET_PRODUCERS.has(input.producer)) throw new ForbiddenError();
  const claims = passport.claims;
  const producer = input.producer as FleetProducer;
  const intent: IntentClaim = {
    type: 'intent_claim',
    intent_type: producer === 'skill' ? 'skill_invocation' : producer === 'a2a' || producer === 'dropoff' ? 'a2a_dispatch' : 'http_call',
    agent_id: input.agentId, named_intent: `stack:${producer}:execute`, target: input.targetId, action: input.action,
    parameters: { request_hash: fleetDigest(input.normalizedRequest) },
    estimated_cost: { wallet_cents: null, tokens: null, gas_gwei: null },
    accountability: 'enforced', reason: null, requires: [], user_subject: null,
    mission_ref: fleetBinding.mission_id, submitted_at: Date.now(),
  };
  const admission = await services.fleetAdmission.prepare({ claims, producer,
    operationKey: runtimeAuthorityRequestIdFromHeaders(request.headers) ?? undefined, connectionId: input.connectionId,
    targetId: input.targetId, action: input.action, normalizedRequest: input.normalizedRequest, intent, bytes: input.bytes });
  if (admission) trackFleetAdmission(request, services, admission);
  if (admission && producer === 'dropoff') {
    if (input.action !== 'create' && input.action !== 'deposit' && input.action !== 'collect') throw new ForbiddenError();
    const authority = await enforceRuntimeAuthority(services.authority, {
      operatorId: request.operatorId, passportJti: claims.jti, agentId: input.agentId,
      authenticatedAgentId: request.agentId ?? null, missionId: fleetBinding.mission_id,
      receiverRequestId: runtimeAuthorityRequestIdFromHeaders(request.headers),
      boundary: { kind: 'dropoff', action: input.action, participantAgentId: input.targetId },
      normalizedRequest: { action: input.action, resource_type: 'agent', resource_ref: input.targetId, request: input.normalizedRequest },
      verificationMode: 'native_receiver',
    });
    dropoffAuthorities.set(admission, authority);
  }
  return { ...base, fleet: admission };
}
