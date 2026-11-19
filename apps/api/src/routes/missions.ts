// /v1/missions/* routes.
//
// Mission lifecycle and evidence REST surface.
//
//   POST   /v1/missions             — open a mission (operator scope)
//   POST   /v1/missions/:id/complete — complete (operator OR agent passport)
//   POST   /v1/missions/:id/revoke  — revoke (operator scope only)
//   POST   /v1/missions/:id/recipients — the owner adds recipients to a running Mission
//   POST   /v1/missions/:id/dossier — author a member post-mortem
//   GET    /v1/missions/:id         — fetch full mission view + computed cap usage
//   GET    /v1/missions/:id/replay  — reconstruct the evidence timeline
//   GET    /v1/missions/:id/dossiers — list dossier history
//   GET    /v1/missions             — list missions for operator (filterable; `?status=paused` is the owner's reviews)
//   POST   /v1/missions/:id/review  — the owner's decision on a Mission a cap paused: raise, continue or close
//   PUT    /v1/missions/:id/making-allowance — the owner's pre-approval of the Mission's print-on-demand orders
//
// Opening a mission is never metered.
//
// Routes use operator-scoped authentication. Dossier writes require a
// same-operator member principal. Audit middleware writes missions.* on
// every successful mutation. Mission claim emission + signed envelope
// persistence happen inside MissionService.

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  ConflictError, ForbiddenError, InvalidRequestError, NotFoundError, FleetMissionStartInput, IssuePassportInputObject,
  MakingOrdersAllowance, MissionLimitBehaviorInput, MissionRecipientsInput, MissionReviewInput, SetMissionMakingAllowanceInput,
  OAUTH_RESOURCE_MCP_DIRECTORY, buildRecipientPins, canonicalize, safeErrorSummary, sha256, type RecipientPin,
} from '@stack/shared';
import type { MissionOpenInput } from '@stack/vault';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { denyAgentContexts, requireOperatorAdmin } from '../middleware/require-platform.js';
import { requireRole } from '../middleware/require-role.js';
import { requireControls } from '../middleware/require-controls.js';
import { auditCtx } from '../middleware/audit.js';
import { meterAction } from '../middleware/meter.js';
import { assertPassportIssueActor, projectActivePassport } from './passports.js';
import { sendersOfMessage } from '../lib/message-senders.js';
import { MISSION_PINS_CHANNEL } from '../config/wiring/control-socket.js';

// ── Body / query schemas ──────────────────────────────────────────

/** The most an integer column of a Mission holds (a Postgres int4): a limit a person may set stops there, in a 400, never as a 500. */
const INT32_MAX = 2_147_483_647;

export const OpenBody = z.object({
  intent_summary: z.string().min(1).max(500),
  intent_services: z.array(z.string()).max(64).optional(),
  expected_counterparties: z.array(z.string()).max(256).optional(),
  baseline_profile: z.record(z.string(), z.unknown()).nullable().optional(),
  expected_output_shape: z.record(z.string(), z.unknown()).nullable().optional(),
  max_actions: z.number().int().positive().max(INT32_MAX).nullable().optional(),
  max_dropoff_bytes: z.number().int().nonnegative().nullable().optional(),
  coverage_cap_cents: z.number().int().nonnegative().nullable().optional(),
  max_duration_seconds: z.number().int().positive().max(INT32_MAX).nullable().optional(),
  max_concurrent_intents: z.number().int().positive().max(INT32_MAX).nullable().optional(),
  max_actions_per_service: z.record(z.string(), z.number().int().positive().max(INT32_MAX)).optional(),
  /**
   * What each cap does when it is reached: `pause` (the default: the Mission is paused for its owner's review),
   * `refuse_action` (only the action is refused) or `end_mission`. `coverage_cap_period: 'day'` makes the money cap
   * what the Mission may spend in one day, ending at midnight in `cap_time_zone` (IANA, default UTC).
   */
  ...MissionLimitBehaviorInput,
  /**
   * What the owner pre-approves of the Mission's print-on-demand orders, in cents across all of them: an order that
   * fits in what is left is approved without asking. Only the owner or an admin sets it; an agent may not.
   */
  making_orders_up_to_cents: MakingOrdersAllowance.optional(),
  expires_in_seconds: z.number().int().positive().optional(),
  /**
   * When provided, validates the new mission's intent_services as a
   * subset of these. Caller (typically a passport-issuance flow)
   * passes the passport's resolved services + intent_services here.
   * When omitted, no subset check runs — operator opens an
   * unconstrained mission as a future-bind container; subset
   * validation happens at passport-issue time via PassportService.issue
   * + MissionLookup instead.
   */
  parent_passport_services: z.array(z.string()).optional(),
  /**
   * opt-in baseline-source passport JTI. When provided
   * MissionService.open() fetches the passport's most recent
   * behavioral_genome and seals it as baseline_profile, stores
   * passport_jti on the mission row + claim for complete()/revoke() to
   * find at mission end, and clears the genome_drift_fired:<jti> Redis
   * key so the 5.1.4 drift detector re-arms for the new baseline window.
   * When omitted, legacy behavior preserved (baseline_profile
   * + behavioral_diff stay null).
   */
  passport_jti: z.string().optional(),
  /**
   * per-mission twin runtime override. When set
   * ignores agent.twin_policy and uses this value directly. Requires
   * passport_jti (no passport → no agent → twin skipped).
   */
  run_twin: z.boolean().optional(),
  /**
   * Who this Mission may send to, for the policy send rules that leave their recipients to each
   * Mission. `recipients` is a list of exact addresses, numbers or ids, applied at every recipient
   * field a send names; `recipient_pins` pins named fields with `eq` or `in`;
   * `reply_to_message` adds the sender of a message the agent received (an agent woken by an
   * incoming message replies to that person and no one else). Fixed when the Mission opens.
   */
  ...MissionRecipientsInput,
  reply_to_message: z.string().min(1).max(200).optional(),
  /**
   * The agent this mission is assigned to. An agent caller is always
   * assigned itself; an operator may name one of its agents.
   */
  agent_id: z.string().regex(/^agt_[\w-]+$/).max(256).optional(),
});

/** Who the owner adds to a running Mission: the same shapes it opens with, at least one of them. */
const AddRecipientsBody = z.object({
  ...MissionRecipientsInput,
  reply_to_message: z.string().min(1).max(200).optional(),
}).strict().refine(
  (body) => body.recipients !== undefined || body.recipient_pins !== undefined || body.reply_to_message !== undefined,
  'Name recipients, recipient_pins or reply_to_message',
);

const CompleteBody = z.object({
  output: z.record(z.string(), z.unknown()).optional(),
});

const RevokeBody = z.object({
  reason: z.enum(['adversarial', 'operator_initiated_clean']),
  notes: z.string().max(1000).optional(),
});

const ListQuery = z.object({
  agent_id: z.string().regex(/^agt_[\w-]+$/).max(256).optional(),
  status: z.enum(['active', 'completed', 'revoked', 'paused']).optional(),
  page: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().positive().max(200).optional(),
});

function scopedReadQuery(request: FastifyRequest, query: z.infer<typeof ListQuery>) {
  if (request.agentId) {
    if (query.agent_id && query.agent_id !== request.agentId) throw new ForbiddenError();
    return { ...query, agent_id: request.agentId };
  }
  return query;
}

/** The agent a new mission is assigned to, checked against the caller. */
async function resolveOpenAgent(
  services: Services,
  request: FastifyRequest,
  agentId: string | undefined,
): Promise<string | undefined> {
  if (request.agentId) {
    if (agentId && agentId !== request.agentId) throw new ForbiddenError();
    return request.agentId;
  }
  if (agentId) await services.agent.getById(agentId, request.operatorId);
  return agentId;
}

/**
 * The baseline-source passport must be the caller's own: same operator, and
 * the assigned agent's when one is set. Without this a caller could copy
 * another account's behavioural baseline into its own mission, re-arm that
 * passport's drift detector, or start a twin from it.
 */
async function assertOwnBaselinePassport(
  services: Services,
  request: FastifyRequest,
  passportJti: string | undefined,
  assignedAgentId: string | undefined,
): Promise<void> {
  if (passportJti === undefined) return;
  const passport = await services.passport.findByJti(passportJti);
  if (
    !passport
    || passport.operator_id !== request.operatorId
    || (assignedAgentId !== undefined && passport.agent_id !== assignedAgentId)
  ) {
    throw new NotFoundError('passport', passportJti);
  }
}

/**
 * The recipient pins a Mission opens with: its list, its field pins and the sender of the message
 * it replies to. A message is found by the deployment's own resolver (the engine has none, so
 * there is nothing to reply to); one the agent cannot reply to reads as not found.
 */
export async function missionRecipientPins(
  services: Pick<Services, 'registries'>,
  operatorId: string,
  assignedAgentId: string | undefined,
  body: Pick<z.infer<typeof OpenBody>, 'recipients' | 'recipient_pins' | 'reply_to_message'>,
): Promise<RecipientPin[] | null> {
  const listed = [...(body.recipients ?? [])];
  if (body.reply_to_message !== undefined) {
    if (!assignedAgentId) throw new InvalidRequestError('A Mission that replies to a message is opened for the agent that received it.');
    const senders = await sendersOfMessage(services, { operatorId, agentId: assignedAgentId, messageId: body.reply_to_message });
    for (const sender of senders) if (!listed.some((known) => known.toLowerCase() === sender.toLowerCase())) listed.push(sender);
  }
  return buildRecipientPins({ ...(listed.length ? { recipients: listed } : {}), ...(body.recipient_pins ? { recipient_pins: body.recipient_pins } : {}) });
}

/** The audit row's hash of a Mission's pins: what it was opened to send to, never the addresses. */
export function recipientPinsHash(pins: RecipientPin[] | null): string | undefined {
  return pins ? sha256(canonicalize(pins)) : undefined;
}

/**
 * An agent never pre-approves its own spending: the making allowance is set by the owner or an admin, at open or on a
 * running Mission, and an agent's open that names one is refused.
 */
function assertAllowanceSetter(request: FastifyRequest, body: { making_orders_up_to_cents?: number | null | undefined }): void {
  if (body.making_orders_up_to_cents === undefined) return;
  if (request.agentId) throw new ForbiddenError('Only the owner or an admin can pre-approve a Mission\'s making orders.');
  requireRole(request, 'admin');
}

/** OpenBody → MissionService.open input. Shared by POST /v1/missions and the operator path of POST /v1/missions/start. */
export function missionOpenInput(
  operatorId: string,
  body: Omit<z.infer<typeof OpenBody>, 'agent_id' | 'recipients' | 'recipient_pins' | 'reply_to_message'>,
  assignedAgentId: string | undefined,
  recipientPins: RecipientPin[] | null = null,
): MissionOpenInput {
  return {
    operatorId,
    ...(recipientPins ? { recipient_pins: recipientPins } : {}),
    ...(assignedAgentId ? { assignedAgentId } : {}),
    intent_summary: body.intent_summary,
    ...(body.intent_services !== undefined ? { intent_services: body.intent_services } : {}),
    ...(body.expected_counterparties !== undefined ? { expected_counterparties: body.expected_counterparties } : {}),
    ...(body.baseline_profile !== undefined ? { baseline_profile: body.baseline_profile } : {}),
    ...(body.expected_output_shape !== undefined ? { expected_output_shape: body.expected_output_shape } : {}),
    ...(body.max_actions !== undefined ? { max_actions: body.max_actions } : {}),
    ...(body.max_dropoff_bytes !== undefined ? { max_dropoff_bytes: body.max_dropoff_bytes } : {}),
    ...(body.coverage_cap_cents !== undefined ? { coverage_cap_cents: body.coverage_cap_cents } : {}),
    ...(body.max_duration_seconds !== undefined ? { max_duration_seconds: body.max_duration_seconds } : {}),
    ...(body.max_concurrent_intents !== undefined ? { max_concurrent_intents: body.max_concurrent_intents } : {}),
    ...(body.max_actions_per_service !== undefined ? { max_actions_per_service: body.max_actions_per_service } : {}),
    ...(body.cap_behavior !== undefined ? { cap_behavior: body.cap_behavior } : {}),
    ...(body.coverage_cap_period !== undefined ? { coverage_cap_period: body.coverage_cap_period } : {}),
    ...(body.cap_time_zone !== undefined ? { cap_time_zone: body.cap_time_zone } : {}),
    ...(body.making_orders_up_to_cents !== undefined ? { making_orders_up_to_cents: body.making_orders_up_to_cents } : {}),
    ...(body.expires_in_seconds !== undefined ? { expiresInSeconds: body.expires_in_seconds } : {}),
    ...(body.parent_passport_services !== undefined ? { parentPassportServices: body.parent_passport_services } : {}),
    ...(body.passport_jti !== undefined ? { passportJti: body.passport_jti } : {}),
    ...(body.run_twin !== undefined ? { run_twin: body.run_twin } : {}),
  };
}

/**
 * body of the operator path of POST /v1/missions/start. An
 * ordinary Mission spec plus the agent it is for; `passport` carries the
 * optional issuance fields (scopes, TTL, intent, ...). The Mission id is
 * never caller-supplied: the Passport is bound to the Mission opened here.
 */
export const OperatorMissionStartInput = z.object({
  agent_id: z.string().regex(/^agt_[\w-]+$/).max(256),
  mission: OpenBody.omit({ agent_id: true }),
  passport: IssuePassportInputObject.omit({ agent_id: true, mission_ids: true }).strict().optional(),
}).strict();

/**
 * one call opens a Mission and issues the agent's Passport bound to
 * it, for operator principals (API key, dashboard), partner-managed account keys
 * and an agent issuing for itself. Fleet agents keep the
 * fleet_policy_id path. The same ownership rules as POST /v1/missions and
 * POST /v1/passports/issue apply. Counted once, as the Passport issue: the
 * Mission open itself is free. If issuance fails, the just-opened Mission is
 * revoked before the error is returned, so no Passport-less Mission is left
 * live.
 */
export async function startOperatorMission(services: Services, request: FastifyRequest, raw: unknown) {
  // The connector directory serves neither a Passport nor this one-call form (its tool profile leaves both out), so a
  // directory token is refused here even though its scope ceiling holds the scopes of the two calls.
  if (request.oauthResource === OAUTH_RESOURCE_MCP_DIRECTORY) {
    throw new ForbiddenError('A connector-directory token cannot start a Mission and issue its Passport.');
  }
  // Opening a Mission and issuing a Passport change what an agent may do: a read-only member may not.
  requireRole(request, 'standard');
  const input = OperatorMissionStartInput.parse(raw);
  const start = Date.now();
  assertPassportIssueActor(request, {
    agent_id: input.agent_id,
    ...(input.passport?.identity_claim_ids !== undefined ? { identity_claim_ids: input.passport.identity_claim_ids } : {}),
    ...(input.passport?.authority_binding_ids !== undefined ? { authority_binding_ids: input.passport.authority_binding_ids } : {}),
  });
  const agentId = (await resolveOpenAgent(services, request, input.agent_id))!;
  assertAllowanceSetter(request, input.mission);
  // A fleet member gets its Mission and Passport from its fleet policy only.
  await services.fleet.assertUnboundIssue(request.operatorId, agentId);
  await assertOwnBaselinePassport(services, request, input.mission.passport_jti, agentId);

  const pins = await missionRecipientPins(services, request.operatorId, agentId, input.mission);
  await meterAction(services, request);
  const opened = await services.mission.open(missionOpenInput(request.operatorId, input.mission, agentId, pins));
  let signed;
  try {
    signed = await services.passport.issue(request.operatorId, {
      ...input.passport,
      agent_id: agentId,
      mission_ids: [opened.mission_id],
      intent: input.passport?.intent ?? {
        summary: input.mission.intent_summary,
        services: input.mission.intent_services ?? [],
      },
    });
  } catch (err) {
    await services.mission.revoke(opened.mission_id, { reason: 'operator_initiated_clean' }).catch((revokeErr: unknown) => {
      // The Mission holds no authority without a Passport and expires on its own.
      console.error('[missions start] rollback revoke failed:', opened.mission_id, safeErrorSummary(revokeErr));
    });
    throw err;
  }
  await services.audit.write({
    ctx: auditCtx(request, { agent_id: agentId, passport_jti: signed.jti }),
    layer: 'vault',
    action: 'mission.start',
    outcome: 'success',
    duration_ms: Date.now() - start,
    ...(recipientPinsHash(pins) ? { payload_hash: recipientPinsHash(pins)! } : {}),
  });
  return {
    mission_id: opened.mission_id,
    claim_id: opened.claim_id,
    expires_at: opened.expires_at.toISOString(),
    passport: { token: signed.token, jti: signed.jti, expires_at: signed.expires_at.toISOString() },
  };
}

// POST /v1/missions/:id/dossier body. Mirrors
// CreateDossierInput from DossierService. The `authored_by_member_id`
// is derived from the request context (not from the body) so a
// member can't impersonate.
const DossierBody = z.object({
  narrative: z.string().max(50_000),
  decision_tree: z.array(
    z.object({
      checkpoint_id: z.string().regex(/^chk_[\w-]+$/),
      decision: z.string().min(1).max(256),
      rationale: z.string().max(4096),
    }),
  ).optional(),
  alerts_walkthrough: z.array(
    z.object({
      detector_signal_claim_id: z.string().regex(/^pc_[\w-]+$/),
      severity: z.enum(['low', 'medium', 'high', 'critical']),
      narrative: z.string().max(8192),
    }),
  ).optional(),
  lessons_learned: z.string().max(50_000),
  incident_classification: z.enum([
    'false_positive',
    'true_positive_handled',
    'true_positive_escalated',
    'inconclusive',
  ]),
});

// ── Route registration ───────────────────────────────────────────

const FLEET_START_KEYS = ['fleet_policy_id', 'requested_access', 'requested_operations', 'limits'];
const FleetStartProbe = z.record(z.string(), z.unknown());

export function registerMissionsRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);
  // Mission dossiers and replay are the record: a controls feature.
  const recordNeedsControls = requireControls(services);
  // Listing the Missions of the account is a controls feature. Opening one is not gated here: a Mission is what a Passport is
  // issued under, so every agent outside an agent account (a partner's tenants included) opens its Missions through this route.
  const missionsNeedControls = requireControls(services, 'missions');

  // POST /v1/missions — open a mission.
  app.post('/v1/missions', { preHandler: auth }, async (request, reply) => {
    // A read-only member may not act: opening, changing, ending or minting is for a standard member or above.
    requireRole(request, 'standard');
    // The body is a fleet-mission start when it carries any fleet key;
    // anything else (including a non-object) falls through to OpenBody, which
    // rejects it with a validation error.
    const probe = FleetStartProbe.safeParse(request.body);
    if (probe.success && FLEET_START_KEYS.some(key => key in probe.data)) {
      if (!request.agentId) throw new ForbiddenError();
      const input = FleetMissionStartInput.parse(request.body);
      await meterAction(services, request, undefined, `fleet-mission:${request.agentId}:${input.fleet_policy_id}:${input.idempotency_key}`);
      const started = await services.fleet.start(request.operatorId, request.agentId, input);
      const mission = await services.mission.findById(started.mission_id);
      if (!mission || mission.operator_id !== request.operatorId) throw new ForbiddenError();
      await request.meterCommit?.();
      // Same operation as POST /v1/missions/start (opens the mission and
      // issues its passport), so it records the same metered action.
      await services.audit.write({ ctx: auditCtx(request, {}), layer: 'vault', action: 'mission.start', outcome: 'success', duration_ms: 0 });
      return reply.status(201).send({ mission_id: mission.mission_id, claim_id: mission.claim_id, expires_at: mission.expires_at.toISOString() });
    }
    if (request.agentId) await services.fleet.assertUnboundIssue(request.operatorId, request.agentId);
    const body = OpenBody.parse(request.body);
    const start = Date.now();

    // Opening, completing and revoking a mission are not metered.
    // The passport issued for the mission is the counted action, so one
    // agent task is billed once. The fleet branch above stays metered
    // because fleet.start issues that passport in the same call.
    const assignedAgentId = await resolveOpenAgent(services, request, body.agent_id);
    assertAllowanceSetter(request, body);
    await assertOwnBaselinePassport(services, request, body.passport_jti, assignedAgentId);

    const pins = await missionRecipientPins(services, request.operatorId, assignedAgentId, body);
    const result = await services.mission.open(missionOpenInput(request.operatorId, body, assignedAgentId, pins));

    await services.audit.write({
      ctx: auditCtx(request, {}),
      layer: 'vault',
      action: 'mission.open',
      outcome: 'success',
      duration_ms: Date.now() - start,
      ...(recipientPinsHash(pins) ? { payload_hash: recipientPinsHash(pins)! } : {}),
    });

    return reply.status(201).send({
      mission_id: result.mission_id,
      claim_id: result.claim_id,
      expires_at: result.expires_at.toISOString(),
    });
  });

  // POST /v1/missions/:id/complete — terminal-state lifecycle.
  app.post<{ Params: { id: string } }>(
    '/v1/missions/:id/complete',
    { preHandler: auth },
    async (request, reply) => {
      requireRole(request, 'standard');
      const body = CompleteBody.parse(request.body ?? {});
      const start = Date.now();

      // Cross-tenant existence hidden — findById returns null for both
      // unknown and other-operator missions; service throws NotFoundError
      // which we re-stamp to 404 below.
      const existing = await services.mission.findById(request.params.id);
      if (!existing || existing.operator_id !== request.operatorId) {
        return reply.status(404).send({
          error: { code: 'NOT_FOUND', message: `mission ${request.params.id} not found` },
        });
      }

      try {
        const result = await services.mission.complete(request.params.id, {
          actor: { operatorId: request.operatorId, ...(request.agentId ? { agentId: request.agentId } : {}) },
          ...(body.output !== undefined ? { output: body.output } : {}),
        });
        await services.audit.write({
          ctx: auditCtx(request, {}),
          layer: 'vault',
          action: 'mission.complete',
          outcome: 'success',
          duration_ms: Date.now() - start,
        });
        return reply.send({
          mission_id: result.mission_id,
          claim_id: result.claim_id,
          terminal_state: result.terminal_state,
          completed_at: result.completed_at.toISOString(),
          transitioned: result.transitioned,
        });
      } catch (err) {
        if (err instanceof ConflictError) {
          return reply.status(409).send({
            error: { code: 'CONFLICT', message: err.message },
          });
        }
        throw err;
      }
    },
  );

  // POST /v1/missions/:id/revoke — operator-initiated revoke.
  app.post<{ Params: { id: string } }>(
    '/v1/missions/:id/revoke',
    { preHandler: auth },
    async (request, reply) => {
      requireRole(request, 'standard');
      const body = RevokeBody.parse(request.body ?? {});
      const start = Date.now();

      const existing = await services.mission.findById(request.params.id);
      if (!existing || existing.operator_id !== request.operatorId) {
        return reply.status(404).send({
          error: { code: 'NOT_FOUND', message: `mission ${request.params.id} not found` },
        });
      }

      try {
        const result = await services.mission.revoke(request.params.id, {
          reason: body.reason,
          ...(body.notes !== undefined ? { notes: body.notes } : {}),
        });
        await services.audit.write({
          ctx: auditCtx(request, {}),
          layer: 'vault',
          action: body.reason === 'adversarial' ? 'mission.revoke_adversarial' : 'mission.revoke',
          outcome: 'success',
          duration_ms: Date.now() - start,
        });
        return reply.send({
          mission_id: result.mission_id,
          claim_id: result.claim_id,
          terminal_state: result.terminal_state,
          revoked_at: result.revoked_at.toISOString(),
          revoke_reason: result.revoke_reason,
          transitioned: result.transitioned,
        });
      } catch (err) {
        if (err instanceof ConflictError) {
          return reply.status(409).send({
            error: { code: 'CONFLICT', message: err.message },
          });
        }
        if (err instanceof NotFoundError) {
          return reply.status(404).send({
            error: { code: 'NOT_FOUND', message: err.message },
          });
        }
        throw err;
      }
    },
  );

  // POST /v1/missions/:id/review — the owner's decision on a Mission a cap paused. `raise` sets the new limit of the
  // cap that paused it and lets it go on, `continue` lets it go on as it is, `close` ends it. The agent the Mission was
  // opened for is told the decision. The owner's own session or key; an agent never decides its own pause. Not metered.
  app.post<{ Params: { id: string } }>(
    '/v1/missions/:id/review',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'standard');
      const body = MissionReviewInput.parse(request.body);
      const start = Date.now();
      const result = await services.mission.review(request.params.id, {
        operatorId: request.operatorId,
        decision: body.decision,
        ...(body.limit !== undefined ? { limit: body.limit } : {}),
      });
      await services.audit.write({
        ctx: auditCtx(request, {}),
        layer: 'vault',
        action: `mission.review.${body.decision}`,
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return { mission_id: result.mission_id, decision: result.decision, result: result.result, mission: missionForWire(result.mission) };
    },
  );

  // PUT /v1/missions/:id/making-allowance — what the owner pre-approves of the Mission's print-on-demand orders, in cents
  // across all of them (null: none). The owner or an admin; an agent never pre-approves its own spending. Not metered.
  app.put<{ Params: { id: string } }>(
    '/v1/missions/:id/making-allowance',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      const body = SetMissionMakingAllowanceInput.parse(request.body);
      const start = Date.now();
      const view = await services.mission.setMakingAllowance(request.params.id, request.operatorId, body.making_orders_up_to_cents);
      await services.audit.write({
        ctx: auditCtx(request, {}),
        layer: 'vault',
        action: 'mission.making_allowance.set',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return missionForWire(view);
    },
  );

  // GET /v1/missions/:id — full view + computed cap usage.
  app.get<{ Params: { id: string } }>(
    '/v1/missions/:id',
    { preHandler: auth },
    async (request, reply) => {
      const query = scopedReadQuery(request, ListQuery.pick({ agent_id: true }).parse(request.query ?? {}));
      if (query.agent_id) await services.agent.getById(query.agent_id, request.operatorId);
      const view = await services.mission.findById(request.params.id, {
        operatorId: request.operatorId, ...(query.agent_id ? { agentId: query.agent_id } : {}),
      });
      if (!view || view.operator_id !== request.operatorId) {
        return reply.status(404).send({
          error: { code: 'NOT_FOUND', message: `mission ${request.params.id} not found` },
        });
      }
      // 5.0.9.1 — cap usage. Compose the cap-counting helpers from
      // MissionRepository (5.0.5b's wallet/dropoff + 5.0.5's
      // intent-based helpers) into a single cap_usage block on the
      // response so the dashboard renders live current-vs-limit bars
      // without a second round-trip.
      const usage = await computeCapUsage(services, view.mission_id);
      const fleet = await services.fleetRepo.missionSummary(request.operatorId, view.mission_id);
      const output = await services.mission.readOutput(view.mission_id, {
        operatorId: request.operatorId, ...(request.agentId ? { agentId: request.agentId } : {}),
      });
      return reply.send({ ...missionForWire(view), cap_usage: fleet ? {
        ...usage as Record<string, unknown>,
        actions: { used: fleet.usage.actions, limit: fleet.limits.max_actions },
        concurrent_intents: { used: fleet.usage.concurrent_actions, limit: fleet.limits.max_concurrent_actions },
        dropoff_bytes: { used: fleet.usage.dropoff_bytes, limit: fleet.limits.max_dropoff_bytes ?? null },
        coverage_cents: { used: fleet.usage.reserved_spend_cents, limit: fleet.limits.max_spend_cents ?? null },
      } : usage, fleet, ...(output ?? {}) });
    },
  );

  // POST /v1/missions/:id/recipients
  //
  // The owner adds who a running Mission may send to: recipients, field pins or the sender of a message its agent received,
  // merged into the pins it opened with. Only widens; an agent never reaches it. One audit row with a hash of the pins.
  app.post<{ Params: { id: string } }>(
    '/v1/missions/:id/recipients',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'standard');
      const body = AddRecipientsBody.parse(request.body);
      const start = Date.now();
      const view = await services.mission.findById(request.params.id, { operatorId: request.operatorId });
      if (!view) throw new NotFoundError('mission', request.params.id);
      const added = await missionRecipientPins(services, request.operatorId, view.assigned_agent_id ?? undefined, body);
      if (!added) throw new InvalidRequestError('Name recipients, recipient_pins or reply_to_message');
      const pins = await services.mission.addRecipientPins(request.operatorId, request.params.id, added);
      await services.redis.publish(MISSION_PINS_CHANNEL, `${request.operatorId} ${request.params.id}`);
      await services.audit.write({
        ctx: auditCtx(request, {}),
        layer: 'vault',
        action: 'missions.recipients.add',
        outcome: 'success',
        duration_ms: Date.now() - start,
        payload_hash: recipientPinsHash(pins)!,
      });
      return { mission_id: request.params.id, recipient_pins: pins };
    },
  );

  // POST /v1/missions/:id/dossier.
  //
  // Author a fresh dossier for a terminal mission. A same-operator
  // member session is required. Agent, passport and
  // operator-key contexts fail closed. A controls feature (402
  // CONTROLS_REQUIRED without controls).
  app.post<{ Params: { id: string } }>(
    '/v1/missions/:id/dossier',
    { preHandler: [auth, denyAgentContexts, recordNeedsControls] },
    async (request, reply) => {
      if (!request.memberId) {
        throw new ForbiddenError('dossier authoring requires a member principal');
      }
      requireRole(request, 'standard');
      const dossierBody = DossierBody.parse(request.body);
      const start = Date.now();
      // A dossier is a signed compliance report: an enterprise feature of a self-managed install.
      services.features.require('evidence_exports');

      const view = await services.mission.findById(request.params.id);
      if (!view || view.operator_id !== request.operatorId) {
        return reply.status(404).send({
          error: { code: 'NOT_FOUND', message: `mission ${request.params.id} not found` },
        });
      }

      try {
        const result = await services.dossier.create(
          request.params.id,
          {
            narrative: dossierBody.narrative,
            ...(dossierBody.decision_tree !== undefined ? { decision_tree: dossierBody.decision_tree } : {}),
            ...(dossierBody.alerts_walkthrough !== undefined ? { alerts_walkthrough: dossierBody.alerts_walkthrough } : {}),
            lessons_learned: dossierBody.lessons_learned,
            incident_classification: dossierBody.incident_classification,
          },
          request.memberId,
        );
        await services.audit.write({
          ctx: auditCtx(request, {}),
          layer: 'vault',
          action: 'dossier.create',
          outcome: 'success',
          duration_ms: Date.now() - start,
        });
        return reply.status(201).send({
          claim_id: result.claim_id,
          claim: result.claim,
        });
      } catch (err) {
        if (err instanceof ConflictError) {
          return reply.status(409).send({
            error: { code: 'CONFLICT', message: err.message },
          });
        }
        throw err;
      }
    },
  );

  // GET /v1/missions/:id/replay
  // Forensic timeline reconstruction over the mission's signed claim
  // set. Live DB path through ReplayService → PassportClaimsRepository.
  // findInMissionScope. Returns the same ReplayedTimeline shape the
  // open-source verifier produces for an exported pack — dashboard +
  // offline pack inspection share one mental model.
  app.get<{ Params: { id: string } }>(
    '/v1/missions/:id/replay',
    { preHandler: [auth, recordNeedsControls] },
    async (request, reply) => {
      const query = scopedReadQuery(request, ListQuery.omit({ status: true }).parse(request.query ?? {}));
      if (query.agent_id) await services.agent.getById(query.agent_id, request.operatorId);
      const view = await services.mission.findById(request.params.id, {
        operatorId: request.operatorId, ...(query.agent_id ? { agentId: query.agent_id } : {}),
      });
      if (!view || view.operator_id !== request.operatorId) {
        return reply.status(404).send({
          error: { code: 'NOT_FOUND', message: `mission ${request.params.id} not found` },
        });
      }
      if (query.page !== undefined || query.limit !== undefined) {
        return reply.send(await services.replay.listMissionClaimPage(request.params.id, request.operatorId, {
          page: query.page ?? 1, limit: query.limit ?? 20,
        }));
      }
      const timeline = await services.replay.reconstructMissionTimeline(
        request.params.id,
        request.operatorId,
      );
      return reply.send(timeline);
    },
  );

  // GET /v1/missions/:id/dossiers
  // Returns the full dossier chain for a mission ordered by
  // issued_at_ms ASC. Empty array when no dossier exists. Operator-
  // scope auth; cross-tenant existence hidden via 404 when the mission
  // belongs to a different operator.
  app.get<{ Params: { id: string } }>(
    '/v1/missions/:id/dossiers',
    { preHandler: [auth, recordNeedsControls] },
    async (request, reply) => {
      const query = scopedReadQuery(request, ListQuery.omit({ status: true }).parse(request.query ?? {}));
      if (query.agent_id) await services.agent.getById(query.agent_id, request.operatorId);
      const view = await services.mission.findById(request.params.id, {
        operatorId: request.operatorId, ...(query.agent_id ? { agentId: query.agent_id } : {}),
      });
      if (!view || view.operator_id !== request.operatorId) {
        return reply.status(404).send({
          error: { code: 'NOT_FOUND', message: `mission ${request.params.id} not found` },
        });
      }
      if (query.page !== undefined || query.limit !== undefined) {
        return reply.send(await services.dossier.listMissionPage(request.params.id, request.operatorId, {
          page: query.page ?? 1, limit: query.limit ?? 20,
        }));
      }
      const dossiers = await services.dossier.findByMission(
        request.params.id,
        request.operatorId,
      );
      return reply.send({ items: dossiers });
    },
  );

  app.get<{ Params: { id: string } }>(
    '/v1/missions/:id/passports',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      const query = scopedReadQuery(request, ListQuery.omit({ status: true }).parse(request.query ?? {}));
      if (query.agent_id) await services.agent.getById(query.agent_id, request.operatorId);
      const { items, ...pagination } = await services.mission.listPassports(request.operatorId, request.params.id, {
        ...(query.agent_id ? { agentId: query.agent_id } : {}),
        ...(query.page ? { page: query.page } : {}),
        ...(query.limit ? { limit: query.limit } : {}),
      });
      const refs = await services.authority.listPassportAuthorityRefsForPassports(
        request.operatorId, items.map((passport) => passport.jti),
      );
      return {
        ...pagination,
        items: items.map((passport) => ({
          ...projectActivePassport(passport, refs.get(passport.jti) ?? []),
          revoked_at: passport.revoked_at?.toISOString() ?? null,
          revoked_reason: passport.revoked_reason,
        })),
      };
    },
  );

  // GET /v1/missions — list missions for operator, filterable.
  app.get('/v1/missions', { preHandler: [auth, missionsNeedControls] }, async (request, reply) => {
    const query = scopedReadQuery(request, ListQuery.parse(request.query ?? {}));
    if (query.agent_id) await services.agent.getById(query.agent_id, request.operatorId);
    const result = await services.mission.listByOperator(request.operatorId, {
      ...(query.agent_id !== undefined ? { agentId: query.agent_id } : {}),
      ...(query.status !== undefined ? { status: query.status } : {}),
      ...(query.page !== undefined ? { page: query.page } : {}),
      ...(query.limit !== undefined ? { limit: query.limit } : {}),
    });
    return reply.send({
      ...result,
      items: result.items.map(missionForWire),
    });
  });

}

// ── Helpers ──────────────────────────────────────────────────────

async function computeCapUsage(services: Services, missionId: string): Promise<unknown> {
  // Delegate to MissionService.getCapUsage which composes the six
  // cap-counting helpers. Returns null when the mission doesn't exist
  // — caller already 404'd above so this branch is unreachable in
  // practice; null guard keeps the type clean.
  return (await services.mission.getCapUsage(missionId)) ?? null;
}

function missionForWire(v: Awaited<ReturnType<Services['mission']['findById']>>): Record<string, unknown> | null {
  if (!v) return null;
  const listEvidence = v as typeof v & {
    dossier_count?: number;
    evidence_pack_count?: number;
  };
  return {
    mission_id: v.mission_id,
    assigned_agent_id: v.assigned_agent_id ?? null,
    authorization_digest: v.authorization_digest ?? null,
    operator_id: v.operator_id,
    claim_id: v.claim_id,
    passport_jti: v.passport_jti,
    intent_summary: v.intent_summary,
    intent_services: v.intent_services,
    expected_counterparties: v.expected_counterparties,
    max_actions: v.max_actions,
    max_dropoff_bytes: v.max_dropoff_bytes,
    coverage_cap_cents: v.coverage_cap_cents,
    max_duration_seconds: v.max_duration_seconds,
    max_concurrent_intents: v.max_concurrent_intents,
    max_actions_per_service: v.max_actions_per_service,
    cap_behavior: v.cap_behavior,
    coverage_cap_period: v.coverage_cap_period,
    cap_time_zone: v.cap_time_zone,
    paused_at: v.paused_at ? v.paused_at.toISOString() : null,
    paused_cap: v.paused_cap,
    paused_service: v.paused_service,
    making_orders_up_to_cents: v.making_orders_up_to_cents,
    baseline_profile: v.baseline_profile,
    expected_output_shape: v.expected_output_shape,
    recipient_pins: v.recipient_pins ?? null,
    started_at: v.started_at.toISOString(),
    expires_at: v.expires_at.toISOString(),
    completed_at: v.completed_at ? v.completed_at.toISOString() : null,
    revoked_at: v.revoked_at ? v.revoked_at.toISOString() : null,
    revoked_reason: v.revoked_reason,
    terminal_state: v.terminal_state,
    ...(listEvidence.dossier_count !== undefined
      ? { dossier_count: listEvidence.dossier_count }
      : {}),
    ...(listEvidence.evidence_pack_count !== undefined
      ? { evidence_pack_count: listEvidence.evidence_pack_count }
      : {}),
  };
}
