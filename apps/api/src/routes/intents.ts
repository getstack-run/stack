// /v1/intents/* routes.
//
// (commit `e1ba430`):
//   POST /v1/intents/simulate  — dry-run a candidate IntentClaim against
//                                a passport. Header: X-Passport-Token.
//
// (this file extension):
//   POST /v1/intents/submit       — register an Intent + create a
//                                   pending approval (optionally with
//                                   inline simulation). Header:
//                                   X-Passport-Token.
//   GET  /v1/intents/pending      — list pending approvals scoped to
//                                   the calling operator.
//   POST /v1/intents/:id/approve  — transition pending → approved.
//   POST /v1/intents/:id/reject   — transition pending → rejected
//                                   (auto-revokes the passport via the
//                                   IntentApprovalService.onReject hook
//                                   wired in services.ts).
//
// All routes are operator-scope (any of the six auth paths). Audit
// middleware writes intents.* on success. Metering: submit counts a
// recorded action; simulate / approve / reject never do
// invariants — see middleware/metering-invariants.test.ts).

import type { FastifyInstance } from 'fastify';
import { denyAgentContexts } from '../middleware/require-platform.js';
import { z } from 'zod';
import { ForbiddenError, INTENT_APPROVAL_MAX_TTL_SECONDS, IntentClaim, IntentSimulationClaim, NotFoundError, intentApprovalPreview } from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { meterAction } from '../middleware/meter.js';
import { enforceGovernanceStepUp } from '../middleware/governance-stepup.js';
import { requireRole } from '../middleware/require-role.js';
import { requireControls } from '../middleware/require-controls.js';
import { beginAgentRuntime, normalizedFleetOperation } from '../lib/agent-runtime.js';

/**
 * The Mission identifier an intent is admitted against. A call to an external
 * service is checked against the Mission's service scope; work that stays inside
 * STACK (a skill, an A2A hand-off, a task completion) is not a service a Mission
 * can list, so only lifecycle and caps apply to it. Anything else is treated as
 * external, which fails closed under a narrowed Mission.
 */
function intentAdmissionTarget(intent: IntentClaim): { requestedService: string; internal: boolean } {
  switch (intent.intent_type) {
    case 'skill_invocation': return { requestedService: 'stack:skill', internal: true };
    case 'a2a_dispatch': return { requestedService: 'stack:a2a', internal: true };
    case 'task_complete': return { requestedService: 'stack:task', internal: true };
    default: return { requestedService: intent.target, internal: false };
  }
}

const SimulateBody = z.object({
  intent: IntentClaim,
  intent_claim_ref: z.string().regex(/^pc_[\w-]+$/).optional(),
  persist: z.boolean().optional(),
});

const SubmitBody = z.object({
  intent: IntentClaim,
  // How long the approval waits for a decision: any time up to a day (default 15 minutes); a longer time is a 400, never cut.
  expires_in_seconds: z.number().int().positive().max(INTENT_APPROVAL_MAX_TTL_SECONDS).optional(),
  skip_simulation: z.boolean().optional(),
});

const DecideBody = z.object({
  notes: z.string().max(1000).optional(),
  block_future: z.boolean().optional(),
});

const PendingQuery = z.object({
  agent_id: z.string().regex(/^agt_[\w-]+$/).max(256).optional(),
  page: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().positive().max(200).optional(),
});

export function registerIntentsRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.post('/v1/intents/simulate', { preHandler: auth }, async (request, reply) => {
    const passportToken = request.headers['x-passport-token'] as string | undefined;
    if (!passportToken) {
      throw new ForbiddenError('X-Passport-Token header required for /v1/intents/simulate');
    }
    const body = SimulateBody.parse(request.body);
    if (body.intent.policy_decision) throw new ForbiddenError();
    const start = Date.now();

    const result = await services.intentSimulation.simulate({
      passportToken,
      intent: body.intent,
      ...(body.intent_claim_ref !== undefined ? { intentClaimRef: body.intent_claim_ref } : {}),
      ...(body.persist !== undefined ? { persist: body.persist } : {}),
    });

    await services.audit.write({
      ctx: auditCtx(request, { agent_id: body.intent.agent_id }),
      layer: 'vault',
      action: 'intents.simulate',
      outcome: result.allowed ? 'success' : 'failure',
      duration_ms: Date.now() - start,
    });

    return reply.send({
      allowed: result.allowed,
      denial_reasons: result.denialReasons,
      simulated_cost: result.simulatedCost,
      predicted_detector_fires: result.predictedDetectorFires,
      simulated_at: result.simulatedAt,
      ...(result.claimId !== undefined ? { claim_id: result.claimId } : {}),
      diagnostics: snakeCaseDiagnostics(result.diagnostics),
    });
  });

  // ── pre-execution approval gate ───────────────────

  app.post('/v1/intents/submit', { preHandler: auth }, async (request, reply) => {
    const passportToken = request.headers['x-passport-token'] as string | undefined;
    if (!passportToken) {
      throw new ForbiddenError('X-Passport-Token header required for /v1/intents/submit');
    }
    const body = SubmitBody.parse(request.body);
    const start = Date.now();

    // Mission admission, before metering and before the intent_claim is
    // written. Gating first means the claim this submit writes is not counted
    // against itself; when the approved intent later executes, the producer's
    // admission discounts it (alreadyCounted), so it is counted exactly once.
    const target = intentAdmissionTarget(body.intent);
    const runtime = await beginAgentRuntime(services, request, {
      agentId: body.intent.agent_id, explicitMissionId: body.intent.mission_ref, producer: 'intent',
      requestedService: target.requestedService, internal: target.internal, targetId: body.intent.target,
      action: body.intent.action, normalizedRequest: normalizedFleetOperation('intent.submit', body.intent),
      denial: { intentType: body.intent.intent_type, namedIntent: body.intent.named_intent, parameters: body.intent.parameters },
    });
    if (!runtime) throw new ForbiddenError('Passport must carry exactly one Mission to act');

    // Submit is metered; simulate, approve and reject are not. Asking "may
    // I?" before acting is the behaviour we want to be free — charging for
    // the cautious path would price people into the reckless one.
    await meterAction(services, request);

    const result = await services.intentApproval.submit({
      passportToken,
      // Attribute the intent to the admitted Mission so its caps count it.
      intent: { ...body.intent, mission_ref: runtime.missionId },
      ...(body.expires_in_seconds !== undefined ? { expiresInSeconds: body.expires_in_seconds } : {}),
      ...(body.skip_simulation !== undefined ? { skipSimulation: body.skip_simulation } : {}),
    });

    await services.audit.write({
      ctx: auditCtx(request, { agent_id: body.intent.agent_id }),
      layer: 'vault',
      action: 'intents.submit',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.status(201).send({
      approval_id: result.approvalId,
      intent_claim_id: result.intentClaimId,
      ...(result.simulatedClaimId !== undefined ? { simulated_claim_id: result.simulatedClaimId } : {}),
      status: result.status,
      expires_at: result.expiresAt.toISOString(),
      ...(result.simulation ? {
        simulation: {
          allowed: result.simulation.allowed,
          denial_reasons: result.simulation.denialReasons,
          simulated_cost: result.simulation.simulatedCost,
          predicted_detector_fires: result.simulation.predictedDetectorFires,
          simulated_at: result.simulation.simulatedAt,
          ...(result.simulation.claimId !== undefined ? { claim_id: result.simulation.claimId } : {}),
          diagnostics: snakeCaseDiagnostics(result.simulation.diagnostics),
        },
      } : {}),
    });
  });

  app.get<{ Params: { id: string } }>(
    '/v1/intents/:id',
    { preHandler: auth },
    async (request, reply) => {
      // findById returns null for both not-found and cross-tenant; we
      // map both to 404 here so cross-tenant existence stays hidden.
      const row = await services.intentApproval.findById(request.params.id, request.operatorId);
      if (!row) {
        return reply.status(404).send({
          error: { code: 'NOT_FOUND', message: `intent_approval ${request.params.id} not found` },
        });
      }
      const query = z.object({ review: z.literal('1').optional() }).parse(request.query ?? {});
      if (!query.review) return rowForWire(row);
      await denyAgentContexts(request, reply);
      if (row.fleet_policy_id && request.isDashboardSession !== true) throw new ForbiddenError();
      const claim = await services.passportClaimsRepo.findByClaimId(row.intent_claim_id);
      if (!claim || claim.operator_id !== request.operatorId || claim.passport_id !== row.passport_jti
        || claim.type !== 'intent_claim') {
        throw new NotFoundError('Intent review', row.id);
      }
      const parsed = IntentClaim.safeParse(claim.body_json);
      // An intent STACK cannot read is shown as the raw JSON it was stored as, and can still be decided. One that reads
      // as another agent's is not this approval's proof.
      if (!parsed.success) {
        return { ...rowForWire(row), intent: null, intent_raw: JSON.stringify(claim.body_json, null, 2) ?? 'null', simulation: null };
      }
      if (parsed.data.agent_id !== row.agent_id) throw new NotFoundError('Intent review', row.id);
      const intent = parsed.data;
      let simulation = null;
      if (row.simulated_claim_id) {
        const sim = await services.passportClaimsRepo.findByClaimId(row.simulated_claim_id);
        const result = IntentSimulationClaim.safeParse(sim?.body_json);
        if (sim && sim.operator_id === request.operatorId && sim.passport_id === row.passport_jti
          && sim.type === 'intent_simulation' && result.success
          && result.data.intent_claim_ref === row.intent_claim_id) {
          simulation = {
            allowed: result.data.allowed, denial_reasons: result.data.denial_reasons,
            simulated_cost: result.data.simulated_cost,
            predicted_detector_fires: result.data.predicted_detector_fires,
            simulated_at: result.data.simulated_at,
          };
        }
      }
      return {
        ...rowForWire(row),
        intent: {
          intent_type: intent.intent_type, named_intent: intent.named_intent,
          target: intent.target, action: intent.action, reason: intent.reason,
          estimated_cost: intent.estimated_cost, requires: intent.requires,
          mission_ref: intent.mission_ref ?? null,
          ...(intent.policy_decision ? { matched_rule: intent.policy_decision.rule_id } : {}),
        },
        simulation,
        ...(row.fleet_policy_id ? { fleet_request: await services.intentApproval.readFleetReview(request.operatorId, row.id) } : {}),
      };
    },
  );

  app.get('/v1/intents/pending', { preHandler: [auth, requireControls(services, 'intent_checks')] }, async (request) => {
    const query = PendingQuery.parse(request.query);
    if (query.agent_id) await services.agent.getById(query.agent_id, request.operatorId);
    const { items, ...pagination } = await services.intentApproval.listPending(request.operatorId, {
      ...(query.agent_id !== undefined ? { agentId: query.agent_id } : {}),
      ...(query.page !== undefined ? { page: query.page } : {}),
      ...(query.limit !== undefined ? { limit: query.limit } : {}),
    });
    return {
      items: items.map(rowForWire),
      ...pagination,
    };
  });

  app.post<{ Params: { id: string } }>(
    '/v1/intents/:id/approve',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      // Deciding what an agent may do is the account's own: the owner, or any member who may change things.
      requireRole(request, 'standard');
      const body = DecideBody.parse(request.body ?? {});
      const approval = await services.intentApproval.findById(request.params.id, request.operatorId);
      if (!approval) throw new NotFoundError('intent_approval', request.params.id);
      if (approval.fleet_policy_id && request.isDashboardSession !== true) throw new ForbiddenError();
      // The owner's key, SDK, CLI or chat decides an intent directly. Only an intent that can move money is approved in
      // the browser, as a held payment is: the Console's own session is the person, anything else is sent to the
      // approval page. An intent that cannot be read is judged by the money fields of its raw JSON and shown as that JSON;
      // only a payload that is not a JSON object, or a money field that cannot be read, is sent there. An approval that is not pending
      // cannot be decided, so nobody is asked about it: the service refuses it below.
      if (approval.status === 'pending' && request.isDashboardSession !== true) {
        const claim = await services.passportClaimsRepo.findByClaimId(approval.intent_claim_id);
        const owned = claim !== null && claim !== undefined && claim.operator_id === request.operatorId
          && claim.passport_id === approval.passport_jti && claim.type === 'intent_claim';
        const parsed = owned ? IntentClaim.safeParse(claim.body_json) : null;
        // A claim that is not this approval's own (another account's or Passport's, or another agent's intent) is no proof
        // of what is approved, so it is approved only in the Console.
        if (!claim || !owned || (parsed?.success === true && parsed.data.agent_id !== approval.agent_id)) {
          throw new ForbiddenError('The intent cannot be read, so it cannot be shown for approval. Approve it in the Console.');
        }
        const intent = parsed?.success === true ? parsed.data : null;
        const preview = intentApprovalPreview(intent ?? claim.body_json);
        if (preview.movesMoney) {
          await enforceGovernanceStepUp(services, request, {
            action: 'intent_approve_payment',
            resourceId: approval.id,
            payload: {
              approval_id: approval.id,
              agent_id: approval.agent_id,
              intent_claim_id: approval.intent_claim_id,
              ...(body.notes !== undefined ? { notes: body.notes } : {}),
            },
            summary: intent
              ? `Approve the intent "${intent.named_intent}" of agent ${approval.agent_id}, which can move money`
              : `Approve an intent of agent ${approval.agent_id} that STACK cannot read`,
            preview: { lines: preview.lines, raw: preview.raw },
          });
        }
      }
      const start = Date.now();
      const result = await services.intentApproval.approve({
        id: request.params.id,
        operatorId: request.operatorId,
        ...(request.memberId ? { memberId: request.memberId } : {}),
        ...(body.notes !== undefined ? { notes: body.notes } : {}),
      });
      await services.audit.write({
        ctx: auditCtx(request, {}),
        layer: 'vault',
        action: 'intents.approve',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return reply.send({
        approval_id: result.approvalId,
        status: result.status,
        decided_at: result.decidedAt.toISOString(),
      });
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/intents/:id/reject',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      // Rejecting needs no approval, but it revokes the agent's Passport (and block_future stops the agent): the
      // owner, or any member who may change things.
      requireRole(request, 'standard');
      const body = DecideBody.parse(request.body ?? {});
      const start = Date.now();
      const result = await services.intentApproval.reject({
        id: request.params.id,
        operatorId: request.operatorId,
        ...(request.memberId ? { memberId: request.memberId } : {}),
        ...(body.notes !== undefined ? { notes: body.notes } : {}),
        ...(body.block_future !== undefined ? { blockFuture: body.block_future } : {}),
      });
      await services.audit.write({
        ctx: auditCtx(request, {}),
        layer: 'vault',
        action: 'intents.reject',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return reply.send({
        approval_id: result.approvalId,
        status: result.status,
        decided_at: result.decidedAt.toISOString(),
      });
    },
  );
}

/** Map an intent_approvals row to the snake_case wire shape. */
export function rowForWire(row: {
  id: string;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
  intent_claim_id: string;
  simulated_claim_id: string | null;
  status: string;
  requested_at: Date;
  expires_at: Date;
  decided_at: Date | null;
  decided_by_member_id: string | null;
  notes: string | null;
  block_future: boolean;
  fleet_policy_id?: string | null;
  fleet_policy_revision?: number | null;
  fleet_mission_id?: string | null;
}) {
  return {
    id: row.id,
    operator_id: row.operator_id,
    agent_id: row.agent_id,
    passport_jti: row.passport_jti,
    intent_claim_id: row.intent_claim_id,
    simulated_claim_id: row.simulated_claim_id,
    status: row.status,
    requested_at: row.requested_at.toISOString(),
    expires_at: row.expires_at.toISOString(),
    decided_at: row.decided_at ? row.decided_at.toISOString() : null,
    decided_by_member_id: row.decided_by_member_id,
    notes: row.notes,
    block_future: row.block_future,
    ...(row.fleet_policy_id ? {
      fleet_policy_id: row.fleet_policy_id,
      fleet_policy_revision: row.fleet_policy_revision,
      fleet_mission_id: row.fleet_mission_id,
    } : {}),
  };
}

/** Convert the camelCase diagnostics shape to snake_case for the wire. */
function snakeCaseDiagnostics(d: {
  failedConstraint?: { path: string; op: string };
  scopeMissingService?: string;
  targetLooksLikeUrl?: boolean;
  accountabilityPassport?: 'enforced' | 'logged' | 'standard';
  accountabilityIntent?: 'enforced' | 'logged' | 'standard';
  tierLimit?: {
    meter: string;
    cap: number;
    used: number;
    walletBalanceCents: number;
    overagePriceCents: number;
  };
  undeclaredEntities?: Array<{ entity: string; entity_type: string }>;
  failingRequires?: string[];
}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (d.failedConstraint) out['failed_constraint'] = d.failedConstraint;
  if (d.scopeMissingService) out['scope_missing_service'] = d.scopeMissingService;
  if (d.targetLooksLikeUrl) {
    out['target_looks_like_url'] = true;
    // #5 — actionable hint: `target` must be a granted service slug.
    out['hint'] =
      'The intent target looks like a URL, but it must be a granted service slug (e.g. "stripe"). Put the full URL in parameters.url.';
  }
  if (d.accountabilityPassport) out['accountability_passport'] = d.accountabilityPassport;
  if (d.accountabilityIntent) out['accountability_intent'] = d.accountabilityIntent;
  if (d.tierLimit) {
    out['tier_limit'] = {
      meter: d.tierLimit.meter,
      cap: d.tierLimit.cap === Infinity ? null : d.tierLimit.cap,
      used: d.tierLimit.used,
      wallet_balance_cents: d.tierLimit.walletBalanceCents,
      overage_price_cents: d.tierLimit.overagePriceCents,
    };
  }
  // surface (undeclared_target flag) and
  // surface (requires_unmet denial). Pass-through with snake_case keys.
  if (d.undeclaredEntities) out['undeclared_entities'] = d.undeclaredEntities;
  if (d.failingRequires) out['failing_requires'] = d.failingRequires;
  return out;
}
