// Policies: the configuration behind hosted controls.
//
//   GET    /v1/control-policies                                       every policy of the customer, and whether controls are on
//   GET    /v1/control-policies/default                               the customer's default policy
//   GET    /v1/control-policies/agents/:agentId                       an agent's own policy, and the one in force for it
//   PUT    /v1/control-policies/default                               create or revise the default
//   PUT    /v1/control-policies/agents/:agentId                       create or revise an agent's policy
//   DELETE /v1/control-policies/default                               delete the default
//   DELETE /v1/control-policies/agents/:agentId                       delete an agent's policy
//   POST   /v1/control-policies/agents/:agentId/start-from-current-access   a policy equal to the agent's grants
//   POST   /v1/control-policies/simulate                              try one call against a policy; nothing is counted, held or sent
//   GET    /v1/control-policies/:id/revisions                         the revisions of a policy
//   GET    /v1/control-reviews[/:id]                                  actions a policy held for a person
//
// A policy only narrows what a connection grant already allows. Tightening it
// applies at once; loosening it, and deleting it, takes a person in a signed-in
// browser (governance step-up `account_control_loosen`, browser-only), and a
// revision that is not provably a tightening counts as a loosening. Every
// mutation is an owner or admin decision, denied to agent contexts: an agent
// can never change its own controls. None of it is metered.

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  ControlsNotEnabledError,
  InvalidRequestError,
  DeleteControlPolicyQuery,
  NotFoundError,
  PolicyAgentParams,
  PolicyDefinition,
  SetControlPolicyInput,
  SimulateControlPolicyInput,
  evaluatePolicy,
  perMissionRulesOnly,
  policyUsesPerMission,
  limitsOf,
  normalizePolicy,
  normalizeRequest,
  policyDigest,
  refusalEvidence,
  type ControlPolicySimulationView,
  type PolicyCall,
} from '@stack/shared';
import type { PolicyPlan } from '@stack/vault';
import type { Services } from '../config/services.js';
import { auditCtx } from '../middleware/audit.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { enforceGovernanceStepUp, GOVERNANCE_APPROVAL_HEADER } from '../middleware/governance-stepup.js';
import { denyAgentContexts, requireOperatorAdmin } from '../middleware/require-platform.js';
import { requireControls } from '../middleware/require-controls.js';
import { policyActor } from '../lib/control-policy/policy-actor.js';
import { replyPinsFor } from '../lib/message-senders.js';

const PolicyIdParams = z.object({ id: z.string().regex(/^cpl_[\w-]+$/) }).strict();
const ReviewIdParams = z.object({ id: z.string().regex(/^crv_[\w-]+$/) }).strict();
const ListReviewsQuery = z
  .object({
    status: z.enum(['pending', 'all']).default('pending'),
    limit: z.coerce.number().int().min(1).max(200).default(50),
  })
  .strict();

const RATE = { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } };

export function registerControlPolicyRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);
  // Reading and simulating policies are controls features; the writes refuse CONTROLS_NOT_ENABLED in `assertControlsOn`.
  const policiesNeedControls = requireControls(services, 'policies');
  const reviewsNeedControls = requireControls(services, 'reviews');

  const actorOf = (request: FastifyRequest): string => policyActor(request);

  /** A policy applies to an account's agent; a policy for any other agent would silently do nothing. */
  async function assertAccountAgent(operatorId: string, agentId: string) {
    const account = await services.controlPolicyRepo.accountOfAgent(operatorId, agentId);
    if (!account) throw new NotFoundError('Agent account for agent', agentId);
    return account;
  }

  async function assertControlsOn(operatorId: string): Promise<void> {
    if (!(await services.entitlements.controlsEnabled(operatorId))) throw new ControlsNotEnabledError();
  }

  /** Do what the plan asks (the step-up for a loosening), then apply it and write the audit row. */
  async function carryOut(request: FastifyRequest, plan: PolicyPlan, start: number) {
    if (plan.needsApproval) {
      await enforceGovernanceStepUp(services, request, {
        action: 'account_control_loosen',
        resourceId: request.operatorId,
        payload: {
          policy: plan.agentId ?? 'default',
          change: plan.change,
          expected_revision: plan.expectedRevision,
          definition_digest: plan.next ? policyDigest(plan.next) : null,
        },
        summary: plan.summary,
      });
    }
    const approvalHeader = request.headers[GOVERNANCE_APPROVAL_HEADER];
    const row = await services.controlPolicies.apply(plan, {
      actor: actorOf(request),
      approvalId: typeof approvalHeader === 'string' ? approvalHeader : null,
      authorized: true,
    });
    if (plan.change !== 'unchanged') {
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: `control_policy.${plan.change}`,
        outcome: 'success',
        duration_ms: Date.now() - start,
        ...(plan.next ? { payload_hash: policyDigest(plan.next) } : {}),
      });
    }
    return row;
  }

  async function viewOf(operatorId: string, agentId: string | null) {
    const row = await services.controlPolicies.get(operatorId, agentId);
    return row ? services.controlPolicies.view(row) : null;
  }

  // ─── reads ──────────────────────────────────────────────────────

  app.get('/v1/control-policies', { preHandler: [auth, denyAgentContexts, policiesNeedControls] }, async (request) => {
    const rows = await services.controlPolicies.list(request.operatorId);
    return {
      controls_enabled: await services.entitlements.controlsEnabled(request.operatorId),
      policies: await Promise.all(rows.map((row) => services.controlPolicies.view(row))),
    };
  });

  app.get('/v1/control-policies/default', { preHandler: [auth, denyAgentContexts, policiesNeedControls] }, async (request) => {
    const policy = await viewOf(request.operatorId, null);
    if (!policy) throw new NotFoundError('Control policy', 'default');
    return policy;
  });

  app.get('/v1/control-policies/agents/:agentId', { preHandler: [auth, denyAgentContexts, policiesNeedControls] }, async (request) => {
    const { agentId } = PolicyAgentParams.parse(request.params);
    await assertAccountAgent(request.operatorId, agentId);
    const own = await viewOf(request.operatorId, agentId);
    const inForce = await services.controlPolicies.effective(request.operatorId, agentId);
    return {
      policy: own,
      in_force: inForce ? { id: inForce.id, revision: inForce.revision, source: inForce.source } : null,
      controls_enabled: await services.entitlements.controlsEnabled(request.operatorId),
    };
  });

  app.get('/v1/control-policies/:id/revisions', { preHandler: [auth, denyAgentContexts, policiesNeedControls] }, async (request) => {
    const { id } = PolicyIdParams.parse(request.params);
    const revisions = await services.controlPolicies.revisions(request.operatorId, id);
    if (revisions.length === 0) throw new NotFoundError('Control policy', id);
    return {
      revisions: revisions.map((row) => ({
        revision: row.revision,
        change: row.change,
        actor: row.actor,
        approval_id: row.approval_id,
        definition: row.definition,
        created_at: row.created_at.toISOString(),
      })),
    };
  });

  // ─── writes ─────────────────────────────────────────────────────

  async function setPolicy(request: FastifyRequest, agentId: string | null) {
    const start = Date.now();
    const input = SetControlPolicyInput.parse(request.body);
    if (agentId) await assertAccountAgent(request.operatorId, agentId);
    await assertControlsOn(request.operatorId);
    const plan = await services.controlPolicies.planSet({
      operatorId: request.operatorId,
      agentId,
      definition: input.definition,
      expectedRevision: input.expected_revision,
    });
    const row = await carryOut(request, plan, start);
    return { change: plan.change, policy: row ? await services.controlPolicies.view(row) : null };
  }

  app.put('/v1/control-policies/default', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], ...RATE }, async (request) => setPolicy(request, null));
  app.put('/v1/control-policies/agents/:agentId', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], ...RATE }, async (request) => {
    const { agentId } = PolicyAgentParams.parse(request.params);
    return setPolicy(request, agentId);
  });

  async function deletePolicy(request: FastifyRequest, agentId: string | null) {
    const start = Date.now();
    const query = DeleteControlPolicyQuery.parse(request.query ?? {});
    const plan = await services.controlPolicies.planDelete({
      operatorId: request.operatorId,
      agentId,
      expectedRevision: query.expected_revision,
    });
    await carryOut(request, plan, start);
    return { change: plan.change, policy: null };
  }

  app.delete('/v1/control-policies/default', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], ...RATE }, async (request) => deletePolicy(request, null));
  app.delete('/v1/control-policies/agents/:agentId', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], ...RATE }, async (request) => {
    const { agentId } = PolicyAgentParams.parse(request.params);
    return deletePolicy(request, agentId);
  });

  app.post('/v1/control-policies/agents/:agentId/start-from-current-access', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], ...RATE }, async (request, reply) => {
    const start = Date.now();
    const { agentId } = PolicyAgentParams.parse(request.params);
    await assertAccountAgent(request.operatorId, agentId);
    await assertControlsOn(request.operatorId);
    const plan = await services.controlPolicies.planStart({ operatorId: request.operatorId, agentId });
    const row = await carryOut(request, plan, start);
    return reply.status(201).send({ change: plan.change, policy: row ? await services.controlPolicies.view(row) : null });
  });

  // ─── simulate ───────────────────────────────────────────────────

  app.post('/v1/control-policies/simulate', { preHandler: [auth, denyAgentContexts, policiesNeedControls], ...RATE }, async (request): Promise<ControlPolicySimulationView> => {
    const input = SimulateControlPolicyInput.parse(request.body);
    const { call } = input;
    const operatorId = request.operatorId;

    let definition: PolicyDefinition | null = null;
    let source: 'agent' | 'default' | 'draft' = 'draft';
    let policyId: string | null = null;
    let revision: number | null = null;
    if (input.definition) {
      definition = normalizePolicy(input.definition);
    } else {
      const inForce = await services.controlPolicies.effective(operatorId, input.agent_id ?? null);
      if (inForce) {
        definition = inForce.definition;
        source = inForce.source;
        policyId = inForce.id;
        revision = inForce.revision;
      }
    }

    const controlsOn = await services.entitlements.controlsEnabled(operatorId);
    const checked = await services.controlPosture.hostedApplies(operatorId, call.action);
    const account = input.agent_id ? await services.controlPolicyRepo.accountOfAgent(operatorId, input.agent_id) : null;

    const target: Record<string, unknown> = { ...call.target, ...(call.connection_id ? { connection_id: call.connection_id } : {}) };
    // A call tried inside a Mission is tried with what that Mission pinned, as enforcement does; a Mission that is not the
    // caller's reads as one that pins no one. An account's own send that answers a stored message (`reply_to_message`) takes
    // its pin from that message, as a live send does.
    const missionView = call.mission_id ? await services.mission.findById(call.mission_id) : null;
    const ownMission = missionView && missionView.operator_id === operatorId ? missionView : null;
    const accountSend = call.action === 'email.send' || call.action === 'sms.send' || call.action === 'call.start';
    if (call.reply_to_message !== undefined && (!accountSend || !input.agent_id)) {
      throw new InvalidRequestError('reply_to_message applies to an account send (email.send, sms.send or call.start) tried for an agent_id.');
    }
    const answeredPins = call.reply_to_message !== undefined && input.agent_id
      ? await replyPinsFor(services, { operatorId, agentId: input.agent_id, messageId: call.reply_to_message })
      : null;
    const policyCall: PolicyCall = {
      action: call.action,
      target,
      amountCents: call.amount_cents ?? null,
      request: call.request ? normalizeRequest({ service: 'simulation', ...call.request }) : null,
      ...(answeredPins
        ? { mission: { recipientPins: answeredPins } }
        : call.mission_id && (call.action === 'proxy.call' || accountSend) ? { mission: { recipientPins: ownMission?.recipient_pins ?? null } } : {}),
    };
    const ownDefinition = definition;
    let verdict = definition ? evaluatePolicy(definition, policyCall) : ({ verdict: 'allow' } as const);
    // A call by another agent than the one the Mission was opened for is held to that agent's per-job rules first, as a delegated
    // child is; the chain of Passports in between is not known to a simulation.
    const missionAgentId = ownMission?.assigned_agent_id ?? null;
    if (call.action === 'proxy.call' && missionAgentId && input.agent_id && missionAgentId !== input.agent_id) {
      const owner = await services.controlPolicies.effective(operatorId, missionAgentId);
      if (owner && policyUsesPerMission(owner.definition)) {
        const inherited = evaluatePolicy(perMissionRulesOnly(owner.definition), policyCall);
        if (inherited.verdict === 'deny') {
          verdict = inherited;
          definition = owner.definition;
          source = owner.source;
          policyId = owner.id;
          revision = owner.revision;
        }
      }
    }

    const limits = ownDefinition && account
      ? await services.actionLimits.usage({
          accountId: account.accountId,
          missionId: account.missionId,
          rules: [...limitsOf(ownDefinition, 'actions'), ...limitsOf(ownDefinition, 'cents')],
        })
      : [];

    return {
      verdict: verdict.verdict,
      policy: definition ? { id: policyId, revision, source } : null,
      refusal:
        verdict.verdict === 'allow' || !definition
          ? null
          : refusalEvidence({ id: policyId ?? 'draft', revision: revision ?? 0 }, verdict),
      message: verdict.verdict === 'allow' ? null : verdict.message,
      limits,
      controls_enabled: controlsOn,
      checked,
    };
  });

  // ─── held actions ───────────────────────────────────────────────

  app.get('/v1/control-reviews', { preHandler: [auth, denyAgentContexts, reviewsNeedControls] }, async (request) => {
    const query = ListReviewsQuery.parse(request.query ?? {});
    const rows = await services.controlReviews.list(request.operatorId, { pendingOnly: query.status === 'pending', limit: query.limit });
    return { reviews: rows.map((row) => services.controlReviews.toView(row)) };
  });

  app.get('/v1/control-reviews/:id', { preHandler: [auth, denyAgentContexts, reviewsNeedControls] }, async (request) => {
    const { id } = ReviewIdParams.parse(request.params);
    return services.controlReviews.toView(await services.controlReviews.get(request.operatorId, id));
  });
}
