import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { FleetPolicyInput, FleetMissionStartInput, FleetEnrollmentInput, ForbiddenError, fleetDigest, fleetMemberships } from '@stack/shared';
import { and, eq } from 'drizzle-orm';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { denyAgentContexts, requireOperatorAdmin } from '../middleware/require-platform.js';
import { requireControls } from '../middleware/require-controls.js';
import { enforceGovernanceStepUp } from '../middleware/governance-stepup.js';
import { auditCtx } from '../middleware/audit.js';
import { meterAction } from '../middleware/meter.js';
import { startOperatorMission } from './missions.js';

function worker(request: FastifyRequest) {
  if (!request.agentId) throw new ForbiddenError();
  return request.agentId;
}

const FleetPageQuery = z.object({ page: z.coerce.number().int().min(1).max(100000).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20) }).strict();
function pagination(query: unknown) {
  const input = (query ?? {}) as Record<string, unknown>;
  return Object.keys(input).length ? FleetPageQuery.parse(input) : undefined;
}

export function registerFleetRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);
  // Fleets are a controls feature: with controls off every fleet route answers 402 CONTROLS_REQUIRED.
  const fleetsNeedControls = requireControls(services, 'fleets');
  const admin = [auth, denyAgentContexts, requireOperatorAdmin, fleetsNeedControls];
  const authFleets = [auth, fleetsNeedControls];
  app.post('/v1/fleets/session', { preHandler: authFleets }, async request => {
    if (!request.freshAgentProof) throw new ForbiddenError();
    const input = z.object({ fleet_policy_id: z.string().regex(/^flp_[\w-]+$/).optional() }).strict().parse(request.body ?? {});
    const state = await services.fleet.sessionState(request.operatorId, worker(request), input.fleet_policy_id);
    const accessToken = await services.signer.signFleetSession(state.claims, state.expiresAt);
    return { access_token: accessToken, token_type: 'Bearer',
      expires_in: state.expiresAt - Math.floor(Date.now() / 1000), expires_at: new Date(state.expiresAt * 1000).toISOString() };
  });
  app.get('/v1/fleets', { preHandler: admin }, async request => {
    const page = pagination(request.query);
    if (page) {
      const result = await services.fleetRepo.listPage(request.operatorId, page.page, page.limit);
      return { ...result, items: result.items.map(({ root_agent_id: _root, ...row }) => row) };
    }
    const rows = await services.fleetRepo.list(request.operatorId);
    return rows.map(({ root_agent_id: _root, ...row }) => row);
  });
  app.get<{ Params: { id: string } }>('/v1/fleets/:id', { preHandler: admin }, request =>
    services.fleetRepo.policySummary(request.operatorId, request.params.id));
  app.get<{ Params: { agentId: string } }>('/v1/fleets/membership/:agentId', { preHandler: admin }, request =>
    services.fleetRepo.memberSummary(request.operatorId, request.params.agentId));

  app.post('/v1/fleets', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin, fleetsNeedControls] }, async request => {
    const input = FleetPolicyInput.parse(request.body);
    const key = z.string().min(8).max(128).parse(request.headers['idempotency-key']);
    for (const rule of input.rules) services.serviceConnection.assertConnectionAccess(request.allowedConnections, rule.access.connection_id);
    await enforceGovernanceStepUp(services, request, {
      action: 'fleet_policy_activate', resourceId: fleetDigest({ operator: request.operatorId, key }), payload: input, summary: input.name,
      idempotencyKey: key,
    });
    const result = await services.fleet.activate(request.operatorId, input, request.memberId ?? request.operatorId, undefined, key);
    await services.audit.write({ ctx: auditCtx(request), layer: 'vault', action: 'fleet.policy.activate', outcome: 'success', duration_ms: 0 });
    return result;
  });

  app.put<{ Params: { id: string } }>('/v1/fleets/:id', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin, fleetsNeedControls] }, async request => {
    const input = FleetPolicyInput.parse(request.body);
    const expectedRevision = z.coerce.number().int().positive().parse(request.headers['if-match']);
    const key = z.string().min(8).max(128).parse(request.headers['idempotency-key']);
    for (const rule of input.rules) services.serviceConnection.assertConnectionAccess(request.allowedConnections, rule.access.connection_id);
    await enforceGovernanceStepUp(services, request, {
      action: 'fleet_policy_activate', resourceId: request.params.id, payload: { policy: input, expected_revision: expectedRevision }, summary: input.name,
      idempotencyKey: key,
    });
    const result = await services.fleet.activate(request.operatorId, input, request.memberId ?? request.operatorId, request.params.id, undefined, expectedRevision);
    await services.audit.write({ ctx: auditCtx(request), layer: 'vault', action: 'fleet.policy.revise', outcome: 'success', duration_ms: 0 });
    return result;
  });

  app.post<{ Params: { id: string } }>('/v1/fleets/:id/revoke', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin, fleetsNeedControls] }, async request => {
    await services.fleet.revoke(request.operatorId, request.params.id);
    await services.audit.write({ ctx: auditCtx(request), layer: 'vault', action: 'fleet.policy.revoke', outcome: 'success', duration_ms: 0 });
    return { success: true };
  });

  app.get<{ Params: { id: string } }>('/v1/fleets/:id/members', { preHandler: admin }, async request => {
    return services.fleetRepo.members(request.operatorId, request.params.id, pagination(request.query));
  });
  app.post<{ Params: { id: string; agentId: string } }>('/v1/fleets/:id/members/:agentId/revoke', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin, fleetsNeedControls] }, async request => {
    await services.fleetRepo.withPolicy(request.operatorId, request.params.id, async tx => {
      const result = await tx.update(fleetMemberships).set({ revoked_at: new Date() }).where(and(
        eq(fleetMemberships.policy_id, request.params.id), eq(fleetMemberships.operator_id, request.operatorId),
        eq(fleetMemberships.agent_id, request.params.agentId))).returning({ id: fleetMemberships.id });
      if (!result.length) throw new ForbiddenError();
    });
    await services.audit.write({ ctx: auditCtx(request, { agent_id: request.params.agentId }), layer: 'vault', action: 'fleet.member.revoke', outcome: 'success', duration_ms: 0 });
    return { success: true };
  });

  // These operational routes accept only a live authenticated agent and the
  // exact provisioner listed in the human-approved policy. An operator key
  // cannot turn a body-supplied agent ID into a provisioning identity.
  app.post<{ Params: { id: string } }>('/v1/fleets/:id/enrollment-challenges', { preHandler: authFleets, config: { rateLimit: { max: 120, timeWindow: '1 minute' } } }, request =>
    services.fleet.enrollmentChallenge(request.operatorId, request.params.id, worker(request)));
  app.post<{ Params: { id: string } }>('/v1/fleets/:id/enroll', { preHandler: authFleets }, async (request, reply) => {
    const result = await services.fleet.enroll(request.operatorId, request.params.id, worker(request), FleetEnrollmentInput.parse(request.body));
    await services.audit.write({ ctx: auditCtx(request, { agent_id: result.agent_id }), layer: 'vault', action: 'fleet.member.enroll', outcome: 'success', duration_ms: 0 });
    // The same status as the workload enrollment: the answer names the member whether it was created or renewed.
    return reply.status(201).send(result);
  });

  app.post('/v1/missions/start', { preHandler: auth }, async (request, reply) => {
    // without a fleet_policy_id this is the one-call start for
    // operators, tenant keys and Connect grants: open a Mission and issue the
    // agent's Passport bound to it. The fleet-agent path below is unchanged.
    const raw = request.body;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !('fleet_policy_id' in raw)) {
      return reply.status(201).send(await startOperatorMission(services, request, raw));
    }
    const input = FleetMissionStartInput.parse(raw);
    const agentId = worker(request);
    await meterAction(services, request, undefined, `fleet-mission:${agentId}:${input.fleet_policy_id}:${input.idempotency_key}`);
    const result = await services.fleet.start(request.operatorId, agentId, input);
    await request.meterCommit?.();
    await services.audit.write({ ctx: auditCtx(request, { agent_id: agentId }), layer: 'vault', action: 'mission.start', outcome: 'success', duration_ms: 0 });
    return result;
  });

  app.post<{ Params: { id: string } }>('/v1/missions/:id/renew', { preHandler: auth }, request =>
    services.fleet.renew(request.operatorId, worker(request), request.params.id));
}
