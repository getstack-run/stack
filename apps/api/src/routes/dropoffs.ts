import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { CreateDropoffInput, DropoffExpiredError, ForbiddenError, StackError, namedDropoffRecipients, sha256 } from '@stack/shared';
import { beginAgentRuntime, normalizedFleetOperation, dispatchFleetDropoff, completeFleetDropoff } from '../lib/agent-runtime.js';
import { decideControl } from '../lib/control-decision.js';
import { controlTargets } from '../lib/control-socket/targets.js';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { meterAction } from '../middleware/meter.js';
import { requireRole } from '../middleware/require-role.js';
import { assertDropoffAgentBinding } from '../lib/dropoff-authority.js';
import { announceDeposit } from '../lib/dropoff-deposited.js';
import { computeDepositProvenance, recordCollectedProvenance } from '../lib/provenance.js';

const DepositBody = z.object({
  agent_id: z.string().min(1),
  payload: z.record(z.unknown()),
  /** Optional stored Passport for account/OAuth/agent-JWT callers. Inbound
   * Passport auth uses the server-verified request context instead. */
  passport_jti: z.string().min(1).optional(),
  /** Optional Mission selector. Must be the Mission the Passport carries. */
  mission_id: z.string().regex(/^ms_/).optional(),
  /**
   * Drive files this drop-off hands to the collector; they open to it when it collects. Read by the handler the
   * deployment registered for the field; a deployment with no drive refuses them.
   */
  drive_files: z.unknown().optional(),
}).passthrough();

/** Fields of a deposit the API names but only a deployment's own handler can carry. */
const RESERVED_ATTACHMENT_FIELDS = ['drive_files'] as const;

/** What a deposit carries beside its payload, each read by the handler that owns its field. */
function depositAttachments(services: Services, body: Record<string, unknown>) {
  const attachments = services.registries.dropoffAttachments;
  for (const field of RESERVED_ATTACHMENT_FIELDS) {
    if (body[field] !== undefined && !attachments.has(field)) {
      throw new StackError(`${field} cannot be handed over with a drop-off on this deployment`, 'NOT_CONFIGURED', 400);
    }
  }
  return attachments.values().flatMap((handler) =>
    body[handler.field] === undefined ? [] : [{ handler, value: handler.schema.parse(body[handler.field]) }]);
}
const CollectBody = z.object({
  agent_id: z.string().min(1),
});

export function registerDropoffRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.post('/v1/dropoffs', { preHandler: auth }, async (request, reply) => {
    requireRole(request, 'standard');
    const input = CreateDropoffInput.parse(request.body);
    const recipients = namedDropoffRecipients(input);
    assertDropoffAgentBinding(request, input.from_agent);
    const start = Date.now();

    // Verify the sender and every agent named belong to the authenticated operator. getById throws
    // NotFoundError when the agent is unknown or owned by a different operator, so a foreign agent in a
    // group reads as a missing one and nothing is created.
    await services.agent.getById(input.from_agent, request.operatorId);
    for (const recipient of recipients) await services.agent.getById(recipient, request.operatorId);

    // Mission admission. Drop-offs stay inside STACK, so the Mission's service
    // scope does not apply (requestedService 'stack:dropoff', internal); its
    // lifecycle, duration and caps do.
    const runtime = await beginAgentRuntime(services, request, { agentId: input.from_agent,
      producer: 'dropoff', requestedService: 'stack:dropoff', internal: true, targetId: recipients[0]!, action: 'create',
      normalizedRequest: normalizedFleetOperation('create', input),
      denial: { intentType: 'a2a_dispatch', namedIntent: 'stack:dropoff:create', parameters: { to_agent: recipients[0]!, to_agents: recipients } } });
    const fleetAdmission = runtime?.fleet ?? null;
    if (fleetAdmission) {
      const gate = await services.approvalGate.check({ passportJti: fleetAdmission.authorization.passportJti,
        agentId: fleetAdmission.authorization.agentId, missionId: fleetAdmission.authorization.binding.mission_id,
        operatorId: request.operatorId, sessionId: '', accountabilityMode: 'enforced', approvalIdHeader: undefined,
        policyAuthorization: fleetAdmission.authorization });
      if (!gate.allowed) throw new ForbiddenError();
      await dispatchFleetDropoff(services, fleetAdmission);
    }

    await meterAction(services, request);
    // An account's agents work together, so a drop-off between them stays open; the
    // customer's decider is asked like for any action.
    await decideControl(services, request, {
      action: 'dropoff.create', scope: 'agent', agentId: input.from_agent, runtime,
      target: controlTargets.dropoffCreate({ toAgents: recipients }),
    });
    const dropoff = await services.db.transaction(async (tx) => {
      const created = await services.dropoff.create(request.operatorId, input, tx);
      await services.audit.write({
        ctx: auditCtx(request, {
          agent_id: input.from_agent,
          ...(request.passportContext ? { passport_jti: request.passportContext.jti } : {}),
        }),
        layer: 'dropoff',
        action: 'dropoff.create',
        outcome: 'success',
        duration_ms: Date.now() - start,
      }, tx);
      return created;
    });

    await completeFleetDropoff(services, fleetAdmission, dropoff);
    return reply.status(201).send(dropoff);
  });

  app.post<{ Params: { id: string } }>(
    '/v1/dropoffs/:id/deposit',
    { preHandler: auth },
    async (request) => {
      requireRole(request, 'standard');
      const depositBody = DepositBody.parse(request.body);
      const { agent_id, payload, mission_id, passport_jti } = depositBody;
      const attachments = depositAttachments(services, depositBody);
      assertDropoffAgentBinding(request, agent_id);
      const start = Date.now();

      let expiryError: DropoffExpiredError | null = null;
      const transfer = await services.dropoff.getStatus(request.params.id, request.operatorId, agent_id);
      const runtime = await beginAgentRuntime(services, request, { agentId: agent_id, passportId: passport_jti,
        explicitMissionId: mission_id, producer: 'dropoff', requestedService: 'stack:dropoff', internal: true,
        targetId: transfer.to_agent, action: 'deposit',
        normalizedRequest: normalizedFleetOperation('deposit', { dropoff_id: request.params.id, to_agent: transfer.to_agent, payload }),
        bytes: Buffer.byteLength(JSON.stringify(payload)),
        denial: { intentType: 'a2a_dispatch', namedIntent: 'stack:dropoff:deposit', parameters: { dropoff_id: request.params.id } } });
      await decideControl(services, request, {
        action: 'dropoff.deposit', scope: 'agent', agentId: agent_id, runtime,
        target: controlTargets.dropoffDeposit({ toAgents: transfer.to_agents, payloadBytes: Buffer.byteLength(JSON.stringify(payload)) }),
      });
      // Where this hand-off's content came from: matched against what the
      // depositor's Mission has read, so the collector inherits the ORIGINAL
      // sources. Before any dispatch or write; with controls on it refuses
      // (503) if it cannot be established. lib/provenance.ts.
      const provenance = await computeDepositProvenance(services, {
        operatorId: request.operatorId, agentId: agent_id, passportJti: runtime?.passportJti ?? null,
        missionId: runtime?.missionId ?? null, payload, producer: 'dropoff', mode: runtime?.accountability,
      });
      const fleetAdmission = runtime?.fleet ?? null;
      if (fleetAdmission) {
        const gate = await services.approvalGate.check({ passportJti: fleetAdmission.authorization.passportJti,
          agentId: fleetAdmission.authorization.agentId, missionId: fleetAdmission.authorization.binding.mission_id,
          operatorId: request.operatorId, sessionId: '', accountabilityMode: 'enforced', approvalIdHeader: undefined,
          policyAuthorization: fleetAdmission.authorization });
        if (!gate.allowed) throw new ForbiddenError();
        await dispatchFleetDropoff(services, fleetAdmission);
      }
      const result = await services.db.transaction(async (tx) => {
        try {
          const deposited = await services.dropoff.deposit(
            request.params.id,
            request.operatorId,
            agent_id,
            payload,
            runtime?.missionId ?? null,
            tx,
            provenance as unknown as Record<string, unknown>,
          );

          // Files handed over with the payload (the drive's): the depositor must be able to
          // read each, and the collector gets them when it collects.
          for (const { handler, value } of attachments) {
            await handler.attach({
              operatorId: request.operatorId,
              dropoffId: request.params.id,
              fromAgentId: agent_id,
              toAgentId: transfer.to_agent,
              value,
              missionId: runtime?.missionId ?? null,
              passportJti: runtime?.passportJti ?? null,
              audit: auditCtx(request, { agent_id, ...(runtime ? { passport_jti: runtime.passportJti } : {}) }),
              transaction: tx,
            });
          }

          await services.audit.write({
            ctx: auditCtx(request, {
              agent_id,
              ...((request.passportContext?.jti ?? passport_jti)
                ? { passport_jti: request.passportContext?.jti ?? passport_jti }
                : {}),
            }),
            layer: 'dropoff',
            action: 'dropoff.deposit',
            outcome: 'success',
            duration_ms: Date.now() - start,
            payload_hash: sha256(JSON.stringify(payload)),
          }, tx);
          return deposited;
        } catch (err) {
          if (!(err instanceof DropoffExpiredError)) throw err;
          expiryError = err;
          await services.audit.write({
            ctx: auditCtx(request, { agent_id }),
            layer: 'dropoff',
            action: 'dropoff.expire',
            outcome: 'success',
            duration_ms: Date.now() - start,
          }, tx);
          return null;
        }
      });

      if (expiryError) throw expiryError;
      await completeFleetDropoff(services, fleetAdmission, result);
      // The work is deposited and committed: tell the deployment, which wakes the agents it names.
      if (result) {
        await announceDeposit(services, {
          operatorId: request.operatorId,
          dropoffId: result.id,
          fromAgentId: agent_id,
          toAgentIds: result.to_agent_ids,
        }, request.log);
      }
      return result;
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/dropoffs/:id/collect',
    { preHandler: auth },
    async (request) => {
      requireRole(request, 'standard');
      const { agent_id } = CollectBody.parse(request.body);
      assertDropoffAgentBinding(request, agent_id);
      const start = Date.now();

      let expiryError: DropoffExpiredError | null = null;
      const transfer = await services.dropoff.getStatus(request.params.id, request.operatorId, agent_id);
      const runtime = await beginAgentRuntime(services, request, { agentId: agent_id,
        producer: 'dropoff', requestedService: 'stack:dropoff', internal: true, targetId: transfer.from_agent, action: 'collect',
        normalizedRequest: normalizedFleetOperation('collect', { dropoff_id: request.params.id, from_agent: transfer.from_agent }),
        bytes: transfer.deposited_bytes ?? 0,
        denial: { intentType: 'a2a_dispatch', namedIntent: 'stack:dropoff:collect', parameters: { dropoff_id: request.params.id } } });
      const fleetAdmission = runtime?.fleet ?? null;
      if (fleetAdmission) {
        const gate = await services.approvalGate.check({ passportJti: fleetAdmission.authorization.passportJti,
          agentId: fleetAdmission.authorization.agentId, missionId: fleetAdmission.authorization.binding.mission_id,
          operatorId: request.operatorId, sessionId: '', accountabilityMode: 'enforced', approvalIdHeader: undefined,
          policyAuthorization: fleetAdmission.authorization });
        if (!gate.allowed) throw new ForbiddenError();
        await dispatchFleetDropoff(services, fleetAdmission);
      }
      const handed = await services.db.transaction(async (tx) => {
        try {
          const { payload: collected, provenance } = await services.dropoff.collectWithProvenance(
            request.params.id,
            request.operatorId,
            agent_id,
            tx,
          );
          // The collector's Mission records the hand-off's content as read
          // from its ORIGINAL sources, before custody transfers: with controls
          // on a failure here rolls the collection back instead of handing
          // content over with no record. A collector with no Passport (an
          // operator key) is a human principal, not an agent the rule follows.
          if (runtime) {
            await recordCollectedProvenance(services, {
              operatorId: request.operatorId, collectorAgentId: agent_id, passportJti: runtime.passportJti,
              missionId: runtime.missionId, dropoffId: request.params.id, fromAgentId: transfer.from_agent,
              payload: collected, provenance, mode: runtime.accountability,
            });
          }

          await services.audit.write({
            ctx: auditCtx(request, {
              agent_id,
              ...(request.passportContext ? { passport_jti: request.passportContext.jti } : {}),
            }),
            layer: 'dropoff',
            action: 'dropoff.collect',
            outcome: 'success',
            duration_ms: Date.now() - start,
            payload_hash: sha256(JSON.stringify(collected)),
          }, tx);
          // The files the depositor handed over open to the collector now.
          const handedOver: Record<string, readonly unknown[]> = {};
          for (const handler of services.registries.dropoffAttachments.values()) {
            const items = await handler.complete({
              dropoffId: request.params.id,
              agentId: agent_id,
              operatorId: request.operatorId,
              transaction: tx,
            });
            if (items.length > 0) handedOver[handler.field] = items;
          }
          return { collected, handedOver };
        } catch (err) {
          if (!(err instanceof DropoffExpiredError)) throw err;
          expiryError = err;
          await services.audit.write({
            ctx: auditCtx(request, { agent_id }),
            layer: 'dropoff',
            action: 'dropoff.expire',
            outcome: 'success',
            duration_ms: Date.now() - start,
          }, tx);
          return null;
        }
      });

      if (expiryError) throw expiryError;
      const payload = handed?.collected ?? null;
      await completeFleetDropoff(services, fleetAdmission, { payload });
      return { payload, ...(handed?.handedOver ?? {}) };
    },
  );

  app.get<{ Params: { id: string } }>(
    '/v1/dropoffs/:id',
    { preHandler: auth },
    async (request) => {
      return services.dropoff.getStatus(request.params.id, request.operatorId, request.agentId);
    },
  );

  app.get('/v1/dropoffs', { preHandler: auth }, async (request) => {
    return services.dropoff.listForOperator(request.operatorId, request.agentId);
  });

  app.post<{ Params: { id: string } }>(
    '/v1/dropoffs/:id/expire',
    { preHandler: auth },
    async (request) => {
      requireRole(request, 'standard');
      const start = Date.now();
      const result = await services.db.transaction(async (tx) => {
        const expired = await services.dropoff.expire(
          request.params.id,
          request.operatorId,
          request.agentId,
          tx,
        );

        await services.audit.write({
          ctx: auditCtx(request, {
            ...(request.agentId ? { agent_id: request.agentId } : {}),
            ...(request.passportContext ? { passport_jti: request.passportContext.jti } : {}),
          }),
          layer: 'dropoff',
          action: 'dropoff.expire',
          outcome: 'success',
          duration_ms: Date.now() - start,
        }, tx);
        return expired;
      });

      return result;
    },
  );
}
