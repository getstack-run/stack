import type { FastifyReply, FastifyRequest } from 'fastify';
import { CreateAuthorityBindingInput, DelegateAuthorityBindingInput } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { enforceGovernanceStepUp } from '../../middleware/governance-stepup.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { beginAgentRuntime, normalizedFleetOperation } from '../../lib/agent-runtime.js';
import { decideControl } from '../../lib/control-decision.js';
import { controlTargets } from '../../lib/control-socket/targets.js';
import { idempotencyKey, writeAudit } from './request-support.js';
import { authorityMutationActor } from './mutation-actor.js';
import { BindingListQuery, EmptyBody, ReasonBody, VersionQuery } from './schemas.js';

type BindingRequest = FastifyRequest<{ Params: { bindingId: string } }>;

export async function createBinding(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const input = CreateAuthorityBindingInput.parse(request.body);
  const binding = await services.authority.createBinding(
    request.operatorId,
    input,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.binding.create');
  return reply.status(201).send(safeAuthorityResponse({ binding }));
}

export async function listBindings(services: Services, request: FastifyRequest): Promise<unknown> {
  const query = BindingListQuery.parse(request.query);
  if (query.agent_id) {
    await services.agent.getById(query.agent_id, request.operatorId);
    return safeAuthorityResponse(await services.authority.listAgentBindings(
      request.operatorId, query.agent_id, query.page, query.limit,
      query.binding_id ? { id: query.binding_id, version: query.binding_version! } : undefined,
    ));
  }
  const bindings = await services.authority.listBindings(request.operatorId);
  return safeAuthorityResponse({ bindings });
}

export async function getBinding(services: Services, request: BindingRequest): Promise<unknown> {
  const { version } = VersionQuery.parse(request.query);
  const binding = await services.authority.getBinding(
    request.operatorId,
    request.params.bindingId,
    version,
  );
  return safeAuthorityResponse({ binding });
}

export async function activateBinding(services: Services, request: BindingRequest): Promise<unknown> {
  const { version } = VersionQuery.parse(request.query);
  EmptyBody.parse(request.body ?? {});
  const mutationIdempotencyKey = idempotencyKey(request);
  await enforceGovernanceStepUp(services, request, {
    action: 'authority_binding_activate',
    resourceId: request.params.bindingId,
    payload: { version: version ?? null },
    summary: `Activate authority binding ${request.params.bindingId}`,
    idempotencyKey: mutationIdempotencyKey,
  });
  const binding = await services.authority.activateBinding(
    request.operatorId,
    request.params.bindingId,
    version,
    mutationIdempotencyKey,
  );
  await writeAudit(services, request, 'authority.binding.activate');
  return safeAuthorityResponse({ binding });
}

export async function delegateBinding(
  services: Services,
  request: BindingRequest,
  reply: FastifyReply,
) {
  const input = DelegateAuthorityBindingInput.parse(request.body);
  const actor = await authorityMutationActor(services, request, reply);
  // An agent delegating authority is acting, so its Mission must admit it
  // (lifecycle, duration, caps). Delegation is not a call to a service, so
  // the Mission's service scope does not apply. Revoke, below, is
  // safety-increasing and deliberately stays reachable on a dead Mission.
  if (actor.kind === 'agent') {
    const runtime = await beginAgentRuntime(services, request, {
      agentId: actor.agent_id, passportId: actor.passport_jti, producer: 'authority',
      requestedService: 'stack:authority', internal: true, targetId: request.params.bindingId, action: 'delegate',
      normalizedRequest: normalizedFleetOperation('authority.delegate', { binding_id: request.params.bindingId, input }),
      denial: { intentType: 'task_complete', namedIntent: 'stack:authority:delegate', parameters: { binding_id: request.params.bindingId } },
    });
    // An account's agents may delegate authority; the customer's decider is asked like for any action.
    await decideControl(services, request, {
      action: 'passport.delegate', scope: 'agent', agentId: actor.agent_id, runtime,
      target: controlTargets.passportDelegate({ bindingId: request.params.bindingId }),
    });
  }
  const binding = await services.authority.delegateBinding(
    request.operatorId,
    request.params.bindingId,
    input,
    actor,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.binding.delegate');
  return reply.status(201).send(safeAuthorityResponse({ binding }));
}

export async function revokeBinding(
  services: Services,
  request: BindingRequest,
  reply: FastifyReply,
): Promise<unknown> {
  const input = ReasonBody.parse(request.body);
  const actor = await authorityMutationActor(services, request, reply);
  const binding = await services.authority.revokeBinding(
    request.operatorId,
    request.params.bindingId,
    input.reason_code,
    actor,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.binding.revoke');
  return safeAuthorityResponse({ binding });
}

export async function eraseBinding(services: Services, request: BindingRequest): Promise<unknown> {
  EmptyBody.parse(request.body ?? {});
  const mutationIdempotencyKey = idempotencyKey(request);
  await enforceGovernanceStepUp(services, request, {
    action: 'authority_binding_erase',
    resourceId: request.params.bindingId,
    payload: {},
    summary: `Erase authority binding ${request.params.bindingId}`,
    idempotencyKey: mutationIdempotencyKey,
  });
  const tombstone = await services.authority.eraseBinding(
    request.operatorId,
    request.params.bindingId,
    mutationIdempotencyKey,
  );
  await writeAudit(services, request, 'authority.binding.erase');
  return safeAuthorityResponse({ tombstone });
}
