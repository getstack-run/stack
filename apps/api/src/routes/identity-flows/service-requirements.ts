import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { SetServiceRequirementInput } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';
import { requireRole } from '../../middleware/require-role.js';

type RequirementList = Awaited<ReturnType<Services['identity']['getServiceRequirements']>>;
type ServiceParams = FastifyRequest<{ Params: { id: string } }>;

// identity requirements are per-operator policy, not global
// catalog state. Read + write + delete are all scoped to the caller's
// own operator, and writes require the caller to actually own a
// connection to the service (no setting policy on a bare catalog id).

const ReplaceServiceRequirementBody = z.object({
  requirement: SetServiceRequirementInput.nullable(),
}).strict();

export async function getServiceRequirements(
  request: ServiceParams,
  services: Services,
): Promise<RequirementList> {
  // Scoped to request.operatorId — a tenant only sees its OWN policy,
  // never another tenant's (closes the cross-tenant read leak).
  return services.identity.getServiceRequirements(request.operatorId, request.params.id);
}

export async function setServiceRequirement(
  request: ServiceParams,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const input = SetServiceRequirementInput.parse(request.body);
  const start = Date.now();

  // Ownership gate: the caller may only set requirements on
  // a service it actually holds an active connection to. Without this
  // any operator could set requirements on a popular global catalog
  // service. Return 404 (not 403) so a non-owner can't probe which
  // catalog ids exist.
  const ownedConn = await services.serviceConnection.findActiveByServiceId(
    request.operatorId,
    request.params.id,
  );
  if (!ownedConn) {
    return reply.status(404).send({
      error: {
        code: 'SERVICE_NOT_CONNECTED',
        message: 'No active connection to this service for your operator',
      },
    });
  }

  // GDPR validation — Layer 2 must declare requires_pii + lawful basis
  if (input.layer === 'identity' && !input.requires_pii) {
    return reply.status(400).send({
      error: {
        code: 'GDPR_VIOLATION',
        message: 'Layer 2 (identity) requirements must set requires_pii: true',
      },
    });
  }
  if (input.requires_pii && !input.lawful_basis) {
    return reply.status(400).send({
      error: {
        code: 'GDPR_VIOLATION',
        message: 'requires_pii: true requires a lawful_basis declaration',
      },
    });
  }

  const requirement = await services.identity.setServiceRequirement(
    request.operatorId,
    request.params.id,
    input,
  );

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'identity.requirement.set',
    outcome: 'success',
    duration_ms: Date.now() - start,
  });

  return reply.status(201).send(requirement);
}

export async function replaceServiceRequirement(
  request: ServiceParams,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const { requirement } = ReplaceServiceRequirementBody.parse(request.body);
  const start = Date.now();

  const ownedConn = await services.serviceConnection.findActiveByServiceId(
    request.operatorId,
    request.params.id,
  );
  if (!ownedConn) {
    return reply.status(404).send({
      error: {
        code: 'SERVICE_NOT_CONNECTED',
        message: 'No active connection to this service for your operator',
      },
    });
  }

  if (requirement?.layer === 'identity' && !requirement.requires_pii) {
    return reply.status(400).send({
      error: {
        code: 'GDPR_VIOLATION',
        message: 'Layer 2 (identity) requirements must set requires_pii: true',
      },
    });
  }
  if (requirement?.requires_pii && !requirement.lawful_basis) {
    return reply.status(400).send({
      error: {
        code: 'GDPR_VIOLATION',
        message: 'requires_pii: true requires a lawful_basis declaration',
      },
    });
  }

  const requirements = await services.identity.replaceServiceRequirement(
    request.operatorId,
    request.params.id,
    requirement,
  );

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'identity.requirement.replace',
    outcome: 'success',
    duration_ms: Date.now() - start,
  });

  return reply.status(200).send({ requirements });
}

export async function deleteServiceRequirement(
  request: FastifyRequest<{ Params: { id: string; reqId: string } }>,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const start = Date.now();

  // Scoped delete — only removes a row that belongs to this operator.
  // A reqId owned by another tenant is a silent no-op (no cross-tenant
  // delete, no existence oracle).
  await services.identity.deleteServiceRequirement(
    request.operatorId,
    request.params.id,
    request.params.reqId,
  );

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'identity.requirement.delete',
    outcome: 'success',
    duration_ms: Date.now() - start,
  });

  return reply.status(204).send();
}
