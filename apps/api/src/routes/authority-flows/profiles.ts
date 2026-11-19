import type { FastifyReply, FastifyRequest } from 'fastify';
import { CreateAuthorityProfileVersionInput } from '@stack/shared';
import { z } from 'zod';
import type { Services } from '../../config/services.js';
import { enforceGovernanceStepUp } from '../../middleware/governance-stepup.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { idempotencyKey, writeAudit } from './request-support.js';

const ProfileActivationBody = z.object({
  profile_kind: z.enum(['proof', 'domain', 'receiver']),
}).strict();

export async function createProfileVersion(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const input = CreateAuthorityProfileVersionInput.parse(request.body);
  const profile = await services.authority.createProfileVersion(
    request.operatorId,
    input,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.profile.create');
  return reply.status(201).send(safeAuthorityResponse({ profile }));
}

export async function activateProfileVersion(
  services: Services,
  request: FastifyRequest<{ Params: { profileId: string } }>,
) {
  const input = ProfileActivationBody.parse(request.body);
  const mutationIdempotencyKey = idempotencyKey(request);
  await enforceGovernanceStepUp(services, request, {
    action: 'authority_profile_activate',
    resourceId: request.params.profileId,
    payload: { profile_kind: input.profile_kind },
    summary: `Activate ${input.profile_kind} authority profile ${request.params.profileId}`,
    idempotencyKey: mutationIdempotencyKey,
  });
  const profile = await services.authority.activateProfileVersion(
    request.operatorId,
    input.profile_kind,
    request.params.profileId,
    mutationIdempotencyKey,
  );
  await writeAudit(services, request, 'authority.profile.activate');
  return safeAuthorityResponse({ profile });
}
