import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  AuthorityProofCallbackInput,
  CreateAuthorityProofCollectionSessionInput,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { requireAuthorityProofCallback } from '../../middleware/authority-proof-callback-auth.js';
import { idempotencyKey, writeAudit } from './request-support.js';

export async function createProofCollectionSession(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const input = CreateAuthorityProofCollectionSessionInput.parse(request.body);
  const session = await services.authority.createProofCollectionSession(
    request.operatorId,
    input,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.proof_collection.create');
  return reply.status(201).send(safeAuthorityResponse({ session }));
}

export async function getProofCollectionSession(
  services: Services,
  request: FastifyRequest<{ Params: { sessionId: string } }>,
) {
  const session = await services.authority.getProofCollectionSession(
    request.operatorId,
    request.params.sessionId,
  );
  return safeAuthorityResponse({ session });
}

/** Provider callback body; the route's preHandler has already run the pinned adapter ceremony. */
export async function completeProofCallback(
  services: Services,
  request: FastifyRequest<{ Params: { adapterKey: string } }>,
) {
  const auth = requireAuthorityProofCallback(request);
  const input = AuthorityProofCallbackInput.parse(request.body);
  const proof = await services.authority.completeProofCollectionSession(auth, input);
  return safeAuthorityResponse({ proof });
}
