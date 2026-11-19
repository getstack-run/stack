import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  ConflictError,
  CreateEnterpriseOidcAuthoritySetupInput,
  canonicalize,
  sha256,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { validateEnterpriseOidcAuthoritySetupRequest } from '../../services/enterprise-oidc-authority-setup.js';
import { idempotencyKey, writeAudit } from './request-support.js';
import {
  AUTHORITY_REQUEST_KEY,
  AUTHORITY_REQUEST_TTL_SECONDS,
  AuthoritySetupRequestParams,
  authorityRequestProjection,
  createAuthorityRequest,
  loadAuthorityRequest,
  type AuthoritySetupRequestRecord,
} from './setup-requests.js';

/** Operator-side handlers for Enterprise OIDC Authority setup requests. */

export async function createEnterpriseOidcRequest(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const input = CreateEnterpriseOidcAuthoritySetupInput.parse(request.body);
  const mutationKey = idempotencyKey(request);
  const requestId = `aor_${sha256(`${request.operatorId}\u0000${mutationKey}`).slice(0, 32)}`;
  const normalizedRequest = {
    ...input,
    expires_at: input.expires_at.toISOString(),
  };
  const validated = await validateEnterpriseOidcAuthoritySetupRequest({
    services,
    operatorId: request.operatorId,
    request: input,
  });
  const requestHash = sha256(canonicalize(normalizedRequest));
  const existingCiphertext = await services.redis.get(AUTHORITY_REQUEST_KEY + requestId);
  if (existingCiphertext) {
    const existing = await loadAuthorityRequest(services, request.operatorId, requestId);
    if (existing.request_hash !== requestHash) {
      throw new ConflictError('Idempotency-Key was already used for a different Authority request');
    }
    return reply.status(200).send(authorityRequestProjection(existing));
  }

  const now = new Date();
  const expiresAt = new Date(Math.min(
    now.getTime() + AUTHORITY_REQUEST_TTL_SECONDS * 1000,
    input.expires_at.getTime(),
  ));
  const record: AuthoritySetupRequestRecord = {
    request_id: requestId,
    operator_id: request.operatorId,
    request_hash: requestHash,
    request: normalizedRequest,
    display: {
      agent_name: validated.agentName,
      mission_summary: validated.missionSummary,
      system_name: input.provider,
    },
    status: 'pending',
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  };
  const created = await createAuthorityRequest(services, record);
  if (!created) {
    const raced = await loadAuthorityRequest(services, request.operatorId, requestId);
    if (raced.request_hash !== requestHash) {
      throw new ConflictError('Idempotency-Key was already used for a different Authority request');
    }
    return reply.status(200).send(authorityRequestProjection(raced));
  }
  await writeAudit(services, request, 'authority.enterprise_oidc.request');
  return reply.status(201).send(authorityRequestProjection(record));
}

export async function getEnterpriseOidcRequest(
  services: Services,
  request: FastifyRequest<{ Params: { requestId: string } }>,
) {
  const { requestId } = AuthoritySetupRequestParams.parse(request.params);
  const record = await loadAuthorityRequest(services, request.operatorId, requestId);
  return authorityRequestProjection(record);
}
