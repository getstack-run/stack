import type { FastifyReply, FastifyRequest } from 'fastify';
import { AttachAuthorityProofInput } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { enforceGovernanceStepUp } from '../../middleware/governance-stepup.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { idempotencyKey, writeAudit } from './request-support.js';
import { accountAuthorityPage, EmptyBody, ReasonBody, VersionQuery } from './schemas.js';

type ProofRequest = FastifyRequest<{ Params: { proofId: string } }>;

export async function importProof(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const input = AttachAuthorityProofInput.parse(request.body);
  const proof = await services.authority.importProof(
    request.operatorId,
    input,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.proof.import');
  return reply.status(201).send(safeAuthorityResponse({ proof }));
}

export async function listProofs(services: Services, request: FastifyRequest): Promise<unknown> {
  const query = accountAuthorityPage(request.query, 'proofs');
  if (query) return safeAuthorityResponse(await services.authority.listAccountRecords(
    request.operatorId, 'proofs', query.page, query.limit,
    query.record_id ? { id: query.record_id, version: query.version } : undefined,
  ));
  const proofs = await services.authority.listProofs(request.operatorId);
  return safeAuthorityResponse({ proofs });
}

export async function getProof(services: Services, request: ProofRequest): Promise<unknown> {
  const { version } = VersionQuery.parse(request.query);
  const proof = await services.authority.getProof(request.operatorId, request.params.proofId, version);
  return safeAuthorityResponse({ proof });
}

export async function revokeProof(services: Services, request: ProofRequest): Promise<unknown> {
  const input = ReasonBody.parse(request.body);
  const proof = await services.authority.revokeProof(
    request.operatorId,
    request.params.proofId,
    input.reason_code,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.proof.revoke');
  return safeAuthorityResponse({ proof });
}

export async function eraseProof(services: Services, request: ProofRequest): Promise<unknown> {
  EmptyBody.parse(request.body ?? {});
  const mutationIdempotencyKey = idempotencyKey(request);
  await enforceGovernanceStepUp(services, request, {
    action: 'authority_proof_erase',
    resourceId: request.params.proofId,
    payload: {},
    summary: `Erase encrypted authority proof ${request.params.proofId}`,
    idempotencyKey: mutationIdempotencyKey,
  });
  const proof = await services.authority.eraseProof(
    request.operatorId,
    request.params.proofId,
    mutationIdempotencyKey,
  );
  await writeAudit(services, request, 'authority.proof.erase');
  return safeAuthorityResponse({ proof });
}
