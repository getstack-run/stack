import type { FastifyReply, FastifyRequest } from 'fastify';
import { isIP } from 'node:net';
import {
  AddAuthorityReceiverKeyInput,
  CreateAuthorityReceiverInput,
  StackError,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { enforceGovernanceStepUp } from '../../middleware/governance-stepup.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { idempotencyKey, writeAudit } from './request-support.js';
import { accountAuthorityPage, EmptyBody, ReasonBody } from './schemas.js';

type ReceiverRequest = FastifyRequest<{ Params: { receiverId: string } }>;

export function assertNormalizedNativeReceiverOrigin(input: {
  mode: 'native' | 'proxy_bridge' | 'internal';
  canonical_identifier: string;
}): void {
  if (input.mode !== 'native') return;
  try {
    const url = new URL(input.canonical_identifier);
    if (
      url.protocol !== 'https:'
      || input.canonical_identifier !== url.origin
      || url.pathname !== '/'
      || url.search
      || url.hash
      || url.username
      || url.password
      || isIP(url.hostname.replace(/^\[|\]$/g, '')) !== 0
    ) {
      throw new Error('invalid origin');
    }
  } catch {
    throw new StackError(
      'Native receiver identifier must be a normalized HTTPS origin',
      'VALIDATION_ERROR',
      400,
    );
  }
}

export async function createReceiver(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const input = CreateAuthorityReceiverInput.parse(request.body);
  assertNormalizedNativeReceiverOrigin(input);
  const receiver = await services.authority.createReceiver(
    request.operatorId,
    input,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.receiver.create');
  return reply.status(201).send(safeAuthorityResponse({ receiver }));
}

export async function listReceivers(services: Services, request: FastifyRequest): Promise<unknown> {
  const query = accountAuthorityPage(request.query, 'receivers');
  if (query) return safeAuthorityResponse(await services.authority.listAccountRecords(
    request.operatorId, 'receivers', query.page, query.limit,
    query.record_id ? { id: query.record_id, version: query.version } : undefined,
  ));
  const receivers = await services.authority.listReceivers(request.operatorId);
  return safeAuthorityResponse({ receivers });
}

export async function getReceiver(services: Services, request: ReceiverRequest) {
  const receiver = await services.authority.getReceiver(
    request.operatorId,
    request.params.receiverId,
  );
  return safeAuthorityResponse({ receiver });
}

export async function createReceiverVerificationChallenge(
  services: Services,
  request: ReceiverRequest,
  reply: FastifyReply,
) {
  EmptyBody.parse(request.body ?? {});
  const challenge = await services.authority.createReceiverVerificationChallenge(
    request.operatorId,
    request.params.receiverId,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.receiver_verification.challenge');
  return reply.status(201).send(safeAuthorityResponse({ challenge }));
}

export async function verifyReceiver(services: Services, request: ReceiverRequest) {
  EmptyBody.parse(request.body ?? {});
  const receiver = await services.authority.verifyReceiver(
    request.operatorId,
    request.params.receiverId,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.receiver.verify');
  return safeAuthorityResponse({ receiver });
}

export async function addReceiverKey(
  services: Services,
  request: ReceiverRequest,
  reply: FastifyReply,
) {
  const input = AddAuthorityReceiverKeyInput.parse(request.body);
  const mutationIdempotencyKey = idempotencyKey(request);
  await enforceGovernanceStepUp(services, request, {
    action: 'authority_receiver_key_add',
    resourceId: request.params.receiverId,
    payload: input,
    summary: `Add receiver trust key ${input.key_id} to ${request.params.receiverId}`,
    idempotencyKey: mutationIdempotencyKey,
  });
  const key = await services.authority.addReceiverKey(
    request.operatorId,
    request.params.receiverId,
    input,
    mutationIdempotencyKey,
  );
  await writeAudit(services, request, 'authority.receiver_key.add');
  return reply.status(201).send(safeAuthorityResponse({ key }));
}

export async function revokeReceiverKey(
  services: Services,
  request: FastifyRequest<{ Params: { receiverId: string; keyId: string } }>,
) {
  const input = ReasonBody.parse(request.body);
  const key = await services.authority.revokeReceiverKey(
    request.operatorId,
    request.params.receiverId,
    request.params.keyId,
    input.reason_code,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.receiver_key.revoke');
  return safeAuthorityResponse({ key });
}
