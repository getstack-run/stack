import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  AuthorityStatusCheckInput,
  ReceiverChallengeInput,
  ReceiverReceiptInput,
  StackError,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { requireAuthorityReceiver } from '../../middleware/authority-receiver-auth.js';

/** STACK direct-post JWT v1 handlers. The route's preHandler has already authenticated the receiver. */

async function safeAuthorityProtocolCall<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof StackError) throw error;
    throw new StackError(
      'Authority protocol dependency is unavailable',
      'SERVICE_UNAVAILABLE',
      503,
    );
  }
}

export async function createPresentationRequest(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const auth = requireAuthorityReceiver(request);
  const input = ReceiverChallengeInput.parse(request.body);
  const presentation = await safeAuthorityProtocolCall(
    () => services.authority.createPresentationRequest(auth, input),
  );
  return reply.status(202).send(safeAuthorityResponse({ presentation }));
}

export async function getPresentationRequest(
  services: Services,
  request: FastifyRequest<{ Params: { presentationId: string } }>,
) {
  const auth = requireAuthorityReceiver(request);
  const presentation = await safeAuthorityProtocolCall(
    () => services.authority.getPresentationRequest(auth, request.params.presentationId),
  );
  return safeAuthorityResponse({ presentation });
}

export async function checkAuthorityStatus(services: Services, request: FastifyRequest) {
  const auth = requireAuthorityReceiver(request);
  const input = AuthorityStatusCheckInput.parse(request.body);
  const status = await safeAuthorityProtocolCall(() => services.authority.statusCheck(auth, input));
  return safeAuthorityResponse({ status });
}

export async function acceptPresentationReceipt(
  services: Services,
  request: FastifyRequest<{ Params: { presentationId: string } }>,
): Promise<unknown> {
  const auth = requireAuthorityReceiver(request);
  const input = ReceiverReceiptInput.parse(request.body);
  const receipt = await safeAuthorityProtocolCall(
    () => services.authority.acceptReceipt(auth, request.params.presentationId, input),
  );
  return safeAuthorityResponse({ receipt });
}
