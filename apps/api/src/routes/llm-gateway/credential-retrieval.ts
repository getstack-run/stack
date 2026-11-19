// Stage 10, second half: decrypt the provider credential. The only place in
// the customer-key LLM gateway that does, and it runs after the scope wall, the approval
// gate, Mission admission and the billing hold. If retrieval fails the wallet
// hold is released. (An agent account's OpenRouter calls take STACK's key in
// `./openrouter/`, at the same point, never earlier.)

import type { FastifyRequest } from 'fastify';
import { ForbiddenError, NotFoundError } from '@stack/shared';
import type { Services } from '../../config/services.js';
import type { LlmHandlerConfig } from './provider-configs.js';
import { releaseBillingHold } from './billing-hold.js';
import type { AdmittedCall, BillingHold } from './types.js';

export async function retrieveProviderCredential(
  services: Services,
  request: FastifyRequest,
  config: LlmHandlerConfig,
  call: AdmittedCall,
  /** The hold to give back when the credential cannot be read; none for a call that took none (images). */
  hold: BillingHold | null,
): Promise<string> {
  const { operatorId, connectionId } = call;
  let apiKey: string;
  try {
    // The connection the call was authorized on, not a second lookup by provider.
    if (!connectionId) throw new NotFoundError('ServiceConnection', config.provider);
    const credResult = await services.serviceConnection.retrieveCredentialByConnectionId(operatorId, connectionId, request.allowedConnections);
    apiKey = 'credential' in credResult
      ? credResult.credential
      : (credResult.credentials.api_key ?? JSON.stringify(credResult.credentials));
  } catch (err) {
    if (hold) await releaseBillingHold(services, operatorId, hold).catch(() => {});
    if (err instanceof NotFoundError) {
      throw new ForbiddenError(
        `No ${config.provider} connection on this operator. Connect ${config.provider} at /services first.`,
      );
    }
    throw err;
  }
  return apiKey;
}
