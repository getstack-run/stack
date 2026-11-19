// Stage 10, first half: shape the provider body, check the call's cost can be
// bounded, take whatever hold the deployment puts on a call on the customer's
// own key, and reserve the fleet spend. Runs before the provider credential is
// decrypted, so a refused hold never touches the secret.
//
// This is the pipeline of Anthropic and OpenAI, which run on the customer's own
// key. OpenRouter has its own route (`./openrouter/`): any endpoint, held at a flat
// amount and charged at the cost OpenRouter reports.

import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  MICROCENTS_PER_CENT,
  OPENROUTER_HOLD_HEADER,
  OPENROUTER_HOLD_MIN_CENTS,
  calculateLlmCost,
} from '@stack/shared';
import type { FleetAdmission } from '@stack/vault';
import type { Services } from '../../config/services.js';
import type { LlmHandlerConfig } from './provider-configs.js';
import {
  BILLING_ENVELOPE_BYTES,
  countImageInputs,
  maxOutputTokens,
  prepareProviderBody,
  unsupportedVariableCost,
} from './request-shaping.js';
import type { AdmittedCall, BillingHold } from './types.js';

const MaxCostCents = z.coerce.number().int().min(OPENROUTER_HOLD_MIN_CENTS);

/** Release whatever hold the call took. Repeated releases are safe. */
export async function releaseBillingHold(
  services: Services,
  operatorId: string,
  hold: BillingHold,
): Promise<void> {
  await services.llmUsage.releaseGatewayAuthorization(operatorId, hold.authorization);
}

/**
 * The caller's own cap on what this call can cost (`X-Max-Cost-Cents`, whole
 * cents, any size: it only lowers a hold), or null when it names none. A value that
 * is not a whole number of cents is a validation error, never read as no cap.
 */
export function readCostCap(request: FastifyRequest): number | null {
  const raw = request.headers[OPENROUTER_HOLD_HEADER.toLowerCase()];
  if (raw === undefined) return null;
  return MaxCostCents.parse(Array.isArray(raw) ? raw[0] : raw);
}

export async function authorizeBillingHold(
  services: Services,
  config: LlmHandlerConfig,
  call: AdmittedCall,
  fleetAdmission: FleetAdmission | null,
  redactedBody: unknown,
): Promise<BillingHold> {
  const { body, isStreaming, operatorId } = call;
  // 10. Forward — streaming or non-streaming.
  // Audit log records what STACK ACTUALLY SENT upstream (redactedBody),
  // not what the agent submitted (body). Critical for forensic accuracy:
  // a chain-of-custody audit needs the post-redaction
  // request bytes.
  let providerBody = prepareProviderBody(
    config.provider,
    redactedBody as Record<string, unknown>,
    isStreaming,
  );
  const authorization = await services.llmUsage.authorizeGateway({
    operatorId,
    provider: config.provider,
    model: typeof body.model === 'string' ? body.model : '',
    requestBytes: Buffer.byteLength(JSON.stringify(providerBody), 'utf8') + BILLING_ENVELOPE_BYTES,
    maxOutputTokens: maxOutputTokens(body),
    completionCount: typeof body.n === 'number' ? body.n : 1,
    imageCount: countImageInputs(body),
    unsupportedCostReason: unsupportedVariableCost(body),
  });
  providerBody = prepareProviderBody(config.provider, providerBody, isStreaming);
  const requestBodyStr = JSON.stringify(providerBody);
  const hold: BillingHold = { providerBody, authorization, requestBodyStr };
  let fleetMaximumSpend: number | undefined;
  if (fleetAdmission && authorization.bounded && authorization.pricing && maxOutputTokens(body) !== null) {
    const price = authorization.pricing;
    const upper = calculateLlmCost({ ...price,
      input_cents_per_1m: Math.max(price.input_cents_per_1m, price.cached_input_cents_per_1m ?? 0, price.cache_write_cents_per_1m ?? 0),
      output_cents_per_1m: Math.max(price.output_cents_per_1m, price.internal_reasoning_cents_per_1m ?? 0),
    }, Buffer.byteLength(requestBodyStr) + BILLING_ENVELOPE_BYTES, maxOutputTokens(body)! * (typeof body.n === 'number' ? body.n : 1),
    { request_count: 1, image_count: countImageInputs(body) });
    fleetMaximumSpend = Math.ceil(upper.total_cost_microcents / MICROCENTS_PER_CENT);
  }
  // Reserve the exact operation and its maximum spend before decrypting a
  // provider credential. A rejected reservation cannot access the secret.
  try {
    if (fleetAdmission) await services.fleetAdmission.reserve(fleetAdmission, fleetMaximumSpend);
  } catch (error) {
    await releaseBillingHold(services, operatorId, hold).catch(() => {});
    throw error;
  }
  return hold;
}
