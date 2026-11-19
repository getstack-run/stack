import type { FastifyRequest } from 'fastify';
import { InvalidRequestError } from '@stack/shared';

/**
 * The request body of a route that registers its own `application/json`
 * parser with `parseAs: 'buffer'` (a payment or identity provider's webhook, the inbound webhook
 * receiver), where the sender's signature covers the exact bytes.
 *
 * Fastify types `request.body` as `unknown`. A request that reached such a
 * route without a JSON content type carries no buffer, and that is a client
 * error, not a crash.
 */
export function rawBodyBuffer(request: FastifyRequest): Buffer {
  const body: unknown = request.body;
  if (!Buffer.isBuffer(body)) {
    throw new InvalidRequestError('Request body must be sent with Content-Type: application/json');
  }
  return body;
}
