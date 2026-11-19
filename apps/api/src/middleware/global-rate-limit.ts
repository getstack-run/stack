import type { FastifyRequest } from 'fastify';
import { FORWARDED_CLIENT_HEADER, verifyForwardedClient } from './forwarded-client.js';
import { preAuthRateLimitKey } from './rate-limit-key.js';

/**
 * The options of the API's global rate limit: the bucket key (`preAuthRateLimitKey`, with the
 * Console's verified client address in place of the source address when it vouches for one) and the
 * caps, 500 a minute for a bearer and 100 a minute otherwise. `forwardedClientSecret` is the
 * dashboard proxy secret of a deployment that has a Console; without it every call is keyed by its
 * source address.
 */
export function globalRateLimitOptions(
  forwardedClientSecret: string | undefined,
  now: () => number = Date.now,
) {
  return {
    keyGenerator: (req: FastifyRequest) => {
      const client = verifyForwardedClient(
        req.headers[FORWARDED_CLIENT_HEADER],
        forwardedClientSecret,
        now(),
      );
      return preAuthRateLimitKey(req.headers.authorization, req.ip, client);
    },
    max: (_req: FastifyRequest, key: string | number) =>
      (typeof key === 'string' && key.startsWith('ip:') ? 100 : 500),
    timeWindow: '1 minute',
  };
}
