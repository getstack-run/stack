// public inbound webhook receiver.
//
// Mounted in the PUBLIC NO-AUTH scope. Slug (in URL) + HMAC signature
// (in header, verified by per-provider extractor against the
// KMS-decrypted webhook secret) IS the auth. NO Bearer auth.
//
// Encapsulated content-type parser keeps the raw body as a Buffer so
// HMAC verification operates on the bytes the provider signed. The
// JSON re-parse happens inside the service. This mirrors the Stripe
// webhook plugin pattern at routes/webhooks.ts:11-20.
//
// Body limit: 1MB (INBOUND_WEBHOOK_BODY_LIMIT_BYTES). Per-route
// rate-limit applied via plugin config.
//
// Structural test at apps/api/src/middleware/require-public-inbound.test.ts
// asserts this file does NOT carry Bearer auth, contains the
// encapsulated parser, and emits audit + counter updates.

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { INBOUND_WEBHOOK_BODY_LIMIT_BYTES, InvalidJsonError } from '@stack/shared';
import type { Services } from '../config/services.js';
import { rawBodyBuffer } from '../lib/raw-body.js';

const SlugParams = z.object({ slug: z.string() });

export async function registerInboundReceiverRoute(app: FastifyInstance, services: Services) {
  await app.register(async function inboundPlugin(instance) {
    // Encapsulated buffer parser — HMAC verification needs the raw
    // bytes the provider signed, not a re-encoded JSON object.
    instance.removeContentTypeParser('application/json');
    instance.addContentTypeParser(
      'application/json',
      { parseAs: 'buffer' },
      (_req, body, done) => {
        done(null, body);
      },
    );

    instance.post<{ Params: { provider: string; slug: string } }>(
      '/v1/inbound/:provider/:slug',
      {
        // 1MB body cap; provider must keep inbound payloads under this.
        bodyLimit: INBOUND_WEBHOOK_BODY_LIMIT_BYTES,
        // Per-slug rate limit. The (slug, ip) bucket keeps one slug +
        // many attackers from saturating the limit; the aggregate is
        // applied in the global limiter at a higher max.
        config: {
          rateLimit: {
            max: 100,
            timeWindow: '1 minute',
            keyGenerator: (req: FastifyRequest) => {
              const params = SlugParams.safeParse(req.params);
              return `iwh:${params.success ? params.data.slug : '_'}:${req.ip ?? '_'}`;
            },
          },
        },
      },
      async (request, reply) => {
        const { provider, slug } = request.params;
        const rawBody = rawBodyBuffer(request);

        // Parse JSON for downstream extraction (HMAC was verified
        // against rawBody by the service).
        let parsedBody: unknown = null;
        if (rawBody.length > 0) {
          try {
            parsedBody = JSON.parse(rawBody.toString('utf8'));
          } catch {
            throw new InvalidJsonError();
          }
        }

        const result = await services.inboundWebhooks.receive({
          provider,
          slug,
          rawBody,
          parsedBody,
          requestPath: request.url,
          headers: request.headers as Record<string, string | string[] | undefined>,
          sourceIp: request.ip,
        });

        if (result.status === 502 || result.status === 503) reply.header('Retry-After', '5');
        return reply.status(result.status).send(result.body);
      },
    );
  });
}
