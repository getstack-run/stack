import type { FastifyReply, FastifyRequest } from 'fastify';

/**
 * The API's not-found handler. Fastify's default logs `Route GET:/full/url not
 * found` and echoes the full URL, query included. A request that matched no
 * route can still carry a one-time token (a connect link's page path, a call
 * relay token) or a credential in its query string, so neither this handler's
 * log line nor its answer carries them.
 */

/** A path segment that follows one of these names is a token, whatever it looks like. */
const TOKEN_FOLLOWS = new Set(['connect-links', 'relay']);
/** A long run of URL-safe characters is token-shaped even under an unknown prefix. */
const TOKEN_SHAPED = /^[A-Za-z0-9_-]{24,}$/;
const REDACTED = '[redacted]';

/** The path of a request URL with the query dropped and every token-bearing segment redacted. */
export function redactPathForLog(rawUrl: string | undefined): string {
  const path = (rawUrl ?? '').split(/[?#]/, 1)[0] ?? '';
  const segments = path.split('/');
  let previous = '';
  for (let i = 0; i < segments.length; i += 1) {
    const segment = segments[i]!;
    const afterToken =
      TOKEN_FOLLOWS.has(previous) ||
      (previous === 'link' && segments[i - 2] === 'connect') ||
      // A drive share link is a signed token in the path (it contains dots).
      (previous === 'links' && segments[i - 2] === 'drive') ||
      // A drive upload URL is a one-time token in the path.
      (previous === 'uploads' && segments[i - 2] === 'drive');
    if (segment !== '' && (afterToken || TOKEN_SHAPED.test(segment))) segments[i] = REDACTED;
    previous = segment;
  }
  return segments.join('/') || '/';
}

export function notFoundHandler(request: FastifyRequest, reply: FastifyReply) {
  const path = redactPathForLog(request.raw.url);
  request.log.info({ method: request.method, path }, 'Route not found');
  // The error envelope every other answer uses (spec/rest-api): a client reads `error.code`, not a Fastify body.
  return reply.code(404).send({
    error: {
      code: 'NOT_FOUND',
      message: `Route ${request.method}:${path} not found`,
    },
  });
}
