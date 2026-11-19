import type { FastifyRequest } from 'fastify';
import { InvalidJsonError } from '@stack/shared';

/**
 * The parser of every `application/json` body. It keeps the exact text beside the parsed value (`request.rawBody`):
 * webhook providers sign the bytes they sent, so the signature is checked over the text and never over a
 * re-serialisation. An empty body is `{}`. A body that is not JSON is the API's own 400 `INVALID_JSON`, in the error
 * envelope, never the 500 an unclassified parser error would be.
 */
export function jsonBodyParser(
  request: FastifyRequest,
  body: string | Buffer,
  done: (error: Error | null, value?: unknown) => void,
): void {
  const text = typeof body === 'string' ? body : body.toString('utf8');
  (request as unknown as { rawBody?: string }).rawBody = text;
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    done(new InvalidJsonError(), undefined);
    return;
  }
  done(null, parsed);
}
