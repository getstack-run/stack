import type { FastifyReply } from 'fastify';
import { z } from 'zod';

/**
 * The one writer of an OAuth error body in this API. These endpoints are bound
 * by the wire shape of the OAuth specifications, not by the API error envelope
 * (`{ error: { code, message } }`), so they send `{ error, error_description }`
 * and nothing else:
 *
 * - RFC 6749 section 5.2: token endpoint errors (`invalid_request`,
 *   `invalid_grant`, `invalid_client`, `unsupported_grant_type`, ...).
 * - RFC 8628 sections 3.2 and 3.5: device authorization and device access
 *   token errors (`authorization_pending`, `slow_down`, `access_denied`,
 *   `expired_token`). The dashboard's device approve and deny endpoint answers
 *   in the same shape so the CLI and the approval page read one vocabulary.
 * - RFC 7591 section 3.2.2: dynamic client registration errors
 *   (`invalid_redirect_uri`, `invalid_client_metadata`).
 * - RFC 8707 section 2: `invalid_target`.
 *
 * Route code never builds this object by hand, and every other failure in the
 * API is thrown as a `StackError` for `middleware/error-handler.ts` to serialise.
 */
export function sendOAuthError(reply: FastifyReply, status: number, error: string, description?: string) {
  return reply.code(status).send({ error, ...(description ? { error_description: description } : {}) });
}

/** RFC 6749 section 3.1: request parameters are single string values. */
const OAuthParams = z.record(z.string(), z.string());

/**
 * The parameters of an OAuth request body or query string, or null when one is
 * not a single string (a repeated parameter or a JSON non-string), which the
 * caller answers with `invalid_request`. An absent body is an empty parameter set.
 */
export function readOAuthParams(raw: unknown): Record<string, string | undefined> | null {
  const parsed = OAuthParams.safeParse(raw ?? {});
  return parsed.success ? parsed.data : null;
}

/** The description sent with `invalid_request` when `readOAuthParams` returns null. */
export const OAUTH_PARAMS_NOT_STRINGS = 'request parameters must each be a single string value';
