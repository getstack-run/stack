import {
  TOKEN_TYPE_JWT,
  TOKEN_TYPE_STACK_PASSPORT,
  StackError,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { sendOAuthError } from './responses.js';
import { audit } from './records.js';

/**
 * RFC 8693 Token Exchange — Part of the Signed Primitive epic.
 *
 * Maps the OAuth standard token-exchange envelope onto STACK's existing
 * passport-refresh primitive. The subject_token is a STACK passport JWT;
 * the response carries a refreshed passport. Bearer-authenticated (the
 * subject_token signature IS the proof of identity) — no client_id /
 * client_secret required.
 *
 * What v1 supports:
 *   - subject_token_type: TOKEN_TYPE_JWT or TOKEN_TYPE_STACK_PASSPORT
 *   - requested_token_type: omitted, TOKEN_TYPE_JWT, or
 *     TOKEN_TYPE_STACK_PASSPORT (all yield the same passport response)
 *
 * What v1 deliberately rejects (deferred to v2):
 *   - audience/resource narrowing (returns invalid_target)
 *   - scope narrowing (returns invalid_scope)
 *   - actor_token / delegation semantics (returns invalid_request)
 *
 * Future v2 work will accept those parameters and route narrowing
 * exchanges to passport-service.delegate() with the actor identifying
 * the child agent. v1 keeps semantics tight: refresh-only.
 */
export async function handleTokenExchangeGrant(
  services: Services,
  _req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
  body: Record<string, string | undefined>,
) {
  const subject_token = body['subject_token'];
  const subject_token_type = body['subject_token_type'];
  const requested_token_type = body['requested_token_type'];
  const actor_token = body['actor_token'];
  const audienceParam = body['audience'];
  const resourceParam = body['resource'];
  const scopeParam = body['scope'];

  if (!subject_token) {
    return sendOAuthError(reply, 400, 'invalid_request', 'subject_token is required');
  }
  if (!subject_token_type) {
    return sendOAuthError(reply, 400, 'invalid_request', 'subject_token_type is required');
  }
  if (subject_token_type !== TOKEN_TYPE_JWT && subject_token_type !== TOKEN_TYPE_STACK_PASSPORT) {
    return sendOAuthError(
      reply,
      400,
      'invalid_request',
      `unsupported subject_token_type "${subject_token_type}"; accept "${TOKEN_TYPE_JWT}" or "${TOKEN_TYPE_STACK_PASSPORT}"`,
    );
  }
  if (requested_token_type && requested_token_type !== TOKEN_TYPE_JWT && requested_token_type !== TOKEN_TYPE_STACK_PASSPORT) {
    return sendOAuthError(
      reply,
      400,
      'invalid_request',
      `unsupported requested_token_type "${requested_token_type}"`,
    );
  }
  if (actor_token) {
    return sendOAuthError(
      reply,
      400,
      'invalid_request',
      'actor_token / delegation semantics not yet supported (v1 is refresh-only)',
    );
  }
  if (audienceParam || resourceParam) {
    return sendOAuthError(
      reply,
      400,
      'invalid_target',
      'audience/resource narrowing not yet supported (v1 is refresh-only; scope is preserved from the subject_token)',
    );
  }
  if (scopeParam) {
    return sendOAuthError(
      reply,
      400,
      'invalid_scope',
      'scope narrowing not yet supported (v1 is refresh-only; scope is preserved from the subject_token)',
    );
  }

  // Peek at the subject_token's claims to extract operator_id for routing.
  // We do NOT trust this value cryptographically — passport-service.refresh
  // verifies the signature internally and enforces operator_id matches the
  // token's stk.operator_id claim. A forged operator_id here hits a clean
  // ForbiddenError below.
  let operatorId: string;
  try {
    const decoded = decodeJwtUnverified(subject_token);
    const stk = decoded?.['stk'];
    if (!stk || typeof stk !== 'object') {
      return sendOAuthError(reply, 400, 'invalid_grant', 'subject_token is not a STACK passport');
    }
    const opId = (stk as Record<string, unknown>)['operator_id'];
    if (typeof opId !== 'string') {
      return sendOAuthError(reply, 400, 'invalid_grant', 'subject_token missing stk.operator_id');
    }
    operatorId = opId;
  } catch {
    return sendOAuthError(reply, 400, 'invalid_grant', 'subject_token is not a parseable JWT');
  }

  let refreshed;
  try {
    refreshed = await services.passport.refresh(operatorId, subject_token);
  } catch (err) {
    if (err instanceof StackError) {
      // Map StackError codes to RFC 6749 §5.2 OAuth error codes.
      const oauthError =
        err.code === 'PASSPORT_EXPIRED' || err.code === 'PASSPORT_REVOKED' || err.code === 'PASSPORT_INVALID'
          ? 'invalid_grant'
          : err.code === 'FORBIDDEN'
            ? 'invalid_grant'
            : 'invalid_request';
      return sendOAuthError(reply, err.statusCode === 401 ? 401 : 400, oauthError, err.message);
    }
    throw err;
  }

  const expiresInSec = Math.max(
    0,
    Math.floor((new Date(refreshed.expires_at).getTime() - Date.now()) / 1000),
  );

  // Best-effort audit. The refresh itself already wrote an audit row;
  // this second row records the OAuth-envelope wrapper for completeness.
  try {
    await audit(services, operatorId, 'oauth.token_exchange', {
      subject_token_type,
      requested_token_type: requested_token_type ?? TOKEN_TYPE_STACK_PASSPORT,
      new_jti: refreshed.jti,
    });
  } catch {
    // Audit failures are non-fatal at the OAuth surface.
  }

  // RFC 8693 §2.2.1 response shape. token_type 'N_A' is per RFC when
  // the issued token is not an OAuth access_token in the traditional
  // sense; STACK passports are bearer-presented JWTs with their own
  // audience binding, so 'N_A' is the honest answer over 'Bearer'.
  return reply.send({
    access_token: refreshed.token,
    issued_token_type: TOKEN_TYPE_STACK_PASSPORT,
    token_type: 'N_A',
    expires_in: expiresInSec,
  });
}

/**
 * Decode a JWT body without verifying. Used only to peek at the
 * operator_id claim before handing the full token to the verifier.
 * A forged token's claims are not trusted past the routing decision.
 */
function decodeJwtUnverified(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1]!, 'base64url').toString('utf8');
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}
