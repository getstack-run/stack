import { createHash } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  AuthorityProofCallbackInput,
  canonicalize,
  ServiceUnavailableError,
  StackError,
} from '@stack/shared';

export interface AuthorityProofCallbackContext {
  adapterKey: string;
  callbackJti: string;
  issuerIdentifier: string;
  expiresAt: Date;
}

export interface AuthorityProofCallbackAuthenticator {
  authenticateProofCallbackRequest(adapterKey: string, sessionId: string, input: {
    method: 'POST';
    path: string;
    headers: Readonly<Record<string, string | undefined>>;
    bodyHash: string;
  }): Promise<AuthorityProofCallbackContext>;
}

function callbackAuthInvalid(): StackError {
  return new StackError('Proof callback authentication invalid', 'PROOF_CALLBACK_AUTH_INVALID', 401);
}

declare module 'fastify' {
  interface FastifyRequest {
    /** Set only after adapter auth succeeds; never derived from callback body fields. */
    authorityProofCallback?: AuthorityProofCallbackContext;
  }
}

export function createAuthorityProofCallbackAuth(
  authenticator: AuthorityProofCallbackAuthenticator,
) {
  return async function authorityProofCallbackAuth(
    request: FastifyRequest<{ Params: { adapterKey: string } }>,
    _reply: FastifyReply,
  ): Promise<void> {
    const callback = AuthorityProofCallbackInput.parse(request.body);
    const canonicalBody = canonicalize(callback);
    const bodyHash = `sha256:${createHash('sha256').update(canonicalBody ?? '').digest('hex')}`;
    const path = request.url.split('?', 1)[0] ?? request.url;
    const headers: Record<string, string | undefined> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
    }

    try {
      request.authorityProofCallback = await authenticator.authenticateProofCallbackRequest(
        request.params.adapterKey,
        callback.session_id,
        { method: 'POST', path, headers, bodyHash },
      );
    } catch (error) {
      if (error instanceof StackError && error.statusCode >= 500) {
        request.log.error(
          { error_code: error.code, status_code: error.statusCode },
          'proof callback authentication infrastructure failure',
        );
        throw new ServiceUnavailableError('Proof callback authentication temporarily unavailable');
      }
      if (!(error instanceof StackError)) {
        request.log.error({}, 'proof callback authentication infrastructure failure');
        throw new ServiceUnavailableError('Proof callback authentication temporarily unavailable');
      }
      throw callbackAuthInvalid();
    }
  };
}

export function requireAuthorityProofCallback(
  request: FastifyRequest,
): AuthorityProofCallbackContext {
  if (!request.authorityProofCallback) throw callbackAuthInvalid();
  return request.authorityProofCallback;
}
