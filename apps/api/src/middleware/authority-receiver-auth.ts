import { createHash } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { canonicalize, ServiceUnavailableError, StackError } from '@stack/shared';

export interface AuthorityReceiverContext {
  receiverId: string;
  keyId: string;
  jti: string;
  expiresAt: Date;
  payload: Record<string, unknown>;
}

export interface AuthorityReceiverAuthenticator {
  authenticateReceiverRequest(input: {
    compactJws: string;
    method: string;
    normalizedPath: string;
    bodyHash: string;
  }): Promise<AuthorityReceiverContext>;
}

function receiverAuthInvalid(): StackError {
  // Uniform response: key/profile/replay/expiry failures must not become an
  // enumeration oracle for registered receivers.
  return new StackError('Receiver authentication invalid', 'RECEIVER_AUTH_INVALID', 401);
}

declare module 'fastify' {
  interface FastifyRequest {
    /** Set only after a receiver assertion has been verified and replay-burned. */
    authorityReceiver?: AuthorityReceiverContext;
  }
}

/**
 * STACK direct-post JWT v1 authentication is deliberately separate from STACK's
 * operator/agent Bearer middleware. A receiver assertion is a short-lived,
 * one-use signed request bound to the exact method, path and canonical body.
 * The service verifies the pinned receiver key/profile and atomically burns
 * the assertion jti before returning this context.
 */
export function createAuthorityReceiverAuth(
  authenticator: AuthorityReceiverAuthenticator,
) {
  return async function authorityReceiverAuth(
    request: FastifyRequest,
    _reply: FastifyReply,
  ): Promise<void> {
    const authorization = request.headers.authorization;
    const prefix = 'STACK-Receiver ';
    if (!authorization?.startsWith(prefix)) {
      throw receiverAuthInvalid();
    }

    const assertion = authorization.slice(prefix.length).trim();
    if (!assertion || assertion.includes(' ')) {
      throw receiverAuthInvalid();
    }

    const canonicalBody = request.body === undefined ? '' : canonicalize(request.body);
    const bodySha256 = createHash('sha256').update(canonicalBody ?? '').digest('hex');
    const path = request.url.split('?', 1)[0] ?? request.url;

    // Assign only after every cryptographic, lifecycle and replay check passes.
    // A failed verifier must never leave a partially-authenticated receiver on
    // the request object for a later hook or error handler to mistake as valid.
    let context: AuthorityReceiverContext;
    try {
      context = await authenticator.authenticateReceiverRequest({
        compactJws: assertion,
        method: request.method,
        normalizedPath: path,
        bodyHash: `sha256:${bodySha256}`,
      });
    } catch (error) {
      // All known credential failures are deliberately indistinguishable.
      // Infrastructure failures remain retriable and must never be mislabeled
      // as a bad receiver key (same posture as operator auth).
      if (error instanceof StackError) {
        if (error.statusCode >= 500) {
          request.log?.error(
            { error_code: error.code, status_code: error.statusCode },
            'receiver authentication infrastructure failure',
          );
          throw new ServiceUnavailableError('Receiver authentication temporarily unavailable');
        }
        throw receiverAuthInvalid();
      }
      // Never log the raw verifier error. It may wrap a provider response or
      // normalized request containing the exact private facts this protocol
      // exists to keep off ordinary logs.
      request.log?.error({}, 'receiver authentication infrastructure failure');
      throw new ServiceUnavailableError('Receiver authentication temporarily unavailable');
    }
    request.authorityReceiver = context;
  };
}

export function requireAuthorityReceiver(request: FastifyRequest): AuthorityReceiverContext {
  if (!request.authorityReceiver) {
    throw receiverAuthInvalid();
  }
  return request.authorityReceiver;
}
