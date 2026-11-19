import { describe, expect, it, vi } from 'vitest';
import type { FastifyRequest } from 'fastify';
import { NotFoundError, ServiceUnavailableError } from '@stack/shared';
import {
  createAuthorityReceiverAuth,
  requireAuthorityReceiver,
  type AuthorityReceiverAuthenticator,
} from './authority-receiver-auth.js';

function request(overrides: Partial<FastifyRequest> = {}): FastifyRequest {
  return {
    method: 'POST',
    url: '/v1/authority/presentation-requests?ignored=yes',
    headers: { authorization: 'STACK-Receiver signed.assertion.value' },
    body: { z: 1, a: 2 },
    ...overrides,
  } as FastifyRequest;
}

describe('authority receiver authentication', () => {
  it('binds the assertion to method, normalized path and canonical body hash', async () => {
    const authenticateReceiverRequest = vi.fn(async () => ({
      receiverId: 'rcv_one',
      keyId: 'kid_one',
      jti: 'receiver-request-one',
      expiresAt: new Date('2026-08-21T12:00:00Z'),
      payload: {},
    }));
    const middleware = createAuthorityReceiverAuth({ authenticateReceiverRequest });
    const req = request();

    await middleware(req, {} as never);

    expect(authenticateReceiverRequest).toHaveBeenCalledWith({
      compactJws: 'signed.assertion.value',
      method: 'POST',
      normalizedPath: '/v1/authority/presentation-requests',
      // sha256('{"a":2,"z":1}')
      bodyHash: 'sha256:c2985c5ba6f7d2a55e768f92490ca09388e95bc4cccb9fdf11b15f4d42f93e73',
    });
    expect(req.authorityReceiver?.receiverId).toBe('rcv_one');
  });

  it('does not stamp receiver context when verification fails', async () => {
    const authenticator: AuthorityReceiverAuthenticator = {
      authenticateReceiverRequest: vi.fn(async () => {
        throw new Error('replay backend unavailable');
      }),
    };
    const req = request();

    await expect(createAuthorityReceiverAuth(authenticator)(req, {} as never)).rejects.toMatchObject({
      code: 'SERVICE_UNAVAILABLE',
      statusCode: 503,
    });
    expect(req.authorityReceiver).toBeUndefined();
  });

  it('maps receiver/key/profile/replay domain failures to one 401', async () => {
    const middleware = createAuthorityReceiverAuth({
      authenticateReceiverRequest: vi.fn(async () => {
        throw new NotFoundError('ReceiverKey', 'secret-kid');
      }),
    });
    await expect(middleware(request(), {} as never)).rejects.toMatchObject({
      code: 'RECEIVER_AUTH_INVALID',
      message: 'Receiver authentication invalid',
      statusCode: 401,
    });
  });

  it('keeps classified infrastructure failures retriable but message-safe', async () => {
    const middleware = createAuthorityReceiverAuth({
      authenticateReceiverRequest: vi.fn(async () => {
        throw new ServiceUnavailableError('Replay backend unavailable');
      }),
    });
    await expect(middleware(request(), {} as never)).rejects.toMatchObject({
      code: 'SERVICE_UNAVAILABLE',
      message: 'Receiver authentication temporarily unavailable',
      statusCode: 503,
    });
  });

  it('never echoes or logs a normalized request from verifier failures', async () => {
    const personalNumber = '19700101-1234';
    const logError = vi.fn();
    const req = request({
      body: { normalized_request: { body: { personal_number: personalNumber } } },
      log: { error: logError } as never,
    });
    const middleware = createAuthorityReceiverAuth({
      authenticateReceiverRequest: vi.fn(async () => {
        throw new Error(`provider rejected ${personalNumber}`);
      }),
    });

    let thrown: unknown;
    try {
      await middleware(req, {} as never);
    } catch (error) {
      thrown = error;
    }
    expect(String((thrown as Error).message)).not.toContain(personalNumber);
    expect(JSON.stringify(logError.mock.calls)).not.toContain(personalNumber);
    expect(logError).toHaveBeenCalledWith({}, 'receiver authentication infrastructure failure');
  });

  it('rejects absent, wrong-scheme and malformed assertions', async () => {
    const authenticator: AuthorityReceiverAuthenticator = {
      authenticateReceiverRequest: vi.fn(),
    };
    const middleware = createAuthorityReceiverAuth(authenticator);

    for (const authorization of [undefined, 'Bearer token', 'STACK-Receiver ', 'STACK-Receiver a b']) {
      const req = request({ headers: authorization ? { authorization } : {} });
      await expect(middleware(req, {} as never)).rejects.toMatchObject({
        code: 'RECEIVER_AUTH_INVALID',
        statusCode: 401,
      });
      expect(req.authorityReceiver).toBeUndefined();
    }
    expect(authenticator.authenticateReceiverRequest).not.toHaveBeenCalled();
  });

  it('fails closed when a route reads receiver context without the middleware', () => {
    expect(() => requireAuthorityReceiver(request({ authorityReceiver: undefined }))).toThrow(
      'Receiver authentication invalid',
    );
  });
});
