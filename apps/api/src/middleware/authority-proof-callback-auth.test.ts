import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { canonicalize, ForbiddenError, ServiceUnavailableError } from '@stack/shared';
import {
  createAuthorityProofCallbackAuth,
  requireAuthorityProofCallback,
} from './authority-proof-callback-auth.js';

function request(overrides: Partial<FastifyRequest> = {}): FastifyRequest {
  return {
    method: 'POST',
    url: '/v1/authority/proof-callbacks/adapter-one?ignored=yes',
    params: { adapterKey: 'adapter-one' },
    headers: { authorization: 'Adapter signed-value', 'x-proof-jti': 'one' },
    body: {
      session_id: 'pcs_one',
      state_token: 'abcdefghijklmnopqrstuv',
      signed_callback: 'provider-native-result',
    },
    ...overrides,
  } as FastifyRequest;
}

describe('authority proof callback authentication', () => {
  it('binds adapter auth to the route adapter, exact path, headers and canonical body hash', async () => {
    const authenticateProofCallbackRequest = vi.fn(async () => ({
      adapterKey: 'adapter-one',
      callbackJti: 'callback-one',
      issuerIdentifier: 'https://issuer.example',
      expiresAt: new Date('2026-08-21T12:00:00Z'),
    }));
    const req = request();
    await createAuthorityProofCallbackAuth({ authenticateProofCallbackRequest })(req as never, {} as never);
    const expectedBodyHash = `sha256:${createHash('sha256')
      .update(canonicalize(req.body) ?? '')
      .digest('hex')}`;

    expect(authenticateProofCallbackRequest).toHaveBeenCalledWith('adapter-one', 'pcs_one', {
      method: 'POST',
      path: '/v1/authority/proof-callbacks/adapter-one',
      headers: { authorization: 'Adapter signed-value', 'x-proof-jti': 'one' },
      bodyHash: expectedBodyHash,
    });
    expect(req.authorityProofCallback?.callbackJti).toBe('callback-one');
  });

  it('maps adapter credential failures to one enumeration-safe 401', async () => {
    const middleware = createAuthorityProofCallbackAuth({
      authenticateProofCallbackRequest: vi.fn(async () => {
        throw new ForbiddenError('unknown issuer and secret key');
      }),
    });
    await expect(middleware(request() as never, {} as never)).rejects.toMatchObject({
      code: 'PROOF_CALLBACK_AUTH_INVALID',
      message: 'Proof callback authentication invalid',
      statusCode: 401,
    });
  });

  it('keeps infrastructure failures retriable without logging callback data', async () => {
    const logError = vi.fn();
    const req = request({
      body: {
        session_id: 'pcs_one',
        state_token: 'abcdefghijklmnopqrstuv',
        signed_callback: 'personal-number-19700101-1234',
      },
      log: { error: logError } as never,
    });
    const middleware = createAuthorityProofCallbackAuth({
      authenticateProofCallbackRequest: vi.fn(async () => {
        throw new ServiceUnavailableError('provider leaked personal-number-19700101-1234');
      }),
    });
    await expect(middleware(req as never, {} as never)).rejects.toMatchObject({
      code: 'SERVICE_UNAVAILABLE',
      message: 'Proof callback authentication temporarily unavailable',
      statusCode: 503,
    });
    expect(JSON.stringify(logError.mock.calls)).not.toContain('19700101-1234');
  });

  it('fails closed when a route reads callback context without middleware', () => {
    expect(() => requireAuthorityProofCallback(request())).toThrow(
      'Proof callback authentication invalid',
    );
  });
});
