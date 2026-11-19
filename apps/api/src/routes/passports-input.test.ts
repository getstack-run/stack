import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Services } from '../config/services.js';
import { PassportRevokeFlagsError } from '@stack/vault';
import { createErrorHandler } from '../middleware/error-handler.js';
import { registerPassportRoutes } from './passports.js';

// The real auth middleware needs the full service graph; these tests are about
// how the routes read their input, so authenticate as a fixed operator.
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: { operatorId: string }) => {
    request.operatorId = 'op_owner';
  },
}));

const apps: Array<ReturnType<typeof Fastify>> = [];
afterEach(async () => Promise.all(apps.splice(0).map((app) => app.close())));

function harness() {
  const claims = { jti: 'ppt_1', sub: 'agt_1', exp: Math.floor(Date.now() / 1000) + 600, stk: { operator_id: 'op_owner', agent_id: 'agt_1' } };
  const passport = {
    verify: vi.fn(async (_token: string, _options: { service_id?: string }) => claims),
    revoke: vi.fn(async (_input: { jti: string; operatorId: string; reason: string }) => ({ cascaded: [] as string[] })),
    revokeAllForAgent: vi.fn(async (_agentId: string, _reason: string) => ({ revoked_count: 2 })),
    revokeBySession: vi.fn(async (_operatorId: string, _sessionId: string, _reason: string) => ({ revoked_count: 3 })),
    listActive: vi.fn(async (_operatorId: string, _filter: { agent_id?: string; session_id?: string }) => []),
  };
  const services = {
    passport,
    agent: { getById: vi.fn(async () => ({})) },
    authority: { listPassportAuthorityRefsForPassports: vi.fn(async () => new Map()) },
    audit: { write: vi.fn(async () => undefined) },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerPassportRoutes(app, services as unknown as Services);
  return { app, passport, audit: services.audit };
}

function post(app: ReturnType<typeof Fastify>, url: string, payload?: unknown) {
  return app.inject({
    method: 'POST',
    url,
    ...(payload === undefined ? {} : { headers: { 'content-type': 'application/json' }, payload: JSON.stringify(payload) }),
  });
}

describe('POST /v1/passports/verify body', () => {
  it.each([
    ['no body', undefined],
    ['a missing token', {}],
    ['a non-string token', { token: 5 }],
    ['a non-string service_id', { token: 't', service_id: 7 }],
  ])('answers %s with 400 VALIDATION_ERROR', async (_name, payload) => {
    const { app, passport } = harness();
    const response = await post(app, '/v1/passports/verify', payload);
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
    expect(passport.verify).not.toHaveBeenCalled();
  });

  it.each([
    ['without service_id', { token: 'tok' }, undefined],
    ['with service_id', { token: 'tok', service_id: 'svc_slack' }, 'svc_slack'],
    ['with a null service_id', { token: 'tok', service_id: null }, undefined],
  ])('verifies %s', async (_name, payload, serviceId) => {
    const { app, passport } = harness();
    const response = await post(app, '/v1/passports/verify', payload);
    expect(response.statusCode).toBe(200);
    expect(passport.verify).toHaveBeenCalledWith('tok', { service_id: serviceId });
  });
});

describe('POST /v1/passports/revoke body', () => {
  it.each([
    ['no body', undefined],
    ['a missing jti', { reason: 'r' }],
    ['an empty jti', { jti: '' }],
    ['a non-string jti', { jti: 3 }],
    ['a non-string reason', { jti: 'ppt_1', reason: 3 }],
  ])('answers %s with 400 VALIDATION_ERROR', async (_name, payload) => {
    const { app, passport } = harness();
    const response = await post(app, '/v1/passports/revoke', payload);
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
    expect(passport.revoke).not.toHaveBeenCalled();
  });

  it.each([
    ['a reason', { jti: 'ppt_1', reason: 'compromised' }, 'compromised'],
    ['no reason', { jti: 'ppt_1' }, 'Revoked by operator'],
    ['a null reason (Python SDK)', { jti: 'ppt_1', reason: null }, 'Revoked by operator'],
  ])('revokes with %s', async (_name, payload, reason) => {
    const { app, passport } = harness();
    const response = await post(app, '/v1/passports/revoke', payload);
    expect(response.statusCode).toBe(200);
    expect(passport.revoke).toHaveBeenCalledWith({ jti: 'ppt_1', operatorId: 'op_owner', reason });
  });
});

describe('GET /v1/passports/active query', () => {
  it('answers a repeated agent_id with 400 VALIDATION_ERROR', async () => {
    const { app, passport } = harness();
    const response = await app.inject({ method: 'GET', url: '/v1/passports/active?agent_id=a&agent_id=b' });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
    expect(passport.listActive).not.toHaveBeenCalled();
  });

  it('passes the filters through and ignores unknown parameters', async () => {
    const { app, passport } = harness();
    const response = await app.inject({ method: 'GET', url: '/v1/passports/active?agent_id=agt_1&session_id=ses_1&other=1' });
    expect(response.statusCode).toBe(200);
    expect(passport.listActive).toHaveBeenCalledWith('op_owner', { agent_id: 'agt_1', session_id: 'ses_1' });
  });

  it('lists everything without filters', async () => {
    const { app, passport } = harness();
    await app.inject({ method: 'GET', url: '/v1/passports/active' });
    expect(passport.listActive).toHaveBeenCalledWith('op_owner', { agent_id: undefined, session_id: undefined });
  });
});

describe('POST /v1/passports/revoke when a revocation flag cannot be written', () => {
  it('writes the audit rows of the revoke that committed, then answers 503, because a retry has no cascade left to report', async () => {
    const { app, passport, audit } = harness();
    passport.revoke.mockRejectedValueOnce(new PassportRevokeFlagsError('Revocation flags temporarily unavailable, please retry', {
      operator_id: 'op_owner',
      cascaded: ['ppt_child'],
      revoked_claims: [{ claim_id: 'pc_1', claim_hash: 'hash_1' }],
    }));
    const response = await post(app, '/v1/passports/revoke', { jti: 'ppt_1' });
    expect(response.statusCode).toBe(503);
    expect(response.json().error.code).toBe('SERVICE_UNAVAILABLE');
    const actions = audit.write.mock.calls.map((call) => (call as unknown as [{ action: string }])[0].action);
    expect(actions).toEqual(['passport.revoke', 'passport.revoke_cascade', 'claim.revoke']);
  });

  it('answers any other failure as it always did, with no audit row', async () => {
    const { app, passport, audit } = harness();
    passport.revoke.mockRejectedValueOnce(new Error('the database is not answering'));
    const response = await post(app, '/v1/passports/revoke', { jti: 'ppt_1' });
    expect(response.statusCode).toBe(500);
    expect(audit.write).not.toHaveBeenCalled();
  });
});

describe('bulk revoke reason bodies', () => {
  it.each([
    ['/v1/passports/revoke-agent/agt_1'],
    ['/v1/passports/revoke-session/ses_1'],
  ])('%s answers a non-string reason with 400 VALIDATION_ERROR', async (url) => {
    const { app, passport } = harness();
    const response = await post(app, url, { reason: { nested: true } });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
    expect(passport.revokeAllForAgent).not.toHaveBeenCalled();
    expect(passport.revokeBySession).not.toHaveBeenCalled();
  });

  it.each([
    ['no body', undefined, 'Bulk revoke by operator'],
    ['an empty object', {}, 'Bulk revoke by operator'],
    ['a null reason (Python SDK)', { reason: null }, 'Bulk revoke by operator'],
    ['a reason', { reason: 'rotated' }, 'rotated'],
  ])('revoke-agent accepts %s', async (_name, payload, reason) => {
    const { app, passport } = harness();
    const response = await post(app, '/v1/passports/revoke-agent/agt_1', payload);
    expect(response.statusCode).toBe(200);
    expect(passport.revokeAllForAgent).toHaveBeenCalledWith('agt_1', reason);
  });

  it.each([
    ['no body', undefined, 'Session revoked by operator'],
    ['a null reason (Python SDK)', { reason: null }, 'Session revoked by operator'],
    ['a reason', { reason: 'rotated' }, 'rotated'],
  ])('revoke-session accepts %s', async (_name, payload, reason) => {
    const { app, passport } = harness();
    const response = await post(app, '/v1/passports/revoke-session/ses_1', payload);
    expect(response.statusCode).toBe(200);
    expect(passport.revokeBySession).toHaveBeenCalledWith('op_owner', 'ses_1', reason);
  });
});
