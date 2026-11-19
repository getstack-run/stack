import Fastify from 'fastify';
import { AGENT_JWT_ISSUER, InvalidApiKeyError, REDIS_COMMAND_TIMEOUT_MS } from '@stack/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRedis } from '../config/wiring/infra.js';
import { startSilentRedis } from '../test/silent-redis.js';
import { registerOperatorRoutes } from './operators.js';
import { fakeEntitlements } from '../test/entitlements.js';
import { createErrorHandler } from '../middleware/error-handler.js';
import { EngineRegistries } from '../config/registries.js';

const apps: ReturnType<typeof Fastify>[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const STAFF_OPERATOR = {
  id: 'op_staff',
  email: 'staff@example.test',
  tier: 'business',
  status: 'active',
  is_admin: true,
  is_platform_staff: true,
  is_partner: false,
  stripe_customer_id: null,
};

function agentToken(): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: AGENT_JWT_ISSUER,
    sub: 'agt_staff_child',
    jti: 'jwt_once',
    exp: Math.floor(Date.now() / 1_000) + 30,
  })).toString('base64url');
  return `${header}.${payload}.signature`;
}

function oauthLikeToken(aud: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ aud, sub: STAFF_OPERATOR.id })).toString('base64url');
  return `${header}.${payload}.signature`;
}

async function makeOAuthApp(verified: { aud: string; payload: Record<string, unknown> }) {
  const operator = { ...STAFF_OPERATOR, is_platform_staff: false };
  const services = {
    audit: { write: vi.fn(async () => {}) },
    member: {},
    entitlements: fakeEntitlements(),
    registries: new EngineRegistries(),
    operator: { getById: vi.fn(async () => operator) },
    signer: {
      verifyAccessOrSession: vi.fn(async () => ({ aud: verified.aud, sub: operator.id, payload: verified.payload })),
    },
    redis: { get: vi.fn(async () => null), set: vi.fn(async () => 'OK') },
  };
  const app = Fastify();
  apps.push(app);
  registerOperatorRoutes(app, services as never);
  await app.ready();
  return app;
}

async function makeOAuthAppWithRedis(redisGet: () => Promise<string | null>) {
  const operator = { ...STAFF_OPERATOR, is_platform_staff: false };
  const services = {
    audit: { write: vi.fn(async () => {}) },
    member: {},
    entitlements: fakeEntitlements(),
    registries: new EngineRegistries(),
    operator: { getById: vi.fn(async () => operator) },
    signer: {
      verifyAccessOrSession: vi.fn(async () => ({
        aud: 'stack:mcp',
        sub: operator.id,
        payload: { scope: 'account:read', token_family_id: 'fam_one' },
      })),
    },
    redis: { get: vi.fn(redisGet), set: vi.fn(async () => 'OK') },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerOperatorRoutes(app, services as never);
  await app.ready();
  return app;
}

async function makeApp(operatorStatus = 'active') {
  const auditWrite = vi.fn(async () => {});
  const operator = { ...STAFF_OPERATOR, status: operatorStatus };
  const services = {
    audit: { write: auditWrite },
    member: {},
    entitlements: fakeEntitlements(), operator: {
      authenticateByApiKey: vi.fn(async (token: string) => {
        if (token === 'sk_live_member') throw new InvalidApiKeyError();
        return operator;
      }),
      getById: vi.fn(async () => operator),
    },
    agent: {
      getById: vi.fn(async () => ({
        id: 'agt_staff_child',
        operator_id: STAFF_OPERATOR.id,
        status: 'active',
        passport_blocked: false,
        pubkey: 'test-public-key',
        enrolled_at: new Date(),
      })),
    },
    signer: {
      verifyAgentJwt: vi.fn(async () => ({})),
    },
    redis: {
      set: vi.fn(async () => 'OK'),
    },
  };

  const app = Fastify();
  apps.push(app);
  registerOperatorRoutes(app, services as never);
  await app.ready();
  return { app, auditWrite };
}

describe('GET /v1/auth/context', () => {
  it('returns the operator as the effective principal', async () => {
    const { app, auditWrite } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/auth/context',
      headers: { authorization: 'Bearer sk_live_operator' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      principal: { type: 'operator', id: STAFF_OPERATOR.id },
      is_platform_staff: true,
    });
    expect(auditWrite).not.toHaveBeenCalled();
  });

  it('rejects a legacy member API key', async () => {
    const { app, auditWrite } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/auth/context',
      headers: { authorization: 'Bearer sk_live_member' },
    });

    expect(response.statusCode).toBe(401);
    expect(auditWrite).not.toHaveBeenCalled();
  });

  it('does not let an agent inherit the parent operator staff flag', async () => {
    const { app, auditWrite } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/auth/context',
      headers: { authorization: `Bearer ${agentToken()}` },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      principal: { type: 'agent', id: 'agt_staff_child' },
      is_platform_staff: false,
    });
    expect(auditWrite).not.toHaveBeenCalled();
  });

  it('reports the resource signed into an OAuth MCP token', async () => {
    const app = await makeOAuthApp({
      aud: 'stack:mcp',
      payload: { scope: 'account:read', resource: 'https://mcp.getstack.run/directory' },
    });
    const response = await app.inject({
      method: 'GET',
      url: '/v1/auth/context',
      headers: { authorization: `Bearer ${oauthLikeToken('stack:mcp')}` },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      principal: { type: 'operator', id: STAFF_OPERATOR.id },
      is_platform_staff: false,
      oauth_resource: 'https://mcp.getstack.run/directory',
    });
  });

  it('omits oauth_resource for an MCP token without the claim and for API tokens', async () => {
    const legacy = await makeOAuthApp({ aud: 'stack:mcp', payload: { scope: 'account:read' } });
    const legacyResponse = await legacy.inject({
      method: 'GET',
      url: '/v1/auth/context',
      headers: { authorization: `Bearer ${oauthLikeToken('stack:mcp')}` },
    });
    expect(legacyResponse.statusCode).toBe(200);
    expect(legacyResponse.json()).not.toHaveProperty('oauth_resource');

    const api = await makeOAuthApp({
      aud: 'stack:api',
      payload: { scope: 'account:read', resource: 'https://mcp.getstack.run/directory' },
    });
    const apiResponse = await api.inject({
      method: 'GET',
      url: '/v1/auth/context',
      headers: { authorization: `Bearer ${oauthLikeToken('stack:api')}` },
    });
    expect(apiResponse.statusCode).toBe(200);
    expect(apiResponse.json()).not.toHaveProperty('oauth_resource');
  });

  it('requires authentication', async () => {
    const { app } = await makeApp();
    const response = await app.inject({ method: 'GET', url: '/v1/auth/context' });
    expect(response.statusCode).toBe(401);
  });

  it('rejects a legacy member key regardless of the parent lifecycle', async () => {
    const { app } = await makeApp('deleted');
    const response = await app.inject({
      method: 'GET',
      url: '/v1/auth/context',
      headers: { authorization: 'Bearer sk_live_member' },
    });
    expect(response.statusCode).toBe(401);
  });
});

describe('GET /v1/operators/me effective staff flag', () => {
  it('does not accept a legacy member API key', async () => {
    const { app } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/operators/me',
      headers: { authorization: 'Bearer sk_live_member' },
    });

    expect(response.statusCode).toBe(401);
  });
  it('answers 503 with Retry-After, not 500, when Redis is down while checking an OAuth token family', async () => {
    const down = new Error('Reached the max retries per request limit (which is 2).');
    down.name = 'MaxRetriesPerRequestError';
    const app = await makeOAuthAppWithRedis(async () => { throw down; });
    const silent = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const response = await app.inject({
        method: 'GET',
        url: '/v1/auth/context',
        headers: { authorization: `Bearer ${oauthLikeToken('stack:mcp')}` },
      });
      expect(response.statusCode).toBe(503);
      expect(response.headers['retry-after']).toBe('5');
      expect(response.json().error.code).toBe('SERVICE_UNAVAILABLE');
    } finally { silent.mockRestore(); }
  });

  it('answers 503 with Retry-After, not a hang, when Redis accepts the socket and never answers', async () => {
    // A Redis that accepts the socket and never answers: the connection is open, so the client never reconnects and only the command timeout ends the wait.
    const silent = await startSilentRedis();
    const redis = await createRedis(silent.url);
    const app = await makeOAuthAppWithRedis(() => redis.get('oauth_family_revoked:fam_one'));
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const started = Date.now();
      const response = await app.inject({
        method: 'GET',
        url: '/v1/auth/context',
        headers: { authorization: `Bearer ${oauthLikeToken('stack:mcp')}` },
      });
      expect(response.statusCode).toBe(503);
      expect(response.headers['retry-after']).toBe('5');
      expect(response.json().error.code).toBe('SERVICE_UNAVAILABLE');
      expect(Date.now() - started).toBeLessThan(REDIS_COMMAND_TIMEOUT_MS + 3_000);
    } finally {
      quiet.mockRestore();
      redis.disconnect();
      await silent.stop();
    }
  }, 20_000);

  it('still answers 401 for a revoked OAuth token family', async () => {
    const app = await makeOAuthAppWithRedis(async () => '1');
    const response = await app.inject({
      method: 'GET',
      url: '/v1/auth/context',
      headers: { authorization: `Bearer ${oauthLikeToken('stack:mcp')}` },
    });
    expect(response.statusCode).toBe(401);
  });
});
