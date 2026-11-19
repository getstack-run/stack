import { describe, it, expect, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { registerAgentJwksRoute } from './agent-jwks.js';
import { createErrorHandler } from '../middleware/error-handler.js';

/**
 * Minimal fake AgentService — only the surface the JWKS route uses
 * (`getPublicSigningInfo`). Real service has dozens of methods; the
 * route deliberately depends on only one.
 */
function makeFakeAgent(opts: {
  id: string;
  hasPubkey?: boolean;
  enrolled?: Date | null;
  keyMode?: string;
}) {
  return {
    getPublicSigningInfo: async (id: string) => {
      if (id !== opts.id) return null;
      if (!opts.hasPubkey) return null;
      // Use `'enrolled' in opts` so a deliberate null vs unset distinction
      // is preserved (null = test wants to assert null-handling path).
      const enrolled_at =
        'enrolled' in opts ? opts.enrolled : new Date(1778600000000);
      return {
        kid: `agent:${id}:v1`,
        pubkey: { kty: 'OKP', crv: 'Ed25519', x: 'TEST_PUBLIC_KEY_X' },
        enrolled_at,
        key_mode: opts.keyMode ?? 'stack_managed',
      };
    },
  };
}

async function makeApp(services: { agent: ReturnType<typeof makeFakeAgent> }): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  app.setErrorHandler(createErrorHandler());
  registerAgentJwksRoute(app, services as never);
  await app.ready();
  return app;
}

describe('GET /v1/agents/:id/.well-known/jwks.json', () => {
  let app: FastifyInstance;

  afterEach(async () => {
    if (app) await app.close();
  });

  it('returns a valid JWKS for a provisioned agent', async () => {
    const agent = makeFakeAgent({ id: 'ag_xyz', hasPubkey: true });
    app = await makeApp({ agent });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents/ag_xyz/.well-known/jwks.json',
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { keys: Array<Record<string, unknown>> };
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'TEST_PUBLIC_KEY_X',
      kid: 'agent:ag_xyz:v1',
      alg: 'EdDSA',
      use: 'sig',
      not_before: 1778600000000,
      not_after: null,
    });
  });

  it('returns 404 for an unknown agent_id', async () => {
    const agent = makeFakeAgent({ id: 'ag_existing', hasPubkey: true });
    app = await makeApp({ agent });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents/ag_nope/.well-known/jwks.json',
    });

    expect(res.statusCode).toBe(404);
    const body = res.json() as { error: { code: string; message: string; details: { agent_id: string } } };
    expect(body.error.code).toBe('SIGNING_KEY_UNAVAILABLE');
    expect(body.error.message).toMatch(/no signing key available/i);
    expect(body.error.details.agent_id).toBe('ag_nope');
  });

  it('returns 404 for an existing agent that has no pubkey provisioned', async () => {
    // hasPubkey: false → getPublicSigningInfo returns null even though
    // the agent_id matches. Covers the un-provisioned stack_managed
    // case and the pre-SDK-enrollment customer_managed case.
    const agent = makeFakeAgent({ id: 'ag_unenrolled', hasPubkey: false });
    app = await makeApp({ agent });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents/ag_unenrolled/.well-known/jwks.json',
    });

    expect(res.statusCode).toBe(404);
  });

  it('does NOT require authentication (the route is mounted public)', async () => {
    // The fake AgentService has no auth-check method; if the route
    // somehow tried to authenticate, the request would fail differently
    // than 200/404. This test asserts the no-auth posture by
    // confirming a clean 200 with no Authorization header in the
    // request.
    const agent = makeFakeAgent({ id: 'ag_xyz', hasPubkey: true });
    app = await makeApp({ agent });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents/ag_xyz/.well-known/jwks.json',
      // No Authorization header.
    });

    expect(res.statusCode).toBe(200);
  });

  it('exposes only public-safe fields (no operator_id, no name, no PII)', async () => {
    const agent = makeFakeAgent({ id: 'ag_xyz', hasPubkey: true });
    app = await makeApp({ agent });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents/ag_xyz/.well-known/jwks.json',
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { keys: Array<Record<string, unknown>> };
    const key = body.keys[0]!;

    // No leak of agent-level metadata into the JWKS response.
    expect(key).not.toHaveProperty('operator_id');
    expect(key).not.toHaveProperty('name');
    expect(key).not.toHaveProperty('description');
    expect(key).not.toHaveProperty('key_mode');
    // Private key field must not appear under any name.
    expect(key).not.toHaveProperty('d');
    expect(key).not.toHaveProperty('signing_key_encrypted');
  });

  it('returns not_before as null when enrolled_at is null', async () => {
    // An edge case — the agent was provisioned without enrolled_at
    // somehow (shouldn't happen under the CHECK constraint, but the
    // route should handle null gracefully).
    const agent = makeFakeAgent({ id: 'ag_xyz', hasPubkey: true, enrolled: null });
    app = await makeApp({ agent });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents/ag_xyz/.well-known/jwks.json',
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { keys: Array<Record<string, unknown>> };
    expect(body.keys[0]).toMatchObject({
      not_before: null,
      not_after: null,
    });
  });
});
