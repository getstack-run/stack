import { afterEach, describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import type { Services } from '../config/services.js';
import { createErrorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/meter.js', () => ({ enforceOverage: vi.fn(async () => undefined) }));

const { registerWorkloadRoutes } = await import('./workload.js');
const { registerWorkloadWitRoutes } = await import('./workload-wit.js');

/**
 * a workload-attested Passport (SPIFFE JWT-SVID or WIMSE WIT) is
 * issued for exactly one live Mission named in the request body. The body is
 * checked before any rate-limit, trust-domain or cryptographic work, and the
 * Mission id reaches PassportService.issue unchanged, where the live-Mission
 * rules apply.
 */

function unsignedJwt(claims: Record<string, unknown>): string {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'EdDSA', kid: 'k' })}.${part(claims)}.c2ln`;
}

function servicesStub() {
  const issue = vi.fn(async () => ({ token: 'tok', jti: 'ppt_new', expires_at: new Date(Date.now() + 600_000) }));
  const notAfter = Math.floor(Date.now() / 1000) + 600;
  const services = {
    redis: { incr: vi.fn(async () => 1), expire: vi.fn(async () => 1) },
    spiffeTrustDomainRepo: {
      findActiveByTrustDomain: vi.fn(async () => [{
        id: 'std_1', operator_id: 'op_wl', trust_domain: 'wl.example', jwks_uri: 'https://wl.example/jwks',
        audience: 'aud', jwks_cache_ttl_seconds: 300, jwks_cached_jwks_json: null,
        spiffe_id_mapping_policy_json: { 'spiffe://wl.example/orders': { agent_id: 'agt_wl' } },
      }]),
    },
    workloadProviderRegistry: {
      get: () => ({
        acceptSvid: vi.fn(async () => ({
          not_after: notAfter, spiffe_id: 'spiffe://wl.example/orders', trust_domain: 'wl.example',
          attestation_claim: { type: 'svid_attestation' },
        })),
      }),
    },
    wimseIssuerRepo: {
      findActiveByIssuerUri: vi.fn(async () => [{
        id: 'wis_1', operator_id: 'op_wl', issuer_uri: 'https://issuer.example', jwks_uri: 'https://issuer.example/jwks',
        audience: 'aud', jwks_cache_ttl_seconds: 300, jwks_cached_jwks_json: null,
        workload_id_mapping_policy_json: { 'wimse://orders': { agent_id: 'agt_wl' } },
      }]),
    },
    wimseWorkloadProvider: {
      acceptWit: vi.fn(async () => ({
        not_after: notAfter, workload_id: 'wimse://orders', attestation_claim: { type: 'workload_attestation' },
      })),
    },
    passport: { issue },
    claimRegistry: { assertRegistrable: vi.fn(), registerClaim: vi.fn(async () => ({ claimId: 'pc_attest' })) },
    audit: { write: vi.fn(async () => undefined) },
  };
  return { services: services as unknown as Services, issue };
}

const ROUTES = [
  {
    name: 'SPIFFE /v1/workload/passport',
    url: '/v1/workload/passport',
    register: registerWorkloadRoutes,
    token: unsignedJwt({ sub: 'spiffe://wl.example/orders' }),
  },
  {
    name: 'WIMSE /v1/workload/wit',
    url: '/v1/workload/wit',
    register: registerWorkloadWitRoutes,
    token: unsignedJwt({ iss: 'https://issuer.example', sub: 'wimse://orders' }),
  },
] as const;

describe.each(ROUTES)('$name requires a Mission', (route) => {
  const apps: Array<ReturnType<typeof Fastify>> = [];
  afterEach(async () => {
    while (apps.length) await apps.pop()!.close();
  });

  async function build() {
    const stub = servicesStub();
    const app = Fastify();
    app.setErrorHandler(createErrorHandler());
    apps.push(app);
    route.register(app, stub.services);
    await app.ready();
    return { app, ...stub };
  }

  it('answers 400 MISSION_REQUIRED without a body, before any other work', async () => {
    const { app, issue, services } = await build();
    const res = await app.inject({ method: 'POST', url: route.url, headers: { authorization: `Bearer ${route.token}` } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('MISSION_REQUIRED');
    expect(issue).not.toHaveBeenCalled();
    expect((services as unknown as { redis: { incr: ReturnType<typeof vi.fn> } }).redis.incr).not.toHaveBeenCalled();
  });

  it('answers 400 for a malformed or extra-field body', async () => {
    const { app, issue } = await build();
    for (const payload of [{ mission_id: 'not-a-mission' }, { mission_id: 'ms_ok', extra: true }, { mission_ids: ['ms_ok'] }]) {
      const res = await app.inject({
        method: 'POST', url: route.url, headers: { authorization: `Bearer ${route.token}` }, payload,
      });
      expect(res.statusCode, JSON.stringify(payload)).toBe(400);
      expect(res.json().error.code).toBe('MISSION_REQUIRED');
    }
    expect(issue).not.toHaveBeenCalled();
  });

  it('binds the issued Passport to exactly the named Mission', async () => {
    const { app, issue } = await build();
    const res = await app.inject({
      method: 'POST', url: route.url, headers: { authorization: `Bearer ${route.token}` },
      payload: { mission_id: 'ms_workload' },
    });
    expect(res.statusCode).toBe(201);
    expect(issue).toHaveBeenCalledTimes(1);
    expect(issue.mock.calls[0]).toEqual(['op_wl', expect.objectContaining({ agent_id: 'agt_wl', mission_ids: ['ms_workload'] })]);
  });
});
