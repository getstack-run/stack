import { afterEach, describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import { SpiffeValidationError, WimseValidationError } from '@stack/vault';
import type { Services } from '../config/services.js';
import { createErrorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/meter.js', () => ({ enforceOverage: vi.fn(async () => undefined) }));

const { registerWorkloadRoutes } = await import('./workload.js');
const { registerWorkloadWitRoutes } = await import('./workload-wit.js');

/**
 * Every refusal from the workload attestation routes is a thrown StackError the
 * central handler serialises into the API error envelope: a stable `code`, the
 * HTTP status the route always used, and the exhausted rate-limit bucket in
 * `details.scope`.
 */

function unsignedJwt(claims: Record<string, unknown>): string {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'EdDSA', kid: 'k' })}.${part(claims)}.c2ln`;
}

interface Overrides {
  redisIncr?: () => Promise<number>;
  spiffeConfigs?: unknown[];
  wimseConfigs?: unknown[];
  spiffeProvider?: unknown;
  witAccept?: () => Promise<unknown>;
  svidAccept?: () => Promise<unknown>;
}

function servicesStub(overrides: Overrides = {}) {
  const notAfter = Math.floor(Date.now() / 1000) + 600;
  const spiffeConfig = {
    id: 'std_1', operator_id: 'op_wl', trust_domain: 'wl.example', jwks_uri: 'https://wl.example/jwks',
    audience: 'aud', jwks_cache_ttl_seconds: 300, jwks_cached_jwks_json: null,
    spiffe_id_mapping_policy_json: { 'spiffe://wl.example/orders': { agent_id: 'agt_wl' } },
  };
  const wimseConfig = {
    id: 'wis_1', operator_id: 'op_wl', issuer_uri: 'https://issuer.example', jwks_uri: 'https://issuer.example/jwks',
    audience: 'aud', jwks_cache_ttl_seconds: 300, jwks_cached_jwks_json: null,
    workload_id_mapping_policy_json: { 'wimse://orders': { agent_id: 'agt_wl' } },
  };
  return {
    redis: { incr: overrides.redisIncr ?? vi.fn(async () => 1), expire: vi.fn(async () => 1) },
    spiffeTrustDomainRepo: { findActiveByTrustDomain: vi.fn(async () => overrides.spiffeConfigs ?? [spiffeConfig]) },
    workloadProviderRegistry: {
      get: () => overrides.spiffeProvider === null ? undefined : {
        acceptSvid: overrides.svidAccept ?? vi.fn(async () => ({
          not_after: notAfter, spiffe_id: 'spiffe://wl.example/orders', trust_domain: 'wl.example', attestation_claim: {},
        })),
      },
    },
    wimseIssuerRepo: { findActiveByIssuerUri: vi.fn(async () => overrides.wimseConfigs ?? [wimseConfig]) },
    wimseWorkloadProvider: {
      acceptWit: overrides.witAccept ?? vi.fn(async () => ({ not_after: notAfter, workload_id: 'wimse://orders', attestation_claim: {} })),
    },
    passport: { issue: vi.fn(async () => ({ token: 'tok', jti: 'ppt_new', expires_at: new Date(Date.now() + 600_000) })) },
    claimRegistry: { registerClaim: vi.fn(async () => ({ claimId: 'pc_attest' })) },
    audit: { write: vi.fn(async () => undefined) },
  } as unknown as Services;
}

const ROUTES = [
  {
    name: 'SPIFFE /v1/workload/passport',
    url: '/v1/workload/passport',
    register: registerWorkloadRoutes,
    token: unsignedJwt({ sub: 'spiffe://wl.example/orders' }),
    unmappedToken: unsignedJwt({ sub: 'spiffe://wl.example/other' }),
    unconfiguredConfigs: { spiffeConfigs: [] as unknown[] },
    validationError: (code: 'expired' | 'jwks_unavailable' | 'verify_failed') => ({
      svidAccept: async () => { throw new SpiffeValidationError(code, `svid ${code}`); },
    }),
    expiringSoon: { svidAccept: async () => ({
      not_after: Math.floor(Date.now() / 1000) + 10, spiffe_id: 'spiffe://wl.example/orders', trust_domain: 'wl.example', attestation_claim: {},
    }) },
    rateScope: 'trust_domain',
  },
  {
    name: 'WIMSE /v1/workload/wit',
    url: '/v1/workload/wit',
    register: registerWorkloadWitRoutes,
    token: unsignedJwt({ iss: 'https://issuer.example', sub: 'wimse://orders' }),
    unmappedToken: unsignedJwt({ iss: 'https://issuer.example', sub: 'wimse://other' }),
    unconfiguredConfigs: { wimseConfigs: [] as unknown[] },
    validationError: (code: 'expired' | 'jwks_unavailable' | 'verify_failed') => ({
      witAccept: async () => { throw new WimseValidationError(code, `wit ${code}`); },
    }),
    expiringSoon: { witAccept: async () => ({
      not_after: Math.floor(Date.now() / 1000) + 10, workload_id: 'wimse://orders', attestation_claim: {},
    }) },
    rateScope: 'issuer',
  },
] as const;

describe.each(ROUTES)('$name errors', (route) => {
  const apps: Array<ReturnType<typeof Fastify>> = [];
  afterEach(async () => {
    while (apps.length) await apps.pop()!.close();
  });

  async function post(overrides: Overrides, headers: Record<string, string>, payload: unknown = { mission_id: 'ms_workload' }) {
    const app = Fastify();
    app.setErrorHandler(createErrorHandler());
    apps.push(app);
    route.register(app, servicesStub(overrides));
    await app.ready();
    return app.inject({ method: 'POST', url: route.url, headers, payload: payload as object });
  }
  const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

  it('answers a missing bearer with 401 UNAUTHORIZED', async () => {
    const res = await post({}, {});
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe('UNAUTHORIZED');
  });

  it('answers an unparseable token with 400 WORKLOAD_TOKEN_MALFORMED', async () => {
    const res = await post({}, bearer('not-a-jwt'));
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('WORKLOAD_TOKEN_MALFORMED');
  });

  it('answers an exhausted per-IP bucket with 429 RATE_LIMITED naming the scope', async () => {
    const res = await post({ redisIncr: async () => 1_000_000 }, bearer(route.token));
    expect(res.statusCode).toBe(429);
    expect(res.json().error).toMatchObject({ code: 'RATE_LIMITED', details: { scope: 'ip' } });
  });

  it('answers an exhausted second bucket with 429 RATE_LIMITED naming that scope', async () => {
    let calls = 0;
    const res = await post({ redisIncr: async () => (++calls === 1 ? 1 : 1_000_000) }, bearer(route.token));
    expect(res.statusCode).toBe(429);
    expect(res.json().error).toMatchObject({ code: 'RATE_LIMITED', details: { scope: route.rateScope } });
  });

  it('answers an unconfigured issuer with 401 WORKLOAD_ISSUER_NOT_CONFIGURED', async () => {
    const res = await post(route.unconfiguredConfigs, bearer(route.token));
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe('WORKLOAD_ISSUER_NOT_CONFIGURED');
  });

  it('answers an unmapped workload with 403 WORKLOAD_IDENTITY_NOT_MAPPED', async () => {
    const res = await post({}, bearer(route.unmappedToken));
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('WORKLOAD_IDENTITY_NOT_MAPPED');
  });

  it.each([
    ['expired', 401, 'WORKLOAD_TOKEN_EXPIRED'],
    ['jwks_unavailable', 503, 'WORKLOAD_JWKS_UNAVAILABLE'],
    ['verify_failed', 400, 'WORKLOAD_VERIFY_FAILED'],
  ] as const)('maps the validator code %s to %i %s', async (validatorCode, status, code) => {
    const res = await post(route.validationError(validatorCode), bearer(route.token));
    expect(res.statusCode).toBe(status);
    expect(res.json().error.code).toBe(code);
  });

  it('refuses a token that expires too soon with 400 WORKLOAD_TOKEN_TOO_CLOSE_TO_EXPIRY', async () => {
    const res = await post(route.expiringSoon, bearer(route.token));
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('WORKLOAD_TOKEN_TOO_CLOSE_TO_EXPIRY');
  });
});

describe('SPIFFE-only and WIMSE-only refusals', () => {
  it('answers a subject that is not a SPIFFE ID with 400 WORKLOAD_SPIFFE_ID_INVALID', async () => {
    const app = Fastify();
    app.setErrorHandler(createErrorHandler());
    registerWorkloadRoutes(app, servicesStub());
    const res = await app.inject({
      method: 'POST', url: '/v1/workload/passport',
      headers: { authorization: `Bearer ${unsignedJwt({ sub: 'urn:not-spiffe' })}` }, payload: { mission_id: 'ms_workload' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('WORKLOAD_SPIFFE_ID_INVALID');
    await app.close();
  });

  it('answers a missing SPIFFE provider with 500 WORKLOAD_PROVIDER_UNAVAILABLE', async () => {
    const app = Fastify();
    app.setErrorHandler(createErrorHandler());
    registerWorkloadRoutes(app, servicesStub({ spiffeProvider: null }));
    const res = await app.inject({
      method: 'POST', url: '/v1/workload/passport',
      headers: { authorization: `Bearer ${unsignedJwt({ sub: 'spiffe://wl.example/orders' })}` }, payload: { mission_id: 'ms_workload' },
    });
    expect(res.statusCode).toBe(500);
    expect(res.json().error.code).toBe('WORKLOAD_PROVIDER_UNAVAILABLE');
    await app.close();
  });

  it('answers a WIT without iss or sub with 400 WORKLOAD_ISSUER_MISSING or WORKLOAD_SUBJECT_MISSING', async () => {
    const app = Fastify();
    app.setErrorHandler(createErrorHandler());
    registerWorkloadWitRoutes(app, servicesStub());
    const noIss = await app.inject({
      method: 'POST', url: '/v1/workload/wit',
      headers: { authorization: `Bearer ${unsignedJwt({ sub: 'wimse://orders' })}` }, payload: { mission_id: 'ms_workload' },
    });
    expect(noIss.statusCode).toBe(400);
    expect(noIss.json().error.code).toBe('WORKLOAD_ISSUER_MISSING');
    const noSub = await app.inject({
      method: 'POST', url: '/v1/workload/wit',
      headers: { authorization: `Bearer ${unsignedJwt({ iss: 'https://issuer.example' })}` }, payload: { mission_id: 'ms_workload' },
    });
    expect(noSub.statusCode).toBe(400);
    expect(noSub.json().error.code).toBe('WORKLOAD_SUBJECT_MISSING');
    await app.close();
  });
});
