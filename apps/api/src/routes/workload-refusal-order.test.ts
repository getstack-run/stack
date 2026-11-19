import { afterEach, describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import { NotFoundError, SchemaValidationError } from '@stack/shared';
import type { Services } from '../config/services.js';
import { createErrorHandler } from '../middleware/error-handler.js';

const meter = vi.hoisted(() => ({
  counted: 0,
  handedBack: 0,
}));

vi.mock('../middleware/meter.js', () => ({
  enforceOverage: vi.fn(async (_services: unknown, _operatorId: string, _meter: string, _ctx: unknown, onCounted?: (rollback: () => Promise<void>) => void) => {
    meter.counted += 1;
    onCounted?.(async () => {
      meter.handedBack += 1;
    });
  }),
}));

const { registerWorkloadRoutes } = await import('./workload.js');
const { registerWorkloadWitRoutes } = await import('./workload-wit.js');

/**
 * A workload passport (SPIFFE JWT-SVID or WIMSE WIT) is a feature of every plan, with no plan gate. Whatever refuses the
 * exchange refuses it before the action is counted and the passport minted, or hands the action back: a refused
 * exchange never leaves a counted action or a passport behind.
 */

function unsignedJwt(claims: Record<string, unknown>): string {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'EdDSA', kid: 'k' })}.${part(claims)}.c2ln`;
}

function servicesStub(opts: { attestationRefused?: boolean; mintRefused?: boolean } = {}) {
  const issue = vi.fn(async () => {
    if (opts.mintRefused) throw new NotFoundError('Mission', 'ms_workload');
    return { token: 'tok', jti: 'ppt_new', expires_at: new Date(Date.now() + 600_000) };
  });
  const assertRegistrable = vi.fn(() => {
    if (opts.attestationRefused) throw new SchemaValidationError({ message: 'payload validation failed' });
  });
  const registerClaim = vi.fn(async () => ({ claimId: 'pc_attest' }));
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
    claimRegistry: { assertRegistrable, registerClaim },
    audit: { write: vi.fn(async () => undefined) },
  };
  return { services: services as unknown as Services, issue, registerClaim };
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

describe.each(ROUTES)('$name refuses before it spends', (route) => {
  const apps: Array<ReturnType<typeof Fastify>> = [];
  afterEach(async () => {
    while (apps.length) await apps.pop()!.close();
    meter.counted = 0;
    meter.handedBack = 0;
  });

  async function exchange(opts: Parameters<typeof servicesStub>[0] = {}) {
    const stub = servicesStub(opts);
    const app = Fastify();
    app.setErrorHandler(createErrorHandler());
    apps.push(app);
    route.register(app, stub.services);
    await app.ready();
    const res = await app.inject({
      method: 'POST', url: route.url, headers: { authorization: `Bearer ${route.token}` },
      payload: { mission_id: 'ms_workload' },
    });
    return { res, ...stub };
  }

  it('mints for any account: no plan gate', async () => {
    const { res, issue, registerClaim } = await exchange();
    expect(res.statusCode).toBe(201);
    expect(meter.counted).toBe(1);
    expect(meter.handedBack).toBe(0);
    expect(issue).toHaveBeenCalledTimes(1);
    expect(registerClaim).toHaveBeenCalledTimes(1);
  });

  it('an attestation the claim registry would refuse is refused before anything is counted or minted', async () => {
    const { res, issue, registerClaim } = await exchange({ attestationRefused: true });
    expect(res.statusCode).toBe(400);
    expect(meter.counted).toBe(0);
    expect(issue).not.toHaveBeenCalled();
    expect(registerClaim).not.toHaveBeenCalled();
  });

  it('a refused mint hands the counted action back', async () => {
    const { res, registerClaim } = await exchange({ mintRefused: true });
    expect(res.statusCode).toBe(404);
    expect(meter.counted).toBe(1);
    expect(meter.handedBack).toBe(1);
    expect(registerClaim).not.toHaveBeenCalled();
  });
});
