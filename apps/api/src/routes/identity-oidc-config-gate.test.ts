import { readFileSync } from 'node:fs';
import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenError, GOVERNANCE_BROWSER_ONLY_ACTIONS } from '@stack/shared';
import { createErrorHandler } from '../middleware/error-handler.js';

// The routes under test carry their own gate: the stand-in for the auth middleware reads who is calling from a header
// and sets the same request fields the real one does, so what is proved here is the route's own chain.
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: import('fastify').FastifyRequest) => {
    const who = String(request.headers['x-test-who'] ?? 'owner');
    request.operatorId = 'op_test';
    request.operatorTier = 'enterprise';
    if (who === 'agent') request.agentId = 'agt_watched';
    if (who === 'member') {
      request.memberId = 'mem_standard';
      request.memberRole = 'standard';
    }
    if (who === 'admin') {
      request.memberId = 'mem_admin';
      request.memberRole = 'admin';
    }
    if (request.headers['x-test-dashboard'] === '1') request.isDashboardSession = true;
  },
}));

const { registerIdentityRoutes } = await import('./identity.js');

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const row = (over: Record<string, unknown> = {}) => ({
  id: 'oidc_1',
  operator_id: 'op_test',
  display_name: 'Corp',
  issuer_uri: 'https://login.corp.example.com',
  client_id: 'client-1',
  client_secret_encrypted: 'enc',
  audience: null,
  redirect_uri: 'https://getstack.run/oidc/callback',
  scopes_json: ['openid', 'email', 'profile'],
  claim_mapping_policy_json: null,
  jwks_cache_ttl_seconds: 3600,
  allowed_return_origins: null,
  sso_slug: 'corp',
  sso_login_enabled: false,
  default_member_role: 'standard',
  active: true,
  jwks_cached_jwks_json: null,
  discovery_cached_json: null,
  ...over,
});

async function makeApp() {
  const repo = {
    findActiveByOperator: vi.fn(async () => null as unknown),
    findById: vi.fn(async () => row()),
    create: vi.fn(async (input: Record<string, unknown>) => row(input)),
    update: vi.fn(async (_id: string, updates: Record<string, unknown>) => row(updates)),
    delete: vi.fn(async () => undefined),
  };
  const requireApproval = vi.fn(async () => {
    throw new ForbiddenError('GOVERNANCE_APPROVAL_REQUIRED');
  });
  const consume = vi.fn(async () => undefined);
  const encrypt = vi.fn(async () => ({ ciphertext: 'enc' }));
  const audit = { write: vi.fn(async () => undefined) };
  const spiffe = { create: vi.fn(), update: vi.fn(), delete: vi.fn() };
  const services = {
    oidcIdpConfigRepo: repo,
    governanceApprovals: { requireApproval, consume },
    kms: { encrypt, decrypt: vi.fn(async () => 'secret') },
    audit,
    features: { require: () => undefined },
    operator: { getById: vi.fn(async () => ({ id: 'op_test', tier: 'enterprise' })) },
    spiffe,
  };
  const app = Fastify();
  app.setErrorHandler(createErrorHandler());
  apps.push(app);
  registerIdentityRoutes(app, services as never);
  await app.ready();
  return { app, repo, requireApproval, consume, audit };
}

const createBody = {
  display_name: 'Corp',
  issuer_uri: 'https://login.corp.example.com',
  client_id: 'client-1',
  client_secret: 'shh',
  redirect_uri: 'https://getstack.run/oidc/callback',
  sso_slug: 'corp',
};

const ROUTES = [
  { method: 'GET', url: '/v1/identity/oidc/config', payload: undefined },
  { method: 'POST', url: '/v1/identity/oidc/config', payload: createBody },
  { method: 'PATCH', url: '/v1/identity/oidc/config/oidc_1', payload: { display_name: 'x' } },
  { method: 'POST', url: '/v1/identity/oidc/config/oidc_1/test', payload: {} },
  { method: 'DELETE', url: '/v1/identity/oidc/config/oidc_1', payload: undefined },
] as const;

describe('the single sign-on provider configuration', () => {
  describe('who may reach it', () => {
    it('refuses a member who is not an administrator on every route, before anything is read or changed', async () => {
      const { app, repo, requireApproval } = await makeApp();
      for (const { method, url, payload } of ROUTES) {
        const response = await app.inject({ method, url, payload, headers: { 'x-test-who': 'member', 'x-test-dashboard': '1' } });
        expect(response.statusCode, `${method} ${url}`).toBe(403);
      }
      for (const fn of Object.values(repo)) expect(fn).not.toHaveBeenCalled();
      expect(requireApproval).not.toHaveBeenCalled();
    });

    it('refuses an agent context on every route, before anything is read or changed', async () => {
      const { app, repo } = await makeApp();
      for (const { method, url, payload } of ROUTES) {
        const response = await app.inject({ method, url, payload, headers: { 'x-test-who': 'agent', 'x-test-dashboard': '1' } });
        expect(response.statusCode, `${method} ${url}`).toBe(403);
      }
      for (const fn of Object.values(repo)) expect(fn).not.toHaveBeenCalled();
    });

    it('lets an administrator member and the owner read it', async () => {
      const { app, repo } = await makeApp();
      for (const who of ['admin', 'owner']) {
        const response = await app.inject({ method: 'GET', url: '/v1/identity/oidc/config', headers: { 'x-test-who': who } });
        expect(response.statusCode, who).toBe(200);
      }
      expect(repo.findActiveByOperator).toHaveBeenCalledTimes(2);
    });

    it('refuses a member who is not an administrator the workload trust configuration too', async () => {
      const { app } = await makeApp();
      for (const [method, url, payload] of [
        ['POST', '/v1/identity/spiffe/trust-domains', { trust_domain: 'corp.example.com' }],
        ['PATCH', '/v1/identity/spiffe/trust-domains/std_1', { active: true }],
        ['DELETE', '/v1/identity/spiffe/trust-domains/std_1', undefined],
        ['POST', '/v1/identity/wimse/issuers', { issuer_uri: 'https://wimse.corp.example.com' }],
        ['PATCH', '/v1/identity/wimse/issuers/wi_1', { active: true }],
        ['DELETE', '/v1/identity/wimse/issuers/wi_1', undefined],
      ] as const) {
        const response = await app.inject({ method, url, payload, headers: { 'x-test-who': 'member' } });
        expect(response.statusCode, `${method} ${url}`).toBe(403);
      }
    });
  });

  describe('creating or changing the provider', () => {
    it('asks for a person\'s approval before it creates one, from anything but a signed-in browser', async () => {
      const { app, repo, requireApproval } = await makeApp();
      const response = await app.inject({ method: 'POST', url: '/v1/identity/oidc/config', payload: createBody, headers: { 'x-test-who': 'admin' } });
      expect(response.statusCode).toBe(403);
      expect(repo.create).not.toHaveBeenCalled();
      expect(requireApproval).toHaveBeenCalledWith(expect.objectContaining({ operatorId: 'op_test', action: 'sso_config_change', resourceId: 'create' }));
    });

    it('never puts the client secret in what the approval is bound to', async () => {
      const { app, requireApproval } = await makeApp();
      await app.inject({ method: 'POST', url: '/v1/identity/oidc/config', payload: createBody, headers: { 'x-test-who': 'admin' } });
      expect(JSON.stringify(requireApproval.mock.calls)).not.toContain('shh');
    });

    it('binds the approval to which client secret was asked for: another secret on the retry is another change', async () => {
      const { app, requireApproval } = await makeApp();
      for (const secret of ['shh', 'shh', 'another-secret']) {
        await app.inject({ method: 'POST', url: '/v1/identity/oidc/config', payload: { ...createBody, client_secret: secret }, headers: { 'x-test-who': 'admin' } });
      }
      const bound = (requireApproval.mock.calls as unknown as Array<[{ payload: { client_secret: unknown } }]>).map((call) => call[0].payload.client_secret);
      expect(bound[0]).toEqual(expect.stringMatching(/^[a-f0-9]{64}$/));
      expect(bound[1]).toBe(bound[0]);
      expect(bound[2]).not.toBe(bound[0]);
    });

    it('announces the approval with the issuer\'s host name only, never what the caller typed after it', async () => {
      const { app, requireApproval } = await makeApp();
      await app.inject({
        method: 'POST',
        url: '/v1/identity/oidc/config',
        payload: { ...createBody, issuer_uri: 'https://login.corp.example.com/call-0800-123-456-to-confirm?urgent=1' },
        headers: { 'x-test-who': 'admin' },
      });
      const summary = (requireApproval.mock.calls as unknown as Array<[{ summary: string }]>)[0]![0].summary;
      expect(summary).toContain('login.corp.example.com');
      expect(summary).not.toMatch(/call-0800|urgent/);
    });

    it('creates it once the exact approval is presented', async () => {
      const { app, repo, consume } = await makeApp();
      const response = await app.inject({ method: 'POST', url: '/v1/identity/oidc/config', payload: createBody, headers: { 'x-test-who': 'owner', 'x-governance-approval': 'gvr_ok' } });
      expect(response.statusCode).toBe(201);
      expect(consume).toHaveBeenCalledWith(expect.objectContaining({ approvalId: 'gvr_ok', action: 'sso_config_change', resourceId: 'create' }));
      expect(repo.create).toHaveBeenCalledTimes(1);
    });

    it('lets a signed-in browser session decide for itself', async () => {
      const { app, repo, requireApproval } = await makeApp();
      const response = await app.inject({ method: 'POST', url: '/v1/identity/oidc/config', payload: createBody, headers: { 'x-test-who': 'admin', 'x-test-dashboard': '1' } });
      expect(response.statusCode).toBe(201);
      expect(requireApproval).not.toHaveBeenCalled();
      expect(repo.create).toHaveBeenCalledTimes(1);
    });

    it.each([
      ['the issuer', { issuer_uri: 'https://login.attacker.example.com' }],
      ['the client', { client_id: 'other' }],
      ['the client secret', { client_secret: 'new-secret' }],
      ['the redirect address', { redirect_uri: 'https://getstack.run/other' }],
      ['the audience', { audience: 'other' }],
      ['the scopes', { scopes: ['openid'] }],
      ['the claim mapping', { claim_mapping_policy: { email: 'upn' } }],
      ['the origins a sign-in may return to', { allowed_return_origins: ['https://evil.example.com'] }],
      ['the sign-in slug', { sso_slug: 'other' }],
      ['the role a new member gets', { default_member_role: 'admin' }],
      ['turning sign-in on', { sso_login_enabled: true }],
    ])('refuses a change of %s without a person\'s approval', async (_name, body) => {
      const { app, repo, requireApproval } = await makeApp();
      const response = await app.inject({ method: 'PATCH', url: '/v1/identity/oidc/config/oidc_1', payload: body, headers: { 'x-test-who': 'admin' } });
      expect(response.statusCode).toBe(403);
      expect(repo.update).not.toHaveBeenCalled();
      expect(requireApproval).toHaveBeenCalledWith(expect.objectContaining({ action: 'sso_config_change', resourceId: 'oidc_1' }));
    });

    it('applies a change once the exact approval is presented', async () => {
      const { app, repo, consume } = await makeApp();
      const response = await app.inject({
        method: 'PATCH',
        url: '/v1/identity/oidc/config/oidc_1',
        payload: { issuer_uri: 'https://login.other.example.com' },
        headers: { 'x-test-who': 'admin', 'x-governance-approval': 'gvr_ok' },
      });
      expect(response.statusCode).toBe(200);
      expect(consume).toHaveBeenCalledWith(expect.objectContaining({ approvalId: 'gvr_ok', action: 'sso_config_change', resourceId: 'oidc_1' }));
      expect(repo.update).toHaveBeenCalledTimes(1);
    });

    it('lets an administrator change what only tightens or only labels, with no approval', async () => {
      const { app, repo, requireApproval } = await makeApp();
      for (const body of [{ display_name: 'Renamed' }, { sso_login_enabled: false }, { active: false }, { jwks_cache_ttl_seconds: 600 }]) {
        const response = await app.inject({ method: 'PATCH', url: '/v1/identity/oidc/config/oidc_1', payload: body, headers: { 'x-test-who': 'admin' } });
        expect(response.statusCode, JSON.stringify(body)).toBe(200);
      }
      expect(requireApproval).not.toHaveBeenCalled();
      expect(repo.update).toHaveBeenCalledTimes(4);
    });

    it('lets an administrator delete it with no approval: that only tightens', async () => {
      const { app, repo, requireApproval } = await makeApp();
      const del = await app.inject({ method: 'DELETE', url: '/v1/identity/oidc/config/oidc_1', headers: { 'x-test-who': 'admin' } });
      expect(del.statusCode).toBe(204);
      expect(repo.delete).toHaveBeenCalledTimes(1);
      expect(requireApproval).not.toHaveBeenCalled();
    });
  });

  describe('structural', () => {
    it('declares the administrator gate on every route, whatever the verb, so a new one cannot be added without it', () => {
      const source = readFileSync(new URL('./identity.ts', import.meta.url), 'utf8');
      const declarations = [...source.matchAll(/app\.(get|post|put|patch|delete)(?:<[^>]*>)?\(\s*'(\/v1\/identity\/oidc\/config[^']*)',\s*\{\s*preHandler:\s*([^}]*)\}/g)];
      expect(declarations.map((m) => `${m[1]!.toUpperCase()} ${m[2]}`)).toEqual([
        'GET /v1/identity/oidc/config',
        'POST /v1/identity/oidc/config',
        'PATCH /v1/identity/oidc/config/:id',
        'POST /v1/identity/oidc/config/:id/test',
        'DELETE /v1/identity/oidc/config/:id',
      ]);
      for (const m of declarations) expect(m[3], `${m[1]} ${m[2]}`).toContain('requireOperatorAdmin');
    });

    it('asks a person for approval, in a browser only, of what loosens', () => {
      expect(GOVERNANCE_BROWSER_ONLY_ACTIONS.has('sso_config_change')).toBe(true);
    });
  });
});
