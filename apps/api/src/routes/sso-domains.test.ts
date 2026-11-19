import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenError, LicenceRequiredError, NotFoundError, SsoDomainError } from '@stack/shared';
import { createErrorHandler } from '../middleware/error-handler.js';
import { requireOperatorAdmin } from '../middleware/require-platform.js';
import { registerSsoDomainRoutes } from './sso-domains.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const view = (over: Record<string, unknown> = {}) => ({
  id: 'ssod_1',
  domain: 'corp.example.com',
  status: 'pending',
  record: { type: 'TXT', name: '_stack-sso.corp.example.com', value: 'stack-sso-verification=abc' },
  verified_at: null,
  last_checked_at: null,
  last_check: null,
  missing_since: null,
  created_at: '2026-10-26T10:00:00.000Z',
  ...over,
});

async function makeApp(options: { tier?: string; features?: 'ok' | 'unlicensed'; admin?: boolean; agent?: boolean } = {}) {
  const auditWrite = vi.fn(async () => undefined);
  const add = vi.fn(async () => ({ domain: view(), created: true }));
  const list = vi.fn(async () => [view()]);
  const verify = vi.fn(async () => ({ domain: view({ status: 'verified' }), check: 'confirmed' as const }));
  const remove = vi.fn(async () => ({ id: 'ssod_1', domain: 'corp.example.com' }));
  const requireApproval = vi.fn(async () => {
    throw new ForbiddenError('GOVERNANCE_APPROVAL_REQUIRED');
  });
  const consume = vi.fn(async () => undefined);
  const app = Fastify();
  app.setErrorHandler(createErrorHandler());
  apps.push(app);
  app.addHook('onRequest', async (request) => {
    request.operatorId = 'op_test';
    request.operatorTier = options.tier ?? 'enterprise';
    if (request.headers['x-test-dashboard'] === '1') request.isDashboardSession = true;
    if (options.agent) request.agentId = 'agt_watched';
    if (options.admin === false) request.memberId = 'mem_reader';
    if (options.admin === false) request.memberRole = 'readonly';
  });
  // The scope the routes are mounted in (start.ts): the gate is the scope's, not the route's.
  await app.register(async (scope) => {
    scope.addHook('preHandler', requireOperatorAdmin);
    registerSsoDomainRoutes(scope, {
      audit: { write: auditWrite },
      ssoDomains: { add, list, verify, remove },
      governanceApprovals: { requireApproval, consume },
      features: {
        require: () => {
          if (options.features === 'unlicensed') throw new LicenceRequiredError('Single sign-on', { feature: 'sso', licence: 'none' });
        },
      },
      operator: { getById: vi.fn(async () => ({ id: 'op_test', tier: options.tier ?? 'enterprise' })) },
    } as never);
  });
  await app.ready();
  return { app, auditWrite, add, list, verify, remove, requireApproval, consume };
}

const dashboard = { 'x-test-dashboard': '1' };

describe('the verified domains of single sign-on', () => {
  describe('who may reach them', () => {
    it('refuses an agent context on every route, before anything is read or changed', async () => {
      const { app, add, list, verify, remove } = await makeApp({ agent: true });
      for (const [method, url] of [['GET', '/v1/identity/sso-domains'], ['POST', '/v1/identity/sso-domains'], ['POST', '/v1/identity/sso-domains/ssod_1/verify'], ['DELETE', '/v1/identity/sso-domains/ssod_1']] as const) {
        const response = await app.inject({ method, url, payload: method === 'POST' ? { domain: 'corp.example.com' } : undefined, headers: dashboard });
        expect(response.statusCode, `${method} ${url}`).toBe(403);
      }
      for (const fn of [add, list, verify, remove]) expect(fn).not.toHaveBeenCalled();
    });

    it('refuses a member who is not an administrator', async () => {
      const { app, add, list } = await makeApp({ admin: false });
      expect((await app.inject({ method: 'GET', url: '/v1/identity/sso-domains' })).statusCode).toBe(403);
      expect((await app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: { domain: 'corp.example.com' }, headers: dashboard })).statusCode).toBe(403);
      expect(list).not.toHaveBeenCalled();
      expect(add).not.toHaveBeenCalled();
    });
  });

  describe('adding a domain', () => {
    it('asks for a person\'s approval of the exact domain before it claims anything, from anything but a signed-in browser', async () => {
      const { app, add, requireApproval } = await makeApp();
      const response = await app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: { domain: 'Corp.Example.com.' } });
      expect(response.statusCode).toBe(403);
      expect(add).not.toHaveBeenCalled();
      expect(requireApproval).toHaveBeenCalledWith(expect.objectContaining({
        operatorId: 'op_test',
        action: 'sso_domain_add',
        resourceId: 'corp.example.com',
        payload: { domain: 'corp.example.com' },
      }));
    });

    it('claims the domain once the exact approval is presented, and records it', async () => {
      const { app, add, consume, auditWrite } = await makeApp();
      const response = await app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: { domain: 'corp.example.com' }, headers: { 'x-governance-approval': 'gvr_ok' } });
      expect(response.statusCode).toBe(201);
      expect(consume).toHaveBeenCalledWith(expect.objectContaining({ approvalId: 'gvr_ok', action: 'sso_domain_add', resourceId: 'corp.example.com', payload: { domain: 'corp.example.com' } }));
      expect(add).toHaveBeenCalledWith('op_test', 'corp.example.com');
      expect(response.json()).toMatchObject({ domain: 'corp.example.com', status: 'pending', record: { type: 'TXT', name: '_stack-sso.corp.example.com' } });
      expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({ action: 'sso.domain.add', outcome: 'success', payload_hash: expect.stringMatching(/^[0-9a-f]{64}$/) }));
    });

    it('lets a signed-in browser session decide for itself, and answers 200 for a claim the account already has, with no second record', async () => {
      const { app, add, auditWrite, requireApproval } = await makeApp();
      add.mockResolvedValueOnce({ domain: view(), created: false });
      const response = await app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: { domain: 'corp.example.com' }, headers: dashboard });
      expect(response.statusCode).toBe(200);
      expect(requireApproval).not.toHaveBeenCalled();
      expect(auditWrite).not.toHaveBeenCalled();
    });

    it('refuses what is not a domain before asking anyone for anything', async () => {
      const { app, add, requireApproval } = await makeApp();
      for (const domain of ['localhost', 'https://corp.example.com', 'a@corp.example.com', '10.0.0.1', 'corp.example.com:8443']) {
        const response = await app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: { domain } });
        expect(response.statusCode, domain).toBe(400);
        expect(response.json().error.code).toBe('SSO_DOMAIN_INVALID');
      }
      for (const body of [{}, { domain: '' }, { domain: 'corp.example.com', extra: 1 }, { domain: 5 }]) {
        const response = await app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: body });
        expect(response.statusCode, JSON.stringify(body)).toBe(400);
      }
      expect(add).not.toHaveBeenCalled();
      expect(requireApproval).not.toHaveBeenCalled();
    });

    it('is for any plan, and on an install for a licensed one, as the connection is', async () => {
      // An account whose row says free is not refused: no plan gates single sign-on.
      const anyPlan = await makeApp({ tier: 'free' });
      const accepted = await anyPlan.app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: { domain: 'corp.example.com' }, headers: dashboard });
      expect(accepted.statusCode).toBe(201);
      expect(anyPlan.add).toHaveBeenCalled();

      const unlicensed = await makeApp({ features: 'unlicensed' });
      const noLicence = await unlicensed.app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: { domain: 'corp.example.com' }, headers: dashboard });
      expect(noLicence.statusCode).toBe(402);
      expect(unlicensed.add).not.toHaveBeenCalled();
    });

    it('passes the service\'s neutral refusal on as it is', async () => {
      const { app, add } = await makeApp();
      add.mockRejectedValueOnce(new SsoDomainError('unavailable', 'This domain cannot be added to this account.'));
      const response = await app.inject({ method: 'POST', url: '/v1/identity/sso-domains', payload: { domain: 'corp.example.com' }, headers: dashboard });
      expect(response.statusCode).toBe(409);
      expect(response.json()).toMatchObject({ error: { code: 'SSO_DOMAIN_UNAVAILABLE', message: 'This domain cannot be added to this account.' } });
    });
  });

  describe('checking a domain', () => {
    it('looks the record up and says what it found, with a row that says the same', async () => {
      const { app, verify, auditWrite } = await makeApp();
      const response = await app.inject({ method: 'POST', url: '/v1/identity/sso-domains/ssod_1/verify' });
      expect(response.statusCode).toBe(200);
      expect(verify).toHaveBeenCalledWith('op_test', 'ssod_1');
      expect(response.json()).toMatchObject({ check: 'confirmed', domain: { status: 'verified' } });
      expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({ action: 'sso.domain.verify', outcome: 'success' }));
    });

    it('records a record that was not there, or a lookup that failed, as a failed check, not as an error of the request', async () => {
      const { app, verify, auditWrite } = await makeApp();
      verify.mockResolvedValueOnce({ domain: view(), check: 'unavailable' as never });
      const response = await app.inject({ method: 'POST', url: '/v1/identity/sso-domains/ssod_1/verify' });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ check: 'unavailable', domain: { status: 'pending' } });
      expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({ action: 'sso.domain.verify', outcome: 'failure', error: expect.objectContaining({ code: 'SSO_DOMAIN_UNAVAILABLE' }) }));
    });

    it('does not find another account\'s domain', async () => {
      const { app, verify } = await makeApp();
      verify.mockRejectedValueOnce(new NotFoundError('SsoDomain', 'ssod_other'));
      expect((await app.inject({ method: 'POST', url: '/v1/identity/sso-domains/ssod_other/verify' })).statusCode).toBe(404);
    });
  });

  describe('removing a domain', () => {
    it('needs no approval, since it only tightens, and is recorded', async () => {
      const { app, remove, auditWrite, requireApproval } = await makeApp();
      const response = await app.inject({ method: 'DELETE', url: '/v1/identity/sso-domains/ssod_1' });
      expect(response.statusCode).toBe(204);
      expect(requireApproval).not.toHaveBeenCalled();
      expect(remove).toHaveBeenCalledWith('op_test', 'ssod_1');
      expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({ action: 'sso.domain.remove', outcome: 'success' }));
    });
  });

  it('lists the account\'s domains', async () => {
    const { app, list } = await makeApp();
    const response = await app.inject({ method: 'GET', url: '/v1/identity/sso-domains' });
    expect(response.statusCode).toBe(200);
    expect(list).toHaveBeenCalledWith('op_test');
    expect(response.json()).toEqual({ domains: [view()] });
  });
});
