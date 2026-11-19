import { fakeEntitlements } from '../test/entitlements.js';
import { fakeBrowserSessions } from '../test/browser-sessions.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import { ForbiddenError, sha256 } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';
import {
  assertDashboardMutationOrigin,
  registerAuthorityPublicRoutes,
} from './authority.js';

const originalDashboardUrl = process.env['DASHBOARD_URL'];
const activeDashboardSessions = { assertActive: async () => ({}) };

afterEach(() => {
  if (originalDashboardUrl === undefined) delete process.env['DASHBOARD_URL'];
  else process.env['DASHBOARD_URL'] = originalDashboardUrl;
});

describe('authority approval CSRF boundary', () => {
  it('accepts only the exact configured dashboard origin', () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test/app';
    expect(() => assertDashboardMutationOrigin('https://console.example.test')).not.toThrow();
  });

  it.each([
    undefined,
    'https://evil.example.test',
    'https://console.example.test.evil.example',
    'https://console.example.test/path',
    'null',
  ])('rejects a missing, cross-site, or non-origin header: %s', (origin) => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    expect(() => assertDashboardMutationOrigin(origin)).toThrow(ForbiddenError);
  });

  it('rejects a cross-site approval request before reading the dashboard session', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const app = Fastify();
    let sessionRead = false;
    registerAuthorityPublicRoutes(app, {
      entitlements: fakeEntitlements(),
      signer: {
        verifyAccessOrSession: async () => {
          sessionRead = true;
          return null;
        },
      },
    } as never);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/authority/approval-requests/apr_one/decide',
      headers: {
        origin: 'https://evil.example.test',
        cookie: 'stack_session=dashboard-session',
      },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(403);
    expect(sessionRead).toBe(false);
  });

  it('does not reinterpret a readonly dashboard member as an eligible standard author', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const app = Fastify();
    let decided = false;
    registerAuthorityPublicRoutes(app, {
      entitlements: fakeEntitlements(),
      signer: {
        verifyAccessOrSession: async () => ({
          aud: 'stack:dashboard',
          sub: 'op_one',
          payload: { member_id: 'mem_readonly', is_member: true, email: 'member@test.invalid' },
        }),
      },
      dashboardSessions: activeDashboardSessions,
      get browserSessions() { return fakeBrowserSessions(this); },
      operator: { getById: async () => ({ id: 'op_one', status: 'active', email: 'owner@test.invalid' }) },
      member: {
        findById: async () => ({
          id: 'mem_readonly',
          operator_id: 'op_one',
          status: 'active',
          role: 'readonly', email: 'member@test.invalid',
        }),
      },
      authority: {
        decideApproval: async () => {
          decided = true;
          return {};
        },
      },
    } as never);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/authority/approval-requests/apr_one/decide',
      headers: {
        origin: 'https://console.example.test',
        cookie: 'stack_session=dashboard-session',
      },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(403);
    expect(decided).toBe(false);
  });

  it('passes the required durable idempotency key with the server-derived author', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const app = Fastify();
    const calls: unknown[][] = [];
    registerAuthorityPublicRoutes(app, {
      entitlements: fakeEntitlements(),
      signer: {
        verifyAccessOrSession: async () => ({
          aud: 'stack:dashboard',
          sub: 'op_one',
          payload: { email: 'owner@test.invalid' },
        }),
      },
      dashboardSessions: activeDashboardSessions,
      get browserSessions() { return fakeBrowserSessions(this); },
      operator: { getById: async () => ({ id: 'op_one', status: 'active', email: 'owner@test.invalid' }) },
      authority: {
        decideApproval: async (...args: unknown[]) => {
          calls.push(args);
          return { id: 'apd_one', status: 'approved' };
        },
      },
      audit: { write: async () => undefined },
    } as never);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/authority/approval-requests/apr_one/decide',
      headers: {
        origin: 'https://console.example.test',
        cookie: 'stack_session=dashboard-session',
        'idempotency-key': 'approval-decision-one',
      },
      payload: {
        request_id: 'apr_one',
        decision: 'approve',
        request_hash: `sha256:${'a'.repeat(64)}`,
        signed_decision: 'signed-ceremony-output',
      },
    });
    await app.close();

    expect(response.statusCode).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.[0]).toBe('op_one');
    expect(calls[0]?.[1]).toBe('apr_one');
    expect(calls[0]?.[2]).toEqual({ kind: 'operator_owner', operator_id: 'op_one' });
    expect(calls[0]?.[4]).toBe('approval-decision-one');
    expect(calls[0]?.[5]).toEqual({ email: 'owner@test.invalid', ownerSessionRevision: '0' });
  });

  it('rejects an approval decision without an idempotency key before service mutation', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const app = Fastify();
    let decided = false;
    registerAuthorityPublicRoutes(app, {
      entitlements: fakeEntitlements(),
      signer: {
        verifyAccessOrSession: async () => ({ aud: 'stack:dashboard', sub: 'op_one', payload: { email: 'owner@test.invalid' } }),
      },
      dashboardSessions: activeDashboardSessions,
      get browserSessions() { return fakeBrowserSessions(this); },
      operator: { getById: async () => ({ id: 'op_one', status: 'active', email: 'owner@test.invalid' }) },
      authority: {
        decideApproval: async () => {
          decided = true;
          return {};
        },
      },
      audit: { write: async () => undefined },
    } as never);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/authority/approval-requests/apr_one/decide',
      headers: {
        origin: 'https://console.example.test',
        cookie: 'stack_session=dashboard-session',
      },
      payload: {
        request_id: 'apr_one',
        decision: 'approve',
        request_hash: `sha256:${'a'.repeat(64)}`,
        signed_decision: 'signed-ceremony-output',
      },
    });
    await app.close();

    expect(response.statusCode).toBe(400);
    expect(decided).toBe(false);
  });

  it('rejects Authorization fallback even when a dashboard cookie is present', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const verifyAccessOrSession = vi.fn();
    const app = Fastify();
    registerAuthorityPublicRoutes(app, { entitlements: fakeEntitlements(), signer: { verifyAccessOrSession } } as never);

    const response = await app.inject({
      method: 'POST', url: '/v1/authority/approval-requests/apr_one/decide',
      headers: {
        authorization: 'Bearer sk_live_agentic',
        origin: 'https://console.example.test',
        cookie: 'stack_session=dashboard-session',
      },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(401);
    expect(verifyAccessOrSession).not.toHaveBeenCalled();
  });

  it('rejects Authorization fallback on guided Authority setup', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const verifyAccessOrSession = vi.fn();
    const app = Fastify();
    registerAuthorityPublicRoutes(app, { entitlements: fakeEntitlements(), signer: { verifyAccessOrSession } } as never);

    const response = await app.inject({
      method: 'POST', url: '/v1/authority/enterprise-oidc/requests/aor_0123456789abcdef0123456789abcdef/start',
      headers: {
        authorization: 'Bearer sk_live_agentic',
        origin: 'https://console.example.test',
        cookie: 'stack_session=dashboard-session',
      },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(401);
    expect(verifyAccessOrSession).not.toHaveBeenCalled();
  });

  it('requires an owner or admin to start guided Authority setup', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const identityLookup = vi.fn();
    const app = Fastify();
    registerAuthorityPublicRoutes(app, {
      entitlements: fakeEntitlements(),
      signer: { verifyAccessOrSession: async () => ({
        aud: 'stack:dashboard', sub: 'op_one', payload: { member_id: 'mem_standard', is_member: true, email: 'member@test.invalid' },
      }) },
      dashboardSessions: activeDashboardSessions,
      get browserSessions() { return fakeBrowserSessions(this); },
      operator: { getById: async () => ({ id: 'op_one', status: 'active', email: 'owner@test.invalid' }) },
      member: { findById: async () => ({
        id: 'mem_standard', operator_id: 'op_one', status: 'active', role: 'standard', email: 'member@test.invalid',
      }) },
      identity: { getProvider: identityLookup },
    } as never);

    const response = await app.inject({
      method: 'POST', url: '/v1/authority/enterprise-oidc/requests/aor_0123456789abcdef0123456789abcdef/start',
      headers: { origin: 'https://console.example.test', cookie: 'stack_session=dashboard-session' },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(403);
    expect(identityLookup).not.toHaveBeenCalled();
  });

  it('binds guided Authority completion to the browser that started it', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const identityLookup = vi.fn();
    const workflow = {
      request_id: 'aor_0123456789abcdef0123456789abcdef',
      operator_id: 'op_one',
      authenticated_author_hash: sha256(JSON.stringify({ kind: 'operator_owner', operator_id: 'op_one' })),
      browser_binding_hash: sha256('a'.repeat(43)),
      method: 'company_sign_in',
    };
    const app = Fastify();
    registerAuthorityPublicRoutes(app, {
      entitlements: fakeEntitlements(),
      signer: { verifyAccessOrSession: async () => ({ aud: 'stack:dashboard', sub: 'op_one', payload: { email: 'owner@test.invalid' } }) },
      dashboardSessions: activeDashboardSessions,
      get browserSessions() { return fakeBrowserSessions(this); },
      operator: { getById: async () => ({ id: 'op_one', status: 'active', email: 'owner@test.invalid' }) },
      redis: { get: async () => 'encrypted-workflow' },
      kms: { decrypt: async () => JSON.stringify(workflow) },
      identity: { getProvider: identityLookup },
    } as never);

    const response = await app.inject({
      method: 'POST', url: '/v1/authority/enterprise-oidc/requests/aor_0123456789abcdef0123456789abcdef/complete',
      headers: { origin: 'https://console.example.test', cookie: 'stack_session=dashboard-session' },
      payload: { session_ref: 's'.repeat(43), browser_binding: 'b'.repeat(43), method: 'company_sign_in' },
    });
    await app.close();

    expect(response.statusCode).toBe(403);
    expect(identityLookup).not.toHaveBeenCalled();
  });

  it.each([
    ['authoriser_principal_id', 'prn_caller_selected'],
    ['identity_proof_id', 'prf_caller_selected'],
    ['capacity_proof_id', 'prf_caller_selected'],
    ['decision_proof_id', 'prf_caller_selected'],
    ['weight', 100],
  ])('rejects caller-selected approval authority field %s', async (field, value) => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const decideApproval = vi.fn();
    const app = Fastify();
    app.setErrorHandler(errorHandler);
    registerAuthorityPublicRoutes(app, {
      entitlements: fakeEntitlements(),
      signer: { verifyAccessOrSession: async () => ({ aud: 'stack:dashboard', sub: 'op_one', payload: { email: 'owner@test.invalid' } }) },
      dashboardSessions: activeDashboardSessions,
      get browserSessions() { return fakeBrowserSessions(this); },
      operator: { getById: async () => ({ id: 'op_one', status: 'active', email: 'owner@test.invalid' }) },
      authority: { decideApproval },
    } as never);

    const response = await app.inject({
      method: 'POST', url: '/v1/authority/approval-requests/apr_one/decide',
      headers: {
        origin: 'https://console.example.test', cookie: 'stack_session=dashboard-session',
        'idempotency-key': `approval-untrusted-${field}`,
      },
      payload: {
        request_id: 'apr_one', decision: 'approve', request_hash: `sha256:${'a'.repeat(64)}`,
        signed_decision: 'signed-ceremony-output', [field]: value,
      },
    });
    await app.close();

    expect(response.statusCode).toBe(400);
    expect(decideApproval).not.toHaveBeenCalled();
  });

  it('binds the decision body to the exact approval request in the path', async () => {
    process.env['DASHBOARD_URL'] = 'https://console.example.test';
    const decideApproval = vi.fn();
    const app = Fastify();
    app.setErrorHandler(errorHandler);
    registerAuthorityPublicRoutes(app, {
      entitlements: fakeEntitlements(),
      signer: { verifyAccessOrSession: async () => ({ aud: 'stack:dashboard', sub: 'op_one', payload: { email: 'owner@test.invalid' } }) },
      dashboardSessions: activeDashboardSessions,
      get browserSessions() { return fakeBrowserSessions(this); },
      operator: { getById: async () => ({ id: 'op_one', status: 'active', email: 'owner@test.invalid' }) },
      authority: { decideApproval },
    } as never);

    const response = await app.inject({
      method: 'POST', url: '/v1/authority/approval-requests/apr_one/decide',
      headers: {
        origin: 'https://console.example.test', cookie: 'stack_session=dashboard-session',
        'idempotency-key': 'approval-path-mismatch',
      },
      payload: {
        request_id: 'apr_other', decision: 'approve', request_hash: `sha256:${'a'.repeat(64)}`,
        signed_decision: 'signed-ceremony-output',
      },
    });
    await app.close();

    expect(response.statusCode).toBe(404);
    expect(decideApproval).not.toHaveBeenCalled();
  });
});
