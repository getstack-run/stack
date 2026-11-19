import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenError, ids } from '@stack/shared';
import { createErrorHandler } from '../middleware/error-handler.js';
import {
  registerMemberAcceptRoutes,
  registerMemberRoutes,
  resolveMemberInviteBaseUrl,
} from './members.js';

const apps: ReturnType<typeof Fastify>[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const member = {
  id: 'mem_test',
  operator_id: 'op_test',
  email: 'member@example.test',
  name: 'Member Test',
  role: 'standard',
  allowed_connections: null,
  status: 'invited',
  invited_at: new Date('2026-09-02T10:00:00.000Z'),
  joined_at: null,
  revoked_at: null,
  api_key_hash: 'must-not-leak',
  key_prefix: 'must-not-leak',
  invite_token_hash: 'must-not-leak',
};

async function makeAdminApp(options: { email?: { sendEmail: ReturnType<typeof vi.fn> } | null }) {
  const auditWrite = vi.fn(async () => undefined);
  const invite = vi.fn(async () => ({ member, inviteToken: ids.inviteToken() }));
  const updateAccess = vi.fn(async () => ({ ...member, status: 'active' }));
  const app = Fastify();
  apps.push(app);
  app.addHook('onRequest', async (request) => {
    request.operatorId = 'op_test';
    request.operatorTier = 'business';
  });
  registerMemberRoutes(app, {
    authEmail: options.email,
    audit: { write: auditWrite },
    member: { invite, list: vi.fn(async () => [member]), updateAccess },
    operator: {
      getById: vi.fn(async () => ({
        id: 'op_test',
        email: 'owner@example.test',
        purchased_seats: 0,
      })),
    },
  } as never);
  await app.ready();
  return { app, auditWrite, invite, updateAccess };
}

const inviteBody = {
  email: member.email,
  name: member.name,
  role: member.role,
};

describe('member invitation delivery', () => {
  it('rejects invalid and non-HTTPS production invitation URLs', () => {
    expect(resolveMemberInviteBaseUrl('not a URL', 'production')).toBeNull();
    expect(resolveMemberInviteBaseUrl('http://getstack.run', 'production')).toBeNull();
    expect(resolveMemberInviteBaseUrl('https://localhost:3100', 'production')).toBeNull();
    expect(resolveMemberInviteBaseUrl('https://getstack.run', 'production')?.origin)
      .toBe('https://getstack.run');
    expect(resolveMemberInviteBaseUrl('http://localhost:3100', 'development')?.origin)
      .toBe('http://localhost:3100');
  });

  it('does not create an invitation when email delivery is not configured', async () => {
    const { app, invite } = await makeAdminApp({ email: null });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/team/members',
      payload: inviteBody,
    });

    expect(response.statusCode).toBe(503);
    expect(invite).not.toHaveBeenCalled();
  });

  it('reports delivery failure and does not expose the invitation token', async () => {
    const sendEmail = vi.fn(async () => {
      throw new Error('provider failure');
    });
    const { app, auditWrite } = await makeAdminApp({ email: { sendEmail } });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/team/members',
      payload: inviteBody,
    });

    expect(response.statusCode).toBe(502);
    expect(response.body).not.toContain('inv_');
    expect(response.body).not.toContain('provider failure');
    expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({ outcome: 'failure' }));
  });

  it('sends the email and returns only public member fields', async () => {
    const sendEmail = vi.fn(async () => ({ id: 'email_test' }));
    const { app } = await makeAdminApp({ email: { sendEmail } });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/team/members',
      payload: inviteBody,
    });

    expect(response.statusCode).toBe(201);
    expect(sendEmail).toHaveBeenCalledOnce();
    expect(response.json()).toMatchObject({
      id: member.id,
      email: member.email,
      status: 'invited',
    });
    expect(response.body).not.toContain('api_key_hash');
    expect(response.body).not.toContain('invite_token_hash');
    expect(response.body).not.toContain('inv_');
  });
});

describe('member response redaction', () => {
  it('returns only public fields after an access update', async () => {
    const { app } = await makeAdminApp({ email: null });
    const response = await app.inject({
      method: 'PATCH',
      url: `/v1/team/members/${member.id}`,
      payload: { role: 'standard', allowed_connections: null },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      id: member.id,
      email: member.email,
      status: 'active',
      allowed_connections: null,
    });
    expect(response.body).not.toContain('api_key_hash');
    expect(response.body).not.toContain('invite_token_hash');
    expect(response.body).not.toContain('key_prefix');
  });
});

describe('clearing single sign-on bindings', () => {
  async function makeBindingApp() {
    const auditWrite = vi.fn(async () => undefined);
    const clearSsoBindings = vi.fn(async (_operatorId: string, target: { memberId: string } | { issuer: string }) =>
      'memberId' in target
        ? [{ id: target.memberId, email: 'alice@corp.example', sso_issuer: 'https://old-idp.corp.example' }]
        : [
            { id: 'mem_a', email: 'alice@corp.example', sso_issuer: target.issuer },
            { id: 'mem_b', email: 'bob@corp.example', sso_issuer: target.issuer },
          ]);
    const requireApproval = vi.fn(async () => {
      throw new ForbiddenError('GOVERNANCE_APPROVAL_REQUIRED');
    });
    const consume = vi.fn(async () => undefined);
    const app = Fastify();
    app.setErrorHandler(createErrorHandler());
    apps.push(app);
    app.addHook('onRequest', async (request) => {
      request.operatorId = 'op_test';
      request.operatorTier = 'enterprise';
      if (request.headers['x-test-dashboard'] === '1') request.isDashboardSession = true;
    });
    registerMemberRoutes(app, {
      audit: { write: auditWrite },
      member: { clearSsoBindings },
      governanceApprovals: { requireApproval, consume },
    } as never);
    await app.ready();
    return { app, auditWrite, clearSsoBindings, requireApproval, consume };
  }

  const clear = (app: Awaited<ReturnType<typeof makeBindingApp>>['app'], payload: unknown, headers: Record<string, string> = {}) =>
    app.inject({ method: 'POST', url: '/v1/team/sso-bindings/clear', payload: payload as object, headers });

  it('asks for a person\'s approval of the exact change before it clears anything, from anything but a signed-in browser', async () => {
    const { app, clearSsoBindings, requireApproval } = await makeBindingApp();
    const response = await clear(app, { member_id: 'mem_alice' });
    expect(response.statusCode).toBe(403);
    expect(clearSsoBindings).not.toHaveBeenCalled();
    expect(requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_test',
      action: 'member_sso_binding_clear',
      resourceId: 'mem_alice',
      payload: { member_id: 'mem_alice' },
    }));
  });

  it('applies an approved change bound to the same target, once, and consumes the approval', async () => {
    const { app, clearSsoBindings, consume, auditWrite } = await makeBindingApp();
    const response = await clear(app, { issuer: 'https://old-idp.corp.example' }, { 'x-governance-approval': 'gvr_approved' });
    expect(response.statusCode).toBe(200);
    expect(consume).toHaveBeenCalledWith(expect.objectContaining({
      approvalId: 'gvr_approved',
      action: 'member_sso_binding_clear',
      resourceId: 'https://old-idp.corp.example',
      payload: { issuer: 'https://old-idp.corp.example' },
    }));
    expect(clearSsoBindings).toHaveBeenCalledWith('op_test', { issuer: 'https://old-idp.corp.example' });
    expect(response.json()).toEqual({
      cleared: [
        { id: 'mem_a', email: 'alice@corp.example', sso_issuer: 'https://old-idp.corp.example' },
        { id: 'mem_b', email: 'bob@corp.example', sso_issuer: 'https://old-idp.corp.example' },
      ],
    });
    // The row of the signed record says who was cleared, by a hash of the target and the members.
    expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({
      action: 'member.sso_binding.clear',
      outcome: 'success',
      payload_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
    }));
  });

  it('lets a signed-in browser session decide for itself, and clears one member', async () => {
    const { app, clearSsoBindings, requireApproval } = await makeBindingApp();
    const response = await clear(app, { member_id: 'mem_alice' }, { 'x-test-dashboard': '1' });
    expect(response.statusCode).toBe(200);
    expect(requireApproval).not.toHaveBeenCalled();
    expect(clearSsoBindings).toHaveBeenCalledWith('op_test', { memberId: 'mem_alice' });
  });

  it('takes a member or an issuer, never both and never neither, and nothing else', async () => {
    const { app, clearSsoBindings } = await makeBindingApp();
    for (const body of [{}, { member_id: 'mem_a', issuer: 'https://x.example' }, { member_id: '' }, { issuer: '' }, { member_id: 'mem_a', all: true }]) {
      const response = await clear(app, body, { 'x-test-dashboard': '1' });
      expect(response.statusCode, JSON.stringify(body)).toBe(400);
    }
    expect(clearSsoBindings).not.toHaveBeenCalled();
  });
});

describe('member invitation acceptance', () => {
  it('accepts a valid one-time token and returns a session identity without a key', async () => {
    const app = Fastify();
    apps.push(app);
    const acceptInvite = vi.fn(async () => ({ member: { ...member, status: 'active' } }));
    registerMemberAcceptRoutes(app, { member: { acceptInvite } } as never);
    await app.ready();

    const token = ids.inviteToken();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/team/invites/accept',
      payload: { token },
    });

    expect(response.statusCode).toBe(200);
    expect(acceptInvite).toHaveBeenCalledWith(token, expect.any(Object));
    expect(response.json()).toEqual({
      member_id: member.id,
      operator_id: member.operator_id,
      email: member.email,
      role: member.role,
    });
    expect(response.body).not.toContain('key');
  });

  it.each([
    ['missing', undefined],
    ['null', null],
    ['number', 123],
    ['object', {}],
    ['wrong prefix', `bad_${'a'.repeat(32)}`],
    ['short', `inv_${'a'.repeat(31)}`],
    ['long', `inv_${'a'.repeat(33)}`],
    ['old oversized fixture', `inv_${'a'.repeat(64)}`],
    ['invalid alphabet', `inv_${'a'.repeat(31)}!`],
    ['newline', `inv_${'a'.repeat(32)}\n`],
    ['whitespace', ` inv_${'a'.repeat(32)}`],
  ])('rejects malformed %s tokens before the service', async (_label, token) => {
    const app = Fastify();
    apps.push(app);
    const acceptInvite = vi.fn();
    registerMemberAcceptRoutes(app, { member: { acceptInvite } } as never);
    const response = await app.inject({
      method: 'POST', url: '/v1/team/invites/accept', payload: { token },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: { message: 'This invite is no longer valid.' } });
    expect(acceptInvite).not.toHaveBeenCalled();
  });
});
