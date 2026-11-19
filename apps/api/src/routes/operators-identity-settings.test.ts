import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GovernanceApprovalRequiredError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    // A token ending in -console is the Console's own signed-in session: the person is there.
    const raw = String((request['headers'] as { authorization?: string }).authorization ?? '').replace(/^Bearer /, '');
    request['isDashboardSession'] = raw.endsWith('-console');
    const token = raw.replace(/-console$/, '');
    request['operatorId'] = 'op_owner';
    request['isAdmin'] = false;
    request['isPlatformStaff'] = false;
    request['isPartner'] = false;
    if (['admin', 'standard', 'readonly'].includes(token)) {
      request['memberId'] = `mem_${token}`;
      request['memberRole'] = token;
    }
  },
}));

import { registerOperatorRoutes } from './operators.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const CURRENT = { identity_claim_ttl: '90d', identity_claim_inheritance: 'opt_in', identity_auto_revoke: true };

async function makeApp(current: Record<string, unknown> = CURRENT) {
  const updateIdentitySettings = vi.fn(async (_operatorId: string, input: Record<string, unknown>) => ({ ...current, ...input }));
  const getIdentitySettings = vi.fn(async () => current);
  const requireApproval = vi.fn(async () => { throw new GovernanceApprovalRequiredError('gvr_new', 'https://getstack.run/app/approve/gvr_new', 'operator'); });
  const consume = vi.fn(async () => undefined);
  const services = {
    operator: { getIdentitySettings, updateIdentitySettings },
    governanceApprovals: { requireApproval, consume },
    audit: { write: vi.fn(async () => undefined) },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerOperatorRoutes(app, services as never);
  await app.ready();
  const patch = (token: string, payload: Record<string, unknown>, headers: Record<string, string> = {}) =>
    app.inject({ method: 'PATCH', url: '/v1/operators/me/identity-settings', headers: { authorization: `Bearer ${token}`, ...headers }, payload });
  return { patch, updateIdentitySettings, requireApproval, consume };
}

describe('PATCH /v1/operators/me/identity-settings', () => {
  it.each([
    ['auto-revoke off', { identity_auto_revoke: false }],
    ['inheritance to auto', { identity_claim_inheritance: 'auto' }],
    ['a longer claim lifetime', { identity_claim_ttl: '1y' }],
    ['several loosenings at once', { identity_auto_revoke: false, identity_claim_inheritance: 'auto', identity_claim_ttl: '180d' }],
    ['tightening', { identity_claim_ttl: '30d' }],
    ['an empty change', {}],
  ])('applies %s for a key or an OAuth token, asking nobody', async (_name, change) => {
    for (const token of ['owner', 'admin']) {
      const { patch, updateIdentitySettings, requireApproval } = await makeApp();
      const response = await patch(token, change);
      expect(response.statusCode).toBe(200);
      expect(requireApproval).not.toHaveBeenCalled();
      expect(updateIdentitySettings).toHaveBeenCalledWith('op_owner', change);
    }
  });

  it.each(['standard', 'readonly'])('still refuses a %s member, and changes nothing', async (token) => {
    const { patch, requireApproval, updateIdentitySettings } = await makeApp();
    expect((await patch(token, { identity_auto_revoke: false })).statusCode).toBe(403);
    expect(requireApproval).not.toHaveBeenCalled();
    expect(updateIdentitySettings).not.toHaveBeenCalled();
  });
});
