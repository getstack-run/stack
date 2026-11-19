import { beforeAll, describe, expect, it, vi } from 'vitest';
import { PassportSigner } from '@stack/vault';
import { ForbiddenError } from '@stack/shared';
import { createAuthMiddleware } from './auth.js';
import { denyAgentContexts } from './require-platform.js';
import { fakeEntitlements } from '../test/entitlements.js';

const signer = new PassportSigner();
const claims = { operator_id: 'op_fleet', agent_id: 'agt_worker', membership_id: 'flm_member',
  principal_kind: 'worker' as const,
  policy_id: 'flp_policy', policy_revision: 1, key_digest: 'a'.repeat(64) };
beforeAll(() => signer.init());

async function authenticate(token: string, state: Parameters<PassportSigner['signFleetSession']>[0] = claims, unavailable = false, url = '/v1/missions/start') {
  const generic = vi.spyOn(signer, 'verifyAccessOrSession').mockClear();
  const request = { headers: { authorization: `Bearer ${token}` }, method: 'POST', url,
    routeOptions: { url: '/v1/missions/start' }, log: { error: vi.fn(), warn: vi.fn(), info: vi.fn() } };
  const services = { signer, fleet: { sessionState: async () => {
    if (unavailable) throw new ForbiddenError();
    return { claims: state };
  } }, entitlements: fakeEntitlements(), operator: { getById: async () => ({ id: claims.operator_id, tier: 'enterprise', status: 'active',
    is_admin: true, is_platform_staff: true, is_partner: true }) } };
  await createAuthMiddleware(services as never)(request as never, {} as never);
  expect(generic).not.toHaveBeenCalled();
  return request as typeof request & { agentId?: string; isAdmin?: boolean; isPlatformStaff?: boolean; isPartner?: boolean; freshAgentProof?: boolean };
}

describe('fleet worker MCP session', () => {
  it('can repeat authentication without gaining governance or fresh key proof', async () => {
    const token = await signer.signFleetSession(claims, Math.floor(Date.now() / 1000) + 120);
    for (let i = 0; i < 3; i++) {
      const request = await authenticate(token);
      expect(request.agentId).toBe(claims.agent_id);
      expect(request.isAdmin).toBe(false);
      expect(request.isPlatformStaff).toBe(false);
      expect(request.isPartner).toBe(false);
      expect(request.freshAgentProof).toBeUndefined();
      await expect(denyAgentContexts(request as never, {} as never)).rejects.toThrow();
    }
  });
  it.each(['policy_revision', 'key_digest', 'membership_id', 'operator_id', 'policy_id', 'agent_id'] as const)('rejects changed live %s', async field => {
    const token = await signer.signFleetSession(claims, Math.floor(Date.now() / 1000) + 120);
    const state = { ...claims, [field]: field === 'policy_revision' ? 2 : 'changed' };
    await expect(authenticate(token, state)).rejects.toThrow();
  });
  it('rejects missing, revoked or expired membership', async () => {
    const token = await signer.signFleetSession(claims, Math.floor(Date.now() / 1000) + 120);
    await expect(authenticate(token, claims, true)).rejects.toThrow();
  });
  it('cannot be minted beyond five minutes or used as an operator session', async () => {
    await expect(signer.signFleetSession(claims, Math.floor(Date.now() / 1000) + 301)).rejects.toThrow();
    const token = await signer.signFleetSession(claims, Math.floor(Date.now() / 1000) + 120);
    await expect(signer.verifyAccessOrSession(token)).rejects.toThrow();
  });
  it('limits a provisioner bearer to enrollment under its exact policy', async () => {
    const { membership_id: _member, ...base } = claims;
    const principal = { ...base, principal_kind: 'provisioner' as const };
    const token = await signer.signFleetSession(principal, Math.floor(Date.now() / 1000) + 120);
    expect((await authenticate(token, principal, false, '/v1/fleets/flp_policy/enroll')).agentId).toBe(claims.agent_id);
    await expect(authenticate(token, principal, false, '/v1/fleets/flp_other/enroll')).rejects.toThrow();
    await expect(authenticate(token, principal)).rejects.toThrow();
    await expect(authenticate(token, principal, false, '/v1/fleets/session')).rejects.toThrow();
    await expect(authenticate(token, principal, false, '/v1/fleets/flp_policy/revoke')).rejects.toThrow();
  });
});
