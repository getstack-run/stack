import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { registerAuthorityRoutes } from './authority.js';
import { fakeEntitlements } from '../test/entitlements.js';

function services(activateProfileVersion: (...args: unknown[]) => Promise<unknown>) {
  return {
    entitlements: fakeEntitlements(), operator: {
      authenticateByApiKey: vi.fn(async () => ({
        id: 'op_one',
        tier: 'pro',
        status: 'active',
        is_admin: true,
        is_platform_staff: false,
        is_partner: false,
        stripe_customer_id: null,
      })),
    },
    governanceApprovals: { consumeAuthorityIdempotently: vi.fn(async () => undefined) },
    authority: { activateProfileVersion },
    audit: { write: vi.fn(async () => undefined) },
  };
}

describe('authority profile routes', () => {
  it('activates a receiver profile through the generic profile endpoint', async () => {
    const activateProfileVersion = vi.fn(async () => ({
      id: 'apv_receiver_one',
      profile_kind: 'receiver',
      status: 'active',
    }));
    const app = Fastify();
    registerAuthorityRoutes(app, services(activateProfileVersion) as never);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/authority/profile-versions/apv_receiver_one/activate',
      headers: {
        authorization: 'Bearer sk_live_test',
        'idempotency-key': 'activate-receiver-profile-one',
        'x-governance-approval': 'gov_receiver_profile_one',
      },
      payload: { profile_kind: 'receiver' },
    });
    await app.close();

    expect(response.statusCode).toBe(200);
    expect(activateProfileVersion).toHaveBeenCalledWith(
      'op_one',
      'receiver',
      'apv_receiver_one',
      'activate-receiver-profile-one',
    );
  });

  it('does not expose duplicate receiver-nested profile mutation routes', async () => {
    const app = Fastify();
    registerAuthorityRoutes(app, services(vi.fn()) as never);

    for (const url of [
      '/v1/authority/receivers/rcv_one/profile-versions',
      '/v1/authority/receivers/rcv_one/profile-versions/apv_receiver_one/activate',
    ]) {
      const response = await app.inject({ method: 'POST', url, payload: {} });
      expect(response.statusCode).toBe(404);
    }
    await app.close();
  });
});
