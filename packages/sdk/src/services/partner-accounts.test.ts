import { describe, expect, it, vi } from 'vitest';
import type { HttpClient } from '../client.js';
import { PartnerAccountsService, mintOutboundPassportImpl } from './partner-accounts.js';

describe('outbound account passport', () => {
  it('binds the minted passport to the given account Mission', async () => {
    const post = vi.fn().mockResolvedValue({ token: 't', jti: 'pas_a', expires_at: '2026-10-01T12:00:00.000Z' });
    const service = new PartnerAccountsService({ post } as unknown as HttpClient);
    const minted = await mintOutboundPassportImpl(service, 'op_account', 'agt_a', { mission_id: 'ms_a' });
    expect(post).toHaveBeenCalledWith('/v1/partner/accounts/op_account/passports/issue',
      expect.objectContaining({ agent_id: 'agt_a', mission_ids: ['ms_a'] }));
    expect(minted.header_value).toBe('t');
  });
});

describe('account webhook signing setup', () => {
  it('encodes account and endpoint IDs and sends the secret only in the body', async () => {
    const put = vi.fn().mockResolvedValue({ configured: true });
    const service = new PartnerAccountsService({ put } as unknown as HttpClient);
    expect(await service.setInboundWebhookSigningSecret('account fixture', 'wh/fixture', 'synthetic-fixture'))
      .toEqual({ configured: true });
    expect(put).toHaveBeenCalledWith('/v1/partner/accounts/account%20fixture/inbound-webhooks/wh%2Ffixture/provider-signing-secret', { signing_secret: 'synthetic-fixture' });
    await service.setInboundWebhookSigningSecret('account', 'wh', 'synthetic-provider', 'synthetic-downstream');
    expect(put).toHaveBeenLastCalledWith('/v1/partner/accounts/account/inbound-webhooks/wh/provider-signing-secret', { signing_secret: 'synthetic-provider', downstream_signing_secret: 'synthetic-downstream' });
  });
});

describe('partner-managed account lifecycle', () => {
  it('opens an account with only the partner reference; accounts carry no plan of their own', async () => {
    const created = {
      account_id: 'op_account',
      external_ref: 'cust_1',
      billing: 'partner' as const,
      status: 'active',
      created: true,
      created_at: '2026-09-29T00:00:00.000Z',
      api_key: 'synthetic-key',
    };
    const post = vi.fn().mockResolvedValue(created);
    const service = new PartnerAccountsService({ post } as unknown as HttpClient);
    const result = await service.create({ external_ref: 'cust_1' });
    expect(post).toHaveBeenCalledWith('/v1/partner/accounts', { external_ref: 'cust_1' });
    expect(result.billing).toBe('partner');
    // @ts-expect-error - `tier` is refused by the API (TENANT_TIER_NOT_ALLOWED) and not part of the input type.
    const invalid: Parameters<PartnerAccountsService['create']>[0] = { external_ref: 'x', tier: 'pro' };
    expect(invalid).toBeDefined();
    // @ts-expect-error - the reference is required: it is the idempotency key.
    const missing: Parameters<PartnerAccountsService['create']>[0] = {};
    expect(missing).toBeDefined();
  });

  it('returns the account list with its share of the partner pool, and finds one by reference', async () => {
    const account = {
      account_id: 'op_account',
      external_ref: 'cust_1',
      billing: 'partner' as const,
      status: 'active',
      created_at: '2026-09-01T00:00:00.000Z',
      deleted_at: null,
      invite: { status: 'none' as const },
      usage: { period: '2026-09', actions: 42 },
    };
    const get = vi.fn().mockResolvedValue({ accounts: [account] });
    const service = new PartnerAccountsService({ get } as unknown as HttpClient);
    const accounts = await service.list();
    expect(get).toHaveBeenCalledWith('/v1/partner/accounts');
    expect(accounts[0]?.usage).toEqual({ period: '2026-09', actions: 42 });
    await service.list({ external_ref: 'cust 1' });
    expect(get).toHaveBeenLastCalledWith('/v1/partner/accounts?external_ref=cust%201');
  });

  it('surfaces the revoke cascade counts', async () => {
    const del = vi.fn().mockResolvedValue({ transitioned: true, webhooks_revoked: 2, passports_revoked: 3 });
    const service = new PartnerAccountsService({ delete: del } as unknown as HttpClient);
    const result = await service.revoke('op_account');
    expect(del).toHaveBeenCalledWith('/v1/partner/accounts/op_account');
    expect(result).toEqual({ transitioned: true, webhooks_revoked: 2, passports_revoked: 3 });
  });

  it('replaces a lost key', async () => {
    const post = vi.fn().mockResolvedValue({ account_id: 'op_account', api_key: 'synthetic-new' });
    const service = new PartnerAccountsService({ post } as unknown as HttpClient);
    expect(await service.rotateKey('op_account')).toEqual({ account_id: 'op_account', api_key: 'synthetic-new' });
    expect(post).toHaveBeenCalledWith('/v1/partner/accounts/op_account/rotate-key', {});
  });
});

describe('inviting and releasing the customer', () => {
  it('invites the customer with the address given at that moment', async () => {
    const post = vi.fn().mockResolvedValue({ status: 'invited', expires_at: '2026-11-01T00:00:00.000Z' });
    const service = new PartnerAccountsService({ post } as unknown as HttpClient);
    await service.invite('op_account', { email: 'customer@example.com' });
    expect(post).toHaveBeenCalledWith('/v1/partner/accounts/op_account/invite', { email: 'customer@example.com' });
  });

  it('releases the account and reads the release, also after the account is no longer the partner\'s', async () => {
    const record = {
      account_id: 'op_account', external_ref: 'cust_1', status: 'pending' as const, requested_by: 'partner' as const,
      requested_at: '2026-10-25T00:00:00.000Z', expires_at: '2026-11-01T00:00:00.000Z', completed_at: null,
    };
    const post = vi.fn().mockResolvedValue({ release: record });
    const get = vi.fn().mockResolvedValue({ release: { ...record, status: 'completed', completed_at: '2026-10-26T00:00:00.000Z' } });
    const del = vi.fn().mockResolvedValue({ cancelled: true });
    const service = new PartnerAccountsService({ post, get, delete: del } as unknown as HttpClient);
    expect(await service.release('op_account')).toEqual(record);
    expect(post).toHaveBeenCalledWith('/v1/partner/accounts/op_account/release', {});
    await service.release('op_account', { email: 'customer@example.com' });
    expect(post).toHaveBeenLastCalledWith('/v1/partner/accounts/op_account/release', { email: 'customer@example.com' });
    expect((await service.getRelease('op_account')).status).toBe('completed');
    expect(await service.cancelRelease('op_account')).toEqual({ cancelled: true });
    expect(del).toHaveBeenCalledWith('/v1/partner/accounts/op_account/release');
    get.mockResolvedValueOnce({ releases: [record] });
    expect(await service.listReleases()).toEqual([record]);
    expect(get).toHaveBeenLastCalledWith('/v1/partner/releases');
  });
});
