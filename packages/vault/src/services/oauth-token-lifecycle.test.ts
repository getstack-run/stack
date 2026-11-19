import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { assertPublicUrl } from '@stack/shared';
import { maybeFetchClientCredentialsToken, maybeRefreshAccessToken, OAuthLifecycleError } from './oauth-token-lifecycle.js';

vi.mock('@stack/shared', () => ({
  assertPublicUrl: vi.fn(),
  publicFetch: (input: string, init: RequestInit) => globalThis.fetch(input, init),
  ConflictError: class extends Error {},
}));

describe('durable OAuth renewal', () => {
  const fields = { access_token: 'old', refresh_token: 'rotation-one', expires_at: 1 };
  let fetchMock: ReturnType<typeof vi.fn>;
  let persist: ReturnType<typeof vi.fn<() => Promise<void>>>;
  const args = () => ({ fields, oauthTokenUrl: 'https://identity.example.test/token',
    connectionId: 'conn', operatorId: 'operator', provider: 'fixture', deps: { persistRefreshed: persist } });
  beforeEach(() => {
    vi.mocked(assertPublicUrl).mockImplementation(async value => new URL(value));
    fetchMock = vi.fn(); persist = vi.fn(async () => {});
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.clearAllMocks(); });

  it('persists rotated access/refresh tokens and exact expiry before releasing them', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ access_token: 'new', refresh_token: 'rotation-two', expires_in: 120, scope: 'read' })));
    const result = await maybeRefreshAccessToken(args());
    expect(result).toEqual({ access_token: 'new', refresh_token: 'rotation-two', expires_at: new Date(1_120_000).toISOString(), scope: 'read' });
    expect(persist).toHaveBeenCalledWith('conn', 'operator', 'fixture', result, new Date(1_120_000));
    expect(fields.refresh_token).toBe('rotation-one');
  });

  it('preserves a non-rotating refresh token and missing scope', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ access_token: 'new', expires_in: 3600 })));
    expect(await maybeRefreshAccessToken({ ...args(), fields: { ...fields, scope: 'read write' } }))
      .toMatchObject({ refresh_token: 'rotation-one', scope: 'read write' });
  });

  it('never releases a token when encrypted persistence fails', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ access_token: 'new', refresh_token: 'new-refresh', expires_in: 3600 })));
    persist.mockRejectedValue(new Error('synthetic persistence failure'));
    await expect(maybeRefreshAccessToken(args())).rejects.toThrow('synthetic persistence failure');
  });

  it('refuses to exchange without durable persistence', async () => {
    await expect(maybeRefreshAccessToken({ ...args(), deps: {} })).rejects.toBeInstanceOf(OAuthLifecycleError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(['invalid_grant', 'invalid_client', 'token_revoked'])('classifies %s as reconnect without exposing provider data', async error => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error, error_description: 'secret-canary' }), { status: 400 }));
    const result = await maybeRefreshAccessToken(args()).catch(error => error);
    expect(result).toMatchObject({ reconnectRequired: true });
    expect(result.message).not.toContain('secret-canary');
    expect(persist).not.toHaveBeenCalled();
  });

  it('fails closed on an outage without asking for consent', async () => {
    fetchMock.mockRejectedValue(new Error('secret-canary'));
    await expect(maybeRefreshAccessToken(args())).rejects.toMatchObject({ reconnectRequired: false });
    expect(persist).not.toHaveBeenCalled();
  });

  it('refuses unsafe endpoints before sending secrets', async () => {
    vi.mocked(assertPublicUrl).mockRejectedValue(new Error('unsafe'));
    await expect(maybeRefreshAccessToken(args())).rejects.toMatchObject({ reconnectRequired: true });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([0, -1, '3600', null])('rejects invalid refresh expiry %s', async expires_in => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ access_token: 'new', expires_in })));
    await expect(maybeRefreshAccessToken(args())).rejects.toBeInstanceOf(OAuthLifecycleError);
    expect(persist).not.toHaveBeenCalled();
  });

  it('renews client credentials from encrypted fields and persists the successor', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ access_token: 'application-token', expires_in: 3600 })));
    const result = await maybeFetchClientCredentialsToken({ fields: {
      client_id: 'id', client_secret: 'secret', access_token: 'expired', expires_at: 1,
      cc_token_url: 'https://identity.example.test/token', cc_scope: 'read',
    }, defaultTokenUrl: '', connectionId: 'conn', operatorId: 'operator', provider: 'fixture', deps: { persistRefreshed: persist } });
    expect(result.access_token).toBe('application-token');
    expect(persist).toHaveBeenCalledOnce();
    expect(new URLSearchParams(fetchMock.mock.calls[0]![1].body).get('grant_type')).toBe('client_credentials');
  });

  it('uses a key set with a client id and secret but no token endpoint as stored, never marking it for reconnect', async () => {
    // STACK's own logins in the system vault (a cloud sandbox provider, a card provider) carry client_id and client_secret for the
    // provider's own sign-in; with no token endpoint they are not an OAuth client-credentials login of STACK's.
    const keySet = { tenant_id: 'tenant', client_id: 'id', client_secret: 'secret', subscription_id: 'sub' };
    expect(await maybeFetchClientCredentialsToken({ fields: keySet, defaultTokenUrl: '', connectionId: 'conn', operatorId: 'operator', provider: 'custom_fixture_cloud', deps: { persistRefreshed: persist } })).toBe(keySet);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(persist).not.toHaveBeenCalled();
  });

  it('still asks for a reconnect when an application token has expired and no token endpoint can renew it', async () => {
    const expired = { client_id: 'id', client_secret: 'secret', access_token: 'old', expires_at: 1 };
    await expect(maybeFetchClientCredentialsToken({ fields: expired, defaultTokenUrl: '', connectionId: 'conn', operatorId: 'operator', provider: 'fixture', deps: { persistRefreshed: persist } }))
      .rejects.toMatchObject({ reconnectRequired: true });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('reuses a fresh durable application token without a provider request', async () => {
    const fresh = { client_id: 'id', client_secret: 'secret', access_token: 'fresh', expires_at: Date.now() + 300_000 };
    expect(await maybeFetchClientCredentialsToken({ fields: fresh, defaultTokenUrl: '', connectionId: 'conn', operatorId: 'operator', provider: 'fixture', deps: {} })).toBe(fresh);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
