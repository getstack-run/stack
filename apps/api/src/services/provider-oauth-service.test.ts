import { describe, expect, it, vi } from 'vitest';
import { ForbiddenError } from '@stack/shared';
import { ConnectionPrincipalConflictError } from '@stack/vault';
import {
  createOAuthClient,
  ProviderOAuthService,
  type SystemAppScopes,
} from './provider-oauth-service.js';

const catalogService = {
  id: 'svc_fixture',
  provider: 'github',
  name: 'Fixture provider',
  oauth_auth_url: 'https://provider.example/authorize',
  oauth_token_url: 'https://provider.example/token',
  scopes_available: ['repo:read'],
  available: true,
};
const principal = {
  operatorId: 'op_fixture',
  operatorTier: 'developer' as const,
};
const appOne = {
  id: 'oa_fixture_one',
  client_id: 'client-fixture-one',
  client_secret: 'synthetic-secret-one',
  scopes: null,
};

function harness(overrides: Record<string, unknown> = {}) {
  let signed: Record<string, unknown> | undefined;
  const exchange = vi.fn(async () => 'synthetic-access-token');
  const getDecrypted = vi.fn(async () => appOne);
  const connect = vi.fn(async () => ({ id: 'scon_fixture' }));
  const deps = {
    catalog: {
      findByProvider: vi.fn(async () => catalogService),
      findById: vi.fn(async () => catalogService),
    },
    oauthApps: { getDecrypted },
    signer: {
      signProviderOAuthState: vi.fn(async (claims: Record<string, unknown>) => {
        signed = claims;
        return 'signed-state-fixture';
      }),
      verifyProviderOAuthState: vi.fn(async () => signed),
    },
    connections: {
      assertConnectionAccess: vi.fn(),
      assertConnectionPrincipal: vi.fn(async () => undefined),
      sharesAppGrant: vi.fn(async (_operatorId: string, _app: unknown) => false),
      connect,
    },
    systemOperatorId: 'op_stack_system',
    dashboardUrl: 'https://dashboard.example',
    createCodeVerifier: () => 'v'.repeat(64),
    createClient: vi.fn(() => ({
      requiresCodeVerifier: true,
      extraAuthParams: {},
      createAuthorizationURL: async () => new URL('https://provider.example/authorize'),
      validateAuthorizationCode: exchange,
    })),
    ...overrides,
  };
  return {
    service: new ProviderOAuthService(deps as never),
    deps,
    exchange,
    getDecrypted,
    connect,
    signed: () => signed,
  };
}

describe('ProviderOAuthService security boundary', () => {
  it('stores refresh credentials and absolute expiry with the exact consenting app binding', async () => {
    const h = harness({ createClient: vi.fn(() => ({
      requiresCodeVerifier: false, extraAuthParams: {},
      createAuthorizationURL: async () => new URL('https://provider.example/authorize'),
      validateAuthorizationCode: async () => ({ access_token: 'synthetic-access', refresh_token: 'synthetic-refresh',
        expires_at: '2030-01-01T00:00:00.000Z', scope: 'repo:read' }),
    })) });
    await h.service.authorize(principal, { provider: 'github', returnTo: 'services' });
    await h.service.callback(principal, { code: 'code', state: 'state' });
    const call = h.connect.mock.calls[0] as unknown as [string, string, { oauth_token: string }, unknown, unknown, object];
    const stored = { ...JSON.parse(call[2].oauth_token), oauth_app_binding: call[5] };
    const context = { serviceId: catalogService.id, provider: catalogService.provider, tokenUrl: catalogService.oauth_token_url };
    expect(stored).toMatchObject({ access_token: 'synthetic-access', refresh_token: 'synthetic-refresh',
      expires_at: '2030-01-01T00:00:00.000Z', scope: 'repo:read',
      oauth_app_binding: { id: appOne.id, owner_id: principal.operatorId, provider: 'github' } });
    expect(stored).not.toHaveProperty('client_secret');
    await expect(h.service.resolveRenewalClient(principal.operatorId, stored, context))
      .resolves.toEqual({ clientId: appOne.client_id, clientSecret: appOne.client_secret });
    h.getDecrypted.mockResolvedValueOnce({ ...appOne, id: 'replaced-app' });
    await expect(h.service.resolveRenewalClient(principal.operatorId, stored, context)).rejects.toMatchObject({ reconnectRequired: true });
    await expect(h.service.resolveRenewalClient('op_other', stored, context)).rejects.toMatchObject({ reconnectRequired: true });
    await expect(h.service.resolveRenewalClient(principal.operatorId, stored, { ...context, tokenUrl: 'https://other.example' }))
      .rejects.toMatchObject({ reconnectRequired: true });
  });

  it('preserves generic provider token metadata and excludes profile and ID token fields', async () => {
    const safeFetch = vi.fn(async () => new Response(JSON.stringify({ access_token: 'synthetic-access',
      refresh_token: 'synthetic-refresh', expires_in: 3600, scope: 'read', id_token: 'private-id-token', user: { email: 'private' } }),
    { headers: { 'content-type': 'application/json' } }));
    const client = createOAuthClient('generic_fixture', 'client', 'secret', 'https://dashboard.example/callback',
      'https://provider.example/authorize', 'https://provider.example/token', 'common', safeFetch as never);
    const result = await client.validateAuthorizationCode('code');
    expect(result).toMatchObject({ access_token: 'synthetic-access', refresh_token: 'synthetic-refresh', scope: 'read' });
    expect(result).not.toHaveProperty('id_token'); expect(result).not.toHaveProperty('user');
    expect(typeof result !== 'string' && Date.parse(String(result.expires_at))).toBeGreaterThan(Date.now());
  });

  it('fails closed when the tenant OAuth-app lookup errors and never tries the system app', async () => {
    const h = harness({
      oauthApps: { getDecrypted: vi.fn(async () => { throw new Error('synthetic lookup failure'); }) },
    });
    await expect(h.service.authorize(principal, {
      provider: 'github', returnTo: 'services',
    })).rejects.toMatchObject({ code: 'provider_lookup_failed' });
    expect(h.deps.oauthApps.getDecrypted).toHaveBeenCalledTimes(1);
  });

  it('binds the selected app and rejects a client/app swap before token exchange', async () => {
    const h = harness();
    await h.service.authorize(principal, { provider: 'github', returnTo: 'connect' });
    h.getDecrypted.mockResolvedValueOnce({ ...appOne, id: 'oa_fixture_replaced', client_id: 'client-fixture-two' });
    await expect(h.service.callback(principal, {
      code: 'code-fixture', state: 'signed-state-fixture', codeVerifier: 'v'.repeat(64),
    })).rejects.toMatchObject({ code: 'oauth_app_changed', returnTo: 'connect' });
    expect(h.exchange).not.toHaveBeenCalled();
    expect(h.connect).not.toHaveBeenCalled();
  });

  it('binds state to the initiating member session', async () => {
    const h = harness();
    await h.service.authorize({ ...principal, memberId: 'mem_one', memberRole: 'standard' }, {
      provider: 'github', returnTo: 'services',
    });
    await expect(h.service.callback({ ...principal, memberId: 'mem_two', memberRole: 'standard' }, {
      code: 'code-fixture', state: 'signed-state-fixture', codeVerifier: 'v'.repeat(64),
    })).rejects.toMatchObject({ code: 'session_mismatch' });
    expect(h.exchange).not.toHaveBeenCalled();
  });

  it('resolves custom OAuth definitions inside the initiating tenant only', async () => {
    const custom = {
      ...catalogService,
      id: 'svc_custom_fixture',
      provider: 'custom_fixture',
      available: false,
    };
    const findByProvider = vi.fn(async (operatorId: string, provider: string) =>
      operatorId === principal.operatorId && provider === custom.provider ? custom : undefined);
    const findById = vi.fn(async (operatorId: string, id: string) =>
      operatorId === principal.operatorId && id === custom.id ? custom : undefined);
    const h = harness({ catalog: { findByProvider, findById } });

    await expect(h.service.authorize(principal, {
      provider: custom.provider, returnTo: 'services', allowedHosts: ['api.example.com'],
    })).resolves.toMatchObject({ authorizationUrl: 'https://provider.example/authorize' });
    expect(findByProvider).toHaveBeenCalledWith(principal.operatorId, custom.provider);

    await expect(h.service.authorize({ ...principal, operatorId: 'op_other' }, {
      provider: custom.provider, returnTo: 'services', allowedHosts: ['api.example.com'],
    })).rejects.toMatchObject({ code: 'service_not_found' });
    expect(h.getDecrypted).toHaveBeenCalledTimes(1);

    await expect(h.service.callback(principal, {
      code: 'code-fixture', state: 'signed-state-fixture', codeVerifier: 'v'.repeat(64),
    })).resolves.toMatchObject({ provider: custom.provider });
    expect(findById).toHaveBeenCalledWith(principal.operatorId, custom.id);
  });

  it('rejects a mismatched PKCE verifier before token exchange', async () => {
    const h = harness();
    await h.service.authorize(principal, { provider: 'github', returnTo: 'services' });
    await expect(h.service.callback(principal, {
      code: 'code-fixture', state: 'signed-state-fixture', codeVerifier: 'x'.repeat(64),
    })).rejects.toMatchObject({ code: 'code_verifier_mismatch' });
    expect(h.exchange).not.toHaveBeenCalled();
  });

  it('normalizes token-exchange failures without storing a credential', async () => {
    const h = harness({
      createClient: vi.fn(() => ({
        requiresCodeVerifier: false,
        extraAuthParams: {},
        createAuthorizationURL: async () => new URL('https://provider.example/authorize'),
        validateAuthorizationCode: async () => { throw new Error('synthetic provider failure'); },
      })),
    });
    await h.service.authorize(principal, { provider: 'github', returnTo: 'services' });
    await expect(h.service.callback(principal, {
      code: 'code-fixture', state: 'signed-state-fixture',
    })).rejects.toMatchObject({ code: 'token_exchange_failed' });
    expect(h.connect).not.toHaveBeenCalled();
  });

  it('rejects loopback and metadata authorization endpoints for generic providers', async () => {
    for (const unsafe of ['https://127.0.0.1/authorize', 'https://169.254.169.254/latest/meta-data']) {
      const client = createOAuthClient(
        'generic_fixture', 'client-fixture', 'synthetic-secret',
        'https://dashboard.example/api/oauth/callback', unsafe,
        'https://provider.example/token',
      );
      await expect(client.createAuthorizationURL('state-fixture', ['read'])).rejects.toThrow(/non-public|blocked|IP/i);
    }
  });

  it('uses the bounded no-redirect transport for a generic token exchange', async () => {
    const safeFetch = vi.fn(async (_url: unknown, init: RequestInit) => {
      expect(init.redirect).toBe('error');
      return new Response(null, { status: 302, headers: { location: 'https://other.example/token' } });
    });
    const client = createOAuthClient(
      'generic_fixture', 'client-fixture', 'synthetic-secret',
      'https://dashboard.example/api/oauth/callback', 'https://provider.example/authorize',
      'https://provider.example/token', 'common', safeFetch as never,
    );
    await expect(client.validateAuthorizationCode('code-fixture')).rejects.toThrow(/rejected/);
    expect(safeFetch).toHaveBeenCalledOnce();
  });
});

describe('ProviderOAuthService connection principal', () => {
  const perMemberConflict = () => new ConnectionPrincipalConflictError(
    'service_per_member_mode',
    'Service "github" uses per-member mode and requires a member connection',
  );

  it('refuses an owner connect to a per-member service before the consent screen', async () => {
    const h = harness();
    h.deps.connections.assertConnectionPrincipal.mockRejectedValueOnce(perMemberConflict());
    await expect(h.service.authorize(principal, { provider: 'github', returnTo: 'connect' }))
      .rejects.toMatchObject({ code: 'service_per_member_mode', status: 409 });
    expect(h.deps.connections.assertConnectionPrincipal)
      .toHaveBeenCalledWith(principal.operatorId, 'github', undefined, undefined);
    expect(h.deps.signer.signProviderOAuthState).not.toHaveBeenCalled();
    expect(h.getDecrypted).not.toHaveBeenCalled();
  });

  it('carries a connection name inside the signed state, refuses a taken one before consent, and connects with it on return', async () => {
    const h = harness();
    await h.service.authorize(principal, { provider: 'github', returnTo: 'services', connectionName: 'Work' });
    expect(h.deps.connections.assertConnectionPrincipal).toHaveBeenCalledWith(principal.operatorId, 'github', undefined, 'Work');
    expect(h.deps.signer.signProviderOAuthState).toHaveBeenCalledWith(expect.objectContaining({ connection_name: 'Work' }));
    await h.service.callback(principal, { code: 'code-fixture', state: 'signed-state-fixture', codeVerifier: 'v'.repeat(64) });
    expect(h.connect).toHaveBeenCalledWith(
      principal.operatorId, principal.operatorTier, expect.objectContaining({ connection_name: 'Work' }),
      undefined, undefined, expect.anything(),
    );

    const taken = harness();
    taken.deps.connections.assertConnectionPrincipal.mockRejectedValueOnce(new ConnectionPrincipalConflictError('connection_name_taken', 'taken'));
    await expect(taken.service.authorize(principal, { provider: 'github', returnTo: 'services', connectionName: 'Work' }))
      .rejects.toMatchObject({ code: 'connection_name_taken', status: 409 });
    expect(taken.deps.signer.signProviderOAuthState).not.toHaveBeenCalled();
  });

  it('refuses a member whose access is limited to named connections before the consent screen', async () => {
    const h = harness();
    h.deps.connections.assertConnectionAccess.mockImplementationOnce(() => {
      throw new ForbiddenError('Service connection is outside this member access grant');
    });
    await expect(h.service.authorize(
      { ...principal, memberId: 'mem_one', memberRole: 'standard', allowedConnections: [] },
      { provider: 'github', returnTo: 'services' },
    )).rejects.toMatchObject({ code: 'connection_not_allowed', status: 403 });
    expect(h.deps.signer.signProviderOAuthState).not.toHaveBeenCalled();
  });

  it('re-checks on return and refuses before spending the authorization code', async () => {
    const h = harness();
    await h.service.authorize(principal, { provider: 'github', returnTo: 'connect' });
    h.deps.connections.assertConnectionPrincipal.mockRejectedValueOnce(perMemberConflict());
    await expect(h.service.callback(principal, {
      code: 'code-fixture', state: 'signed-state-fixture', codeVerifier: 'v'.repeat(64),
    })).rejects.toMatchObject({ code: 'service_per_member_mode', returnTo: 'connect' });
    expect(h.exchange).not.toHaveBeenCalled();
    expect(h.connect).not.toHaveBeenCalled();
  });

  it('reports a conflict raised while storing as a coded error, not as unavailable', async () => {
    const h = harness();
    await h.service.authorize(principal, { provider: 'github', returnTo: 'services' });
    h.connect.mockRejectedValueOnce(new ConnectionPrincipalConflictError(
      'connection_name_taken',
      'A connection of this service is already named "work": pass a different connection_name.',
    ));
    await expect(h.service.callback(principal, {
      code: 'code-fixture', state: 'signed-state-fixture', codeVerifier: 'v'.repeat(64),
    })).rejects.toMatchObject({ code: 'connection_name_taken', status: 409, returnTo: 'services' });
  });
});

/**
 * Which app a provider connects through: the customer's own app for the service
 * or its family, then the system operator's own for Slack and Google only.
 */
describe('ProviderOAuthService app resolution', () => {
  const gmailService = {
    ...catalogService, id: 'svc_gmail', provider: 'gmail',
    scopes_available: ['https://scopes.example/basic', 'https://scopes.example/read'],
  };
  const outlookService = { ...catalogService, id: 'svc_outlook', provider: 'outlook', scopes_available: ['Mail.Read'] };
  const jiraService = { ...catalogService, id: 'svc_jira', provider: 'jira', scopes_available: ['read:jira-work'] };

  /** Apps by `owner:provider`; anything else is not registered. `seen` holds the scopes each consent URL was built with. */
  function appsHarness(
    rows: Record<string, { tenant?: string }>,
    service: typeof catalogService,
    systemAppScopes?: SystemAppScopes,
    extra: Record<string, unknown> = {},
  ) {
    const seen: string[][] = [];
    const getDecrypted = vi.fn(async (owner: string, provider: string) => {
      const row = rows[`${owner}:${provider}`];
      return row ? { ...appOne, id: `oa_${owner}_${provider}`, ...row } : null;
    });
    const list = vi.fn(async (owner: string) => Object.keys(rows)
      .filter((key) => key.startsWith(`${owner}:`)).map((key) => ({ provider: key.slice(owner.length + 1) })));
    const createClient = vi.fn((..._args: unknown[]) => ({
      requiresCodeVerifier: false,
      extraAuthParams: {},
      createAuthorizationURL: async (_state: string, scopes: string[]) => {
        seen.push(scopes);
        return new URL('https://provider.example/authorize');
      },
      validateAuthorizationCode: async () => 'synthetic-access-token',
    }));
    const h = harness({
      catalog: { findByProvider: vi.fn(async () => service), findById: vi.fn(async () => service) },
      oauthApps: { getDecrypted, list },
      createClient,
      ...(systemAppScopes ? { systemAppScopes } : {}),
      ...extra,
    });
    return { ...h, createClient, seen };
  }

  it('lets one Google app of the customer cover every Google service', async () => {
    const h = appsHarness({ 'op_fixture:google': {} }, gmailService);
    await h.service.authorize(principal, { provider: 'gmail', returnTo: 'services' });
    expect(h.signed()).toMatchObject({ oauth_app_owner_id: 'op_fixture', oauth_app_provider: 'google' });
    expect(await h.service.hasResolvableApp('op_fixture', 'google_drive')).toBe(true);
    expect(await h.service.hasResolvableApp('op_fixture', 'google_calendar')).toBe(true);
  });

  it('prefers an app entered under the service itself over the family app', async () => {
    const h = appsHarness({ 'op_fixture:google': {}, 'op_fixture:gmail': {} }, gmailService);
    await h.service.authorize(principal, { provider: 'gmail', returnTo: 'services' });
    expect(h.signed()).toMatchObject({ oauth_app_owner_id: 'op_fixture', oauth_app_provider: 'gmail' });
  });

  it('uses the system operator\'s Google app when the customer has none, and never a retired system app', async () => {
    const google = appsHarness({ 'op_stack_system:google': {} }, gmailService);
    await google.service.authorize(principal, { provider: 'gmail', returnTo: 'services' });
    expect(google.signed()).toMatchObject({ oauth_app_owner_id: 'op_stack_system', oauth_app_provider: 'google' });

    const github = appsHarness({ 'op_stack_system:github': {} }, catalogService);
    await expect(github.service.authorize(principal, { provider: 'github', returnTo: 'services' }))
      .rejects.toMatchObject({ code: 'provider_not_configured' });
    expect(await github.service.hasResolvableApp('op_fixture', 'github')).toBe(false);
  });

  /** An invented scope of an invented provider: the tests of the mechanism name no real deployment's list. */
  const scope = (name: string) => `https://scopes.example/${name}`;
  /** A deployment's list for the system operator's Google app: two services named, any other allowed nothing, another app not limited. */
  const listedApp: SystemAppScopes = (appProvider, serviceProvider) => {
    if (appProvider !== 'google') return null;
    return serviceProvider === 'gmail' || serviceProvider === 'google_drive' ? [scope('basic')] : [];
  };

  it('holds the system operator\'s app to the deployment\'s list, in the claims and in the consent URL, and a customer\'s own app to nothing', async () => {
    const mail = { ...gmailService, scopes_available: [scope('read'), scope('basic'), scope('wide')] };
    const files = { ...catalogService, id: 'svc_drive', provider: 'google_drive', scopes_available: [scope('all'), scope('basic')] };
    for (const service of [mail, files]) {
      const system = appsHarness({ 'op_stack_system:google': {} }, service, listedApp);
      await system.service.authorize(principal, { provider: service.provider, returnTo: 'services' });
      expect(system.signed(), service.provider).toMatchObject({ scopes: [scope('basic')] });
      expect(system.seen[0], service.provider).toEqual([scope('basic')]);

      const own = appsHarness({ 'op_fixture:google': {} }, service, listedApp);
      await own.service.authorize(principal, { provider: service.provider, returnTo: 'services' });
      expect(own.signed(), service.provider).toMatchObject({ scopes: service.scopes_available });
      expect(own.seen[0], service.provider).toEqual(service.scopes_available);
    }
  });

  it('refuses a request that leaves no allowed scope, and a service the list does not name, before any consent', async () => {
    const files = { ...catalogService, id: 'svc_drive', provider: 'google_drive', scopes_available: [scope('all'), scope('basic')] };
    const onlyOutside = appsHarness({ 'op_stack_system:google': {} }, files, listedApp);
    await expect(onlyOutside.service.authorize(principal, {
      provider: 'google_drive', scopes: [scope('all')], returnTo: 'services',
    })).rejects.toMatchObject({ code: 'invalid_scopes' });
    expect(onlyOutside.seen).toHaveLength(0);

    const unnamed = { ...catalogService, id: 'svc_docs', provider: 'google_docs', scopes_available: [scope('docs')] };
    const notListed = appsHarness({ 'op_stack_system:google': {} }, unnamed, listedApp);
    await expect(notListed.service.authorize(principal, { provider: 'google_docs', returnTo: 'services' }))
      .rejects.toMatchObject({ code: 'invalid_scopes' });
  });

  it('says a connection exceeds its app only for the system operator\'s app, under a list, with a scope outside it', () => {
    const withList = harness({ systemAppScopes: listedApp }).service;
    const system = { owner_id: 'op_stack_system', provider: 'google' };
    expect(withList.exceedsAppScopes(system, 'gmail', [scope('basic')])).toBe(false);
    expect(withList.exceedsAppScopes(system, 'gmail', [scope('basic'), scope('wide')])).toBe(true);
    // A record that is empty cannot be shown to be inside the list.
    expect(withList.exceedsAppScopes(system, 'gmail', [])).toBe(true);
    expect(withList.exceedsAppScopes({ owner_id: 'op_fixture', provider: 'google' }, 'gmail', [])).toBe(false);
    expect(harness().service.exceedsAppScopes(system, 'gmail', [])).toBe(false);
    // A service the list does not name allows nothing through that app.
    expect(withList.exceedsAppScopes(system, 'google_docs', [scope('docs')])).toBe(true);
    // The customer's own app, an app the list does not limit, and a deployment with no list are never affected.
    expect(withList.exceedsAppScopes({ owner_id: 'op_fixture', provider: 'google' }, 'gmail', [scope('wide')])).toBe(false);
    expect(withList.exceedsAppScopes({ owner_id: 'op_stack_system', provider: 'slack' }, 'slack', ['chat:write'])).toBe(false);
    expect(harness().service.exceedsAppScopes(system, 'gmail', [scope('wide')])).toBe(false);
  });

  it('says which of a Google service\'s scopes STACK\'s own app will request, and nothing for any other service', () => {
    const withList = harness({ systemAppScopes: listedApp }).service;
    // The row's scopes held to the list, in the row's order.
    expect(withList.stackAppScopes('gmail', [scope('wide'), scope('basic')])).toEqual([scope('basic')]);
    // A Google service the list does not name: STACK's app asks for none of it.
    expect(withList.stackAppScopes('google_docs', [scope('docs')])).toEqual([]);
    // A service of another family, and an install with no list, have no answer.
    expect(withList.stackAppScopes('slack', ['chat:write'])).toBeNull();
    expect(withList.stackAppScopes('outlook', ['Mail.Read'])).toBeNull();
    expect(harness().service.stackAppScopes('gmail', [scope('basic')])).toBeNull();
  });

  it('refuses a consent that grants nothing of a listed app\'s scopes, and leaves another app\'s alone', async () => {
    const mail = { ...gmailService, scopes_available: [scope('basic')] };
    const revokeGrant = vi.fn(async (_appProvider: string, _token: string) => {});
    const grantNothing = (rows: Record<string, { tenant?: string }>, withList: boolean) => {
      const h = appsHarness(rows, mail, withList ? listedApp : undefined, { revokeGrant });
      h.createClient.mockImplementation(() => ({
        requiresCodeVerifier: false,
        extraAuthParams: {},
        createAuthorizationURL: async () => new URL('https://provider.example/authorize'),
        validateAuthorizationCode: async () => ({ access_token: 'synthetic-access', refresh_token: 'r', scope: 'openid' }),
      }) as never);
      return h;
    };
    const listed = grantNothing({ 'op_stack_system:google': {} }, true);
    await listed.service.authorize(principal, { provider: 'gmail', returnTo: 'services' });
    await expect(listed.service.callback(principal, { code: 'code', state: 'state' })).rejects.toMatchObject({ code: 'invalid_scopes' });
    expect(listed.connect).not.toHaveBeenCalled();
    // The tokens Google issued are not left on the person's account.
    expect(revokeGrant).toHaveBeenCalledWith('google', 'r');
    revokeGrant.mockClear();
    // A revoke that fails changes nothing about the refusal.
    revokeGrant.mockRejectedValueOnce(new Error('google down'));
    await listed.service.authorize(principal, { provider: 'gmail', returnTo: 'services' });
    await expect(listed.service.callback(principal, { code: 'code', state: 'state' })).rejects.toMatchObject({ code: 'invalid_scopes' });
    revokeGrant.mockClear();

    // A live connection of the operator through the same app may stand on the same grant: Google would end it too, so it is left.
    const shared = grantNothing({ 'op_stack_system:google': {} }, true);
    shared.deps.connections.sharesAppGrant.mockResolvedValueOnce(true);
    await shared.service.authorize(principal, { provider: 'gmail', returnTo: 'services' });
    await expect(shared.service.callback(principal, { code: 'code', state: 'state' })).rejects.toMatchObject({ code: 'invalid_scopes' });
    expect(shared.deps.connections.sharesAppGrant).toHaveBeenCalledWith(
      'op_fixture',
      { owner_id: 'op_stack_system', provider: 'google', client_id_hash: expect.any(String) },
    );
    expect(revokeGrant).not.toHaveBeenCalled();
    // A check that cannot be made counts as shared: nothing is revoked.
    const unreadable = grantNothing({ 'op_stack_system:google': {} }, true);
    unreadable.deps.connections.sharesAppGrant.mockRejectedValueOnce(new Error('kms down'));
    await unreadable.service.authorize(principal, { provider: 'gmail', returnTo: 'services' });
    await expect(unreadable.service.callback(principal, { code: 'code', state: 'state' })).rejects.toMatchObject({ code: 'invalid_scopes' });
    expect(revokeGrant).not.toHaveBeenCalled();

    const own = grantNothing({ 'op_fixture:google': {} }, true);
    await own.service.authorize(principal, { provider: 'gmail', returnTo: 'services' });
    await own.service.callback(principal, { code: 'code', state: 'state' });
    expect(own.connect).toHaveBeenCalledOnce();
    expect(revokeGrant).not.toHaveBeenCalled();
  });

  it('narrows nothing when the deployment names no list, or names none for the app', async () => {
    const files = { ...catalogService, id: 'svc_drive', provider: 'google_drive', scopes_available: [scope('all'), scope('basic')] };
    const install = appsHarness({ 'op_stack_system:google': {} }, files);
    await install.service.authorize(principal, { provider: 'google_drive', returnTo: 'services' });
    expect(install.seen[0]).toEqual(files.scopes_available);
    expect(install.signed()).toMatchObject({ scopes: files.scopes_available });

    const slack = { ...catalogService, id: 'svc_slack', provider: 'slack', scopes_available: ['chat:write', 'channels:read'] };
    const other = appsHarness({ 'op_stack_system:slack': {} }, slack, listedApp);
    await other.service.authorize(principal, { provider: 'slack', returnTo: 'services' });
    expect(other.seen[0]).toEqual(slack.scopes_available);
  });

  it('keeps the system operator\'s Slack app', async () => {
    const slack = { ...catalogService, id: 'svc_slack', provider: 'slack' };
    const h = appsHarness({ 'op_stack_system:slack': {} }, slack);
    await h.service.authorize(principal, { provider: 'slack', returnTo: 'services' });
    expect(h.signed()).toMatchObject({ oauth_app_owner_id: 'op_stack_system', oauth_app_provider: 'slack' });
  });

  it('reports which services resolve, and which through an app of the customer\'s own', async () => {
    const h = appsHarness({ 'op_fixture:microsoft': {}, 'op_stack_system:google': {}, 'op_stack_system:github': {} }, gmailService);
    const result = await h.service.appAvailability('op_fixture', ['outlook', 'microsoft_teams', 'gmail', 'github', 'jira']);
    expect([...result.available].sort()).toEqual(['gmail', 'microsoft_teams', 'outlook']);
    expect([...result.own].sort()).toEqual(['microsoft_teams', 'outlook']);
  });

  it('signs a single-tenant Microsoft app in against its own tenant', async () => {
    const h = appsHarness({ 'op_fixture:microsoft': { tenant: 'contoso.onmicrosoft.com' } }, outlookService);
    await h.service.authorize(principal, { provider: 'outlook', returnTo: 'services' });
    // createOAuthClient(provider, id, secret, redirect, authUrl, tokenUrl, tenant)
    expect(h.createClient.mock.calls[0]?.[6]).toBe('contoso.onmicrosoft.com');
    // The connection keeps the scopes the person chose.
    expect(h.signed()).toMatchObject({ scopes: ['Mail.Read'] });
  });

  it('asks Atlassian and Microsoft for offline_access so the connection gets a refresh token', async () => {
    for (const [service, expected] of [
      [jiraService, ['read:jira-work', 'offline_access']],
      [outlookService, ['Mail.Read', 'offline_access']],
    ] as const) {
      const seen: string[][] = [];
      const h = harness({
        catalog: { findByProvider: vi.fn(async () => service), findById: vi.fn(async () => service) },
        createClient: vi.fn(() => ({
          requiresCodeVerifier: false,
          extraAuthParams: {},
          createAuthorizationURL: async (_state: string, scopes: string[]) => {
            seen.push(scopes);
            return new URL('https://provider.example/authorize');
          },
          validateAuthorizationCode: async () => 'synthetic-access-token',
        })),
      });
      await h.service.authorize(principal, { provider: service.provider, returnTo: 'services' });
      expect(seen[0]).toEqual(expected);
      expect(h.signed()).toMatchObject({ scopes: [service.scopes_available[0]] });
    }
  });

  it('refuses to renew through a system app STACK no longer runs, as reconnect with the reason', async () => {
    const h = harness();
    const fields = {
      access_token: 'a',
      refresh_token: 'r',
      oauth_app_binding: {
        id: 'oa_old', owner_id: 'op_stack_system', provider: 'github', client_id_hash: 'x',
        service_id: catalogService.id, connection_provider: 'github', token_url: catalogService.oauth_token_url,
      },
    };
    expect(h.service.isRetiredBinding(fields.oauth_app_binding)).toBe(true);
    expect(h.service.isRetiredBinding({ ...fields.oauth_app_binding, provider: 'google' })).toBe(false);
    expect(h.service.isRetiredBinding({ ...fields.oauth_app_binding, provider: 'slack' })).toBe(false);
    expect(h.service.isRetiredBinding({ ...fields.oauth_app_binding, owner_id: 'op_fixture' })).toBe(false);
    await expect(h.service.resolveRenewalClient('op_fixture', fields, {
      serviceId: catalogService.id, provider: 'github', tokenUrl: catalogService.oauth_token_url,
    })).rejects.toMatchObject({ reconnectRequired: true, reason: 'stack_oauth_app_retired' });
    expect(h.getDecrypted).not.toHaveBeenCalled();
  });

  it('returns the tenant of the app that obtained consent for renewal', async () => {
    const h = appsHarness({ 'op_fixture:microsoft': { tenant: 'contoso.onmicrosoft.com' } }, outlookService);
    await h.service.authorize(principal, { provider: 'outlook', returnTo: 'services' });
    await h.service.callback(principal, { code: 'code', state: 'state' });
    const call = h.connect.mock.calls[0] as unknown as [string, string, { oauth_token: string }, unknown, unknown, object];
    const stored = { ...JSON.parse(call[2].oauth_token), oauth_app_binding: call[5] };
    await expect(h.service.resolveRenewalClient('op_fixture', stored, {
      serviceId: outlookService.id, provider: 'outlook', tokenUrl: outlookService.oauth_token_url,
    })).resolves.toMatchObject({ tenant: 'contoso.onmicrosoft.com' });
  });
});
