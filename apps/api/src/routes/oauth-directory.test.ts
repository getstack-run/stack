import Fastify from 'fastify';
import { createHash } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { decodeJwt } from 'jose';
import { eq, inArray } from 'drizzle-orm';
import {
  createDb,
  oauthAuthorizationCodes,
  oauthClients,
  oauthRefreshTokens,
  operators,
  OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
  OAUTH_DEFAULT_SCOPE,
  OAUTH_DIRECTORY_DEFAULT_SCOPES,
  OAUTH_RESOURCE_MCP,
  OAUTH_RESOURCE_MCP_DIRECTORY,
} from '@stack/shared';
import { PassportSigner } from '@stack/vault';
import { env } from '../config/env.js';
import { createClientMetadataResolver, type ClientMetadataResolver } from '../lib/oauth-cimd.js';
import { issueAuthorizationCode } from '../services/oauth-grant-state.js';
import { audienceForResource, defaultScopeForResource, scopeForResource, stripRetiredScopes } from './oauth-helpers.js';
import { registerOAuthRoutes } from './oauth.js';

const CLIENT_ID = 'https://connector.example/oauth/client.json';
const REDIRECT = 'https://connector.example/callback';

function metadataDocument(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLIENT_ID,
    client_name: 'Example Connector',
    redirect_uris: [REDIRECT],
    grant_types: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_method: 'none',
    ...overrides,
  };
}

function resolverServing(body: unknown): ClientMetadataResolver {
  return createClientMetadataResolver({
    fetchImpl: async () => new Response(JSON.stringify(body), { status: 200 }),
  });
}

const previousOAuthEnabled = env.OAUTH_ENABLED;
const apps: ReturnType<typeof Fastify>[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});
afterAll(() => {
  (env as { OAUTH_ENABLED: string }).OAUTH_ENABLED = previousOAuthEnabled;
});

/** In-memory oauth_clients table, enough for GET /oauth/authorize. */
function fakeServices(existing: Array<Record<string, unknown>> = []) {
  const rows = new Map(existing.map((row) => [row['id'] as string, row]));
  const consent = vi.fn(async (_sub: string, claims: Record<string, unknown>) => `consent.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`);
  const services = {
    db: {
      query: {
        oauthClients: {
          // Drizzle passes an SQL expression; the fake only ever holds the ids
          // used by these tests, so return the single row under test.
          findFirst: vi.fn(async () => [...rows.values()][0]),
        },
      },
      insert: vi.fn(() => ({
        values: (values: Record<string, unknown>) => ({
          onConflictDoUpdate: async () => {
            rows.set(values['id'] as string, values);
          },
        }),
      })),
      update: vi.fn(() => ({
        set: (values: Record<string, unknown>) => ({
          where: async () => {
            const [id] = [...rows.keys()];
            rows.set(id!, { ...rows.get(id!), ...values });
          },
        }),
      })),
    },
    signer: { signOAuthConsentToken: consent },
  };
  return { services, rows, consent };
}

async function makeApp(services: unknown, clientMetadata: ClientMetadataResolver) {
  (env as { OAUTH_ENABLED: string }).OAUTH_ENABLED = 'true';
  const app = Fastify();
  apps.push(app);
  registerOAuthRoutes(app, services as never, { clientMetadata });
  await app.ready();
  return app;
}

function authorizeUrl(params: Record<string, string>) {
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    code_challenge: 'x'.repeat(43),
    code_challenge_method: 'S256',
    resource: OAUTH_RESOURCE_MCP_DIRECTORY,
    scope: 'agents:read',
    state: 's1',
    ...params,
  });
  return `/oauth/authorize?${q.toString()}`;
}

describe('authorization server metadata', () => {
  it('advertises Client ID Metadata Documents, public clients and PKCE S256', async () => {
    const { services } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' });
    const body = response.json();
    expect(body.client_id_metadata_document_supported).toBe(true);
    expect(body.token_endpoint_auth_methods_supported).toContain('none');
    expect(body.code_challenge_methods_supported).toEqual(['S256']);
    expect(body.registration_endpoint).toMatch(/\/oauth\/register$/);
  });
});

describe('GET /oauth/authorize with a Client ID Metadata Document', () => {
  it('accepts a valid document, stores a public client row and continues to consent', async () => {
    const { services, rows, consent } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({ method: 'GET', url: authorizeUrl({}) });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toMatch(/\/oauth\/consent\?state=/);
    expect(rows.get(CLIENT_ID)).toMatchObject({
      id: CLIENT_ID,
      client_type: 'public',
      client_secret_hash: null,
      token_endpoint_auth_method: 'none',
      metadata_url: CLIENT_ID,
      redirect_uris: [REDIRECT],
    });
    expect(consent).toHaveBeenCalledWith('pending', expect.objectContaining({
      client_id: CLIENT_ID,
      resource: OAUTH_RESOURCE_MCP_DIRECTORY,
    }));
  });

  it('rejects a document whose client_id does not match its URL', async () => {
    const { services, rows } = fakeServices();
    const app = await makeApp(
      services,
      resolverServing(metadataDocument({ client_id: 'https://attacker.example/client.json' })),
    );
    const response = await app.inject({ method: 'GET', url: authorizeUrl({}) });
    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe('invalid_client');
    expect(rows.size).toBe(0);
  });

  it('rejects a redirect_uri that the document does not list', async () => {
    const { services, consent } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({
      method: 'GET',
      url: authorizeUrl({ redirect_uri: 'https://attacker.example/callback' }),
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'invalid_request', error_description: 'redirect_uri not registered' });
    expect(consent).not.toHaveBeenCalled();
  });

  it('rejects a client_id URL that points at a private address', async () => {
    const { services, rows } = fakeServices();
    // The real resolver and SSRF guard: no fetch is injected.
    const app = await makeApp(services, createClientMetadataResolver());
    for (const clientId of ['https://127.0.0.1/client.json', 'https://10.1.2.3/client.json', 'https://169.254.169.254/latest']) {
      const response = await app.inject({ method: 'GET', url: authorizeUrl({ client_id: clientId }) });
      expect(response.statusCode, clientId).toBe(400);
      expect(response.json().error, clientId).toBe('invalid_client');
    }
    expect(rows.size).toBe(0);
  });

  it('never overwrites a client row that was not created from a metadata document', async () => {
    const { services, rows } = fakeServices([{ id: CLIENT_ID, metadata_url: null, redirect_uris: ['https://legit.example/cb'] }]);
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({ method: 'GET', url: authorizeUrl({}) });
    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe('invalid_client');
    expect(rows.get(CLIENT_ID)?.['redirect_uris']).toEqual(['https://legit.example/cb']);
  });
});

describe('directory resource scope ceiling', () => {
  it('drops scopes the directory resource does not allow', async () => {
    const { services, consent } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({
      method: 'GET',
      url: authorizeUrl({ scope: 'agents:read proxy:write skills:invoke credentials:read missions:write' }),
    });
    expect(response.statusCode).toBe(302);
    expect(consent).toHaveBeenCalledWith('pending', expect.objectContaining({ scope: 'agents:read missions:write' }));
  });

  it('grants the directory default scope set when a directory request names no scope', async () => {
    const { services, consent } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const params = new URLSearchParams(authorizeUrl({}).split('?')[1]);
    params.delete('scope');
    const response = await app.inject({ method: 'GET', url: `/oauth/authorize?${params.toString()}` });
    expect(response.statusCode).toBe(302);
    expect(consent).toHaveBeenCalledWith('pending', expect.objectContaining({
      scope: OAUTH_DIRECTORY_DEFAULT_SCOPES.join(' '),
    }));
    expect(defaultScopeForResource(OAUTH_RESOURCE_MCP)).toBe(OAUTH_DEFAULT_SCOPE);
  });

  it('refuses a request whose every scope is outside the ceiling', async () => {
    const { services } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({ method: 'GET', url: authorizeUrl({ scope: 'proxy:write admin' }) });
    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe('invalid_scope');
  });

  it('leaves the standard MCP and API resources unclamped', () => {
    expect(scopeForResource(OAUTH_RESOURCE_MCP, 'proxy:write skills:invoke')).toBe('proxy:write skills:invoke');
    expect(scopeForResource(OAUTH_RESOURCE_MCP_DIRECTORY, 'proxy:write skills:invoke')).toBeNull();
    expect(audienceForResource(OAUTH_RESOURCE_MCP_DIRECTORY)).toBe(OAUTH_ACCESS_TOKEN_AUDIENCE_MCP);
    expect(audienceForResource('https://mcp.getstack.run/directory/')).toBeNull();
  });
});

describe('scopes the published CLI still requests but the server no longer knows', () => {
  it('accepts the request and consents to it without the retired scope', async () => {
    const { services, consent } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({
      method: 'GET',
      url: authorizeUrl({ resource: OAUTH_RESOURCE_MCP, scope: 'agents:read partner-grants:read proxy:write' }),
    });
    expect(response.statusCode).toBe(302);
    expect(consent).toHaveBeenCalledWith('pending', expect.objectContaining({ scope: 'agents:read proxy:write' }));
  });

  it('treats a request for only a retired scope as a request for no scope', async () => {
    const { services } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const retired = await app.inject({
      method: 'GET',
      url: authorizeUrl({ resource: OAUTH_RESOURCE_MCP, scope: 'partner-grants:read' }),
    });
    const empty = await app.inject({ method: 'GET', url: authorizeUrl({ resource: OAUTH_RESOURCE_MCP, scope: '' }) });
    expect(retired.statusCode).toBe(empty.statusCode);
    expect(retired.json()).toEqual(empty.json());
  });

  it('strips only the retired scopes', () => {
    expect(stripRetiredScopes('a:read partner-grants:read b:write partner-grants:write')).toBe('a:read b:write');
    expect(stripRetiredScopes('partner-grants:read')).toBe('');
    expect(stripRetiredScopes('agents:read proxy:write')).toBe('agents:read proxy:write');
  });
});

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('token binding to the requested resource (database)', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_oauth_dir_${suffix}`;
  const clientId = `https://connector-${suffix}.example/oauth/client.json`;
  const redirect = `https://connector-${suffix}.example/callback`;
  const verifier = `verifier-${suffix}-${'v'.repeat(40)}`;
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const signer = new PassportSigner();
  const app = Fastify();

  beforeAll(async () => {
    (env as { OAUTH_ENABLED: string }).OAUTH_ENABLED = 'true';
    await signer.init();
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@oauth-test.invalid`,
      tier: 'business',
      api_key_hash: `hash_${suffix}`,
    } as typeof operators.$inferInsert);
    registerOAuthRoutes(app, {
      db,
      signer,
      audit: { write: vi.fn(async () => {}) },
      securityEvent: { record: vi.fn(async () => null) },
      analytics: { fireOnce: vi.fn() },
    } as never, {
      clientMetadata: createClientMetadataResolver({
        fetchImpl: async () => new Response(JSON.stringify({
          client_id: clientId,
          client_name: 'Binding test connector',
          redirect_uris: [redirect],
          token_endpoint_auth_method: 'none',
        }), { status: 200 }),
      }),
    });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    await db.delete(oauthRefreshTokens).where(eq(oauthRefreshTokens.operator_id, operatorId));
    await db.delete(oauthAuthorizationCodes).where(eq(oauthAuthorizationCodes.operator_id, operatorId));
    await db.delete(oauthClients).where(inArray(oauthClients.id, [clientId]));
    await db.delete(operators).where(eq(operators.id, operatorId));
  });

  async function tokenFor(resource: string, scope: string) {
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code', client_id: clientId, redirect_uri: redirect,
        code_challenge: challenge, code_challenge_method: 'S256', resource, scope, state: 's',
      }).toString()}`,
    });
    expect(authorize.statusCode).toBe(302);
    const issued = await issueAuthorizationCode(db, {
      operatorId, clientId, memberId: null, redirectUri: redirect, scope: scopeForResource(resource, scope)!,
      resource, codeChallenge: challenge, codeChallengeMethod: 'S256',
    });
    if (issued.kind !== 'success') throw new Error(`code not issued: ${issued.kind}`);
    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'authorization_code', code: issued.code, redirect_uri: redirect,
        client_id: clientId, code_verifier: verifier,
      }).toString(),
    });
    expect(token.statusCode).toBe(200);
    return token.json() as { access_token: string; scope: string };
  }

  it('signs the directory resource into a metadata-document client token', async () => {
    const stored = await db.query.oauthClients.findFirst({ where: eq(oauthClients.id, clientId) });
    expect(stored).toBeUndefined();
    const { access_token, scope } = await tokenFor(OAUTH_RESOURCE_MCP_DIRECTORY, 'agents:read proxy:write');
    const claims = decodeJwt(access_token);
    expect(claims.aud).toBe(OAUTH_ACCESS_TOKEN_AUDIENCE_MCP);
    expect(claims['resource']).toBe(OAUTH_RESOURCE_MCP_DIRECTORY);
    expect(claims['client_id']).toBe(clientId);
    expect(scope).toBe('agents:read');
    const row = await db.query.oauthClients.findFirst({ where: eq(oauthClients.id, clientId) });
    expect(row).toMatchObject({ client_type: 'public', metadata_url: clientId, token_endpoint_auth_method: 'none' });
  });

  it('signs the standard MCP resource into a /mcp token', async () => {
    const { access_token } = await tokenFor(OAUTH_RESOURCE_MCP, 'agents:read proxy:write');
    const claims = decodeJwt(access_token);
    expect(claims['resource']).toBe(OAUTH_RESOURCE_MCP);
    expect(claims['scope']).toBe('agents:read proxy:write');
  });
});

describe('POST /oauth/register (dynamic client registration)', () => {
  it("registers Cursor's real client, including its cursor:// redirect", async () => {
    const { services } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/register',
      payload: {
        client_name: 'Cursor',
        redirect_uris: [
          'cursor://anysphere.cursor-mcp/oauth/callback',
          'https://www.cursor.com/agents/mcp/oauth/callback',
          'http://localhost:8787/callback',
        ],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      },
    });
    expect(response.statusCode).toBe(201);
    expect(response.json().redirect_uris).toContain('cursor://anysphere.cursor-mcp/oauth/callback');
  });

  it('registers a client that also declares grants this server does not offer, keeping the supported ones', async () => {
    const { services } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/register',
      payload: {
        client_name: 'Claude',
        redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
        grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      },
    });
    expect(response.statusCode).toBe(201);
    expect(response.json().grant_types).toEqual(['authorization_code', 'refresh_token']);
  });

  it('refuses a client whose grant types are all unsupported', async () => {
    const { services } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/register',
      payload: { client_name: 'x', redirect_uris: ['https://client.example/cb'], grant_types: ['client_credentials'] },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe('invalid_client_metadata');
  });

  it('still refuses code-running and non-loopback http redirects', async () => {
    const { services } = fakeServices();
    const app = await makeApp(services, resolverServing(metadataDocument()));
    for (const bad of ['javascript:alert(1)', 'http://evil.example/cb', 'data:text/html,x', 'file:///etc/passwd']) {
      const response = await app.inject({
        method: 'POST',
        url: '/oauth/register',
        payload: { client_name: 'x', redirect_uris: [bad] },
      });
      expect(response.statusCode, bad).toBe(400);
      expect(response.json().error).toBe('invalid_redirect_uri');
    }
  });
});
