import { describe, expect, it, vi } from 'vitest';
import {
  ClientMetadataError,
  createClientMetadataResolver,
  isClientMetadataUrl,
  validateClientMetadataDocument,
} from './oauth-cimd.js';

const CLIENT_ID = 'https://client.example/oauth/metadata.json';

function doc(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLIENT_ID,
    client_name: 'Example Connector',
    redirect_uris: ['https://client.example/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    ...overrides,
  };
}

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

describe('isClientMetadataUrl', () => {
  it('accepts an https URL with a path', () => {
    expect(isClientMetadataUrl(CLIENT_ID)).toBe(true);
  });

  it.each([
    ['plain registered id', 'oclient_123'],
    ['http scheme', 'http://client.example/metadata.json'],
    ['root path', 'https://client.example/'],
    ['no path', 'https://client.example'],
    ['query string', 'https://client.example/metadata.json?a=1'],
    ['fragment', 'https://client.example/metadata.json#x'],
    ['credentials', 'https://user:pass@client.example/metadata.json'],
    ['dot segment', 'https://client.example/a/../metadata.json'],
    ['non-canonical form', 'https://CLIENT.example/metadata.json'],
  ])('rejects %s', (_label, value) => {
    expect(isClientMetadataUrl(value)).toBe(false);
  });
});

describe('validateClientMetadataDocument', () => {
  it('returns the normalized public client registration', () => {
    expect(validateClientMetadataDocument(CLIENT_ID, doc())).toEqual({
      client_id: CLIENT_ID,
      client_name: 'Example Connector',
      redirect_uris: ['https://client.example/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
    });
  });

  it('rejects a document whose client_id does not equal its URL', () => {
    expect(() =>
      validateClientMetadataDocument(CLIENT_ID, doc({ client_id: 'https://other.example/metadata.json' })),
    ).toThrow(/does not match/);
  });

  it('rejects client secrets and confidential auth methods', () => {
    expect(() => validateClientMetadataDocument(CLIENT_ID, doc({ client_secret: 'x' }))).toThrow(ClientMetadataError);
    expect(() =>
      validateClientMetadataDocument(CLIENT_ID, doc({ token_endpoint_auth_method: 'client_secret_post' })),
    ).toThrow(/public clients/);
  });

  it("accepts ChatGPT's client, which prefers private_key_jwt but supports none", () => {
    const result = validateClientMetadataDocument(CLIENT_ID, doc({
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
      token_endpoint_auth_signing_alg: 'RS256',
      jwks_uri: 'https://client.example/jwks.json',
    }));
    expect(result.client_id).toBe(CLIENT_ID);
  });

  it('still rejects a confidential client that does not support none', () => {
    expect(() => validateClientMetadataDocument(CLIENT_ID, doc({
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_methods_supported: ['private_key_jwt'],
    }))).toThrow(/public clients/);
  });

  it('rejects non-https, non-loopback or fragment redirect URIs', () => {
    for (const uri of ['http://evil.example/cb', 'javascript:alert(1)', 'https://client.example/cb#frag']) {
      expect(() => validateClientMetadataDocument(CLIENT_ID, doc({ redirect_uris: [uri] })), uri).toThrow(
        ClientMetadataError,
      );
    }
    expect(() => validateClientMetadataDocument(CLIENT_ID, doc({ redirect_uris: [] }))).toThrow(ClientMetadataError);
  });

  it('accepts loopback redirect URIs', () => {
    const result = validateClientMetadataDocument(CLIENT_ID, doc({ redirect_uris: ['http://127.0.0.1:33418/callback'] }));
    expect(result.redirect_uris).toEqual(['http://127.0.0.1:33418/callback']);
  });

  it('rejects grant types other than authorization_code and refresh_token', () => {
    expect(() =>
      validateClientMetadataDocument(CLIENT_ID, doc({ grant_types: ['client_credentials'] })),
    ).toThrow(ClientMetadataError);
  });

  it("accepts Claude's published client document and keeps only supported grants", () => {
    const result = validateClientMetadataDocument(CLIENT_ID, doc({
      grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
    }));
    expect(result.grant_types).toEqual(['authorization_code', 'refresh_token']);
  });

  it('still rejects a document without authorization_code', () => {
    expect(() =>
      validateClientMetadataDocument(CLIENT_ID, doc({ grant_types: ['refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'] })),
    ).toThrow(ClientMetadataError);
  });

  it('falls back to the host name when client_name is absent', () => {
    const { client_name: _omit, ...rest } = doc();
    expect(validateClientMetadataDocument(CLIENT_ID, rest).client_name).toBe('client.example');
  });
});

describe('createClientMetadataResolver', () => {
  it('fetches, validates and caches the document (happy path)', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(doc()));
    let now = 1_000;
    const resolver = createClientMetadataResolver({ fetchImpl, now: () => now, ttlMs: 60_000 });

    const first = await resolver.resolve(CLIENT_ID);
    expect(first.redirect_uris).toEqual(['https://client.example/callback']);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledWith(CLIENT_ID, expect.objectContaining({ method: 'GET' }));

    await resolver.resolve(CLIENT_ID);
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    now += 60_001;
    await resolver.resolve(CLIENT_ID);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('shares one in-flight fetch between concurrent requests', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(doc()));
    const resolver = createClientMetadataResolver({ fetchImpl });
    await Promise.all([resolver.resolve(CLIENT_ID), resolver.resolve(CLIENT_ID), resolver.resolve(CLIENT_ID)]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not cache a document served with Cache-Control: no-store', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(doc(), { headers: { 'cache-control': 'no-store' } }));
    const resolver = createClientMetadataResolver({ fetchImpl });
    await resolver.resolve(CLIENT_ID);
    await resolver.resolve(CLIENT_ID);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('rejects a mismatched client_id and does not cache the failure', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(doc({ client_id: 'https://attacker.example/metadata.json' })));
    const resolver = createClientMetadataResolver({ fetchImpl });
    await expect(resolver.resolve(CLIENT_ID)).rejects.toThrow(/does not match/);
    await expect(resolver.resolve(CLIENT_ID)).rejects.toThrow(/does not match/);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('rejects non-200 responses, invalid JSON and oversized documents', async () => {
    const notFound = createClientMetadataResolver({ fetchImpl: async () => new Response('', { status: 404 }) });
    await expect(notFound.resolve(CLIENT_ID)).rejects.toThrow(/HTTP 404/);
    const garbage = createClientMetadataResolver({ fetchImpl: async () => new Response('{nope', { status: 200 }) });
    await expect(garbage.resolve(CLIENT_ID)).rejects.toThrow(/not valid JSON/);
    const huge = createClientMetadataResolver({
      fetchImpl: async () => jsonResponse(doc({ client_name: 'x'.repeat(10_000) })),
    });
    await expect(huge.resolve(CLIENT_ID)).rejects.toThrow(/too large/);
  });

  it('hides transport errors behind a generic message', async () => {
    const resolver = createClientMetadataResolver({
      fetchImpl: async () => {
        throw new Error('ECONNREFUSED 10.0.0.5:443 internal detail');
      },
    });
    await expect(resolver.resolve(CLIENT_ID)).rejects.toThrow('client metadata document could not be fetched');
  });

  it('never fetches a client_id that is not a metadata URL', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(doc()));
    const resolver = createClientMetadataResolver({ fetchImpl });
    await expect(resolver.resolve('http://client.example/metadata.json')).rejects.toThrow(ClientMetadataError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  // Real SSRF guard: these addresses are refused before any socket opens.
  it.each([
    'https://127.0.0.1/metadata.json',
    'https://10.0.0.8/metadata.json',
    'https://169.254.169.254/latest/meta-data',
    'https://[::1]/metadata.json',
    'https://localhost/metadata.json',
    'https://metadata.google.internal/metadata.json',
  ])('refuses a private or internal address with the default fetcher: %s', async (clientId) => {
    const resolver = createClientMetadataResolver();
    await expect(resolver.resolve(clientId)).rejects.toThrow('client metadata document could not be fetched');
  });
});
