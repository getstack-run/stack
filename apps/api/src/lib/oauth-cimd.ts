// OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).
//
// A client may use an https URL as its client_id. The authorization server
// fetches the JSON document at that URL and treats it as the client's
// registration. STACK accepts such clients as PUBLIC clients only: PKCE S256
// is mandatory for every client and no client secret is ever accepted.
//
// Threat model
//   1. SSRF. /oauth/authorize is unauthenticated, so the client_id URL is
//      attacker-chosen. The fetch goes through publicFetch: https only, DNS
//      resolved once and pinned to the socket, private / loopback / link-local
//      / metadata / CGNAT ranges refused (also for literal IPs and hostnames
//      like localhost or *.internal), redirects refused, no cookies, no proxy
//      environment, 5 KB response cap, 5 s total deadline. The request carries
//      no credentials, and its outcome is not reflected beyond an error code.
//   2. Amplification and DoS. Results are cached for a bounded time,
//      concurrent fetches of one URL share one request, the cache is size
//      bounded, and the route carries a per-IP rate limit.
//   3. Impersonation. The document must name itself (client_id equal to the
//      URL, byte for byte). The consent screen shows the client_id URL, so
//      the host that serves the document is what the user approves.
//   4. Redirect hijack. The redirect_uri must exactly equal one listed in the
//      fetched document; every listed URI must be https, loopback http or a
//      native app's private-use scheme (RFC 8252 §7.1, PKCE-protected).
//   5. Secret confusion. A document that declares a client secret, or that
//      cannot work as a public client (neither token_endpoint_auth_method nor
//      token_endpoint_auth_methods_supported allows "none"), is refused. STACK
//      stores the client with client_type "public" and no secret hash.
//   6. Row takeover. The persisted oauth_clients row for a URL client is
//      written only when no row exists or the existing row is itself a
//      metadata-document client for the same URL (metadata_url = client_id).

import { publicFetch } from '@stack/shared';
import { isAllowedRedirectUri } from '../routes/oauth-helpers.js';

export const CIMD_MAX_DOCUMENT_BYTES = 5 * 1024;
export const CIMD_FETCH_TIMEOUT_MS = 5_000;
export const CIMD_CACHE_TTL_MS = 5 * 60 * 1000;
export const CIMD_CACHE_MAX_ENTRIES = 500;
const MAX_CLIENT_ID_LENGTH = 1024;
const MAX_REDIRECT_URIS = 20;
const ALLOWED_GRANT_TYPES = new Set(['authorization_code', 'refresh_token']);

export interface ClientMetadataDocument {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
}

export class ClientMetadataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClientMetadataError';
  }
}

/**
 * True when client_id is a syntactically valid metadata-document URL:
 * https, a non-root path, no credentials, query or fragment, and no dot
 * segments. Anything else is treated as an ordinary registered client id.
 */
export function isClientMetadataUrl(clientId: string): boolean {
  if (clientId.length > MAX_CLIENT_ID_LENGTH || !clientId.startsWith('https://')) return false;
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return false;
  if (url.pathname === '/' || url.pathname === '') return false;
  // URL parsing removes dot segments; the raw string must not contain them.
  if (/\/\.{1,2}(?:\/|$)/.test(clientId.slice(url.origin.length))) return false;
  // Exact form only: the document must be fetched from the string presented.
  return url.href === clientId;
}

type FetchFn = (url: string, init: RequestInit) => Promise<Response>;

const defaultFetch: FetchFn = (url, init) =>
  publicFetch(url, init, {
    timeoutMs: CIMD_FETCH_TIMEOUT_MS,
    maxResponseBytes: CIMD_MAX_DOCUMENT_BYTES,
    allowedProtocols: ['https:'],
  });

export interface ClientMetadataResolverOptions {
  fetchImpl?: FetchFn;
  now?: () => number;
  ttlMs?: number;
  maxEntries?: number;
}

export interface ClientMetadataResolver {
  resolve(clientId: string): Promise<ClientMetadataDocument>;
  clear(): void;
}

export function validateClientMetadataDocument(clientId: string, raw: unknown): ClientMetadataDocument {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ClientMetadataError('client metadata document is not a JSON object');
  }
  const doc = raw as Record<string, unknown>;
  if (doc['client_id'] !== clientId) {
    throw new ClientMetadataError('client metadata document client_id does not match its URL');
  }
  if ('client_secret' in doc || 'client_secret_expires_at' in doc) {
    throw new ClientMetadataError('client metadata document must not contain a client secret');
  }
  const authMethod = doc['token_endpoint_auth_method'];
  const supportedMethods = doc['token_endpoint_auth_methods_supported'];
  // A client may prefer another method yet also work as a public client:
  // ChatGPT's document says private_key_jwt but lists "none" as supported.
  // Register it as public; discovery advertises "none", and PKCE still binds
  // the code to the client that started the flow.
  const acceptsNone = authMethod === undefined || authMethod === 'none'
    || (Array.isArray(supportedMethods) && supportedMethods.includes('none'));
  if (!acceptsNone) {
    throw new ClientMetadataError('only public clients (token_endpoint_auth_method "none") are supported');
  }
  const redirectUris = doc['redirect_uris'];
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > MAX_REDIRECT_URIS) {
    throw new ClientMetadataError(`redirect_uris must list 1-${MAX_REDIRECT_URIS} URIs`);
  }
  for (const uri of redirectUris) {
    if (typeof uri !== 'string' || uri.length > 2048 || !isAllowedRedirectUri(uri)) {
      throw new ClientMetadataError('every redirect_uri must be https, loopback http or a native app scheme, without a fragment');
    }
  }
  const declaredGrantTypes = doc['grant_types'] ?? ['authorization_code', 'refresh_token'];
  if (
    !Array.isArray(declaredGrantTypes)
    || !declaredGrantTypes.every((g) => typeof g === 'string')
    || !declaredGrantTypes.includes('authorization_code')
  ) {
    throw new ClientMetadataError('grant_types must include authorization_code');
  }
  // A client may declare grants this server does not offer (Claude's own
  // document adds jwt-bearer). Keep only the supported ones, as RFC 7591 lets
  // a server replace requested metadata; /oauth/token refuses any other grant.
  const grantTypes = (declaredGrantTypes as string[]).filter((g) => ALLOWED_GRANT_TYPES.has(g));
  const responseTypes = doc['response_types'];
  if (
    responseTypes !== undefined
    && (!Array.isArray(responseTypes) || responseTypes.length !== 1 || responseTypes[0] !== 'code')
  ) {
    throw new ClientMetadataError('response_types must be ["code"]');
  }
  const name = doc['client_name'];
  if (name !== undefined && (typeof name !== 'string' || name.trim().length === 0 || name.length > 200)) {
    throw new ClientMetadataError('client_name must be 1-200 characters');
  }
  return {
    client_id: clientId,
    client_name: typeof name === 'string' ? name.trim() : new URL(clientId).hostname,
    redirect_uris: [...new Set(redirectUris as string[])],
    grant_types: [...new Set(grantTypes)],
  };
}

export function createClientMetadataResolver(
  options: ClientMetadataResolverOptions = {},
): ClientMetadataResolver {
  const fetchImpl = options.fetchImpl ?? defaultFetch;
  const now = options.now ?? Date.now;
  const ttlMs = options.ttlMs ?? CIMD_CACHE_TTL_MS;
  const maxEntries = options.maxEntries ?? CIMD_CACHE_MAX_ENTRIES;
  const cache = new Map<string, { doc: ClientMetadataDocument; expiresAt: number }>();
  const inFlight = new Map<string, Promise<ClientMetadataDocument>>();

  async function fetchDocument(clientId: string): Promise<{ doc: ClientMetadataDocument; cacheable: boolean }> {
    let response: Response;
    try {
      response = await fetchImpl(clientId, {
        method: 'GET',
        headers: { accept: 'application/json' },
      });
    } catch {
      // Do not reflect network, DNS or guard details back to the caller.
      throw new ClientMetadataError('client metadata document could not be fetched');
    }
    if (response.status !== 200) {
      throw new ClientMetadataError(`client metadata document returned HTTP ${response.status}`);
    }
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > CIMD_MAX_DOCUMENT_BYTES) {
      throw new ClientMetadataError('client metadata document is too large');
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new ClientMetadataError('client metadata document is not valid JSON');
    }
    const cacheControl = response.headers.get('cache-control') ?? '';
    return {
      doc: validateClientMetadataDocument(clientId, parsed),
      cacheable: !/\bno-store\b/i.test(cacheControl),
    };
  }

  return {
    async resolve(clientId) {
      if (!isClientMetadataUrl(clientId)) {
        throw new ClientMetadataError('client_id is not a valid client metadata document URL');
      }
      const cached = cache.get(clientId);
      if (cached && cached.expiresAt > now()) return cached.doc;
      if (cached) cache.delete(clientId);
      const pending = inFlight.get(clientId);
      if (pending) return pending;
      const work = fetchDocument(clientId)
        .then(({ doc, cacheable }) => {
          if (cacheable && ttlMs > 0) {
            if (cache.size >= maxEntries) {
              const oldest = cache.keys().next().value;
              if (oldest !== undefined) cache.delete(oldest);
            }
            cache.set(clientId, { doc, expiresAt: now() + ttlMs });
          }
          return doc;
        })
        .finally(() => inFlight.delete(clientId));
      inFlight.set(clientId, work);
      return work;
    },
    clear() {
      cache.clear();
    },
  };
}
