// Pure helpers for OAuth 2.1. Extracted from oauth.ts so they
// can be unit-tested without standing up Fastify or the DB.
//
// Anything that touches the request, the DB, or external IO stays in
// oauth.ts. Anything that's a deterministic function of strings/buffers
// lives here.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  OAUTH_ACCESS_TOKEN_AUDIENCE_API,
  OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
  OAUTH_DEFAULT_SCOPE,
  OAUTH_DIRECTORY_DEFAULT_SCOPES,
  OAUTH_DIRECTORY_SCOPES,
  deployment,
  OAUTH_SCOPES,
} from '@stack/shared';

const VALID_SCOPES = new Set<string>(OAUTH_SCOPES as readonly string[]);
const DIRECTORY_SCOPES = new Set<string>(OAUTH_DIRECTORY_SCOPES as readonly string[]);

export function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

/**
 * RFC 7636 §4.6: code_challenge = BASE64URL(SHA256(code_verifier)) with no
 * padding. Length must match before timingSafeEqual; jose/crypto throws
 * on length mismatch.
 */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  const computed = createHash('sha256').update(verifier).digest('base64url');
  if (computed.length !== challenge.length) return false;
  return timingSafeEqual(Buffer.from(computed), Buffer.from(challenge));
}

/**
 * RFC 8628 §6.1 user_code generation. Reduced alphabet excludes
 * A/E/I/O/U/0/1 to avoid phonetic + visual confusion when read aloud
 * over the phone or transcribed by hand. 8 chars from a 29-char alphabet
 * = ~38 bits of entropy, plenty for the bounded pending-code population.
 */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXYZ23456789';
export function generateUserCode(): string {
  const bytes = randomBytes(8);
  let s = '';
  for (let i = 0; i < 8; i++) {
    s += USER_CODE_ALPHABET[bytes[i]! % USER_CODE_ALPHABET.length];
  }
  return `${s.slice(0, 4)}-${s.slice(4, 8)}`;
}

export function audienceForResource(resource: string):
  | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_API
  | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_MCP
  | null {
  if (resource === deployment().apiBaseUrl) return OAUTH_ACCESS_TOKEN_AUDIENCE_API;
  // Both MCP resources map to the stack:mcp audience. The exact resource is
  // also signed into the token (`resource` claim), and the MCP transport
  // binds each path to its own resource.
  if (resource === deployment().mcpResource || resource === deployment().mcpDirectoryResource) {
    return OAUTH_ACCESS_TOKEN_AUDIENCE_MCP;
  }
  return null;
}

/**
 * Apply the per-resource scope ceiling to a requested scope string.
 * The directory resource keeps only OAUTH_DIRECTORY_SCOPES (RFC 6749 §3.3:
 * the server may grant less than requested). Returns null when nothing in
 * the request survives, which the caller reports as invalid_scope. Other
 * resources pass through unchanged.
 */
export function scopeForResource(resource: string, scope: string): string | null {
  if (resource !== deployment().mcpDirectoryResource) return scope;
  const kept = scope.split(/\s+/).filter((s) => DIRECTORY_SCOPES.has(s));
  return kept.length > 0 ? [...new Set(kept)].join(' ') : null;
}

/**
 * Scopes the published CLI (2.1.0 and earlier) still asks for at sign-in, which
 * no route or permission answers to any more. A request that names one is
 * accepted: the scope is dropped before validation, so it is granted to nothing,
 * never shown for consent and never in a token.
 */
const RETIRED_SCOPES: ReadonlySet<string> = new Set(['partner-grants:read', 'partner-grants:write']);

export function stripRetiredScopes(scope: string): string {
  if (!scope.includes('partner-grants:')) return scope;
  return scope.split(/\s+/).filter((s) => !RETIRED_SCOPES.has(s)).join(' ');
}

export function isValidScope(scope: string): boolean {
  if (!scope || scope.length > 1024) return false;
  return scope.split(/\s+/).every((s) => VALID_SCOPES.has(s));
}

/**
 * RFC 6749 §3.1.2.4: redirect_uri must be a literal match against one
 * of the registered URIs. No prefix, no glob, no fragment.
 */
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', 'localhost']);

/**
 * Exact match, except the port of an http loopback redirect (RFC 8252 §7.3):
 * native clients bind an ephemeral port at sign-in time, so the server MUST
 * accept any port for a registered loopback URI. Scheme, host, path and query
 * must still match exactly, and nothing else is relaxed. Claude Code's client
 * metadata document lists `http://localhost/callback` and then signs in on
 * `http://localhost:<port>/callback`. The token exchange still requires the
 * redirect_uri byte for byte as presented here, so the code stays bound to
 * the one port that started the flow.
 */
export function redirectUriRegistered(registered: string[], presented: string): boolean {
  if (registered.includes(presented)) return true;
  const loose = loopbackWithoutPort(presented);
  return loose !== null && registered.some((uri) => loopbackWithoutPort(uri) === loose);
}

function loopbackWithoutPort(uri: string): string | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' || !LOOPBACK_HOSTS.has(u.hostname)) return null;
  if (u.username || u.password || u.hash) return null;
  return `http://${u.hostname}${u.pathname}${u.search}`;
}

export function isLoopbackOrHttps(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === 'https:') return true;
    if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]')) return true;
    return false;
  } catch {
    return false;
  }
}

// Schemes that are never a native app's callback: web/loopback http is
// handled above, and these either run code, read local files, address the
// browser itself or are not a redirect target at all.
const FORBIDDEN_PRIVATE_SCHEMES = new Set([
  'http', 'https', 'javascript', 'data', 'file', 'blob', 'about', 'vbscript',
  'filesystem', 'view-source', 'chrome', 'chrome-extension', 'edge', 'moz-extension',
  'ws', 'wss', 'ftp', 'mailto', 'tel', 'sms', 'intent', 'content', 'jar', 'urn',
]);
const PRIVATE_SCHEME = /^[a-z][a-z0-9+.-]{1,62}$/u;

/**
 * A native app's private-use URI scheme redirect (RFC 8252 §7.1), such as
 * `cursor://anysphere.cursor-mcp/oauth/callback`. Another app on the device
 * could register the same scheme, so the reply can be intercepted; PKCE S256,
 * which /oauth/authorize requires of every client, makes an intercepted code
 * useless without the verifier only the initiating app holds. Exact matching
 * still applies, and code-running or browser-internal schemes are refused.
 */
export function isPrivateUseSchemeRedirect(uri: string): boolean {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  const scheme = u.protocol.slice(0, -1);
  if (!PRIVATE_SCHEME.test(scheme) || FORBIDDEN_PRIVATE_SCHEMES.has(scheme)) return false;
  if (u.username || u.password || u.hash || uri.includes('#')) return false;
  return u.host !== '' || u.pathname.length > 1;
}

/** Every redirect a client may register: https, loopback http, or a native app scheme. */
export function isAllowedRedirectUri(uri: string): boolean {
  if (uri.includes('#')) return false;
  return isLoopbackOrHttps(uri) || isPrivateUseSchemeRedirect(uri);
}

/**
 * Scope granted when an authorization request names none. A directory client
 * gets the directory default set, which covers every directory tool; every
 * other resource keeps OAUTH_DEFAULT_SCOPE.
 */
export function defaultScopeForResource(resource: string): string {
  return resource === deployment().mcpDirectoryResource
    ? OAUTH_DIRECTORY_DEFAULT_SCOPES.join(' ')
    : OAUTH_DEFAULT_SCOPE;
}
