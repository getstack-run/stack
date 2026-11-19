// A reference check of a client metadata document (spec/oauth-profile/SPEC.md, sections 4.1 and 4.3), written from
// the specification with nothing but the standard library. The `oauth-client-metadata` suite runs against it in CI.

const FORBIDDEN_SCHEMES = new Set([
  'http', 'https', 'javascript', 'data', 'file', 'blob', 'about', 'vbscript', 'filesystem', 'view-source', 'chrome',
  'chrome-extension', 'edge', 'moz-extension', 'ws', 'wss', 'ftp', 'mailto', 'tel', 'sms', 'intent', 'content', 'jar', 'urn',
]);
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const OFFERED_GRANTS = new Set(['authorization_code', 'refresh_token']);

/** Whether a client id names a metadata document: an https URL with a path, in its exact form, and nothing more. */
export function isMetadataClientId(clientId) {
  if (typeof clientId !== 'string' || clientId.length > 1024 || !clientId.startsWith('https://')) return false;
  let url;
  try {
    url = new URL(clientId);
  } catch {
    return false;
  }
  if (url.username || url.password || url.search || url.hash || url.pathname === '/' || url.pathname === '') return false;
  if (/\/\.{1,2}(?:\/|$)/.test(clientId.slice(url.origin.length))) return false;
  return url.href === clientId;
}

/** A redirect URI a client may register: https, loopback http or a native app's private-use scheme, without a fragment. */
export function allowedRedirect(uri) {
  if (typeof uri !== 'string' || uri.length > 2048 || uri.includes('#')) return false;
  let url;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.protocol === 'https:') return true;
  if (url.protocol === 'http:') return LOOPBACK.has(url.hostname);
  const scheme = url.protocol.slice(0, -1);
  if (!/^[a-z][a-z0-9+.-]{1,62}$/.test(scheme) || FORBIDDEN_SCHEMES.has(scheme)) return false;
  if (url.username || url.password) return false;
  return url.host !== '' || url.pathname.length > 1;
}

export function validate(clientId, document) {
  if (!isMetadataClientId(clientId)) throw new Error('client_id is not a metadata document URL');
  if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error('not a JSON object');
  if (document.client_id !== clientId) throw new Error('client_id is not the URL');
  if ('client_secret' in document || 'client_secret_expires_at' in document) throw new Error('a client secret');
  const method = document.token_endpoint_auth_method;
  const supported = document.token_endpoint_auth_methods_supported;
  const works = method === undefined || method === 'none' || (Array.isArray(supported) && supported.includes('none'));
  if (!works) throw new Error('cannot work as a public client');
  const uris = document.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 20) throw new Error('redirect_uris must list 1 to 20');
  if (!uris.every(allowedRedirect)) throw new Error('a redirect URI is not allowed');
  const declared = document.grant_types ?? ['authorization_code', 'refresh_token'];
  if (!Array.isArray(declared) || !declared.every((g) => typeof g === 'string') || !declared.includes('authorization_code')) throw new Error('grant_types');
  const types = document.response_types;
  if (types !== undefined && !(Array.isArray(types) && types.length === 1 && types[0] === 'code')) throw new Error('response_types');
  const name = document.client_name;
  if (name !== undefined && (typeof name !== 'string' || name.trim().length === 0 || name.length > 200)) throw new Error('client_name');
  return {
    client_id: clientId,
    client_name: typeof name === 'string' ? name.trim() : new URL(clientId).hostname,
    redirect_uris: [...new Set(uris)],
    grant_types: [...new Set(declared.filter((g) => OFFERED_GRANTS.has(g)))],
  };
}
