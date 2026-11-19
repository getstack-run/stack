/** Provider token renewal. The connection service holds a database row lock
 * across the refresh and encrypted persistence. Never cache secrets in Redis. */
import { createHash } from 'node:crypto';
import { assertPublicUrl, publicFetch, ConflictError, type ReconnectReason } from '@stack/shared';

const REFRESH_MARGIN_MS = 60_000;

export interface CredentialFields {
  access_token?: string;
  refresh_token?: string;
  expires_at?: string | number;
  expires_in?: number;
  scope?: string;
  client_id?: string;
  client_secret?: string;
  tenant_id?: string;
  cc_scope?: string;
  cc_token_url?: string;
  oauth_app_binding?: { id: string; owner_id: string; provider: string; client_id_hash: string;
    service_id: string; connection_provider: string; token_url: string };
  token_auth_method?: 'client_secret_basic' | 'client_secret_post';
  [k: string]: unknown;
}

export type { ReconnectReason };

/** What a connection's app binding keeps of the app's client id, and what the id in a token check is compared with. */
export function oauthClientIdDigest(clientId: string): string {
  return createHash('sha256').update(clientId).digest('base64url');
}

export class OAuthLifecycleError extends ConflictError {
  constructor(readonly reconnectRequired = false, readonly reason?: ReconnectReason) {
    // Existing customer wording. Machine classification never includes provider text.
    super('Credential refresh is pending; retry policy evaluation');
  }
}

export interface TokenLifecycleDeps {
  persistRefreshed?: (
    connectionId: string, operatorId: string, provider: string,
    nextFields: CredentialFields, accessTokenExpiresAt: Date,
  ) => Promise<void>;
}

/**
 * A Microsoft token endpoint names its tenant in the path. A single-tenant app
 * only answers on its own tenant's endpoint, so a renewal for one swaps the
 * catalogue's multi-tenant segment for the app's tenant.
 */
export function tenantTokenUrl(tokenUrl: string, tenant: string | undefined): string {
  if (!tenant) return tokenUrl;
  return tokenUrl.replace(
    /^(https:\/\/login\.microsoftonline\.com\/)(common|organizations|consumers)(\/)/,
    (_all, head: string, _segment: string, tail: string) => `${head}${encodeURIComponent(tenant)}${tail}`,
  );
}

export function credentialExpiresAt(fields: CredentialFields): number | null {
  const value = typeof fields.expires_at === 'number' ? fields.expires_at
    : typeof fields.expires_at === 'string' ? Date.parse(fields.expires_at) : NaN;
  return Number.isFinite(value) ? value : null;
}

export async function maybeRefreshAccessToken(args: {
  fields: CredentialFields; oauthTokenUrl: string; clientId?: string; clientSecret?: string;
  connectionId: string; operatorId: string; provider: string; deps: TokenLifecycleDeps;
}): Promise<CredentialFields> {
  const { fields } = args;
  if (!fields.refresh_token) return fields;
  const expiry = credentialExpiresAt(fields);
  if (expiry !== null && expiry > Date.now() + REFRESH_MARGIN_MS) return fields;
  if (!args.oauthTokenUrl) throw new OAuthLifecycleError(true);
  if (!args.deps.persistRefreshed) throw new OAuthLifecycleError();
  const params = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: fields.refresh_token });
  const response = await fetchTokenEndpoint(args.oauthTokenUrl, params,
    args.clientId ?? fields.client_id, args.clientSecret ?? fields.client_secret, fields.token_auth_method);
  return persistResponse(args, response);
}

export async function maybeFetchClientCredentialsToken(args: {
  fields: CredentialFields; defaultTokenUrl: string; connectionId: string;
  operatorId: string; provider: string; deps: TokenLifecycleDeps;
}): Promise<CredentialFields> {
  const { fields } = args;
  if (!fields.client_id || !fields.client_secret || fields.refresh_token) return fields;
  const expiry = credentialExpiresAt(fields);
  if (fields.access_token && expiry !== null && expiry > Date.now() + REFRESH_MARGIN_MS) return fields;
  if (!args.deps.persistRefreshed) throw new OAuthLifecycleError();
  let tokenUrl = fields.cc_token_url ?? args.defaultTokenUrl;
  if (fields.tenant_id && tokenUrl.includes('/common/')) {
    // A path segment, never an authority or injected path.
    if (!/^[a-zA-Z0-9.-]+$/.test(fields.tenant_id)) throw new OAuthLifecycleError(true);
    tokenUrl = tokenUrl.replace('/common/', `/${fields.tenant_id}/`);
  }
  if (!tokenUrl) {
    // No token endpoint and no application token: a key set that carries the provider's own client id and secret (STACK's
    // Azure sandbox and Agentcard logins), used as stored. A token that expired with no endpoint to renew it still asks
    // for a reconnect.
    if (!fields.access_token) return fields;
    throw new OAuthLifecycleError(true);
  }
  const params = new URLSearchParams({ grant_type: 'client_credentials' });
  if (fields.cc_scope) params.set('scope', fields.cc_scope);
  const response = await fetchTokenEndpoint(tokenUrl, params, fields.client_id, fields.client_secret,
    fields.token_auth_method ?? 'client_secret_post');
  return persistResponse(args, response);
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  scope?: string;
}

async function persistResponse(args: {
  fields: CredentialFields; connectionId: string; operatorId: string; provider: string;
  deps: TokenLifecycleDeps;
}, response: TokenResponse): Promise<CredentialFields> {
  const expiry = new Date(Date.now() + response.expires_in * 1000);
  const next: CredentialFields = {
    ...args.fields,
    access_token: response.access_token,
    expires_at: expiry.toISOString(),
    ...(response.refresh_token ? { refresh_token: response.refresh_token } : {}),
    ...(response.scope !== undefined ? { scope: response.scope } : {}),
  };
  delete next.expires_in;
  // Returning a rotated token before this succeeds loses the only usable refresh token.
  await args.deps.persistRefreshed!(args.connectionId, args.operatorId, args.provider, next, expiry);
  return next;
}

async function fetchTokenEndpoint(
  url: string, params: URLSearchParams, clientId?: string, clientSecret?: string,
  authMethod: CredentialFields['token_auth_method'] = 'client_secret_post',
): Promise<TokenResponse> {
  try {
    await assertPublicUrl(url, { allowedProtocols: ['https:'] });
  } catch {
    throw new OAuthLifecycleError(true);
  }
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json',
  };
  if (authMethod === 'client_secret_basic' && clientId && clientSecret) {
    const encode = (value: string) => new URLSearchParams({ v: value }).toString().slice(2);
    headers.Authorization = `Basic ${Buffer.from(`${encode(clientId)}:${encode(clientSecret)}`).toString('base64')}`;
  } else {
    if (clientId) params.set('client_id', clientId);
    if (clientSecret) params.set('client_secret', clientSecret);
  }
  try {
    const res = await publicFetch(url, { method: 'POST', headers, body: params.toString(), redirect: 'error' }, {
      allowedProtocols: ['https:'], maxRequestBytes: 16 * 1024, maxResponseBytes: 256 * 1024, timeoutMs: 10_000,
    });
    const json = await res.json() as Record<string, unknown>;
    if (!res.ok || json.error || json.ok === false) {
      // Only these explicit provider codes require re-consent. Outages do not.
      throw new OAuthLifecycleError(['invalid_grant', 'invalid_client', 'unauthorized_client',
        'token_revoked', 'invalid_refresh_token'].includes(String(json.error)));
    }
    if (typeof json.access_token !== 'string' || !json.access_token
      || typeof json.expires_in !== 'number' || !Number.isFinite(json.expires_in)
      || json.expires_in <= 0 || json.expires_in > 315_360_000
      || (json.refresh_token !== undefined && (typeof json.refresh_token !== 'string' || !json.refresh_token))
      || (json.scope !== undefined && typeof json.scope !== 'string')) {
      throw new OAuthLifecycleError();
    }
    return { access_token: json.access_token, expires_in: json.expires_in,
      ...(typeof json.refresh_token === 'string' ? { refresh_token: json.refresh_token } : {}),
      ...(typeof json.scope === 'string' ? { scope: json.scope } : {}) };
  } catch (error) {
    if (error instanceof OAuthLifecycleError) throw error;
    throw new OAuthLifecycleError();
  }
}
