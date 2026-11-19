import { ids, oauthClients, OAUTH_DEFAULT_SCOPE } from '@stack/shared';
import { isValidScope, isAllowedRedirectUri, stripRetiredScopes } from '../oauth-helpers.js';
import type { OAuthFlowContext, OAuthHttpReply, OAuthHttpRequest } from './context.js';
import { z } from 'zod';
import { sendOAuthError } from './responses.js';

/** RFC 7591 section 3.1: a JSON object of client metadata, validated field by field below. */
const ClientMetadata = z.record(z.string(), z.unknown());

// ─── Dynamic Client Registration (RFC 7591) ────────────────────────
// Public PKCE clients only. Confidential clients (with client_secret)
// must be created out-of-band by an admin operator; we don't accept
// those via DCR to avoid open-secret-issuance. Per-IP rate limit on
// this route via Fastify's existing rate-limit + a tighter override.
export async function handleClientRegistration(
  { db }: OAuthFlowContext,
  req: OAuthHttpRequest,
  reply: OAuthHttpReply,
) {
  const parsedBody = ClientMetadata.safeParse(req.body ?? {});
  if (!parsedBody.success) {
    return sendOAuthError(reply, 400, 'invalid_client_metadata', 'request body must be a JSON object');
  }
  const body = parsedBody.data;
  const redirect_uris = body['redirect_uris'];
  const client_name = body['client_name'];

  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0 || redirect_uris.length > 20) {
    return sendOAuthError(reply, 400, 'invalid_redirect_uri', 'redirect_uris must list 1-20 URIs');
  }
  for (const uri of redirect_uris) {
    // https, loopback http, or a native app's private-use scheme such as
    // Cursor's cursor://anysphere.cursor-mcp/oauth/callback (RFC 8252).
    if (typeof uri !== 'string' || uri.length > 2048 || !isAllowedRedirectUri(uri)) {
      return sendOAuthError(reply, 400, 'invalid_redirect_uri', 'each redirect_uri must be https, loopback http or a native app scheme, without a fragment');
    }
  }
  if (typeof client_name !== 'string' || client_name.length === 0 || client_name.length > 200) {
    return sendOAuthError(reply, 400, 'invalid_client_metadata', 'client_name required (1-200 chars)');
  }

  const requestedGrantTypes = Array.isArray(body['grant_types'])
    ? (body['grant_types'] as unknown[])
    : ['authorization_code', 'refresh_token'];
  const allowed = new Set(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code']);
  // Clients may request grants this server does not offer. RFC 7591 lets
  // the server replace requested metadata, so register the supported
  // subset (returned below) instead of refusing the client; /oauth/token
  // rejects any other grant regardless.
  const grant_types = [...new Set(requestedGrantTypes.filter(
    (g): g is string => typeof g === 'string' && allowed.has(g),
  ))];
  if (grant_types.length === 0) {
    return sendOAuthError(reply, 400, 'invalid_client_metadata', 'grant_types must include a supported grant type');
  }

  const scope = typeof body['scope'] === 'string' ? stripRetiredScopes(body['scope'] as string) : OAUTH_DEFAULT_SCOPE;
  if (!isValidScope(scope)) {
    return sendOAuthError(reply, 400, 'invalid_scope');
  }

  const id = ids.oauthClient();
  await db.insert(oauthClients).values({
    id,
    client_secret_hash: null,
    client_type: 'public',
    client_name,
    redirect_uris: redirect_uris as string[],
    grant_types,
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope,
    software_id: typeof body['software_id'] === 'string' ? (body['software_id'] as string) : null,
    software_version: typeof body['software_version'] === 'string' ? (body['software_version'] as string) : null,
    metadata_url: null,
    operator_id: null,
  });

  return reply.code(201).send({
    client_id: id,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_name,
    redirect_uris,
    grant_types,
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope,
  });
}
