import { eq } from 'drizzle-orm';
import { oauthClients, deployment } from '@stack/shared';
import { env } from '../../config/env.js';
import {
  audienceForResource, isValidScope, redirectUriRegistered, stripRetiredScopes,
  scopeForResource, defaultScopeForResource,
} from '../oauth-helpers.js';
import {
  ClientMetadataError,
  isClientMetadataUrl,
  type ClientMetadataDocument,
} from '../../lib/oauth-cimd.js';
import type { OAuthFlowContext, OAuthHttpReply, OAuthHttpRequest } from './context.js';
import { OAUTH_PARAMS_NOT_STRINGS, readOAuthParams, sendOAuthError } from './responses.js';
import { persistMetadataClient } from './client-metadata.js';

// ─── /oauth/authorize — entry ──────────────────────────────────────
// Validates the request, mints a short-lived consent JWT, and either:
//   - 302s to the dashboard /oauth/consent page if a session cookie
//     is present and validates against the operator (consent flow), or
//   - 302s to dashboard /login?return_to=<consent-url> otherwise.
//
// The actual issuance of the auth code happens at POST /oauth/authorize
// after the user clicks Approve on the dashboard.
// Per-IP limit: a metadata-document client_id makes this route fetch a URL.
export async function handleAuthorizeRequest(
  { services, db, clientMetadata }: OAuthFlowContext,
  req: OAuthHttpRequest,
  reply: OAuthHttpReply,
) {
  const q = readOAuthParams(req.query);
  if (!q) return sendOAuthError(reply, 400, 'invalid_request', OAUTH_PARAMS_NOT_STRINGS);
  const response_type = q['response_type'];
  const client_id = q['client_id'];
  const redirect_uri = q['redirect_uri'];
  const resource = q['resource'] ?? deployment().apiBaseUrl;
  const requestedScope = stripRetiredScopes(q['scope'] ?? defaultScopeForResource(resource));
  const code_challenge = q['code_challenge'];
  const code_challenge_method = q['code_challenge_method'] ?? 'S256';
  const state = q['state'] ?? '';
  const nonce = q['nonce'];

  if (response_type !== 'code') {
    return sendOAuthError(reply, 400, 'unsupported_response_type');
  }
  if (!client_id || !redirect_uri || !code_challenge) {
    return sendOAuthError(reply, 400, 'invalid_request', 'client_id, redirect_uri, code_challenge required');
  }
  if (code_challenge_method !== 'S256') {
    return sendOAuthError(reply, 400, 'invalid_request', 'code_challenge_method must be S256');
  }
  if (!audienceForResource(resource)) {
    return sendOAuthError(reply, 400, 'invalid_target', 'unknown resource');
  }
  if (!isValidScope(requestedScope)) {
    return sendOAuthError(reply, 400, 'invalid_scope');
  }
  const scope = scopeForResource(resource, requestedScope);
  if (!scope) {
    return sendOAuthError(reply, 400, 'invalid_scope', 'no requested scope is available for this resource');
  }

  let client: { redirect_uris: string[] } | undefined;
  if (isClientMetadataUrl(client_id)) {
    let doc: ClientMetadataDocument;
    try {
      doc = await clientMetadata.resolve(client_id);
    } catch (err) {
      if (err instanceof ClientMetadataError) return sendOAuthError(reply, 400, 'invalid_client', err.message);
      throw err;
    }
    client = await persistMetadataClient(db, doc);
    if (!client) {
      return sendOAuthError(reply, 400, 'invalid_client', 'client_id is registered by another method');
    }
  } else {
    client = await db.query.oauthClients.findFirst({ where: eq(oauthClients.id, client_id) });
  }
  if (!client) {
    return sendOAuthError(reply, 401, 'invalid_client', 'unknown client_id');
  }
  if (!redirectUriRegistered(client.redirect_uris, redirect_uri)) {
    return sendOAuthError(reply, 400, 'invalid_request', 'redirect_uri not registered');
  }

  // The OAuth client (Claude Code / ChatGPT / Cursor / etc.) hits this
  // endpoint directly in the user's browser. Cookies set on the dashboard
  // origin (getstack.run) do NOT auto-attach to api.getstack.run, so we
  // can't read the session here. The dashboard owns that — we just mint
  // the consent JWT and 302 unconditionally to /oauth/consent. The
  // dashboard reads its own cookie, redirects to /login if needed, then
  // POSTs the approval back through its proxy.
  const consentToken = await services.signer.signOAuthConsentToken('pending', {
    client_id,
    redirect_uri,
    scope,
    resource,
    code_challenge,
    code_challenge_method,
    state,
    nonce,
  });

  const consentUrl = `${env.DASHBOARD_URL}/oauth/consent?state=${encodeURIComponent(consentToken)}`;
  return reply.redirect(consentUrl, 302);
}
