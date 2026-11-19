import { GRANT_TYPE_TOKEN_EXCHANGE } from '@stack/shared';
import type { Services } from '../../config/services.js';
import type { OAuthHttpReply, OAuthHttpRequest } from './context.js';
import { OAUTH_PARAMS_NOT_STRINGS, readOAuthParams, sendOAuthError } from './responses.js';
import { handleAuthorizationCodeGrant } from './authorization-code-grant.js';
import { handleRefreshGrant } from './refresh-grant.js';
import { handleDeviceTokenGrant } from './device-token-grant.js';
import { handleTokenExchangeGrant } from './token-exchange-grant.js';

// ─── /oauth/token — multi-grant exchange ──────────────────────────
export async function handleTokenRequest(
  services: Services,
  req: OAuthHttpRequest,
  reply: OAuthHttpReply,
) {
  const body = readOAuthParams(req.body);
  if (!body) return sendOAuthError(reply, 400, 'invalid_request', OAUTH_PARAMS_NOT_STRINGS);
  const grant_type = body['grant_type'];
  if (grant_type === 'authorization_code') {
    return handleAuthorizationCodeGrant(services, req, reply, body);
  }
  if (grant_type === 'refresh_token') {
    return handleRefreshGrant(services, req, reply, body);
  }
  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    return handleDeviceTokenGrant(services, req, reply, body);
  }
  if (grant_type === GRANT_TYPE_TOKEN_EXCHANGE) {
    return handleTokenExchangeGrant(services, req, reply, body);
  }
  return sendOAuthError(reply, 400, 'unsupported_grant_type');
}
