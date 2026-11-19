import { eq } from 'drizzle-orm';
import {
  ids,
  oauthClients, oauthDeviceCodes,
  OAUTH_DEVICE_CODE_TTL_SECONDS,
  OAUTH_DEVICE_CODE_INTERVAL_SECONDS,
  deployment,
} from '@stack/shared';
import { env } from '../../config/env.js';
import {
  hashToken, generateUserCode,
  audienceForResource, isValidScope, stripRetiredScopes,
  scopeForResource, defaultScopeForResource,
} from '../oauth-helpers.js';
import type { OAuthFlowContext, OAuthHttpReply, OAuthHttpRequest } from './context.js';
import { OAUTH_PARAMS_NOT_STRINGS, readOAuthParams, sendOAuthError } from './responses.js';

// ─── /oauth/device/authorize (RFC 8628) ───────────────────────────
export async function handleDeviceAuthorize(
  { db }: OAuthFlowContext,
  req: OAuthHttpRequest,
  reply: OAuthHttpReply,
) {
  const body = readOAuthParams(req.body);
  if (!body) return sendOAuthError(reply, 400, 'invalid_request', OAUTH_PARAMS_NOT_STRINGS);
  const client_id = body['client_id'];
  const resource = body['resource'] ?? deployment().apiBaseUrl;
  const requestedScope = stripRetiredScopes(body['scope'] ?? defaultScopeForResource(resource));

  if (!client_id) return sendOAuthError(reply, 400, 'invalid_request', 'client_id required');
  if (!isValidScope(requestedScope)) return sendOAuthError(reply, 400, 'invalid_scope');
  if (!audienceForResource(resource)) return sendOAuthError(reply, 400, 'invalid_target');
  const scope = scopeForResource(resource, requestedScope);
  if (!scope) return sendOAuthError(reply, 400, 'invalid_scope');

  const client = await db.query.oauthClients.findFirst({ where: eq(oauthClients.id, client_id) });
  if (!client) return sendOAuthError(reply, 401, 'invalid_client');

  const rawDeviceCode = ids.oauthDeviceCode();
  // user_code uniqueness — collisions theoretically possible across the
  // small alphabet × 8 chars space (~6.6e11), but the at-rest set is bounded
  // to <1k pending codes; retry once on conflict.
  let userCode = generateUserCode();
  for (let i = 0; i < 3; i++) {
    const existing = await db.query.oauthDeviceCodes.findFirst({ where: eq(oauthDeviceCodes.user_code, userCode) });
    if (!existing) break;
    userCode = generateUserCode();
  }

  await db.insert(oauthDeviceCodes).values({
    device_code_hash: hashToken(rawDeviceCode),
    user_code: userCode,
    client_id,
    scope,
    resource,
    status: 'pending',
    expires_at: new Date(Date.now() + OAUTH_DEVICE_CODE_TTL_SECONDS * 1000),
    interval_seconds: OAUTH_DEVICE_CODE_INTERVAL_SECONDS,
  });

  const verificationUri = `${env.DASHBOARD_URL}/cli/auth`;
  return reply.send({
    device_code: rawDeviceCode,
    user_code: userCode,
    verification_uri: verificationUri,
    verification_uri_complete: `${verificationUri}?code=${encodeURIComponent(userCode)}`,
    expires_in: OAUTH_DEVICE_CODE_TTL_SECONDS,
    interval: OAUTH_DEVICE_CODE_INTERVAL_SECONDS,
  });
}
