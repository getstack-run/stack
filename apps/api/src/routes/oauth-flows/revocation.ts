import {
  OAUTH_FAMILY_REVOKED_KEY,
  OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP,
  safeErrorSummary,
} from '@stack/shared';
import { revokeRefreshFamilyByToken } from '../../services/oauth-grant-state.js';
import type { OAuthFlowContext, OAuthHttpReply, OAuthHttpRequest } from './context.js';
import { audit } from './records.js';
import { OAUTH_PARAMS_NOT_STRINGS, readOAuthParams, sendOAuthError } from './responses.js';

// ─── /oauth/revoke (RFC 7009) ─────────────────────────────────────
// Revoke the refresh family. Access tokens carry the family id. The
// next STACK-verified call rejects them, with a one-hour hard TTL.
export async function handleRevocation(
  { services, db }: OAuthFlowContext,
  req: OAuthHttpRequest,
  reply: OAuthHttpReply,
) {
  const body = readOAuthParams(req.body);
  if (!body) return sendOAuthError(reply, 400, 'invalid_request', OAUTH_PARAMS_NOT_STRINGS);
  const token = body['token'];
  if (!token) return reply.code(200).send({}); // RFC 7009 §2.2: always 200 even on unknown token
  const row = await revokeRefreshFamilyByToken(db, { refreshToken: token, reason: 'logout' });
  if (row) {
    try {
      await services.redis.set(
        OAUTH_FAMILY_REVOKED_KEY(row.token_family_id), '1', 'EX', OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP,
      );
    } catch (err) {
      console.error('[oauth] family revocation Redis write failed', safeErrorSummary(err));
    }
    await audit(services, row.operator_id, 'oauth.token_revoke', { token_family_id: row.token_family_id });
  }
  return reply.code(200).send({});
}
