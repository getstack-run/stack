import { eq } from 'drizzle-orm';
import { ids, oauthAuthorizationCodes } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { hashToken, verifyPkceS256, audienceForResource } from '../oauth-helpers.js';
import { consumeAuthorizationCode } from '../../services/oauth-grant-state.js';
import { sendOAuthError } from './responses.js';
import { audit, recordSecurityEvent } from './records.js';
import { prepareTokenPair, recordMcpSetupCompleted } from './token-issuance.js';

// ─── Grant handlers ──────────────────────────────────────────────────

// Redemption of an authorization code. PKCE is verified twice: here against
// the stored challenge before any token is minted, and again inside the
// atomic claim in consumeAuthorizationCode so a racing redeemer cannot slip
// past the first check.
export async function handleAuthorizationCodeGrant(
  services: Services,
  _req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
  body: Record<string, string | undefined>,
) {
  const code = body['code'];
  const redirect_uri = body['redirect_uri'];
  const client_id = body['client_id'];
  const code_verifier = body['code_verifier'];

  if (!code || !redirect_uri || !client_id || !code_verifier) {
    return sendOAuthError(reply, 400, 'invalid_request', 'code, redirect_uri, client_id, code_verifier required');
  }

  const codeHash = hashToken(code);
  const candidate = await services.db.query.oauthAuthorizationCodes.findFirst({
    where: eq(oauthAuthorizationCodes.code_hash, codeHash),
  });
  if (!candidate) return sendOAuthError(reply, 400, 'invalid_grant', 'unknown code');
  if (candidate.consumed_at) return sendOAuthError(reply, 400, 'invalid_grant', 'code already used');
  if (candidate.expires_at.getTime() < Date.now()) return sendOAuthError(reply, 400, 'invalid_grant', 'code expired');
  if (candidate.client_id !== client_id) return sendOAuthError(reply, 400, 'invalid_grant', 'client_id mismatch');
  if (candidate.redirect_uri !== redirect_uri) return sendOAuthError(reply, 400, 'invalid_grant', 'redirect_uri mismatch');
  if (!verifyPkceS256(code_verifier, candidate.code_challenge)) {
    await recordSecurityEvent(services, candidate.operator_id, 'oauth_invalid_pkce', 'warning', 'PKCE verifier did not match challenge', { client_id });
    return sendOAuthError(reply, 400, 'invalid_grant', 'PKCE verification failed');
  }
  const aud = audienceForResource(candidate.resource);
  if (!aud) return sendOAuthError(reply, 400, 'invalid_target');
  const tokenFamilyId = ids.oauthTokenFamily();
  const tokens = await prepareTokenPair(services, {
    operatorId: candidate.operator_id,
    memberId: candidate.member_id,
    clientId: candidate.client_id,
    scope: candidate.scope,
    resource: candidate.resource,
    audience: aud,
    tokenFamilyId,
  });

  const claim = await consumeAuthorizationCode(services.db, {
    codeHash,
    clientId: client_id,
    redirectUri: redirect_uri,
    codeVerifier: code_verifier,
    refreshToken: tokens.refresh_token,
    tokenFamilyId,
  });
  if (claim.kind === 'invalid_grant') {
    return sendOAuthError(reply, 400, 'invalid_grant', claim.description);
  }
  if (claim.kind === 'invalid_pkce') {
    await recordSecurityEvent(services, claim.row.operator_id, 'oauth_invalid_pkce', 'warning', 'PKCE verifier did not match challenge', { client_id });
    return sendOAuthError(reply, 400, 'invalid_grant', 'PKCE verification failed');
  }
  const row = claim.row;
  recordMcpSetupCompleted(services, row.operator_id, row.client_id, aud);

  await audit(services, row.operator_id, 'oauth.token_issue', {
    grant_type: 'authorization_code',
    client_id: row.client_id,
    scope: row.scope,
    resource: row.resource,
    member_id: row.member_id,
  });

  return reply.send(tokens);
}
