import {
  OAUTH_FAMILY_REVOKED_KEY,
  OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP,
  safeErrorSummary,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { isValidScope, audienceForResource, stripRetiredScopes } from '../oauth-helpers.js';
import { rotateRefreshGrant } from '../../services/oauth-grant-state.js';
import { sendOAuthError } from './responses.js';
import { audit, recordSecurityEvent } from './records.js';
import { issueAccessToken } from './token-issuance.js';

export async function handleRefreshGrant(
  services: Services,
  req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
  body: Record<string, string | undefined>,
) {
  const refresh_token = body['refresh_token'];
  const client_id = body['client_id'];
  const requestedScope = body['scope'] === undefined ? undefined : stripRetiredScopes(body['scope']);
  if (!refresh_token || !client_id) return sendOAuthError(reply, 400, 'invalid_request', 'refresh_token, client_id required');
  if (requestedScope !== undefined && !isValidScope(requestedScope)) {
    return sendOAuthError(reply, 400, 'invalid_scope');
  }

  const result = await rotateRefreshGrant(
    { db: services.db, kms: services.kms },
    {
      refreshToken: refresh_token,
      clientId: client_id,
      ip: req.ip,
      userAgent: (req.headers['user-agent'] as string | undefined) ?? null,
      requestedScope,
    },
  );
  if (result.kind === 'invalid_grant') {
    return sendOAuthError(reply, 400, 'invalid_grant', result.description);
  }
  if (result.kind === 'invalid_scope') {
    return sendOAuthError(reply, 400, 'invalid_scope', result.description);
  }
  if (result.kind === 'temporarily_unavailable') {
    reply.header('Retry-After', '1');
    return sendOAuthError(reply, 503, 'temporarily_unavailable', 'refresh recovery temporarily unavailable');
  }
  if (result.kind === 'reuse') {
    // Kill any already-issued access token of this family on its next call.
    try {
      await services.redis.set(
        OAUTH_FAMILY_REVOKED_KEY(result.row.token_family_id), '1', 'EX', OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP,
      );
    } catch (err) {
      // The DB family state is authoritative. Auth checks it as a fallback.
      // Keep recording the critical event even when the cache write fails.
      console.error('[oauth] reuse revocation Redis write failed', safeErrorSummary(err));
    }
    const message = result.reason === 'integrity_failure'
      ? 'Refresh successor failed integrity validation'
      : 'Replayed refresh token (already rotated)';
    await recordSecurityEvent(services, result.row.operator_id, 'oauth_refresh_reuse', 'critical', message, {
      client_id, token_family_id: result.row.token_family_id, reason: result.reason,
    });
    return sendOAuthError(reply, 400, 'invalid_grant', `${result.reason === 'integrity_failure' ? 'refresh integrity failure' : 'refresh reuse detected'}; family revoked`);
  }

  const row = result.row;
  const aud = audienceForResource(row.resource);
  if (!aud) return sendOAuthError(reply, 400, 'invalid_target');
  const access = await issueAccessToken(services, {
    operatorId: row.operator_id,
    memberId: row.member_id ?? null,
    clientId: row.client_id,
    scope: row.scope,
    resource: row.resource,
    audience: aud,
    tokenFamilyId: row.token_family_id,
  });
  await audit(services, row.operator_id, result.retry ? 'oauth.token_refresh_retry' : 'oauth.token_refresh', {
    client_id, token_family_id: row.token_family_id,
  });
  return reply.send({ ...access, refresh_token: result.refreshToken });
}
