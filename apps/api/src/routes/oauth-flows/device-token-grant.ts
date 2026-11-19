import { eq } from 'drizzle-orm';
import { ids, oauthDeviceCodes, OAUTH_DEVICE_CODE_MAX_INTERVAL_SECONDS } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { hashToken, audienceForResource } from '../oauth-helpers.js';
import { consumeApprovedDeviceCode } from '../../services/oauth-grant-state.js';
import { sendOAuthError } from './responses.js';
import { audit } from './records.js';
import { prepareTokenPair, recordMcpSetupCompleted } from './token-issuance.js';

export async function handleDeviceTokenGrant(
  services: Services,
  _req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
  body: Record<string, string | undefined>,
) {
  const device_code = body['device_code'];
  const client_id = body['client_id'];
  if (!device_code || !client_id) return sendOAuthError(reply, 400, 'invalid_request');

  const row = await services.db.query.oauthDeviceCodes.findFirst({ where: eq(oauthDeviceCodes.device_code_hash, hashToken(device_code)) });
  if (!row) return sendOAuthError(reply, 400, 'invalid_grant', 'unknown device_code');
  if (row.client_id !== client_id) return sendOAuthError(reply, 400, 'invalid_grant', 'client_id mismatch');
  if (row.expires_at.getTime() < Date.now()) {
    return sendOAuthError(reply, 400, 'expired_token');
  }
  if (row.status === 'denied') return sendOAuthError(reply, 400, 'access_denied');
  if (row.status === 'pending') {
    // Slow-down enforcement: client polled too fast → bump interval and report slow_down.
    const now = Date.now();
    if (row.last_polled_at && (now - row.last_polled_at.getTime()) / 1000 < row.interval_seconds) {
      const newInterval = Math.min(row.interval_seconds * 2, OAUTH_DEVICE_CODE_MAX_INTERVAL_SECONDS);
      await services.db
        .update(oauthDeviceCodes)
        .set({ interval_seconds: newInterval, last_polled_at: new Date() })
        .where(eq(oauthDeviceCodes.device_code_hash, row.device_code_hash));
      return sendOAuthError(reply, 400, 'slow_down');
    }
    await services.db
      .update(oauthDeviceCodes)
      .set({ last_polled_at: new Date() })
      .where(eq(oauthDeviceCodes.device_code_hash, row.device_code_hash));
    return sendOAuthError(reply, 400, 'authorization_pending');
  }
  if (row.status !== 'approved' || !row.operator_id) {
    return sendOAuthError(reply, 400, 'authorization_pending');
  }

  const aud = audienceForResource(row.resource);
  if (!aud) return sendOAuthError(reply, 400, 'invalid_target');

  const tokenFamilyId = ids.oauthTokenFamily();
  const tokens = await prepareTokenPair(services, {
    operatorId: row.operator_id,
    memberId: row.member_id ?? null,
    clientId: row.client_id,
    scope: row.scope,
    resource: row.resource,
    audience: aud,
    tokenFamilyId,
  });
  const claim = await consumeApprovedDeviceCode(services.db, {
    deviceCodeHash: row.device_code_hash,
    clientId: client_id,
    refreshToken: tokens.refresh_token,
    tokenFamilyId,
  });
  if (claim.kind === 'invalid_grant') {
    return sendOAuthError(reply, 400, 'invalid_grant', claim.description);
  }
  const claimed = claim.row;
  recordMcpSetupCompleted(services, claimed.operator_id!, claimed.client_id, aud);

  await audit(services, claimed.operator_id!, 'oauth.token_issue', {
    grant_type: 'device_code',
    client_id: claimed.client_id,
    scope: claimed.scope,
    resource: claimed.resource,
    member_id: claimed.member_id ?? null,
  });
  return reply.send(tokens);
}
