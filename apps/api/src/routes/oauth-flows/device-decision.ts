import { eq } from 'drizzle-orm';
import { oauthDeviceCodes, operators } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { decideDeviceCode, type DeviceCodeDecision } from '../../services/oauth-grant-state.js';
import { tryReadCookieSession } from './cookie-session.js';
import { audit } from './records.js';
import { enforceAccessForOperator } from '../../middleware/auth.js';
import { enforceMemberFloor } from '../../middleware/member-floor.js';
import { OAUTH_PARAMS_NOT_STRINGS, readOAuthParams, sendOAuthError } from './responses.js';

type DeviceDecisionFailure = Exclude<DeviceCodeDecision, { kind: 'success' }>;

/** The OAuth error answering a decision that did not take effect. */
function deviceDecisionFailure(reply: import('fastify').FastifyReply, result: DeviceDecisionFailure) {
  switch (result.kind) {
    case 'not_found': return sendOAuthError(reply, 404, 'invalid_grant', 'unknown user_code');
    case 'operator_inactive':
    case 'member_inactive': return sendOAuthError(reply, 401, 'access_denied');
    case 'expired': return sendOAuthError(reply, 400, 'expired_token');
    case 'already_decided': return sendOAuthError(reply, 400, 'invalid_grant', 'already decided');
  }
}

// ─── /oauth/device/approve + /oauth/device/deny ──────────────────
// Called by the dashboard /cli/auth approval UI. Cookie-session-gated.
// Approves or denies a pending device code by user_code (the human-
// readable form, e.g. WDJB-MJHT). The dashboard verifies the operator's
// session before accepting POST; we re-verify on the API side because
// CSRF resilience is operator-table-gated, not just origin-gated.
export async function handleDeviceDecision(
  services: Services,
  req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
  decision: 'approve' | 'deny',
) {
  const body = readOAuthParams(req.body);
  if (!body) return sendOAuthError(reply, 400, 'invalid_request', OAUTH_PARAMS_NOT_STRINGS);
  const userCode = body['user_code'];
  if (!userCode) return sendOAuthError(reply, 400, 'invalid_request', 'user_code required');

  const session = await tryReadCookieSession(services, req);
  if (!session) return sendOAuthError(reply, 401, 'access_denied');
  const op = await services.db.query.operators.findFirst({ where: eq(operators.id, session.operatorId) });
  if (!op || op.status !== 'active') return sendOAuthError(reply, 401, 'access_denied');
  // An account with no platform subscription connects nothing: the same 402 as the API, before any other work.
  await enforceAccessForOperator(services, { method: 'POST', route: '/oauth/device/approve', operatorId: op.id });
  // The member's own approval or refusal of a device sign-in is on the floor's allowlist: the token it issues carries the member.
  enforceMemberFloor(services, { method: 'POST', route: `/oauth/device/${decision}`, memberId: session.memberId, memberRole: session.memberRole });

  // Refuse 'admin' scope from non-admin members at approval boundary.
  // A standard/readonly member who somehow finds a pending device code
  // requesting admin scope cannot promote it to live tokens.
  const row = await services.db.query.oauthDeviceCodes.findFirst({ where: eq(oauthDeviceCodes.user_code, userCode) });
  if (!row) return sendOAuthError(reply, 404, 'invalid_grant', 'unknown user_code');
  if (row.status !== 'pending') return sendOAuthError(reply, 400, 'invalid_grant', 'already decided');
  if (row.expires_at.getTime() < Date.now()) return sendOAuthError(reply, 400, 'expired_token');

  if (decision === 'approve') {
    if (session.memberId) {
      // Re-load + role-check at write time. Member must be active.
      const member = await services.member.findById(session.memberId);
      if (!member || member.status !== 'active') return sendOAuthError(reply, 401, 'access_denied');
      if (member.role !== 'admin' && row.scope.split(/\s+/).includes('admin')) {
        return sendOAuthError(reply, 400, 'invalid_scope', 'admin scope requires admin role');
      }
    }
    const result = await decideDeviceCode(services.db, {
      userCode,
      decision,
      operatorId: op.id,
      sessionEmail: session.email,
      ownerSessionRevision: session.ownerSessionRevision,
      memberId: session.memberId ?? null,
    });
    if (result.kind !== 'success') return deviceDecisionFailure(reply, result);
    await audit(services, op.id, 'oauth.device_approve', {
      client_id: result.row.client_id,
      scope: result.row.scope,
      resource: result.row.resource,
      member_id: session.memberId ?? null,
    });
    return reply.send({ status: 'approved' });
  }
  const result = await decideDeviceCode(services.db, {
    userCode,
    decision,
    operatorId: op.id,
    sessionEmail: session.email,
    ownerSessionRevision: session.ownerSessionRevision,
    memberId: session.memberId ?? null,
  });
  if (result.kind !== 'success') return deviceDecisionFailure(reply, result);
  await audit(services, op.id, 'oauth.device_deny', {
    client_id: result.row.client_id,
    member_id: session.memberId ?? null,
  });
  return reply.send({ status: 'denied' });
}
