import { eq } from 'drizzle-orm';
import { operators } from '@stack/shared';
import { issueAuthorizationCode } from '../../services/oauth-grant-state.js';
import type { OAuthFlowContext, OAuthHttpReply, OAuthHttpRequest } from './context.js';
import { OAUTH_PARAMS_NOT_STRINGS, readOAuthParams, sendOAuthError } from './responses.js';
import { tryReadCookieSession } from './cookie-session.js';
import { audit } from './records.js';
import { enforceAccessForOperator } from '../../middleware/auth.js';
import { enforceMemberFloor } from '../../middleware/member-floor.js';

// ─── POST /oauth/authorize — consent confirm ───────────────────────
// Called by the dashboard /oauth/consent page on user approval.
// Verifies the consent JWT against the cookie session (defense in
// depth), mints the auth code, and 302s to client redirect_uri.
export async function handleConsentDecision(
  { services, db }: OAuthFlowContext,
  req: OAuthHttpRequest,
  reply: OAuthHttpReply,
) {
  const body = readOAuthParams(req.body);
  if (!body) return sendOAuthError(reply, 400, 'invalid_request', OAUTH_PARAMS_NOT_STRINGS);
  const consentJwt = body['state'];
  const decision = body['decision'];
  if (!consentJwt) return sendOAuthError(reply, 400, 'invalid_request', 'state required');

  let claims: Awaited<ReturnType<typeof services.signer.verifyOAuthConsentToken>>;
  try {
    claims = await services.signer.verifyOAuthConsentToken(consentJwt);
  } catch {
    return sendOAuthError(reply, 400, 'invalid_request', 'invalid or expired consent token');
  }

  // The dashboard proxy forwards the user's cookie session as a header
  // here; we read it, validate operator + (optional) member context,
  // and stamp the auth code with both. The consent JWT itself binds the
  // request bundle (client_id, redirect_uri, scope, resource, PKCE
  // challenge) — its `sub` is the literal 'pending' since GET
  // /oauth/authorize doesn't see cookies. Authoritative identity comes
  // from the cookie session at this POST. Returns JSON {redirect_url}
  // so the dashboard's proxy route can issue the eventual 302 to the
  // browser — the API itself does not know which origin the cookie
  // lives on, so it cannot do that 302 with cookie continuity.
  const session = await tryReadCookieSession(services, req);
  if (!session) return sendOAuthError(reply, 401, 'access_denied', 'no session');
  // An account with no platform subscription connects nothing: the same 402 as the API, before any other work.
  await enforceAccessForOperator(services, { method: 'POST', route: '/oauth/authorize', operatorId: session.operatorId });
  // The member's own consent for a client they connect is on the floor's allowlist: the token it issues carries the member,
  // so what they connect stays read-only. Any other member route is refused to a read-only member here as everywhere.
  enforceMemberFloor(services, { method: 'POST', route: '/oauth/authorize', memberId: session.memberId, memberRole: session.memberRole });

  if (decision !== 'approve') {
    const denyUrl = new URL(claims.claims.redirect_uri);
    denyUrl.searchParams.set('error', 'access_denied');
    if (claims.claims.state) denyUrl.searchParams.set('state', claims.claims.state);
    return reply.send({ redirect_url: denyUrl.toString() });
  }

  const op = await db.query.operators.findFirst({ where: eq(operators.id, session.operatorId) });
  if (!op || op.status !== 'active') return sendOAuthError(reply, 401, 'access_denied', 'operator not active');

  // Member binding (if any) comes from the cookie session, NOT the
  // consent JWT — that JWT was minted at GET /oauth/authorize before
  // we knew who the user was. The cookie is the authoritative session.
  if (session.memberId) {
    const member = await services.member.findById(session.memberId);
    if (!member || member.status !== 'active') return sendOAuthError(reply, 401, 'access_denied', 'member not active');
    if (member.role !== 'admin' && claims.claims.scope.split(/\s+/).includes('admin')) {
      return sendOAuthError(reply, 400, 'invalid_scope', 'admin scope requires admin role');
    }
  }

  const issued = await issueAuthorizationCode(db, {
    operatorId: op.id,
    sessionEmail: session.email,
    ownerSessionRevision: session.ownerSessionRevision,
    clientId: claims.claims.client_id,
    memberId: session.memberId ?? null,
    redirectUri: claims.claims.redirect_uri,
    scope: claims.claims.scope,
    resource: claims.claims.resource,
    codeChallenge: claims.claims.code_challenge,
    codeChallengeMethod: claims.claims.code_challenge_method,
    nonce: claims.claims.nonce ?? null,
  });
  if (issued.kind === 'operator_inactive') {
    return sendOAuthError(reply, 401, 'access_denied', 'operator not active');
  }
  if (issued.kind === 'member_inactive') {
    return sendOAuthError(reply, 401, 'access_denied', 'member not active');
  }

  await audit(services, op.id, 'oauth.authorize', {
    client_id: claims.claims.client_id,
    scope: claims.claims.scope,
    resource: claims.claims.resource,
    member_id: session.memberId ?? null,
  });

  const back = new URL(claims.claims.redirect_uri);
  back.searchParams.set('code', issued.code);
  if (claims.claims.state) back.searchParams.set('state', claims.claims.state);
  return reply.send({ redirect_url: back.toString() });
}
