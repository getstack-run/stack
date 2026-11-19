import {
  ids,
  OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP,
  OAUTH_ACCESS_TOKEN_TTL_SECONDS_API,
  OAUTH_ACCESS_TOKEN_AUDIENCE_API,
  OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
} from '@stack/shared';
import type { Services } from '../../config/services.js';

// ─── Token mint helper ───────────────────────────────────────────────

export type TokenArgs = {
  operatorId: string;
  memberId: string | null;
  clientId: string;
  scope: string;
  resource: string;
  audience: typeof OAUTH_ACCESS_TOKEN_AUDIENCE_API | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_MCP;
  tokenFamilyId: string;
};

export async function issueAccessToken(
  services: Services,
  args: TokenArgs,
): Promise<{ access_token: string; token_type: 'Bearer'; expires_in: number; scope: string }> {
  const accessTtl =
    args.audience === OAUTH_ACCESS_TOKEN_AUDIENCE_MCP
      ? OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP
      : OAUTH_ACCESS_TOKEN_TTL_SECONDS_API;
  const jti = ids.oauthAccessTokenJti();
  const access_token = await services.signer.signAccessToken({
    operatorId: args.operatorId,
    audience: args.audience,
    clientId: args.clientId,
    scope: args.scope,
    jti,
    ttlSeconds: accessTtl,
    memberId: args.memberId ?? undefined,
    tokenFamilyId: args.tokenFamilyId, // binds the access token to its family for live revocation
    // MCP tokens carry their exact resource so /mcp and /directory can each
    // refuse a token granted for the other. API tokens keep their old shape.
    ...(args.audience === OAUTH_ACCESS_TOKEN_AUDIENCE_MCP ? { resource: args.resource } : {}),
  });

  return {
    access_token,
    token_type: 'Bearer',
    expires_in: accessTtl,
    scope: args.scope,
  };
}

export async function prepareTokenPair(
  services: Services,
  args: TokenArgs,
): Promise<{ access_token: string; token_type: 'Bearer'; expires_in: number; refresh_token: string; scope: string }> {
  const access = await issueAccessToken(services, args);
  const refresh_token = ids.oauthRefreshToken();
  return {
    ...access,
    refresh_token,
  };
}

export function recordMcpSetupCompleted(
  services: Services,
  operatorId: string,
  clientId: string,
  audience: typeof OAUTH_ACCESS_TOKEN_AUDIENCE_API | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
): void {
  if (audience === OAUTH_ACCESS_TOKEN_AUDIENCE_MCP) {
    services.analytics.fireOnce(operatorId, 'mcp_setup_completed', { client_id: clientId });
  }
}
