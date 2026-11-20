import { OAUTH_DIRECTORY_DEFAULT_SCOPES, OAUTH_MCP_DEFAULT_SCOPES } from '@stack/shared';

// Protected-resource metadata scopes and the scope named in each endpoint's
// 401 challenge. The sets live in @stack/shared so the authorization server
// and the deployment's own tool-scope test use the same lists.
//
// /mcp requests every scope its tools need except the explicit incremental
// grants (team mutation, raw credentials, payout mutation, OAuth-app/CMEK
// administration, authority/identity configuration, marketplace publishing,
// partner administration and platform admin). The account's own scopes
// (accounts:manage, account:write, billing:write, governance:write,
// security-events:write) are in the default, so a person's sign-in from a chat
// needs no second consent; each route's own gates decide who may act. The
// write scopes it does request authorize routine operations only:
// direction-aware API gates still require payload-bound browser approval before
// any agent/grant expansion or security-control weakening.
export const MCP_OAUTH_SCOPES = OAUTH_MCP_DEFAULT_SCOPES;

// /directory requests the scopes its tools need, all inside the authorization
// server's directory ceiling (OAUTH_DIRECTORY_SCOPES), which the server also
// enforces on every directory token.
export const MCP_DIRECTORY_OAUTH_SCOPES = OAUTH_DIRECTORY_DEFAULT_SCOPES;
