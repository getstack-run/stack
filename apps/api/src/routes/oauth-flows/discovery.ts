import {
  deployment,
  OAUTH_SCOPES,
  GRANT_TYPE_TOKEN_EXCHANGE,
  OAuthServerMetadata,
} from '@stack/shared';
import type { OAuthHttpReply } from './context.js';

// ─── Discovery (RFC 8414) ───────────────────────────────────────────
export async function handleDiscovery(reply: OAuthHttpReply) {
  const issuer = deployment().apiBaseUrl;
  return reply.send(OAuthServerMetadata.parse({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    device_authorization_endpoint: `${issuer}/oauth/device/authorize`,
    registration_endpoint: `${issuer}/oauth/register`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    jwks_uri: `${issuer}/v1/internal/jwks`,
    response_types_supported: ['code'],
    grant_types_supported: [
      'authorization_code',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:device_code',
      GRANT_TYPE_TOKEN_EXCHANGE,
    ],
    code_challenge_methods_supported: ['S256'],
    // Every client is public: /oauth/token takes no client secret, so none is advertised.
    token_endpoint_auth_methods_supported: ['none'],
    // An https client_id is resolved as a Client ID Metadata Document and
    // registered as a public ("none") client. DCR remains available.
    client_id_metadata_document_supported: true,
    scopes_supported: [...OAUTH_SCOPES],
    service_documentation: `${deployment().siteUrl}/docs/security/stack-auth`,
  }));
}
