import { z } from 'zod';

// The wire shapes of STACK's OAuth authorization server (spec/oauth-profile).
// The discovery handler builds its document through OAuthServerMetadata, and
// the specification's JSON Schemas are generated from all of these by
// scripts/generate-spec.mjs. The error body is the flat RFC 6749 section 5.2
// shape, not the API's error envelope.

/** RFC 6749 section 5.2 and the codes of RFC 7591, RFC 8628 and RFC 8707. */
export const OAuthError = z.object({
  error: z.string().min(1),
  error_description: z.string().optional(),
});
export type OAuthError = z.infer<typeof OAuthError>;

/** GET /.well-known/oauth-authorization-server (RFC 8414). */
export const OAuthServerMetadata = z.object({
  issuer: z.string().url(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  device_authorization_endpoint: z.string().url(),
  registration_endpoint: z.string().url(),
  revocation_endpoint: z.string().url(),
  jwks_uri: z.string().url(),
  response_types_supported: z.array(z.literal('code')).length(1),
  grant_types_supported: z.array(z.string().min(1)).min(1),
  code_challenge_methods_supported: z.array(z.literal('S256')).length(1),
  token_endpoint_auth_methods_supported: z.array(z.literal('none')).length(1),
  client_id_metadata_document_supported: z.literal(true),
  scopes_supported: z.array(z.string().min(1)).min(1),
  service_documentation: z.string().url(),
});
export type OAuthServerMetadata = z.infer<typeof OAuthServerMetadata>;

/** The answer of /oauth/token to an authorization code, refresh token or device code. */
export const OAuthTokenResponse = z.object({
  access_token: z.string().min(1),
  token_type: z.literal('Bearer'),
  expires_in: z.number().int().positive(),
  refresh_token: z.string().min(1),
  scope: z.string().min(1),
});
export type OAuthTokenResponse = z.infer<typeof OAuthTokenResponse>;

/** The answer of /oauth/token to a token exchange (RFC 8693): a refreshed Passport. */
export const OAuthTokenExchangeResponse = z.object({
  access_token: z.string().min(1),
  issued_token_type: z.literal('urn:stack:token-type:passport'),
  token_type: z.literal('N_A'),
  expires_in: z.number().int().nonnegative(),
});
export type OAuthTokenExchangeResponse = z.infer<typeof OAuthTokenExchangeResponse>;

/** POST /oauth/register (RFC 7591): the members STACK reads. Others are ignored. */
export const OAuthClientRegistrationRequest = z.object({
  redirect_uris: z.array(z.string().min(1).max(2048)).min(1).max(20),
  client_name: z.string().min(1).max(200),
  grant_types: z.array(z.string()).optional(),
  scope: z.string().max(1024).optional(),
  software_id: z.string().optional(),
  software_version: z.string().optional(),
}).passthrough();
export type OAuthClientRegistrationRequest = z.infer<typeof OAuthClientRegistrationRequest>;

/** POST /oauth/register: the 201 answer. Every client is public. */
export const OAuthClientRegistrationResponse = z.object({
  client_id: z.string().min(1),
  client_id_issued_at: z.number().int(),
  client_name: z.string().min(1),
  redirect_uris: z.array(z.string()).min(1),
  grant_types: z.array(z.string()).min(1),
  response_types: z.array(z.literal('code')).length(1),
  token_endpoint_auth_method: z.literal('none'),
  scope: z.string().min(1),
});
export type OAuthClientRegistrationResponse = z.infer<typeof OAuthClientRegistrationResponse>;

/** POST /oauth/device/authorize (RFC 8628): the answer. */
export const OAuthDeviceAuthorizationResponse = z.object({
  device_code: z.string().min(1),
  user_code: z.string().regex(/^[BCDFGHJKLMNPQRSTVWXYZ2-9]{4}-[BCDFGHJKLMNPQRSTVWXYZ2-9]{4}$/),
  verification_uri: z.string().url(),
  verification_uri_complete: z.string().url(),
  expires_in: z.number().int().positive(),
  interval: z.number().int().positive(),
});
export type OAuthDeviceAuthorizationResponse = z.infer<typeof OAuthDeviceAuthorizationResponse>;

/**
 * The Client ID Metadata Document a client publishes at its https client_id
 * (draft-ietf-oauth-client-id-metadata-document), as STACK reads it. Members
 * not named here are ignored. `client_secret` and `client_secret_expires_at`
 * make the document invalid.
 */
export const OAuthClientMetadataDocument = z.object({
  client_id: z.string().url().max(1024),
  client_name: z.string().min(1).max(200).optional(),
  redirect_uris: z.array(z.string().min(1).max(2048)).min(1).max(20),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.literal('code')).length(1).optional(),
  token_endpoint_auth_method: z.string().optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
}).passthrough();
export type OAuthClientMetadataDocument = z.infer<typeof OAuthClientMetadataDocument>;
