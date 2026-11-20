# STACK OAuth Server Profile

**Specification:** STACK OAuth Server Profile
**Version:** 2.0.0
**Status:** Stable
**Licence:** Apache-2.0

STACK is an OAuth 2.1 authorization server for the clients that act for a person: an AI client (a chat app, a coding agent, an IDE), a command-line tool, an SDK. This document is a profile of the existing OAuth standards. It says which parts of them STACK implements, which it does not, and what is particular to STACK: the discovery document, how a client identifies itself (a metadata document at its own address, or registration), the authorization code flow with PKCE, the device flow, the resources a token is for, the scopes, the lifetimes of tokens, rotation of refresh tokens, revocation, and the one token exchange STACK offers.

Contents: 1 Conventions, 2 Standards, 3 Discovery, 4 Clients, 5 Resources and scopes, 6 Authorization request, 7 Token endpoint, 8 Tokens and their lifetimes, 9 Revocation, 10 Errors, 11 Security considerations, 12 Machine-readable schemas and conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The **server** is a STACK deployment with OAuth enabled; the **client** is the software that asks for tokens; the **person** is the owner or team member who approves. A **base address** is the origin of the deployment's API (the hosted service, or a self-managed install's own address), written `{base}` below. A server conforms to this profile if it satisfies every MUST; the `oauth` conformance suite tests a running server, and the `oauth-client-metadata` suite tests the check of a client metadata document.

A deployment can switch OAuth off. When it is off, none of the endpoints below exist and a client sees `404`.

## 2. Standards

| Standard | What STACK takes from it |
|---|---|
| RFC 6749 (OAuth 2.0) and the OAuth 2.1 draft | The authorization code grant and refresh token grant; the token endpoint and its errors. No implicit grant, no password grant, no client credentials grant. |
| RFC 7636 (PKCE) | Required for every client; only method `S256`. |
| RFC 8414 | The discovery document (section 3). |
| RFC 7591 | Dynamic client registration, for public clients only (4.2). |
| Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document) | A client whose `client_id` is an `https` URL (4.1). |
| RFC 8252 | Redirect URIs of native apps: loopback with any port, private-use schemes. |
| RFC 8628 | The device authorization grant, for command-line tools. |
| RFC 8707 | The `resource` parameter of the authorization and device requests (section 5). |
| RFC 7009 | Revocation, of refresh tokens (section 9). |
| RFC 8693 | Token exchange, one profile: refreshing a Passport (7.5). |
| RFC 9728 | Protected resource metadata, published by the MCP server for each of its resources (section 5). |

Not implemented: client authentication at the token endpoint (every client is public), confidential clients, the `client_credentials` and `password` grants, `plain` PKCE, dynamic client management (RFC 7592), token introspection (RFC 7662), JWT-secured authorization requests, pushed authorization requests, and the `iss` authorization response parameter (RFC 9207).

## 3. Discovery

`GET /.well-known/oauth-authorization-server` answers `200` with an RFC 8414 document ([`schemas/OAuthServerMetadata.json`](schemas/OAuthServerMetadata.json)):

| Member | Value |
|---|---|
| `issuer` | `{base}`. |
| `authorization_endpoint` | `{base}/oauth/authorize`. |
| `token_endpoint` | `{base}/oauth/token`. |
| `device_authorization_endpoint` | `{base}/oauth/device/authorize`. |
| `registration_endpoint` | `{base}/oauth/register`. |
| `revocation_endpoint` | `{base}/oauth/revoke`. |
| `jwks_uri` | `{base}/v1/internal/jwks`: the same key set as `{base}/v1/.well-known/jwks.json` of the [Passport](../passport/SPEC.md) specification, which also signs access tokens. |
| `response_types_supported` | `["code"]`. |
| `grant_types_supported` | `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code`, `urn:ietf:params:oauth:grant-type:token-exchange`. |
| `code_challenge_methods_supported` | `["S256"]`. |
| `token_endpoint_auth_methods_supported` | `["none"]`. |
| `client_id_metadata_document_supported` | `true`. |
| `scopes_supported` | Every scope of section 5.2. |
| `service_documentation` | The deployment's documentation page. |

The `issuer` is the base address, as RFC 8414 requires. The `iss` claim of an access token is not: it is the deployment's short issuer name (`getstack.run` in the hosted service, the install's host in a self-managed one), the same as a Passport's `iss`. A client treats access tokens as opaque and never relies on `iss` to find the metadata.

## 4. Clients

Every client is **public**: it has no secret, and the token endpoint authenticates nothing but the grant it is given. PKCE is what binds a code to the client instance that asked for it. A client identifies itself by one of two means.

### 4.1 Client ID Metadata Document

A `client_id` that is an `https` URL (no credentials, query or fragment, a path other than `/`, no dot segments, at most 1024 characters, and exactly equal to its normalised form) names a document the server fetches and treats as the client's registration. The server MUST:

- fetch it with a GET, over `https` only, resolving the host once and connecting to the address it resolved, refusing any private, loopback, link-local, metadata or internal address, refusing redirects, sending no credentials or cookies, accepting only `200`, reading at most 5 KiB and giving up after 5 seconds;
- require a JSON object ([`schemas/OAuthClientMetadataDocument.json`](schemas/OAuthClientMetadataDocument.json)) whose `client_id` equals the URL byte for byte;
- refuse a document that carries `client_secret` or `client_secret_expires_at`, and one that cannot work as a public client (its `token_endpoint_auth_method` is present and is not `none`, and its `token_endpoint_auth_methods_supported` does not include `none`);
- require 1 to 20 `redirect_uris`, each of at most 2048 characters and each an allowed redirect (4.3);
- require `grant_types`, when present, to be an array of strings that includes `authorization_code`, and keep only the grant types of 4.2; require `response_types`, when present, to be exactly `["code"]`; require `client_name`, when present, to be 1 to 200 characters (the host of the URL is the name otherwise);
- store the client as public, with the document's redirect URIs, and refresh the stored client when the document changes; never overwrite a client that was registered another way under the same identifier;
- cache a valid document for at most 5 minutes (not at all when its response says `no-store`), share one fetch between concurrent requests for the same URL, and bound the cache.

A document that fails any rule is `400 invalid_client` at the authorization endpoint. The error does not say what the fetch saw. The consent screen shows the `client_id` URL, so the host that serves the document is what the person approves.

### 4.2 Dynamic client registration

`POST /oauth/register` takes a JSON object ([`schemas/OAuthClientRegistrationRequest.json`](schemas/OAuthClientRegistrationRequest.json)) and answers `201` ([`schemas/OAuthClientRegistrationResponse.json`](schemas/OAuthClientRegistrationResponse.json)). The server MUST:

- require 1 to 20 `redirect_uris` (4.3) and a `client_name` of 1 to 200 characters;
- register only public clients: the answer has `token_endpoint_auth_method` `none` and no secret, whatever the request asked for;
- keep only the grant types it supports, `authorization_code`, `refresh_token` and `urn:ietf:params:oauth:grant-type:device_code` (the answer says which), and refuse the request when none is left; `grant_types` defaults to `authorization_code` and `refresh_token`. The token exchange grant is not a client grant: it is open to any caller who holds a Passport (7.5);
- accept `scope`, a space-separated list of scopes of section 5.2, defaulting to the default scope of section 5.2;
- limit registration to 10 requests per hour per source address.

Errors are the flat shape of section 10 with `invalid_redirect_uri`, `invalid_client_metadata` or `invalid_scope`.

### 4.3 Redirect URIs

A redirect URI MUST be an `https` URL, an `http` URL whose host is `localhost`, `127.0.0.1` or `[::1]`, or a native app's private-use URI (RFC 8252 section 7.1: a scheme of 2 to 63 characters from `a-z 0-9 + . -`, starting with a letter, that is not `http`, `https`, `javascript`, `data`, `file`, `blob`, `about`, `vbscript`, `filesystem`, `view-source`, `chrome`, `chrome-extension`, `edge`, `moz-extension`, `ws`, `wss`, `ftp`, `mailto`, `tel`, `sms`, `intent`, `content`, `jar` or `urn`, with a host or a path beyond `/`, and no credentials). No URI may contain a fragment.

Matching is exact, with one relaxation (RFC 8252 section 7.3): the port of a registered `http` loopback URI is ignored, because a native client binds a free port when it signs in. Scheme, host, path and query still match exactly. The token request must then present the redirect URI byte for byte as the authorization request did, so a code stays bound to the one port that started the flow.

## 5. Resources and scopes

### 5.1 Resources

A token is for one **resource** (RFC 8707). The server knows three:

| Resource | Access token audience | Served by |
|---|---|---|
| `{base}` (the API) | `stack:api` | The REST API. |
| `{mcp}/mcp` | `stack:mcp` | The MCP server's standard endpoint. |
| `{mcp}/directory` | `stack:mcp` | The MCP server's directory endpoint, which serves only the tools a connector directory lists. |

where `{mcp}` is the origin of the MCP server (`https://mcp.getstack.run` in the hosted service). A request with another `resource` is `400 invalid_target`. A request with none is for the API. The two MCP resources share an audience, so a token also carries the exact resource it was granted for (`resource` claim), and the MCP server refuses a token granted for `/directory` on `/mcp` and the reverse. The `resource` parameter belongs to the authorization and device requests; the token endpoint takes the resource from the grant, and refuses it only on a token exchange (7.5).

The MCP server publishes RFC 9728 protected resource metadata for each of its resources, at `/.well-known/oauth-protected-resource` (and the same path followed by `/mcp` or `/directory`), naming `{base}` as the authorization server and listing the scopes it asks for by default.

### 5.2 Scopes

A scope is one of the values below. A request lists scopes separated by spaces, at most 1024 characters. A scope not in the table is `400 invalid_scope`. A request with no `scope` gets the default scope of its resource.

<!-- spec:generated:oauth-scopes -->

| Scope | Granted for the directory resource | In the default MCP request |
|---|---|---|
| `account:read` | yes | yes |
| `account:write` | - | yes |
| `team:read` | yes | yes |
| `team:write` | - | - |
| `oauth-apps:read` | - | - |
| `oauth-apps:write` | - | - |
| `cmek:read` | - | - |
| `cmek:write` | - | - |
| `passports:read` | yes | yes |
| `passports:write` | yes | yes |
| `agents:read` | yes | yes |
| `agents:write` | yes | yes |
| `accounts:read` | yes | yes |
| `accounts:write` | yes | yes |
| `accounts:act` | - | yes |
| `accounts:manage` | - | yes |
| `services:read` | yes | yes |
| `services:write` | yes | yes |
| `services:connect` | - | yes |
| `inbound-webhooks:read` | yes | yes |
| `inbound-webhooks:write` | yes | yes |
| `credentials:read` | - | - |
| `credentials:write` | - | - |
| `proxy:read` | yes | yes |
| `proxy:write` | - | yes |
| `audit:read` | yes | yes |
| `billing:read` | yes | yes |
| `billing:write` | - | yes |
| `payouts:read` | - | - |
| `payouts:write` | - | - |
| `identity:read` | yes | yes |
| `identity:write` | - | - |
| `authority:read` | yes | yes |
| `authority:write` | - | - |
| `governance:read` | yes | yes |
| `governance:write` | - | yes |
| `governance:decide` | yes | yes |
| `intents:read` | yes | yes |
| `intents:write` | - | yes |
| `missions:read` | yes | yes |
| `missions:write` | yes | yes |
| `reviews:read` | yes | yes |
| `reviews:write` | yes | yes |
| `evidence:read` | yes | yes |
| `evidence:write` | yes | yes |
| `dropoffs:read` | yes | yes |
| `dropoffs:write` | yes | yes |
| `skills:read` | yes | yes |
| `skills:write` | yes | yes |
| `skills:invoke` | - | yes |
| `skills:publish` | - | - |
| `notifications:read` | yes | yes |
| `notifications:write` | yes | yes |
| `security-events:read` | yes | yes |
| `security-events:write` | - | yes |
| `llm:read` | yes | yes |
| `llm:invoke` | - | yes |
| `scan:read` | yes | yes |
| `scan:write` | yes | yes |
| `detectors:read` | yes | yes |
| `detectors:write` | yes | yes |
| `pii:read` | yes | yes |
| `pii:write` | yes | yes |
| `partner:read` | yes | yes |
| `partner:write` | - | - |
| `admin` | - | - |

<!-- /spec:generated -->

For the directory resource the server grants only the scopes marked in the second column (RFC 6749 section 3.3 lets it grant less than was asked); a request with none of them is `400 invalid_scope`. When a team member approves, the `admin` scope is granted only if that member is an administrator. A scope is a ceiling: which route a token may call is the API's own map from routes to scopes, and a route nobody mapped is refused to every token that came from OAuth. A scope never raises what the person behind the token may do.


## 6. Authorization request

`GET /oauth/authorize` takes the query parameters `response_type` (`code`), `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method` (`S256`, the default), `scope`, `resource`, `state` and `nonce`. The server MUST check, in this order, and answer each failure as a JSON error (section 10) with status `400` unless stated, without redirecting:

1. A repeated or non-string parameter is `invalid_request`.
2. `response_type` is not `code`: `unsupported_response_type`.
3. `client_id`, `redirect_uri` or `code_challenge` is missing: `invalid_request`. `code_challenge_method` is not `S256`: `invalid_request`.
4. The resource is unknown: `invalid_target`. A scope is unknown, or none survives the resource's ceiling: `invalid_scope`.
5. The client is a metadata document that fails (4.1): `invalid_client`. An `https` client id that is not a metadata document, or any other id that is not registered: `401 invalid_client`.
6. The `redirect_uri` does not match one of the client's (4.3): `invalid_request`.

When all hold, the server answers `302` to its consent page (`{console}/oauth/consent?state=<token>`), where `<token>` is a signed, fifteen-minute handoff that binds the request (client, redirect URI, scopes, resource, challenge, `state` and `nonce`). The person signs in and approves or declines there. The server never reads the person's session at this endpoint: the consent page does, and returns the decision to `POST /oauth/authorize`, which is the Console's call and not the client's. On approval the browser is sent to the client's `redirect_uri` with `code` (single-use, valid for 10 minutes) and the client's `state`; on refusal, with `error=access_denied` and the `state`. The client MUST send a `state` and check it, and MUST send a `code_challenge` that is the base64url SHA-256 of a verifier of its own.

## 7. Token endpoint

`POST /oauth/token` takes `application/x-www-form-urlencoded`; a JSON object whose members are all strings is also accepted. Parameters are single strings; a repeated or non-string one is `invalid_request`. There is no client authentication. The answers are JSON, and a client MUST NOT cache them. The `grant_type` is one of the four below; any other is `400 unsupported_grant_type`.

### 7.1 `authorization_code`

Parameters `code`, `redirect_uri`, `client_id`, `code_verifier`, all required. The server MUST answer `invalid_grant` when the code is unknown, already used, expired, issued to another `client_id`, or issued for another `redirect_uri`; when the SHA-256 of `code_verifier`, base64url, is not the stored `code_challenge`; or when the person or the team member behind it is no longer active. A used code stays used; using it again does not revoke the tokens its first use produced. The answer is a token pair (8) with a new token family; the code is consumed in the same step that checks the verifier, so two requests with one code cannot both succeed.

### 7.2 `refresh_token`

Parameters `refresh_token`, `client_id`, and optionally `scope`. A refresh token is single-use: a successful call returns a new refresh token and the old one is spent (rotation). A `scope` that is given may only narrow the granted scope (`invalid_scope` otherwise); one that is absent keeps it. The server answers `invalid_grant` for an unknown, revoked or expired token, for another client, and for an operator that is no longer active.

A client may not have received the answer to a rotation, so the same request repeated within 60 seconds, from the same source address and with the same user agent, returns the same successor and not an error. Presenting a spent token in any other way (after that window, from elsewhere, or when the successor has already been used) is a **reuse**: the server revokes the whole token family, so that the access tokens of the family also stop working on their next call, and answers `invalid_grant` ("refresh reuse detected; family revoked"). A refresh whose successor cannot be recovered because the server's key service failed is `503 temporarily_unavailable` with `Retry-After: 1`; the client retries.

### 7.3 `urn:ietf:params:oauth:grant-type:device_code`

Parameters `device_code` and `client_id` (RFC 8628 section 3.4). While the person has not decided, the answer is `400 authorization_pending`; a client polling faster than the interval gets `400 slow_down`, and the interval doubles up to its cap. A refusal is `access_denied`, an expired code `expired_token`, an unknown code or another client `invalid_grant`. Approval yields a token pair.

### 7.4 Device authorization

`POST /oauth/device/authorize` takes `client_id` (a client the server already has: one registered with `/oauth/register`, or a metadata-document client the server has stored from an earlier authorization request; any other is `401 invalid_client`), `scope` and `resource`, validated as in section 6, and answers ([`schemas/OAuthDeviceAuthorizationResponse.json`](schemas/OAuthDeviceAuthorizationResponse.json)) the `device_code`, a `user_code` of eight characters from `BCDFGHJKLMNPQRSTVWXYZ23456789` written `XXXX-XXXX`, `verification_uri` (the Console's `/cli/auth`), `verification_uri_complete`, `expires_in` and `interval`. The person enters or confirms the code in the Console and approves or denies; those two calls (`/oauth/device/approve`, `/oauth/device/deny`) belong to the Console and need the person's session. At most 30 device authorizations per minute per source address.

### 7.5 Token exchange

`grant_type` `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) is STACK's way of refreshing a Passport under the OAuth envelope. It is authenticated by the subject token alone: no `client_id` is needed. Parameters: `subject_token`, a Passport, which may have expired within its refresh grace period (the [Passport](../passport/SPEC.md) specification, section 7); `subject_token_type`, `urn:ietf:params:oauth:token-type:jwt` or `urn:stack:token-type:passport`; optionally `requested_token_type`, either of the same two. The answer ([`schemas/OAuthTokenExchangeResponse.json`](schemas/OAuthTokenExchangeResponse.json)) is `access_token` (the new Passport), `issued_token_type` `urn:stack:token-type:passport`, `token_type` `N_A` and `expires_in`. The new Passport carries nothing the old one did not.

This profile of the exchange is a refresh and nothing more. A request with an `actor_token` is `invalid_request`, one with `audience` or `resource` is `invalid_target`, one with `scope` is `invalid_scope`; a subject token that is not a Passport, is revoked, or is expired beyond its grace is `invalid_grant`. A Passport the server cannot refresh for another reason answers `invalid_request`.

## 8. Tokens and their lifetimes

An **access token** is a JWT signed with EdDSA by the deployment's key (`kid` in the header, the key set of section 3), with the claims:

| Claim | Value |
|---|---|
| `iss` | The deployment's short issuer name. |
| `sub` | The operator id of the account the token acts for. |
| `aud` | `stack:api` or `stack:mcp` (5.1). |
| `client_id` | The client the token was issued to. |
| `scope` | The granted scopes, space-separated. |
| `token_use` | `access`. |
| `member_id` | The team member, when a member approved. |
| `token_family_id` | The refresh family; it ties the token to revocation (section 9). |
| `resource` | The exact resource, for an MCP token. |
| `iat`, `nbf`, `exp`, `jti` | As usual. |

A **refresh token** is an opaque string. The server keeps only its hash. The token response ([`schemas/OAuthTokenResponse.json`](schemas/OAuthTokenResponse.json)) is `access_token`, `token_type` `Bearer`, `expires_in`, `refresh_token` and `scope`. A refresh answer carries the new refresh token and the same scope or the narrowed one.

The lifetimes and fixed values:

<!-- spec:generated:oauth-constants -->

| Constant | Value |
|---|---|
| Access token lifetime, API resource | 3600 s (1 h) |
| Access token lifetime, MCP resources | 3600 s (1 h) |
| Refresh token lifetime | 2592000 s (30 d) |
| Refresh rotation grace (a retry of the same request returns the same successor) | 60 s (1 min) |
| Authorization code lifetime (single use) | 600 s (10 min) |
| Device code lifetime | 900 s (15 min) |
| Device code polling interval, first and longest after `slow_down` | 5 s and 60 s |
| Access token audience, API resource | `stack:api` |
| Access token audience, MCP resources | `stack:mcp` |
| Token exchange grant type | `urn:ietf:params:oauth:grant-type:token-exchange` |
| Token type of a Passport in a token exchange | `urn:stack:token-type:passport` |
| Token type of a JWT in a token exchange | `urn:ietf:params:oauth:token-type:jwt` |
| Scope granted when a request names none (API resource) | `passports:read`, `agents:read`, `services:read`, `audit:read` |

<!-- /spec:generated -->

An access token is checked at every call: its signature, audience, expiry, and, live, whether its family has been revoked, whether the operator is active, and whether the team member behind it is. A token whose family was revoked stops working on its next call, before it expires.

## 9. Revocation

`POST /oauth/revoke` takes `token`, a refresh token. It revokes the token's whole family: the refresh token and every successor, and with them every access token of the family on its next call. No client authentication is needed: holding the refresh token is the authority. The answer is `200` with `{}` in every case: a token the server does not know, a token already revoked, a missing `token`, and an access token passed as `token` (revoke its refresh token to end the session). `token_type_hint` is ignored. A repeated or non-string parameter is `400 invalid_request`.

## 10. Errors

The endpoints of this profile answer errors in the flat shape of RFC 6749 section 5.2, `{ "error", "error_description"? }` ([`schemas/OAuthError.json`](schemas/OAuthError.json)), and not in the API's own error envelope. The codes: `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `unsupported_response_type`, `invalid_scope`, `invalid_target`, `access_denied`, `authorization_pending`, `slow_down`, `expired_token`, `invalid_redirect_uri`, `invalid_client_metadata` and `temporarily_unavailable`. The status is `400` unless a section above says otherwise (`401` for an unknown client, `503` for `temporarily_unavailable`). `error_description` is for a person and MAY change; a client acts on `error`.

## 11. Security considerations

- Every client is public, so a code or a refresh token is protected by PKCE and by rotation, not by a secret. The server requires `S256` of every client, so that an intercepted code (a private-use scheme redirect can be claimed by another app on the device) is useless without the verifier.
- A client given by a metadata document names itself by a URL the server fetches on an unauthenticated request. The fetch rules of 4.1 (public addresses only, no redirects, a small bounded answer, no credentials, caching and sharing of requests) are what stop it being a way to reach a server's internal network or to load it.
- Rotation with reuse detection means a stolen refresh token is found out the first time both the thief and the client use it, and ends the whole family. The retry window of 7.2 is bound to the address and user agent that rotated, so that it cannot be used to read a successor from elsewhere.
- A scope is a ceiling over a default-deny route map, so a new route is unreachable by OAuth until someone maps it. Operations that widen what an agent may do need a person's approval in a browser whatever the token's scope; a token from OAuth, which may be an AI client, never approves such a thing for itself.
- A consent handoff and a code are bound to the redirect URI as presented, to the client and to the challenge; the redirect to the client only ever happens from the Console after the person's decision.
- Access tokens are bearer tokens and live an hour; family revocation is checked live, so the hour is not the revocation delay. Clients MUST NOT log tokens, and servers MUST receive them over TLS.

## 12. Machine-readable schemas and conformance

[`schemas/`](schemas/) holds the JSON Schemas (draft-07) of the wire shapes above, generated from the reference implementation: `OAuthServerMetadata`, `OAuthError`, `OAuthTokenResponse`, `OAuthTokenExchangeResponse`, `OAuthClientRegistrationRequest`, `OAuthClientRegistrationResponse`, `OAuthDeviceAuthorizationResponse` and `OAuthClientMetadataDocument`. Conformance tests are in [`../conformance/`](../conformance/README.md): `oauth` takes the base address of a server and tests discovery, registration, the authorization request, the token endpoint's refusals, the device authorization and revocation, with nothing that needs a person's approval; `oauth-client-metadata` takes a function that checks a client metadata document.
