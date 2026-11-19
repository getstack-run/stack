# STACK Single Sign-on Profile

**Specification:** STACK Single Sign-on Profile
**Version:** 1.3.1
**Status:** Stable
**Licence:** Apache-2.0

A customer's people can sign in to the customer's own STACK account through the customer's own identity provider. STACK is the relying party and the customer's provider is the OpenID Provider. This document is a profile of OpenID Connect Core 1.0 (the authorization code flow) and of OpenID Connect Discovery 1.0: it says which parts STACK uses, in which order, what it requires of the provider (its discovery document, its keys, the claims and the algorithms it signs the ID token with, and how much clock skew it can have), what STACK does with the ID token, how a person is found or created, and what a sign-in leaves behind for the deployment's sign-in page to redeem.

Contents: 1 Conventions, 2 Overview, 3 The connection, 4 Starting a sign-in, 5 The authentication request, 6 The callback, 7 The token request, 8 The ID token, 9 Finding the person (9.5 Verified domains), 10 The handoff, 11 Errors, 12 What STACK requires of the identity provider, 13 Security considerations, 14 Machine-readable schemas, 15 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The roles are: the **browser**, which a person uses and which carries every redirect; **STACK**, the relying party, which is a STACK deployment (the hosted service or a self-managed install, called the deployment); the **provider**, the customer's OpenID Provider (Okta, Microsoft Entra, Auth0, Google Workspace, Keycloak or any other that implements the parts below); and the **sign-in page**, the part of the deployment, apart from the API, that a person's browser starts at and returns to, and that turns a finished sign-in into a session. A provider conforms to this profile if it satisfies every MUST in section 12. A relying party implementation conforms if it satisfies sections 3 to 11. The conformance kit in [`../conformance/`](../conformance/README.md) (the `sso-login` suite) plays a provider and a browser and tests a STACK deployment.

All times in tokens are seconds since the Unix epoch. Section 8 uses the terms of RFC 7519 (JWT), RFC 7515 (JWS) and RFC 7517 (JWK); PKCE is RFC 7636.

## 2. Overview

1. A customer's administrator **connects** the provider to the account (section 3): the issuer, a client id and secret, the redirect address, and a **slug** that names the organisation in the sign-in address.
2. A person opens the sign-in address of their organisation, `/v1/identity/sso/{slug}/start`. STACK answers with a redirect to the provider's authorization endpoint (sections 4 and 5), and sets a cookie that ties the attempt to this browser.
3. The person authenticates at the provider, which sends the browser back to the callback (section 6) with a code and the state.
4. STACK checks that the browser is the one that began, redeems the code at the token endpoint (section 7), checks the ID token (section 8), finds or creates the person in the account (section 9) and writes an audit row.
5. STACK leaves a **handoff reference** that lives for 60 seconds, can be used once, and is tied to the browser, and redirects the browser to the sign-in page with it (section 10). The sign-in page redeems it and starts the session. STACK never puts a session in a URL.

The organisation is named by the slug, **never by the e-mail domain** in the ID token (section 4.3).

Single sign-on is open to every account, whatever its plan; a self-managed install needs a licence that includes it (the `sso` feature of the install's licence key; creating a person from a sign-in is the separate `provisioning` feature, section 9). How a licence is issued and checked is not part of this specification.

## 3. The connection

One connection per account, written by an owner or an administrator of the account: every call below, the read included, is refused to a member who is not an administrator and to an agent, because whoever sets the connection decides who may sign in as any member, the owner included. Creating the connection, and any change of its issuer, client, secret, redirect address, audience, scopes, claim mapping, sign-in slug, return origins or default role, or turning sign-in on, is also a governance step-up (`sso_config_change`): a person approves it in a signed-in browser, never in a chat. Renaming it, turning it off and deleting it ask for no approval. The calls are `POST /v1/identity/oidc/config` (create), `GET /v1/identity/oidc/config` (read), `PATCH /v1/identity/oidc/config/{id}` (change), `POST /v1/identity/oidc/config/{id}/test` and `DELETE /v1/identity/oidc/config/{id}`. The calls that change the connection are refused to an agent and are not offered as a tool, and no call returns the secret; the [REST API](../rest-api/SPEC.md) specification describes their answers. The body of a create is [`schemas/OidcIdpConfigCreateInput.json`](schemas/OidcIdpConfigCreateInput.json) and of a change [`schemas/OidcIdpConfigUpdateInput.json`](schemas/OidcIdpConfigUpdateInput.json):

| Field | Meaning |
|---|---|
| `issuer_uri` | The provider's issuer, `https` only. STACK compares the ID token's `iss` with it as a string (section 8): a trailing slash that one has and the other lacks is a mismatch. |
| `client_id`, `client_secret` | The client STACK is at the provider. The secret is write-only and is kept encrypted under the account. |
| `audience` | The `aud` STACK requires in an ID token. Default: the client id. |
| `redirect_uri` | The address the provider is told to return the browser to, `https` only. It MUST be the address of the callback (section 6) and be registered at the provider. |
| `scopes` | What is asked for. Default `openid`, `email`, `profile`. |
| `jwks_cache_ttl_seconds` | How long STACK keeps the provider's key set: 60 to 3600, default 300. |
| `sso_slug` | The name of the organisation in the sign-in address: 3 to 63 characters of `a-z`, `0-9` and `-`, beginning and ending with a letter or digit. |
| `default_member_role` | The role of a person created by a sign-in: `readonly`, `standard` or `admin`. Default `standard`. |
| `sso_login_enabled` | Whether sign-in works. A connection is never created enabled: the administrator tests it, then enables it, and enabling needs a slug. |
| `active` | A connection that is not active is as if it did not exist. |

The `test` call fetches the discovery document and the key set and unwraps the stored secret; it is not a sign-in, and only a round trip through the browser proves that the client id and the redirect address are right.

## 4. Starting a sign-in

`GET /v1/identity/sso/{slug}/start?browser_binding=<hash>` is public: the caller is a browser of someone who is not signed in.

### 4.1 The browser binding

`browser_binding` is the SHA-256 of a secret the sign-in page keeps for this browser (a random value it holds in an HttpOnly cookie of its own), as 64 lower-case hexadecimal characters. STACK keeps the hash with the attempt and hands it on to the handoff (section 10), so that only the browser that started can finish. A start without it, or with anything but 64 lower-case hexadecimal characters, is `400` `BROWSER_BINDING_REQUIRED`: a person starts from the sign-in page.

### 4.2 What STACK checks, in this order

1. The binding (4.1).
2. A connection with this slug that is active and enabled. There is none, or its account is not active: `404` `NOT_FOUND`, the same answer for a slug nobody has, one whose connection is disabled and one whose account is closed, so that the address does not say which organisations exist or have single sign-on on.
3. The `sso` feature is licensed: `402` `LICENCE_REQUIRED` otherwise.
4. The engine's OpenID provider is available: `503` `SSO_PROVIDER_UNAVAILABLE`.

STACK then makes the attempt (a fresh state, nonce and PKCE verifier, kept for 10 minutes), marks it as a **sign-in** (on its own side: the mode is never in the address, because a mode a person can change by editing a URL is not a mode) and answers `302` to the provider's authorization endpoint (section 5) with the cookie of 4.4.

### 4.3 The slug names the organisation

The account a sign-in lands in is the account of the connection that has the slug in the address, found **before** any token is exchanged. STACK does not map the e-mail domain of an ID token to an account: that would let anyone who connects a provider that says `acme.com` walk into Acme's account unless STACK had first proved who owns the domain. A slug never contains a dot, so an address that holds a domain in its place matches no connection and is the `404` above. A person with the same e-mail address in two organisations signs in to each by that organisation's slug.

### 4.4 The state cookie

`Set-Cookie: stack_sso_state=<state>; HttpOnly; Path=/v1/identity; Max-Age=600; SameSite=Lax`, with `Secure` in production. `Lax` is deliberate: the callback arrives as a top-level navigation from the provider, which `Lax` permits, and the cookie is still kept from cross-site subrequests. The cookie is the same value as the `state` parameter of the request. It is deleted (`Max-Age=0`) when the callback reaches the binding check (section 6, step 6), whether the check passes or not.

## 5. The authentication request

The redirect from 4.2 is the provider's `authorization_endpoint` (from its discovery document, section 7.1) with these query parameters added to any it already has:

| Parameter | Value |
|---|---|
| `response_type` | `code`. |
| `client_id` | The connection's client id. |
| `redirect_uri` | The connection's `redirect_uri`, exactly. |
| `scope` | The connection's scopes, separated by spaces. |
| `state` | 256 random bits as 43 base64url characters. |
| `nonce` | 256 random bits as 43 base64url characters. |
| `code_challenge`, `code_challenge_method` | The S256 challenge of a 256-bit PKCE verifier, and `S256`. `plain` is never used. |

STACK sends no `prompt`, `max_age`, `login_hint`, `acr_values` or `claims` parameter, no `response_mode` (the code comes back in the query string of the redirect) and no client secret: the secret is only ever sent from STACK's server to the token endpoint (section 7).

## 6. The callback

`GET /v1/identity/oidc/callback` is where every provider sends the browser back, for every connection of the deployment. It is public by necessity: the provider's redirect is the caller, and the state is what ties it to an attempt. The same address also serves STACK's identity verification flow, which starts elsewhere and is not part of this specification; the callback tells the two apart by the attempt the state names (4.2: the mode is held on STACK's side), and a state that names no attempt at all is refused (step 5 below).

The query is `code`, `state`, `error` and `error_description`. STACK does, in this order:

1. Read the query: a parameter given twice is `400` `VALIDATION_ERROR`. Then require the `sso` feature: `402` `LICENCE_REQUIRED` otherwise.
2. If `error` is present, answer `400` `SSO_UPSTREAM_ERROR` with the provider's `error_description` (or its `error`) as the message. The attempt is not touched.
3. Require `code` and `state`: `400` `SSO_CALLBACK_INVALID` otherwise.
4. Require the engine's OpenID provider: `503` `SSO_PROVIDER_UNAVAILABLE`.
5. Park the code against the state. A state that is unknown, expired or that already has a code parked is `400` `SSO_STATE_INVALID`: **a state is single use**, so a callback that is replayed, and a callback that races another for the same state, is refused. A code is kept for 5 minutes.
6. Read the attempt. If it is a sign-in:
    1. Require that the `stack_sso_state` cookie of this request equals the state (compared in constant time), **before the code is redeemed**: otherwise `400` `SSO_STATE_NOT_BOUND`, with the cookie cleared, and the provider's token endpoint is never called. This is what stops a login CSRF: without it an attacker could authenticate at the customer's provider as themselves, stop at the callback and give the address to a colleague, whose browser would finish the sign-in and be signed in as the attacker.
    2. Forget the attempt's sign-in mark and clear the cookie, so that the same callback cannot be replayed even from the browser that began it.
    3. Redeem the code and check the ID token (sections 7 and 8). Any failure is `400` `SSO_LOGIN_FAILED`.
    4. Find or create the person (section 9), write the audit row, and make the handoff (section 10).

A failed sign-in is not retried with the same state or code: the attempt ends, and the person starts again from the sign-in page. Every refusal of this section is the error envelope as a `400` (or the status shown), shown to the person as a page of the deployment's choosing; STACK does not redirect a refusal to the provider or to the sign-in page.

## 7. The token request

### 7.1 Discovery

STACK fetches the provider's configuration from `{issuer_uri without a trailing slash}/.well-known/openid-configuration` and needs the members `authorization_endpoint`, `token_endpoint` and `jwks_uri`. It keeps the document for 24 hours. It does not compare the document's `issuer` with the connection's (the ID token's `iss` is compared, section 8), and does not read `id_token_signing_alg_values_supported`, `userinfo_endpoint` or any other member.

Every request to the provider (the discovery document, the token endpoint, the key set) is made by STACK's server and is guarded: the address MUST be `https`, its host MUST resolve only to public addresses (a private, loopback, link-local or internal address is refused), a redirect is **not followed** (a `3xx` answer is a failure, since the address was checked and the place it points to was not), and a request that is not answered in 5 seconds fails.

### 7.2 The request

STACK sends `POST {token_endpoint}` with `Content-Type: application/x-www-form-urlencoded` and `Accept: application/json`, and a form of `grant_type=authorization_code`, `code`, `redirect_uri` (the connection's, as in the authentication request), `client_id`, `client_secret` and `code_verifier`. The client authenticates with `client_secret_post`; `client_secret_basic` is not used and a provider that accepts only that is not supported. The answer MUST be `200` JSON with an `id_token`, and no `error` member. STACK uses the ID token and nothing else in the answer: it neither keeps nor uses an access token or a refresh token, and does not call the UserInfo endpoint, so every claim it needs MUST be in the ID token.

## 8. The ID token

The ID token is a signed JWT (a JWS in compact form). STACK refuses it, as `SSO_LOGIN_FAILED`, unless every one of these holds:

1. **The header** is well formed and has a `kid`, and the provider's key set (7.1's `jwks_uri`) has a key with that `kid`. A token without a `kid`, with a `kid` the set does not have, or that is not signed at all (an empty signature, `alg` of `none`) is refused. The algorithm is the one of the key: its `alg` member when it has one, otherwise `RS256` for an RSA key, `ES256`, `ES384` or `ES512` for an EC key on P-256, P-384 or P-521, and `EdDSA` for an Ed25519 key. STACK verifies with that algorithm, never with the one the token names: a token whose `alg` is another (an HMAC, the algorithm of another key type, `none`) does not verify. A key of a type outside this list is read with the token's own `alg`, and a provider SHOULD NOT sign with one. A provider that signs with RSASSA-PSS publishes its keys with `alg: PS256` (or `PS384`, `PS512`).
2. **The signature** verifies with that key.
3. **`iss`** equals the connection's `issuer_uri` exactly.
4. **`aud`** is, or (as an array) contains, the connection's `audience`, or its client id when no audience is set. STACK does not require or check `azp`.
5. **`exp` is present** and in the future, and **`nbf`, when present,** is not in the future, each with a tolerance of 30 seconds either way for the clocks of the two sides. A token with no `exp` is refused: it would never expire. `iat` is not checked.
6. **`sub` is present.**
7. **`nonce`** equals the nonce STACK sent (OpenID Connect Core section 3.1.3.7). A token with no nonce is refused.
8. **`email`** is a non-empty string. STACK trims and lower-cases it (it is a lookup key). `name`, if a string, is used as the person's name. `email_verified` is read for the first sign-in of a person (section 9): it MUST be the JSON boolean `true` then, unless the token has no such claim at all and the address is vouched for another way (section 9.5); it is not read once the person is linked.

STACK reads no other claim for a sign-in (`acr`, `amr`, `auth_time`, `at_hash`, `typ`, `jti`, the groups or roles a provider adds), except `tid` and `xms_edov` of Microsoft Entra ID, and only as section 9.5 says. A claim mapping policy and an assurance map on the connection apply to STACK's identity verification flow, not to a sign-in.

### 8.1 Keys

The key set is fetched from `jwks_uri` and kept for the connection's `jwks_cache_ttl_seconds`. A token signed by a key the cached set lacks makes STACK fetch the set once more, so that a rotation is picked up before the cache runs out; such a fetch happens at most once in 60 seconds for one `jwks_uri`, so a stream of tokens with made-up key ids does not become a stream of requests to the provider. A key set that is not a JSON object with a non-empty `keys` array is a failure to fetch. When the fetch fails (the provider is unreachable, answers an error), STACK uses the last key set it fetched successfully, which it keeps with the connection, however old it is: a provider that is down does not stop people signing in with a key STACK has already seen, and does not let a key STACK has not seen sign anyone in.

## 9. Finding the person

The account is the connection's (4.3). Within it, a person is the provider's own name for them: the **issuer and subject** of the ID token (`iss` and `sub`), not the e-mail address, which a provider may let a user change or may never have verified. The address is only how a person who has not signed in before is found, once.

1. **A linked person.** When a member of the account is linked to this `iss` and `sub` (step 3), that member signs in, whatever address the ID token now carries and whether or not `email_verified` is there. A member who has been removed from the account is refused, `403` `FORBIDDEN`: a sign-in does not bring back someone an administrator removed; an administrator invites them again.
2. **A first sign-in** (no member is linked to this `iss` and `sub`). STACK requires the address to be verified: `email_verified` exactly `true`, or, when the token has no `email_verified` claim at all, a domain of the account or the issuer's own statement that vouches for it (section 9.5). Otherwise it refuses, `400` `SSO_LOGIN_FAILED`, before it reads anything of the account, so an unverified address learns nothing about who is a member. With a verified address:
   - A member with that address who is **already linked to another subject** is refused, `400` `SSO_LOGIN_FAILED`, and is never re-linked: the address does not make the new subject that person.
   - A member with that address who has been removed is refused, `403` `FORBIDDEN`.
   - A member who was invited and has not joined becomes a member by signing in, and an active member who has not signed in through the provider before signs in; each is **linked** to this `iss` and `sub` (step 3).
   - When there is no such member, STACK creates one, active at once (the provider has authenticated them, so there is no invitation to accept and no key to hand over), with the connection's default role and no API key, linked to this `iss` and `sub`, only when the `provisioning` feature is licensed. Without it, an address that is not already a member is `403` `FORBIDDEN`: "ask an administrator to invite you".
3. **The link** is made in one conditional step: of two first sign-ins racing for one member, one links and the other is refused. A subject is linked to at most one member of an account, and one subject may be a member of several accounts. A member whose administrator **invites them again** loses the link, so the next verified sign-in links the provider identity they now have (this is how a person is moved to a new subject, for instance after the customer changes provider).
4. **Forgetting links.** A customer that replaces its provider would otherwise lock out every member already linked: their address now arrives under a subject and an issuer that are not the ones linked, which is refused (step 2). The deployment SHOULD therefore give an owner or an administrator of the account a way to forget the link of one member, or of every member linked to one issuer (the `iss` of the provider that was replaced); if it does, it MUST NOT allow it to anyone else, for an agent, or without a person's approval of the exact change made in a browser. Forgetting a link changes nothing else about a member: the role, the status and the sessions are untouched, a removed member stays removed, and a member with no link is not an error. The next verified sign-in with the provider in use links the person again (step 2), so whoever that provider says holds the address takes the seat: that is why a person approves it. Each use is written to the audit record. In STACK's reference implementation this is `POST /v1/team/sso-bindings/clear` with `{ "member_id": "..." }` or `{ "issuer": "..." }`, which answers `{ "cleared": [{ "id", "email", "sso_issuer" }] }`.

A member who signed in before this rule (version 1.0.0) has no link and is linked by the next verified sign-in. A provider that does not send `email_verified` therefore cannot link anyone, unless the account has verified the domain of their address or the provider is Microsoft Entra ID and says so (section 9.5, section 12).

STACK writes an audit row for each sign-in that gets this far, `sso.login`, or `sso.login.provision` when it created the person. The role of a person who already exists is never changed by a sign-in.

### 9.5 Verified domains

Some providers never say that an address is verified. Microsoft Entra ID sends no `email_verified` claim unless a customer's administrator turns on an optional claim, and a customer's people cannot sign in for the first time without it. So an account can **verify an e-mail domain** by proving in DNS that it controls it, as Okta, Slack and Atlassian let a customer do. A deployment MAY implement this section; one that does MUST follow all of it, and one that does not follows section 9 unchanged (the suite skips its checks, section 15).

**Claiming a domain.** An owner or an administrator of the account (never an agent) names a domain: its exact name, such as `corp.example.com`, in lower case and ASCII (an internationalised name in its punycode form), with at least two labels and no address, port, path or wildcard; anything else is `400` `SSO_DOMAIN_INVALID`. STACK answers with the DNS record to publish: a **TXT record** at `_stack-sso.{domain}` whose whole value is `stack-sso-verification=` followed by the claim's token, 24 random bytes as 32 base64url characters. The token is published in DNS, so it names the claim and is not a secret. An account holds at most 20 domains (`409` `SSO_DOMAIN_LIMIT_REACHED`); claiming one it already has returns the same claim. A claim grants nothing until its record has been seen.

**Looking the record up.** STACK looks the record up when an administrator asks, for each verified domain every hour, and when a sign-in needs it (below). A lookup is one query for the TXT records at the name, with the strings of one record read as one, and it has exactly three outcomes: **confirmed** (a record is, whole and exactly, the value for the claim's token), **missing** (the name server answered, and there is no such name, no TXT data or no record that is the proof) and **unavailable** (no answer: a timeout, a server failure, a refusal, an unreachable name server). STACK fails closed on every lookup: an answer that is not an answer is never read as the record being there, and never as it being gone. A domain is looked up on request at most once in ten seconds. The deployment asks its machine's resolver, or the name servers its operator names; it does not follow a CNAME the resolver does not, and it does not validate DNSSEC unless the resolver it asks does (section 13).

**One account per domain.** A domain is *verified* for at most one account at a time. Any number of accounts may have claimed a name, and none of those claims is worth anything until its record is seen; the first to be seen holds the name. Claiming or verifying a name another account has verified is `409` `SSO_DOMAIN_UNAVAILABLE`, with the one message that is given for any name the account cannot take, so the answer never says who holds it or whether anyone does.

**What a verified domain is worth, and for how long.** An address counts as being at a verified domain only when its domain is **exactly** a domain the account holds as verified: a subdomain of it is another domain, and so is its parent. A verified domain counts at a sign-in only while its record was *seen* within the last 6 hours. Past that, the sign-in looks the record up again, and a lookup that is not confirmed (missing, unavailable or failed in any way) means the domain does not count for that sign-in: a cached confirmation is never trusted past the window. A record seen missing for 7 days makes the domain **lapse**: it stops belonging to the account, is free for any account to verify, and must be proved again; a lookup that gives no answer never starts that clock. A claim that was never verified is dropped after 14 days, and an administrator can remove a domain at any time, which takes effect at once.

**What it does at a sign-in.** For a first sign-in (section 9, step 2) and for provisioning, an address counts as verified when the ID token has **no `email_verified` claim at all** and either its domain is verified for the account, or the issuer says so itself (below). A token that has the claim with any value but `true` (`false`, `null`, a string, a number) has said something about the address, is taken at its word, and is refused whatever the domain. Everything else in section 9 stays as it is: the person is the provider's `iss` and `sub`, an address that belongs to a member linked to another subject is refused and never re-linked, a removed member is refused, and an administrator can still forget a link (step 4). The domain finds a person to link; it never replaces the provider's authentication. A first sign-in that was linked or provisioned on a domain or on the issuer's statement writes a second audit row, `sso.login.link.verified_domain` or `sso.login.link.issuer_domain_claim`, beside `sso.login` or `sso.login.provision`.

**The issuer's own statement (Microsoft Entra ID).** Entra's optional ID token claim `xms_edov` (Microsoft Learn, "Optional claims reference") is a boolean that is true when the address belongs to the tenant the user's account lives in and that tenant's administrator has verified the domain. The customer turns it on in the app registration, and the `email` scope must be granted. STACK reads it only when all of these hold: the token's `iss`, which equals the connection's `issuer_uri` exactly (section 8), is `https://login.microsoftonline.com/{tenant}/v2.0` (or the same path at `login.microsoftonline.us` or `login.partner.microsoftonline.cn`) with a tenant identifier; the token's `tid` is that same tenant; the claim is the JSON boolean `true`; an `email` claim is present; and there is no `email_verified` claim. A provider that is not Entra, a multi-tenant issuer such as `common`, another tenant's token, and a value that is a string or a number, are all not read. With this, a customer on Entra whose domain its tenant has verified needs no DNS record at all.

**The calls.** Owner or administrator only, on any plan (a self-managed install needs the `sso` feature of its licence), refused to an agent, and scope `identity:read` or `identity:write`. The [REST API](../rest-api/SPEC.md) specification describes their answers; the body of an add is [`schemas/SsoDomainAddInput.json`](schemas/SsoDomainAddInput.json).

| Call | What it does |
|---|---|
| `GET /v1/identity/sso-domains` | The account's domains, each with its `status` (`pending`, `verified` or `lapsed`), the `record` to publish, when it was last checked and what the last lookup found. |
| `POST /v1/identity/sso-domains` | Claim a domain (body `{ "domain": "corp.example.com" }`): `201` with the claim, `200` when the account already has it. A governance step-up, `sso_domain_add`: a person approves the exact domain in a signed-in browser, never in a chat, because adding one loosens who the provider may vouch for. |
| `POST /v1/identity/sso-domains/{id}/verify` | Look the record up now: `{ "domain", "check" }`, where `check` is `confirmed`, `missing` or `unavailable`. The domain becomes verified when it is confirmed. |
| `DELETE /v1/identity/sso-domains/{id}` | Stop claiming a domain: `204`. Needs no approval, since it only tightens. |

Each use is written to the audit record (`sso.domain.add`, `sso.domain.verify`, `sso.domain.remove`, and `sso.domain.lapse` when the upkeep lapses a domain). The approval is asked at the add and not at the check, so that the periodic lookup that keeps a verified domain verified never waits for a person.

| Code | HTTP status | When |
|---|---|---|
| `SSO_DOMAIN_INVALID` | 400 | The name is not a domain (above). |
| `SSO_DOMAIN_UNAVAILABLE` | 409 | The name is verified for another account, or became so first. |
| `SSO_DOMAIN_LIMIT_REACHED` | 409 | The account already holds 20 domains. |

## 10. The handoff

When the person is found or created, STACK makes a **handoff reference**: `ssoh_` and 32 random characters of `A-Z a-z 0-9 _ -`. It stores, under the reference, the account, the person, their e-mail address and role, and the browser binding hash of 4.1, for **60 seconds**, and redirects the browser, `302`, to `/auth/sso/callback` on the deployment's sign-in page with the reference as the query parameter `ref`. If the account has stopped being active in the meantime, no reference is made and the answer is `401` `SSO_HANDOFF_INVALID`. The reference is not a session and carries no identity; the session is made when the sign-in page redeems it.

The address `POST /v1/identity/sso/handoff` is inert on purpose: it answers `404` `NOT_FOUND` and never reads, uses or burns a reference, so that a caller with no credential neither consumes someone's reference nor receives an identity.

### 10.1 Redeeming a reference

The sign-in page redeems the reference on its own server, with a credential of its own that only the deployment's sign-in page holds (it is not an API credential of any account and is not part of this specification), and the secret the binding hash was made from. A redeemer MUST:

1. Look the reference up, and refuse with one answer if it is not there (never made, expired or used).
2. Compare the SHA-256 of the secret it was given with the stored binding hash in constant time, and refuse with the same answer when they differ. A reference redeemed by another browser is as good as unknown.
3. Only then remove the reference with a single atomic read-and-delete, and refuse if what it removed is not what it checked, so that two redeemers racing for one reference cannot both win.
4. Make a session only for a person who is still a member, of an account that is still active, and never put the session, the reference's contents or the person's address in a URL.

## 11. Errors

Errors use the envelope `{ "error": { "code", "message", "details" } }` (the [REST API](../rest-api/SPEC.md) specification, section 5).

<!-- spec:generated:sso-errors -->

| Code | HTTP status | Reason in the engine |
|---|---|---|
| `BROWSER_BINDING_REQUIRED` | 400 | `browser_binding_required` |
| `SSO_CALLBACK_INVALID` | 400 | `invalid_callback` |
| `SSO_UPSTREAM_ERROR` | 400 | `upstream_error` |
| `SSO_STATE_INVALID` | 400 | `state_invalid` |
| `SSO_STATE_NOT_BOUND` | 400 | `state_not_bound` |
| `SSO_LOGIN_FAILED` | 400 | `login_failed` |
| `SSO_HANDOFF_INVALID` | 401 | `handoff_invalid` |
| `SSO_PROVIDER_UNAVAILABLE` | 503 | `provider_unavailable` |

<!-- /spec:generated -->

When each is answered:

| Code | When |
|---|---|
| `BROWSER_BINDING_REQUIRED` | The start has no `browser_binding`, or one that is not 64 lower-case hexadecimal characters (4.1). |
| `SSO_CALLBACK_INVALID` | The callback has no `code` or no `state` (section 6, step 3). |
| `SSO_UPSTREAM_ERROR` | The provider sent the browser back with an `error` (section 6, step 2). The message is the provider's `error_description`. |
| `SSO_STATE_INVALID` | The state is unknown, expired, or already used (a repeated or replayed callback), or the attempt's record is damaged. |
| `SSO_STATE_NOT_BOUND` | The callback did not come from the browser that started: the cookie is missing or is not the state (section 6, step 6.1). |
| `SSO_LOGIN_FAILED` | The code could not be redeemed, the token endpoint answered anything but a JSON with an `id_token`, the ID token failed a check of section 8, the connection was switched off after the person began, or the person could not be found (section 9): a first sign-in whose `email_verified` is not true, or whose address belongs to a member linked to another subject. |
| `SSO_HANDOFF_INVALID` | The account stopped being active before the handoff was made (section 10). |
| `SSO_PROVIDER_UNAVAILABLE` | The deployment has no OpenID provider registered. |

Other answers a sign-in can meet: `404` `NOT_FOUND` (4.2), `403` `FORBIDDEN` (4.2 and section 9), `402` `LICENCE_REQUIRED` (4.2 and section 6) and `400` `VALIDATION_ERROR` (a repeated query parameter). Every other failure of the flow is one of the codes above, so that a caller learns of a failed sign-in no more than that it failed; the message of `SSO_LOGIN_FAILED` names what was wrong for the benefit of the customer's administrator, who reads it in the deployment's log and can test the connection (section 3).

## 12. What STACK requires of the identity provider

A provider MUST:

1. Publish an OpenID Provider configuration at `{issuer}/.well-known/openid-configuration` over `https`, at a public address, answering `200` without a redirect, with `authorization_endpoint`, `token_endpoint` and `jwks_uri`, and publish the key set at `jwks_uri` over `https` without a redirect.
2. Support the authorization code flow with `response_type=code`, returning `code` and `state` in the query string of the redirect to the `redirect_uri` that was registered, and return `state` unchanged. A provider SHOULD verify the PKCE `S256` challenge STACK sends and MUST NOT fail a request that carries one.
3. Accept a client that authenticates at the token endpoint with `client_secret_post` and answer `200` with a JSON body that has an `id_token`.
4. Issue an ID token that is a JWS in compact form, signed with a key of its published set, with `kid` in the header naming that key. The key MUST be of a type STACK maps to an algorithm (RSA, EC on P-256, P-384 or P-521, or Ed25519: section 8, step 1) and MUST publish `alg` when it signs with anything but the algorithm STACK would infer (RSASSA-PSS, for one). A provider MUST NOT sign an ID token for STACK with a symmetric key or with `none`.
5. Put in the ID token: `iss` equal, character for character, to the issuer the customer configured (so the issuer in the connection is the one the provider puts in `iss`); `aud` containing the client id (or the audience the connection names); `exp`; `sub`; the `nonce` of the request; an `email` claim with the person's address (so the `email` scope MUST be granted) and `email_verified` set to the boolean `true` when it has verified that address (without it nobody signs in for the first time, section 9, unless the account has verified the domain, or the provider is Microsoft Entra ID and sends `xms_edov`, section 9.5). It SHOULD add `iat` and `nbf`. The `sub` MUST be stable and never reused for another person: it is who the person is for good.
6. Keep its clock within 30 seconds of real time. STACK allows 30 seconds either way and no more.
7. Publish a new signing key in the key set before it signs with it, and keep the old one until the tokens it signed have expired, so that a rotation does not fail a sign-in in progress (section 8.1).
8. Not rely on a redirect from its discovery document, key set or token endpoint (they are not followed) nor on an address that is not public.
9. Only say `email_verified` is true of an address the person controls, and keep `sub` the same for the same person (section 13).

## 13. Security considerations

- **The subject is the identity, the address is not.** An e-mail claim a user can change at the provider, or one the provider never verified, would let that user sign in as a colleague of the same account, an administrator included (the "nOAuth" pattern). STACK therefore links a member to the `iss` and `sub` of the first sign-in, matches on them afterwards, refuses an address that belongs to a member linked to another subject, and uses an address to find a member only on a first sign-in and only when `email_verified` is true (section 9). What remains is the first sign-in itself: a provider that says `email_verified: true` of an address its user does not control can link that user to the member the address names, before the real person has signed in. A customer whose provider lets people claim unverified addresses MUST NOT connect it, or MUST make sure each member has signed in once, or have the member's address be one only they can receive mail at. A provider that reuses a `sub` for another person defeats the link, and the customer's administrator can invite the member again to reset it.
- **A verified domain finds a person; it does not authenticate one** (9.5). It replaces only the provider's word that an address is verified, and only for a token that says nothing about it. The provider still authenticates the person, and the first sign-in is still the weak point of section 9: a provider that lets a user put an address at the customer's domain on their own account, and sends no `email_verified`, lets that user take the seat of the member with that address if they sign in first. A customer whose provider does that MUST NOT verify the domain, or MUST make sure each member has signed in once. That is why adding a domain needs a person's approval in a browser.
- **DNS is what proves a domain** (9.5). The proof is a record only the domain's owner can publish, named by a random token; claiming a name grants nothing, and the first account whose record is seen holds it. A resolver that does not validate DNSSEC can be made to give a false answer by whoever can forge answers to it, for as long as the answer lives and no longer than the 6 hours a confirmation counts; an install that needs more names a validating resolver. A domain that is sold or lost stops counting within 6 hours of its record going, and lapses after 7 days.
- **The slug, not the domain, picks the account** (4.3). A verified domain does not change this: it is a fact about an address inside the account the slug already named, and it never maps a token to an account. The slug is not a secret: it names an organisation in public, and a prober learns nothing from a wrong one (4.2, step 2).
- **Login CSRF and session fixation** are stopped by the cookie (4.4, section 6 step 6.1), checked before the code is redeemed, and by the single use of the state. The cookie is `HttpOnly`, so a script on the page cannot read it.
- **The handoff is bound to the browser** (section 10) and lives 60 seconds: a reference that leaks in a `Referer` header or a log is dead, or unusable by anyone but the browser that began. No session is ever in a URL.
- **The provider's addresses are the customer's to name and are guarded.** The issuer is an address the customer chose and the token endpoint and key set come from a document at that address, so every request to them is guarded against private addresses and never follows a redirect (7.1): a customer cannot use a connection to scan STACK's network.
- **A provider that is down.** The last key set STACK fetched keeps people signing in (8.1). A key STACK has never fetched cannot; a provider that wants to retire a key at once removes it from the set and waits for the cache (at most `jwks_cache_ttl_seconds`) to run out.
- **No refresh of a sign-in.** STACK does not keep the provider's tokens and does not ask the provider again: a person removed at the provider keeps the session STACK made until it ends, and loses the ability to start another. An administrator who needs them out at once removes them from the account.
- **The audience of the callback.** The callback serves every connection of a deployment. A provider's `redirect_uri` is registered per client, so one customer's provider cannot send a code for another customer's attempt to be redeemed: the state, the cookie and the PKCE verifier are all per attempt.

## 14. Machine-readable schemas and constants

The JSON Schemas in [`schemas/`](schemas/) (draft-07) are generated from the reference implementation: `OidcIdpConfigCreateInput`, `OidcIdpConfigUpdateInput` and `SsoDomainAddInput`. The table of constants below is generated from the values the engine runs on.

<!-- spec:generated:sso-constants -->

| Constant | Value |
|---|---|
| State cookie name | `stack_sso_state` |
| State cookie lifetime and sign-in attempt lifetime | 600 s (10 min) |
| An authorization code is kept for | 300 s (5 min) |
| Handoff reference lifetime (single use) | 60 s (1 min) |
| Clock tolerance on `exp` and `nbf` | 30 s |
| Longest time for one request to the identity provider | 5 s |
| Discovery document is kept for | 86400 s (1 d) |
| Key set cache lifetime, default and range | 300 s (5 min), 60 to 3600 s |
| Forced refetch of the key set for an unknown `kid`, at most once per | 60 s (1 min) |
| PKCE method | `S256` |
| Authorization request and sign-in path | `/v1/identity/sso/{slug}/start` |
| Callback path | `/v1/identity/oidc/callback` |
| Dashboard path the browser is sent to with the handoff reference | `/auth/sso/callback` |
| DNS name of a domain's proof record | `_stack-sso.{domain}` |
| Text a proof record starts with, then the token | `stack-sso-verification=` |
| A successful check of a record counts at sign-in for | 21600 s (6 h) |
| A verified domain's record is looked up again every | 3600 s (1 h) |
| A record seen missing for this long lapses the domain | 604800 s (7 d) |
| A domain added and never verified is kept for | 1209600 s (14 d) |
| A domain is looked up on request at most once in | 10 s |
| Longest time for one DNS lookup | 5 s |
| Most domains one account may hold | 20 |

<!-- /spec:generated -->

## 15. Conformance

The `sso-login` suite of the [conformance kit](../conformance/README.md) plays the provider and the browser against a **test** deployment: it serves a discovery document, a key set and a token endpoint of its own, asks the deployment (through a function you give it) to connect that provider under a slug of its choosing, and then signs in. It checks that a start without a binding or with a malformed one is refused, that an unknown slug and an address that holds a domain in its place are the same `404`, and that a good start redirects to the provider's authorization endpoint with `response_type=code`, the connection's client id and redirect address, the `openid` scope, a state and a nonce of at least 256 bits, an S256 challenge, no secret, and a `stack_sso_state` cookie that is `HttpOnly`, `SameSite=Lax`, scoped to `/v1/identity` and ten minutes long. It checks the token request (the form, `client_secret_post`, the verifier that matches the challenge) and that a sign-in with an ID token signed with `ES256`, `RS256` or `EdDSA`, with the audience as an array, with an upper-case e-mail address, within the clock tolerance, and with a key that was rotated in after the set was fetched, ends at the sign-in page with a handoff reference, each different. It then checks that the deployment refuses with `SSO_LOGIN_FAILED`, and with no redirect, an ID token with the wrong issuer, audience or nonce, one that has expired, is not yet valid or has no expiry, one with no subject or no e-mail address, a first sign-in whose `email_verified` is false, missing or not the boolean `true`, an address that belongs to a person already linked to another subject (and that the person's own subject still signs in), one signed with `none`, with no signature, with another key of a known `kid`, with an unknown `kid` or none, one whose payload was changed after it was signed and an HMAC token keyed with the provider's public key, and a token endpoint that answers an error or no ID token; that a replayed state is `SSO_STATE_INVALID`, a callback without the cookie, with another attempt's cookie or with a forged one is `SSO_STATE_NOT_BOUND` and never reaches the token endpoint, a provider's `error` is `SSO_UPSTREAM_ERROR`, a callback with no code is `SSO_CALLBACK_INVALID`, and an unknown state is `SSO_STATE_INVALID`; and that the public handoff address is inert. A deployment that implements section 9.5 gives the suite three functions (`domains`: make a domain verified for the connected account, make one verified for another account, and take a verified domain's record away and let its window pass), and the suite then checks that a first sign-in with no `email_verified` claim at a verified domain signs in and is created (and is still bound to its subject), that the same at another domain, a subdomain, the parent or a domain only another account verified is refused, that a token that says `email_verified` false or anything but `true` is refused even at a verified domain, and that once the record is gone and the window has passed a first sign-in is refused while a person already linked still signs in. Without the functions those four checks are skipped. The suite never redeems a reference: that is the sign-in page's.

The reference relying party in `conformance/reference/sso-login-reference.mjs` passes the suite, and the suite fails each of its defective variants (one that accepts `none`, does not check the nonce, the issuer, the audience or the expiry, does not bind the attempt to the browser, accepts a state twice, sends the secret in the authorization request, links an address the provider does not say is verified or finds a person by address alone). The engine passes it against a real database, a real Redis and its real routes in the continuous integration of STACK's code.
