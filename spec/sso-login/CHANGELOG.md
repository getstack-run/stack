# Changelog: STACK Single Sign-on Profile

This specification follows semantic versioning. A new optional parameter in the authentication request, a new claim STACK reads or a new error code is a minor version: a provider ignores what it does not know. A change that makes a conforming provider or relying party stop conforming is a major version. The shapes in `schemas/` are generated from the reference implementation.

## 1.3.1 - 2026-10-26

A clarification of who may configure the connection and under what approval. The calls and their bodies are unchanged, so it is a patch version.

- The connection (section 3): every call, the read included, is for the owner or an administrator of the account and is refused to a member who is not an administrator and to an agent. Creating the connection, changing anything that decides who it may sign in, and turning sign-in on are a governance step-up (`sso_config_change`) approved in a signed-in browser only; turning sign-in off, renaming the connection and deleting it need none.

## 1.3.0 - 2026-10-26

Customers whose provider never says that an address is verified (Microsoft Entra ID does not, by default) can sign in for the first time. It adds an optional duty to the deployment and relaxes nothing for a provider that speaks, so it is a minor version.

- Verified domains (new section 9.5): an account proves it controls an e-mail domain with a DNS TXT record at `_stack-sso.{domain}`. An address at that exact domain counts as verified for a first sign-in and for provisioning when the ID token has no `email_verified` claim at all; a claim that says `false` or anything but `true` is still taken at its word. A domain is verified for one account at a time (`409` `SSO_DOMAIN_UNAVAILABLE`, the same answer for any name the account cannot take); a confirmation counts for 6 hours and then the sign-in looks the record up again, failing closed; a record seen gone for 7 days lapses the domain. Adding a domain is a governance step-up approved in a browser; checking and removing are not. The calls are `GET` and `POST /v1/identity/sso-domains`, `POST /v1/identity/sso-domains/{id}/verify` and `DELETE /v1/identity/sso-domains/{id}`, with the error codes `SSO_DOMAIN_INVALID`, `SSO_DOMAIN_UNAVAILABLE` and `SSO_DOMAIN_LIMIT_REACHED`.
- The ID token (section 8): Microsoft Entra's `xms_edov` claim, read together with `tid` and only for an issuer that is one tenant of Entra's own v2 endpoints, vouches for the address when `email_verified` is absent.
- Finding the person (section 9, step 2) and the provider's duties (section 12) say where a verified domain or `xms_edov` stands in for `email_verified`; security considerations (section 13) say what a verified domain does not do and what DNS can and cannot prove.
- Conformance: checks S25 to S28 (sign-in at a verified domain with no `email_verified`; refusal at another domain, a subdomain, the parent, a domain another account verified, and where the claim says `false`; a domain that stops counting once its record is gone and the window has passed). They run when the deployment gives the kit a way to verify a domain (`domains`) and are skipped otherwise. The reference relying party implements the section, with four defective variants.

## 1.2.0 - 2026-10-25

A way out of the lock that 1.1.0 makes when a customer replaces its identity provider. It adds a duty to the deployment, not to the provider, so it is a minor version.

- Finding the person (section 9, step 4): an owner or administrator can forget the link of one member, or of every member linked to one issuer, with a person's approval in a browser, so the next verified sign-in with the new provider links them again. Nothing else about a member changes. Each use is audited.

## 1.1.0 - 2026-10-25

A person is the provider's subject, not the e-mail claim (the "nOAuth" pattern). Nobody relied on 1.0.0 yet, so this is a minor version although it changes what a provider must send.

- Finding the person (section 9): a member is linked to the `iss` and `sub` of their first sign-in and found by them afterwards; an address that belongs to a member linked to another subject is refused (`400` `SSO_LOGIN_FAILED`) and never re-linked; the link is made in one conditional step; inviting a member again clears the link.
- The ID token (section 8) and the provider's duties (section 12): `email_verified` MUST be the boolean `true` for a person's first sign-in, to link an existing member or to create one (`400` `SSO_LOGIN_FAILED` otherwise). It is not read once the person is linked. A provider that does not send it cannot sign anyone in for the first time.
- Security considerations (section 13) rewritten around the subject, with what a customer must still do about a provider that does not verify addresses.
- Conformance: checks S23 (first sign-in with `email_verified` false, missing or not a boolean) and S24 (the same address under another subject, and the person's own subject still signing in); the reference relying party links by subject, with two defective variants.

## 1.0.0 - 2026-10-25

Initial public release, as a profile of OpenID Connect Core 1.0 and Discovery 1.0.

- The connection: the issuer, client, audience, redirect address, scopes, key cache lifetime, slug, default role and the enable switch.
- Starting a sign-in: the browser binding, the order of the checks, the 404 that does not say which organisations exist, the slug (never the e-mail domain) that names the account, and the state cookie.
- The authentication request: the authorization code flow with PKCE S256, a state and a nonce of 256 bits.
- The callback: the order of the checks, a state that is single use, the binding of the attempt to the browser checked before the code is redeemed, and the errors.
- The token request (`client_secret_post`, the PKCE verifier) and discovery, with the guard on every address STACK fetches.
- The ID token: the key and algorithm, issuer, audience, expiry (required) and `nbf` with 30 seconds of tolerance, subject, nonce and e-mail; the key set cache, the one forced refetch for an unknown `kid` and the last key set used when the provider is down.
- Finding or creating the person by e-mail address within the account, and the audit rows.
- The handoff: a 60 second single-use reference bound to the browser, the inert public redemption address and the rules for a redeemer.
- What STACK requires of the provider, and the security considerations.
- JSON Schemas for the connection.
