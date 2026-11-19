# Changelog: STACK Partner API

This specification follows semantic versioning. A new optional field, a new scope, a new route or a new error code is a minor version: a partner ignores what it does not know. A change that makes a conforming partner or server stop conforming is a major version. The shapes in `schemas/` are generated from the reference implementation.

## 2.1.0 - 2026-10-31

- Changed: an account has its own plan, free amounts and usage like any customer's, and the partner's wallet pays for it; before, accounts shared the partner's pool. The partner still does not choose the plan (`TENANT_TIER_NOT_ALLOWED`).
- Added: `plan` on the account view (optional, where a deployment charges for accounts), and `PUT /v1/partner/accounts/{account_id}/controls`.
- Added: the refusals `INSUFFICIENT_BALANCE` (a wallet that cannot pay the first month of an account or of its controls) and `SPEND_FROZEN`, both `402`, as a deployment's own conditions.

## 2.0.0 - 2026-10-25

Grants are gone. This is a major version: a partner built on 1.x stops conforming.

- Removed: `POST /v1/partner/connect`, the `sk_grant_` credential and everything about grants (the route map, scopes, provider binding, provenance, `GET|DELETE /v1/partner/connections`, `rotate-token`), the customer's consent and opt-out, and the notice mailed to a customer on connect. A platform no longer asks a customer's address first: it opens an account and the customer has nothing to do.
- Changed: white-label tenants become partner-managed accounts. `/v1/partner/tenants` is `/v1/partner/accounts`; `external_customer_id` is the required `external_ref`, and opening is idempotent on it (`201` the first time, `200` and no key after); the views carry `account_id` where they carried `operator_id`, drop `parent_operator_id` and `tier`, and add `invite`. A closed account's reference is not reused.
- Added: replacing a lost key (`POST .../rotate-key`), inviting the customer to see the account read-only (`POST .../invite`), and releasing an account to its customer: `POST|DELETE|GET .../release`, `GET /v1/partner/releases`, the claim (the platform checkout and the sanctions check) that moves the account only when it completes, the outcomes `pending`, `completed`, `returned` and `cancelled`, and what moves and what ends. A deployment that does not run the claim answers `404` on the release routes.
- Added: the error codes `RELEASE_EMAIL_REQUIRED` (400), `RELEASE_NOT_AVAILABLE` (409) and `RELEASE_CMEK_ACTIVE` (409: an account whose data is under a customer-managed key is not released).
- Changed: what a partner set up inside an account does not move with it. Every service connection, the Stripe payment key, the agent's bot token, supplier and OAuth app secrets, the control socket's addresses and secrets, notification, wake and inbound webhook destinations and secrets, network installs, workload trust anchors and the payout destination are removed when the claim completes (section 6.5), and a step that must reach another service fails the claim closed. The partner may rely on that when it decides what to set up before a release.
- Added: the conformance check P35, which a server fails when a webhook the partner created still takes events after the claim.
- Removed from the constants: the grant prefix, scopes and statuses, the consent window and the connect rate; added the claim link's life, the resend window, the record's life, the hourly limit of invitations and releases and the invited role.

## 1.0.1 - 2026-10-25

- Wording: section 7 says that `generic` is the one inbound provider the engine ships, and that any other `provider` value names an extractor a deployment registers for itself (a deployment that does not serve it answers `404`). No behaviour changed.

## 1.0.0 - 2026-10-24

- Initial public release. Partner authentication and the error shape; `POST /v1/partner/connect` and the two branches of a grant (a new address gets an account at once after a notice, an existing one is asked), the `sk_grant_` credential shown once, idempotency on the partner's customer id, the connect rate limit (`429` `RATE_LIMITED`), reading, rotating and revoking a grant, with revocation dead at the next request and a cascade that a repeated `DELETE` finishes.
- What a grant may reach: the default-deny route map (25 routes and their scopes), provider binding, resource provenance, and the routes left out on purpose.
- White-label tenants: create (the key shown once, a plan refused by name), read, revoke with its cascade and a retry that finishes it.
- A tenant's inbound webhooks: create, list, revoke, rotate the downstream secret and set the provider signing secret; the two secrets and what each signs; the receiver's request and its answers; forwards signed as the Webhooks specification says.
- Passports issued under a tenant, for one live Mission the tenant opened.
- JSON Schemas for the request and answer shapes (`schemas/`).
- A `forward_url` that is not a public address is now a `400` `INVALID_REQUEST`; it was an unhandled `500`.
- A grant that is already revoked answers `DELETE /v1/partner/connections/{id}` with `200` and runs the cascade again; it was `404`, which left a cascade that failed part way unfinishable.
- `connect` over its limit answers `429` `RATE_LIMITED`; it answered `403` `TIER_LIMIT_EXCEEDED` with a message about upgrading a plan.
