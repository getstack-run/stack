# STACK Partner API

**Specification:** STACK Partner API
**Version:** 2.1.0
**Status:** Stable
**Licence:** Apache-2.0

A platform (a mail service, an agent builder, a workspace product) can put STACK underneath its customers' agents. It opens an **account** for each customer through the API, under its own reference for the customer. The customer does not have to do anything: there is no consent screen and no checkout, and STACK holds no personal data about the customer. The platform pays for the account from its own wallet, and the account has its own plan, free amounts and usage like any customer's. The customer can be invited to see the account, read-only, and when the relationship ends (the platform releases the customer, or the customer asks to leave) the account moves to the customer with everything in it except what the platform set up in it (its connections, keys, secrets and addresses). This document is the wire contract a partner builds against: how the partner authenticates, opening and reading accounts, inviting the customer, releasing an account and reading how the release ended, an account's inbound webhooks and the passports a partner issues under an account.

It does not define the customer's own pages (the claim page, the Console), which are the deployment's interface; how an operator becomes a partner; or what a deployment charges. Signed requests STACK sends to an account's `forward_url` are those of the [Webhooks specification](../webhooks/SPEC.md); passports are those of the [Passport specification](../passport/SPEC.md).

Contents: 1 Conventions, 2 Overview, 3 Authentication and errors, 4 Accounts, 5 The customer, 6 Releasing an account, 7 An account's inbound webhooks, 8 Passports under an account, 9 Errors, 10 Security considerations, 11 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The **partner** is the platform; the **server** is a deployment of STACK (or another implementation of this contract); the **customer** is the person the account is for. A server conforms if it satisfies every MUST in sections 3 to 8; section 6 is the one part a server MAY leave out (it answers `404` on its routes, and nothing else changes). Request and response bodies are JSON; field shapes are in [`schemas/`](schemas/) (generated from the reference implementation) and the tables below. A field not listed MAY be added in a later minor version: a partner MUST ignore fields it does not know.

## 2. Overview

| | |
|---|---|
| Whose account | The partner's, until the customer claims it. It is an isolated child account: its own audit chain, encryption context, signing key, agents, Passports and webhooks. |
| The partner holds | The account's API key (`sk_live_`), full authority over the account, and its own key over all of its accounts. |
| The customer can | Nothing until the partner invites them; then see the account, read-only. After a release, everything: it is theirs. |
| Plan and billing | The account's own plan, free amounts and usage, paid by the partner's wallet. The partner does not choose the plan. Hosted controls are the account's own switch (section 4.6). |
| What STACK holds about the customer | Nothing. The account holds the partner's reference. The one address STACK holds before a release is the invited customer's, stored as that invited person's, and only if the partner invites. |
| Created by | `POST /v1/partner/accounts` |

The life of an account: the partner **opens** it, may **invite** the customer to see it, and may **release** it. A release mails the customer a link; the customer **claims** the account by starting the platform trial with a card, which runs the deployment's normal sign-up checks; only then does the account **move** to them and the partner's access end. If the claim does not complete, nothing moves.

A person who already has an account of their own is never touched: the partner opens a separate account, and a claim for an address that already has one cannot complete.

## 3. Authentication and errors

**The partner's credential.** Every `/v1/partner/*` call is authenticated with the partner's API key, `Authorization: Bearer sk_live_...`, of an operator the deployment has marked a partner. A call with no credential or with one that is not valid is `401` (`INVALID_API_KEY`); the key of an operator that is not a partner is `403` (`FORBIDDEN`). An account's own key is `403` on `/v1/partner/*`. An OAuth sign-in of the partner's owner reaches the calls with the scopes `partner:read` (the reads) and `partner:write` (open, close, invite, release, withdraw, webhooks and passports); the calls that return or set a credential (a new account key, a webhook signing secret) refuse OAuth.

**Errors.** Every error is `{ "error": { "code": "<STABLE_CODE>", "message": "...", "details": { } } }` with the HTTP status of its code (section 9); `details` is optional. A body that does not validate is `400` `VALIDATION_ERROR`. A partner reads the code, never the message. Errors for a resource that is not the partner's are `404`, never `403`, so the partner cannot learn what else exists.

**Where the partner surface exists.** A deployment that does not carry the partner feature answers `/v1/partner/*` before any other check, and nothing about partners is discoverable.

## 4. Accounts

<!-- spec:generated:partner-constants -->

| Constant | Value |
|---|---|
| Release statuses | `pending`, `completed`, `returned`, `cancelled` |
| Who can ask for a release | `partner`, `customer` |
| A claim link works for | 604800 s (168 h) |
| A claim link is not mailed again for the same account within | 600 s (10 min) |
| A release stays readable to the partner after it ended for | 7776000 s (2160 h) |
| Releases and invitations per partner | 60 per hour |
| Role of an invited customer | `readonly` |
| Reserved placeholder domain of the address an account holds until it is claimed | `*.stack-tenant.local` |
| Inbound webhook request body, largest | 1048576 bytes |
| Content scanned of an inbound request, at most | 65536 bytes |
| A repeated provider event is recognised for | 172800 s (48 h) |
| Forward timeout | 10 s |

<!-- /spec:generated -->

### 4.1 Opening an account

`POST /v1/partner/accounts`, body [`PartnerAccountCreateInput`](schemas/PartnerAccountCreateInput.json):

| Field | Meaning |
|---|---|
| `external_ref` | Required. The partner's own reference for its customer, 1 to 256 characters, unique per partner. It is the idempotency key of the call. |

The answer is [`PartnerAccountCreateResult`](schemas/PartnerAccountCreateResult.json), `201` when the call opened the account and `200` when it repeats one:

```json
{
  "account_id": "op_...",
  "external_ref": "cus_your_id",
  "billing": "partner",
  "status": "active",
  "created": true,
  "created_at": "2026-10-25T09:00:00.000Z",
  "api_key": "sk_live_..."
}
```

`api_key` is in the answer **once**, on the call that opened the account, and is stored by STACK only as a hash. A repeat with the same `external_ref` returns the account that exists with `created: false`, `200` and **no** `api_key`; a partner that lost the key replaces it (section 4.4). A body with `tier` is `400` `TENANT_TIER_NOT_ALLOWED`: the partner does not choose an account's plan, and a client that sends one learns why by name. A deployment that charges for accounts takes the first month from the partner's wallet in the same step: a wallet that cannot pay answers `402` `INSUFFICIENT_BALANCE` and no account is made. Any other unknown field is `400` `VALIDATION_ERROR`. A reference that belongs to a closed account is `409` `CONFLICT`: a closed account's reference is not reused. A deployment that limits the accounts a partner may have answers `409` `TENANT_LIMIT_REACHED`.

The account holds no email of the customer. The address it carries internally is a placeholder under the reserved domain of the table above, which no mail flow can reach.

### 4.2 Reading accounts

| Call | Answer |
|---|---|
| `GET /v1/partner/accounts` | `200` `{ "accounts": [PartnerAccountView] }`. With `?external_ref=` only the account under that reference. |
| `GET /v1/partner/accounts/{account_id}` | `200` [`PartnerAccountView`](schemas/PartnerAccountView.json). `404` for an id that is not the partner's account. |

A view has `account_id`, `external_ref`, `billing` (always `partner`), `status` (`active` until closed), `created_at`, `deleted_at`, `invite` (`{ "status": "none" | "invited" | "active" }`: whether the customer was invited and whether they accepted, never their address) and `usage` (`period`, `actions`: the account's metered actions in the current UTC month, the account's own, not a share of a pool) and `plan` (below) when the deployment can say. The partner never reads an account's audit content, intent bodies or security events, and a view never carries a key. An account that has been claimed is no longer the partner's: it is `404` here, and section 6.4 says how the partner reads how it ended.

### 4.3 Using an account's key

The account's key acts as that account on the ordinary API (agents, Missions, the proxy) and cannot reach `/v1/partner/*` (`403`) or any billing route. A deployment that meters actions meters them on the account's own plan, and what it costs past that plan's free amounts is paid from the partner's wallet. The account's key never reads the partner's balance or its other accounts.

### 4.4 Replacing a key

`POST /v1/partner/accounts/{account_id}/rotate-key` answers `200` `{ "account_id", "api_key" }` with a new key, shown once; the key it replaces stops working at once. It needs the partner's own key as an owner or administrator of the partner account, and is refused to OAuth. `404` for an account that is not the partner's, `403` for one that is closed.

### 4.5 Closing an account

`DELETE /v1/partner/accounts/{account_id}` answers `200` [`PartnerAccountRevokeResult`](schemas/PartnerAccountRevokeResult.json), `{ transitioned, webhooks_revoked, passports_revoked }`. The account is marked closed (`status` is no longer `active`, `deleted_at` is set), its key is refused from its next use (STACK answers `403` `OPERATOR_DELETED`, as for any deleted account; another server MAY answer `401`), and the cascade closes its inbound webhooks and revokes its Passports. The answer says what this call did: `transitioned` (false when the account was already closed), `webhooks_revoked` and `passports_revoked`. The cascade runs on every call, not only on the transition, so repeating a `DELETE` finishes a cascade that failed part way; each step is idempotent. The account's audit chain is kept for the retention window.

### 4.6 The account's plan and controls

A view carries `plan` where the deployment charges the partner for its accounts one by one: `monthly_cents`, `status` (`active` while paid, `paused` when the partner's wallet did not cover a renewal, which pauses that account alone), `renews_on` and `controls` (`monthly_cents`, `status` `off`, `active` or `paused`, `renews_on`); it is absent where the deployment does not charge that way. `PUT /v1/partner/accounts/{account_id}/controls` with `{ "enabled": true | false }` switches hosted controls on or off for that account and answers `200` `{ "account_id", "plan" }` (`plan` is absent in the same case). Switching on takes the first month from the partner's wallet at once (`402` `INSUFFICIENT_BALANCE` and no change when it cannot); switching off ends the charge, without a refund of the month under way. The partner's charge for an account ends when the customer claims it (the renewals of the plan continue while a release is waiting) or when the account is closed, and the customer then starts on their own subscription.

## 5. The customer

### 5.1 Inviting the customer to see the account

`POST /v1/partner/accounts/{account_id}/invite`, body [`PartnerAccountInviteInput`](schemas/PartnerAccountInviteInput.json): `email` (required) and `name` (optional, at most 100 characters), and nothing else. The server mails the invitation to that address and answers `201` [`PartnerAccountInviteResult`](schemas/PartnerAccountInviteResult.json), `{ "status": "invited", "expires_at": "..." }`. The answer carries neither the invitation's token nor the address.

The address is the one the partner gives at that moment. It is stored as the invited person's, and it is the customer's own address only because they accept by opening the mail. An invitation to the partner's own address, or to the reserved placeholder domain, is `403` `FORBIDDEN`. Invitations and releases together are limited per partner (the table in section 4): over it is `429` `RATE_LIMITED`, with `details.limit` and `details.window_seconds`. A server that cannot send mail answers `503` `SERVICE_UNAVAILABLE` and stores nothing; an invitation whose mail fails is taken back, so no one is left invited unseen.

### 5.2 What the invited customer may do

The invited customer signs in to the account with the address they were invited on and sees it: its agents, what they hold and the record of what they did. Their role is `readonly`: they change nothing, connect nothing and spend nothing. They may ask to leave (section 6.7). They never see the partner's key, and the partner does not see what the customer sees of the account's audit record.

### 5.3 What STACK holds about the customer

Until a release completes, the only personal data about the customer is the invited address (if the partner invited), kept as a member of the account, and, while a release is pending, the address the claim link went to, which is kept only for the claim window, encrypted. A claim that does not complete deletes it. After a release, the customer's data is the data of any customer of the deployment.

## 6. Releasing an account

A deployment that runs the customer's claim (its platform checkout and its normal sign-up checks) offers these routes. A server that does not answers `404` `NOT_FOUND` on them and has no accounts that can be claimed.

### 6.1 Requesting a release

`POST /v1/partner/accounts/{account_id}/release`, body [`PartnerReleaseInput`](schemas/PartnerReleaseInput.json): `email` (optional). The server mails the customer a claim link and answers `202` `{ "release": PartnerReleaseRecord }` ([`PartnerReleaseRecord`](schemas/PartnerReleaseRecord.json)). The link goes to `email` when it is given, otherwise to the one customer invited to the account; with neither, or with more than one invited and no `email`, the call is `400` `RELEASE_EMAIL_REQUIRED` and nothing is sent. A release to the partner's own address or the reserved placeholder domain is `409` `RELEASE_NOT_AVAILABLE`, as is a release of an account that is not active. An account whose data is under a customer-managed key is `409` `RELEASE_CMEK_ACTIVE` until the key is turned off. A repeat inside the resend window (the table in section 4) returns the release that is pending and sends nothing again; a repeat after it replaces the link, and the earlier link stops working. A server that cannot send the mail answers `503` `SERVICE_UNAVAILABLE` and no release is pending.

### 6.2 The claim

The claim is the customer's, and the account stays the partner's while it runs. The customer opens the link; the checkout they are sent to is fixed to the address the link went to; they start the platform trial with a card, and the claim runs the deployment's normal sign-up checks, as for any customer of the deployment. Only when the checkout is complete and those checks pass does the account move (section 6.5). If they do not pass, the account **stays with the partner**, nothing is charged, and the release ends as `returned`; so it does for a checkout that does not finish, an address that already belongs to another account, an account whose data is under a customer-managed key, and a link that lapses or is withdrawn. The partner reads `returned` and nothing else: the reason is never given to it.

A person who asks the deployment to leave the partner (section 6.7) is subject to the same claim.

### 6.3 What a release reads as

A release is a [`PartnerReleaseRecord`](schemas/PartnerReleaseRecord.json): `account_id`, `external_ref`, `status`, `requested_by`, `requested_at`, `expires_at` and `completed_at`.

| Status | Meaning |
|---|---|
| `pending` | The claim link is out and has not expired. The account is the partner's. |
| `completed` | The customer claimed the account and it is theirs. `completed_at` is set. |
| `returned` | The claim did not complete. The account is still the partner's, and the reason is never given. |
| `cancelled` | The partner withdrew the release before it was claimed. |

| Requested by | Meaning |
|---|---|
| `partner` | The partner called `POST .../release`. |
| `customer` | The invited customer asked to leave (section 6.7). The partner cannot withdraw it. |

A release whose `expires_at` has passed without being claimed reads `returned`.

### 6.4 Reading a release

`GET /v1/partner/accounts/{account_id}/release` answers `200` `{ "release": PartnerReleaseRecord }`, `404` `NOT_FOUND` when the partner has no record of one for that id. `GET /v1/partner/releases` answers `200` `{ "releases": [PartnerReleaseRecord] }`, newest request first. Both read the partner's own record of its releases, which outlasts the claim (the table in section 4), because after a claim the account is no longer the partner's to read: `GET /v1/partner/accounts/{account_id}` is `404`, and this is how the partner learns it completed. A record is the partner's alone.

### 6.5 What moves, and what ends

When the claim completes, in one step: the account becomes the customer's top-level account on their address and their own subscription, and everything in it stays (its id, agents, pieces, record and chain) except what the partner set up in it, which is removed. At the same moment the partner's access and billing end: the account's key stops working; the people the partner invited are removed (the customer signs in as the owner); every Passport of the account is revoked in the same step, and its inbound webhooks are closed (so the partner no longer receives its events); agent keys that are held on the customer's own infrastructure are cleared, so a key the partner may hold stops working and the agent enrolls again under the customer's own key; approvals the partner asked a person to give are expired; the account's spend is paid from the customer's own wallet and no longer from the partner's. The account no longer counts against the partner's limit, and the partner's `external_ref` is free again.

**What the partner set up does not move.** The customer starts with no secret the partner put into the account and nothing that points at the partner's own servers. In the same step the account's holdings of each of these are removed:

- every service connection (a credential for a provider), with the grants that pointed at it; one that a proxied call has used keeps its row for the record of that call and loses its credential;
- the Stripe payment connection: its restricted key and webhook signing secret. The payment links and checkout sessions it made are turned off at Stripe first, while the key still works;
- the card the partner enrolled in the account's card vault: the vault is disconnected at the card provider (purchases nobody approved are cancelled first) and the card piece goes back to waiting for the customer's own card, which they add themselves;
- the mail domains the partner connected, removed at the mail provider together with the inboxes on them, which open again on the deployment's shared mail domain with a new address, and the custom addresses the partner pointed at the agent's website, removed at the website host (the site itself stays on the deployment's own sites domain);
- the agent's Telegram bot token (its webhook at Telegram is removed first), the Slack installation, and every chat identity bound to approve held payments from a chat;
- supplier keys for making, the client secrets of OAuth apps and of OAuth clients registered under the account, the postal supplier key (the street address is closed), and single sign-on provider configurations;
- the control socket: the decision and events addresses, their signing secrets, and the choice of decider, which returns to its default;
- notification destinations (with the rules that named them), the wake webhook address and its secret, and the secrets and forward addresses of inbound webhooks;
- STACK network installs with their keys, the network subscriptions, the workload trust anchors (SPIFFE trust domains and WIMSE issuers), and the account's Stripe Connect payout destination;
- sign-in sessions, OAuth sessions and codes, and sign-in links, connect links or address changes that were still unused.

What stays is what the account owns: its agents, record, files, memory and messages, and the pieces STACK made for it (the number, the workspace, the agent's wallet address, its signing keys), whose secrets STACK created and never gave to the partner. The authority bindings of the account stay, and carry nothing until the customer issues new Passports, since every Passport was revoked. Settings of the account stay (a spending budget, its policies, which kinds of action are checked); the customer owns them from then on. The account's record notes how many of each kind were removed, and never a value. A partner therefore cannot hand a credential, a server of its own or a bank account to a customer by releasing the account, and the customer sets up their own after the claim.

An account whose data is under a customer-managed key (in any state of it) is not handed over: a release is refused (`RELEASE_CMEK_ACTIVE`) and a claim that finds the key on does not complete, until the key is turned off.

A step that must reach another service (turning off a payment link at Stripe, removing a bot's webhook at Telegram, disconnecting the card vault, removing a mail domain or a website address) is part of the claim: if it cannot finish, the claim does not complete, the account stays the partner's, and the claim is tried again while its link lives. A claim that does not complete removes nothing.

### 6.6 Withdrawing a release

`DELETE /v1/partner/accounts/{account_id}/release` answers `200` `{ "cancelled": true }` and the link stops working, or `{ "cancelled": false }` when none is pending. A release the customer asked for is `409` `RELEASE_NOT_AVAILABLE`.

### 6.7 The customer asks to leave

An invited customer signed in to the account asks to leave from the deployment's own interface (it is not a partner call). The claim link goes to their own address, at most once in the resend window, and the release reads `requested_by: customer`. The partner is told only through its record of releases and the audit entry on its own chain, and it cannot refuse: the customer has decided to leave.

## 7. An account's inbound webhooks

An inbound webhook is an address a provider (or the partner's own product) posts events to; STACK scans each event for content that attacks an agent and forwards the clean ones to the account's `forward_url`. The webhook belongs to the account: its chain, its encryption context and its secrets are the account's.

| Call | Answer |
|---|---|
| `POST /v1/partner/accounts/{account_id}/inbound-webhooks` | `201` [`CreateInboundWebhookResult`](schemas/CreateInboundWebhookResult.json). Body [`CreateInboundWebhookInput`](schemas/CreateInboundWebhookInput.json). |
| `GET /v1/partner/accounts/{account_id}/inbound-webhooks` | `200` `{ "webhooks": [InboundWebhookView] }` ([`InboundWebhookView`](schemas/InboundWebhookView.json)): never a secret. |
| `DELETE /v1/partner/accounts/{account_id}/inbound-webhooks/{wh_id}` | `200` `{ "transitioned": true }`, or `false` for one already revoked. `404` for an id that is not the account's. |
| `POST /v1/partner/accounts/{account_id}/inbound-webhooks/{wh_id}/rotate-secret` | `200` `{ "webhook_secret": "whsec_...", "previous_valid_until": "<ISO 8601>" }`. |
| `PUT /v1/partner/accounts/{account_id}/inbound-webhooks/{wh_id}/provider-signing-secret` | `200` `{ "configured": true }`. Body `{ "signing_secret", "downstream_signing_secret"? }`, each 1 to 256 characters, strict. |

Creating needs the account to be the partner's and active (`404` or `403` otherwise) and the agent to be the account's (`404`). `provider` is `generic`, the one provider the engine ships. Any other value names an extractor that a deployment registers for itself, so which values exist is specific to the deployment: a value the deployment does not serve is `404`, and a value that is not a provider name at all is `400`. `forward_url` is optional (without it the webhook scans and answers and forwards nothing) and MUST be a public address: one that resolves to a private, loopback or internal address is `400` `INVALID_REQUEST`. The two secrets are different, shown once, and never readable again:

| Secret | What it signs | Format |
|---|---|---|
| `webhook_secret` | What STACK sends to `forward_url`: [Standard Webhooks](../webhooks/SPEC.md), family `inbound_forward`. | `whsec_` and base64. |
| `incoming_signing_secret` | What the provider sends to STACK, for a `generic` webhook. | 64 hexadecimal characters. |

The rotation and the signing-secret calls need the partner's own key as an owner or administrator of the partner account: they are refused to OAuth, because they return or set a credential. Rotating returns a new downstream secret; the replaced one keeps signing the forwards beside it for 24 hours (the Webhooks specification, section 6). Setting the signing secret is how a deployment-specific provider whose own scheme the deployment verifies is configured; until it is set, that webhook answers `503` `provider_signing_secret_unconfigured` and forwards nothing. A `generic` webhook is configured by the signing secret returned when it is created.

**The receiver.** The create answer carries `webhook_url`, `https://<api origin>/v1/inbound/<provider>/<slug>`. The sender `POST`s there with `Content-Type: application/json`, at most 1 MiB, with no credential: the signature is the credential. A `generic` webhook is signed over the raw body bytes as `X-Webhook-Signature: sha256=<hex>`, the HMAC-SHA256 of the body under `incoming_signing_secret` (the header name and the algorithm, `hmac-sha256` or `hmac-sha1`, are those of `generic_config` when it was set; `dedupe_key_path`, default `id`, names the member of the body that identifies the event, and `content_paths` the members that are scanned, default the whole body). The answer:

| Status | Body | Meaning |
|---|---|---|
| `200` | `{ "decision": "clean", "forwarded": bool, "message_id", "downstream_status"? }` | The event was scanned and, with a `forward_url`, forwarded. |
| `200` | `{ "decision": "blocked", "reason", "forwarded": false }` | A detector found content that attacks an agent; nothing was forwarded. |
| `200` | `{ "decision": "deduplicated", "message_id", "forwarded": false }` | The event was already received in the last 48 hours. |
| `400` | `{ "error": "<reason>" }` | The signature is missing or does not match, or the event id is not usable. A bad signature is `400`, not `401`: it does not say whether the slug exists. |
| `404` | `{ "error": "not_found" }` | No such webhook, a revoked one, or an unknown provider. |
| `413` | the STACK error body | A body over 1 MiB. |
| `429` | the STACK error body | More than 100 requests a minute for one webhook from one address. |
| `409` | `{ "error": "message_id_content_conflict" }` | An event id that was seen with other content. |
| `410` | `{ "decision": "revoked_during_flight", "forwarded": false }` | The webhook was revoked while the event was being handled. |
| `502`, `503` | `{ "error", "forwarded": false }` with `Retry-After: 5` | The forward failed or the service could not take the event: the sender retries, and the retry carries the same event id. |
| `500` | `{ "error": "detector_failure" }` or another | STACK failed: the sender retries. |

## 8. Passports under an account

`POST /v1/partner/accounts/{account_id}/passports/issue` issues a Passport for one of the account's agents, signed by the deployment's key like every Passport, with `stk.operator_id` naming the account. The body is [`IssuePassportInput`](../passport/schemas/IssuePassportInput.json) of the Passport specification, and the answer is `201` `{ "token", "jti", "expires_at" }`.

Every Passport carries exactly one live Mission: `mission_ids` holds one `ms_...` id of a Mission opened under the account, for an agent of the account. The partner opens it with the account's key (`POST /v1/missions` with the `agent_id`). The Passport never outlives the Mission, and completing or revoking the Mission revokes its Passports. A body with no Mission, or with more than one, is `400`; a Mission or an agent that is not the account's is `404`; the account must be active. Issuing is a counted action, metered on the account's own plan; a refused issue is not counted. A receiver verifies the Passport offline against the deployment's JWKS as the Passport specification says; the account's own signing keys sign the claim envelopes of its agents, never the Passport. After a claim the partner can no longer issue under the account (`404`).

## 9. Errors

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | A body that does not match its schema. |
| 400 | `TENANT_TIER_NOT_ALLOWED` | The create body names a `tier`. |
| 400 | `RELEASE_EMAIL_REQUIRED` | A release with no `email` and not exactly one invited customer. |
| 400 | `INVALID_REQUEST` | A `forward_url` that is not a public address. |
| 401 | `UNAUTHORIZED`, `INVALID_API_KEY` | No credential, or one that is unknown, revoked, or whose partner or account is no longer active. |
| 403 | `OPERATOR_DELETED` | The key of a closed account, or of any account that was deleted. |
| 403 | `FORBIDDEN` | Not a partner; an account that is not active; a rotation or signing call from OAuth; an invitation to an address that cannot be invited. |
| 404 | `NOT_FOUND` | A resource that is not the caller's: an account, a webhook, an agent, a Mission, a release with no record. |
| 409 | `CONFLICT` | A reference that belongs to a closed account. |
| 409 | `RELEASE_CMEK_ACTIVE` | An account whose data is under a customer-managed key, whatever state the key is in. |
| 409 | `RELEASE_NOT_AVAILABLE` | An account that cannot be released now; an address that cannot claim; a release the customer asked for, withdrawn by the partner. |
| 409 | `TENANT_LIMIT_REACHED` | The deployment's limit of active accounts for the partner. |
| 429 | `RATE_LIMITED` | More invitations and releases than the limit in an hour. |
| 503 | `SERVICE_UNAVAILABLE` | A mail that must go out could not be delivered, or a dependency is down: retry after `Retry-After`. A dependency failure is never reported as a bad credential. |

A deployment that bills its partners MAY add `402` refusals (`INSUFFICIENT_BALANCE`: the wallet cannot cover a new account or its controls; `SPEND_FROZEN`: the partner's spending is frozen and every action of its accounts is refused) and `403` `TENANT_BILLED_BY_PARTNER` (an account key on a billing route); their codes are stable but their conditions are the deployment's own.

## 10. Security considerations

- **Keys.** An account key and a secret are shown once and stored as peppered hashes (keys) or KMS envelopes bound to their owner and purpose (secrets). A partner stores them like any credential, on its server, never in a browser or an agent. A lost key is replaced, never read back.
- **No personal data before it is needed.** The account holds the partner's reference. The customer's address reaches STACK only when the partner invites them or releases the account, and is kept for the invitation or the claim window; the claim link's address is encrypted and the link's token is stored as a hash only.
- **The partner mails strangers on STACK's behalf.** An invitation or a claim link goes to an address the partner gives, with the partner's address in the mail. The partner is vetted, and both are limited per hour, so a stolen key cannot be used to send STACK mail in bulk. The mail says only that the account is being handed over and offers a link; if the customer does nothing, nothing changes.
- **The claim proves the mailbox, and the checkout is locked to it.** The link is a single account's capability, valid for the claim window and withdrawn when replaced; the checkout it starts is fixed to the address it was sent to, so holding the link without the mailbox does not move the account to another address.
- **A release is never a way to learn who has an account.** A claim for an address that already has an account does not complete, and the partner reads `returned` exactly as for any other reason not to complete; the customer's page says only that the claim did not complete.
- **A claim that does not pass never shuts the partner's customer.** A claim that does not complete does not suspend the account being claimed. The account stays open and with the partner, and the partner is told nothing of why.
- **The move ends the partner's reach completely.** Its key, its invited members, its Passports, its inbound webhooks (which would otherwise keep forwarding the customer's events), the agent keys it may hold and the approvals it asked for end in the same step as its billing, so there is no moment at which the customer owns the account and the partner still acts for it. What the partner connected under its own credentials does not pass to the customer either: every secret and address the partner set up in the account is removed in the same step (section 6.5), so no credential of the partner is ever readable, or usable, by the customer and no server of the partner still decides for the customer's agents or receives their events.
- **Fail closed.** A claim that lapses, or whose record is gone, leaves the account where it was (the window is the server's own clock, and the move itself checks it), and the partner asks again; a claim whose checks cannot be read is held for a few hours and then ends with the trial cancelled; no step moves an account on a guess.
- **Accounts are isolated.** An account's key reaches nothing of another account or of the partner; a partner reaches an account's configuration and its issue calls, not its audit content. A guarded change made with an account key (a policy that loosens what an agent may do) is held for the approval of a signed-in person of the partner account until the account is claimed, and of the customer after: an API key, the partner's or the account's, never approves.
- **Content.** What arrives at an account's inbound webhook is third-party content. STACK scans it and marks it; the account's agent still treats it as data.
- **Screening.** A partner is checked at its own checkout like any customer. Until a release completes, the partner is responsible for checking its own customers: the terms say so, and STACK does not screen an account that is not yet a customer of its own.

## 11. Conformance

The `partner` suite of the [conformance kit](../conformance/README.md) is pointed at a **test** instance with a test partner's key. It checks that a call without a credential, with an unknown key, and with the key of an operator that is not a partner is refused; that an account is opened with its key once and the call is idempotent on the reference, that a plan and any unknown field are refused by name, that the view carries no key and no address, that the account's own key works as that account and is refused on the partner surface, and that a lost key is replaced and the old one stops working; that an invitation refuses what it must before it sends anything (a body that does not validate, the placeholder domain), and, given a mailbox it owns (`inviteEmail`), invites and shows the invitation in the view without returning the token or the address; that the release routes refuse what they must (no address to send to, an account that is not the partner's) and, given a mailbox it owns (`releaseEmail`), request a release, repeat it without sending twice, read it, list it, withdraw it and read it as cancelled; given a way to complete a claim out of band (`completeClaim`, which a test instance with its own checkout provides), that a completed claim moves the account (it is `404` for the partner, its old key is refused, the release reads `completed`, the reference is free again) and leaves nothing the partner set up taking effect (a webhook the partner created takes events before the claim and answers `404` at its receiver after it) and, given `failClaim`, that a claim that does not clear leaves the account usable by the partner and reads `returned` with no reason; that a webhook is created under an account with two different secrets, refuses a foreign agent and a forward address that is not public, takes a signed event once and a repeat as deduplicated, refuses a bad signature and an unknown slug and answers `404` once revoked; that a Passport is issued for a Mission the account opened and refused without one; and that closing an account cascades, refuses its key afterwards and finishes on a retry. Without a mailbox the suite sends nothing to anyone, and a check that needs a handle it was not given is reported as skipped, never as passed. The suite does not judge the customer's claim page.

The reference server in `conformance/reference/partner-reference.mjs` passes the suite, and STACK's own routes pass it in the continuous integration of STACK's code.
