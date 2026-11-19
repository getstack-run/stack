# Changelog: STACK REST API

This specification follows semantic versioning. A new operation, a new optional field of a request or an answer, and a new error code are minor versions: clients ignore what they do not know and act on the status class of a code they do not know. A change to the envelope, to a code's status, or to what a listed field means is a major version.

## 2.4.1 - 2026-11-11

A correction. A client that holds both scopes below keeps working.

- Changed: a read-only team member's POST, PUT, PATCH or DELETE is refused `403` ("This action requires standard access or higher") on every route, before the request is counted; before, many routes that open, change, end or send something answered it. It still reads, signs itself in or out and connects its own chat client, and it may call the lookups that only read through a POST (`POST /v1/control-policies/simulate`, `POST /v1/proxy/operations/get`, `POST /v1/dashboard/proxy/operations/get`). An owner's key, an owner's session, an agent and a Passport are not affected.
- Changed: `POST /v1/missions/start` (the operator form) is available to an OAuth access token that carries both `missions:write` and `passports:write`; before, every OAuth token was refused. A token with only one of them is refused `403 insufficient_scope`, and the `scope` of the answer names every scope it lacks, separated by spaces. The fleet form still needs an agent session.

## 2.4.0 - 2026-11-03

A loosening of when a person has to say yes, and an addition. A client that handles `GOVERNANCE_APPROVAL_REQUIRED` keeps working, and one that still sends `X-Governance-Approval` where none is asked is not refused for it.

- Changed: registering an agent never asks for an approval, whatever settings it starts with (`agent_register` is retired).
- Changed: `POST /v1/intents/{id}/approve` decides an intent directly for an API key or an OAuth token; only an intent that can move money (an onchain transaction, or a wallet or gas cost) answers `GOVERNANCE_APPROVAL_REQUIRED` and is approved in a browser (`intent_approve_payment`). An intent the server cannot read is shown as its raw JSON and judged by the same fields read from that JSON; only one that is not a JSON object, or whose type or cost fields cannot be read, counts as one that can move money. A standard member may approve and reject, and retire an agent (`DELETE /v1/agents/{id}`).
- Changed: an approval can be used for one hour from the decision, and an approval still pending past its time can no longer be approved. It is bound to the agent and the Mission it was asked for, not to the Passport, so a refresh does not lose it.
- Changed: loosening the identity settings, removing or weakening a service's identity requirement and dismissing an agent's warnings ask for no approval.
- Added: `GET /v1/intents/{id}?review=1` answers `intent: null` and `intent_raw` for an intent the server cannot read.
- Added: `POST /v1/missions/{id}/recipients`: the owner adds `recipients`, `recipient_pins` or `reply_to_message` to a running Mission (409 for one that has ended). `*` also covers a recipient inside the URL; a Mission takes 64 pins and 1,000 recipients a list, and a recipient listed twice is kept once. `reply_to_message` may name an incoming call the agent answered or declined. See section 7.4.
- Changed: a per-job rule refuses only the calls it covers; an account's send that names no message is judged against the Mission's own pins, an invite response goes to its organizer, and numbers are compared in E.164 form.
- Added: `call.reply_to_message` on `POST /v1/control-policies/simulate`.
- Changed: a grant rule (`alternatives`) with no limits is accepted, a scope holds up to eight choices of rules, and a Passport may be up to 48,000 characters (request headers up to 64 KB).
- Changed: a refusal under a choice of rules names the constraint each rule failed on.
- Added: the codes `FLEET_REVIEW_PENDING`, `FLEET_REVIEW_REJECTED`, `FLEET_REVIEW_USED` and `FLEET_REVIEW_EXPIRED` (403, `details.status`) in place of a bare `FORBIDDEN` for a request a fleet policy holds; an expired review opens again for the same operation key.
- Changed: a custom connect link takes a name of up to 200 characters, a description of up to 2,000, 1 to 100 hosts and a credential template, and the owner may correct the hosts on the key page.

## 2.3.0 - 2026-11-01

A loosening. Nothing a client sends or reads changes: a client that handles `MODEL_COST_CAP` keeps working.

- Changed: on a call on the customer's own provider key, a server may ignore the caller's `X-Max-Cost-Cents` instead of refusing it with `MODEL_COST_CAP` (`cost_cap_unavailable`), and says which it does. STACK's hosted deployment ignores it. A server that refuses still conforms. A server that ignores the header there does not read it, so a malformed value is not refused on that key.
- Added: the mode `own_key_ignored` of `probes.costCap` in the conformance kit's `rest-api` suite, which expects the call to go on; `M01` is skipped in that mode.
## 2.2.0 - 2026-10-31

An addition. Nothing a client sends or reads changes unless it uses the new fields.

- Added: a policy rule that allows a send may set `recipients` to `per_mission`: it then allows a send only inside a Mission that pins every recipient field with an exact value, and only to those values. A Mission opens with its pins from `recipients`, `recipient_pins` and `reply_to_message` on `POST /v1/missions` and on the `mission` of `POST /v1/missions/start`, and `GET /v1/missions/{id}` returns `recipient_pins`. A delegated Passport is held to the same pins. See section 7.4.
- Added: `definition.recipients.email`, `sms` and `call` of a policy may be `per_mission` in place of a list, on a server that has agent accounts: the account's own send then names the stored message it answers and goes only to its sender. See section 7.4, item 5.
- Added: the reason code `recipients_not_pinned` of a policy refusal (the Mission does not name who it may send to); a send to someone the Mission did not pin is `recipient_not_allowed`.
- Added: `call.mission_id` on `POST /v1/control-policies/simulate`.
- Changed: the message of `UNBOUNDED_SEND_RULE` also offers `per_mission`.
- Added: the check `C02` of the conformance kit's `rest-api` suite, which takes `probes.perJob` (skipped without it).

## 2.1.0 - 2026-10-31

A loosening of when a person has to say yes, and an addition. Nothing a client sends or reads changes: a client that handles `GOVERNANCE_APPROVAL_REQUIRED` keeps working, and one that sends `X-Governance-Approval` where none is asked is not refused for it.

- Changed: registering an agent (`POST /v1/agents/register`) no longer asks for a person's approval, except when the request starts the agent weaker than the defaults: `eval_traffic` or `is_synthetic` true, `llm_redact_pii` or `llm_inject_system_prompt` false, a lower `accountability_mode`, looser `credential_access` or a lower `twin_policy`. Then a person approves the whole request (`agent_register`, in a chat client or on the approval page) and the approval names each weakening. The same settings on `PATCH /v1/agents/{id}` still need a person, as before; moving `credential_access` to a looser value now asks and to a stricter one does not (the ranking was reversed).
- Changed: allowing a skill for an agent (`POST /v1/agents/{id}/allowed-skills`), and adding skills or widening `skill_access_mode` on `PATCH /v1/agents/{id}`, no longer ask for a person's approval, and `agent_skill_allow` is no longer raised. Every other widening on `PATCH /v1/agents/{id}` still asks (`agent_authority_expand`). Both routes answer `403` to a read-only member.
- Changed: the governance action `making_order_approve` is no longer approved in a signed-in browser only: it may be approved in a chat client as well, where the confirmation names the supplier, product, quantity, destination city and country, and amount. The names `agent_register` and `agent_skill_allow` stay in the list of actions.
- Added: the conformance kit's `rest-api` suite asks for a gated change that a server which does not gate registering an agent still gates (unblocking an agent, with two test agents it registers and removes), and takes another in `probes.stepUp`.
- Changed: on a key of the deployment's own, a server may hold the caller's `X-Max-Cost-Cents` instead of refusing a call whose worst case is above it, and charge what the call costs above the cap from the caller's balance; it says which it does. A server that refuses still conforms. A server may hold an estimate for a call whose cost it cannot bound instead of answering `BILLING_COST_UNBOUNDED`.

## 2.0.0 - 2026-10-25

- Removed: the `sk_grant_` credential, every route of the partner grants (`/v1/partner/connect`, `/v1/partner/connections`, `/v1/operator/partner-grants`, the customer's consent and opt-out routes) and the `partner-grants:read` and `partner-grants:write` scopes. The partner routes are now the partner-managed accounts of the [Partner API](../partner/SPEC.md) 2.0.0 (`/v1/partner/accounts`, replacing `/v1/partner/tenants`).
- The error codes `RELEASE_EMAIL_REQUIRED` and `RELEASE_NOT_AVAILABLE` are added.
- Added: `POST /v1/team/sso-bindings/clear` (scope `team:write`), which forgets the single sign-on link of one member or of every member linked to one issuer, so a customer that replaces its identity provider does not lock its members out ([Single Sign-on Profile](../sso-login/SPEC.md) 1.2.0); the governance action `member_sso_binding_clear`, approved in a signed-in browser only; and `sso_issuer` on a team member (null until the member has signed in through single sign-on).
- Added: `GET` and `POST /v1/identity/sso-domains`, `POST /v1/identity/sso-domains/{id}/verify` and `DELETE /v1/identity/sso-domains/{id}` (scopes `identity:read` and `identity:write`; owner or admin, refused to an agent), the verified e-mail domains of single sign-on ([Single Sign-on Profile](../sso-login/SPEC.md) 1.3.0); the governance action `sso_domain_add`, approved in a signed-in browser only; and the error codes `SSO_DOMAIN_INVALID`, `SSO_DOMAIN_UNAVAILABLE` and `SSO_DOMAIN_LIMIT_REACHED`.
- Changed: `GET`, `POST`, `PATCH` and `DELETE` on `/v1/identity/oidc/config` and `POST /v1/identity/oidc/config/{id}/test` are for the owner or an administrator member and answer `403` to any other member and to an agent; creating the provider, changing what decides who it may sign in and turning sign-in on need the governance action `sso_config_change`, approved in a signed-in browser only ([Single Sign-on Profile](../sso-login/SPEC.md) 1.3.1).

## 1.0.0 - 2026-10-24

Initial public release.

- `openapi.json`: every route the engine serves, as an OpenAPI 3.1 document generated from the routes the engine registers and the schemas its handlers parse with. A route cannot exist without an entry.
- The error envelope (`error.code`, `error.message`, optional `error.details`) for every error, the status classes a client acts by, and the codes the engine raises, generated from its source.
- The rules for reading a request: JSON bodies, an empty body, a body that is not JSON (`INVALID_JSON`), a body too large, an unknown content type, the answer to an unknown route.
- Authentication with a bearer credential, one refusal for every credential that is not accepted, roles, the OAuth scope ceiling of each operation and its RFC 6750 refusal, and the gates an operation runs.
- The governance step-up: `GOVERNANCE_APPROVAL_REQUIRED`, the approval, how a person decides it, the retry with `X-Governance-Approval`, and every refusal of the retry.
- The refusals of a customer's controls (`CONTROL_DENIED`, `CONTROL_LIMIT_EXCEEDED`, `CONTROL_SOCKET_UNAVAILABLE`, `CONTROL_UNAVAILABLE`), the retry reference `X-Control-Ref` and the statement of purpose `X-Control-Purpose`.
- The `402` answers (`LICENCE_REQUIRED` and the codes of a deployment that keeps a balance).
- The cost cap `X-Max-Cost-Cents` and `MODEL_COST_CAP`.
- Rate limit headers and the retry rules for `429` and `503`.

Two behaviours of the engine were made to agree with this text: a body that is not JSON answers `400 INVALID_JSON` (it answered `500 INTERNAL_ERROR`), and a request that reaches no route answers `404 NOT_FOUND` in the error envelope (it answered the framework's own body). A token presented as a Passport that is not one (unreadable, tampered, or made for another audience or issuer) answers `401 PASSPORT_INVALID` (it answered `500 INTERNAL_ERROR`); `PASSPORT_REVOKED` stays for a Passport that was revoked.
