# STACK REST API

**Specification:** STACK REST API
**Version:** 2.4.1
**Status:** Stable
**Licence:** Apache-2.0

The STACK engine serves its functions over HTTP: issuing and checking Passports, opening Missions, calling services through the proxy, reading the record, deciding what an agent may do. This document defines what every route has in common, which a client builds on and a server must keep: how a request is read, how a caller is authenticated, the one body every error has and the codes it carries, the step-up a person approves before a safety control is loosened, the refusals of a customer's own controls, the `402` answers, and the cap a caller puts on what a model call may cost. The routes themselves, with their paths, methods, parameters and request bodies, are in [`openapi.json`](openapi.json), an OpenAPI 3.1 document generated from the routes the engine registers and the schemas they run.

Contents: 1 Conventions, 2 Overview, 3 Requests, 4 Authentication and authorisation, 5 Errors, 6 Governance step-up, 7 Refusals by the customer's controls, 8 Payment and licence refusals (402), 9 The cost cap, 10 Rate limits and availability, 11 The operations, 12 Error codes, 13 Security considerations, 14 Conformance, 15 Machine-readable files.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. Two roles are used: the **server** is a STACK engine, or anything that serves the same routes; the **client** is the caller. A server conforms to this specification if it satisfies every MUST that is addressed to a server in sections 3 to 10. A client is written against it: sections 5, 6, 7, 8 and 10 say what a client may rely on and what it MUST NOT.

STACK's own hosted deployment serves the engine's routes and more. The routes only it serves are not part of this specification; every rule of sections 3 to 10 holds for them as well.

## 2. Overview

A server answers on one host. A route's path begins with `/v1` (the API, which a later version of this specification changes only by adding), or is one of the few outside it: `/health`, the discovery documents under `/.well-known/`, the OAuth endpoints under `/oauth/`, and routes under `/internal/` that a deployment's own console calls and no other client is meant to.

Bodies, in both directions, are one JSON value in UTF-8 (`application/json`). A route that answers with no body answers `204`, or `200` with an object.

<!-- spec:generated:rest-counts -->

The engine's document lists 318 operations on 266 paths, in 41 groups (OpenAPI tags). 42 of them take no bearer credential: they are public, or carry a credential of their own kind (a signed request, a token in the path).

<!-- /spec:generated -->

Each operation of the document carries three extensions beside the standard fields:

| Field | Meaning |
|---|---|
| `x-stack-oauth-scope` | The one OAuth scope an access token needs to call the operation (section 4.3), or `none` when the operation is never available to an OAuth access token (it has a credential of its own kind). |
| `x-stack-gates` | The checks the operation runs after authentication, by name (section 4.4). Absent when it has none. |
| `x-stack-body` | `not described` on an operation that takes a body or may, whose schema this document does not give: the handler reads it where the generator does not look, or the operation takes none. |

The document lists a request body only where the route's handler parses it with a schema; a success answer is described only where this specification names its shape (section 6). Every other success answer is a JSON value this document does not constrain.

## 3. Requests

A server MUST read a request body as follows.

- A body is sent with `content-type: application/json`. The text is parsed as one JSON value and the exact text is kept for the routes that check a signature over it (the inbound receivers).
- A JSON request with an empty body is read as `{}`.
- A body that is not JSON is `400 INVALID_JSON`.
- A body larger than the server's limit (one mebibyte unless a route says more) is `400 INVALID_REQUEST`.
- A content type the server has no parser for is `415 UNSUPPORTED_MEDIA_TYPE`. A body sent as `text/plain` or with no content type is not parsed as JSON; the route's validation refuses it as `400 VALIDATION_ERROR`.
- A body, query or path parameter that fails the route's schema is `400 VALIDATION_ERROR` (the failure of a schema the handler parses with) or `400 INVALID_REQUEST` (a check the handler or the parser makes itself). A client treats both as "this request is wrong; change it".
- A request that reaches no route is `404 NOT_FOUND`. The message names the method and the path, with the query string left out and any path segment that looks like a token replaced by `[redacted]`: a server MUST NOT echo a query string or a token it was sent. There is no `405`: a method a path does not serve is a `404`.
- `HEAD` is answered for every `GET` route, with the status and headers of the `GET` and no body.

The failure of a request is decided before anything it asks for is done: a request refused by sections 3 to 5 changed nothing.

## 4. Authentication and authorisation

### 4.1 Credentials

A route that needs a caller reads `Authorization: Bearer <token>`. The kinds of token a server accepts, told apart by their form:

| Token | What it is |
|---|---|
| `sk_live_...` | An operator API key. |
| A signed token whose audience is the API | An OAuth access token (`stack:api`, or `stack:mcp` for the MCP server), a dashboard session, or a team member's session. |
| A signed token whose issuer is `stack-sdk` | An agent's own request, signed with the agent's key: valid for one request, and refused with `AGENT_JWT_REPLAYED` when presented again. |

A call an agent makes with a Passport (a model call, a proxied call) carries the Passport in the header `X-Passport-Token`, beside the credential that authenticates the request.

A request with no credential, a credential of a kind the server does not know, or one it does not accept for any reason (unknown, revoked, expired, for another account, for a member who has left) MUST be refused alike: `401 INVALID_API_KEY`, message and all. A server MUST NOT say which of these it was; the reason belongs in its own log. When the server cannot check a credential because a service it depends on is unreachable, it MUST answer `503 SERVICE_UNAVAILABLE` with `Retry-After` (section 10) and MUST NOT answer `401`: the credential is not at fault.

An account that is suspended or deleted is refused `403 OPERATOR_SUSPENDED` or `403 OPERATOR_DELETED` on every route that needs a credential.

### 4.2 Roles

An account has an owner. A deployment that has members gives each a role: `readonly`, `standard` or `admin`. A route that needs more than the caller's role answers `403 FORBIDDEN` (the message names the role needed). An owner's own credential has every role.

### 4.3 OAuth scopes

An OAuth access token carries scopes, and every operation has one ceiling (`x-stack-oauth-scope`): a token is accepted only if it carries it. One operation, `POST /v1/missions/start`, needs a second scope besides its ceiling (`passports:write`, the scope of the Passport it issues): it does in one call what `POST /v1/missions` and `POST /v1/passports/issue` do in two, so a token needs the scope of each. Its fleet form is never available to an OAuth token. A request an OAuth token may not make is refused `403` with the body RFC 6750 gives a bearer token, which is not the envelope of section 5:

```json
{ "error": "insufficient_scope", "error_description": "This access token does not carry the required agents:write scope.", "scope": "agents:write" }
```

with `WWW-Authenticate: Bearer error="insufficient_scope", scope="agents:write"`. `scope` is absent, and so is the scope in the challenge, on an operation that is closed to OAuth. The scopes, and how many operations of the document each one is the ceiling of:

<!-- spec:generated:rest-oauth-scopes -->

| Scope | Operations |
|---|---|
| `account:read` | 5 |
| `account:write` | 2 |
| `team:read` | 1 |
| `team:write` | 4 |
| `oauth-apps:read` | 1 |
| `oauth-apps:write` | 2 |
| `cmek:read` | 1 |
| `cmek:write` | 2 |
| `passports:read` | 2 |
| `passports:write` | 9 |
| `agents:read` | 8 |
| `agents:write` | 14 |
| `accounts:read` | 0 |
| `accounts:write` | 0 |
| `accounts:act` | 0 |
| `accounts:manage` | 24 |
| `services:read` | 5 |
| `services:write` | 12 |
| `services:connect` | 3 |
| `inbound-webhooks:read` | 2 |
| `inbound-webhooks:write` | 2 |
| `credentials:read` | 2 |
| `credentials:write` | 0 |
| `proxy:read` | 2 |
| `proxy:write` | 1 |
| `audit:read` | 4 |
| `billing:read` | 0 |
| `billing:write` | 0 |
| `payouts:read` | 0 |
| `payouts:write` | 0 |
| `identity:read` | 10 |
| `identity:write` | 19 |
| `authority:read` | 15 |
| `authority:write` | 22 |
| `governance:read` | 2 |
| `governance:write` | 2 |
| `governance:decide` | 1 |
| `intents:read` | 2 |
| `intents:write` | 2 |
| `missions:read` | 5 |
| `missions:write` | 8 |
| `reviews:read` | 5 |
| `reviews:write` | 5 |
| `evidence:read` | 3 |
| `evidence:write` | 1 |
| `dropoffs:read` | 2 |
| `dropoffs:write` | 5 |
| `skills:read` | 0 |
| `skills:write` | 0 |
| `skills:invoke` | 0 |
| `skills:publish` | 0 |
| `notifications:read` | 2 |
| `notifications:write` | 12 |
| `security-events:read` | 2 |
| `security-events:write` | 1 |
| `llm:read` | 2 |
| `llm:invoke` | 9 |
| `scan:read` | 1 |
| `scan:write` | 1 |
| `detectors:read` | 2 |
| `detectors:write` | 2 |
| `pii:read` | 1 |
| `pii:write` | 2 |
| `partner:read` | 3 |
| `partner:write` | 6 |
| `admin` | 0 |

<!-- /spec:generated -->

### 4.4 Gates

An operation that runs a check after authentication names it in `x-stack-gates`. A caller that fails a gate is refused `403 FORBIDDEN`.

| Gate | What it requires |
|---|---|
| `denyAgentContexts` | The caller is not an agent: a request authenticated by an agent's own signed token or by a Passport is refused. The operations that change what governs an agent, or read what is held about it, are closed to the agent they govern. |
| `requireOperatorAdmin` | The caller is the owner or a member with the `admin` role. |
| `requirePartner` | The caller's account is a partner. |
| `dashboardSessionOnly`, `requireBrowserSession` | The caller is a person at a signed-in browser (a session cookie), never a bearer credential. |
| `authorityReceiverAuth`, `authorityProofCallbackAuth`, `enrollmentOrStandardAuth` | The operation is authenticated by a credential of its own kind (a receiver's signature, a proof provider's callback, an enrolment ticket). |

An operation with no `security` entry takes no bearer credential: it is public, or authenticated by something other than a bearer token (a signed request, a token in its path).

## 5. Errors

### 5.1 The envelope

Every answer with a status of `400` or above from a route of the API is one JSON object with one property, `error`: [`schemas/ErrorEnvelope.json`](schemas/ErrorEnvelope.json).

```json
{
  "error": {
    "code": "GOVERNANCE_APPROVAL_REQUIRED",
    "message": "This action loosens a safety control and requires human approval. ...",
    "details": { "approval_id": "gvr_cH64Mb5Zt3kaSHVNy9chx", "approval_url": "https://console.example/app/approve/gvr_cH64Mb5Zt3kaSHVNy9chx" }
  }
}
```

| Field | Type | Meaning |
|---|---|---|
| `error.code` | string | A stable identifier in upper case with underscores (`^[A-Z][A-Z0-9_]*$`). A client decides what to do by the code. A code is never renamed or reused for another meaning; codes are added. |
| `error.message` | string | A sentence for a person. It MAY change between versions, and a client MUST NOT parse it. It names no secret and no credential. A `VALIDATION_ERROR` message is the findings of the failed schema: the fields, what was expected and the kind of value that arrived; a server SHOULD NOT put the text of a value in it, though a finding about a value out of a list of allowed ones may repeat what the caller itself sent. |
| `error.details` | object, optional | Fields that depend on the code, listed with the code in this specification. Absent when a code has none. It MUST NOT carry a secret. |

The envelope is the answer to every failure but these, which keep the shape of the protocol they belong to:

- the OAuth refusal of section 4.3;
- the answers of the `/oauth/` endpoints, which are the errors RFC 6749 defines (`{ "error": "invalid_grant" }` and the like);
- the answer to a browser's CORS preflight, which is plain text;
- answers a server's own front end (a proxy or a gateway) gives before the request reaches it.

A client therefore reads `error.code` when `error` is an object, and treats any other body of a status `400` or above by its status.

A server MUST NOT answer `200` to a request it refused, and MUST NOT put `error` at the top level of a success body.

### 5.2 Status classes

A client that does not know a code MUST act by the status. The class is part of the contract.

| Status | Class | A client |
|---|---|---|
| `400` | The request is wrong. | Changes the request. Does not retry it as it is. |
| `401` | The credential is not accepted. | Obtains a credential. |
| `402` | Payment or a licence is needed (section 8). | Does not retry; the fix is not a different request. |
| `403` | Refused: the caller may not, or a control or a person has not allowed it. | Does not retry as it is. A `403` is never retried blindly, which is why controls answer with it (section 7). |
| `404`, `410` | There is no such thing, or no longer. | Does not retry. |
| `409` | The request conflicts with the state. | Reads the state, then decides. |
| `415`, `422` | The media type or the content cannot be handled (`422` is a cost cap or a call that cannot be priced; section 9). | Changes the request. |
| `429` | Too many requests (section 10). | Waits for `Retry-After`, then retries. |
| `500` | A fault of the server that nothing classifies: `INTERNAL_ERROR`. | May retry once with a delay; reports it if it persists. |
| `501` | The deployment has the route but not the integration behind it: `NOT_CONFIGURED`. | Does not retry. |
| `502`, `503` | A dependency of the server failed, or the server could not serve just now. Nothing ran. | Retries with a delay, after `Retry-After` when given. |

A server MUST NOT answer `500` for anything a caller can cause: a body that is not JSON, a token that is not a Passport, a request that fails a schema. These are `4xx` answers.

### 5.3 Codes of every route

| Code | Status | Meaning and `details` |
|---|---|---|
| `VALIDATION_ERROR` | 400 | The body, query or parameters failed the route's schema. |
| `INVALID_REQUEST` | 400 | A check other than the route's schema failed (a body past the size limit, a value the handler refuses). |
| `INVALID_JSON` | 400 | The body is not JSON. |
| `INVALID_CONTENT_LENGTH` | 400 | The `Content-Length` did not match the bytes received. |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | The content type has no parser; send `application/json`. |
| `NOT_FOUND` | 404 | No such route, or no such object (the message names which). |
| `CONFLICT` | 409 | The request conflicts with the current state. |
| `INVALID_API_KEY` | 401 | The credential is absent or not accepted (section 4.1). |
| `UNAUTHORIZED` | 401 | A route that needs a person's session found none. |
| `AGENT_JWT_REPLAYED` | 401 | An agent's one-request token was presented twice. Sign a new one for every request, retries included. |
| `FORBIDDEN` | 403 | The caller may not do this (section 4.2, 4.4). |
| `OPERATOR_SUSPENDED` | 403 | The account is suspended. |
| `OPERATOR_DELETED` | 403 | The account is deleted. |
| `BILLING_ACCOUNT_INACTIVE` | 403 | The account this one is billed through is not active. |
| `RATE_LIMITED` | 429 | Too many requests; no `details`. |
| `SERVICE_UNAVAILABLE` | 503 | A service the server depends on is unreachable; `details.retry_after_seconds` (integer), and `Retry-After`. |
| `NOT_CONFIGURED` | 501 | The deployment lacks the integration behind the route. |
| `INTERNAL_ERROR` | 500 | An unexpected fault; the message is fixed and says nothing of it. |

## 6. Governance step-up

A few changes loosen what keeps an agent safe: they widen what it may do, unblock it, loosen a detector, move the control socket, or decide a held action. Anyone who holds an API key or an OAuth token can ask for them, and a credential like that may be in the hands of an agent. So the server does not do such a change on the word of a bearer credential. It records the request as an **approval**, refuses with `403 GOVERNANCE_APPROVAL_REQUIRED`, and does the change only when the request is repeated after **a person** has approved it where a bearer credential cannot: in a signed-in browser, or in a chat client that attests the person confirmed it.

### 6.1 Who steps up

A change that needs approval says so by this refusal. A dashboard session (a person at a signed-in browser) passes without approval: the person is the approval. Every other credential, an API key, an OAuth token, a member's key, steps up. The operations that change what governs an agent are closed to an agent's own credential (`denyAgentContexts`, section 4.4), so the one that is watched cannot ask for its own approval.

### 6.2 The refusal

`403 GOVERNANCE_APPROVAL_REQUIRED`, with these `details`:

| Field | Type | Meaning |
|---|---|---|
| `approval_id` | string | The approval's id: `gvr_` followed by letters, digits, `_` and `-`. It is worthless without the person's decision and without the same credential, and may be shown to a model. |
| `approval_url` | string | The page where a person decides this one approval. |

The message states the protocol in words: who is to approve, where, and the header to send on the retry. Asking again for the same change from the same caller creates another approval, except for the changes whose request is the same by definition (activating a fleet policy), which share one.

### 6.3 Completing it

1. The client gives the person `approval_url` (or the id), and waits. It can read the state of the approval with `GET /v1/governance/approvals/{id}`, whose answer is [`schemas/GovernanceApprovalDetail.json`](schemas/GovernanceApprovalDetail.json), or list them with `GET /v1/governance/approvals` (`{ "approvals": [ GovernanceApprovalView ] }`, [`schemas/GovernanceApprovalView.json`](schemas/GovernanceApprovalView.json)). Both are closed to an agent's credential.
2. A person decides the approval. They approve or reject it on the approval page, with a signed-in browser session (`POST /v1/governance/approvals/{id}/decide`, `{ "decision": "approve" | "reject" }`, which a bearer credential can never call: it answers `401 UNAUTHORIZED`). A deployment that offers it also lets a person decide in a chat client through `POST /v1/governance/approvals/{id}/chat-decision` ([`schemas/GovernanceChatDecisionInput.json`](schemas/GovernanceChatDecisionInput.json)): a rejection from any caller that is not an agent; an approval only from an OAuth access token that presents the attestation the MCP server signs after the person accepted the prompt, and never for an action the table below lists as browser-only. A deployment with no browser console (an install on its own machine) gives the person at the machine a command that decides.
3. The client sends the **same request again** with the header `X-Governance-Approval: <approval_id>`. The server does the change if, and only if, the approval:
   - belongs to the caller's account;
   - is `approved` and has not expired;
   - is for this action and this object;
   - was made for exactly this change: the approval stores a SHA-256 hash of the canonical form of the payload the route fixes for the change (`payload_hash` in the detail), and the retry's payload must have the same hash. What the person saw is what runs;
   - has not been used: the server consumes it with one compare-and-set, so it works once, even when two requests race.

   A retry whose request differs from the approved one is refused and the approval stays unused.

An approval stays open for the time below; states and the action names are the generated tables.

<!-- spec:generated:rest-approval-constants -->

| Constant | Value |
|---|---|
| Header that names the approval | `X-Governance-Approval` |
| An approval stays open for | 86400 s (24 h) |
| Approval states | `pending`, `approved`, `rejected`, `consumed`, `expired` |
| Approval id | `gvr_` followed by letters, digits, `_` and `-` |

<!-- /spec:generated -->

### 6.4 Refusals of the retry

A retry that cites an approval is refused as follows; the message says which.

| Code | Status | When |
|---|---|---|
| `NOT_FOUND` | 404 | The approval does not exist for this account (a wrong id, another account's, one that was erased). |
| `GOVERNANCE_APPROVAL_PENDING` | 403 | The approval is still `pending`: the person has not decided. Wait and repeat the call with the same header. |
| `GOVERNANCE_APPROVAL_REJECTED` | 403 | The person rejected the approval. |
| `GOVERNANCE_APPROVAL_EXPIRED` | 403 | The approval expired before it was used. |
| `FORBIDDEN` | 403 | The approval has been used already, or does not match this action, this object or this exact change. |

The three `GOVERNANCE_APPROVAL_*` refusals carry `details.approval_id` and `details.status`. A client that gets a refusal other than `GOVERNANCE_APPROVAL_PENDING` asks for a new approval by repeating the request without the header.

The changes to authority records carry the header `Idempotency-Key`. For those, the same key and the same change MAY use an approval that a first attempt consumed and then failed before its answer reached the client, so a lost answer does not need a second person. Any other repeat of a consumed approval is refused.

### 6.5 The actions

The action an approval is for is named in `GovernanceApprovalView.action`. Each is decided where the table says.

<!-- spec:generated:rest-governance-actions -->

| Action | Decided |
|---|---|
| `fleet_policy_activate` | on the approval page, or in a chat client that attests the person confirmed |
| `detector_config_upsert` | on the approval page, or in a chat client that attests the person confirmed |
| `detector_config_reset` | on the approval page, or in a chat client that attests the person confirmed |
| `review_decide_approve` | on the approval page, or in a chat client that attests the person confirmed |
| `agent_unblock` | on the approval page, or in a chat client that attests the person confirmed |
| `agent_register` | on the approval page, or in a chat client that attests the person confirmed |
| `agent_setup` | on the approval page, or in a chat client that attests the person confirmed |
| `agent_authority_expand` | on the approval page, or in a chat client that attests the person confirmed |
| `agent_skill_allow` | on the approval page, or in a chat client that attests the person confirmed |
| `agent_key_enroll` | on the approval page, or in a chat client that attests the person confirmed |
| `agent_enrollment_ticket_mint` | on the approval page, or in a chat client that attests the person confirmed |
| `service_grant_expand` | on the approval page, or in a chat client that attests the person confirmed |
| `service_proxy_disable` | on the approval page, or in a chat client that attests the person confirmed |
| `service_allowed_hosts_expand` | on the approval page, or in a chat client that attests the person confirmed |
| `notification_config_mutate` | on the approval page, or in a chat client that attests the person confirmed |
| `billing_mutate` | on the approval page in a signed-in browser only |
| `pii_config_upsert` | on the approval page, or in a chat client that attests the person confirmed |
| `pii_config_reset` | on the approval page, or in a chat client that attests the person confirmed |
| `authority_binding_activate` | on the approval page, or in a chat client that attests the person confirmed |
| `authority_principal_erase` | on the approval page, or in a chat client that attests the person confirmed |
| `authority_binding_erase` | on the approval page, or in a chat client that attests the person confirmed |
| `authority_proof_erase` | on the approval page, or in a chat client that attests the person confirmed |
| `authority_presentation_erase` | on the approval page, or in a chat client that attests the person confirmed |
| `authority_receiver_profile_activate` | on the approval page, or in a chat client that attests the person confirmed |
| `authority_profile_activate` | on the approval page, or in a chat client that attests the person confirmed |
| `authority_receiver_key_add` | on the approval page, or in a chat client that attests the person confirmed |
| `account_open` | on the approval page, or in a chat client that attests the person confirmed |
| `account_contact_consent_add` | on the approval page, or in a chat client that attests the person confirmed |
| `account_piece_resume` | on the approval page, or in a chat client that attests the person confirmed |
| `account_toll_free_verification_submit` | on the approval page, or in a chat client that attests the person confirmed |
| `account_email_change` | on the approval page in a signed-in browser only |
| `account_delete` | on the approval page in a signed-in browser only |
| `control_socket_change` | on the approval page in a signed-in browser only |
| `account_control_loosen` | on the approval page in a signed-in browser only |
| `control_review` | on the approval page in a signed-in browser only |
| `network_install_key_add` | on the approval page in a signed-in browser only |
| `making_order_approve` | on the approval page, or in a chat client that attests the person confirmed |
| `member_sso_binding_clear` | on the approval page in a signed-in browser only |
| `sso_domain_add` | on the approval page in a signed-in browser only |
| `sso_config_change` | on the approval page in a signed-in browser only |
| `trust_widen` | on the approval page, or in a chat client that attests the person confirmed |
| `intent_approve` | on the approval page, or in a chat client that attests the person confirmed |
| `intent_approve_payment` | on the approval page in a signed-in browser only |
| `identity_settings_loosen` | on the approval page, or in a chat client that attests the person confirmed |
| `service_requirement_loosen` | on the approval page, or in a chat client that attests the person confirmed |
| `agent_warnings_dismiss` | on the approval page, or in a chat client that attests the person confirmed |

<!-- /spec:generated -->

## 7. Refusals by the customer's controls

An account can have controls: policies the account's owner wrote, a server of their own that decides (the [control socket](../control-socket/SPEC.md)), or none. Before an agent's action spends, sends or acts, the server asks the deciders that apply. Four refusals reach the client. Each is a `403` or a `503` that never charges for the action, and each hands the action back to the account's allowance: a refused action is never counted.

| Code | Status | `details` |
|---|---|---|
| `CONTROL_DENIED` | 403 | See 7.1. The decider said no. |
| `CONTROL_LIMIT_EXCEEDED` | 403 | See 7.2. A limit of the policy was reached while the action was being paid for. |
| `CONTROL_SOCKET_UNAVAILABLE` | 403 | `decision_id` (string), `cause` (string: one of the causes in section 6 of the control socket specification). The customer's own server gave no usable answer in time. |
| `CONTROL_UNAVAILABLE` | 503 | `decision_id` (string). STACK's own hosted controls could not decide just now. |

The first three are `403` and not `5xx` on purpose: a client that retries every `5xx` would retry into a customer's server that is down. A client retries a `CONTROL_SOCKET_UNAVAILABLE` or a `CONTROL_UNAVAILABLE` only after a delay, and a `CONTROL_DENIED` only as 7.1 says.

### 7.1 `CONTROL_DENIED`

| Field | Type | Meaning |
|---|---|---|
| `decision_id` | string | The decision's id, the same the customer's record and (for the control socket) the request carried. |
| `reason_code` | string or null | The decider's own reason code (the control socket pattern `^[a-z][a-z0-9_]{0,63}$`), or one of the policy codes below. `null` when the decider gave none. |
| `retry` | object, optional | Present when the decider holds the action for a person: `ref` (string, opaque) and optionally `after_seconds` (integer). |
| `rule` | object, optional | Present when a hosted policy refused: [`schemas/PolicyRefusalEvidence.json`](schemas/PolicyRefusalEvidence.json). Which policy (`policy_id`, `policy_revision`), which section and rule, and the policy's own side of the comparison; never a value from the call. |

The message is the decider's own sentence when it gave one. To retry a held action the client repeats the request with the header `X-Control-Ref: <retry.ref>` once the person has approved it; the decider recognises the reference and allows that one retry. A client MAY send `X-Control-Purpose: <text>` with any action: a short statement of why the agent acts, which the decider reads (longer than the limit of the control socket specification is cut).

The sections of a policy (`rule.section`):

<!-- spec:generated:rest-policy-sections -->

`connections`, `actions`, `recipients`, `spend`, `review`, `models`, `browser`, `card`, `wallet`, `workspace`, `tools`

<!-- /spec:generated -->

The reason codes a policy refusal carries (`rule.code`):

<!-- spec:generated:rest-policy-reason-codes -->

| `rule.code` |
|---|
| `connection_denied` |
| `connection_not_listed` |
| `call_outside_rules` |
| `action_denied` |
| `recipient_not_allowed` |
| `recipients_not_pinned` |
| `amount_over_limit` |
| `model_not_allowed` |
| `cost_over_limit` |
| `host_not_allowed` |
| `merchant_not_allowed` |
| `payee_not_allowed` |
| `timeout_over_limit` |
| `tool_not_allowed` |
| `limit_reached` |
| `concurrency_reached` |
| `review_required` |
| `review_pending` |
| `review_rejected` |
| `review_mismatch` |
| `policy_unevaluable` |

<!-- /spec:generated -->

### 7.2 `CONTROL_LIMIT_EXCEEDED`

| Field | Type | Meaning |
|---|---|---|
| `limit.window` | string | `day`, `month`, `mission`, or `action` (the most one action may cost). |
| `limit.unit` | string | `cents` or `actions`. |
| `limit.scope` | string, optional | `spend:<rule id>` when a spend rule's counter refused; absent for the account's shared window. |
| `remaining` | integer | What the limit has left, in `limit.unit`. |
| `max_per_action_cents` | integer, optional | Present when `limit.window` is `action`: the most one action may cost. |

Nothing was reserved or charged.

### 7.3 Configuring controls

Two refusals belong to setting the controls up, not to an action: `409 CONTROLS_NOT_ENABLED` (hosted controls are not on for the account) and `400 CONTROL_SOCKET_ADDRESS_REFUSED` (`details.cause`: the address is not `https`, names an internal host, or failed its setup check). A policy that allows a send without naming who receives it is refused `400 UNBOUNDED_SEND_RULE` (`details.rules` lists the rules and the recipient fields left unbound), unless the rule leaves its recipients to each Mission (7.4).

### 7.4 Recipients set per job

A policy rule that allows a send on a connection names who the send may reach, or leaves that to each Mission. A rule that leaves it sets `recipients` to `per_mission` (in a rule of `definition.connections.rules` of the policy routes in [`openapi.json`](openapi.json), `recipients` is absent or the one value `per_mission`, and only an `allow` rule may carry it). Such a rule allows a send only inside a Mission that pins every recipient field of the sends the rule names, with an exact value, and only to those values.

A server that accepts the field:

1. MUST accept a `per_mission` rule whose intents are sends with recipient fields a Mission can pin, and MUST keep refusing the same rule without it as `UNBOUNDED_SEND_RULE`. It MUST refuse a `per_mission` rule that names no send, or a send with no recipient field to pin (a reply, a stored draft), as `UNBOUNDED_SEND_RULE`, and a `per_mission` rule that is not an `allow` rule as `VALIDATION_ERROR`.
2. MUST open a Mission with its pins when `POST /v1/missions` or `POST /v1/missions/start` (the `mission` object) carries `recipients`, `recipient_pins` or `reply_to_message`, and MUST NOT change them afterwards except by `POST /v1/missions/{id}/recipients`, which only the owner (never an agent) calls, which takes the same three fields and merges them into the pins (nothing is taken away), and which answers `409` for a Mission that has ended. `recipients` is a list of exact addresses, numbers or ids, applied at every recipient field a send names; `recipient_pins` is a list of `{ path, op, value }` with `op` `eq` (one value) or `in` (a list), `path` a request field such as `body.to` or `*` for every recipient field, a recipient inside the URL included (`url.pathname` matches when it, or one of its segments, is a listed value), one pin per path, at most 64 pins and 1,000 recipients a list, a recipient listed twice kept once; `reply_to_message` is the id of a message the agent's account received (or of an incoming call the agent answered or declined) and pins the Mission to its sender or caller, and is `404 NOT_FOUND` for a message the agent cannot reply to. A server MUST pin an email's sender only when the receiving server authenticated it (a DMARC pass, or an SPF or DKIM pass aligned with the From domain) and its From is exactly one mailbox; for any other email it MUST answer `422 MESSAGE_SENDER_NOT_VERIFIED` and pin no one. The Mission read (`GET /v1/missions/{id}`) returns `recipient_pins`, an array or `null`.
3. MUST refuse a send that only a per-job rule covers when its Mission has no pins, or pins no value for a recipient field the rule leaves open, as `CONTROL_DENIED` with `rule.code` `recipients_not_pinned`; and MUST refuse a send that names any recipient the Mission did not pin, a request that names no recipient, and a recipient field it cannot read, as `CONTROL_DENIED` with `rule.code` `recipient_not_allowed`. A call under no Mission has no pins. A per-job rule refuses only the calls it covers: in `connections.mode` `any` a call that fails the rule's own constraints is left to the mode. The refusal names the rule and never a recipient.
4. MUST hold every call of the Mission to the same pins, whatever the number of calls at once, and MUST hold a delegated Passport, which carries its parent's Mission, to them as well: a child cannot send further than the job named, whatever policy its own agent has, and the per-job rules of every agent that delegated it, and of the agent the Mission was opened for when there is one, bind it. A revision that adds an allowance at the endpoint of a send a per-job rule covers, which is not per job itself, is a loosening. A server that cannot read the Mission refuses the send (`CONTROL_UNAVAILABLE`); it never allows an unpinned one.
5. MAY leave an agent account's own mail, texts and calls out of this: they run only under the account's own Mission, so a second Mission is not how they are bound. A server that has them MAY accept `per_mission` in place of a list in `definition.recipients.email`, `sms` and `call`: a send, text or call then names the stored message it answers (`reply_to_message`) and goes only to the sender of that message, or, naming none, goes only to the account Mission's own pins; a response to an invite goes to its organizer; numbers are compared in E.164 form; it is refused with the same two codes (`recipients_not_pinned` when nothing pins it, `recipient_not_allowed` for any other recipient); an id that is not one of the account's received messages is `404 NOT_FOUND`.

`POST /v1/control-policies/simulate` accepts `call.mission_id` to try a call inside a Mission, and `call.reply_to_message` (with `agent_id`) to try an account send that answers a stored message.

## 8. Payment and licence refusals (402)

`402` means the fix is a licence, a balance or a plan, not a different request. Its body is the envelope of section 5.1; the status is the whole class, and the code says which. A `402` never means the action ran: nothing was charged and, for an action that is counted, nothing was counted.

| Code | Status | `details` |
|---|---|---|
| `LICENCE_REQUIRED` | 402 | `feature` (string, one of the features below), `licence` (`none`, `invalid`, `expired` or `valid`: what the install's licence is, never the key). A self-managed install is without the licence key that covers `feature`. |
| `ALLOWANCE_EXHAUSTED` | 402 | None. An account on a hard monthly cap of actions has reached it. |

A deployment that keeps a prepaid balance refuses a spend with a `402` whose code names the cause. A client MUST treat every `402` alike by status and read `code` and `details` only for what it knows. STACK's own hosted deployment raises these, and a client of it can meet them:

| Code | Status | `details` |
|---|---|---|
| `INSUFFICIENT_CREDITS` | 402, hosted | None. The balance does not cover the spend. |
| `INSUFFICIENT_BALANCE` | 402, hosted | The balance does not cover the spend, or the account owes for a spend that cost more than its hold (`details.owed_cents`); a top-up pays that first. |
| `SPEND_FROZEN` | 402, hosted | `reason` (string). Spending is frozen until a dispute or a refund is resolved. |
| `AGENT_BUDGET_EXCEEDED` | 402, hosted | `account_id` (string), `remaining_cents` (integer). The agent's budget for the month is spent. |
| `PLATFORM_SUBSCRIPTION_REQUIRED` | 402, hosted | `status` (string), and the plan's price, trial length and where to subscribe. |

The features a licence key covers:

<!-- spec:generated:rest-licence-features -->

| Feature | What it covers |
|---|---|
| `sso` | single sign-on |
| `provisioning` | user provisioning |
| `roles` | member roles beyond owner and member |
| `siem` | security-monitoring connectors |
| `evidence_exports` | signed evidence exports and compliance reports |
| `partners` | partner and multi-tenant features |
| `lts` | long-term-support versions |

<!-- /spec:generated -->

`GET /v1/licence` reads an install's licence state: `mode`, `licence` (`none`, `valid`, `invalid`, `expired`), `features`, and when and why. It never returns the key.

## 9. The cost cap

A model call (a request to a `/v1/llm/` route) MAY carry a cap of the caller's own on what it can cost.

`X-Max-Cost-Cents: <n>` where `n` is a whole number of cents, `1` or more, written in decimal digits. A server that reads the value reads it as a number and refuses one that is not a whole number of cents as `400 VALIDATION_ERROR`; a cap is never read as "no cap". A server that ignores the header on a call on the customer's own provider key (below) does not read it there. With no header there is no cap.

When the call is on a key of the deployment's own, the server prices the call's **worst case** (or, where it cannot, an estimate) and holds it before the provider's credential is read or anything is sent. If the worst case is above the cap the server does one of two things, and says which in its own documentation: it refuses the call,

`422 MODEL_COST_CAP`, `details`: `reason` (`cost_cap_exceeded`), `worst_case_cents` (integer), `max_cost_cents` (the cap),

or it holds the cap instead of the worst case and charges what the call costs above it from the caller's balance once the call is charged (a deployment that keeps a balance may then refuse new spend while that balance is owed, with its own `402`). STACK's hosted deployment holds the cap.

When the call is on the customer's own provider key, which the provider bills, the server has no worst case to hold the cap to, and says in its own documentation which it does: it ignores the cap and the call goes on, or it refuses the call, `422 MODEL_COST_CAP`, `details.reason` is `cost_cap_unavailable`. STACK's hosted deployment ignores the cap there.

A call whose cost the server cannot bound and will not estimate (no output limit, a feature that bills by use) is `422 BILLING_COST_UNBOUNDED`, cap or not. A model that makes images, asked of a provider that has none, is `422 IMAGE_NOT_SUPPORTED` (`details.provider`).

The server checks the cap after it has admitted the call (the Passport, the Mission, the scope) and before it holds funds or reads a credential; a call refused earlier is refused for that reason, and the cap is not looked at. A call refused for its cap is never charged. The catalogue says which models and tools take a cap and where (`cost_cap` in the [Catalogue specification](../catalogue/SPEC.md)); a tool takes it as the body field `max_cost_cents` instead of the header.

## 10. Rate limits and availability

A server limits the requests it takes, per credential and, before a request is authenticated, per address. A deployment chooses its limits (the engine's defaults are 100 a minute per address before authentication and 500 a minute per credential, with a lower limit on a few routes such as issuing and verifying Passports). Every answer to a route that is limited carries:

| Header | Meaning |
|---|---|
| `X-RateLimit-Limit` | The requests allowed in the window that applies. |
| `X-RateLimit-Remaining` | What is left of it. |
| `X-RateLimit-Reset` | Seconds until the window ends. |

A request over the limit is `429 RATE_LIMITED` with `Retry-After` (seconds), whose body names nothing about the limiter. A client waits for `Retry-After`.

A `503` is retried with a delay: `SERVICE_UNAVAILABLE` carries `Retry-After` and `details.retry_after_seconds`, and a `CONTROL_UNAVAILABLE` (and the hosted deployment's capacity codes) means that STACK itself could not serve: nothing ran and nothing was charged. `CMEK_REVOKED` is a `503` too: the customer's own encryption key cannot be reached, and a retry fails until they restore it.

## 11. The operations

[`openapi.json`](openapi.json) is the list of the operations of the engine. A server that claims to serve the engine's API serves each of them as the document says; a server MAY serve more.

The document is generated, never edited. `node scripts/generate-spec.mjs` writes it from the routes the built API registers (the same registration the server runs, listed with no server started and no connection opened) and from the schemas the route handlers parse their input with, and `node scripts/generate-spec.mjs --check` fails when it differs. A route that exists is in the document because the document is the route table, and a test in the engine's own suite compares it with a second, independent reading of the route files, so a route cannot be added without an entry.

STACK's own deployment serves routes the engine does not. They are described in a document that stays with that deployment and is not published.

## 12. Error codes

The codes of the engine's source are the table that ends this section, generated from it. A client MUST treat a code that is not in it, and a code with a status it does not list, by the status class (section 5.2). The meaning of the codes that belong to a specification of their own is in it: the Passport codes (`PASSPORT_EXPIRED`, `PASSPORT_REVOKED`, `PASSPORT_INVALID`, `PASSPORT_BLOCKED`, `DELEGATION_DEPTH_EXCEEDED`, `SCOPE_ESCALATION`, `DELEGATION_ACCOUNTABILITY_VIOLATION`) in [Passport](../passport/SPEC.md) section 11; the control socket's in [Control Socket Protocol](../control-socket/SPEC.md) section 6. A token that is not a Passport at all (unreadable, tampered, or made for another audience or issuer) is `401 PASSPORT_INVALID`; `PASSPORT_REVOKED` is only for a Passport that was revoked.

<!-- spec:generated:rest-error-codes -->

| Code | HTTP status |
|---|---|
| `ACCOUNTABILITY_REQUIRED` | 400 |
| `AGENT_JWT_REPLAYED` | 401 |
| `ALLOWANCE_EXHAUSTED` | 402 |
| `AUTHORITY_REQUEST_EXPIRED` | 410 |
| `AUTHORITY_STREAM_RESPONSE_TOO_LARGE` | 502 |
| `BILLING_ACCOUNT_INACTIVE` | 403 |
| `BROWSER_BINDING_REQUIRED` | 400 |
| `CAPACITY_EXCEEDED` | 429 |
| `CHECKPOINT_NOT_AVAILABLE` | 404 |
| `CMEK_CONFIGURATION_INVALID` | 400 |
| `CMEK_REVOKED` | 503 |
| `CONFLICT` | 409 |
| `CONNECTION_AMBIGUOUS` | 409 |
| `CONNECTION_NO_ACCESS_TOKEN` | 409 |
| `CONTROL_DENIED` | 403 |
| `CONTROL_LIMIT_EXCEEDED` | 403 |
| `CONTROL_SOCKET_ADDRESS_REFUSED` | 400 |
| `CONTROL_SOCKET_UNAVAILABLE` | 403 |
| `CONTROL_UNAVAILABLE` | 503 |
| `CONTROLS_NOT_ENABLED` | 409 |
| `CONTROLS_REQUIRED` | 402 |
| `DELEGATION_ACCOUNTABILITY_VIOLATION` | 400 |
| `DELEGATION_DEPTH_EXCEEDED` | 400 |
| `DETECTOR_CONFIG_INVALID` | 400 |
| `DROPOFF_ALREADY_COLLECTED` | 409 |
| `DROPOFF_EXPIRED` | 410 |
| `EMAIL_SEND_FAILED` | 502 |
| `EMPTY_BODY` | 400 |
| `ENROLL_NOT_APPLICABLE` | 409 |
| `FORBIDDEN` | 403 |
| `GDPR_VIOLATION` | 400 |
| `GOVERNANCE_APPROVAL_EXPIRED` | 403 |
| `GOVERNANCE_APPROVAL_PENDING` | 403 |
| `GOVERNANCE_APPROVAL_REJECTED` | 403 |
| `GOVERNANCE_APPROVAL_REQUIRED` | 403 |
| `IDENTITY_REQUIREMENTS_NOT_MET` | 403 |
| `IMAGE_NOT_SUPPORTED` | 422 |
| `INTERNAL_ERROR` | 500 |
| `INVALID_API_KEY` | 401 |
| `INVALID_CONTENT_LENGTH` | 400 |
| `INVALID_EMAIL` | 400 |
| `INVALID_ENROLLMENT` | 400 |
| `INVALID_INPUT` | 400 |
| `INVALID_INVITE` | 400 |
| `INVALID_JSON` | 400 |
| `INVALID_QUERY` | 400 |
| `INVALID_REQUEST` | 400 |
| `INVALID_SPIFFE_ID` | 400 |
| `INVALID_TOKEN` | 400 |
| `INVALID_WEBHOOK_SIGNATURE` | 400 |
| `INVALID_WORKLOAD_ID` | 400 |
| `LICENCE_REQUIRED` | 402 |
| `MESSAGE_SENDER_NOT_VERIFIED` | 422 |
| `MISSION_NOT_PAUSED` | 409 |
| `MISSION_PAUSED` | 403 |
| `MISSION_REQUIRED` | 400 |
| `MODEL_COST_CAP` | 422 |
| `NOT_CONFIGURED` | 400, 404, 501 |
| `NOT_FOUND` | 404 |
| `OIDC_CONFIG_EXISTS` | 409 |
| `OPENROUTER_ENDPOINT_REFUSED` | 403 |
| `OPERATOR_DELETED` | 403 |
| `OPERATOR_SUSPENDED` | 403 |
| `PASSPORT_BLOCKED` | 403 |
| `PASSPORT_EXPIRED` | 401 |
| `PASSPORT_INVALID` | 401 |
| `PASSPORT_REVOKED` | 401 |
| `PII_CONFIG_INVALID` | 400 |
| `PROOF_CALLBACK_AUTH_INVALID` | 401 |
| `PROVIDER_CAPACITY_UNAVAILABLE` | 503 |
| `RATE_LIMITED` | 429 |
| `RECEIVER_AUTH_INVALID` | 401 |
| `SAVE_OUTPUT_UNAVAILABLE` | 400 |
| `SCHEMA_VALIDATION_FAILED` | 400 |
| `SCOPE_ESCALATION` | 400 |
| `SERVICE_NOT_CONNECTED` | 404 |
| `SERVICE_UNAVAILABLE` | 502, 503 |
| `SIGNING_KEY_UNAVAILABLE` | 404 |
| `SSO_CALLBACK_INVALID` | 400 |
| `SSO_DOMAIN_INVALID` | 400 |
| `SSO_DOMAIN_LIMIT_REACHED` | 409 |
| `SSO_DOMAIN_UNAVAILABLE` | 409 |
| `SSO_HANDOFF_INVALID` | 401 |
| `SSO_LOGIN_FAILED` | 400 |
| `SSO_PROVIDER_UNAVAILABLE` | 503 |
| `SSO_STATE_INVALID` | 400 |
| `SSO_STATE_NOT_BOUND` | 400 |
| `SSO_UPSTREAM_ERROR` | 400 |
| `TENANT_LIMIT_REACHED` | 409 |
| `TENANT_TIER_NOT_ALLOWED` | 400 |
| `TIER_LIMIT_EXCEEDED` | 403 |
| `TRUST_DOMAIN_EXISTS` | 409 |
| `TRUST_DOMAIN_MISMATCH` | 400 |
| `UNAUTHORIZED` | 401 |
| `UNBOUNDED_SEND_RULE` | 400 |
| `UNSUPPORTED_MEDIA_TYPE` | 415 |
| `UPSTREAM_ANSWER_BROKE_OFF` | 502 |
| `UPSTREAM_TIMEOUT` | 504 |
| `VALIDATION_ERROR` | 400 |
| `WEBHOOK_HANDLER_FAILED` | 500 |
| `WIMSE_ISSUER_EXISTS` | 409 |
| `WORKLOAD_AUDIENCE_MISMATCH` | 401 |
| `WORKLOAD_IDENTITY_NOT_MAPPED` | 403 |
| `WORKLOAD_ISSUER_MISMATCH` | 400 |
| `WORKLOAD_ISSUER_MISSING` | 400 |
| `WORKLOAD_ISSUER_NOT_CONFIGURED` | 401 |
| `WORKLOAD_JWKS_UNAVAILABLE` | 503 |
| `WORKLOAD_KEY_ID_MISSING` | 400 |
| `WORKLOAD_KEY_ID_UNKNOWN` | 400 |
| `WORKLOAD_PROVIDER_UNAVAILABLE` | 500 |
| `WORKLOAD_SIGNATURE_INVALID` | 401 |
| `WORKLOAD_SPIFFE_ID_INVALID` | 400 |
| `WORKLOAD_SUBJECT_MISSING` | 400 |
| `WORKLOAD_TOKEN_EXPIRED` | 401 |
| `WORKLOAD_TOKEN_MALFORMED` | 400 |
| `WORKLOAD_TOKEN_TOO_CLOSE_TO_EXPIRY` | 400 |
| `WORKLOAD_TRUST_DOMAIN_MISMATCH` | 400 |
| `WORKLOAD_VERIFY_FAILED` | 400 |

<!-- /spec:generated -->

## 13. Security considerations

- **No enumeration.** A credential is refused with one code and one message whatever was wrong with it. An unknown approval and an approval of another account are the same `404`.
- **No secrets in errors.** `message` and `details` carry no credential, key or secret. The 404 of an unknown route leaves out the query and replaces token-shaped path segments.
- **Approvals bind to the exact change.** An approval is single use, expires, belongs to one account, one action and one object, and is checked against the hash of the payload that was approved. A bearer credential can never decide an approval, so the credential that asks cannot be the one that grants.
- **Controls fail closed.** A customer's decider that cannot answer refuses the action; it is never read as "allowed". The refusal is `403` so that it is not retried into the failure.
- **A cap is held, or the caller is told it is not.** A call on a key of the deployment's own holds at most the cap. On the customer's own provider key, where the provider bills and nothing is held, a server ignores the cap or refuses it with a `422`, and says which in its documentation.
- **Retry safety.** Retry only what the status class allows; a `403` for a control or an approval is not retried as it is.

## 14. Conformance

The `rest-api` suite of the [conformance kit](../conformance/README.md) plays the client. Given the base URL of a server, it checks that the server answers a request that reaches no route, one without a credential and one with a bad credential in the envelope; that a body that is not JSON is `400 INVALID_JSON`, a body that fails its schema `400 VALIDATION_ERROR` and an unknown content type `415`; that a refusal does not echo a query string or a token it was sent; and, with an API key, that the step-up of section 6 works end to end and is bound to the exact change. With the probes the suite documents it checks the `402` refusals, the refusals of the customer's controls and the cost cap. A check that needs something it was not given is reported as skipped, never as passed.

The engine passes the suite in its own tests, started the way the engine image is started. `reference/rest-api-server.mjs` in the kit is a small server of the wire contract that passes it.

## 15. Machine-readable files

| File | What it is |
|---|---|
| [`openapi.json`](openapi.json) | The operations of the engine, OpenAPI 3.1, schemas in JSON Schema draft-07. |
| [`schemas/ErrorEnvelope.json`](schemas/ErrorEnvelope.json) | The body of every error. |
| [`schemas/GovernanceApprovalView.json`](schemas/GovernanceApprovalView.json), [`schemas/GovernanceApprovalDetail.json`](schemas/GovernanceApprovalDetail.json) | An approval, and an approval with its payload hash and page. |
| [`schemas/GovernanceChatDecisionInput.json`](schemas/GovernanceChatDecisionInput.json) | A decision made in a chat client. |
| [`schemas/PolicyRefusalEvidence.json`](schemas/PolicyRefusalEvidence.json) | The `rule` of a `CONTROL_DENIED`. |
