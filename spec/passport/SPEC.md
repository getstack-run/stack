# STACK Passport

**Specification:** STACK Passport
**Version:** 1.3.0
**Status:** Stable
**Licence:** Apache-2.0

A Passport is a short-lived, signed credential that tells a service who an AI agent is, who stands behind it, which task it is on, and exactly what it may do. This document defines the Passport token, the rules for issuing, narrowing and delegating one, how a service verifies one offline and online, and how revocation reaches the services that rely on it.

Contents: 1 Conventions, 2 Model, 3 Token, 4 Claims, 5 Scope and constraints, 6 Lifetimes, 7 Issuing and refreshing, 8 Delegation, 9 Verifying a Passport, 10 Revocation, 11 Errors, 12 Security considerations, 13 Machine-readable schemas and conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

All times in tokens are seconds since the Unix epoch. All JSON is UTF-8. Identifiers are opaque strings; the prefixes shown (`op_`, `agt_`, `pas_`, `ms_`, `scon_`) are conventions of the reference implementation and a verifier MUST NOT depend on them except where a pattern is stated in a schema.

## 2. Model

- An **operator** is the customer account that owns agents and the connections they use.
- An **agent** is a registered software actor owned by one operator.
- A **Mission** is the task an agent is on. Every agent Passport belongs to exactly one live Mission. A Mission has an expiry, and when it ends (completed, revoked or expired) every Passport issued for it is revoked.
- A **connection** is a credential an operator holds for an external service (identified by `scon_*`). A Passport names connections and the scopes it may use on each; it never contains the credential.
- A **Passport** is the signed token. It is bearer-style: whoever holds a valid one presents the authority it names.

A Passport only ever narrows. A delegated Passport carries no more than its parent, a refreshed Passport no more than its Mission still allows, and a service that verifies a Passport learns the least the issuer decided it needed.

## 3. Token

A Passport is a JSON Web Token (RFC 7519) in JWS compact form, signed with EdDSA over Ed25519 (RFC 8037).

Protected header:

| Field | Value |
|---|---|
| `alg` | MUST be `EdDSA`. A verifier MUST reject every other value, including `none`. |
| `kid` | Identifies the signing key in the issuer's JWKS. |

Registered claims:

| Claim | Value |
|---|---|
| `iss` | The issuer. `getstack.run` for the hosted service; a self-hosted deployment sets its own and verifiers MUST be configured with it. |
| `aud` | `stack:passport`. A verifier MUST reject a token whose audience is anything else (the same keys sign other tokens for other audiences). |
| `sub` | The agent id. MUST equal `stk.agent_id`. |
| `iat`, `exp` | Issue and expiry times. |
| `jti` | The Passport id, unique per token. It is the key for revocation. |

The STACK claims are in one object, `stk`, described in section 4.

Example payload (shortened):

```json
{
  "iss": "getstack.run",
  "aud": "stack:passport",
  "sub": "agt_8f2c",
  "iat": 1790000000,
  "exp": 1790000900,
  "jti": "pas_3k9d",
  "stk": {
    "operator_id": "op_41aa",
    "agent_id": "agt_8f2c",
    "agent_name": "inbox-triage",
    "services": [
      {
        "service_id": "svc_gmail",
        "service_name": "gmail",
        "scopes": ["gmail.readonly"],
        "credential_ref": "cred_9c",
        "connection_id": "scon_77"
      }
    ],
    "identity_claims": [],
    "delegation_depth": 0,
    "session_id": "ses_12",
    "accountability": "enforced",
    "mission_ids": ["ms_5d1"]
  }
}
```

## 4. Claims

The `stk` object is defined by [`schemas/PassportClaims.json`](schemas/PassportClaims.json). Every producer and consumer MUST treat that schema as normative for field names, types and bounds. The fields are:

| Field | Meaning |
|---|---|
| `operator_id` | The owning operator. Required. |
| `agent_id` | The agent the Passport is for. Required. |
| `agent_name` | A display name. Informational. |
| `services` | The connections the bearer may use, each a `ServiceScope` (section 5). May be empty. |
| `identity_claims` | References to verified identity facts about the principal. A reference carries an opaque claim id, the provider, the claim type, the assurance level, and when it was verified and expires. A Passport MUST NOT carry personal data; the facts themselves are resolved by the issuer, never embedded. |
| `delegation_depth` | 0 for a root Passport; each delegation adds one. At most 4. |
| `parent_passport_id` | The `jti` of the Passport this one was delegated from. Present exactly when `delegation_depth` is above 0. |
| `session_id` | Groups the Passports of one run, including delegated ones. |
| `accountability` | `enforced`, `logged` or `standard` (section 6). |
| `intent_summary`, `intent_services`, `intent_refs` | What the agent declared it would do, and with which services, at issue time. Informational for a service; the issuer judges behaviour against it. |
| `checkpoint_interval` | Seconds between required checkpoints for `enforced` agents. |
| `mission_ids` | The Mission the Passport belongs to: exactly one entry for an agent Passport. |
| `authority_refs` | At most 8 opaque references to authority bindings the issuer resolves server-side. None of the binding's contents are in the token. |
| `fleet` | A binding to a fleet policy revision, when the Passport was issued under one. |
| `workspace_command` | Present only on a Passport the issuer made for one command run in an agent account's workspace (`{ workspace_id }`). A service that is not the issuer MUST ignore Passports carrying it. The issuer accepts such a Passport as a bearer only at its credential proxy, refuses to refresh it, and delegation carries the claim to every child. |
| `platform_intent` | Present only on the issuer's own administrative Passports. A verifier that is not the issuer MUST ignore Passports carrying it. It is never inherited by delegation. |

Verifiers MUST ignore claims they do not recognise. The schema is additive: new optional claims may appear in a minor version of this specification and existing claims keep their meaning.

## 5. Scope and constraints

A `ServiceScope` grants use of one connection:

| Field | Meaning |
|---|---|
| `service_id`, `service_name` | The service and its provider name. |
| `connection_id` | The canonical connection id (`scon_*`). Tokens issued by older versions of the reference implementation may omit it; they expire within the maximum lifetime. |
| `credential_ref` | An opaque reference to the credential. It is not the credential and not a connection id. |
| `scopes` | The provider scopes permitted. `*` means every scope the connection holds. |
| `constraints` | Zero to 32 parameter-level constraints (below). |
| `policy` | An operation policy: `open` (anything not constrained is permitted, the default when absent) or `closed` (only the listed `operations` are permitted, each with the methods, path match and `allow_fields` it may carry). |
| `allow_data_from` | The services whose content may flow into this one. Absent or empty means no cross-service movement into this service is permitted; reading from a service and writing back to the same service always needs no declaration. |

### 5.1 Constraints

A constraint is `{ "path", "op", "value" }`. The constraints of a scope are combined with AND: a request is permitted only if every constraint holds.

`path` addresses a view of the request the bearer is making:

| Path | Resolves to |
|---|---|
| `method` | The upper-cased HTTP method. |
| `url.pathname`, `url.host`, `url.origin` | Parts of the target URL (host lower-cased, trailing slash removed from the path). |
| `headers.<name>` | A request header, name case-insensitive. |
| `query.<key>` | A URL parameter; a repeated key is a list. Parameters already in the URL are included, so one cannot be smuggled past a constraint. |
| `body.<a.b.c>` | A field of the JSON body. |
| `body.<list>[].<field>` | The `field` of every element of an array. A constraint on a fan-out holds only if it holds for every element. |
| `derived.email.recipients`, `.from`, `.subject`, `.text` | The decoded fields of an outbound email whose headers are encoded in the body. |

Operators: `eq`, `not_eq`, `in`, `not_in`, `matches` (an RE2 regular expression of at most 256 characters), `starts_with`, `lt`, `lte`, `gt`, `gte`, `exists`, `not_exists`.

One more constraint holds a choice of rules: `{ "path": "any_of", "op": "any_of", "value": [[constraint, ...], [constraint, ...]] }`, with two to 16 groups of plain constraints (the groups do not nest, and hold at most 128 constraints in all). It holds when every constraint of at least one group holds, and it is one of the constraints of the scope, so every other constraint of the scope must hold as well. An issuer uses it for a grant that allows several things on one connection, such as a read and a post. A verifier that enforces constraints MUST evaluate it that way, and one that does not know it MUST refuse the call rather than skip it. A child scope carries its parent's `any_of` whole and narrows it by adding constraints, which may include an `any_of` of its own: a call must then meet both. A scope holds at most eight of them.

Evaluation MUST fail closed:

- A path that does not resolve is a failure, except for `not_exists`, which then holds, and `exists`, which then fails.
- A list is quantified universally: the constraint holds only if it holds for every element. An empty list fails a positive operator and satisfies `not_eq` and `not_in`.
- A fan-out over a shape that cannot be read (an element that is not an object where the path goes deeper, a field that should be an array and is not, more than 10,000 elements) is present and equal to nothing: even `not_eq`, `not_in` and `not_exists` MUST NOT pass it.
- Numeric operators accept a number or a numeric string, never a boolean.
- `matches` MUST be evaluated with a linear-time engine.

The reference implementation is `evaluateConstraint` in `@stack/shared`; a service that enforces constraints itself MUST give the same answers.

## 6. Lifetimes

<!-- spec:generated:passport-constants -->

| Constant | Value |
|---|---|
| Default lifetime | 900 s (15 min) |
| Maximum lifetime | 3600 s (1 h) |
| Refresh grace after expiry | 86400 s (24 h) |
| Maximum delegation depth | 4 |
| Issuer (`iss`) | `getstack.run` |
| Audience (`aud`) | `stack:passport` |
| Signature algorithm | `EdDSA` (Ed25519) |
| Revocation channel | `stack:revoked` |

<!-- /spec:generated -->

- A Passport MUST NOT live longer than the maximum lifetime, nor longer than its Mission, nor (when delegated) longer than any ancestor.
- `accountability` sets how the issuer supervises the agent. `enforced` Passports live as long as the checkpoint interval (never more than the maximum) and are extended only by a passing checkpoint; `logged` and `standard` Passports live for the requested lifetime. A delegated Passport MUST NOT be less accountable than its parent (`enforced` above `logged` above `standard`).
- An expired Passport can be exchanged for a fresh one within the refresh grace period, subject to section 7.

## 7. Issuing and refreshing

The hosted API is described here so that other implementations of an issuer can be compatible; a service that only consumes Passports needs sections 3 to 5, 9 and 10.

**Issue** (`POST /v1/passports/issue`, authenticated as the operator or its agent): the body is [`schemas/IssuePassportInput.json`](schemas/IssuePassportInput.json). The response is `201` with `{ "token", "jti", "expires_at" }`.

An issuer:

1. MUST require `mission_ids` to hold exactly one live Mission of the same operator (the only exception is an issuer's own administrative Passport), and MUST refuse a Mission that is missing, foreign, completed, revoked or expired.
2. MUST construct the scopes from the agent's current grants. A request MAY narrow them (`scopes` subset, extra `constraints`, `intents`); it MUST NOT add a scope, drop a constraint the grant sets, or declare a data flow the grant does not permit.
3. MUST clamp the lifetime to the maximum and to the Mission's expiry.
4. MUST refuse to issue for an agent that is blocked or inactive.
5. MUST sign the claims only after validating them against the claims schema, so that it never mints a token its own verifier would reject.

**Refresh** (`POST /v1/passports/refresh`): the body is [`schemas/RefreshPassportInput.json`](schemas/RefreshPassportInput.json). The token may be expired, but only within the refresh grace period. A refreshed Passport MUST NOT carry anything the old one did not. The issuer MUST re-check that the Mission is live, the agent is active and not checked out, and that each connection is still active; the new scopes are the old scopes that the current grant still covers, the constraints are the old ones plus the grant's, and a connection that is gone or has no scope left is dropped. A delegated Passport cannot be extended beyond its original signed lifetime: when that ends, the holder obtains a fresh delegation from a valid parent.

## 8. Delegation

**Delegate** (`POST /v1/passports/delegate`): a Passport holder derives a Passport for another agent of the same operator. The body is [`schemas/DelegatePassportInput.json`](schemas/DelegatePassportInput.json).

An issuer MUST enforce all of the following and MUST refuse the delegation otherwise:

1. The parent Passport verifies online (section 9.2) and belongs to the operator making the call.
2. The parent's `delegation_depth` is below the maximum; the child's is the parent's plus one.
3. The parent's Mission is live. The child carries the parent's Mission unchanged.
4. The child agent belongs to the same operator, is active and is not blocked.
5. Every requested scope names a connection the parent has, and every scope string is one the parent has. A child MUST NOT hold a scope its parent lacks. A connection is named by its `connection_id`; for a Passport issued before connection ids existed, by its `credential_ref` or its `service_id`.
6. The child's constraints for a service contain every constraint of the parent verbatim (the child may add more). A child MUST NOT drop a parent constraint.
7. The child's `allow_data_from` for a service is a subset of the parent's. Omitting it inherits the parent's declaration.
8. The child's accountability is not below the parent's. The parent's accountability is the higher of what its token says and what its agent is configured with. A parent whose accountability is `enforced` MUST have declared at issue that it would delegate (`intent.will_delegate`): without that declaration the delegation is refused with `403 FORBIDDEN`, and a parent that is `logged` may delegate undeclared but the issuer records a warning.
9. The child's lifetime is at most the parent's remaining lifetime and at most the remaining lifetime of every ancestor.
10. A Passport carrying `platform_intent` MUST NOT be delegated.

Identity claim references pass down unchanged. The `session_id` is inherited.

## 9. Verifying a Passport

A service that receives a Passport (for example in an `X-Stack-Passport` header) chooses between two checks. They are not interchangeable: only the second sees revocation.

### 9.1 Offline verification

A verifier that has the issuer's public key MUST:

1. Parse the token as a compact JWS and reject it if `alg` is not `EdDSA`.
2. Select the key whose `kid` equals the header's `kid` from the issuer's JWKS and verify the signature.
3. Reject if `iss` is not the expected issuer, if `aud` is not `stack:passport`, or if `exp` is not in the future. A verifier MAY allow a clock tolerance of at most 60 seconds.
4. Reject if `jti`, `sub`, `iat`, `exp` or `stk` is missing, if `stk.operator_id` or `stk.agent_id` is missing, if `stk.services` or `stk.identity_claims` is not an array, or if `sub` differs from `stk.agent_id`.
5. If `stk.authority_refs` is present, reject it if it is not an array of at most 8 well-formed references.
6. Then apply its own authorisation: the requested service and scopes MUST be present in `stk.services`, and any constraints of that scope MUST hold for the request.

Offline verification MUST NOT be described to users as proof that the Passport is still valid: it cannot see revocation.

The issuer publishes its signing keys as a JWKS (RFC 7517) at `GET /v1/.well-known/jwks.json` (no authentication). Keys are Ed25519 JWKs (`kty: OKP`, `crv: Ed25519`) carrying `kid`, `alg: EdDSA` and `use: sig`. An issuer that rotates keys SHOULD keep publishing a retired key until every Passport signed by it has expired and its refresh grace period has passed, so that verifiers do not reject live tokens at the rotation. A verifier SHOULD cache the JWKS and MUST re-fetch it once, rate-limited, when it meets an unknown `kid`.

### 9.2 Online verification

`POST /v1/passports/verify` takes [`schemas/VerifyPassportInput.json`](schemas/VerifyPassportInput.json) (`token`, optional `service_id`) and needs no authentication: the token is the credential. A successful answer is `200` with [`schemas/VerifyPassportResult.json`](schemas/VerifyPassportResult.json); its `claims` are the token's `stk` claims. Every other outcome is an error (section 11): the endpoint never answers `200` with `"valid": false`.

The issuer MUST, in this order, treat the Passport as invalid unless:

1. The signature, issuer, audience and expiry verify as in 9.1.
2. The owning operator exists and is active.
3. The `jti` is not revoked (section 10).
4. The agent is active; and for a delegated Passport every ancestor is unrevoked and unexpired.
5. Every connection in `stk.services` that has a `connection_id` is still active and still covers the signed scopes, constraints and data flows. A grant that was narrowed or removed after issue invalidates the Passport (and the issuer SHOULD revoke it).
6. Every identity claim reference and authority reference the token carries is still valid.
7. When `service_id` is given, the Passport satisfies that service's identity requirements.

An unreadable revocation store MUST produce a retriable `503`, never an acceptance and never a `401`.

A relying service that calls `verify` on every request SHOULD do so only for requests that matter and cache a positive answer for at most a few seconds. An issuer MAY limit how often one caller may verify (the reference implementation allows 20 calls a minute and answers `429 RATE_LIMITED` beyond that, with a `Retry-After` header), which is another reason to cache.

## 10. Revocation

A Passport is revoked by `jti`. A revocation takes effect, for services that verify online, on the next verification, not after a delay.

The issuer MUST:

- Revoke a Passport's descendants whenever it is revoked (a cascade).
- Revoke every Passport of a Mission when the Mission ends, and every Passport of an agent, a session or an operator when told to do so in bulk.
- Record revocation in a store that online verification reads before it answers, with a retention at least as long as the Passport's remaining lifetime.

### 10.1 Revoking

An operator revokes with these calls, each authenticated as the operator and each answering `200` with `{ "success": true, ... }`:

| Call | Body | Revokes | Answer besides `success` |
|---|---|---|---|
| `POST /v1/passports/revoke` | `{ "jti", "reason"? }` | The Passport and its descendants. Repeating it is a success. | `jti`, `cascaded_count`, `revoked_claims_count` |
| `POST /v1/passports/revoke-agent/{agent_id}` | `{ "reason"? }` | Every Passport of the agent. | `revoked_count` |
| `POST /v1/passports/revoke-session/{session_id}` | `{ "reason"? }` | Every Passport of the session. | `revoked_count` |
| `POST /v1/passports/revoke-all` | `{ "reason"? }` | Every Passport of the operator. | `revoked_count` |

A Mission ends with its own calls, which the Mission API defines (`POST /v1/missions/{id}/complete` and `/revoke`); ending one revokes its Passports (the rule above). An operator can only revoke what belongs to it.

### 10.2 The channel

Revocation notices are published on the channel `stack:revoked` of the issuer's Redis deployment. The channel is a notification for services that run beside the issuer (a self-hosted deployment's own gateways and workers); it is not a public endpoint, and a service that cannot subscribe MUST use online verification when it must reject a revoked Passport before it expires. Each message is a JSON object described by [`schemas/RevocationEvent.json`](schemas/RevocationEvent.json):

| `type` | Meaning |
|---|---|
| `single` | One Passport (`jti`) and the descendants listed in `cascaded`. |
| `bulk_agent` | Every Passport of an agent. |
| `bulk_session` | Every Passport of a session. |
| `bulk_operator` | Every Passport of an operator. |
| `bulk_claim` | Every Passport carrying a revoked identity claim. |
| `bulk_mission` | A Mission ended; `cascaded_passport_jtis` lists the Passports it revoked. |

A subscriber MUST treat the message as a hint to drop caches and MUST NOT treat a missing message as proof of validity: Redis publish is at-most-once. The `at` field is a Unix time in milliseconds. A subscriber that was disconnected SHOULD discard any cached positive verdicts on reconnecting.

## 11. Errors

Errors from the hosted API use the envelope `{ "error": { "code", "message", "details" } }`. The codes a Passport verifier can meet:

<!-- spec:generated:passport-errors -->

| Code | HTTP status | Message |
|---|---|---|
| `PASSPORT_EXPIRED` | 401 | Passport has expired |
| `PASSPORT_REVOKED` | 401 | Passport has been revoked |
| `PASSPORT_INVALID` | 401 | Passport is not valid |
| `DELEGATION_DEPTH_EXCEEDED` | 400 | Maximum delegation depth exceeded |
| `SCOPE_ESCALATION` | 400 | Child scope cannot exceed parent scope |
| `DELEGATION_ACCOUNTABILITY_VIOLATION` | 400 | Cannot delegate from enforced agent to standard agent. Delegation cannot reduce accountability. |
| `PASSPORT_BLOCKED` | 403 | Agent agt_example is blocked from passport issuance pending review |

<!-- /spec:generated -->

Other codes (`GOVERNANCE_APPROVAL_REQUIRED`, `FORBIDDEN`, `VALIDATION_ERROR`, `RATE_LIMITED`) are part of the wider API and not defined here. A Passport that is not accepted is reported with the least detail that lets a client act. An expired one is `401 PASSPORT_EXPIRED`, which is distinguishable so that a client can refresh. A token that is not a Passport of the issuer (not a token at all, signed by another key, made for another audience or issuer, or changed after signing) is `401 PASSPORT_INVALID`. A revoked or unknown Passport, or one of a deactivated agent, is `401 PASSPORT_REVOKED`, without saying which. A request that carries no token, or a token that is not a string, is `400 VALIDATION_ERROR`. A server error is never the answer to a bad token.

## 12. Security considerations

- A Passport is a bearer credential. Services MUST receive it only over TLS and MUST NOT log it. Issuers keep lifetimes short for this reason.
- The signature proves the issuer minted the token; it does not prove the presenter is the agent. Where that matters, bind the Passport to a key held by the agent (the reference implementation does this with agent-signed requests) or restrict it to the connection it arrived on.
- Offline verification trades revocation latency for availability. A service that takes a consequential action MUST verify online.
- `aud` separation prevents a session or OAuth state token signed by the same key from being accepted as a Passport. Verifiers MUST check it.
- Constraint evaluation is part of the security boundary. An implementation that evaluates constraints MUST fail closed on anything it cannot read or parse, MUST use a linear-time regular expression engine, and MUST apply the constraint of every element of a list.
- Personal data MUST NOT be placed in a Passport. Identity claims travel as references.

## 13. Machine-readable schemas and conformance

The JSON Schemas in [`schemas/`](schemas/) (draft-07) are generated from the reference implementation and are normative for the shapes they describe: `PassportClaims`, `ServiceScope`, `Constraint`, `DeclaredOperation`, `ScopePolicy`, `IssuePassportInput`, `DelegatePassportInput`, `RefreshPassportInput`, `VerifyPassportInput`, `VerifyPassportResult` and `RevocationEvent`. Where a schema and this text disagree, report it as a defect; the schema is what the reference implementation enforces.

Conformance tests are in [`../conformance/`](../conformance/README.md): the `passport` suite tests a verifier of section 9.1, and the `passport-online` suite tests an issuer: online verification (9.2), revocation and its channel (10) and the narrowing rules of delegation (8), on a test instance.
