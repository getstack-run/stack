# STACK Authority Receiver Protocol

**Specification:** STACK Authority Receiver Protocol
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

An authority, a bank or any other service may ask the owner of an AI agent for information before it lets the agent act: who the owner is, that the owner may do this, that a person has agreed. This document defines how such a service, the **receiver**, asks STACK for exactly that information, gets it and nothing else, checks that it is genuine and tells STACK what it did with it. The protocol is called STACK direct-post JWT, version 1 (`stack.direct_post.jwt`, `"1"`). It also defines the two other outside exchanges of the same feature: the callback an identity or mandate provider makes to STACK, and what STACK needs from a company's OpenID Connect provider when a person approves an agent's authority.

Contents: 1 Conventions, 2 Overview, 3 Receivers, keys and the profile, 4 Encodings, 5 Authenticating a call, 6 The presentation request, 7 Delivery of the presentation, 8 Status checks, 9 Receipts, 10 Reading a presentation request, 11 Proof provider callbacks, 12 Enterprise OIDC approvals, 13 Errors, 14 Security considerations, 15 Conformance, 16 Machine-readable schemas.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. Roles: the **receiver** is the outside service (an authority, a bank, any server that asks for information about an agent's owner); **STACK** is the deployment that holds the owner's records and answers; the **agent** is the AI agent that wants to act at the receiver; the **owner** is the person or organisation whose agent it is and who registered the receiver. A receiver implementation conforms to this specification if it satisfies every MUST in sections 3 to 10 and 15 that is addressed to a receiver. The conformance kit in [`../conformance/`](../conformance/README.md) (the `authority` suite) tests exactly that. A provider that calls back (section 11) or an identity provider (section 12) conforms to the sections that name it.

HTTP paths are relative to the **STACK origin**: the origin of the STACK API that serves a receiver, for example `https://api.example.com`. The owner's registration gives it to the receiver; it is also returned in `audience` by the origin challenge (section 3.3). Times are Unix seconds unless a field says otherwise.

## 2. Overview

1. The owner registers the receiver with STACK: its identifier, its public keys, and a **receiver profile**, which states which facts the receiver may ask for and where STACK delivers them (section 3).
2. The owner gives the agent an **authority binding**: an exact, time-limited statement of what the agent may do at that receiver and which facts it may disclose, backed by proofs STACK has verified. The Passport the agent carries names the binding by a short **authority reference**.
3. The agent comes to the receiver with its Passport and wants to act. The receiver builds a transaction (an action, a resource, a request, a nonce) and the agent signs a **proof of possession** over it (section 6.3).
4. The receiver calls STACK to open a **presentation request** (section 6). Every call is authenticated by a short-lived signed assertion that binds the exact HTTP request (section 5); the body is a second signed message in which the receiver repeats what it asks.
5. STACK checks the whole chain, collects what the receiver asked for and no more, signs it as a **presentation**, encrypts it to the receiver's own key and POSTs it to the receiver's delivery endpoint (section 7). The agent never sees the content. STACK's answer to the receiver's call only says that it was delivered.
6. The receiver decrypts the presentation, checks it (section 7.2) and decides. Before it acts it MAY ask STACK whether the binding is still in force (section 8).
7. The receiver sends STACK a signed **receipt** that says whether it accepted, rejected or failed the transaction and commits to the result (section 9). STACK records it in the owner's signed record.

A receiver gets only what it asked for: the facts it requests MUST be exactly the facts its profile requires, in the disclosure mode the owner's binding allows, and STACK refuses a request that asks for more or for less (section 6.4).

Version 1 is the one protocol defined here. The receiver profile names it, so a later protocol (for example an OpenID for Verifiable Presentations adapter) can sit beside it without changing this one.

## 3. Receivers, keys and the profile

### 3.1 Identifiers

A receiver is identified by `rcv_` followed by letters, digits, `_` and `-`. A **native** receiver (one outside STACK that implements this protocol) also has a **canonical identifier**: a normalised HTTPS origin, `https://host[:port]`, with no path, query, fragment or credentials, a DNS name and not an IP address, and resolving only to public addresses. A canonical identifier belongs to one receiver. The receiver's owner is the STACK account that registered it.

The other identifiers the protocol carries have these forms: profile versions `apv_…`, bindings `abn_…`, signed claims `pc_…`, Missions `ms_…`, agents `agt_…` or `ag_…`, presentations `prs_…`, presentation tokens `pjt_…`, authority uses `aus_…`, principals `prn_…` and proofs `prf_…`. A receiver treats them as opaque.

### 3.2 Keys

A receiver has up to three kinds of key, each registered by its owner as a **public** JWK (RFC 7517) with a `key_id` of at most 256 characters, a `use`, an algorithm, and a validity window (`valid_from`, optional `valid_until`):

| `use` | Algorithm | JWK | What it does |
|---|---|---|---|
| `request_signing` | `EdDSA` or `ES256` | `OKP`/`Ed25519` or `EC`/`P-256` | Signs the receiver's calls (section 5), its presentation requests (section 6.2) and the origin document (section 3.3). |
| `response_encryption` | `ECDH-ES+A256KW` | `EC`/`P-256` | STACK encrypts presentations to it (section 7). |
| `receipt_signing` | `EdDSA` or `ES256` | `OKP`/`Ed25519` or `EC`/`P-256` | Signs receipts (section 9). |
| `transport_mtls` | one of the three above, matching the key | `OKP`/`Ed25519` or `EC`/`P-256` | Reserved. Registered and recorded, used by nothing in version 1. |

A registered key MUST be a public key: STACK refuses any JWK carrying `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k`, and any key whose type does not match its algorithm. Symmetric keys, `none`, RSA keys and CBC content encryption are not part of version 1. A key is usable at a moment when it is active, its algorithm is the algorithm of the message that names it, `valid_from` has passed and `valid_until` has not. The owner can revoke a key at any time and the revocation holds from the next message. Adding a key is a governance step-up that needs a human approval; a receiver cannot add one for itself. The key a message uses is named by the `kid` in its protected header, which MUST be the `key_id`.

A receiver SHOULD keep an overlap when it rotates: register the new key and let both sign until the owner has activated a profile that lists the new one, then revoke the old.

### 3.3 Origin verification

Before a native receiver can be used, its owner proves that the receiver controls its origin. STACK gives the owner a challenge (`challenge_id`, `challenge`, `audience`, `expires_at`; valid for the time in the constants table below, single use). The receiver serves, at `GET <canonical identifier>/.well-known/stack-receiver.json`, a JSON document of at most 64 KiB with status `200` and no redirect:

```json
{
  "origin": "https://receiver.example.org",
  "key_id": "receiver-request-2026-10",
  "signed_challenge": "<compact JWS>"
}
```

`origin` MUST equal the canonical identifier. `signed_challenge` is a compact JWS made with a registered `request_signing` key, whose `kid` MUST be `key_id` and whose payload is:

| Claim | Value |
|---|---|
| `iss`, `sub` | The receiver identifier `rcv_…`. |
| `aud` | The STACK origin, with no path (the challenge's `audience`). |
| `iat`, `exp` | Integers; `exp` MUST be present and at most the lifetime of the challenge after `iat`. |
| `challenge_id`, `challenge` | The two values STACK gave, unchanged. |

STACK fetches the document from the addresses the host resolves to, refuses a private address, does not follow a redirect, and accepts the receiver once the signature verifies and the challenge is consumed.

### 3.4 The receiver profile

A receiver profile is a versioned, immutable JSON document the owner registers (and activates) for the receiver. A presentation request names the profile version it is made under and it MUST be the receiver's current active version. The members are in [`schemas/NativeReceiverProfileV1.json`](schemas/NativeReceiverProfileV1.json); the ones a receiver depends on are:

| Member | Meaning |
|---|---|
| `receiver_id`, `protocol` | The receiver and `{ "key": "stack.direct_post.jwt", "version": "1" }`. |
| `audience` | The `aud` of every presentation addressed to this receiver (a string the receiver chooses). |
| `request_authentication` | `{ method: "stack.http_request.jwt", signing_key_ids, allowed_algs, maximum_age_seconds }`: which `request_signing` keys and algorithms STACK accepts, and the longest a signed message may live (1 to 120 seconds). |
| `delivery` | `{ endpoint, mode: "stack.direct_post.jwt", encryption_key_ids, allowed_key_management_algs: ["ECDH-ES+A256KW"], allowed_content_encryption_algs: ["A256GCM"] }`. `endpoint` is an `https` URL without credentials or fragment that resolves only to public addresses. |
| `accepted_proofs` | Which kinds of proof, from which issuers, how fresh and in which disclosure modes the receiver accepts. |
| `required_facts` | The facts the receiver may ask for, each with the modes it accepts, its purpose, its lawful basis and a retention rule. |
| `approval_policy` | Who must confirm a disclosure to this receiver before it is made. |
| `receipt` | `{ required, signing_key_ids, allowed_algs }`: the `receipt_signing` keys and algorithms. |
| `live_status_required` | Whether the proofs behind a disclosure must have a fresh live status check. |

A profile carries no executable member (`code`, `command`, `script`, `module` and the like are refused). A change to what a receiver may ask for is a new profile version.

### 3.5 Constants

<!-- spec:generated:authority-receiver-constants -->

| Constant | Value |
|---|---|
| Protocol | `stack.direct_post.jwt`, version `1` |
| Request authentication method | `stack.http_request.jwt` |
| Delivery mode | `stack.direct_post.jwt` |
| Call assertion, longest life | 60 s (1 min) |
| Signed presentation request, agent proof and presentation, longest life | 120 s (2 min) |
| Receipt, longest life | 60 s (1 min) |
| Clock tolerance | 5 s |
| Origin verification challenge valid for | 300 s (5 min) |

<!-- /spec:generated -->

## 4. Encodings

### 4.1 Compact JWS

Every signed message in this protocol is a compact JWS (RFC 7515): three base64url parts, no padding. The protected header MUST carry `alg` (`EdDSA` or `ES256`; STACK's own presentation uses `EdDSA`) and `kid`, SHOULD carry `typ: "JWT"`, and MUST NOT carry `jku`, `x5u`, `jwk` or `crit`. The key is found only by `kid` among the keys registered for the receiver (or, for STACK's messages, among the keys STACK publishes, section 7.2). An `ES256` signature is the 64-byte `R || S` form of RFC 7515 section 3.4. An unsecured message (`alg: "none"`) and any MAC algorithm are never accepted.

### 4.2 Digests

A **digest** on the wire is the text `sha256:` followed by 64 lowercase hexadecimal digits: the SHA-256 of the UTF-8 bytes of a string. Digests are never sent without the prefix, and uppercase hexadecimal is refused.

### 4.3 Canonical JSON

Wherever this document says the digest of a value, the string hashed is its canonical JSON: object members sorted by key (in the order of UTF-16 code units) at every depth, arrays in order, no whitespace, strings and numbers as `JSON.stringify` writes them, `undefined` members omitted. A receiver SHOULD keep numbers in hashed values to integers: the formatting of a fraction is the one of ECMAScript's number-to-string conversion and a hash over one is only reproducible by an implementation that formats it the same way.

Two digests are shared by several messages:

- `request_hash` = digest of the canonical JSON of `{ "receiver_request_id": <string>, "normalized_request": <object> }`;
- `resource_hash` = digest of the canonical JSON of `{ "receiver_request_id": <string>, "resource_ref": <string> }`, or `null` when the transaction names no resource.

`receiver_request_id` is chosen by the receiver for one transaction: 22 to 256 base64url characters, from a source of at least 128 bits of randomness, never reused. `normalized_request` is the receiver's own view of the transaction as a JSON object; the owner's domain profile decides which `action_uri` and `resource_ref` it means, and STACK derives both from it (section 6.4).

### 4.4 Claims every receiver-signed message shares

Every JWS a receiver signs (the call assertion, the presentation request, the receipt, the origin challenge) carries:

| Claim | Rule |
|---|---|
| `iss`, `sub` | Both the receiver identifier `rcv_…`. A canonical origin is not an identifier. |
| `aud` | The exact value the section that defines the message gives. |
| `jti` | A non-empty string, new for every message. A receiver's `jti` values for assertions and presentation requests are remembered for at least 24 hours and a repeat is refused, so the two kinds MUST NOT share a value. |
| `iat`, `exp` | Integers. `iat` is now: not more than 5 seconds ahead and not older than the message's maximum lifetime. `exp` is in the future, after `iat`, and at most the maximum lifetime after it. |

The maximum lifetimes are in the constants table (section 3.5) and a profile can lower the ones that depend on `maximum_age_seconds`. The two clocks are allowed the tolerance in the same table.

## 5. Authenticating a call

Every receiver call to STACK (sections 6, 8, 9 and 10) carries the header

```
Authorization: STACK-Receiver <compact JWS>
```

with exactly one space and no other content. The credential is a one-use assertion bound to the exact HTTP request:

| Claim | Value |
|---|---|
| `iss`, `sub`, `jti`, `iat`, `exp` | As in section 4.4, with a lifetime of at most the assertion maximum and at most the profile's `maximum_age_seconds`. |
| `aud` | The STACK origin followed by the request path, for example `https://api.example.com/v1/authority/status-checks`. |
| `htm` | The HTTP method, upper case. |
| `htu` | The request path exactly as sent, without the query string. |
| `body_hash` | The digest of the canonical JSON of the request body (section 4.3), or the digest of the empty string for a request with no body. |

The header names a `request_signing` key that the receiver's active profile lists in `request_authentication.signing_key_ids` with an algorithm it lists in `allowed_algs`. STACK verifies the signature, the claims and the binding to the request, and records the `jti`; the same `jti` is never accepted twice.

A call whose credential is missing, malformed, unverifiable, expired, replayed or for a receiver, key, profile or algorithm STACK does not accept is answered with the same status and body, so the answer says nothing about which receivers exist: `401` `RECEIVER_AUTH_INVALID`. A failure on STACK's side is `503` `SERVICE_UNAVAILABLE` and is retried with a **new** assertion.

## 6. The presentation request

`POST /v1/authority/presentation-requests` opens one transaction. The body is a JSON object; members not listed here are refused.

| Member | Meaning |
|---|---|
| `signed_request` | A compact JWS made by the receiver (section 6.2). |
| `agent_proof` | A compact JWS made by the agent (section 6.3), passed along unchanged. |
| `passport` | The agent's Passport as the agent gave it, a string of at most 1,000,000 characters. STACK verifies it; the receiver does not need to. |
| `authority_ref` | The authority reference from the Passport's `stk.authority_refs`: `{ binding_id, binding_version, binding_claim_id, binding_digest, receiver_id, receiver_profile_version_id, expires_at }`, unchanged. |
| `receiver_profile_version_id` | The profile version this request is made under. It MUST equal `authority_ref.receiver_profile_version_id`. |
| `receiver_request_id` | The transaction identifier (section 4.3). |
| `mission_id` | The Mission the agent acts under, or `null`. |
| `action_uri` | The action, a machine-readable identifier of up to 1,024 characters (`[A-Za-z][A-Za-z0-9._:/-]*`) with no run of six or more digits. |
| `resource_hash` | `resource_hash` of section 4.3, or `null`. |
| `request_hash` | `request_hash` of section 4.3. |
| `normalized_request` | The transaction as a JSON object. It is write-only: STACK uses it to recompute the hashes and to apply the owner's constraints and never returns it. |
| `requested_facts` | The facts asked for: 1 to 256 objects `{ "fact_id": <string>, "mode": <mode> }`. |
| `nonce` | 22 to 256 base64url characters from a source of at least 128 bits, new for the transaction. It returns in the presentation (section 7.2). |
| `issued_at`, `expires_at` | Integers; `expires_at` is after `issued_at` and at most 120 seconds after it. |

The disclosure modes are `predicate` (a yes or no derived from a fact), `pairwise` (an identifier that is the same for this receiver and unlinkable across receivers), `exact_private` (the value itself), `issuer_evidence` (the issuer's own evidence, which the receiver can check against the issuer) and `status_only` (whether a proof is valid). The schema is [`schemas/AuthorityPresentationRequestInput.json`](schemas/AuthorityPresentationRequestInput.json).

### 6.1 Order of work for a receiver

The agent comes with its Passport and its authority reference. The receiver chooses `receiver_request_id` and `nonce`, builds `normalized_request` and the hashes, and gives the agent what the agent must sign. The agent returns `agent_proof`. The receiver signs `signed_request` and posts, with its call assertion over the final body.

### 6.2 The signed request

`signed_request` is signed with a `request_signing` key and has the claims of section 4.4 with:

| Claim | Value |
|---|---|
| `aud` | The STACK origin followed by `/v1/authority/presentation-requests`. |
| `iat`, `exp` | `iat` equals the body's `issued_at` and `exp` its `expires_at`. The lifetime is at most the profile's `maximum_age_seconds` (and at most 120 seconds). |
| `jti` | New, and different from the `jti` of the call assertion that carries it. |

and, repeated exactly from the body (equal as canonical JSON): `authority_ref`, `receiver_profile_version_id`, `receiver_request_id`, `mission_id`, `action_uri`, `resource_hash`, `request_hash`, `requested_facts`, `nonce`, `issued_at`, `expires_at` and `normalized_request`; plus `passport_hash`, the digest of the `passport` string as sent, and `agent_proof_hash`, the digest of the `agent_proof` string as sent. A body member that differs from the signed one makes the request fail: the receiver is held to what it signed, and STACK to what it was asked.

### 6.3 The agent proof

`agent_proof` is made by the agent with the key its binding pins and proves that the agent itself means this transaction. It is `EdDSA`; its `kid` is the agent key's thumbprint, which is `sha256:` and the lowercase hexadecimal SHA-256 of the JSON text `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` for the key's public part; `iss` and `sub` are the agent's identifier; `aud` is the receiver identifier `rcv_…`; `jti` is new; `iat` equals `issued_at` and `exp` equals `expires_at`; and it repeats `receiver_request_id`, `authority_ref`, `passport_hash`, `mission_id`, `action_uri`, `resource_hash`, `request_hash` and `nonce`. The receiver cannot verify it (it does not hold the key) and MUST NOT alter it.

### 6.4 What STACK checks

STACK refuses the request, with `403` `FORBIDDEN` unless the table says otherwise and without delivering anything, unless every one of these holds. The list is the contract a receiver can rely on; an implementation detail not listed is not part of it.

- The receiver is active and the profile version is its current active one; `signed_request` is made by a key and algorithm the profile lists, verifies, has `aud` equal to the presentation-requests path, a lifetime within the limits, repeats the body exactly, and its `jti` has not been seen (a repeat is `409` `CONFLICT`).
- The binding named by `authority_ref` exists for this receiver, is active, inside its validity window, with every required proof current and its Mission live; the reference equals the binding's own; the Passport verifies and carries exactly that reference (and the Mission when `mission_id` is set); the agent's key is the current one and the one the binding pins; `agent_proof` verifies against it, repeats the transaction exactly, has not been seen before (a replay is `409` `CONFLICT`), and has the lifetime of the request.
- `request_hash` is the digest of section 4.3 over the body's own `receiver_request_id` and `normalized_request`; `action_uri` and `resource_hash` are what the owner's domain profile derives from `normalized_request`; the owner's scope for that action and resource, with its constraints, permits the transaction.
- The facts requested are **exactly** the facts of the profile's `required_facts`, none more and none less, each once, each in a mode the profile accepts and in the mode the owner's binding allows for it; and every disclosure the binding requires is among them.
- Any confirmation the owner's approval policy requires has been given for this exact request (`403`, "principal confirmation is required before disclosure"); the proofs behind the facts have a fresh live status when the profile or the binding requires one (`503` `SERVICE_UNAVAILABLE`); exactly one accepted proof supplies each fact.
- One transaction is one presentation: a second request for a `receiver_request_id` that already has one is refused, whatever its body.

### 6.5 Response

`202` with the presentation as STACK has recorded it, after STACK has delivered it (section 7):

```json
{
  "presentation": {
    "id": "prs_...",
    "authority_use_id": "aus_...",
    "status": "delivered",
    "disclosure_manifest": [{ "fact_id": "person.over_18", "mode": "predicate" }],
    "proof_refs": [{ "proof_id": "prf_...", "proof_version": 1 }],
    "expires_at": "2026-10-24T09:31:00.000Z"
  }
}
```

The response never holds a disclosed value. `presentation.id` is what the receiver uses in sections 9 and 10. If the receiver's delivery endpoint did not answer `2xx`, or STACK could not deliver, the answer is `503` `SERVICE_UNAVAILABLE`, the presentation is recorded as `delivery_failed` and the transaction is over: the receiver starts a new one with a new `receiver_request_id`. Two requests for the same transaction at the same moment produce one presentation; the other is refused.

## 7. Delivery of the presentation

### 7.1 The request to the receiver

STACK POSTs to the profile's `delivery.endpoint`:

```
POST <delivery.endpoint>
accept: application/json
content-type: application/x-www-form-urlencoded
idempotency-key: <presentation id, prs_...>

response=<compact JWE>
```

The body is an `application/x-www-form-urlencoded` form with the one field `response`; a compact JWE contains only base64url characters and full stops, so form encoding does not change it. The endpoint answers `2xx` once it has durably accepted the presentation and any other status for a presentation it refuses; STACK does not retry, does not follow a redirect, connects only to an address it resolved and checked at that moment, waits at most 10 seconds and reads at most 64 KiB of the answer, which it does not act on. The `idempotency-key` is the presentation id: a repeat of it is the same presentation.

The compact JWE (RFC 7516) has the protected header

```json
{ "alg": "ECDH-ES+A256KW", "enc": "A256GCM", "cty": "JWT", "kid": "<response_encryption key_id>", "epk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }
```

(RFC 7518 sections 4.6 and 5.3, with empty `apu` and `apv`) and its plaintext is one compact JWS, signed by STACK with `EdDSA`, whose payload is the presentation (section 7.3). The agent and every other receiver cannot decrypt it.

### 7.2 What a receiver must check

A receiver MUST, before it relies on a presentation:

1. Accept only `alg` `ECDH-ES+A256KW` and `enc` `A256GCM`, with a `kid` of one of its own `response_encryption` keys, and refuse a message whose authenticated header or ciphertext was changed (the AES-GCM tag covers the protected header).
2. Verify the inner JWS with a key STACK publishes, found by `kid`, with `alg` `EdDSA` only. STACK publishes its signing keys as a JWKS at `GET /v1/.well-known/jwks.json` of the STACK origin (the document of the [Passport specification](../passport/SPEC.md), section 9.1); a receiver SHOULD cache it and MUST re-fetch it once, rate-limited, on an unknown `kid`. A key that is not in it, a signature that does not verify and a MAC-signed or unsecured message are refused.
3. Check `iss` against the issuer STACK gave it at registration, `aud` against the profile's `audience`, `receiver_id` and `receiver_profile_version_id` against its own, `iat` (not in the future by more than the tolerance), `exp` (in the future), and that `exp - iat` is at most 120 seconds.
4. Check `nonce` against the nonce it sent for this transaction, and `request_hash` (and `resource_hash`, `action_uri`) against the transaction it opened, never against the presentation's own claims alone.
5. Take a presentation in once: it MUST treat the nonce of a transaction as spent when a presentation for it has been accepted, and SHOULD refuse a `jti` it has already seen, remembering each until the presentation's `exp` has passed (and, better, for longer).

A receiver that refuses a presentation answers non-`2xx` and SHOULD NOT send a receipt for it. A receiver MUST NOT log the decrypted payload where a person's facts would be readable by anyone who does not need them.

### 7.3 The presentation

The payload of the inner JWS has exactly these members; the schema is [`schemas/AuthorityReceiverPresentationPayload.json`](schemas/AuthorityReceiverPresentationPayload.json).

| Member | Meaning |
|---|---|
| `iss`, `aud`, `jti`, `iat`, `exp` | The issuing deployment's origin; the profile's `audience`; a `pjt_…` identifier, new for each presentation; the times, with `exp - iat` at most 120 seconds and `exp` at most the end of the binding. |
| `authority_use_id`, `agent_id`, `agent_key_thumbprint` | The record of this use, the agent and its pinned key. |
| `binding_ref`, `principal_ref` | The authority reference of the request and the opaque reference of the owner's principal. |
| `mission_id`, `action_uri`, `resource_hash`, `request_hash`, `nonce` | The transaction, repeated from the request. |
| `receiver_id`, `receiver_profile_version_id`, `domain_profile_version_id`, `proof_profile_version_ids` | The profiles the presentation was made under. |
| `live_check_time` | When STACK checked live status. |
| `evidence_refs` | One entry for each required proof: `{ proof_id, proof_version, role, authoriser_principal_id, group_key_hash, profile_version_id, issuer_identifier, schema_uri, schema_version, assurance_uri, evidence_digest, evidence_modes, status }`: provenance without content. |
| `approval_claim_refs`, `approval_requirements` | The signed approvals and the approval requirements behind the disclosure, with their statuses. |
| `proof_strength` | `native_issuer_evidence` when every disclosed fact is issuer evidence the receiver can check itself, `native_stack_attestation` when STACK attests it checked the evidence, `proxy_stack_enforced` for a transaction STACK enforced itself (never in a native presentation). |
| `disclosed_facts` | The facts, one per requested fact. |

A disclosed fact has `fact_id`, `mode`, `proof_id`, `assertion_source` (`issuer_native`, `adapter_derived` or `stack_derived`), `proof_strength`, `provenance` and a value that depends on the mode:

| `mode` | `assertion_source`, `proof_strength` | Value |
|---|---|---|
| `exact_private` | `stack_derived`, `native_stack_attestation` | `value`: any JSON. |
| `status_only` | `stack_derived`, `native_stack_attestation` | `status`: `pending`, `active`, `suspended`, `revoked`, `replaced`, `erased`, `valid` or `unknown`. |
| `predicate` | `adapter_derived`, `native_stack_attestation` | `value`: a boolean, and `evidence_digest`. |
| `pairwise` | `stack_derived`, `native_stack_attestation` | `value`: `hmac-sha256:` and 43 base64url characters, unlinkable across receivers; and `evidence_digest`. |
| `issuer_evidence` | `issuer_native`, `native_issuer_evidence` | `value`: the issuer's own evidence, and `evidence_digest`. |

STACK stores no presentation payload in readable form: only its digest, which is the digest of the canonical JSON of the payload (section 4.3) and which the receipt echoes.

## 8. Status checks

`POST /v1/authority/status-checks` asks whether a binding is still in force for one exact transaction, without a presentation and without any disclosure. Use it just before acting on a presentation a moment old, or for a transaction that needs no facts. The body is a JSON object:

| Member | Meaning |
|---|---|
| `binding_id`, `binding_claim_id` | The binding and its signed claim, from the authority reference. |
| `agent_id`, `agent_key_thumbprint` | The agent and its key, as in section 6.3. |
| `mission_id` | The one Mission this transaction uses; required when the binding names Missions. |
| `action_uri`, `receiver_request_id`, `resource_ref` | The transaction. `resource_ref` is the resource itself (not its digest) and is omitted when there is none. |
| `request_hash` | `request_hash` of section 4.3 over `receiver_request_id` and `normalized_request`: the same value a presentation request for this transaction carries. |
| `normalized_request` | The transaction, as in section 6. Write-only. |

The answer is `200`:

```json
{ "status": { "active": true, "binding_ref": { "binding_id": "abn_...", "binding_version": 1, "binding_claim_id": "pc_...", "binding_digest": "sha256:...", "receiver_id": "rcv_...", "receiver_profile_version_id": "apv_...", "expires_at": 1790003600 }, "checked_at": "2026-10-24T09:30:00.000Z" } }
```

`active` is always `true` in a `200`: an answer that is anything other than "in force" is an error. The answer is `403` `FORBIDDEN` when the binding does not belong to this receiver, is not usable now (revoked, suspended, outside its window, a proof or principal or agent key no longer current, its Mission no longer live), does not match the agent, its key or the Mission, does not match `request_hash`, derives a different action or resource from the transaction, or does not permit the action and resource with the constraints it carries. A receiver treats any answer but `200` as a reason not to proceed, and never reads the reason as more than a hint. A status check is schema [`schemas/AuthorityStatusCheckInput.json`](schemas/AuthorityStatusCheckInput.json).

## 9. Receipts

`POST /v1/authority/presentations/{presentation_id}/receipts` closes a transaction. The body is `{ "native_format": "application/jwt", "signed_receipt": "<compact JWS>" }`; `native_format` names the receipt format and is recorded as sent. A receipt is accepted once, for a presentation that was delivered and has not been closed.

`signed_receipt` is signed with a `receipt_signing` key and algorithm the profile's `receipt` member lists, and has the claims of section 4.4 with `aud` equal to the STACK origin followed by `/v1/authority/presentations/{presentation_id}/receipts`, a lifetime of at most the receipt maximum (the profile cannot raise it), and:

| Claim | Value |
|---|---|
| `receiver_id`, `presentation_id`, `authority_use_id` | The receiver, the presentation and its use, from the presentation. |
| `presentation_payload_hash` | The digest of the canonical JSON of the presentation payload the receiver opened (section 7.3). |
| `request_hash`, `action_uri` | From the presentation. |
| `outcome` | `accepted`, `rejected` or `failed`. |
| `result`, `result_commitment_nonce`, `result_hash` | The result of the transaction as the receiver records it (any JSON value, including `null`, `result` present); a nonce of at least 22 base64url characters, new for every receipt; and the digest of the canonical JSON of `{ "value": <result>, "commitment_nonce": <nonce> }`. |
| `external_transaction_ref` | Optional. The receiver's own reference. STACK keeps only a digest of it bound to the receipt. |

A receipt that does not bind the presentation, the use, the request and the action, whose `outcome` is not one of the three, or whose result does not hash to `result_hash`, is refused with `403` `FORBIDDEN`. The `result` is a commitment: STACK records `result_hash` and the signed receipt (encrypted at rest) and never returns the result in an answer, so the receiver reveals it only if it chooses to. An `accepted` outcome completes the use as succeeded; `rejected` and `failed` complete it as failed. STACK signs a claim for the receipt and for the completed use into the owner's [record](../record/SPEC.md).

The answer is `200`:

```json
{ "receipt": { "id": "rtr_...", "authority_use_id": "aus_...", "presentation_id": "prs_...", "receiver_id": "rcv_...", "outcome": "accepted", "receipt_hash": "sha256:...", "request_hash": "sha256:...", "result_hash": "sha256:...", "verified_at": "2026-10-24T09:30:05.000Z", "received_at": "2026-10-24T09:30:05.000Z" } }
```

A second receipt for a presentation, a receipt for a presentation that was not delivered to this receiver, and two receipts at the same moment are refused (`403` or `409`), and exactly one of two simultaneous receipts is accepted.

## 10. Reading a presentation request

`GET /v1/authority/presentation-requests/{presentation_id}` returns `{ "presentation": { … } }` in the shape of section 6.5 with the presentation's current `status`: `pending`, `prepared`, `delivered`, `delivery_failed`, `accepted`, `rejected`, `expired` or `erased`. A presentation of another receiver is `404`. The call has no body, so its `body_hash` is the digest of the empty string (section 5). It never returns what was disclosed.

## 11. Proof provider callbacks

A proof provider (an issuer of identity, capacity or mandate evidence) can take a person through its own ceremony and report the result to STACK. The owner starts a **collection session** with the provider's adapter (`POST /v1/authority/proof-collection-sessions`, an operator call, not part of the receiver protocol); the session carries an opaque `state_token`, valid for 15 minutes, which STACK gives the provider to carry through the ceremony. The provider reports with:

`POST /v1/authority/proof-callbacks/{adapter_key}`, body `{ "session_id": "pcs_…", "state_token": <base64url, 22 to 512 characters>, "signed_callback": <string, at most 1,000,000 characters> }` (no other member; [`schemas/AuthorityProofCallbackInput.json`](schemas/AuthorityProofCallbackInput.json)).

This route takes no operator or agent credential. It is authenticated by the **adapter** the session was started with, which STACK has pinned for the provider: before anything in the body is trusted, the adapter is given the method, the request path, the request headers (names in lower case) and the digest of the canonical JSON of the body (section 4.3), and returns the callback's `jti`, the provider's issuer identifier and an expiry. The credential an adapter expects (a header, a signature, a signed callback) is the adapter's own contract with its provider and is published with the adapter. What is fixed here is the rest:

- `signed_callback` is verified by the adapter and is evidence, never an instruction: STACK takes the proof's facts, issuer and times from it and from nothing else in the request.
- The session, the adapter, the issuer and the `state_token` must all be the ones the session was started with, and the session must be inside its lifetime.
- A callback is single use per `jti`. The same callback again (same `signed_callback`, same `jti`) returns the stored result; a different callback for a session that has one is `409` `CONFLICT`.
- A callback that cannot be authenticated, for any reason, is `401` `PROOF_CALLBACK_AUTH_INVALID` with one fixed message; a failure on STACK's side or the provider's is `503` `SERVICE_UNAVAILABLE`; a session that is unknown, expired or not bound to the callback is `403` `FORBIDDEN`.
- The answer is `200` `{ "proof": { … } }`, the safe view of the new proof: its identifier and version, kind, issuer, schema, status and times, and digests of its evidence and facts; never the evidence or the facts.

In version 1 STACK's own deployment registers no adapter that takes a callback: every callback is answered `401` and a collection session cannot be started. The route and the envelope are defined so that a deployment that registers one has one wire contract.

## 12. Enterprise OIDC approvals

A company can let a person approve an agent's authority by signing in with the company's own OpenID Connect provider. Two outside parties take part: the person (in a browser) and the provider.

### 12.1 The request

An owner or admin (never an agent) asks for an approval with `POST /v1/authority/enterprise-oidc/requests`, carrying an `Idempotency-Key` header and a JSON body ([`schemas/CreateEnterpriseOidcAuthoritySetupInput.json`](schemas/CreateEnterpriseOidcAuthoritySetupInput.json)): the organisation, the role the approver must hold (`role_name`, the claim path `role_claim_path` and the value `role_claim_value`), the agent, optionally a Mission, the connected service and provider, the purpose in plain words, one HTTP method and one resource path, up to 16 constraints, and `expires_at`, which MUST be within 60 minutes. The answer is `201` for a new request and `200` for a repeat of the same key and body (a different body under the same key is `409`):

```json
{ "request_id": "aor_<32 hex>", "status": "pending", "approval_url": "https://…", "created_at": "…", "expires_at": "…" }
```

`GET /v1/authority/enterprise-oidc/requests/{request_id}` returns the same object, with `status` `pending`, `rejected`, `expired` or `completed`, and after completion a `result` with `binding_id`, `binding_version`, `binding_status`, `organisation_principal_id`, `approver_principal_id`, `receiver_id`, `identity_proof_id`, `capacity_proof_id`, `approval_request_id` and `expires_at`. It never carries a token or evidence from the provider. A request lives at most 15 minutes before it is approved and for 24 hours after it is decided.

The request grants nothing. The approver opens `approval_url` in a signed-in browser, reads exactly what the agent will be allowed to do, and approves or declines. The approval is the person's own act in their own browser session; no token, API key or agent can make it.

### 12.2 What STACK needs from the OpenID Connect provider

The provider is an ordinary OpenID Connect provider (OpenID Connect Core 1.0 and Discovery 1.0) that the company has registered with STACK as a client. STACK is the relying party and acts as follows, so the provider MUST support:

- **Discovery** at the configured issuer (without a trailing slash) followed by `/.well-known/openid-configuration`, over HTTPS, answering `authorization_endpoint`, `token_endpoint` and `jwks_uri`, with no redirect on any endpoint STACK calls (a redirect is a failure). STACK keeps the document for 24 hours. Every address STACK calls MUST be https and resolve only to public addresses.
- **The authorization code flow with PKCE** (`code_challenge_method=S256`, mandatory), with `response_type=code`, `scope` as configured (by default `openid email profile`), a `state` and a `nonce` of 256 bits each, and the registered `redirect_uri`, which is `GET /v1/identity/oidc/callback` of the STACK API.
- **Client authentication at the token endpoint** by `client_id` and `client_secret` in the form body (`client_secret_post`), with `grant_type=authorization_code`, `code`, `redirect_uri` and `code_verifier`.
- **An ID token** in the token response (`id_token`), signed with a key in the provider's JWKS: a header `kid` that is in the set, an `alg` the key allows, `iss` equal to the configured issuer exactly, `aud` containing the configured audience (by default the client id), `exp` present and in the future, `exp` and `nbf` honoured with 30 seconds of tolerance, and `nonce` equal to the one STACK sent. A key rotation is picked up by one re-fetch of the JWKS on an unknown `kid`, rate-limited to one a minute.
- **The role in the ID token.** The role the approver must hold is read from the ID token itself (not from the UserInfo endpoint) at the claim path of the request: a dot-separated path of object members (`roles`, `realm_access.roles`), each member name a letter or `_` followed by letters, digits, `_` or `-`, with no `__proto__`, `prototype` or `constructor`; the value at the path is a string or an array of strings and one of them MUST equal the request's `role_claim_value` exactly.

STACK does not store the provider's access or refresh tokens and requests no `offline_access`. It keeps the ID token, encrypted, only for the length of the approval and discards it once the approval is recorded.

## 13. Errors

Every error is `{ "error": { "code": <string>, "message": <string>, "details": <object|null> } }` with the status below. A receiver MUST key on `code` and status, never on `message`, which is for people and can change.

| Status | `code` | When |
|---|---|---|
| `400` | `VALIDATION_ERROR` | The body does not have the shape of its schema (a missing, extra or malformed member). |
| `401` | `RECEIVER_AUTH_INVALID` | Any failure to authenticate a receiver call (section 5), including a replay. |
| `401` | `PROOF_CALLBACK_AUTH_INVALID` | Any failure to authenticate a proof provider callback (section 11). |
| `403` | `FORBIDDEN` | STACK understood the call and will not do it: a check of section 6.4, 8 or 9 failed. The message is a hint and is not part of the contract. |
| `404` | `NOT_FOUND` | A presentation that is not this receiver's. |
| `409` | `CONFLICT` | A replayed signed request, a second callback with different evidence, a lost race. |
| `503` | `SERVICE_UNAVAILABLE` | STACK, the delivery endpoint or a dependency could not be reached or could not finish. `details.retry_after_seconds` says when to try again. A retry needs a new assertion, and a new transaction after a failed delivery. |

## 14. Security considerations

**The agent is not trusted with the facts.** A presentation is encrypted to a key only the receiver holds, delivered by STACK directly, and answered to the agent with an acknowledgement and no content. An agent cannot read, alter or withhold it for itself; a different receiver cannot read one meant for another.

**The receiver is bound to one transaction and one lifetime.** A call assertion is bound to the method, the path, the canonical body and a one-use identifier, and lives at most a minute; a presentation request, an agent proof and a presentation each live at most two minutes and bind the same hashes and nonce. A captured message is useless after its lifetime and cannot be replayed within it.

**The receiver cannot ask for more.** STACK intersects the receiver's profile, the owner's binding and the request: a fact outside the profile, a mode the owner did not allow, a missing required fact or a different resource is a refusal and not a smaller answer.

**Authentication failures reveal nothing.** Every receiver authentication failure is one status and one message, so a caller cannot learn which receivers, keys or profiles exist, or whether a replay was the reason.

**Algorithms are pinned.** Version 1 accepts `EdDSA` and `ES256` for receiver signatures, `ECDH-ES+A256KW` and `A256GCM` for delivery, and `EdDSA` for STACK's presentation. A key is found only by `kid` among registered keys: a message that names its own key location (`jku`, `x5u`, `jwk`) is refused. Receiver implementations MUST apply the same discipline to what they verify; the suite includes the classic attacks (an unsecured token, a MAC made with a public key, a swapped key under the right `kid`).

**Clocks.** The protocol tolerates five seconds of clock difference. A receiver whose clock is wrong refuses good presentations or signs messages STACK refuses; it SHOULD synchronise to a trusted time source.

**Destinations.** A delivery endpoint and an origin document are fetched only over HTTPS, only from addresses checked to be public at the moment of the call, without redirects, with the connection pinned to the checked address, and with a size and time bound. A receiver that moves its endpoint registers a new profile version.

**Results are commitments.** A receipt reveals neither the result nor a reference to it; it binds a salted hash, so the receiver chooses whether to disclose the result and a guessable result cannot be tested against the hash.

**Logging.** A receiver MUST NOT put a decrypted presentation, a Passport or an agent proof in a log, a URL, an error message or a third-party service. STACK does the same: its responses are filtered so that no ciphertext, plaintext or evidence field can leave in them.

**Key compromise.** An owner who suspects a receiver key revokes it; the revocation holds from the next message. A receiver that suspects its decryption key asks its owner to revoke it and to register another; a presentation delivered before the revocation stays readable to whoever holds the key.

## 15. Conformance

The `authority` suite of the [conformance kit](../conformance/README.md) plays STACK against a receiver. It reads what the receiver produces (call assertions, signed requests, receipts, the origin document) the way section 5, 6 and 9 say STACK does, and hands the receiver presentations (one right, seventeen each wrong in one way) and requires it to accept the first and refuse the others. A MUST that fails is a defect; a SHOULD that fails is a warning. The reference receiver in [`../conformance/reference/authority-receiver.mjs`](../conformance/reference/authority-receiver.mjs) passes it, and STACK's own protocol implementation is tested against the reference receiver in both directions.

### 15.1 The receiver functions

A receiver is tested through five functions, given a configuration: the receiver's identifier, the STACK origin, the issuer and audience of presentations, the receiver's own keys (as private JWKs) and the STACK keys it trusts (as public JWKs).

| Function | Returns |
|---|---|
| `authorization({ method, path, body, now })` | The value of the `Authorization` header for one call (section 5). `path` may carry a query. |
| `signPresentationRequest(fields, { now })` | The `signed_request` for the given request fields (section 6.2). |
| `signReceipt({ presentationId, presentation, outcome, result, externalTransactionRef, now })` | The `signed_receipt` (section 9) for a presentation payload. |
| `openPresentation(compactJwe, { now, expected: { nonce, requestHash } })` | The verified payload, or a refusal (a thrown error), per section 7.2. |
| `verificationDocument({ challengeId, challenge, now })` | The origin document of section 3.3. |

A receiver in another language is run as a program that reads `{ op, config, input }` as JSON on stdin and writes `{ "result": … }` or `{ "error": … }` on stdout.

### 15.2 The delivery endpoint

A deployed delivery endpoint is tested by giving the suite its URL and the public JWK of its `response_encryption` key. The test instance MUST be configured to trust the STACK test key published in `fixtures/authority/stack-jwks.json` as STACK's presentation key, `https://stack-conformance.test` as the issuer, `urn:conformance:receiver` as its audience, `rcv_conformance` as its identifier, and to expect the nonce and request hash of `fixtures/authority/vectors.json`. It answers `2xx` to the one correct presentation and a non-`2xx` status to every other.

## 16. Machine-readable schemas

JSON Schemas (draft-07) generated from the reference implementation are in [`schemas/`](schemas/): `AuthorityPresentationRequestInput`, `AuthorityStatusCheckInput`, `ReceiverReceiptInput`, `AuthorityPresentationView`, `AuthorityReceiverPresentationPayload`, `AuthorityReference`, `NativeReceiverProfileV1`, `AuthorityProofCallbackInput` and `CreateEnterpriseOidcAuthoritySetupInput`. Test vectors for every signed and encrypted message are in [`../conformance/fixtures/authority/vectors.json`](../conformance/fixtures/authority/vectors.json), built by [`../conformance/scripts/build-authority-vectors.mjs`](../conformance/scripts/build-authority-vectors.mjs).
