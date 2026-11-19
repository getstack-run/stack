# STACK Network

**Specification:** STACK Network
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

The STACK network is the set of services that a self-hosted install, or a company that deals with one, calls on STACK's hosted API: an install proves who it is with a key of its own, has STACK countersign the passports it issues so that another company can trust them, publishes revocations that other companies can read, fetches signed detection rules and asks a classifier for a verdict; a counterparty checks what STACK has signed, offline or online, and is told when something is revoked. This document defines every signed object, every call and every check of those services exactly enough to implement either side of them.

Contents: 1 Conventions, 2 Model, 3 Common encodings, 4 Signed objects, 5 Installs and keys, 6 The install proof, 7 Countersigning, 8 Checking a countersigned passport, 9 The STACK-verified statement, 10 Revocation, 11 Revocation subscriptions, 12 Detection rules and the classifier, 13 Licence keys and their revocation, 14 Test vectors, 15 Errors, 16 Security considerations, 17 Machine-readable schemas, 18 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

Four roles are used. The **service** is a STACK network (STACK's hosted API is the one in production; section 18 tests any other). An **install** is a self-hosted STACK that calls the service. A **counterparty** is any party that checks an object the service signed and needs no account to do so. The **owner** is the account that registered an install. A conforming **verifier** satisfies every MUST of sections 4, 8, 9, 10 and 12 that is addressed to a verifier; a conforming **install client** satisfies every MUST of sections 5, 6 and 12 addressed to an install; a conforming **service** satisfies every MUST addressed to the service.

All times inside tokens are seconds since the Unix epoch. Timestamps inside bodies and claims objects are ISO 8601 UTC with milliseconds (`2026-10-24T09:30:00.000Z`). All JSON is UTF-8. Identifiers are opaque strings; the prefixes shown (`ins_`, `ink_`, `csg_`, `rev_`, `nsub_`, `op_`) are conventions of the reference implementation and a party MUST NOT depend on them except where a pattern is stated in a schema.

Endpoints are relative to the service's base address and use HTTPS. Errors use the envelope `{ "error": { "code", "message", "details" } }` (section 15).

## 2. Model

- An **install** is a self-hosted STACK that an owner registered with the service. It holds an Ed25519 key pair; the service holds the public half. An owner may have several installs.
- An **install key** is that public key. Its id, the `kid`, is its RFC 7638 thumbprint (section 3).
- A **passport** here is whatever EdDSA-signed JWS the install issued for one of its agents. The service never sees it: it sees only the passport's digest and, optionally, its `jti` and the agent's name (section 7).
- A **countersignature** is the service's signature over that digest, saying that this owner's install, holding a key it proved it holds, issued this passport.
- A **revocation** says that a passport, an agent, a key or an install is no longer to be trusted. The service keeps them in one ordered, public, signed list.
- The **STACK-verified statement** is a five-minute signed snapshot saying whether a countersigned passport or agent is live.
- **Detection rules** are regular-expression rule sets the service signs and installs fetch; the **classifier** is a hosted call that returns a verdict for a piece of content.
- A **licence key** is a signed bearer credential STACK issues to an account; the network accepts it for the two calls an install makes with nothing of its own to register, and the account can revoke it before it expires.

What a counterparty can establish from the tokens alone, offline, is that STACK saw this install's key proved by its holder, the owner who registered it, and this passport digest, when the countersignature was issued. It cannot learn from the tokens that anything was revoked afterwards. That is what the short life of a countersignature, the online check (section 8.2), the statement (section 9) and the revocation list (section 10) are for.

## 3. Common encodings

**Compact JWS.** Every signed object is a JWS in compact serialisation (RFC 7515): three base64url parts (RFC 4648 section 5, no padding) joined with a full stop, signed with EdDSA over Ed25519 (RFC 8037). The protected header always has `alg` set to `EdDSA` and a `typ` that names the kind of object. A party MUST reject `alg` `none` and every other value, and MUST NOT accept a symmetric algorithm for a key it holds as a public key. Unknown claims MUST be ignored by a verifier of an object STACK signs (they are added in minor versions); a service MUST refuse unknown claims in the objects an install signs (sections 5.3 and 6.2).

**Install key.** An Ed25519 public key as a JWK with exactly these members and no others: `{ "kty": "OKP", "crv": "Ed25519", "x": "<43 characters of base64url>" }`.

**Key thumbprint (`kid`).** The base64url (no padding) SHA-256 of the UTF-8 string `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` with `<x>` replaced by the key's `x`: members in that order, no whitespace. It is always 43 characters and is unique across every install of the service.

**Passport digest.** The base64url (no padding) SHA-256 of the UTF-8 bytes of the passport's compact serialisation exactly as the install issued it (43 characters). A passport that is parsed and re-serialised has a different digest.

**STACK's keys.** The service signs the objects of section 4 with its deployment signing key, the same key that signs the passports of STACK's hosted service. Nothing but `typ` and `aud` separates a passport from these objects (section 4.2). The service publishes the current key, then the retired keys it still stands behind, as a JWKS (RFC 7517) at:

```
GET /v1/network/jwks.json
```

```json
{ "keys": [ { "kty": "OKP", "crv": "Ed25519", "x": "...", "kid": "stack-passport-v1", "alg": "EdDSA", "use": "sig" } ] }
```

The answer may be cached for five minutes (`cache-control: public, max-age=300`). A signed object names its key in the protected header `kid`; a verifier selects the key with that `kid` and MUST refuse an object whose `kid` matches no key or more than one key. An object signed by a retired key keeps verifying for as long as that key is listed. A key not listed is not trusted.

## 4. Signed objects

### 4.1 The kinds

<!-- spec:generated:network-kinds -->

| Object | `typ` (header) | `aud` (claim) | Signed by |
|---|---|---|---|
| Countersignature | `stack-countersignature+jwt` | `stack:countersignature` | STACK |
| Revocation list | `stack-revocation-list+jwt` | `stack:revocation-list` | STACK |
| STACK-verified statement | `stack-verified+jwt` | `stack:verified` | STACK |
| Detection rule set | `stack-detection-rules+jwt` | `stack:detection-rules` | STACK |
| Install proof (a request) | `stack-install+jwt` | `stack:network` | the install's key |
| Key proof of possession | `stack-install-pop+jwt` | `stack:network` | the key being registered |

<!-- /spec:generated -->

The first four are signed by STACK; the last two are signed by an install key (sections 5 and 6). Every claim set below also carries the registered claims stated for its kind.

### 4.2 Verifying an object STACK signed

A verifier of a countersignature, a revocation list, a verified statement or a detection rule set MUST, before it reads any claim:

1. Check that the compact form has exactly three parts and that the header names `alg` `EdDSA`, the `typ` of the kind it expects and a `kid`.
2. Select the one key of the JWKS with that `kid` (section 3) and check the signature.
3. Check `iss` is `getstack.run` and `aud` is the audience of the kind it expects. A verifier of one kind MUST reject a token of every other kind: the two checks together are what stop a countersignature being accepted as a statement, or any object being accepted as a passport (audience `stack:passport`, no `typ`) and the reverse.
4. Check `iat` and `exp` against its clock with a tolerance of at most 5 seconds. An expired object MUST be rejected, whatever it says.

Then it reads the claim set of the kind, rejecting a claim set whose version `v` it does not know (every kind below is version 1). A verifier MUST NOT use any claim, including the install key inside a countersignature, before the signature has verified.

### 4.3 Claims common to the objects STACK signs

| Claim | Value |
|---|---|
| `iss` | `getstack.run`. |
| `aud` | The audience of the kind (section 4.1). |
| `iat`, `exp` | Issue and expiry, in seconds. The lifetime of each kind is in the constants table (section 4.4). |
| `sub` | Set for a countersignature (the install id) and for a statement (section 9.2); absent from a revocation list and a rule set. |
| `jti` | Set for a countersignature (`csg_...`); absent from the others. |

### 4.4 Constants

<!-- spec:generated:network-constants -->

| Constant | Value |
|---|---|
| Install proof, longest life (`exp` minus `iat`) | 120 s (2 min) |
| Clock difference accepted on a proof, either way | 60 s (1 min) |
| Key registration challenge lives | 300 s (5 min) |
| Countersignature life, default | 900 s (15 min) |
| Countersignature life, shortest and longest a proof may ask for | 60 s (1 min) and 3600 s (1 h) |
| Countersignature record kept after it expires | 30 days |
| STACK-verified statement life | 300 s (5 min) |
| Revocation list life | 300 s (5 min) |
| Detection rule set life | 259200 s (72 h) |
| Usable keys of one install, most | 3 |
| Key rollover, default and longest | 86400 s (24 h) and 604800 s (168 h) |
| Active installs of one account, most | 250 |
| Subscriptions of one account, most | 100 |
| Revocation list page, default and largest | 200 and 500 entries |
| Revocation push timeout | 5 s |
| Revocation push retry back-off | 1 s doubling to 3600 s |
| A failing subscription pauses after | 259200 s (72 h) |
| A revoked licence key is refused everywhere within | 30 s |
| A revoked licence key is listed after it would have expired for | 90 days |
| Mark | `STACK-verified` |

<!-- /spec:generated -->

## 5. Installs and keys

### 5.1 The owner's calls

These calls are made with the owner's own credential (an API key, a console session or an OAuth sign-in) by an owner or administrator. A credential that belongs to an agent is refused with `403 FORBIDDEN`, so an agent can never register, widen or remove its own way of being vouched for. Another account's install, key or subscription is never visible: its id is a plain `404 NOT_FOUND`.

| Call | What it does |
|---|---|
| `POST /v1/network/installs` with `{ "name" }` (1 to 80 characters) | Registers an install. `201` with the install view. |
| `GET /v1/network/installs`, `GET /v1/network/installs/{id}` | `{ "installs": [view, ...] }`, one view. |
| `POST /v1/network/installs/{id}/key-challenges` | A challenge to answer with the key being registered (section 5.2). `201` with `{ "nonce", "expires_at", "audience": "stack:network", "install" }`. |
| `POST /v1/network/installs/{id}/keys` with `{ "public_jwk", "proof", "rollover_seconds"? }` | Registers a key (section 5.3). `201` with the install view. |
| `POST /v1/network/installs/{id}/keys/{keyId}/revoke` with `{ "reason"? }` | Stops one key at once and publishes it (section 5.5). |
| `POST /v1/network/installs/{id}/revoke` with `{ "reason"? }` | Stops the install and all its keys at once and publishes it. |

The **install view** is `{ "id", "name", "status": "active" | "revoked", "created_at", "revoked_at", "keys": [key view, ...] }`; a **key view** is `{ "id", "kid", "status": "active" | "revoked", "valid_until", "usable", "created_at", "revoked_at", "revoked_reason", "public_jwk" }`. `valid_until` is null for the newest key and is when a rolled-over key stops working; `usable` is true when the key can sign a proof right now. An owner has a bounded number of active installs; when it is full registering another answers `409 NETWORK_LIMIT_REACHED` with `details` `{ "what": "installs", "limit": <n> }`.

### 5.2 The key registration challenge

Registering a key lets an install have STACK countersign passports in the owner's name, so it takes a person. The service MAY require that a person approve the challenge in a browser before it issues it: STACK's hosted service answers `403 GOVERNANCE_APPROVAL_REQUIRED` with `details` `{ "approval_id", "approval_url" }` to a credential that is not a signed-in console session, and the same request, repeated with the header `X-Governance-Approval: <approval_id>` after a person approved it, is answered with the challenge. An install that already has a revoked status gets `409 INSTALL_REVOKED`.

The challenge is a random value of at least 24 random bytes in base64url (the `nonce`, 32 to 64 characters of `[A-Za-z0-9_-]`). It is bound to the owner and the install it was asked for, valid for 300 seconds and can be used once.

### 5.3 The proof of possession

The install generates an Ed25519 key pair, keeps the private half and signs the challenge with it. The **key proof** is a compact JWS:

| Part | Value |
|---|---|
| Header | `{ "alg": "EdDSA", "typ": "stack-install-pop+jwt", "kid": "<thumbprint of the key being registered>" }` |
| `iss` | The thumbprint of the key being registered. |
| `aud` | `stack:network`. |
| `install` | The install id. |
| `nonce` | The challenge's nonce. |
| `iat`, `exp` | At most 300 seconds apart (120 is typical); `iat` no more than 60 seconds ahead of the service's clock; the service accepts the proof until 60 seconds after `exp`. |

No other claim is allowed. The service registers the key only if: the header `kid` and `iss` equal the thumbprint of `public_jwk`; the signature verifies with `public_jwk`; `install` is the install named in the request; and the nonce is a live challenge asked for by this owner for this install. The challenge is consumed only by a proof that verified, so nobody can use up another owner's challenge without the key. Every refusal is the same `400 KEY_CHALLENGE_INVALID`: it never says which check failed. A key already registered, by anyone, is `409 CONFLICT`. An install has at most 3 usable keys at a time; a fourth is `409 NETWORK_LIMIT_REACHED` with `details` `{ "what": "keys", "limit": 3 }`.

### 5.4 Rollover

Registering a new key leaves the install's other usable keys working for `rollover_seconds` (0 to 604800; 86400 when omitted) and then they stop (`valid_until`); a key already due to stop sooner keeps its sooner end. This lets an install move to a new key without a gap: it registers the new key, switches its signing to it and lets the old one lapse. A key past its `valid_until` is refused as `key_expired` (section 6.3).

### 5.5 Revoking a key or an install

Revoking a key or an install takes effect on the next call: its proofs are refused from then on, every countersignature made under it is reported revoked (sections 8.2 and 9.3), and a revocation of kind `key` (or `install`) is published (section 10). Revoking is never metered and is not behind an approval: stopping something must always work. A revoked key or install cannot be revived.

## 6. The install proof

### 6.1 How a call is authenticated

An install holds no account credential. Every call it makes to the network carries one **install proof**, a request the install signed with a registered key, as its bearer value:

```
Authorization: Bearer <install proof>
```

A proof is good for one request. What the request asks for, and its data, are inside the signed claims, so a proof authorises exactly one thing. A leaked install key can therefore make the calls of section 6.4 and nothing else, and revoking the key ends even that.

A proof is told from other bearer values by its header `typ`, which is `stack-install+jwt`. Which calls accept which credentials is in the table of section 6.4.

### 6.2 The proof

| Part | Value |
|---|---|
| Header | `{ "alg": "EdDSA", "typ": "stack-install+jwt", "kid": "<thumbprint of the signing key>" }`, in any member order. |
| `iss`, `sub` | Both the install id. |
| `aud` | `stack:network`. |
| `iat`, `exp` | `exp` no more than 120 seconds after `iat` (60 is typical). |
| `jti` | 16 to 64 characters of `[A-Za-z0-9_-]`, fresh for every proof. |
| `act` | What the proof asks for: one of `rules`, `classify`, `countersign`, `revoke`. |

and the claims of the action:

| `act` | Further claims | Meaning |
|---|---|---|
| `rules` | none | Fetch the signed rule set (section 12.1). |
| `classify` | none | Call the classifier (section 12.2). The content travels in the request body, not in the proof. |
| `countersign` | `pd` (the passport digest, required); `pjti` (the passport's own `jti`, 1 to 128 characters); `agent` (the agent in the install's own namespace, 1 to 128 characters); `ttl` (the countersignature's life in seconds, 60 to 3600) | Countersign one passport digest (section 7). |
| `revoke` | `kind` (`passport`, `agent`, `key` or `install`, required); `subject` (1 to 256 characters, required); `reason` | Publish a revocation (section 10.2). |

A proof that carries a claim not listed for its `act` is malformed and refused.

### 6.3 What the service checks

The service MUST check, in any order, and refuse with `401 INSTALL_PROOF_INVALID` and the reason in `details.reason` (the reason never carries the key or the claims):

| `details.reason` | Refused when |
|---|---|
| `malformed` | The header is not `alg` `EdDSA`, `typ` `stack-install+jwt` and a 43-character `kid`; the claims are not those of section 6.2 for the `act`; `exp` is more than 120 seconds after `iat`; `iat` is more than 60 seconds in the future; or `iss` is not the install the key belongs to. |
| `unknown_key` | No registered key has that `kid`. |
| `bad_signature` | The signature does not verify with the registered key, or `aud` is wrong. |
| `expired` | 60 seconds have passed since `exp`. |
| `wrong_action` | `act` is not the action of the call. A proof for one call is never good for another. |
| `key_revoked` | The key was revoked. |
| `key_expired` | The key's rollover ended. |
| `install_revoked` | The install was revoked. |

Only after the proof verifies does the service count the call against the install's rate (a forged request spends none of an install's allowance): beyond it the answer is `429 RATE_LIMITED` with `details` `{ "retry_after_seconds" }`. The limits are per action and per minute; their values are the service's.

Last, the service records the proof's `jti` for this install and refuses a second proof with the same `jti` with `401 INSTALL_PROOF_REPLAYED`: a proof is good for exactly one request, and every request needs a new `jti` and a new signature. The record is kept at least until the proof can no longer be accepted (`exp` plus 60 seconds). A service that cannot read or write that record MUST fail the call with a retriable `503 SERVICE_UNAVAILABLE`, never accept the proof.

### 6.4 Which calls take which credential

| Call | An install proof | The owner's credential | A licence key |
|---|---|---|---|
| `POST /v1/network/countersignatures` | `countersign` | refused | refused |
| `POST /v1/network/revocations` | `revoke` | accepted | refused |
| `POST /v1/network/detection/rules` | `rules` | accepted | accepted |
| `POST /v1/network/detection/classify` | `classify` | accepted | accepted |
| `POST /v1/network/detection/intent-deviation` | `classify` | accepted | accepted |

A countersignature is asked for only with a proof, because possession of the key is what is being proved: a stolen account credential MUST NOT be enough to have STACK vouch for a passport, and a call that needs a proof and gets any other credential is `401 INSTALL_PROOF_REQUIRED`. A missing, empty or larger-than-4096-character bearer value is `401 INVALID_API_KEY`. Whichever credential a call carries, it is made for the owner's account with no authority of its own: it is never an administrator of anything.

A service MAY meter these calls; metering and the price of a call are not part of this specification. A call refused because of a client mistake, a replay or a revoked passport is not a billable action.

## 7. Countersigning

```
POST /v1/network/countersignatures
Authorization: Bearer <install proof, act countersign>
```

The body is empty or an empty object; any other body is `400 VALIDATION_ERROR`. The data is in the proof (section 6.2). The service sees the digest, never the passport.

The service MUST refuse with `409 CONFLICT` a digest that a revocation of this owner already covers (section 10.3), and a call for an agent that is revoked. Otherwise it issues a countersignature with a fresh `jti` and answers `201`:

```json
{
  "id": "csg_...",
  "countersignature": "<compact JWS>",
  "expires_at": "2026-10-24T09:45:00.000Z",
  "install": "ins_...",
  "passport_digest": "..."
}
```

`id` equals the countersignature's `jti`. The countersignature's life is `ttl` seconds, 900 when the proof has none. The install asks for a new one when it refreshes the passport.

**The countersignature.** Header `{ "alg": "EdDSA", "kid": "<STACK key>", "typ": "stack-countersignature+jwt" }`. Registered claims `iss`, `aud` (`stack:countersignature`), `sub` (the install id), `iat`, `exp`, `jti`, and:

```json
{
  "cs": {
    "v": 1,
    "install": "ins_...",
    "owner": "op_...",
    "owner_verified": true,
    "key": { "kid": "<thumbprint>", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." } },
    "passport": { "alg": "sha256", "digest": "...", "jti": "pas_...", "agent": "support-bot" }
  }
}
```

| Field | Meaning |
|---|---|
| `install` | The install. |
| `owner` | The account that registered the install, authenticated when it did. Opaque. |
| `owner_verified` | Whether the service had verified the owner's identity when it issued this. Informational: countersigning never requires it, so a counterparty that wants it checks it. |
| `key` | The install's public key that signed the passport, with its thumbprint, so a verifier needs no lookup. |
| `passport.alg` | `sha256`. |
| `passport.digest` | The passport digest (section 3). |
| `passport.jti`, `passport.agent` | Present when the proof named them. |

A countersignature that contains a `key.kid` that is not the thumbprint of `key.jwk` is malformed. The service keeps a record of each countersignature (its `jti`, install, key, owner, digest, agent and expiry) for 30 days after it expires and no longer.

## 8. Checking a countersigned passport

### 8.1 Offline

A counterparty given a passport and its countersignature, with only the JWKS, MUST check:

1. The countersignature as an object STACK signed (section 4.2): header `alg`, `typ` `stack-countersignature+jwt`, `kid`; signature; `iss`; `aud` `stack:countersignature`; not expired.
2. The claim set: `cs.v` is 1, `cs.passport.alg` is `sha256`, `cs.key.jwk` is an Ed25519 install key, and `cs.key.kid` is the thumbprint of `cs.key.jwk`.
3. The SHA-256 digest of the passport string equals `cs.passport.digest`.
4. The passport's EdDSA signature verifies with `cs.key.jwk`, and the passport is not expired.

If all hold, the verifier may rely on what section 2 says and nothing more. It MUST NOT infer that the key, the install, the agent or the passport has not been revoked. A counterparty that takes a consequential action MUST also check online (section 8.2) or consult the revocation list (section 10.4) as recently as the action requires.

### 8.2 Online

```
POST /v1/network/verify
Content-Type: application/json

{ "countersignature": "<compact JWS>", "passport": "<compact JWS>" }
```

No credential. `passport` is optional; when it is given the service also checks the passport. The body is at most 64 KiB; each token is at most 24,000 characters. A body that is not that shape is `400 VALIDATION_ERROR`; everything else, including a forged token, is answered `200` with a verdict:

```json
{
  "valid": false,
  "reasons": ["revoked"],
  "checked_at": "2026-10-24T09:31:00.000Z",
  "install": "ins_...",
  "owner": "op_...",
  "passport_digest": "...",
  "countersignature_expires_at": "2026-10-24T09:45:00.000Z",
  "revoked": { "kind": "agent", "at": "2026-10-24T09:30:00.000Z", "reason": "agent_decommissioned" }
}
```

`valid` is true exactly when `reasons` is empty. `install`, `owner`, `passport_digest` and `countersignature_expires_at` are null when the countersignature could not be read. `revoked` is null unless a revocation covers this countersignature (section 10.3). The `reasons`, each a short code:

| Reason | Meaning |
|---|---|
| `countersignature_invalid` | Not a countersignature the service signed (signature, `typ`, `aud`, `iss` or shape). Nothing else is evaluated. |
| `countersignature_expired` | It is past `exp`. The other checks still run, so the answer says all that is wrong. |
| `countersignature_unknown` | Its signature verifies but the service has no record of it that agrees with its claims (a countersignature past the retention of section 7, or one of another network). |
| `install_revoked` | The install was revoked. |
| `key_revoked` | The key was revoked (and the install was not). |
| `owner_suspended` | The owner's account is suspended or closed: whatever its remaining life, it is no longer vouched for. |
| `revoked` | A revocation of kind `passport` or `agent` covers it, or one of kind `key` or `install` does and `install_revoked` and `key_revoked` do not already say so. |
| `passport_digest_mismatch` | A passport was given and its digest is not the one the countersignature covers. |
| `passport_expired` | The passport was given, its digest matches and it has expired. |
| `passport_signature_invalid` | The passport was given, its digest matches and its signature does not verify with the countersignature's key. |

Verdicts are never cacheable (`cache-control: no-store`). Public routes are rate limited per source address (`429 RATE_LIMITED`).

## 9. The STACK-verified statement

### 9.1 Asking

```
GET /v1/network/verified?passport_digest=<digest>
GET /v1/network/verified?install=<install id>&agent=<agent>
```

No credential. Exactly one form: a passport digest, or an install and an agent together; anything else is `400 VALIDATION_ERROR`. The service answers from its newest countersignature over that digest, or for that agent of that install (the one that expires last). If it never countersigned that digest or agent the answer is `404 NOT_FOUND`: an install's agent is never answered for another install. Otherwise `200`:

```json
{ "status": "live", "statement": "<compact JWS>" }
```

`status` repeats what is signed; a client MUST rely only on the signed statement. The answer is never cacheable.

### 9.2 The statement

Header `{ "alg": "EdDSA", "kid": "<STACK key>", "typ": "stack-verified+jwt" }`. Registered claims `iss`, `aud` (`stack:verified`), `iat`, `exp` (five minutes after `iat`) and `sub`: `passport:<digest>` for the first form, `agent:<install id>:<agent>` for the second. And:

```json
{
  "vs": {
    "v": 1,
    "mark": "STACK-verified",
    "status": "live",
    "install": "ins_...",
    "countersignature": "csg_...",
    "valid_until": "2026-10-24T09:45:00.000Z",
    "passport_digest": "..."
  }
}
```

| Field | Meaning |
|---|---|
| `mark` | `STACK-verified`, spelled exactly like that. |
| `status` | `live`, `expired` or `revoked` (section 9.3). |
| `install`, `countersignature`, `passport_digest` | The install, the countersignature's `jti` and the digest the statement is about. For the agent form these are those of the newest countersignature. |
| `valid_until` | When that countersignature stops being good. |

### 9.3 Status

The status is `revoked` when a revocation covers the countersignature (section 10.3), or the owner's account is not active, or the install is not active, or its key is revoked. Otherwise it is `expired` when the countersignature's expiry has passed, and `live` when it has not. A key whose rollover has ended does not by itself make a statement `revoked`.

### 9.4 Showing the mark

Only `live` earns the mark. A site or supplier that shows it MUST show it from a statement it fetched and verified just now (section 4.2), MUST NOT show it from one that has passed its `exp`, and SHOULD show the statement's time with it. The statement is a snapshot: it is never a statement about anything but the moment it was signed. The mark's name is spelled exactly `STACK-verified`, and its use is governed by STACK's trademark policy.

## 10. Revocation

### 10.1 What a revocation names

| `kind` | `subject` | Covers |
|---|---|---|
| `passport` | A passport digest. | Countersignatures over that digest. |
| `agent` | An agent id, as the install named it when it countersigned. | Countersignatures of that install with that agent. |
| `key` | An install key's thumbprint. | Every countersignature made under that key. |
| `install` | An install id. | Every countersignature of that install. |

`reason` is one of a closed list, so that the public list never carries free text. `by` says who published it.

<!-- spec:generated:network-revocation-lists -->

| List | Values |
|---|---|
| `kind` | `passport`, `agent`, `key`, `install` |
| `reason` | `unspecified`, `key_compromise`, `agent_decommissioned`, `superseded`, `policy_violation`, `owner_request` |
| `by` | `install`, `owner`, `stack` |
| Install and key `status` | `active`, `revoked` |
| Subscription `status` | `active`, `failing`, `paused` |
| Statement `status` | `live`, `expired`, `revoked` |
| Rule packs (`id`, direction) | `prompt_injection` (input), `output_injection` (output) |

<!-- /spec:generated -->

### 10.2 Publishing

```
POST /v1/network/revocations
```

**By an install.** `Authorization: Bearer <install proof, act revoke>` naming `kind`, `subject` and optionally `reason` (`unspecified` when absent). The body is ignored. An install can revoke only what is its own: an `install` revocation must name the install itself, and a `key` revocation a key of that install; anything else is `404 NOT_FOUND`.

**By the owner.** The owner's own credential and the body `{ "kind", "subject", "install", "reason"? }` (`owner_request` when `reason` is absent). Every revocation names the install it belongs to, so `install` is required for every kind and must be one of the owner's installs. The subject must belong to that install: for `install` it equals `subject`; for `key` the key is one of the install's; for `passport` STACK has countersigned that digest for that install (section 7); for `agent` STACK has countersigned that agent name for that install (section 7), whether or not the countersignature has since expired; the list is public, so an owner cannot publish an arbitrary string as an agent. (An install's own signed `revoke` may name any agent in its own namespace.) A subject that does not belong to the install, or an install that is not the owner's, is `404 NOT_FOUND`. An agent of the owner's that belongs to no install is not on the network list: revoking it is the account's own passport revocation, not a network revocation.

Either way the answer is `201` with the entry as the list shows it (section 10.4). A revocation is never metered and is never refused because an allowance is spent. It is rate limited per install and per source. Publishing the same `(kind, subject, install)` again, by the same owner, changes nothing and returns the first entry. A revocation is permanent.

### 10.3 What a revocation covers

A revocation covers a countersignature when it was published by the same owner as the countersigned install and: it is of kind `passport` and names the countersignature's digest; or of kind `key` and names its key; or of kind `install` and names its install; or of kind `agent`, names the countersignature's agent and names the countersignature's install. A revocation never affects another owner's countersignatures, whatever it names. The service applies this when it countersigns (section 7), answers an online check (section 8.2) and signs a statement (section 9.3).

### 10.4 The signed list

```
GET /v1/network/revocations?after=<seq>&limit=<n>&install=<install id>
```

No credential; rate limited per source; never cacheable (`cache-control: no-store`). `after` is a cursor (default 0), `limit` is 1 to 500 (default 200), and `install` restricts the list to one install's entries. An unknown parameter or a value out of range is `400 VALIDATION_ERROR`. The answer is `{ "list": "<compact JWS>" }`, and everything a client relies on is inside the signed list.

Header `{ "alg": "EdDSA", "kid": "<STACK key>", "typ": "stack-revocation-list+jwt" }`. Registered claims `iss`, `aud` (`stack:revocation-list`), `iat`, `exp` (five minutes after `iat`) and:

```json
{
  "rl": {
    "v": 1,
    "after": 0,
    "head": 2,
    "next": null,
    "entries": [
      { "seq": 1, "id": "rev_...", "kind": "agent", "subject": "support-bot", "install": "ins_...", "reason": "agent_decommissioned", "by": "install", "at": "2026-10-24T09:30:00.000Z" }
    ]
  }
}
```

| Field | Meaning |
|---|---|
| `after` | The cursor this page starts after. |
| `head` | The highest sequence number the service had published when it read the page, over every install, whatever the `install` filter. |
| `next` | The cursor of the next page, or null when this page was not full (it reached the end). A page is full when it holds `limit` entries; `next` is then the `seq` of its last entry. |
| `entries` | The entries with `seq` greater than `after`, in ascending `seq`. `seq`: a positive integer; `id`: the revocation's id; `kind`, `subject`, `reason`, `by` as above; `install`: the install the subject belongs to, never null; `at`: when it was published. |

Sequence numbers are assigned in commit order under a lock, so a poller that has read up to a number never misses a lower one that commits later. The service reads `head` before it reads the entries, so an entry published while the page is read can appear in the page with a `seq` above `head`.

**What a counterparty MUST do.** Verify the list as an object STACK signed (section 4.2) and refuse to use one that has passed its `exp`. Resume from `next` when it is not null, else from `head`; keep the highest `seq` it has handled and deduplicate on `seq`. A counterparty MUST match an entry to a countersignature on **both the subject and the install**: the entry's `install` must equal the countersignature's `cs.install`, and the subject must be the countersignature's passport digest (`passport`), agent (`agent`), key id `cs.key.kid` (`key`) or install (`install`). It MUST ignore an entry whose `install` differs from the countersignature's, and an entry with no `install`: a digest or an agent name is only meaningful inside the install it was issued under, and another install's entry about the same digest or name is another company's. For an exact answer about a countersignature it holds, ask the online check (section 8.2). A counterparty that cannot reach the service MUST NOT treat the silence as proof of validity.

## 11. Revocation subscriptions

A counterparty with a STACK account can have each new revocation pushed to it instead of polling.

### 11.1 The owner's calls

| Call | What it does |
|---|---|
| `POST /v1/network/subscriptions` with `{ "url", "installs"? }` | Subscribes. `url` is an `https` address at a public host (it is checked when it is set and at every delivery; a refused address is `400 NETWORK_ADDRESS_REFUSED`); `installs` (at most 100 install ids) restricts the subscription to those installs, and omitting it follows every revocation. `201` with the subscription view and, once, `signing_secret`. |
| `GET /v1/network/subscriptions` | `{ "subscriptions": [view, ...] }`. |
| `DELETE /v1/network/subscriptions/{id}` | `{ "success": true }`. |
| `POST /v1/network/subscriptions/{id}/rotate-secret` | A new signing secret, shown once: `{ "signing_secret", "previous_valid_until" }`. |
| `POST /v1/network/subscriptions/{id}/resume` | Puts a paused or failing subscription back to work at once; it is sent what it missed. |

The **subscription view** is `{ "id", "url", "installs", "status": "active" | "failing" | "paused", "last_delivered_seq", "last_error", "signed", "created_at" }`. `last_error` is one of `unsafe_address`, `timeout`, `unreachable`, `http_<status>` or `unsigned`. An owner has a bounded number of subscriptions (`409 NETWORK_LIMIT_REACHED`, `details.what` `subscriptions`). The signing secret is returned to an API key or a console session and never through an OAuth sign-in (a chat), which is given `signing_secret: null` and a note saying how to rotate one; rotating through an OAuth sign-in is `403 FORBIDDEN`. A subscription made before deliveries were signed has `signed` false and is never sent unsigned: it waits until a secret is rotated in.

### 11.2 What is pushed

A subscription starts at the head: it is sent what is published from the moment it is made. When there are entries after its cursor that it follows, the service posts:

```
POST <url>
content-type: application/json

{ "type": "stack.network.revocations", "list": "<compact JWS>" }
```

The request is signed as Standard Webhooks with the subscription's own secret, exactly as [the webhook specification](../webhooks/SPEC.md) sets out (family `revocation_push`: headers, signed string, secrets and rotation with a 24 hour overlap, receiver checks, tolerance, retry and timeout), and that specification is normative for all of it. This one adds only:

- `list` is the same signed list that section 10.4 serves, after the subscription's cursor and restricted to its `installs`. A receiver verifies the JWS (section 4.2), so a relayed copy still verifies; the request's signature proves who sent it, the JWS proves the list.
- Delivery is at least once and in order. The cursor moves only after a `2xx`, so a receiver that answers `2xx` has durably accepted the page; a receiver deduplicates on `seq`.
- On failure the service retries in order with backoff from 1 second to 1 hour; a subscription that has failed for 72 hours pauses, until its owner resumes it. The service sends at most one request at a time to one subscription.
- A page holds at most 100 entries. A page that follows nothing is not sent (the cursor moves on).

## 12. Detection rules and the classifier

### 12.1 The rule set

```
POST /v1/network/detection/rules
Authorization: Bearer <install proof, act rules | the owner's credential | a licence key>
```

The body is empty or an empty object. The answer is `200`:

```json
{ "version": "r1-0a1b2c3d4e5f", "revision": 1, "expires_at": "2026-10-27T09:30:00.000Z", "statement": "<compact JWS>" }
```

(A POST, because each call is a recorded action.) The statement is an object STACK signs: header `typ` `stack-detection-rules+jwt`, registered claims `iss`, `aud` (`stack:detection-rules`), `iat`, `exp` (72 hours after `iat`) and:

```json
{
  "rs": {
    "v": 1,
    "version": "r1-0a1b2c3d4e5f",
    "revision": 1,
    "sha256": "<64 lowercase hexadecimal characters>",
    "packs": [
      { "id": "prompt_injection", "direction": "input", "rules": [ { "id": "...", "severity": "critical", "pattern": "...", "flags": "i" } ] },
      { "id": "output_injection", "direction": "output", "rules": [] }
    ]
  }
}
```

| Field | Meaning |
|---|---|
| `revision` | A positive integer that orders rule sets. It goes up whenever a rule is added, removed or changed. |
| `version` | `r<revision>-<the first 12 characters of sha256>`. |
| `sha256` | The lowercase hexadecimal SHA-256 of the canonical JSON of `packs`: UTF-8, no whitespace, object members sorted by name in UTF-16 code unit order at every depth, arrays in their order, strings and numbers as `JSON.stringify` writes them. |
| `packs[].id` | `prompt_injection` (direction `input`: content going into an agent) or `output_injection` (direction `output`: content an agent sends). |
| `rules[]` | `id` (1 to 100 characters), `severity` (`warning` or `critical`), `pattern` (an ECMAScript regular expression, at most 4000 characters), `flags` (at most 8). A rule matches content when `new RegExp(pattern, flags)` finds a match in it. |

An install client MUST verify the statement as an object STACK signed (section 4.2) before it uses a rule, MUST refuse one whose `revision` is lower than the highest it already runs (so an old set replayed to it cannot undo a newer one) and one that has passed its `exp`, and SHOULD check that `sha256` is the digest of `packs`. It SHOULD fetch a new set well before the one it holds expires, and keeps running the set it holds when a fetch fails (a refused or unreachable call is an ordinary failed fetch). What an install does with a match (block, flag, log) is its own policy; the rule set says only what matched and how severe the rule is. The patterns are written by STACK, but an install SHOULD run them with a bound on the work a match may do.

### 12.2 The classifier

```
POST /v1/network/detection/classify
Authorization: Bearer <install proof, act classify | the owner's credential | a licence key>
```

Body (at most 512 KiB):

```json
{ "content": "text, or a JSON object", "context": "email" }
```

`content` is a string of 1 to 200,000 characters or a JSON object. `context` is optional: `email`, `document`, `webpage`, `chat_log`, `api_response`, `calendar` or `other`. Unknown members are refused (`400 INVALID_REQUEST`). The content is not stored: the service keeps the call, the verdict and the id of the rule that matched, never the content or the matched text.

The answer is `200`:

```json
{
  "verdict": "suspicious",
  "request_id": "ses_...",
  "duration_ms": 412,
  "rules_version": "r1-0a1b2c3d4e5f",
  "match": { "pattern_id": "...", "severity": "warning", "field_path": "content", "matched_excerpt": "...", "encoding": "base64" },
  "llm": { "verdict": "suspicious", "confidence": 0.82, "reasoning": "...", "model": "..." },
  "l3_degraded": null
}
```

| Field | Meaning |
|---|---|
| `verdict` | `clean`, `suspicious` or `critical`: `critical` when a rule of severity `critical` matched or the model said so, `suspicious` for a `warning`. |
| `rules_version` | The `version` of the rule set the regular expressions ran. |
| `match` | The rule that matched (`pattern_id`, `severity`, the `field_path` it matched in, a short `matched_excerpt`, and `encoding` when it matched after decoding), or null. The excerpt is in the answer only. |
| `llm` | The model's verdict, `confidence` (0 to 1), `reasoning` and the identifier of the model, or null when the model did not run or could not answer. |
| `l3_degraded` | `{ "reason", "duration_ms" }` when the model was asked and could not answer, so the verdict is the regular expressions' alone; otherwise null. |

An install SHOULD treat content it sends for classification as leaving its machine: the classifier is a hosted service and may pass part of the content on to a model provider.

### 12.3 Intent deviation

```
POST /v1/network/detection/intent-deviation
Authorization: Bearer <install proof, act classify | the owner's credential | a licence key>
```

Body (at most 512 KiB): what an agent declared for its passport and what it then did.

```json
{
  "declared": { "summary": "Read the calendar", "services": ["calendar"] },
  "observed": {
    "services_used": ["calendar", "email"],
    "tool_calls": [{ "service": "email", "method": "send", "target": "a@example.com" }],
    "actions_count": 2,
    "summary": "Sent an email"
  }
}
```

`declared.summary` is 1 to 2,000 characters and `declared.services` at most 100 names; `observed.services_used` at most 200 names, `observed.tool_calls` at most 500 calls of `service`, `method` and an optional `target`, `observed.actions_count` a non-negative integer and `observed.summary` optional, at most 2,000 characters. Unknown members are refused (`400 INVALID_REQUEST`). Nothing of it is stored: the service keeps the call and its grade.

The answer is `200`:

```json
{ "request_id": "ses_...", "graded": true, "score": 0.8, "flag": { "severity": "critical", "message": "..." }, "duration_ms": 640 }
```

| Field | Meaning |
|---|---|
| `graded` | Whether a model graded the checkout. `false` when no model could be asked or its answer could not be read; `score` and `flag` are then null. |
| `score` | 0 (the behaviour matched the intent) to 1 (unrelated to it), or null. |
| `flag` | `{ "severity": "warning" or "critical", "message" }` for a score of 0.4 or more (`critical` from 0.7), else null. |

A grade is advice for the install's own review of the checkout; what the install does with a flag is its own policy.

## 13. Licence keys and their revocation

A licence key is a signed bearer credential STACK issues to a self-managed install's account.

```
STACKLIC1.<payload>.<signature>
```

`payload` is the base64url of a JSON claim object; `signature` is the base64url of an Ed25519 signature over the UTF-8 bytes of `stack-licence-v1\n` followed by `payload` exactly as written in the key (nothing is re-serialised). The claims: `v` (1), `kid` (which of STACK's licence keys signed it), `customer`, `issued_at` and `expires_at` (ISO 8601), `features` (a list; a feature a verifier does not know is never granted and is not an error), and for a key issued to an account `operator_id` (the account) and `jti` (the key's own id: 16 to 64 characters of `[A-Za-z0-9_-]`, unique, unguessable). The public keys that verify a licence are published with STACK's engine source; a key naming a `kid` not in that set is invalid.

**Accepted for three calls.** The network takes a licence key as the credential of the account it names, for `rules`, `classify` and `intent-deviation` only (section 6.4), so a self-managed install with nothing registered can use them. The account is named by a claim STACK signed, so nothing the caller sends picks an account; a call made this way is that account's. A licence is refused (`401 INVALID_API_KEY`, one plain answer that does not say why) when it is not signed by a trusted licence key, is expired, names no account, carries no `jti` (it could not be revoked), names an account that is closed, or is revoked.

**Revoking one.** The account revokes a key that leaked, before it expires:

```
POST /v1/network/licences/revoke      { "licence_key": "<the key>", "reason"? }
GET  /v1/network/licences/revoked
```

The owner's credential, by an owner or administrator; a credential of an agent is refused; never metered. The key itself is the proof it is the account's: the route reads its signed claims. A key that STACK did not sign, that is expired, that was issued to another account or that carries no `jti` is one `400 LICENCE_NOT_REVOCABLE`, so the route says nothing about anyone else's keys. Otherwise `201` with the revocation, and `200` with the first revocation when the key was already revoked (the first reason and time stand):

```json
{ "jti": "lk_...", "customer": "Example AB", "reason": "owner_request", "expires_at": "2099-01-01T00:00:00.000Z", "revoked_at": "2026-10-24T09:30:00.000Z" }
```

`reason` is one of the closed list of section 10.1 (`owner_request` when absent). The service stores the key's id and not the key. `GET /v1/network/licences/revoked` answers `{ "revoked": [revocation, ...] }`, the account's own, newest first. A revoked key is listed until 90 days after the key would have expired.

**The check.** The service asks, on every request that carries a licence key and before it does anything billable, whether its `jti` is revoked. A revoked key is refused on every machine of the service no later than 30 seconds after the revoking call returned. If the service cannot find out, the call is a retriable `503 SERVICE_UNAVAILABLE` and goes no further: a check that cannot be made is a refusal, never a pass. A client treats a refused or unavailable licence check like any failed fetch and keeps what it holds.

## 14. Test vectors

[`test-vectors.json`](test-vectors.json) holds the objects of this specification for fixed public test keys and a fixed clock (`now`, 1790000000, with `exp` and checks relative to it): a passport, its countersignature, a verified statement, a revocation list, a rule set, three install proofs (`rules`, `countersign`, `revoke`) and a key proof of possession, each as its three dot-separated parts (join them with a full stop), the JWKS that verifies the objects STACK signs, and the install's public key and 32-byte seed. `negative` lists the cross-kind confusions every verifier must refuse and cases that must each be refused, with the clock to check them at. Ed25519 signatures are deterministic, so the same inputs give the same bytes.

The vectors are produced by a public script, [`../conformance/scripts/build-network-vectors.mjs`](../conformance/scripts/build-network-vectors.mjs), from the keys and builders in [`../conformance/src/network-vectors.mjs`](../conformance/src/network-vectors.mjs); it needs only Node. `--check` fails when the file differs from what the script produces. Every key in the vectors is public and for the vectors only: STACK's is the Ed25519 key whose seed is 32 bytes of `0x01`, the install's 32 bytes of `0x02`. Two things are format-only: the rule set's `sha256` and `version` are not those of its `packs`, and the countersignature's `owner` and ids are not real.

## 15. Errors

Errors use the envelope `{ "error": { "code", "message", "details" } }`. `message` is for a person; a client MUST key on `code`. The codes a party of the network can meet:

| Code | Status | When |
|---|---|---|
| `INVALID_API_KEY` | 401 | A bearer value is missing, too long, or is a licence key or credential the service does not accept (sections 6.4 and 13). |
| `INSTALL_PROOF_REQUIRED` | 401 | The call needs an install proof and carries another credential. |
| `INSTALL_PROOF_INVALID` | 401 | The proof was refused; `details.reason` is one of the reasons of section 6.3. |
| `INSTALL_PROOF_REPLAYED` | 401 | The proof's `jti` was presented before. |
| `FORBIDDEN` | 403 | The credential belongs to an agent, or may not do this. |
| `GOVERNANCE_APPROVAL_REQUIRED` | 403 | A person must approve registering a key (section 5.2). |
| `KEY_CHALLENGE_INVALID` | 400 | The key registration challenge was unknown, used, expired or answered wrongly. |
| `LICENCE_NOT_REVOCABLE` | 400 | The key offered for revocation cannot be revoked by this account. |
| `NETWORK_ADDRESS_REFUSED` | 400 | A subscription's address is not https or not public. |
| `VALIDATION_ERROR`, `INVALID_REQUEST` | 400 | The request does not have the shape this specification says. |
| `NOT_FOUND` | 404 | Nothing of that id is visible to the caller, or the digest or agent was never countersigned. |
| `INSTALL_REVOKED` | 409 | The install is revoked. |
| `NETWORK_LIMIT_REACHED` | 409 | A bound on installs, usable keys or subscriptions is reached; `details` `{ "what", "limit" }`. |
| `CONFLICT` | 409 | A key is already registered; a revoked passport or agent cannot be countersigned. |
| `RATE_LIMITED` | 429 | The install, or the source address, is calling too fast. |
| `SERVICE_UNAVAILABLE` | 503 | The service could not check what it must check (a replay record, a licence revocation). Retry; the call was not accepted. |

A client MUST treat an `INSTALL_PROOF_INVALID` for `expired` or an unexplained `bad_signature` as a hint to check its clock before it concludes that its key is wrong.

## 16. Security considerations

- **One signing key, many purposes.** STACK's key signs passports and every object of section 4.1. What separates them is the header `typ` and the claim `aud`, which a verifier MUST demand (section 4.2); a verifier that checks only the signature accepts a revocation list as a countersignature. The install's own key signs only proofs and key proofs, under their own `typ`.
- **A proof is a request, not a login.** The data of a call rides inside the signed claims, a proof lives at most 120 seconds (180 with the skew), and each is accepted once. A leaked install key can call the four install calls and nothing else; revoke it and it is dead on the next call. Keep the private key in a file only the install can read and never log a proof.
- **Possession before registration.** A key is registered only with a proof signed by its private half over a challenge the service just made for that owner and install, and the service may require a person to approve it. An API key alone can create an install but not give it a key.
- **The service fails closed.** A replay record or licence revocation that cannot be read or written is a retriable `503`, never an acceptance. A counterparty SHOULD do the same: a list it cannot refresh, a statement that has expired and a check it cannot make are not validity.
- **Revocation is not knowable offline.** A countersignature lives 15 minutes by default (a minute to an hour on request) for that reason. A counterparty that relies on one for longer than it can tolerate a revoked key MUST check online or follow the list.
- **Revocations are scoped to an install.** Every entry names the install it belongs to, and a verifier MUST match on both the subject and the install (section 10.4). An entry that says nothing about whose it is would let one company have another's agent refused by publishing a digest or an agent name it knows; with the install in every entry and in the match, an entry can only ever concern the countersignatures of the install it names.
- **What leaves an install.** `rules` sends nothing but the signed request. `countersign` sends a digest, the passport's `jti`, an agent's name and the public key; never the passport. `revoke` publishes what it names, so an agent id is public: choose names you are willing to publish. `classify` sends the content, and part of it may go on to a model provider.
- **A suspended owner is not vouched for.** Online checks and statements read the owner's account: suspended or closed, a countersignature is `owner_suspended` and a statement `revoked`, whatever life is left.
- **No cross-account data.** Every install, key and subscription lookup is scoped by the owner; public lookups find only what was countersigned for exactly the digest, or the install and agent, the caller names, and a digest is not guessable.
- **Subscription addresses.** An address is checked as public and https when it is set and at every delivery, with no redirects. It is not proven to belong to the subscriber: the payload is a public list.
- **Not covered.** An install key is not registered under a hardware attestation. The `owner_verified` flag is the owner's state when the countersignature was issued, nothing later.

## 17. Machine-readable schemas

The JSON Schemas in [`schemas/`](schemas/) (draft-07) are generated from the reference implementation and are normative for the shapes they describe: the claim sets of the objects an install signs (`NetworkInstallProofClaims`, `NetworkInstallPopClaims`), those of the objects STACK signs (`CountersignatureClaims`, `RevocationListClaims`, `VerifiedStatementClaims`, `DetectionRuleSetClaims`), `InstallPublicJwk` and the inputs of the calls (`RegisterInstallInput`, `AddInstallKeyInput`, `RevokeNetworkInput`, `PublishRevocationInput`, `CreateNetworkSubscriptionInput`, `ListRevocationsQuery`, `VerifyCountersignatureInput`, `VerifiedStatusQuery`, `NetworkClassifyInput`, `RevokeLicenceInput`). Where a schema and this text disagree, report it as a defect; the schema is what the reference implementation enforces.

## 18. Conformance

The conformance kit ([`../conformance/`](../conformance/README.md)) has two suites for this specification.

- **`network-verifier`** tests a counterparty or an install client. Given a module or a program that verifies the four kinds of object, it mints tokens with keys of its own and checks that the verifier accepts what it must (a countersigned passport, a list, a statement, a rule set, a key chosen by `kid` from several, extra unknown claims) and refuses what it must (every other kind presented as the kind asked for, a wrong audience or issuer, `alg` `none`, a symmetric algorithm keyed with the public key, a tampered payload, a foreign key under a known `kid`, an unknown `kid`, an expired token, malformed tokens, a passport that does not match, is not signed by the install key or has expired, a rule set older than the one held). It also checks how a verifier matches a revocation list to a countersigned passport: on the subject and the install, ignoring an entry of another install or with none. It also runs every case of [`test-vectors.json`](test-vectors.json). Given a signer for an install, it checks the key proof and the install proof it produces against sections 5.3 and 6.2.
- **`network-service`** tests a service. Given its base address, it checks the public calls (the JWKS, the signed revocation list and its paging, the online check, the statement, what a forged, absent or mismatched credential gets) and, when it is given a registered install key, the whole flow: countersigning, replay, the wrong action, the online check, a revocation and its effect on the list, the check and the statement.

The SDK of `@getstackrun/sdk` (`InstallKey` and the `verify*` functions of its network module) is the reference install client and verifier and passes `network-verifier`; the reference in-memory service in the kit's `reference/` directory passes `network-service`, as does STACK's hosted service in STACK's own continuous integration. The suites never use a STACK package to judge your implementation.
