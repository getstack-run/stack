# STACK Workload Identity Exchange

**Specification:** STACK Workload Identity Exchange
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

A workload (a service, a job, a container) that already has an identity from the infrastructure it runs on can exchange that identity for a STACK Passport, with no STACK credential stored on the machine. This document defines how STACK accepts two kinds of workload identity token, a SPIFFE JWT-SVID and a WIMSE Workload Identity Token (WIT); what a deployment configures to trust an issuer; the two exchange calls and what they answer; and how the same tokens admit workers to a fleet.

Contents: 1 Conventions, 2 Model, 3 What a deployment configures, 4 Accepting a token, 5 Key sets, 6 The exchange, 7 Fleet enrollment, 8 Errors, 9 Security considerations, 10 Machine-readable schemas and conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The **relying deployment** is the STACK deployment that accepts the token; the **issuer** is the system that signs the workload's token (a SPIRE server, a WIMSE issuer). A relying deployment conforms if it satisfies every MUST of sections 4 to 7; the conformance kit (the `workload-token` and `workload-exchange` suites) tests exactly that.

References: SPIFFE JWT-SVID (<https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md>), the SPIFFE trust bundle format, and the WIMSE workload identity drafts of the IETF (draft-ietf-wimse-s2s-protocol). Of those drafts this specification adopts only what section 4 states; where a draft says more (a `typ` header value, proof of possession), STACK's behaviour is what this text says.

## 2. Model

- A **trust domain** (SPIFFE) names an issuer's namespace: the host part of a workload's SPIFFE id `spiffe://{trust_domain}/{path}`.
- A **WIMSE issuer** is named by the `iss` URI of its tokens; the **workload id** is the token's `sub`.
- The relying deployment holds, per operator, one configuration for each trust domain or issuer it trusts (section 3). A configuration maps workload ids to **agents** of that operator. A token is accepted only for a workload id that a configuration maps.
- The exchange gives the workload a **Passport** (the [Passport](../passport/SPEC.md) specification) for the mapped agent, bound to one live **Mission** the operator opened, together with a signed attestation claim recording who was seen.

## 3. What a deployment configures

A relying deployment keeps this configuration; how it is entered (an API, a console) is outside this specification. Fields:

| Field | SPIFFE trust domain | WIMSE issuer |
|---|---|---|
| Identity | `trust_domain`: a DNS-style name, no scheme, no slash. | `issuer_uri`: the exact `iss` value. |
| Key set | `jwks_uri`: an `https` URL of the issuer's JWKS (RFC 7517) or SPIFFE trust bundle (JWT keys). | `jwks_uri`, as for SPIFFE. |
| Audience | `audience`: the one `aud` value tokens must carry. | `audience`, as for SPIFFE. |
| Mapping | A map from exact SPIFFE id to `{ "agent_id" }`; every key MUST be under `trust_domain` and every agent MUST belong to the operator. | A map from exact workload id to `{ "agent_id" }`. |
| Cache | `jwks_cache_ttl_seconds`: 60 to 3600, default 300. | The same. |
| Rate | `rate_limit_per_second`: optional, can lower the rates in 6.1. | The same. |
| State | `active`. | The same. |

At most one configuration exists per operator and trust domain (or issuer). More than one operator may configure the same trust domain: a workload belongs to the operator whose mapping lists its id. Mapping is by exact match: there are no patterns.

An `audience` left empty means the configuration accepts any `aud`. A deployment SHOULD NOT leave it empty, and a configuration used for fleet enrollment (section 7) MUST have one.

## 4. Accepting a token

Both token kinds are JWTs (RFC 7519) in JWS compact form, presented as `Authorization: Bearer <token>`. A relying deployment MUST apply these rules, in this order, to a token and the configuration it selects (a decoded claim only selects configuration; nothing is trusted until the signature has verified):

1. **Decode.** The token parses as a compact JWS with a JSON payload, else `malformed_jwt`.
2. **Identity claims.** SPIFFE: `sub` is a SPIFFE id, `spiffe://{trust_domain}/…` (else `invalid_spiffe_id`, whether `sub` is absent or is not one). WIMSE: `iss` is present (`missing_iss`) and `sub` is present (`missing_sub`).
3. **Configuration.** The active configurations for the SPIFFE id's trust domain, or for the WIMSE `iss`, are found (none: `not_configured`), and the first whose mapping lists the exact `sub` is the one used (none: `not_mapped`). The mapped agent is the one the Passport is issued for. A configuration is chosen before the signature is checked, because the key set to check it against is the key set of the configuration that maps the identity. The trust domain of the SPIFFE id MUST equal the configuration's (`trust_domain_mismatch`) and the `iss` of a WIT MUST equal its `issuer_uri` (`issuer_mismatch`); selection by exact name makes both hold, and a validator given a configuration that does not match MUST still refuse.
4. **Key.** The protected header carries a `kid` (else `missing_kid`) that names a key of the issuer's key set (else `unknown_kid`). A relying deployment MUST NOT select a key by any other means, and MUST verify only with the algorithm the key set gives for that key: its `alg` member, else the one its type implies (`ES256`, `ES384` or `ES512` for P-256, P-384 and P-521 keys, `EdDSA` for Ed25519, `RS256` for RSA). A key of another type, or one that gives a symmetric algorithm, is not usable (`verify_failed`). A token's own `alg` therefore cannot choose a weaker algorithm, and a token with `alg` `none` or an HMAC algorithm is never accepted.
5. **Signature and claims.** The signature verifies with that key (else `signature_invalid`, or `verify_failed` for any other failure); `exp` is present and in the future (`expired`); `nbf`, if present, is not in the future; and, when the configuration has an audience, `aud` (a string, or an array of strings that includes it) matches it (`audience_mismatch`).
6. **Lifetime.** At least 60 seconds of the token's life remain (else `too_close_to_expiry`): a token about to expire cannot yield a useful Passport.

The result of acceptance is the subject (the SPIFFE id or the workload id), the issuer (`iss`), the audience if the token carries a single string, and `exp`, which the exchange's Passport must not outlive. The `typ` header is not checked.

The WIMSE `cnf` (confirmation) claim, if the token carries a `jwk`, is recorded in the attestation claim. The exchange does not verify possession of that key; fleet enrollment does (section 7).

## 5. Key sets

The key set of a configuration is fetched and kept as follows.

- The address MUST use `https` and MUST resolve only to public addresses; the fetch refuses redirects, private, loopback, link-local and internal addresses, and has a 5 second deadline. A deployment MUST NOT fetch a key set from an address that fails these checks, and MUST check the address when the configuration is created and at every fetch.
- The answer is a JSON object with a non-empty `keys` array. Anything else is a failed fetch.
- A fresh copy is used for `jwks_cache_ttl_seconds`. For 60 seconds after that a stale copy is used while one request refreshes it (stale-while-revalidate, one refresher at a time). After that the next request fetches synchronously.
- If a synchronous fetch fails, the last key set the deployment fetched successfully is used (a failure of the issuer's key set must not stop every workload at once). If there is none, the exchange fails with `jwks_unavailable` (`503`).
- A key set that has rotated is learned at the next refresh. A token signed by a key the cached set does not hold fails with `unknown_kid` until then.

## 6. The exchange

| | SPIFFE JWT-SVID | WIMSE WIT |
|---|---|---|
| Call | `POST /v1/workload/passport` | `POST /v1/workload/wit` |
| Bearer | A JWT-SVID. | A WIT. |
| Attestation claim attached | `svid_attestation` | `workload_attestation` |

Neither call takes a STACK credential: the token is the credential, so both are served outside the API's authentication. The body is [`schemas/WorkloadPassportInput.json`](schemas/WorkloadPassportInput.json): `{ "mission_id": "ms_…" }`, no other member, naming a Mission the operator opened for the workload. The server applies these steps in order:

1. No bearer, or one that is not `Bearer <token>`, is `401 UNAUTHORIZED`.
2. A body that is not exactly `{ "mission_id" }` is `400 MISSION_REQUIRED`. Every Passport belongs to one live Mission, so the call is refused before any other work.
3. Rate limits (6.1).
4. The token is decoded, its identity read and its configuration chosen (section 4, steps 1 to 3).
5. The token is accepted under section 4, steps 4 to 6.
6. The Passport's lifetime is the shorter of the token's remaining life and 900 seconds (the Passport default).
7. The action is metered, after the token has verified: a token that has not verified MUST NOT spend anyone's allowance.
8. A Passport is issued for the mapped agent and the Mission, with the intent summary `Workload-attested via SPIFFE: {spiffe id}` or `Workload-attested via WIMSE: {workload id}` and no services. The ordinary issue rules apply, so a Mission that is missing, foreign, completed, revoked or expired, an agent that is blocked or inactive, and an operator that is not active refuse the call with the Passport specification's errors.
9. The attestation claim (`svid_attestation` with the SPIFFE id, trust domain, token expiry, issuer and the time of attestation; `workload_attestation` with the workload id, issuer and the `cnf` key if any) is signed and attached to the Passport, so that revoking the Passport revokes it. The exchange is recorded in the audit log.

The server answers `201` with [`schemas/WorkloadSvidPassportResult.json`](schemas/WorkloadSvidPassportResult.json) or [`schemas/WorkloadWitPassportResult.json`](schemas/WorkloadWitPassportResult.json): the `passport` token, its `jti` and `expires_at`, `claim_id` and `ttl_seconds`, and the identity that was seen (`spiffe_id` and `trust_domain`, or `workload_id` and `issuer`).

### 6.1 Rate limits

A server limits the calls it will take before it does work on them: 10 per second per source address (checked before the token is read) and 1000 per second per trust domain (SPIFFE) or per issuer (WIMSE), as fixed one-second windows. A configuration's own `rate_limit_per_second`, when set, adds a third window for that configuration; it can lower the rate, never raise the two above. A call over a limit is `429 RATE_LIMITED` with `details.scope` `ip`, `trust_domain`, `issuer` or `configuration`.

## 7. Fleet enrollment

A fleet policy ([Agent Runtime Sign-in](../agent-auth/SPEC.md) section 6) can name workloads as its principals. For this the workload presents its token as the bearer of the two workload enrollment calls instead of calling the exchange, and the server applies section 4 and the rules below. The result is an enrollment principal, and the token never yields a Passport on this path.

The policy lists **trust entries**, each `{ kind: "spiffe" | "wimse", issuer, audience, subjects[] }`. A server MUST:

1. Refuse a token longer than 4096 bytes, one that does not decode, and one whose `iss`, `sub` or `aud` is not a string (an `aud` that is an array is refused), all with `403 FORBIDDEN`.
2. Require that the policy is active, not revoked, not expired, and that **exactly one** trust entry matches the token's `iss` as `issuer`, its `aud` as `audience` and its `sub` among `subjects`. Two entries or none are refused: authority is never inferred from the near match.
3. Find the active configurations of the entry's kind for the trust domain (SPIFFE: the host of `sub`) or the issuer (WIMSE: `iss`), keep those of the policy's operator whose `audience` equals the token's, and require that exactly one remains.
4. Accept the token under section 4, steps 1, 2, 4 and 5, with that configuration (the mapping of section 3 is not used on this path: the policy names the subjects, and the remaining life is checked here). The accepted subject, issuer and audience MUST equal the decoded ones, and the token MUST have more than 5 seconds of life left.
5. If the token carries `cnf`, it MUST be an object with only `jwk` and `jkt` members, where `jwk` is an Ed25519 public `OKP` key (no private member) and `jkt`, if present, equals its RFC 7638 thumbprint; the key the worker then enrolls MUST be that key. Any other shape is refused.

Every failure on this path is `403 FORBIDDEN`: the caller learns nothing about the policy. A challenge issued to a workload is bound to the token's SHA-256 digest, so that the enroll call must present the same token.

## 8. Errors

Failures of the exchange (section 6, steps 4 to 6) are `WorkloadAttestationError`s and carry the codes below in the API's error envelope `{ "error": { "code", "message", "details" } }`, not the flat shape of the OAuth token endpoint: these calls are not OAuth token endpoints.

<!-- spec:generated:workload-reasons -->

| Reason | Code | HTTP status |
|---|---|---|
| `malformed_jwt` | `WORKLOAD_TOKEN_MALFORMED` | 400 |
| `missing_sub` | `WORKLOAD_SUBJECT_MISSING` | 400 |
| `missing_iss` | `WORKLOAD_ISSUER_MISSING` | 400 |
| `invalid_spiffe_id` | `WORKLOAD_SPIFFE_ID_INVALID` | 400 |
| `trust_domain_mismatch` | `WORKLOAD_TRUST_DOMAIN_MISMATCH` | 400 |
| `issuer_mismatch` | `WORKLOAD_ISSUER_MISMATCH` | 400 |
| `missing_kid` | `WORKLOAD_KEY_ID_MISSING` | 400 |
| `unknown_kid` | `WORKLOAD_KEY_ID_UNKNOWN` | 400 |
| `verify_failed` | `WORKLOAD_VERIFY_FAILED` | 400 |
| `too_close_to_expiry` | `WORKLOAD_TOKEN_TOO_CLOSE_TO_EXPIRY` | 400 |
| `expired` | `WORKLOAD_TOKEN_EXPIRED` | 401 |
| `audience_mismatch` | `WORKLOAD_AUDIENCE_MISMATCH` | 401 |
| `signature_invalid` | `WORKLOAD_SIGNATURE_INVALID` | 401 |
| `not_configured` | `WORKLOAD_ISSUER_NOT_CONFIGURED` | 401 |
| `not_mapped` | `WORKLOAD_IDENTITY_NOT_MAPPED` | 403 |
| `jwks_unavailable` | `WORKLOAD_JWKS_UNAVAILABLE` | 503 |
| `provider_unavailable` | `WORKLOAD_PROVIDER_UNAVAILABLE` | 500 |

<!-- /spec:generated -->

The other answers of the exchange: `401 UNAUTHORIZED` (no bearer), `400 MISSION_REQUIRED` (the body), `429 RATE_LIMITED` (6.1), and for the issue step the errors of the Passport specification section 11.

## 9. Security considerations

- A token is a bearer credential. It is as short-lived as its issuer makes it; a relying deployment refuses a token with less than 60 seconds left and caps the Passport at the token's life, so nothing the exchange mints outlives the identity that earned it. Services MUST receive it only over TLS.
- The exchange reveals one thing before it has verified anything: because the configuration is chosen by the identity in the token, an unauthenticated caller can tell an unconfigured issuer (`401`) and an unmapped identity (`403`) from a configured and mapped one. It reveals nothing about the agent or the operator, and every check that needs the issuer's key set comes after.
- Mapping by exact identity, from a configuration that names an agent of the operator, is what stops a workload of one trust domain from becoming an agent of another operator: a token is useful only to the operator whose configuration lists its id. An operator MUST NOT map an id it does not control.
- Pinning the audience keeps a token meant for another service from being replayed here. An unpinned configuration accepts any audience and so any token the issuer ever signed for the workload.
- Fetching a key set is a request the server makes to an address an operator chose. The `https`, public-address, no-redirect and size rules of section 5 are what keep that from reaching a server's internal network, and they apply at every fetch, not only when the configuration is saved.
- Falling back to the last good key set favours availability. It means a key the issuer withdrew keeps verifying until the issuer is reachable again; issuers rotate by publishing the new key first, and a deployment can deactivate the configuration to stop trusting an issuer at once.
- The WIMSE exchange accepts the token as a bearer token: it does not check proof of possession of the `cnf` key. Fleet enrollment does, so a worker that must be bound to a key enrolls through a fleet.

## 10. Machine-readable schemas and conformance

[`schemas/`](schemas/) holds `WorkloadPassportInput`, `WorkloadSvidPassportResult` and `WorkloadWitPassportResult` (draft-07), generated from the reference implementation. Conformance tests are in [`../conformance/`](../conformance/README.md): `workload-token` takes a function that accepts a token under a configuration and a key set and tests section 4 and section 7's token rules; `workload-exchange` takes the address of a server and tests the parts of section 6 that need no trust configuration.
