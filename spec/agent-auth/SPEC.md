# STACK Agent Runtime Sign-in

**Specification:** STACK Agent Runtime Sign-in
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

An agent that runs on its own machine signs in to STACK with a key pair it makes itself. The private key never leaves the machine; STACK keeps the public key. Every request the agent then sends carries a fresh, short-lived token signed with that key. This document defines how the key is enrolled (a challenge the agent answers to prove it holds the key), the token itself (the agent JWT, issuer `stack-sdk`), the rules a server applies to it, and the two calls with which a fleet enrolls its workers.

Contents: 1 Conventions, 2 Model, 3 The agent JWT, 4 Verifying an agent JWT, 5 Key enrollment, 6 Fleet enrollment, 7 Constants, 8 Errors, 9 Security considerations, 10 Machine-readable schemas and conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. All times in tokens are seconds since the Unix epoch. All JSON is UTF-8. Binary values (keys, signatures) are base64url without padding (RFC 4648 section 5). Identifiers are opaque; the prefixes shown (`agt_`, `flp_`, `fec_`) are conventions of the reference implementation.

Two roles are used. The **agent** is the software that holds the key and signs. The **server** is a STACK deployment (the hosted service or a self-managed install) that stores the public key and checks what the agent sends. A server implementation conforms to this specification if it satisfies every MUST addressed to a server; an agent-side implementation (an SDK) conforms if it satisfies every MUST addressed to an agent. The conformance kit in [`../conformance/`](../conformance/README.md) (the `agent-jwt` and `agent-enrollment` suites) tests both.

## 2. Model

- An **agent** is a registered actor owned by one operator. An agent whose key the customer holds has the key mode `customer_managed`; only such an agent enrolls a key (section 5). An agent whose key STACK holds (`stack_managed`, `co_signed`) has no enrollment step and signs in with the operator's credential instead.
- A **key** is an Ed25519 key pair (RFC 8037). The server stores one public key per agent, as the JWK members `kty` (`OKP`), `crv` (`Ed25519`) and `x`.
- An **agent JWT** is a token the agent signs with its private key and sends as `Authorization: Bearer <token>`. One token authenticates one request.
- **Enrollment** is a proof of possession: the server issues a random challenge, the agent signs it with the new private key, and the server stores the public key only if the signature verifies.
- An **enrollment ticket** is a single-use bearer a person's approval in a browser mints for the enrollment of one agent. It lets an agent enroll from a machine that has no other credential.
- A **fleet** is a policy a person approved under which workers enroll themselves (section 6). A worker enrolled that way is an agent with a `customer_managed` key, and signs in as in section 3.

## 3. The agent JWT

An agent JWT is a JSON Web Token (RFC 7519) in JWS compact form, signed with EdDSA over Ed25519. It is not a Passport: a Passport says what an agent may do, and the server issues it; an agent JWT says that the request comes from the holder of the agent's key, and the agent issues it.

Protected header: `alg` MUST be `EdDSA`. A `kid` is not used: the server selects the key by the agent named in `sub`.

Claims, defined by [`schemas/AgentJwtClaims.json`](schemas/AgentJwtClaims.json):

| Claim | Value |
|---|---|
| `iss` | `stack-sdk`. It is how a server tells an agent JWT from the other bearer tokens it accepts. |
| `aud` | `stack:agent`. |
| `sub` | The agent id: 1 to 128 characters from `A-Z a-z 0-9 _ -`. |
| `iat` | The time the agent signed. Required. |
| `nbf` | The same time. The reference SDKs send it; a server MUST apply it if present and MUST NOT require it. |
| `exp` | At most 120 seconds after `iat`. The reference SDKs use 60. |
| `jti` | A nonce, 1 to 200 characters from `A-Z a-z 0-9 _ -`, unique per token. |

An agent MUST sign a new token for every request, including every retry of a request, MUST give each token a `jti` that no other token of the agent carries, containing bits drawn from a cryptographically secure random source (never a counter, a clock alone or a non-secure generator), and MUST NOT reuse a token. A `jti` SHOULD carry at least 128 random bits. The TypeScript SDK uses `aj_` followed by the base64url of 16 random bytes; the Python SDK uses `aj_`, the time and 48 random bits, which meets the MUST and not the SHOULD.

Example payload:

```json
{
  "iss": "stack-sdk",
  "sub": "agt_8f2c",
  "aud": "stack:agent",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000060,
  "jti": "aj_q3Jm2o1k8nU0b9xWc4TzAw"
}
```

## 4. Verifying an agent JWT

A server that receives a bearer token dispatches on its claims: a token with `iss` equal to `stack-sdk` and a `sub` is an agent JWT; the server then applies the following checks, in this order, before it acts on anything in the request. A token longer than 4096 bytes MUST be refused before it is decoded. Every failure below is the same answer, `401 INVALID_API_KEY` (section 8), so that a caller learns nothing about which check failed, except for a repeat (step 8), which is `401 AGENT_JWT_REPLAYED`.

1. The `sub` is well formed (section 3) and so is the `jti`, and `exp` is an integer.
2. The agent named by `sub` exists, has an enrolled key (a stored public key and an enrollment time), is active and is not blocked from issuing Passports. An agent without an enrolled key is refused: it MUST NOT fall back to any other check.
3. The signature verifies with the stored public key, and `alg` is `EdDSA`. A server MUST reject every other algorithm, including `none`.
4. `iss` is `stack-sdk` and `aud` is `stack:agent`.
5. `exp` is in the future and `nbf`, if present, is not, each allowing the clock tolerance of section 7.
6. `iat` is present, `exp - iat` is at most 120 seconds, and `iat` is not later than the server's time plus the clock tolerance.
7. The operator that owns the agent exists and is active.
8. The `jti` has not been presented before for this agent. The server records the `jti` of every token that passed steps 1 to 7, atomically (a conditional write, so that two concurrent requests with one token cannot both pass), and keeps it until the token can no longer verify: `exp` plus the clock tolerance. A server MUST NOT record a `jti` before the signature has verified, because a record made for an unverified token lets anyone fill the store and burn a nonce that a real agent has yet to use.

A server that cannot read or write the record in step 8, or the agent or operator in steps 2 and 7, answers a retriable `503 SERVICE_UNAVAILABLE` and never accepts the token and never answers `401`: an outage is not a verdict on the credential.

A request authenticated this way acts as the agent, for the operator that owns it. It never carries administrative authority: an agent JWT MUST NOT make the request an operator administrator, a platform administrator or a partner.

## 5. Key enrollment

An agent enrolls its key with two calls. Both are `POST /v1/agents/{agent_id}/…` and both are authenticated by one of:

- an **enrollment ticket** minted for exactly this agent (below), or
- any other credential the server accepts for the operator that owns the agent (an API key, an OAuth access token, a dashboard session) held by a caller that may write to agents (a read-only team member is refused with `403 FORBIDDEN`). Unless it is a dashboard session, such a credential also needs a person's approval of the enrollment (5.2 step 6), which is what stops a credential that belongs to an agent from enrolling keys on its own.

An agent that does not exist, or that belongs to another operator, is `404 NOT_FOUND` on both calls.

### 5.1 Challenge

`POST /v1/agents/{agent_id}/enrollment-challenge` takes no body. It answers `200` with [`schemas/AgentEnrollmentChallengeResult.json`](schemas/AgentEnrollmentChallengeResult.json): a `challenge_id`, a `challenge` of random characters, and `expires_in` (300 seconds). The server stores the challenge bound to the agent, the operator, the team member (if any) and the ticket (if any) that asked for it. A challenge is single-use and is refused after its lifetime.

### 5.2 Enroll

`POST /v1/agents/{agent_id}/enroll` takes [`schemas/AgentEnrollInput.json`](schemas/AgentEnrollInput.json):

| Field | Meaning |
|---|---|
| `public_key` | The agent's new public key: `kty` `OKP`, `crv` `Ed25519`, `x` the 32 key bytes as 43 base64url characters. Other members are ignored and not stored. |
| `challenge_id` | The id the challenge call answered. |
| `signed_challenge` | The Ed25519 signature, by the key in `public_key`, over the UTF-8 bytes of the `challenge` string exactly as the server sent it, base64url. |

The server MUST, in this order:

1. Refuse a body that does not match the schema with `400 VALIDATION_ERROR`.
2. Refuse an agent whose key mode is not `customer_managed` with `409 ENROLL_NOT_APPLICABLE`: STACK holds the key of such an agent and provisions it on first use.
3. Refuse an agent that already has a key, with `409 CONFLICT`, unless the request is a rotation (5.3).
4. Find the challenge by `challenge_id` and refuse the request, with `400 INVALID_ENROLLMENT`, if it is missing, expired or already used, or if it was issued for another agent, another operator, another team member or another ticket than the one now calling. The refusal is the same for each cause.
5. Verify `signed_challenge` against `public_key` and the challenge. A signature that does not verify, or a key that cannot be read, is `400 INVALID_ENROLLMENT`. This proves the caller holds the private key; without it anyone could register a key they do not hold.
6. If the call is not authenticated by a ticket and not by a dashboard session, require a person's approval of this exact enrollment: the server answers `403 GOVERNANCE_APPROVAL_REQUIRED` with the id of a pending approval, a person decides it in the Console, and the caller repeats the identical request with `X-Governance-Approval: <approval id>` (the approval names the agent, the public key and whether it is a rotation, is single-use and lasts 24 hours). The same challenge serves the repeat.
7. Consume the challenge and, for a ticket, the ticket, then store the key and the enrollment time and record the enrollment in the audit log, in one transaction. A ticket is single-use: once an enrollment has used it, a server refuses it on both calls with `401 INVALID_API_KEY`, and of two concurrent `enroll` calls with one ticket only one succeeds (the other is `400 INVALID_ENROLLMENT`). A failure before that transaction commits MUST leave the challenge and the ticket as they were, so that the caller can retry; a failure after it MUST leave them used.

On success the server answers `200` with [`schemas/AgentEnrollResult.json`](schemas/AgentEnrollResult.json): `agent_id` and `enrolled_at`. From then on the agent signs in as in section 3, and the server publishes the key (see the [Agent Keys](../agent-keys/SPEC.md) specification).

### 5.3 Rotation

`POST /v1/agents/{agent_id}/enroll?force=true` replaces the key of an agent that has one. It needs everything in 5.2 and, in addition, an operator administrator: an agent context never rotates a key (`403 FORBIDDEN`), and a rotation without `force=true` on an agent that has a key is `409 CONFLICT`. A server MUST revoke every live Passport of the agent before it stores the new key, so that nothing issued under the old key survives it. The old key stops verifying as soon as the new one is stored.

### 5.4 Enrollment tickets

`POST /v1/agents/{agent_id}/enrollment-tickets` takes `{ "machine_label"? }` ([`schemas/AgentEnrollmentTicketInput.json`](schemas/AgentEnrollmentTicketInput.json)) and answers [`schemas/AgentEnrollmentTicketResult.json`](schemas/AgentEnrollmentTicketResult.json): the `ticket`, its `jti`, `expires_at` and `expires_in` (300 seconds). It is a person's decision: the call needs a dashboard session or the approval of 5.2 step 6, and an agent context never reaches it. The ticket is a JWT signed by the server with the audience `stack:enrollment-ticket`, bound to the operator, the team member, the agent and the machine label. The reference SDK obtains one by opening the dashboard's approval page in the person's browser, which hands the ticket back to a loopback address the SDK listens on; the exchange is the person's, and this specification fixes only what the server accepts.

A server MUST accept a ticket only on the two enrollment calls and only for the agent it names (`403 FORBIDDEN` otherwise), and MUST refuse one that has been used. A ticket that fails verification for any reason (wrong audience, signature or lifetime) is treated as an ordinary bearer credential.

## 6. Fleet enrollment

A fleet lets workers (containers, jobs, short-lived processes) enroll themselves as agents under a policy a person approved, without a person approving each worker. A worker is admitted by one of two **principals** the policy names, and enrolls with the same two-call exchange as in section 5, at different addresses:

| Principal | Challenge | Enroll | Bearer |
|---|---|---|---|
| A **provisioner**: an enrolled agent the policy lists in `provisioner_agent_ids` | `POST /v1/fleets/{policy_id}/enrollment-challenges` | `POST /v1/fleets/{policy_id}/enroll` | An agent JWT of the provisioner, or a fleet session token it obtained from `POST /v1/fleets/session` with one. |
| A **workload**: a process with a SPIFFE or WIMSE identity the policy trusts | `POST /v1/fleets/{policy_id}/workload/enrollment-challenges` | `POST /v1/fleets/{policy_id}/workload/enroll` | The workload's token (the [Workload Identity Exchange](../workload-identity/SPEC.md) specification, section 7), with no other credential. |

`policy_id` is `flp_` followed by `A-Z a-z 0-9 _ -`. The challenge call takes an empty body and answers `200` with [`schemas/FleetEnrollmentChallengeResult.json`](schemas/FleetEnrollmentChallengeResult.json) (`challenge_id`, `challenge`, `expires_in`: 120 seconds). The enroll call takes [`schemas/FleetEnrollmentInput.json`](schemas/FleetEnrollmentInput.json), whose members are exactly:

| Field | Meaning |
|---|---|
| `idempotency_key` | 8 to 128 characters chosen by the worker. One key names one worker identity under one principal. |
| `name` | The agent's name, 1 to 128 characters. |
| `public_key` | The worker's key, as in 5.2. |
| `challenge_id` | The id the challenge call answered. |
| `proof` | The Ed25519 signature, by `public_key`, over the UTF-8 bytes of the `challenge` string. |
| `previous_key_proof` | Present only to replace the key of a worker already enrolled under this `idempotency_key` (6.2). |

A body with any other member is refused with `400 VALIDATION_ERROR`. On success the server answers `201` ([`schemas/FleetEnrollmentResult.json`](schemas/FleetEnrollmentResult.json)) with `agent_id`, `membership_id` and `identity_expires_at`, whether the call created the worker or renewed it. Every other refusal of these calls, whatever the cause (the policy is revoked or expired, the principal is not one the policy names, the challenge is missing, used, expired or another principal's, the proof does not verify, a quota is reached), is the same `403 FORBIDDEN`, so that a caller cannot probe the policy. A server MUST apply every check below before it creates or changes anything, and MUST check the principal again inside the transaction that does:

1. The policy is active, not revoked and not expired, and the principal is one it names (a provisioner by id; a workload by the exact `kind`, `issuer`, `audience` and `subject` of one trust entry, and no other: a token that matches two entries, or none, is refused).
2. The challenge exists, was issued under this policy revision to this same principal (for a workload, to this same token), and is consumed by this call. A challenge is single-use and lasts 120 seconds. A policy revised between the two calls invalidates it.
3. `proof` verifies as in 5.2 step 5. If the workload's token carries a confirmation key (`cnf`), `public_key` MUST be that key.
4. The policy's quotas hold: members at most `max_members`, enrollments in the last hour at most `max_enrollments_per_hour` (challenges count against the hour too), and the operator's allowance of agents.

The worker's agent is created with a `customer_managed` key, enforced accountability and proxy-only credential access. Its identity lease ends at the earliest of the policy's expiry, `identity_lease_seconds` after the call, and (for a workload) the expiry of the workload's token; the worker renews it by enrolling again before then.

### 6.1 Idempotence

A repeat of an enroll call with the same principal, the same `idempotency_key`, the same `name` and the same key (with a fresh challenge and proof) renews the lease and answers the same `agent_id` and `membership_id`. The same `idempotency_key` with another `name`, or by another principal, or after the worker was revoked, is `409 CONFLICT`.

### 6.2 Key replacement

A worker that holds its previous key replaces it by enrolling under the same `idempotency_key` with the new `public_key`, a `proof` of the new key, and a `previous_key_proof`: the old key's signature, base64url, over the UTF-8 string

```
{"challenge":"<challenge>","challenge_id":"<challenge_id>","domain":"stack:fleet-key-rotation:v1","idempotency_key":"<idempotency_key>","policy_id":"<policy_id>","public_key_thumbprint":"<thumbprint>"}
```

with those six members in that order, no whitespace, each value a JSON string, and `thumbprint` the RFC 7638 thumbprint of the new key (the SHA-256 of `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`, base64url). Both proofs are over the same fresh challenge, so neither can be reused. A key change without a valid `previous_key_proof` is `403 FORBIDDEN`; a `previous_key_proof` on a first enrollment is also refused. Once the new key is stored, agent JWTs and fleet sessions signed with the old key no longer verify.

## 7. Constants

<!-- spec:generated:agent-auth-constants -->

| Constant | Value |
|---|---|
| Agent JWT issuer (`iss`) | `stack-sdk` |
| Agent JWT audience (`aud`) | `stack:agent` |
| Signature algorithm | `EdDSA` (Ed25519) |
| Lifetime the SDKs mint | 60 s (1 min) |
| Longest lifetime a verifier accepts | 120 s (2 min) |
| Clock tolerance | 30 s |
| Enrollment challenge lifetime | 300 s (5 min) |
| Enrollment ticket audience | `stack:enrollment-ticket` |
| Enrollment ticket lifetime | 300 s (5 min) |
| Fleet enrollment challenge lifetime | 120 s (2 min) |

<!-- /spec:generated -->

## 8. Errors

Errors use the envelope `{ "error": { "code", "message", "details" } }`.

<!-- spec:generated:agent-auth-errors -->

| Code | HTTP status | Message |
|---|---|---|
| `INVALID_API_KEY` | 401 | Invalid API key |
| `AGENT_JWT_REPLAYED` | 401 | Agent JWT already used - mint a fresh JWT for every request (one JWT = one request; re-sign on retries, never resend the same Authorization header) |
| `FORBIDDEN` | 403 | Forbidden |
| `CONFLICT` | 409 | Conflict |
| `SERVICE_UNAVAILABLE` | 503 | Enrollment temporarily unavailable, please retry |

<!-- /spec:generated -->

Other codes the calls of this specification can answer: `VALIDATION_ERROR` (400, a body that does not match its schema), `INVALID_ENROLLMENT` (400, section 5.2), `ENROLL_NOT_APPLICABLE` (409, section 5.2) and `GOVERNANCE_APPROVAL_REQUIRED` (403, section 5.2). A `503` carries a `Retry-After` header.

## 9. Security considerations

- The private key is the agent's identity. An agent MUST keep it where only its own process can read it (the reference SDKs write it with mode 0600) and MUST NOT send it anywhere, including to STACK.
- A token is a bearer credential for one request, valid for at most 150 seconds including the tolerance. Servers MUST receive it only over TLS and MUST NOT log it. The single-use `jti` is what makes a captured token useless to a second request; this is why a server records it for the whole life of the token and why an agent signs again for every retry.
- Proof of possession matters twice. The enrollment challenge stops anyone enrolling a key they do not hold (and so signing claims in another agent's name); the fleet's rotation message stops a worker from replacing another worker's key by obtaining a challenge of its own.
- Enrollment is a change of who can act as the agent. Outside a person's own browser session or a ticket a person approved, it needs a person's approval of the exact key, so that a stolen operator credential cannot silently add a key of its own. Rotation revokes what the old key's holder was given.
- Servers answer one refusal for every failed agent JWT check, and one `403` for every failed fleet enrollment, so that neither endpoint tells an attacker what is missing.
- The agent JWT does not carry what the agent may do. Authority comes from the Passport the agent then obtains and from the grants of its operator, never from signing in.

## 10. Machine-readable schemas and conformance

The JSON Schemas in [`schemas/`](schemas/) (draft-07) are generated from the reference implementation: `AgentJwtClaims`, `AgentEnrollmentChallengeResult`, `AgentEnrollInput`, `AgentEnrollResult`, `AgentEnrollmentTicketInput`, `AgentEnrollmentTicketResult`, `FleetEnrollmentInput`, `FleetEnrollmentChallengeResult` and `FleetEnrollmentResult`. Where a schema and this text disagree, report it as a defect; the schema is what the reference implementation enforces.

Conformance tests are in [`../conformance/`](../conformance/README.md): `agent-jwt` runs against an agent-side minter (an SDK) and a server-side verifier (a function), and `agent-enrollment` runs against a server's enrollment calls, key publication and sign-in.
