# STACK Web Bot Auth Profile

**Specification:** STACK Web Bot Auth Profile
**Version:** 1.1.0
**Status:** Stable
**Licence:** Apache-2.0

A site that wants to know whether a request comes from an AI agent, and whose, can check an HTTP message signature on it. STACK signs the outbound requests of an agent's account (the requests the agent makes through STACK's proxy and its cloud browser) with HTTP Message Signatures, names where the public keys are published, and publishes them. This document is the profile of the IETF Web Bot Auth drafts and of RFC 9421 that STACK follows: what a signed request carries, how the signature base is built, how a key directory is served and signed, how an account owner manages the keys, and what a site that checks must do.

The profile follows RFC 9421 (HTTP Message Signatures), RFC 8941 (Structured Field Values), RFC 7638 and RFC 8037 appendix A.3 (the JWK thumbprint of an Ed25519 key), and two IETF drafts, `draft-meunier-web-bot-auth-architecture` (the signature profile and its test vectors) and `draft-meunier-http-message-signatures-directory` (the key directory). Both are individual drafts, replaced by the working group's `draft-ietf-webbotauth-*` documents; where this profile makes a choice the drafts leave open it says so.

Contents: 1 Conventions, 2 Overview, 3 The signed request, 4 Keys, 5 The key directory, 6 Managing an account's keys, 7 What a site must do, 8 Security considerations, 9 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. Three roles are used: the **signer** adds the signature to a request it sends, the **site** is the server that receives the request and checks it, and the **directory** is the document that publishes the signer's public keys. A signer conforms to this specification if it satisfies every MUST in sections 3 and 4; a server of a directory if it satisfies every MUST in section 5; a site if it satisfies every MUST in section 7. The conformance kit in [`../conformance/`](../conformance/README.md) (the `web-bot-auth` suite) tests exactly that.

Times are Unix time in seconds. Binary values in a `Signature` header are standard base64 (RFC 4648 section 4); a key's `x`, a `kid`, a `keyid` and a `nonce` are base64url without padding (RFC 4648 section 5).

## 2. Overview

- **What is signed.** A request that an agent's account makes through STACK to a site. The signature identifies the account's key, not the agent's behaviour: it says that STACK sent the request on behalf of an account that holds this key, and nothing more.
- **Added, never required.** A signature is added to a request when STACK can make it. A request that cannot be signed (the key service is unavailable) is sent without one, and the failure is logged. A site MUST NOT treat the absence of a signature as evidence about the sender, and a signer MUST NOT treat a signature as a control on what the agent may do.
- **One key per account.** An account has one Ed25519 key in use. The keys of every account that has signed are published together in STACK's public directory, under opaque thumbprints: the directory names no account, agent or customer. STACK also serves the directory of one account's own keys, on its own domain and under the agent's id (section 5.6): an agent's site serves only what the agent publishes, never a key directory made by STACK.
- **The two documents.** A signed request carries a `Signature-Agent` header that names the origin of a directory. The site fetches `/.well-known/http-message-signatures-directory` there, finds the key by the request's `keyid`, and checks the signature.

## 3. The signed request

### 3.1 Headers

A signed request carries these headers, beside the ones it would carry anyway:

| Header | Value |
|---|---|
| `Signature-Input` | One dictionary member: `sig1=` and an inner list of the covered components with the signature parameters. Section 3.2 and 3.3. |
| `Signature` | One member: `sig1=:` and the base64 of the 64-byte Ed25519 signature `:`. |
| `Signature-Agent` | `sig1="https://api.getstack.run"`: a dictionary member with the same label as the signature, whose value is the https origin of the directory. Present when the signer has a directory to name (section 3.4). |

The label is `sig1`. A request MAY carry other signatures under other labels (a site or an intermediary can add its own); a site finds the one that is Web Bot Auth by its `tag` (section 7).

### 3.2 Covered components

The covered components are, in this order:

1. `"@authority"`
2. `"@method"`
3. `"@path"`
4. `"signature-agent";key="sig1"`, when a `Signature-Agent` header is sent

so that a signature is no good for another host, another verb or another resource, and the directory that vouches for the key cannot be changed after signing. The query, the body and every other header are NOT covered (section 8). A signer MUST cover `@authority`, `@method` and `@path`, and MUST cover `Signature-Agent` whenever it sends one.

The values of the components are those of RFC 9421 section 2.2, of the request as it is sent to the site:

| Component | Value |
|---|---|
| `@authority` | The host of the request URL in lower case, followed by `:` and the port when the port is not the default of the scheme. |
| `@method` | The method, in upper case. |
| `@path` | The absolute path of the URL as it is sent, percent-encoding unchanged; `/` when the path is empty. The query is not part of it. |
| `signature-agent;key="sig1"` | The member `sig1` of the `Signature-Agent` header, serialised: with its quotes, as `"https://api.getstack.run"`. |

### 3.3 Parameters

The signature parameters follow the inner list, in this order:

| Parameter | Value |
|---|---|
| `created` | The time of signing, an integer. |
| `keyid` | The JWK thumbprint of the key (section 4), a string. |
| `alg` | `"ed25519"`. |
| `expires` | `created` plus 300, an integer: a signature is for one request. A signer MUST NOT set it more than 86400 seconds after `created`, and SHOULD NOT set it more than 300 seconds after. |
| `nonce` | 64 random bytes, base64url without padding (86 characters), different for every signature. |
| `tag` | `"web-bot-auth"`. |

Strings are RFC 8941 strings (printable ASCII, `"` and `\` escaped); integers are written without a sign or leading zeros. The `@signature-params` value is the inner list followed by the parameters exactly as they appear after `sig1=` in `Signature-Input`.

### 3.4 Signature-Agent

`Signature-Agent` names the directory. The value of the `sig1` member MUST be an https origin: scheme `https`, a host, an optional port, and no path (other than `/`), query, fragment or credentials. A signer writes the origin without a trailing slash. A signer that has no such origin to name (its address is not https, as a local development server's is) MUST send no `Signature-Agent` and MUST NOT cover it; the request is signed over the three derived components alone.

### 3.5 The signature base

The signature base is built as RFC 9421 section 2.5 says: one line for each covered component, `<identifier>: <value>`, in the order of the inner list, then the line `"@signature-params": <value>`, the lines joined by a line feed with no line feed at the end. The signature is Ed25519 (RFC 8032, pure, no pre-hash) over the UTF-8 bytes of the base, base64 encoded.

For `GET https://shop.example/products/42?utm=1` signed at 1790000000 with a directory at `https://agent.example`, the base is:

```
"@authority": shop.example
"@method": GET
"@path": /products/42
"signature-agent";key="sig1": "https://agent.example"
"@signature-params": ("@authority" "@method" "@path" "signature-agent";key="sig1");created=1790000000;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1790000300;nonce="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";tag="web-bot-auth"
```

and the request carries:

```
Signature-Input: sig1=("@authority" "@method" "@path" "signature-agent";key="sig1");created=1790000000;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1790000300;nonce="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";tag="web-bot-auth"
Signature: sig1=:Mu6RXTr9GPebOkQuKqkHzXvtjDlNIdXGEsl5BXPXZIPBEqEHTsZpElJacr0cPOp2WaYWRXo11EojeNIMLyQgDg==:
Signature-Agent: sig1="https://agent.example"
```

The key in that example is the Ed25519 test key of RFC 9421 appendix B.1.4 (it is public: never use it for anything but vectors). The vectors of the conformance kit ([`../conformance/fixtures/web-bot-auth/vectors.json`](../conformance/fixtures/web-bot-auth/vectors.json)) hold this request, one without a `Signature-Agent` and with an upper-case host, a port and an escaped path, the directory response of section 5, and the published vectors of RFC 9421 appendix B.2.6 and of the architecture draft appendix A.2. They are written by [`../conformance/scripts/build-web-bot-auth-vectors.mjs`](../conformance/scripts/build-web-bot-auth-vectors.mjs); Ed25519 is deterministic, so the same inputs give the same bytes.

## 4. Keys

- **Algorithm.** Ed25519 (RFC 8037). The signature algorithm in `alg` is `ed25519`.
- **Identity.** A key is named by its JWK thumbprint: SHA-256 (RFC 7638) over the JSON object `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` with the members in that order and no whitespace, base64url without padding. That string is the `keyid` of every signature the key makes and the `kid` of the key in the directory. The thumbprint of the RFC 9421 test key is `poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`.
- **One in use per account.** An account signs with one key at a time. The key is made on the account's first use of it, under a lock, so two machines never make two. Its private half is kept only as a KMS envelope bound to the account's owner and to this purpose, and is never readable by the account, its agent or its owner.
- **Rotation.** The owner (never the agent: an agent that could rotate its own key could shake off a site's ban on it) asks for a new key (section 6). The old key is retired: it stays in the directory for 48 hours, with an `exp`, so a signature made just before the rotation stays verifiable, and then it is no longer published.
- **Closing.** When an account is closing or closed its keys stop being published at once.
- **STACK's directory key.** STACK's public directory is signed by its own key, held like the others, which is listed in the directory beside the accounts' keys.

## 5. The key directory

### 5.1 Where

`GET /.well-known/http-message-signatures-directory` at the origin a `Signature-Agent` names. STACK's hosted service serves it at its API origin. The path is public and needs no credential.

### 5.2 The response

| | |
|---|---|
| Status | `200`. |
| `Content-Type` | `application/http-message-signatures-directory+json`. |
| `Cache-Control` | `public` with a `max-age`: STACK sets 300. A key is made on its first use, so a site that misses a `keyid` fetches the directory again (section 7). |
| `Signature-Input`, `Signature` | The signature of section 5.4. |

The server rebuilds a directory at most every 30 seconds for one host: the `created` of its signature can be up to that old.

### 5.3 The body

A JWK Set (RFC 7517 section 5) of public keys:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
      "kid": "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
      "use": "sig",
      "nbf": 1789996400
    }
  ]
}
```

| Member | Meaning |
|---|---|
| `kty`, `crv`, `x` | `OKP`, `Ed25519` and the base64url public key (43 characters). |
| `kid` | The JWK thumbprint of the key (section 4). A directory of this profile always carries it. |
| `use` | `sig`. |
| `nbf` | When the key came into use, an integer. A signature made before it is not the key's. |
| `exp` | Present only on a retired key: when it stops being published, an integer after `nbf`. Absent for a key in use. A signature made at or after it is not the key's. |

A directory MUST NOT carry a private member (`d`) of any key, and MUST carry at least one key. The public directory lists STACK's directory key and every account key in use or retiring, and at most 5000 keys; it contains nothing that names an account, an agent or a customer.

### 5.4 The signature of the response

The response is signed by the directory's own key, so a site that has the directory knows who served it. The `Signature-Input` has one member, `sig1`, over the response's request: its inner list is `("@authority";req)` and its parameters, in this order, are `created`, `keyid` (the thumbprint of a key that is listed in the same directory), `alg="ed25519"`, `expires` and `tag="http-message-signatures-directory"`. `expires` is after `created` and at most 86400 seconds after it: STACK sets `created` plus 86400. The signature base is two lines:

```
"@authority";req: api.getstack.run
"@signature-params": ("@authority";req);created=1790000000;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1790086400;tag="http-message-signatures-directory"
```

where the authority is the lower-case `Host` the client asked, with its port when it has one and it is not the default of the scheme. The signature is therefore bound to the host asked: a directory signed for one host does not verify for another. A server of a directory MUST sign for the host the request came to, and MUST list the signing key in the body.

### 5.5 Dates

`nbf` is the key's creation time, and `exp` is the retirement time plus 48 hours. A directory does not list a key after `exp`.

### 5.6 An account's own directory

STACK also serves the directory of one account's keys alone, on its own domain, at `GET /v1/agent-identity/agents/{agent_id}/http-message-signatures-directory` ([`../agent-identity/SPEC.md`](../agent-identity/SPEC.md) section 8), so someone who has an agent's signed card can check it against the keys of the requests that agent signs without reading the public directory of every account. It has the body, the media type and the signature rules above: the account's keys only (the key in use first, then a retiring one), signed by the key in use over the host the request came to, public and without a credential. It is served only for an agent that is active or suspended and whose owner has not switched its public answer off; for any other the answer is the one an unknown agent gets. An agent's own site does not serve it: a site serves only what its agent publishes, and the `Signature-Agent` of a signed request names STACK's origin, never the site.

## 6. Managing an account's keys

The calls need the account's owner or an administrator of it; the agent may read but never rotate. They are configuration: never metered, never asked of the customer's decider.

| Call | Answer |
|---|---|
| `GET /v1/accounts/{id}/signing-keys` | `200` `{ "keys": [View] }`, the key in use first. |
| `POST /v1/accounts/{id}/signing-keys/rotate` | `200` `{ "keys": [View] }`: a new key signs from now on, the old one is retiring. Owner or administrator only; agent contexts are refused. At most 10 a minute. |

A key view:

| Field | Meaning |
|---|---|
| `key_id` | The thumbprint: the `keyid` of its signatures and its `kid`. |
| `public_key` | The base64url public key (`x`). |
| `status` | `active` or `retiring`. |
| `created_at` | When the key came into use, ISO 8601. |
| `retired_at`, `publish_until` | For a retiring key, when it was retired and when it stops being published; otherwise null. |

An account that is not the caller's is a `404`. A rotation is an audited action of the account.

## 7. What a site must do

A site that checks a request:

1. MUST find the signature by its tag: a member of `Signature-Input` with `tag="web-bot-auth"` and the member of `Signature` with the same label. A request may carry other signatures; they are not this one. A request with no such signature is not a signed request.
2. MUST require `alg` to be absent or `"ed25519"`, and MUST require `created`, `expires` and `keyid`.
3. MUST require `@authority` to be covered, and MUST rebuild the signature base from the request it received (its own host, method and path), not from what the signature claims. A signature made for another host, verb or path does not verify.
4. MUST refuse the signature when the clock is at or after `expires`, or when `created` is more than 60 seconds ahead of its clock. A site SHOULD refuse a signature whose `expires` is more than 86400 seconds after `created`.
5. MUST find the key in a directory named by a covered `Signature-Agent`: the member with the signature's label, an https origin (section 3.4). A site MUST NOT look for a key at the origin of a `Signature-Agent` header the signature does not cover, and MUST refuse a `Signature-Agent` that is not an https origin, or whose covered value is not the one that was sent. A site that has its own list of trusted agents MAY use it instead.
6. MUST fetch `/.well-known/http-message-signatures-directory` at that origin without credentials and without following redirects, MUST refuse a directory that does not answer `200`, is not a JWK Set or has no keys, and MUST find the key whose JWK thumbprint (section 4) is the `keyid`; the `kid` of a key, when it has one, is that thumbprint. A site SHOULD keep a directory for its `max-age` and, when a `keyid` is not in the one it holds, fetch it again once before it refuses. A site SHOULD verify the directory's own signature (section 5.4): signed by a key it lists, for the host it asked, with the tag `http-message-signatures-directory`.
7. MUST refuse a signature made before the key's `nbf` (by more than 60 seconds) and one made at or after its `exp`.
8. MUST verify the Ed25519 signature over the rebuilt base with that key, and accept the request only if it verifies.
9. SHOULD remember the `nonce` of every signature it accepts until its `expires`, and refuse a repeat.
10. MUST treat a header it cannot read (not a dictionary, an inner list that is not closed, a signature that is not a byte sequence) as a request that failed the check, never as one that passed it, and never fail with an error that lets the request through.

A site that accepts a signed request knows that STACK sent it for an account that holds that key. It does not know that the query, the body or any header besides the three covered ones are what STACK sent. What it does with that knowledge is its own policy.

## 8. Security considerations

- **What is bound.** Only the host, the method, the path and the directory are covered. A signature made for `GET /products/42?a=1` also verifies for `GET /products/42?a=2`, and for the same request with another body or another header. A site that needs the body or a header bound MUST NOT rely on this signature for it.
- **Replay.** A signature lives five minutes and carries a nonce. A captured request can be replayed to the same host, method and path within that window, with whatever query and body the attacker likes. A site that cannot accept this remembers nonces (rule 9).
- **The directory is the root of trust.** Whoever controls the origin in `Signature-Agent` decides which keys vouch for requests. That is why the header is covered, must be an https origin and is never taken from an unsigned header, and why a site that cares trusts a list of origins rather than any origin a request names.
- **Key leakage.** A leaked private key lets its holder sign as the account until the key is rotated and retires. A site that learns of a leak refuses the `keyid`; the owner rotates (section 6). Retiring keys stay published for 48 hours, so a site SHOULD NOT treat a retiring key as a fresh one: it checks `created` against `nbf` and `exp`.
- **Absence of a signature.** A signature is added when it can be made. A site MUST NOT infer from an unsigned request that the sender is not an agent of an account.
- **Clock.** A site with a clock more than the 60 seconds of skew from real time refuses signatures that are valid.
- **Fetching a directory.** A site fetches an origin that a request names. It SHOULD refuse origins that resolve to its own network, apply the usual limits on size and time, and not follow redirects.

## 9. Conformance

The `web-bot-auth` suite of the [conformance kit](../conformance/README.md) judges the three roles. Given a signer, it checks the headers, the covered components, the parameters, the thumbprint, the nonce and the signature against a signature base it builds itself. Given a site's verifier and a `fetch` that serves directories, it signs requests with the kit's own key and damages them one way at a time (another host, verb or path, an expired or future `created`, a missing parameter, another tag or algorithm, an uncovered `@authority`, an uncovered or changed `Signature-Agent`, a directory that is not https, a key that is not listed, a signature before `nbf` or after `exp`, a malformed header, a directory that fails) and checks that the verifier accepts the requests that are right and refuses the others. Given a directory, it checks the status, the media type, the key set, that no private member is published, the thumbprints, the dates, and the signature, including that it is bound to the host asked. It judges STACK's public directory and the directory of one account (section 5.6) alike.

The reference signer, verifier and directory in `conformance/reference/web-bot-auth-reference.mjs`, written from this document with `node:crypto` alone, pass the suite, and STACK's own signer and its directories (the public one and the one of an account) pass it in the continuous integration of STACK's hosted service.
