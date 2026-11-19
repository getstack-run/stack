# STACK Agent Keys

**Specification:** STACK Agent Keys
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

Every agent has a key of its own. This document defines the key identifier an agent's key carries, the public key set STACK publishes for it so that anyone can verify what the agent signed, how a customer who holds the agent's private key signs a claim envelope with it, and how a verifier checks such a claim. It builds on the claim envelope and the COSE_Sign1 profile of the [Record Format](../record/SPEC.md) and on the enrollment of the [Agent Runtime Sign-in](../agent-auth/SPEC.md) specification.

Contents: 1 Conventions, 2 Model, 3 Key identifiers, 4 The agent key set, 5 Signing a claim, 6 Verifying a claim, 7 What this version does not define, 8 Security considerations, 9 Machine-readable schemas and conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. Binary values are base64url without padding. A **signer** produces claims; a **verifier** checks them; a **key set** client fetches the published key set. A signer conforms if it satisfies the MUSTs of section 5 and a verifier if it satisfies those of section 6. The conformance kit (the `agent-keys` suite) tests both and the published key set.

## 2. Model

- An agent's key is an Ed25519 key pair. Who holds the private half depends on the agent's **key mode**:

| Key mode | Private key held by | Who signs the agent's claims |
|---|---|---|
| `customer_managed` | The customer, on their own machine. STACK stores the public key given at enrollment. | The customer, with the helper of section 5. STACK cannot sign for the agent. |
| `stack_managed` | STACK, wrapped by its key service. The key is made when the agent first signs. | STACK. |
| `co_signed` | STACK, as for `stack_managed`. | STACK, and the operator's own claim key adds a second signature, the `operator_attestation` co-signature of the Record Format. |

- The key set the agent publishes (section 4) is the same for the three modes: it carries the public key, whoever holds the private one.
- A **claim** is a signed fact STACK records, whose envelope and signing are defined by the Record Format. This specification covers the claims that an agent's own key signs.

## 3. Key identifiers

The key of an agent has the identifier

```
agent:{agent_id}:v1
```

where `agent_id` is the agent's id, as in `agent:agt_8f2c:v1`. The suffix `v1` is the only value this version defines: it does **not** change when the key is replaced (a rotation, [Agent Runtime Sign-in](../agent-auth/SPEC.md) section 5.3), because the published key set carries only the current key (section 4). A verifier MUST NOT infer trust from the shape of an identifier (as the Record Format also says): the identifier names which key to look up, and trust comes from where the key is looked up.

## 4. The agent key set

`GET /v1/agents/{agent_id}/.well-known/jwks.json` answers a JSON Web Key Set (RFC 7517) with no authentication. The key is public material.

The answer is `200` with [`schemas/AgentJwks.json`](schemas/AgentJwks.json): `{ "keys": [ … ] }` holding exactly one key in this version, described by [`schemas/AgentJwk.json`](schemas/AgentJwk.json):

| Member | Value |
|---|---|
| `kty`, `crv` | `OKP` and `Ed25519`. |
| `x` | The public key, 43 base64url characters. |
| `kid` | `agent:{agent_id}:v1`. |
| `alg`, `use` | `EdDSA` and `sig`. |
| `not_before` | When the key was enrolled or first provisioned, in Unix milliseconds, or `null`. |
| `not_after` | `null`: the key in the set is the current one. A later version may keep a replaced key in the set and put the time of its replacement here. |

`not_before` and `not_after` are informational (RFC 7517 section 4: a reader ignores members it does not know). A verifier selects the key by `kid`, not by the window.

The server answers `404 SIGNING_KEY_UNAVAILABLE` for an agent that does not exist and for an agent that has no key yet (a `customer_managed` agent that has not enrolled, a `stack_managed` agent that has never signed), in both cases with the same body, so that the endpoint does not reveal which agent ids exist, and so that a verifier does not cache an empty set. A server MAY answer `403 FORBIDDEN` for an agent it uses for its own purposes. A verifier SHOULD cache the set for a short time and MUST re-fetch it, rate-limited, when it meets a `kid` it does not hold.

## 5. Signing a claim

A customer who holds an agent's private key signs a claim envelope locally. A signer MUST produce a COSE_Sign1 message (RFC 9052) exactly as the Record Format section 4.4 defines it, with these particulars for an agent's key:

1. The payload is the CBOR encoding of the claim envelope ([Record Format](../record/SPEC.md) section 4). The signer does not validate the envelope against its claim type; the receiving side does.
2. The protected header is a CBOR map with label `1` (`alg`) equal to `-8` (EdDSA), label `4` (`kid`) equal to the UTF-8 bytes of `agent:{agent_id}:v1` as a byte string, and label `16` (`typ`) equal to the text `stack/claim+cose`. The map is serialised as the Record Format says.
3. The signature is Ed25519 (RFC 8032), over the CBOR encoding of `["Signature1", protected, h'', payload]` (RFC 9052 section 4.4) with an empty external authenticated data.
4. The message is `[protected, {}, payload, signature]`, encoded as CBOR and then as base64url. The unprotected header is empty.

A signer MUST use the private key whose public half is the one STACK has for the agent, and MUST use the agent's own `kid`. It MUST NOT sign with the identifier of another agent, or of the operator's claim key.

The signing algorithm is `EdDSA` only. The identifier of a post-quantum algorithm is reserved: a signer MUST refuse to sign with an algorithm this version does not define, and MUST NOT silently fall back to another.

## 6. Verifying a claim

A verifier is given a base64url COSE_Sign1 message and the key set of the agent it expects. For a claim from an agent whose key mode is `customer_managed` it MUST:

1. Decode the message as the Record Format section 4.4 requires, and refuse it if it is not a four-element array, if the protected header is not a map, or if `alg` is not `-8`.
2. Read the `kid` from the protected header (a byte string, or a text string) and refuse the message if it is missing or empty.
3. Accept only the `kid` `agent:{agent_id}:v1` of the agent the claim is checked for. A message whose `kid` names another agent, the operator's key or any other key MUST be refused, even if its signature would verify against some key in the key set: a customer who enrolled a key for one agent must not be able to submit a message that speaks for another.
4. Find the keys in the key set whose `kid` equals that identifier exactly (several entries that are the same key, by RFC 7638 thumbprint, count as one), and refuse the message if there is none. A candidate key MUST be refused, and with it the message, if it carries private key material (a `d` member), if its `alg` is present and not `EdDSA`, if its `use` is present and not `sig`, or if it cannot be read as an Ed25519 key. If more than one distinct key verifies the signature, the message is refused as ambiguous.
5. Rebuild `Sig_structure1` from the protected bytes and payload bytes **as they are on the wire** (not by encoding the decoded values again) and verify the signature. A signature that does not verify fails the message; so does a payload or a protected header that was changed after signing.

A verifier of a claim from a `stack_managed` agent applies steps 1, 2, 4 and 5 against the agent's key set. A verifier of a `co_signed` claim also requires an `operator_attestation` co-signature that verifies against the operator's key set, under the Record Format's co-signature rules; a claim without one, or with one that does not verify, is refused even when the agent's own signature is good.

A result of the verifier carries the decoded envelope only when every check passed.

## 7. What this version does not define

- **Submission.** This version defines how a claim is signed and verified. It does not define an endpoint that accepts a pre-signed claim: the hosted API does not take one over HTTP today, and STACK signs the claims of its own agents itself. A customer uses the signing helper (the reference SDKs `signClaimEnvelope` and `sign_claim_envelope`, and the command `agent sign-claim`) to produce messages that a verifier of this specification accepts.
- **Rotation history.** The key set holds the current key only. After a rotation, a message signed with the previous key no longer verifies against the published set. A party that must verify old messages keeps its own copy of the key set it verified them against, or of the messages' verification result.
- **Other algorithms.** Only EdDSA over Ed25519.

## 8. Security considerations

- The key set is trusted because of where it is fetched from: over TLS, from the issuer's own address. A verifier MUST NOT take a key from the message it is verifying.
- The proof of possession at enrollment is what makes the published key the agent's: STACK stores a public key only after the caller signed a fresh challenge with the private half.
- Pinning the identifier (section 6, step 3) closes the confusion between an agent's key and the operator's keys: a verifier that resolves any identifier it is shown against any key set it holds can be made to accept a message signed by the wrong party.
- A customer-held key means STACK cannot produce a valid claim for that agent. A claim that verifies under it was signed by someone who held the private key.
- A key set that names a key but never a revoked one is not a revocation list. A leaked agent key is handled by rotating it, which revokes the agent's Passports ([Agent Runtime Sign-in](../agent-auth/SPEC.md) section 5.3).

## 9. Machine-readable schemas and conformance

[`schemas/`](schemas/) holds `AgentJwk` and `AgentJwks` (draft-07), generated from the reference implementation. Conformance tests are in [`../conformance/`](../conformance/README.md): the `agent-keys` suite takes a signer (an SDK function or program), a verifier (a function) and, optionally, the base address of a server, whose key-set endpoint it checks.
