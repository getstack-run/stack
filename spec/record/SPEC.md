# STACK Record Format

**Specification:** STACK Record Format
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

The record is how STACK writes down what an AI agent did, in a form that anyone can check without asking STACK. It has three parts: signed claims (one signed statement per recorded fact), a hash-chained audit log (an ordered, tamper-evident list of what happened), and the evidence pack (one JSON file that carries a set of claims, the keys and schemas needed to check them, and a signed summary of the whole). This document defines the byte-level formats of all three and the algorithm a verifier follows to check an evidence pack offline.

Contents: 1 Conventions, 2 Scope and threat model, 3 Canonical JSON and encodings, 4 Signed claims, 5 Audit hash chain, 6 Merkle rule, 7 Evidence packs, 8 Verification procedure, 9 Activity reconstruction, 10 Conformance, 11 Machine-readable schemas, 12 Worked example, 13 Versioning and compatibility, Appendix A Example manifest.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

- A **producer** is software that writes claims, audit entries or evidence packs. A **verifier** is software that checks an evidence pack. A **relying party** is the person or organisation that acts on a verifier's result.
- An **operator** is the customer account that owns agents. Operator identifiers match `^op_[\w-]+$`.
- The **STACK system key** is the signing key that STACK operates for the whole deployment, as distinct from the per-operator claim signing keys.
- A **pack** is an evidence pack manifest, the JSON file defined in Section 7. A **pack claim** is the signed claim of type `evidence_pack` that the manifest carries.
- All JSON is UTF-8. Timestamps are integers counting milliseconds since the Unix epoch (`_ms` suffix, or `issued_at`).
- **hex** means lowercase hexadecimal with no separators. A **prefixed hash** is the string `sha256:` followed by 64 hex characters. A **bare hash** is the 64 hex characters alone. Each field in this document says which form it uses.
- **base64url** is the URL-safe alphabet of RFC 4648 Section 5 without padding. Producers MUST NOT emit padding. Verifiers MUST accept unpadded input.
- SHA-256 is FIPS 180-4. Ed25519 is RFC 8032 (pure EdDSA, no pre-hash).
- `valid` and `complete` are the two verdict flags of Section 8. They are different things and are never combined.
- Where this document says a verifier "reports" a code, the code is one of those listed in Section 8.4 and 8.5. A verifier MUST NOT report a code that this document does not list for the condition at hand, because conformance (Section 10) compares code sets.
- Identifier prefixes (`op_`, `pc_`, `pck_`, `ms_`) are conventions of the reference implementation. A verifier MUST NOT depend on them except where this document states a pattern.

## 2. Scope and threat model

### 2.1 Scope

This document defines:

- the claim envelope and the COSE_Sign1 profile that signs it (Section 4);
- the audit entry hash, versions 1 and 2, and the chain it forms (Section 5);
- the Merkle rule that commits an evidence pack to its set of claims (Section 6);
- the evidence pack manifest and pack claim (Section 7);
- the verification procedure and its result (Section 8);
- an optional reconstruction of an agent's activity from a verified pack (Section 9).

It does not define how claims are authorised, how Passports are issued (see the STACK Passport specification), how packs are stored or transported, the meaning of each claim type's payload (the per-type JSON Schemas in Section 11 do that), or any live service interface other than the two public key-set locations in Section 4.5.

### 2.2 What a successful verification establishes

If a verifier returns `valid: true` for a pack, then, relative to the key sets and schemas inside that pack:

1. **Integrity.** Every signed claim envelope, and the pack claim, is exactly the byte string its signer signed. Each `claim_hash` is the SHA-256 of those bytes.
2. **Internal consistency.** The set of claims in the pack is the set the pack claim commits to: its count, its Merkle root, and the hash over the rest of the manifest (including the keys and schemas) match. A claim cannot be added, removed, reordered or edited without breaking a signed value.
3. **Signer binding.** Each signature verifies under a key that appears in the pack's own key sets, under the rules of Section 4.5. Every inner claim names the same issuer as the pack claim.
4. **Schema pinning.** For every inline schema, the pack claim pins its hash, so a reader can tell which schema a claim was written against.
5. **Head signature.** The audit chain head hash and time named in the pack claim carry a valid signature by a key in the pack.
6. **Exact review links.** Where the pack contains operator decisions, checkpoints, detector alerts and reviews, the references between them resolve to claims inside the pack and agree on mission and operator.

### 2.3 What it does not establish

A relying party MUST read the following as limits of the format, not as defects of a particular verifier.

- **Internal integrity, not independent truth.** A claim records what the operator's runtime stated and signed. The record shows that the statements were made, by whom, in what order and that they were not altered afterwards. It does not show that the statements are true of the outside world.
- **Key authenticity.** The key sets are carried inside the pack. A verifier that trusts only the pack proves the pack agrees with itself; anyone who holds a signing key can build a pack that does. To establish that a key belongs to a given operator or to STACK, the relying party MUST obtain the key set independently, either from the two locations in Section 4.5 at a time it trusts or from a copy pinned in advance, and compare it with the pack's inline copy. This document defines no offline mechanism for that comparison; verifiers are encouraged to let the user supply trusted key thumbprints.
- **Collusion of the operator and STACK.** The pack claim is signed by the operator key and, when present, co-signed by the STACK system key. A party that controls both keys can produce a self-consistent false pack. The two signatures defend against one party acting alone, not against both.
- **Omission.** The Merkle root commits to the claims the producer put in the pack. It does not prove that the producer included every claim that exists for the scope. Detecting later omission relies on the audit chain, the signed head and external anchors, and an omission made shortly before an anchor is published may not be detectable.
- **Revocation freshness.** Each claim entry carries `revoked_at_ms` as of `revocation_snapshot_at_ms`. A verifier reports the count and does not treat revoked claims as invalid. Whether a claim or Passport is revoked now is a live question that a pack cannot answer.
- **Key compromise.** If a signing key was compromised, claims forged under it before revocation verify normally.
- **Placeholder or missing anchors.** A pack with no external chain anchor, a synthetic (`noop://`) anchor, no usable audit inclusion proofs or no STACK co-signature is still `valid` if everything that is present checks out, but it is not `complete`. Section 8.3 defines the distinction.
- **Payload semantics.** This version defines no result code for a claim payload that violates its claim type's schema. Section 7.5 explains how schemas are pinned.

## 3. Canonical JSON and encodings

### 3.1 Canonical JSON

Canonical JSON is the byte string over which several hashes in this document are computed. It is defined on JSON values (null, booleans, numbers, strings, arrays, objects). The serialisation `C(v)` is:

1. `null` is `null`; booleans are `true` and `false`.
2. A string is written as a JSON string literal exactly as ECMAScript `JSON.stringify` writes it: delimited by `"`; `"` and `\` escaped with a backslash; the control characters U+0008, U+0009, U+000A, U+000C and U+000D written as `\b`, `\t`, `\n`, `\f` and `\r`; every other control character below U+0020 written as `\u` followed by four lowercase hex digits; lone surrogates written as `\u` plus lowercase hex; every other character written literally.
3. A number is written as ECMAScript `Number::toString` writes it (RFC 8785 Section 3.2.2.3). Negative zero is written `0`.
4. An array is `[` followed by the serialisations of its elements, in order, separated by `,`, followed by `]`.
5. An object is `{` followed by its members, separated by `,`, followed by `}`. Each member is the serialisation of the key as a string, a `:`, and the serialisation of the value. Members are ordered by key, ascending, comparing the keys as sequences of UTF-16 code units. A member whose value is `undefined` (absent in the source value) is omitted. Duplicate keys do not occur.
6. There is no whitespace outside string literals.

The canonical bytes are the UTF-8 encoding of `C(v)`. For the value domain of this document (strings, booleans, null, arrays, objects and integers) this is identical to RFC 8785 JSON Canonicalization Scheme.

**Floats are not used.** Every numeric field in the manifest and in the hashed parts of the pack claim is an integer, and producers MUST NOT put a non-integer number into any structure that is canonicalised. Rule 3 states what happens if one is present (for example inside an inline JSON Schema body) so that independent implementations still agree. Numbers whose magnitude exceeds 2^53 MUST NOT be used.

**Undefined omission.** Rule 5 means that an optional member that a producer did not set is simply absent from the canonical form. A manifest read from a file never contains `undefined`; the rule matters to producers that hold values in memory.

Example. The value `{"b":1,"a":{"d":null,"c":[2,1]},"e":"é","f":"x\"y","g":false}` has the canonical form

```
{"a":{"c":[2,1],"d":null},"b":1,"e":"é","f":"x\"y","g":false}
```

whose UTF-8 SHA-256 is `349db78e528b9be316930719a674e04abdb110c56e4fa1fd645093a89377ec42`.

### 3.2 Where canonical JSON is used

| Use | Input | Result |
|---|---|---|
| Pack `content_hash` | the five-member skeleton of Section 7.2 | prefixed hash |
| Inline schema `content_hash` | the entry's `json_schema` value | prefixed hash |
| Head signature surface | `{head_at_ms, head_hash}` of the pack claim | signed bytes (Section 5.5) |

Audit entry hashes (Section 5) do NOT use canonical JSON. They use a fixed member order defined there.

### 3.3 Hashes and encodings

- `claim_hash` and every other bare hash is the SHA-256 of the stated bytes, as hex.
- A prefixed hash is `sha256:` plus the same hex.
- Signatures and COSE messages are carried as base64url strings.
- Verifiers MUST compare hashes as exact, case-sensitive strings. An uppercase hex digest does not match a lowercase one.

## 4. Signed claims

### 4.1 Claim envelope

Every recorded fact is a **claim**. A claim is a logical object, the **envelope**, serialised to CBOR and signed as a COSE_Sign1 message (Section 4.4). The envelope has these members. All are required unless stated.

| Member | Type | Constraint |
|---|---|---|
| `envelope_version` | integer | Exactly `1`. |
| `issuer` | string | An operator identifier, `^op_[\w-]+$`: the operator the claim belongs to. Older deployments signed some claims with the STACK system key while naming the operator here (4.5). |
| `subject` | string | A subject URI (4.2). What the claim is about. |
| `issued_at` | integer | Milliseconds since the Unix epoch at signing. Inside the signed bytes, so it cannot be changed afterwards. |
| `claim_type` | string | A registered claim type name (4.8). Selects the payload schema. |
| `claim_version` | integer | At least `1`. The schema version of this claim type's payload. Every claim type is at version `1` in this specification. |
| `payload` | object | The typed claim body. Its schema is chosen by `claim_type`. Its own member `type` repeats the claim type for the types that have one. |
| `receipt` | object or null | A transparency-log receipt (4.3), or `null`. |
| `co_signatures` | array | Co-signature entries (4.7). Claims issued under this version carry the empty array here: co-signatures are stored beside the signed bytes, never inside them. |

A verifier MUST ignore envelope members it does not recognise. Within the envelope, only `issuer`, `claim_type`, `issued_at` and `payload` are examined by the verification procedure of Section 8; the remaining members are covered by the signature but not interpreted. A verifier MAY check more (for example that `envelope_version` equals `1`) but MUST NOT report an error code for it that is not listed in Section 8.

### 4.2 Subject URI

The subject names the thing a claim is about. The grammar is:

```
subject    = "stack://" kind "/" id [ "/" subkind "/" subid ]
kind       = 1*( %x61-7A )                      ; lowercase letters
subkind    = 1*( %x61-7A )
id         = 1*( ALPHA / DIGIT / "_" / "-" )
subid      = 1*( ALPHA / DIGIT / "_" / "-" )
```

Equivalently the regular expression `^stack:\/\/[a-z]+\/[\w-]+(\/[a-z]+\/[\w-]+)?$`. The forms in use are:

| Form | Meaning |
|---|---|
| `stack://operator/{operator_id}` | An operator-scoped claim. The pack claim uses this form. |
| `stack://operator/{operator_id}/passport/{passport_id}` | A claim about one Passport. |
| `stack://operator/{operator_id}/mission/{mission_id}` | A claim about one mission. |

The scheme is specific to STACK and is not a SPIFFE trust domain. Identifiers inside external attestations carried as payload (for example a SPIFFE identifier in an SVID attestation) keep their own scheme.

### 4.3 Receipt slot

`receipt` is `null` or an object recording registration with a transparency log:

| Member | Type |
|---|---|
| `registry` | string, the registry identifier |
| `registered_at` | integer, milliseconds |
| `registry_entry_uri` | string or null |
| `proof` | object or null: `format` (one of `scitt-cose-receipt`, `rekor-v2-tle`, `stack-merkle-v1`), `bytes` (base64url native proof), `log_index` (integer or null), `tree_size` (integer or null), `root_hash` (base64url string or null) |
| `witnesses` | array or null of objects with `registry` (string), `registry_entry_uri` (string), `proof_bytes` (string or null) |

In this version every producer sets `receipt` to `null`, and verifiers MUST ignore the slot. The shape is fixed now so that later registration can be recorded without a new `envelope_version`. Because `receipt` is inside the signed bytes, a claim can only carry a receipt by being signed again with it.

### 4.4 COSE_Sign1 profile

A signed claim is a COSE_Sign1 message (RFC 9052 Section 4.2) with the following profile. It carries the algorithm label `-8` (EdDSA, RFC 9053 Section 2.2) and is signed with Ed25519.

**Message.** The message is a CBOR array of four elements, untagged (no CBOR tag 18):

```
COSE_Sign1 = [ protected : bstr, unprotected : map, payload : bstr, signature : bstr ]
```

**Protected header.** The first element is a byte string holding the CBOR encoding of a map with exactly these entries:

| Label | Name | Value |
|---|---|---|
| `1` | `alg` | the integer `-8` |
| `4` | `kid` | a byte string: the UTF-8 bytes of the key identifier (4.5) |
| `16` | `typ` | the text string `stack/claim+cose` |

The reference producer wraps the map in CBOR tag 259 (`d9 0103`), so that the byte string begins `d9 01 03 a3`. A verifier MUST accept the tag-259 form. A verifier SHOULD also accept the same map without the tag. A verifier MUST accept a `kid` given as a byte string, and SHOULD accept one given as a text string. A verifier MUST reject a message whose `alg` is not `-8`. The reference verifier does not inspect label `16`; producers MUST include it and verifiers MAY require it.

**Unprotected header.** The second element is an empty map (the reference producer writes tag 259 around it as well). Verifiers MUST ignore its content.

**Payload.** The third element is a byte string holding the CBOR encoding of the envelope (4.1) as a map with text-string keys. The key order inside that CBOR is not significant and is not canonical, because the signature covers these exact bytes and a verifier MUST NOT re-encode them. Integer-valued numbers may be encoded either as CBOR integers or as double-precision floats; the reference producer writes integers up to 4294967295 as unsigned integers and larger ones (including millisecond timestamps) as IEEE 754 double. Decoders MUST accept both and MUST treat an integer-valued float as an integer. `null` is the CBOR simple value null. The CBOR value `undefined` MUST NOT appear. Decoders MUST accept definite-length maps and arrays whose length prefix is longer than the shortest form (the reference encoder writes a two-byte map length even for small maps).

**Signature.** The fourth element is a 64-byte Ed25519 signature over the byte string `Sig_structure1` of RFC 9052 Section 4.4, which is the CBOR encoding of the four-element array

```
[ "Signature1", protected, h'', payload ]
```

where `protected` is the first element of the message and `payload` the third element, each byte string exactly as it appears in the message, and `h''` is the empty byte string (no external additional authenticated data). The array and strings use definite lengths. The signature algorithm is Ed25519 over those bytes directly, with no pre-hash.

**Transport.** The CBOR bytes of the whole message are written as base64url. This string is called `envelope_cose` in a manifest and `cose_sign1` in a co-signature.

**Decoding failures.** A message is undecodable if it is not a four-element array, if the protected or payload or signature element is not a byte string, if the protected bytes do not decode to a map, if `alg` is not `-8`, if no non-empty `kid` is present, or if the payload does not decode. How an undecodable message is reported depends on where it appears (Section 8).

### 4.5 Key identifiers and key sets

**Key identifier (`kid`).** A `kid` is an opaque string, matched byte for byte. The reference producer uses two shapes:

| Key | Shape | Example |
|---|---|---|
| Operator claim signing key | `{operator_id}:claim:v{N}`, with `N` a positive integer that grows at each rotation | `op_example:claim:v1` |
| STACK system key | `stack-passport-v{suffix}`, the suffix being letters, digits, `.`, `_` or `-` | `stack-passport-v1` |

A verifier MUST NOT infer trust from the shape of a `kid`.

**Key sets.** Keys are published as a JSON Web Key Set (RFC 7517) at two locations:

| Key set | URL |
|---|---|
| Operator claim keys | `https://api.getstack.run/v1/operators/{operator_id}/jwks.json` |
| STACK system keys | `https://api.getstack.run/v1/.well-known/jwks.json` |

The operator key set lists the operator's active and retired (not revoked) claim keys. Each entry has `kty` `OKP`, `crv` `Ed25519`, `x` (base64url public key), `kid`, `alg` `EdDSA`, `use` `sig`, and the informational members `not_before` and `not_after` (milliseconds; `not_after` is `null` for the active key).

A pack carries copies of both sets inline (Section 7.1) together with the URLs. A verifier MUST resolve keys from the inline copies. It MUST NOT depend on network access to do so. A verifier MAY offer to refresh a key set from the URL on request, but the results of such a refresh are outside this specification.

**Resolving a `kid` against a key set.** Given a `kid` and a key set:

1. The candidates are the members of the set's `keys` array whose `kid` member equals the `kid` exactly. A key with no `kid` member is never a candidate. If there is no candidate, the signature fails to verify.
2. Every candidate MUST satisfy: `kty` is `OKP`; `crv` is `Ed25519`; `x` is a string; there is no `d` member (private key material is forbidden); `alg` is absent or `EdDSA`; `use` is absent or `sig`. If any candidate violates this, the signature fails to verify.
3. Candidates are de-duplicated by RFC 7638 thumbprint: the SHA-256 of the UTF-8 string `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`, base64url. Several entries may share a `kid` when a deployment key was reused across rotations.
4. The signature is checked against each distinct candidate. Exactly one distinct key MUST verify. If none verifies the signature fails. If more than one distinct key verifies the result is ambiguous and the signature fails.

**Which key sets may sign what.** Different signatures are accepted from different key sets. "Operator set" is `verification_material.operator_jwks_inline` and "system set" is `verification_material.stack_system_jwks_inline`.

| Signature | Accepted when it verifies under |
|---|---|
| Pack claim (primary) | the operator set, or else the system set |
| Co-signature on the pack claim | the system set only |
| Inner claim of type `operator_decision` or `operator_review` | the operator set only |
| Any other inner claim | the operator set, or else the system set |
| `audit_chain_anchor.head_signature` | any key in either set (Section 5.5) |

The operator set is tried first where two sets are allowed. An ambiguous result in the first set ends the attempt as failed. Older deployments signed some claims with the system key while naming the operator as issuer, which is why the system set is accepted for them. Decisions and reviews are acts of the operator organisation, so a system-key signature on them is never accepted.

### 4.6 `claim_hash` and `claim_id`

`claim_hash` is the SHA-256 of the raw bytes of the COSE_Sign1 message (the decoded `envelope_cose`), as a bare hash. It identifies the signed bytes. Because co-signatures are stored outside the primary message, adding or removing a co-signature never changes `claim_hash`.

A registry also gives each stored claim a `claim_id` matching `^pc_[\w-]+$`. A `claim_id` is an exact reference used between claims (Section 8.2, step 10). It is carried beside the envelope in a manifest entry and is not inside the signed bytes.

### 4.7 Co-signatures and signer roles

A co-signature is an independent COSE_Sign1 message that signs the same payload bytes as a primary message, under another key. In a manifest it is an object:

| Member | Type | Constraint |
|---|---|---|
| `signer_kid` | string | Non-empty. MUST equal the `kid` in the co-signature's own protected header. |
| `signer_role` | string | One of `operator_attestation`, `agent_self`, `witness`. |
| `cose_sign1` | string | base64url COSE_Sign1 as in 4.4. Its payload bytes MUST be byte-for-byte the payload bytes of the primary message. |

The three roles state why the signer signed:

| Role | Meaning |
|---|---|
| `operator_attestation` | STACK attests, as the operator-side authority, that it produced or observed the claim under the operator's policy. |
| `agent_self` | An agent attests an envelope originally signed on its behalf. Reserved. |
| `witness` | An independent third party attests that it observed the envelope. Reserved. |

In this version a verifier accepts only `operator_attestation` co-signatures, and only under the system set. A co-signature that verifies under the system set with another role is reported as `COSIG_ROLE_INVALID`; one that does not verify is `COSIG_SIG_INVALID`.

Effects on verification:

- **Stripping.** The primary signature does not cover co-signatures, so removing them leaves the primary valid. Because the manifest hash (Section 7.2) also excludes them, a stripped pack still verifies. The only consequence is that when no co-signature remains the verifier reports the warning `STACK_COSIGNATURE_MISSING` and the result is not complete. Removing one of several co-signatures is not detectable by this format.
- **Appending.** A co-signature that an attacker adds must verify under a key in the system set. A forged one fails with `KID_MISMATCH`, `COSIG_PAYLOAD_MISMATCH`, `COSIG_ROLE_INVALID`, `COSIG_SIG_INVALID` or `COSIG_DECODE_FAILED` and makes the pack invalid.

Only the pack claim carries co-signatures in a manifest. Inner claim entries have no co-signature slot.

### 4.8 Claim types and schema versioning

`claim_type` is a lowercase identifier. A payload's JSON Schema is selected by `claim_type` and `claim_version`. The claim types defined by this version are listed, with their schema files, in Section 11. A claim type name that is reserved but has no schema MUST NOT be produced.

**Additive-only rule.** For every wire version defined here (`envelope_version` 1, `claim_version` 1 of each claim type, `pack_version` 1, audit hash versions 1 and 2), for at least 24 months from the first release of that version:

- only optional members may be added;
- no member may be removed, renamed, retyped or given a different meaning;
- no required member may be added.

A breaking change after that period requires a new version number, a published migration window and the re-signing of affected historical claims. Verifiers MUST ignore members they do not recognise (subject to the hashing rules, which cover whole values). Because the signed bytes are immutable, a claim signed under a version stays verifiable under that version indefinitely; the definitions of audit hash versions 1 and 2 are frozen permanently.

New kinds of evidence are introduced as new claim types, never as changes to the pack format (Section 13).

## 5. Audit hash chain

### 5.1 Entries and chains

The audit log records each action taken through the runtime. Each operator has its own chain; entries written for an operator, including entries made on its behalf by a partner, belong to that operator's chain. An entry has these stored fields:

| Field | Type | Notes |
|---|---|---|
| `entry_id` | string | Unique. |
| `trace_id`, `span_id` | string | Trace correlation. |
| `parent_span_id` | string or null | |
| `timestamp` | integer | Milliseconds. |
| `operator_id` | string | The chain owner. |
| `agent_id` | string | |
| `passport_jti` | string | The Passport the action ran under. |
| `layer` | string | The subsystem that wrote the entry. |
| `action` | string | |
| `outcome` | string | For example `success`, `failure`, `pending`, `blocked`. |
| `duration_ms` | integer or null | |
| `payload_hash` | string or null | |
| `error_code`, `error_message` | string or null | |
| `prev_entry_hash` | string | Bare hash of the previous entry's `entry_hash`, or the genesis value. |
| `entry_hash` | string | Bare hash computed by 5.2. |
| `passport_claims_at_event` | array of strings or null | `claim_hash` values of the claims active on the Passport when the entry was written. |
| `request_bytes`, `response_bytes` | integer or null | Body sizes. |
| `request_entropy`, `response_entropy` | number or null | Shannon entropy, bits per byte, a double. |
| `actor_grant_id`, `actor_partner_operator_id` | string or null | Set when a partner acted for the operator under a grant. |
| `hash_version` | integer | `1` or `2`. Absent in legacy rows, which are version 1. |
| `claim_binding_status` | string | One of `legacy_unbound`, `not_applicable`, `no_active_claims`, `bound`. Absent in legacy rows, which are `legacy_unbound`. |

The format in which entries are exchanged is outside this version. What is defined is how `entry_hash` is computed from the fields, so that any export of the fields above can be checked.

### 5.2 Entry hash

`entry_hash` is the SHA-256 (bare hash) of the UTF-8 bytes of a JSON text. That JSON text is NOT canonical JSON: it is the plain serialisation of an object whose members appear in the fixed order listed below, with no whitespace, strings escaped as in 3.1 rule 2, and numbers written as in 3.1 rule 3. The order is part of the definition.

**Version 1.** Members, in this order. The first eight are always present.

1. `entry_id`
2. `timestamp`
3. `operator_id`
4. `agent_id`
5. `layer`
6. `action`
7. `outcome`
8. `prev_entry_hash`
9. `passport_claims_at_event`, only if the stored value is an array with at least one element; written as the elements sorted ascending by UTF-16 code units
10. `request_bytes`, only if not null
11. `response_bytes`, only if not null
12. `request_entropy`, only if not null
13. `response_entropy`, only if not null
14. `actor_grant_id`, only if not null
15. `actor_partner_operator_id`, only if not null

Version 1 does not bind `trace_id`, `span_id`, `parent_span_id`, `passport_jti`, `duration_ms`, `payload_hash`, `error_code`, `error_message` or `claim_binding_status`. Optional members that are null or empty are omitted, so rows written before a field existed hash as if the field had never been defined.

**Version 2.** Members, in this order. All 25 are always present. A stored null is written as `null` (it is never omitted), and a missing optional value is `null`.

1. `hash_version`, the integer `2`
2. `entry_id`
3. `trace_id`
4. `span_id`
5. `parent_span_id`
6. `timestamp`
7. `operator_id`
8. `agent_id`
9. `passport_jti`
10. `layer`
11. `action`
12. `outcome`
13. `duration_ms`
14. `payload_hash`
15. `error_code`
16. `error_message`
17. `prev_entry_hash`
18. `claim_binding_status`
19. `passport_claims_at_event`, an array, sorted ascending by UTF-16 code units, empty if there are none
20. `request_bytes`
21. `response_bytes`
22. `request_entropy`
23. `response_entropy`
24. `actor_grant_id`
25. `actor_partner_operator_id`

An entry whose `hash_version` is absent is version 1. A verifier that meets any other `hash_version` value MUST treat the entry as a hash mismatch. Every entry written under this specification is version 2, and a version 2 entry MUST carry `trace_id`, `span_id`, `passport_jti` and `claim_binding_status`.

`request_entropy` and `response_entropy` are the only non-integer numbers in the record. Writers and verifiers MUST serialise them as ECMAScript `Number::toString` does (the shortest decimal string that round-trips the double), and a store MUST keep them at double precision, because a narrower column changes the value being hashed.

**Test vectors.** Both vectors were computed with the reference implementation.

Version 1, using `prev_entry_hash` equal to the genesis value (5.3):

```
{"entry_id":"aud_example0","timestamp":1792487099000,"operator_id":"op_example","agent_id":"agt_example","layer":"vault","action":"passport.issue","outcome":"success","prev_entry_hash":"0000000000000000000000000000000000000000000000000000000000000000"}
```

`entry_hash` = `b3a6ad886d7bc738a8de6aebc49a10c17c7dc513bff79069a8cf65eb072bf839`

Version 2 (the entry used in Section 12), whose `passport_claims_at_event` holds the example claim hash:

```
{"hash_version":2,"entry_id":"aud_example1","trace_id":"tr_example1","span_id":"sp_example1","parent_span_id":null,"timestamp":1792487100000,"operator_id":"op_example","agent_id":"agt_example","passport_jti":"ppt_example","layer":"vault","action":"passport.issue","outcome":"success","duration_ms":12,"payload_hash":null,"error_code":null,"error_message":null,"prev_entry_hash":"0000000000000000000000000000000000000000000000000000000000000000","claim_binding_status":"bound","passport_claims_at_event":["ff8830c039e250b817fb49c9519538833f26be1ce937f30e82b7d332d8a0b860"],"request_bytes":null,"response_bytes":null,"request_entropy":null,"response_entropy":null,"actor_grant_id":null,"actor_partner_operator_id":null}
```

`entry_hash` = `5eb86cc984a6f26a21fb079f9f2013ade24f46f10eed45a515666c24cf253338`

### 5.3 Genesis and linkage

The **genesis value** is 64 zero characters: `0000000000000000000000000000000000000000000000000000000000000000`. The first entry of an operator's chain has `prev_entry_hash` equal to the genesis value. Every later entry has `prev_entry_hash` equal to the `entry_hash` of the entry before it in the same operator's chain. Entries therefore form a single linked list per operator.

Chain order is `timestamp` ascending, ties broken by `entry_id` ascending. Because tie-breaking by identifier depends on a collation, a verifier SHOULD reconstruct order by following `prev_entry_hash` links and use `timestamp` and `entry_id` only to cross-check.

### 5.4 Binding claims into the chain

When an entry is written, `passport_claims_at_event` records the `claim_hash` of each claim active on the Passport at that moment. In version 2 the array, and the `claim_binding_status` that says whether the array is complete (`bound`), empty because there were none (`no_active_claims`), not applicable (`not_applicable`) or not recorded (`legacy_unbound`), are part of the hash. Changing the set of claims bound to an entry therefore changes that entry's hash and every later hash on the chain. A `claim_hash` found in an entry shows the claim existed, with exactly those signed bytes, when the entry was written.

### 5.5 Chain head and signed head

The **chain head** is the `entry_hash` of the latest entry of an operator's chain. If the operator has no entries, a pack uses the genesis value as `head_hash`.

A pack names the head it was exported against in `audit_chain_anchor` (Section 7.3): `head_hash` (bare hash), `head_at_ms` (the head entry's `timestamp`, or the revocation snapshot time if the chain is empty) and `head_signature`. The signature is a raw Ed25519 signature (64 bytes, base64url, not a COSE message) over the UTF-8 bytes of the canonical JSON (3.1) of an object with exactly two members, `head_hash` and `head_at_ms`. With canonical ordering the signed text is

```
{"head_at_ms":<integer>,"head_hash":"<64 hex>"}
```

The member order is `head_at_ms` first, then `head_hash`, and it is fixed by canonicalisation. A verifier accepts the signature if any key in the pack's operator set or system set verifies it. The `kid`, `alg` and `use` members are not consulted for this signature, but the key MUST be an Ed25519 OKP key and a verifier SHOULD reject a key that carries a `d` member.

### 5.6 Inclusion proofs

A manifest carries `audit_chain_proofs`: one entry per claim, with `claim_hash`, `audit_position` (a non-negative integer) and `merkle_path` (an array of prefixed hashes). They are intended as sibling hashes linking a claim to the anchored head. The head is an audit entry hash, not a Merkle root, and the proof entry contains no left or right direction for each step. Version 1.0.0 therefore defines no procedure that evaluates `merkle_path`, and a verifier MUST NOT treat these entries as verified. Producers currently write placeholder entries with `audit_position` `0` and an empty path. The verifier reports the proofs as incomplete (placeholders or missing) or unverified (present but not evaluable), and in both cases the result is not complete (step 12 of Section 8.2). A later minor version may define how a path is evaluated, in which case the placeholders will stay valid and incomplete.

### 5.7 What a verifier does with a chain

A verifier that is given an operator's entries (the format of that export being outside this version) and wants to check them:

- MUST recompute `entry_hash` for each entry by 5.2 and compare it with the stored value;
- MUST check that each entry's `prev_entry_hash` equals the previous entry's `entry_hash`, and that the first entry's `prev_entry_hash` equals the genesis value if the export begins at the start of the chain;
- MUST treat a chain that starts later (because earlier entries were pruned under a retention policy, or because the export began at a date) as verified only from its first entry onward, accepting that entry's `prev_entry_hash` as given, and MUST say so in its result;
- MUST report the first entry at which a check fails and whether it was a link failure or a hash failure;
- SHOULD confirm that the last entry's `entry_hash` equals the `head_hash` of a pack when the two refer to the same moment;
- MAY use `passport_claims_at_event` to show that a particular claim, with exactly its signed bytes, existed when an entry was written.

## 6. Merkle rule

The Merkle root commits to an ordered list of claim hashes. The leaves are the `claim_hash` values of the manifest's `claims` array, in the order they appear in the array. The rule:

1. Every leaf MUST be a bare hash: exactly 64 lowercase hex characters. A verifier that meets another leaf reports `MERKLE_COMPUTE_FAILED`.
2. If there are no leaves, the root is the SHA-256 of the empty byte string: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
3. If there is one leaf, the root is that leaf unchanged.
4. Otherwise build levels. The first level is the list of leaves. To form the next level, take the current level in pairs from the left: for each pair `(left, right)` the parent is the SHA-256, as hex, of the ASCII text formed by writing the 64 characters of `left` followed by the 64 characters of `right`. The hash input is therefore 128 ASCII bytes, not the 64 raw bytes of the two digests. If the level has an odd number of nodes, the last node has no pair and is promoted to the next level unchanged. It is not duplicated and it is not hashed. Repeat until one node remains.
5. The root is written as a prefixed hash: `sha256:` plus that node.

The rule that an unpaired node is promoted, never duplicated, removes the second-preimage ambiguity that duplication creates.

**Worked example.** Three leaves, each the SHA-256 of an ASCII label:

| Leaf | Label | Value |
|---|---|---|
| L1 | `leaf-1` | `4140bf0e8569ed03ec838871ff2f190e9b3ea86bc083d7e9901049f75f00e855` |
| L2 | `leaf-2` | `649837ddcb7e1967086d7d35aaef7b975c513815d96fc6e70015e93a2bfe0f9a` |
| L3 | `leaf-3` | `9fde56c376760bd399b82eb8569229a2dff19219411ac71154dfeab2cf502454` |

- One leaf (L1): root `sha256:4140bf0e8569ed03ec838871ff2f190e9b3ea86bc083d7e9901049f75f00e855`.
- Two leaves (L1, L2): the root is `sha256:` plus SHA-256 of the 128 ASCII characters `L1` then `L2`, which is `sha256:04b880ac3c9bb353fd13b7b30cf3d1a2e84ac4a6765f8faa79513f24f129d5a7`.
- Three leaves (L1, L2, L3): the first level pairs L1 and L2 into `H12` = `04b880ac3c9bb353fd13b7b30cf3d1a2e84ac4a6765f8faa79513f24f129d5a7`, and L3 is promoted. The second level is `(H12, L3)`, and the root is `sha256:c9646be59b19992442100bf58a18bf09b40c92050f78bb92d3b4595ef6063023`.
- No leaves: `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The values can be reproduced with:

```
node -e "const c=require('node:crypto');const h=s=>c.createHash('sha256').update(s).digest('hex');const L=['leaf-1','leaf-2','leaf-3'].map(h);const h12=h(L[0]+L[1]);console.log(h12,h(h12+L[2]))"
```

The order of the leaves is the order of the manifest's `claims` array. Producers SHOULD order claims by `issued_at` ascending, ties broken by `claim_id` ascending, so that the order is deterministic. A verifier MUST use the array order as given and MUST NOT sort.

## 7. Evidence packs

An evidence pack is one JSON file, the **manifest**. It carries the signed pack claim, the claims it covers, the key sets and schemas needed to check them, and placeholders for audit inclusion proofs. Everything a verifier needs in the default path is in the file.

### 7.1 Manifest members

| Member | Type | Constraint |
|---|---|---|
| `pack_version` | integer | Exactly `1`. Anything else is `INVALID_MANIFEST`. |
| `claim` | string | Non-empty. The pack claim as base64url COSE_Sign1 (4.4), signed by the operator claim key (or, in older deployments, the system key). |
| `co_signatures` | array | Co-signatures (4.7) over the pack claim's payload. May be absent, which means empty. |
| `claims` | array | Claim entries (below), in producer order. |
| `audit_chain_proofs` | array | Inclusion proof entries (below). |
| `verification_material` | object | Key sets (below). |
| `schemas_inline` | object | Map from key (`envelope` or a claim type name) to an inline schema entry (below). |

A verifier ignores other top-level members. They are not covered by any hash, so a producer MUST NOT rely on them for meaning.

**Claim entry.**

| Member | Type | Constraint |
|---|---|---|
| `claim_id` | string | Optional. `^pc_[\w-]+$`. Absent only in packs produced before exact ids existed. |
| `claim_hash` | string | Bare hash of the decoded `envelope_cose` bytes (4.6). |
| `envelope_cose` | string | base64url COSE_Sign1 of the claim (4.4). |
| `revoked_at_ms` | integer or null | Revocation time as of the pack's snapshot, or `null` if not revoked. |

**Audit proof entry.**

| Member | Type | Constraint |
|---|---|---|
| `claim_hash` | string | Bare hash, matching a claim entry. |
| `audit_position` | integer | At least `0`. |
| `merkle_path` | array of strings | Prefixed hashes. See 5.6. |

**Verification material.**

| Member | Type |
|---|---|
| `operator_jwks_url` | string, URL of the operator key set |
| `operator_jwks_inline` | object `{"keys": [...]}`, copy of that key set |
| `stack_system_jwks_url` | string, URL of the system key set |
| `stack_system_jwks_inline` | object `{"keys": [...]}`, copy of that key set |

An absent inline set is treated as a set with no keys. The URLs are informational and are never required to resolve.

**Inline schema entry.**

| Member | Type | Constraint |
|---|---|---|
| `$schema` | string | The JSON Schema dialect URI. Not verified. |
| `content_hash` | string | Prefixed hash of the canonical JSON (3.1) of `json_schema`. |
| `json_schema` | object | The JSON Schema body. |

A verifier MUST NOT report `valid: true` for a manifest that lacks a member required above or has one of the wrong JSON type. The reference verifier aborts on a missing `claims`, `audit_chain_proofs`, `verification_material` or `schemas_inline`; a verifier SHOULD report `INVALID_MANIFEST` instead. A manifest SHOULD NOT contain duplicate object member names, and a verifier SHOULD reject one that does.

### 7.2 `content_hash`

The pack claim carries `content_hash`, a prefixed hash that identifies the manifest's content at byte level. It is computed over the manifest with `claim` and `co_signatures` removed, and with every member other than the five below ignored. The **skeleton** is the object

```
{
  "pack_version":          <manifest.pack_version>,
  "claims":                <manifest.claims>,
  "audit_chain_proofs":    <manifest.audit_chain_proofs>,
  "verification_material": <manifest.verification_material>,
  "schemas_inline":        <manifest.schemas_inline>
}
```

with each value taken whole, exactly as parsed (including any members this version does not define). `content_hash` is `sha256:` plus the SHA-256 of the UTF-8 canonical JSON (3.1) of the skeleton. It covers the claim list, the proofs, both key sets and the schema bodies, so none of them can change without the hash ceasing to match the value the pack claim's signature protects. It does not cover `claim`, because the signed pack claim contains the hash, and it does not cover `co_signatures`, which sign the pack claim.

The producer computes `content_hash` before it signs the pack claim. Two packs with equal content hashes are the same pack. A re-export of a scope is a new pack with a different `pack_id` and `content_hash` (Section 7.6).

Because the hash is over the parsed value, insignificant whitespace and member order in the file do not matter. Producers store the canonical text, but verifiers MUST accept any JSON text that parses to the same value.

### 7.3 Pack claim

The pack claim is a claim (4.1) with `claim_type` `evidence_pack`, `subject` of the operator form `stack://operator/{operator_id}`, and a payload with these members:

| Member | Type | Constraint |
|---|---|---|
| `type` | string | Exactly `evidence_pack`. A message whose payload has any other `type` is `NOT_EVIDENCE_PACK`. |
| `pack_id` | string | `^pck_[\w-]+$`. Unique per export. |
| `content_hash` | string | Prefixed hash (7.2). |
| `scope` | object | `kind` and `ref` (7.4). |
| `time_bounds` | object | `t0_ms` (inclusive) and `t1_ms` (exclusive), integers, with `t1_ms` greater than `t0_ms`. |
| `claim_count` | integer | At least `0`. Equals the length of `claims`. |
| `included_review_claim_ids` | array of strings | Each `^pc_[\w-]+$`. Absent only in older packs. See 7.9. |
| `merkle_root` | string | Prefixed hash (Section 6) over `claims[].claim_hash`. |
| `audit_chain_anchor` | object | `head_hash` (bare hash), `head_signature` (base64url), `head_at_ms` (integer). See 5.5. |
| `revocation_snapshot_at_ms` | integer | When `revoked_at_ms` values were sampled. |
| `schema_versions` | object | `envelope` and `by_claim_type`, both described in 7.5. |
| `canonical_schema_base_url` | string | URL root where schemas are published. Reference only. |
| `supersedes` | string or null | `pck_` identifier of an earlier pack for the same scope, or `null`. |
| `cross_tenant_refs` | array | References to claims signed by other operators (7.8). Default empty. |
| `external_chain_anchors` | array | References to public anchors of the chain head (7.7). Default empty. |

### 7.4 Scope

`scope.kind` is one of the four values below. `scope.ref` is a string of 1 to 256 characters.

| Kind | `ref` | Claims covered |
|---|---|---|
| `mission` | the mission identifier, matching `^ms_[\w-]+$` | The claims of one mission between its start and its end (completion, revocation or the export time). |
| `session` | a session identifier | Claims of one session. Bounds are exact. |
| `incident` | `incident:` plus an identifier | Claims linked to an incident. Reserved: producers do not yet emit it, verifiers MUST accept it. |
| `period` | `period:YYYY-Qn`, `period:YYYY-MM` or `period:YYYY-MM-DD/YYYY-MM-DD` | Claims whose `issued_at` is in the half-open interval `[t0_ms, t1_ms)`, plus the claim that immediately precedes the interval for each passport that has a claim in it, plus revocations inside the interval of claims issued inside it. |

The producer decides which claims fall in a scope; a verifier cannot recompute that and reports `scope` as stated in the signed pack claim. The relationship rules of Section 8.2 step 10 apply to `mission` scope only.

### 7.5 Schema pinning and inline schemas

`schema_versions` pins the schema of the envelope and of each claim type used in the pack:

```
"schema_versions": {
  "envelope":      { "version": 1, "content_hash": "sha256:..." },
  "by_claim_type": { "<claim_type>": { "version": 1, "content_hash": "sha256:..." }, ... }
}
```

`version` is an integer of at least 1. `content_hash` is a prefixed hash of the canonical JSON of the schema. A producer MUST list in `by_claim_type` every claim type that appears in `claims`.

`schemas_inline` carries the schema bodies. Its key `envelope` holds the envelope schema and each other key is a claim type. The producer copies the body, its hash and its `$schema` URI into the entry. A verifier recomputes the hash of each body and compares it with both the entry's `content_hash` and the matching pin. Together they ensure the schema a reader sees is the schema the signer pinned.

A pin means something only if it is the real hash of a body a verifier can recompute. The all-zero value `sha256:` plus 64 zero characters is the placeholder that early producers wrote when they had no schema to hash. Such a pack stays valid, but the verifier reports the pin as not attested and the result is not complete. A non-zero pin with no inline body cannot be recomputed and is reported the same way. A pin that disagrees with an inline body is an error.

In this version the verification procedure checks hashes and pins. It does not validate the payload of each claim against its schema, and it defines no result code for a payload that does not conform. A verifier MAY perform such validation as an extra, but MUST NOT let it change `valid`, `complete` or the code set.

The `canonical_schema_base_url` is for discovery. The verifier never fetches from it. A claim type whose schema is not inline (7.10) can be fetched from `canonical_schema_base_url` plus the claim type plus `.json`, and compared with its pin by the user.

### 7.6 `supersedes`

Exporting a scope again yields a new pack with its own `pack_id`. The new pack's `supersedes` is the earlier pack's `pack_id`. The earlier pack stays valid as a snapshot of its time. The pointer runs forward only; a verifier never needs to follow it, and this version defines no check on it beyond its being `null` or a `pck_` identifier.

### 7.7 External chain anchors

An external anchor says that the operator's chain head was published to a public location. Each element of `external_chain_anchors` has:

| Member | Type |
|---|---|
| `registry` | string, 1 to 128 characters, naming where it was published |
| `permalink` | string, a URL |
| `anchored_at_ms` | integer |
| `anchored_chain_head_hash` | bare hash |

A permalink beginning `noop://` is synthetic: it was produced by a producer that does not publish anywhere, and is not externally verifiable. The reference verifier does not fetch permalinks. An anchor that is present therefore never becomes a passing check in this version, and `external_anchors_verified` stays `0`.

### 7.8 Cross-tenant references

`cross_tenant_refs` names claims signed by other operators that this pack's claims refer to. Each element has `foreign_claim_hash` (bare hash), `foreign_issuer_op_id` (an operator identifier), `foreign_jwks_url` (URL) and `relation` (one of `delegation_parent`, `a2a_dispatch`, `skill_invocation`). The pack carries references, never the foreign envelopes. Producers currently leave the array empty. Verifiers ignore it, and MUST ignore a `relation` value they do not know.

### 7.9 Review claim identifiers

`included_review_claim_ids` lists the `claim_id` of every claim of type `operator_review` or `dossier` that is in `claims`. This pins exactly which review revisions the pack contains: a review cannot be dropped from the manifest or an older revision swapped in without the signed list disagreeing. A pack produced before this member existed omits it, and the verifier warns.

### 7.10 Unknown claim types and verifier modes

A claim type is **unknown to the pack** when it appears in `claims` but has no entry in `schemas_inline`. (This depends on the pack, not on the verifier's own knowledge.) How a verifier treats it depends on the mode:

| Mode | Behaviour |
|---|---|
| default | One warning `UNKNOWN_CLAIM_TYPE` for each such type. `valid` is unaffected. |
| strict | One error `UNKNOWN_CLAIM_TYPE` for each such type. |
| ignore-unknown | One warning `UNKNOWN_CLAIM_TYPE` in total, stating how many types were skipped. |

Strict and ignore-unknown are mutually exclusive; a verifier MUST refuse a request for both.

**Air-gap mode.** In air-gap mode the verifier uses only material inside the pack and MUST NOT access any network. In this version air-gap changes one outcome: an unknown claim type is an error as in strict mode, even if ignore-unknown was also requested. Every verifier of this version resolves keys from the inline copies and skips external anchor fetching whatever the mode, so air-gap changes neither key resolution nor anchor handling.

## 8. Verification procedure

### 8.1 Inputs, options and result

A verifier takes a manifest (parsed JSON) and these options, all default off: `air_gap`, `strict`, `ignore_unknown`, `activity` (alias `replay`). A fifth option, `fresh_jwks`, is reserved and has no effect in this version.

A verifier produces a **VerifyResult**:

| Member | Type | Meaning |
|---|---|---|
| `valid` | boolean | `true` if and only if `errors` is empty. |
| `complete` | boolean | `true` if and only if `valid` is `true` and every entry of `checks` has outcome `pass`. |
| `pack_id` | string or null | From the pack claim, or `null` if it could not be read. |
| `scope` | object or null | The pack claim's `scope`, or `null`. |
| `claim_count` | integer | The pack claim's `claim_count`, or `0` if unread. |
| `timespan` | array or null | `[t0_ms, t1_ms]` from the pack claim, or `null`. |
| `revoked_at_export` | integer | Number of claim entries whose `revoked_at_ms` is not `null`. `0` if unread. |
| `unknown_claim_types` | integer | Number of distinct claim types unknown to the pack (7.10), whatever the mode. |
| `external_anchors_verified` | integer | Number of external anchors verified. Always `0` in this version. |
| `checks` | array | Objects `{name, outcome, detail?}`, `outcome` being `pass`, `fail`, `warn` or `skip`, in the order the steps ran. |
| `errors` | array | Objects `{code, message}`. |
| `warnings` | array | Objects `{code, message}`. |
| `activity` | object or null | Present only when requested (Section 9). |

Messages are human-readable and are not normative. Codes are.

### 8.2 Ordered steps

A verifier MUST produce the same `valid`, `complete` and set of error codes as this procedure. The steps run in the order listed, except that steps 1 and 2 end the procedure on failure. Each step records its check by name. A fail records the error code named. Steps do not stop at the first error from step 3 onward, so a damaged pack often produces several codes.

Notation: "the pack issuer" is the `issuer` of the pack claim's envelope if it is a string, otherwise unset. "The decoded claims" is defined in step 9.

**1. Manifest shape.** Check `manifest-shape`. Fail with `INVALID_MANIFEST` if `pack_version` is not the integer `1`, or if `claim` is not a non-empty string (and see the extra rule at the end of 7.1). On failure return immediately, with `pack_id` and `scope` null and zero counts. On success record `pass`.

**2. Decode the pack claim.** Check `pack-claim-decode`. Decode `claim` as a COSE_Sign1 (4.4). If it cannot be decoded, fail with `COSE_DECODE_FAILED` and return. If the envelope's `payload` is missing or its `type` is not `evidence_pack`, fail with `NOT_EVIDENCE_PACK` and return. Nothing is recorded on success. The remaining steps read the pack claim's payload as `pack`.

**3. Primary signature.** Check `pack-claim-signature`. Verify the signature under the operator set, then the system set (4.5). Pass, or fail with `PRIMARY_SIG_INVALID`. Continue after a failure.

**4. Co-signatures.** Check `co-signature`. If `co_signatures` is empty or absent, record `warn` with `STACK_COSIGNATURE_MISSING`. Otherwise, for each entry in order, in this order of tests:
- decode `cose_sign1`; on failure `COSIG_DECODE_FAILED`;
- if the decoded `kid` differs from `signer_kid`, `KID_MISMATCH`;
- if the decoded payload bytes are not byte-identical to the pack claim's payload bytes, `COSIG_PAYLOAD_MISMATCH`;
- verify under the system set only. If it verifies and `signer_role` is `operator_attestation`, record `pass`. If it verifies with any other role, `COSIG_ROLE_INVALID`. If it does not verify, `COSIG_SIG_INVALID`.
The first failing test for an entry is the one reported for it.

**5. Content hash.** Check `content-hash`. Compute `sha256:` plus SHA-256 of the canonical JSON of the skeleton (7.2). If it differs from `pack.content_hash`, fail with `CONTENT_HASH_MISMATCH`.

**6. Claim count.** Check `claim-count`. If `pack.claim_count` differs from the length of `claims`, fail with `CLAIM_COUNT_MISMATCH`.

**7. Claim identifiers.** Check `claim-ids`. Let the present identifiers be the `claim_id` values of the entries that have one. If any does not match `^pc_[\w-]+$`, fail with `CLAIM_ID_INVALID`. Otherwise, if two are equal, fail with `CLAIM_ID_DUPLICATE`. Otherwise, if some entry has no `claim_id`, record `warn` with `CLAIM_IDS_MISSING`. Otherwise `pass`.

**8. Merkle root.** Check `merkle-root`. Compute the root (Section 6) over the `claim_hash` values in array order. If a leaf is malformed, fail with `MERKLE_COMPUTE_FAILED`. If the root differs from `pack.merkle_root`, fail with `MERKLE_ROOT_MISMATCH`.

**9. Per-claim hashes and signatures.** For each entry in order:
- decode `envelope_cose` from base64url and compute its SHA-256. If it differs from `claim_hash`, count a hash failure and go to the next entry (the entry is not examined further and is not among the decoded claims);
- otherwise decode the message. If it cannot be decoded, count a signature failure and go to the next entry;
- verify the signature under the key sets that 4.5 allows for the entry's `claim_type`; if it does not verify, count a signature failure;
- if the pack issuer is set and the entry's `issuer` is not equal to it, count a signature failure;
- add the entry to the **decoded claims**, with its `claim_id`, `claim_hash`, `issuer`, `claim_type` (a string or null), `issued_at` (a number or null) and `payload` (an object, or null if it is not a non-array object). An entry whose signature failed is still added.
After the loop, record `fail` `CLAIM_HASH_MISMATCH` if there were hash failures (once, whatever their number), and `fail` `CLAIM_SIG_INVALID` if there were signature failures (once). When the manifest has at least one claim, each of the two checks `per-claim-hashes` and `per-claim-signatures` records `pass` if it did not fail.

**10. Review relationships.** Check `review-relationships`. Let `reviews` be true if any decoded claim has type `dossier` or `operator_review`. If `reviews` is true and any manifest entry lacks a `claim_id`, record `warn` `REVIEW_RELATIONSHIPS_UNVERIFIABLE` and apply no rules. Otherwise apply the rules of 8.3 to the decoded claims. Any violation is reported as a single `fail` `REVIEW_REFERENCE_INVALID`. If there is no violation and `reviews` is true, record `pass`. If there is no violation and `reviews` is false, nothing is recorded.

**11. Included review identifiers.** Check `included-review-ids`. If `pack.included_review_claim_ids` is absent, record `warn` `INCLUDED_REVIEW_IDS_MISSING`. If it is present but is not an array of strings, fail with `INCLUDED_REVIEW_IDS_INVALID`. Otherwise compare it, as a sorted list, with the sorted list of `claim_id` values of the decoded claims whose type is `dossier` or `operator_review` and that have a `claim_id`. If the lists differ, fail with `INCLUDED_REVIEW_IDS_MISMATCH`; else `pass`.

**12. Audit chain proofs.** Check `audit-chain-proofs`. Index the proof entries by `claim_hash`. Count the manifest claims that have no proof or whose proof has `audit_position` `0` and an empty `merkle_path`. If that count is positive, or the number of distinct proof hashes differs from the number of manifest claims, record `warn` `AUDIT_PROOFS_INCOMPLETE`. Otherwise record `warn` `AUDIT_PROOFS_UNVERIFIED`. This check always records a warning in this version (5.6).

**13. Schema hashes and pins.** For each `(key, entry)` of `schemas_inline`:
- if SHA-256 of the canonical JSON of `entry.json_schema`, prefixed, differs from `entry.content_hash`, fail with `SCHEMA_HASH_MISMATCH` (check `schema-content-hash`);
- the pin is `schema_versions.envelope.content_hash` for the key `envelope`, otherwise `schema_versions.by_claim_type[key].content_hash`. If there is no pin, fail with `SCHEMA_PIN_MISSING` (check `schema-pin-missing`); if the pin differs from `entry.content_hash`, fail with `SCHEMA_PIN_MISMATCH` (check `schema-pin-mismatch`).
If none of these failed, record `pass` for check `schemas-inline`, even when there are no entries.

**14. Schema attestation.** Check `schema-hash-attestation`. Collect the pins: the envelope pin and every `by_claim_type` pin. For each pin whose key is not in `schemas_inline`: if the pin is missing or is the all-zero placeholder, add its key to the placeholder list, otherwise to the unchecked list. If the placeholder list is not empty, record `warn` `SCHEMA_HASH_NOT_ATTESTED`. If the unchecked list is not empty, record `warn` `SCHEMA_PIN_UNCHECKED`. If both lists are empty and step 13 recorded no failure, record `pass`.

**15. Unknown claim types.** Check `unknown-claim-type`. Collect the distinct `claim_type` strings of all manifest entries that decode (including entries that failed step 9). For each that has no key in `schemas_inline`: in strict mode or air-gap mode, fail with `UNKNOWN_CLAIM_TYPE`; in ignore-unknown mode count it; otherwise record `warn` `UNKNOWN_CLAIM_TYPE`. In ignore-unknown mode, if any were counted, record one `warn` `UNKNOWN_CLAIM_TYPE`. If none were unknown and at least one claim type is present, record `pass`.

**16. Audit chain anchor.** Check `audit-chain-anchor`. Let the keys be every key in the operator set followed by every key in the system set. If there are none, fail with `NO_ANCHOR_JWK`. Otherwise verify `head_signature` (5.5) under each key in turn; if none verifies, fail with `ANCHOR_SIG_INVALID`; else `pass`.

**17. External anchors.** Check `external-anchor`. If `external_chain_anchors` is empty or absent, record `warn` `EXTERNAL_ANCHORS_MISSING`. For each anchor: if its permalink begins `noop://`, record `warn` `NOOP_ANCHOR`; otherwise record `skip` (the reference does not fetch anchors, with or without air-gap). No anchor yields `pass` in this version.

**18. Revocation snapshot.** Check `revocation-snapshot`. Count manifest entries whose `revoked_at_ms` is not `null`, set `revoked_at_export` to it and record `pass`. Revocation never causes an error.

**19. Activity (optional).** If requested, produce `activity` (Section 9). It never changes `valid` or `complete`.

**20. Result.** Set `valid` and `complete` as defined in 8.1, and return the result with `pack_id`, `scope`, `claim_count` and `timespan` from the pack claim.

The order of steps and the wording of messages are not observable in conformance. The set of error codes, `valid` and `complete` are.

### 8.3 Review relationship rules (step 10)

The rules apply only when the pack's `scope.kind` is `mission` and every decoded claim has a `claim_id`. Let `M` be `scope.ref`. A decoded claim **belongs to M** if its payload member `mission_ref` equals `M`, or if its type is `mission` and its payload member `mission_id` equals `M`. To **resolve** a reference means: it is a string; some decoded claim has that `claim_id`; that claim's type is among the types the rule names; and that claim belongs to `M`. A reference that does not resolve is a violation. Non-object members of the review lists and of `alerts_walkthrough` are skipped; a non-object member of `decision_tree` has no checkpoint identifier and so does not resolve.

For a claim of type `operator_decision`:

- it MUST belong to `M`, and its payload `operator_id` MUST equal the pack issuer when that is set;
- its `action` MUST be one of the actions in the table below, and its `effect` and `effect_scope` MUST be the values in that row;
- its `target_agent_id` MUST be a non-empty string;
- its `source_refs` MUST be an object whose arrays `checkout_ids`, `security_event_ids`, `detector_claim_ids` and `approval_ids` (a missing or non-array value counts as empty) match the row's source group;
- each entry of `detector_claim_ids` MUST resolve to a `detector_signal`.

| `action` | `effect` | `effect_scope` | Source group |
|---|---|---|---|
| `checkout_approved` | `checkout_released` | `mission` | checkout |
| `checkout_blocked` | `checkout_blocked_and_agent_blocked` | `agent_global` | checkout |
| `security_events_dismissed` | `security_events_resolved` | `mission` | security |
| `agent_suspended` | `agent_suspended_and_events_resolved` | `agent_global` | security |
| `future_warning_block_enabled` | `checkouts_released_and_agent_warning_policy_set_to_block` | `agent_global` | checkout |
| `future_critical_block_enabled` | `checkouts_released_and_agent_critical_policy_set_to_block` | `agent_global` | checkout |
| `governance_approved` | `governance_approval_approved` | `mission` | governance |
| `governance_rejected` | `governance_approval_rejected` | `mission` | governance |

Source groups: **checkout** needs at least one `checkout_ids` and the other three arrays empty. **security** needs at least one `security_event_ids`, as many `detector_claim_ids` as `security_event_ids`, and empty `checkout_ids` and `approval_ids`. **governance** needs exactly one `approval_ids` and the other three empty.

For a claim of type `operator_review`: it MUST belong to `M` and have `operator_id` equal to the pack issuer when set; each `checkpoint_notes[].checkpoint_claim_id` MUST resolve to a `checkpoint_approval`; each `decision_rationales[].operator_decision_claim_id` MUST resolve to an `operator_decision`; each `alert_explanations[].detector_claim_id` MUST resolve to a `detector_signal`; and `prior_review_ref`, when neither `null` nor absent, MUST resolve to an `operator_review` or a `dossier`.

For a claim of type `dossier`: it MUST belong to `M`; each `decision_tree[].checkpoint_id` MUST equal the `checkpoint_id` of some `checkpoint_approval` claim that belongs to `M`; each `alerts_walkthrough[]` entry's `detector_signal_claim_id` MUST resolve to a `detector_signal` whose `severity` equals the entry's `severity`; and `prior_dossier_ref`, when neither `null` nor absent, MUST resolve to a `dossier` or an `operator_review`.

Decoded claims of other types are not examined. Because a hash-mismatched entry is not among the decoded claims, damage to one claim can also produce `REVIEW_REFERENCE_INVALID` or `INCLUDED_REVIEW_IDS_MISMATCH` for claims that point at it.

### 8.4 Error codes

An error code makes `valid` false.

| Code | Step | Meaning |
|---|---|---|
| `INVALID_MANIFEST` | 1 | `pack_version` is not `1`, `claim` is missing or empty, or a required manifest member is absent or ill-typed. |
| `COSE_DECODE_FAILED` | 2 | The pack claim is not a decodable COSE_Sign1 under 4.4. |
| `NOT_EVIDENCE_PACK` | 2 | The pack claim's payload is missing or its `type` is not `evidence_pack`. |
| `PRIMARY_SIG_INVALID` | 3 | The pack claim's signature does not verify under an allowed key set (including: no key for the `kid`, an unusable key, an ambiguous result). |
| `COSIG_DECODE_FAILED` | 4 | A co-signature cannot be decoded. |
| `KID_MISMATCH` | 4 | A co-signature's `signer_kid` differs from the `kid` in its header. |
| `COSIG_PAYLOAD_MISMATCH` | 4 | A co-signature's payload bytes are not those of the pack claim. |
| `COSIG_ROLE_INVALID` | 4 | A co-signature verifies but its role is not `operator_attestation`. |
| `COSIG_SIG_INVALID` | 4 | A co-signature does not verify under the system set. |
| `CONTENT_HASH_MISMATCH` | 5 | The skeleton hash differs from the signed `content_hash`. |
| `CLAIM_COUNT_MISMATCH` | 6 | `claim_count` differs from the number of claim entries. |
| `CLAIM_ID_INVALID` | 7 | A `claim_id` is malformed. |
| `CLAIM_ID_DUPLICATE` | 7 | Two entries share a `claim_id`. |
| `MERKLE_COMPUTE_FAILED` | 8 | A `claim_hash` is not 64 lowercase hex characters. |
| `MERKLE_ROOT_MISMATCH` | 8 | The recomputed root differs from the signed `merkle_root`. |
| `CLAIM_HASH_MISMATCH` | 9 | An entry's `claim_hash` is not the SHA-256 of its `envelope_cose`. |
| `CLAIM_SIG_INVALID` | 9 | An entry could not be decoded, its signature does not verify, or its issuer differs from the pack issuer. |
| `REVIEW_REFERENCE_INVALID` | 10 | A reference or rule of 8.3 is violated. |
| `INCLUDED_REVIEW_IDS_INVALID` | 11 | `included_review_claim_ids` is not an array of strings. |
| `INCLUDED_REVIEW_IDS_MISMATCH` | 11 | The signed list differs from the review claims actually present. |
| `SCHEMA_HASH_MISMATCH` | 13 | An inline schema body does not hash to its `content_hash`. |
| `SCHEMA_PIN_MISSING` | 13 | An inline schema has no pin in `schema_versions`. |
| `SCHEMA_PIN_MISMATCH` | 13 | A pin differs from the inline schema's hash (including a zero placeholder beside an inline schema). |
| `UNKNOWN_CLAIM_TYPE` | 15 | A claim type has no inline schema, in strict or air-gap mode. |
| `NO_ANCHOR_JWK` | 16 | Neither key set holds any key to check the head signature. |
| `ANCHOR_SIG_INVALID` | 16 | `head_signature` does not verify under any key. |

### 8.5 Warning codes

A warning code never changes `valid`. Every warning makes `complete` false.

| Code | Step | Meaning |
|---|---|---|
| `STACK_COSIGNATURE_MISSING` | 4 | The pack has no co-signature. |
| `CLAIM_IDS_MISSING` | 7 | Some claim entries have no `claim_id` (an older pack). |
| `REVIEW_RELATIONSHIPS_UNVERIFIABLE` | 10 | Review claims exist but not every entry has a `claim_id`, so the links cannot be checked. |
| `INCLUDED_REVIEW_IDS_MISSING` | 11 | The pack claim does not list its review revisions (an older pack). |
| `AUDIT_PROOFS_INCOMPLETE` | 12 | Some claims have no inclusion proof, or only a placeholder. |
| `AUDIT_PROOFS_UNVERIFIED` | 12 | Proof entries are present but this version cannot evaluate them. |
| `SCHEMA_HASH_NOT_ATTESTED` | 14 | A pin is missing or is the all-zero placeholder. |
| `SCHEMA_PIN_UNCHECKED` | 14 | A pin names a schema that has no inline body to recompute. |
| `UNKNOWN_CLAIM_TYPE` | 15 | A claim type has no inline schema (default or ignore-unknown mode). |
| `EXTERNAL_ANCHORS_MISSING` | 17 | The pack lists no external chain anchor. |
| `NOOP_ANCHOR` | 17 | An anchor is synthetic (`noop://`). |

A check recorded as `skip` (an external anchor that was not fetched) also makes `complete` false, although it adds no warning code.

**Reachability of `complete`.** Step 12 always records a warning in this version, so a verifier that follows this procedure returns `complete: false` for every pack. The flag is part of the result so that a later minor version, which defines how inclusion proofs are evaluated, can return `true` without changing the result shape. A relying party in this version MUST NOT read `complete: false` alone as a sign of damage, and SHOULD read the warning codes.

### 8.6 Reference command line

A verifier SHOULD offer a command-line interface. The reference interface is:

```
stack-verify <pack.json> [flags]
stack-verify - < pack.json
```

The path argument is the first argument that does not start with `--`; `-` reads standard input. Flags: `--air-gap`, `--strict`, `--ignore-unknown`, `--fresh-jwks` (accepted, no effect), `--activity`, `--replay` (alias of `--activity`), `--json` (print the VerifyResult as JSON), `--help`.

| Exit code | Meaning |
|---|---|
| `0` | The result is `valid: true`, or `--help` was given. |
| `1` | The result is `valid: false`, or the verifier failed abnormally (including `--strict` with `--ignore-unknown`). |
| `2` | Usage error: no arguments, no path, the file cannot be read, or the content is not JSON. |

`complete` does not affect the exit code.

## 9. Activity reconstruction

Activity reconstruction is OPTIONAL. A verifier that implements it conforms to Level 3 (Section 10). It turns the signed claims of a verified mission pack into an ordered account of what happened. It is an interpretation of signed claims, not additional evidence, and it never affects `valid` or `complete`.

**When it runs.** On request (`--activity`, or `--replay`), the verifier sets `activity` in the result. `activity` is `null` if the result has any error, if `scope.kind` is not `mission`, or if the pack issuer is unset. Otherwise it is the timeline below, built from the decoded claims of step 9 that have a string `claim_type`, a numeric `issued_at` and an object payload. The mission id is `scope.ref` and the operator id is the pack issuer.

**Timeline shape.**

| Member | Type | Content |
|---|---|---|
| `mission` | object | `mission_id`, `operator_id`, `open` (payload of the first mission claim, if any), `close` (payload of the last mission claim, if any; equal to `open` when there is only one), `closed` (boolean). |
| `events` | array | Events, ordered as below. |
| `behavioral_diff` | object or null | `max_z`, `l2_norm`, `per_dimension`, from the last mission claim. |
| `cap_usage` | object | `max_actions`, `max_dropoff_bytes`, `coverage_cap_cents` (numbers or null), `observed_wallet_cents`, `observed_action_count`. |
| `dossiers` | array | Events of kind `dossier`. |
| `operator_reviews` | array | Events of kind `dossier` and `operator_review` together. |
| `twin_divergence` | event or null | The latest `twin_divergence` claim. |

An **event** is `{kind, at_ms, claim_id, claim_hash, body}` where `body` is the claim's payload, `claim_id` and `claim_hash` are those of the entry (`null` if absent), and `at_ms` is the envelope's `issued_at` unless stated.

**Rules.**

1. Mission claims are the claims of type `mission` whose payload `mission_id` equals the mission id. They are ordered by `issued_at` ascending (stable). The first yields an event of kind `mission_open`. If there are at least two and the last has a truthy `terminal_state`, the last yields an event of kind `mission_close`. `closed` is true if the last mission claim has a truthy `terminal_state`. `behavioral_diff` is the last mission claim's `behavioral_diff` if it is an object with numeric `max_z` and `l2_norm` and an object `per_dimension`, otherwise `null`. The three caps are the last mission claim's `max_actions`, `max_dropoff_bytes` and `coverage_cap_cents` when they are numbers, otherwise `null`.
2. Claims of the following types, other than the mission and the special cases below, each yield an event whose kind is shown:

| Claim type | Kind |
|---|---|
| `intent_claim` | `intent_submitted` |
| `intent_outcome` | `intent_outcome` |
| `intent_denial` | `intent_denial` |
| `intent_simulation` | `intent_simulation` |
| `entity_observation` | `entity_observation` |
| `detector_signal` | `detector_signal` |
| `checkpoint_approval` | `checkpoint_approval` |
| `skill_invocation` | `skill_invocation` |
| `behavioral_genome` | `behavioral_genome` |
| `operator_decision` | `operator_decision` |

Claims of any other type are not shown in `events`. The event kinds also include `mission_open`, `mission_close`, `operator_review`, `dossier` and `twin_divergence`.

3. `events` holds the mission events and the events of rule 2, ordered by `at_ms` ascending, ties broken by `claim_id` ascending (a missing `claim_id` sorts as the empty string), comparing as UTF-16 code unit sequences.
4. A `dossier` claim yields an event of kind `dossier` whose `at_ms` is the payload's `authored_at_ms` if numeric, otherwise `issued_at`. `dossiers` is these events ordered by `at_ms`, then `claim_id`. An `operator_review` claim yields an event of kind `operator_review` with `at_ms` defined the same way. `operator_reviews` is the dossier events and the review events together, in one ordering by `at_ms` then `claim_id`. Neither kind appears in `events`.
5. `twin_divergence` is the claim of that type with the greatest `issued_at` (an event of kind `twin_divergence`), or `null`.
6. `observed_action_count` is the number of `intent_outcome` claims and `observed_wallet_cents` is the sum of their numeric payload `wallet_cents`. Both count every `intent_outcome` claim among the decoded claims.

Claims of the types in rules 2, 4 and 5 are not filtered by mission; only mission claims are.

## 10. Conformance

A verifier is evaluated at one of three levels. A higher level includes every requirement of the lower ones.

| Level | Name | Requires |
|---|---|---|
| 1 | Internal integrity | Steps 1 to 9, 13, 14 and 15 of Section 8.2: manifest shape, pack claim decoding and signature, co-signatures, content hash, claim count, claim identifiers, Merkle root, per-claim hashes and signatures, schema content hashes and pins, schema attestation, unknown claim types and the three modes. The COSE profile (4.4), the key resolution rules (4.5), canonical JSON (3.1) and the Merkle rule (Section 6). |
| 2 | Audit anchor and relationships | Level 1, plus steps 10, 11, 12, 16, 17 and 18: review relationships, included review identifiers, audit proof reporting, the signed chain head, external anchor reporting and the revocation snapshot count. |
| 3 | Activity | Level 2, plus step 19 and Section 9. |

A conforming implementation at any level MUST:

- compute `valid` and `complete` as in 8.1 and report error codes only for the conditions in 8.4;
- report warning codes for the conditions in 8.5 (warning codes are not compared by the kit but MUST be reported);
- support the default, strict, ignore-unknown and air-gap modes at Level 1, and refuse strict together with ignore-unknown;
- not require network access in any mode.

**The conformance kit.** The kit in `spec/conformance/` feeds each fixture pack in `spec/conformance/fixtures/record/` to the verifier under test and compares three things with the fixture's expected outcome: `valid`, `complete`, and the set of error codes (as a set, ignoring order and repetition). The fixtures are one valid pack and a number of tampered variants, each of which is expected to produce a named error code. A verifier passes a level if it matches the expected outcome on every fixture of that level and the levels below. Because of 8.5, the expected `complete` is `false` for every fixture in this version. How the kit invokes a verifier is described in the kit.

The reference implementation is published as `@getstackrun/verify`.

## 11. Machine-readable schemas

JSON Schemas generated from the reference implementation's definitions are stored next to this file, in `schemas/`:

| File | Describes |
|---|---|
| `schemas/ClaimEnvelope.json` | The claim envelope (4.1). |
| `schemas/EvidencePackManifest.json` | The manifest (7.1). |
| `schemas/EvidencePackClaim.json` | The pack claim payload (7.3). |
| `schemas/CoSignature.json` | A co-signature (4.7). |
| `schemas/Receipt.json` | The receipt (4.3). |
| `schemas/claims/<claim_type>.json` | The payload of each claim type, one file per type. |

The claim types defined by this version are:

<!-- spec:generated:record-claim-types -->

| Claim type | Payload schema | Content hash |
|---|---|---|
| `ai_bom_ref` | [`schemas/claims/ai_bom_ref.json`](schemas/claims/ai_bom_ref.json) | `sha256:19f9718e58bc61fdd5bc3db40c4c3f4ccdb8a79dee2b963e1cef869bb2a9d85a` |
| `authority_approval` | [`schemas/claims/authority_approval.json`](schemas/claims/authority_approval.json) | `sha256:b940a7f89d21a3ea231369c4551948135114f743a814bb848448c2b243c958e3` |
| `authority_binding` | [`schemas/claims/authority_binding.json`](schemas/claims/authority_binding.json) | `sha256:73736da826de63d7a631d2fe8822334dd3d962b5c5fe2b509fe2963066c96dfe` |
| `authority_erasure_tombstone` | [`schemas/claims/authority_erasure_tombstone.json`](schemas/claims/authority_erasure_tombstone.json) | `sha256:e4c6a63190480e460028479d0f7ebc652e253ec44a95206dc85f2e783e91e5c6` |
| `authority_use` | [`schemas/claims/authority_use.json`](schemas/claims/authority_use.json) | `sha256:09446941ab3d9e0a62f19bf8f274050bb26e466472e38c66a5ab6352884037f0` |
| `behavioral_genome` | [`schemas/claims/behavioral_genome.json`](schemas/claims/behavioral_genome.json) | `sha256:0e097a947407083aed4b04eb39c0e45f756ff980afba581651e441a46c9b1ed1` |
| `c2pa_assertion` | [`schemas/claims/c2pa_assertion.json`](schemas/claims/c2pa_assertion.json) | `sha256:2af4b1d5a4fe479645bdbc9bbf1ed1f9ed2a6298266706e83d46eaccd410aa67` |
| `checkpoint_approval` | [`schemas/claims/checkpoint_approval.json`](schemas/claims/checkpoint_approval.json) | `sha256:f6aa07dae9e1b5ef6d1558286645ffdee5a96ed6403999a564a0a9ad516ff09a` |
| `detector_signal` | [`schemas/claims/detector_signal.json`](schemas/claims/detector_signal.json) | `sha256:caf070cd15a4068601a564f07b58365588cf77a11f850846843131462b77bfc8` |
| `dossier` | [`schemas/claims/dossier.json`](schemas/claims/dossier.json) | `sha256:614e55ed961f810b7cfa887f0d1b8262c7a86e3a586b892fd1ea6d344b0b2f16` |
| `entity_observation` | [`schemas/claims/entity_observation.json`](schemas/claims/entity_observation.json) | `sha256:9e4804d731b2b696a984ef6ba575b55dcb7e4a752b964f455f92e490bf728fc4` |
| `evidence_pack` | [`schemas/claims/evidence_pack.json`](schemas/claims/evidence_pack.json) | `sha256:26f9fcce77f8ef0700f56f3bb46f396a2daaf0de3314bd7f3625feb8ce877a69` |
| `external_proof_verification` | [`schemas/claims/external_proof_verification.json`](schemas/claims/external_proof_verification.json) | `sha256:779319b26b9e11f7bd5e96795dfe3b5c944504bb7c92931368c4573e8326279c` |
| `identity_claim` | [`schemas/claims/identity_claim.json`](schemas/claims/identity_claim.json) | `sha256:8d52ee204de567dbf6e498a4c619d8d246915fadbde1010dfc9e5e5dc71e9d4f` |
| `intent_claim` | [`schemas/claims/intent_claim.json`](schemas/claims/intent_claim.json) | `sha256:0305fd29a947bf3dcd0f210a13368104cd49eaa09932d70cd0bb2ef51073b8c1` |
| `intent_denial` | [`schemas/claims/intent_denial.json`](schemas/claims/intent_denial.json) | `sha256:3a810a8207568c392cb1f712c3dda6d7e5a761ead789830c856bd5923bbab3cc` |
| `intent_outcome` | [`schemas/claims/intent_outcome.json`](schemas/claims/intent_outcome.json) | `sha256:4c5ad44b725e2e4f521a83735db2216bbfdcfeb739f3bb42e8946b575a3e1299` |
| `intent_simulation` | [`schemas/claims/intent_simulation.json`](schemas/claims/intent_simulation.json) | `sha256:0ed880035e87703c5097fbd2bb86da285ee17948417188aa8546c528b8a8b96c` |
| `mission` | [`schemas/claims/mission.json`](schemas/claims/mission.json) | `sha256:30570bdd0fa8e71d70c53f3fd78453d97ddfb03873e1f10ad571639e616e13ae` |
| `operator_decision` | [`schemas/claims/operator_decision.json`](schemas/claims/operator_decision.json) | `sha256:2105ef6fde2acd2661229e056e45544f1ba26e7bb029731995d2b6ed475824dc` |
| `operator_review` | [`schemas/claims/operator_review.json`](schemas/claims/operator_review.json) | `sha256:868e19f5ae860c74fb3c9147f769c0e00ba77919cc85466a4f98e9bbf168484f` |
| `rats_evidence` | [`schemas/claims/rats_evidence.json`](schemas/claims/rats_evidence.json) | `sha256:9ea68b1fd9cb875e2d7ed186c64d78ebffd83b9ba0271edd0c6ef2cc8248c508` |
| `receiver_transaction_receipt` | [`schemas/claims/receiver_transaction_receipt.json`](schemas/claims/receiver_transaction_receipt.json) | `sha256:2dc3cc33859befd301f8acc723305f953af32b96b7319cb0b64127b520d7c228` |
| `sandbox_run` | [`schemas/claims/sandbox_run.json`](schemas/claims/sandbox_run.json) | `sha256:7268a6e78eb19b74c06de226e326df9a70d183de7dd8dbb0c589e451141d908e` |
| `skill_invocation` | [`schemas/claims/skill_invocation.json`](schemas/claims/skill_invocation.json) | `sha256:44035bc9fcfe79766ead5c2a06035b39b99ca5a405ba358b38dad37cf12ed40d` |
| `slsa_provenance` | [`schemas/claims/slsa_provenance.json`](schemas/claims/slsa_provenance.json) | `sha256:7ee16d13732c61c1ace57f65552c379ff89440bb2ec0862db10a743aa03c624f` |
| `svid_attestation` | [`schemas/claims/svid_attestation.json`](schemas/claims/svid_attestation.json) | `sha256:1541bcc06502998197400e4122164d9c50fa9e0826da8e5c28e229b7b82f7a89` |
| `twin_divergence` | [`schemas/claims/twin_divergence.json`](schemas/claims/twin_divergence.json) | `sha256:5bdef39432f5cb281134052c0c6e831006cd24816144d5f65b0e5b0f84ab3678` |
| `workload_attestation` | [`schemas/claims/workload_attestation.json`](schemas/claims/workload_attestation.json) | `sha256:4ddcf123e800cfdf6849a4b651bc50891875b9a2d1fca8dbd8c08f3bb4a04170` |
| `workspace_action` | [`schemas/claims/workspace_action.json`](schemas/claims/workspace_action.json) | `sha256:8917ec47a80bf2cdea19b9605583bcffc609a0ac256492bc0775948967fa110c` |

<!-- /spec:generated -->

The schemas are an aid to implementers. They describe the shape of values after parsing; they cannot express the rules of Sections 3 to 8 (for example the COSE profile or the hashes). Where a schema and this text disagree, this text governs and the disagreement is a defect.

## 12. Worked example

This example builds the smallest useful pack: one mission claim, a pack claim, a STACK co-signature and a signed chain head. The complete manifest is in Appendix A. Every value below was produced with the reference implementation, and the finished manifest verified with it. The keys are throwaway keys created only for this document. The mission claim's payload is abbreviated to three members for readability, and the two inline schemas are stand-in bodies (`{"$id": "...", "type": "object"}`) so that the manifest stays short; a real pack carries the full schemas.

**1. The operator key and the system key.** The operator key has `kid` `op_example:claim:v1` and public key `x` = `rDRf8ubnmxRWVrlTHwNYAZFwNTP7wIcuR9qHEdZvjSU`. The system key has `kid` `stack-passport-v1` and `x` = `68D41oAx3bk2cbG_dKSz5yNzqIr6IupMKgzi7Q3oC-0`. Both are published as inline key sets in `verification_material`.

**2. The claim.** The envelope (before CBOR encoding) is

```
{
  "envelope_version": 1,
  "issuer": "op_example",
  "subject": "stack://operator/op_example/mission/ms_example",
  "issued_at": 1792486800000,
  "claim_type": "mission",
  "claim_version": 1,
  "payload": { "type": "mission", "mission_id": "ms_example", "terminal_state": null },
  "receipt": null,
  "co_signatures": []
}
```

It is encoded to CBOR (234 bytes). The protected header is the 45 bytes

```
d90103 a3 01 27 04 53 6f705f6578616d706c653a636c61696d3a7631 10 70 737461636b2f636c61696d2b636f7365
```

read as tag 259, a three-entry map, `1: -8`, `4:` a 19-byte byte string (the UTF-8 of `op_example:claim:v1`), and `16:` the 16-character text `stack/claim+cose`. `Sig_structure1` (296 bytes) is `["Signature1", protected, h'', payload]`. The Ed25519 signature over it is placed in the fourth element, and the 354-byte message, base64url encoded, is the claim's `envelope_cose`.

**3. The claim hash.** `claim_hash` = SHA-256 of the 354 message bytes = `ff8830c039e250b817fb49c9519538833f26be1ce937f30e82b7d332d8a0b860`. The manifest entry is `{"claim_id":"pc_example1","claim_hash":"ff88...b860","envelope_cose":"...","revoked_at_ms":null}`.

**4. The audit entry.** An audit entry of hash version 2 records that the Passport was issued, with `passport_claims_at_event` equal to `["ff88...b860"]` and the genesis value as `prev_entry_hash`. Its hash (Section 5.2) is `5eb86cc984a6f26a21fb079f9f2013ade24f46f10eed45a515666c24cf253338`. It is the only entry, so it is the chain head.

**5. The signed head.** The operator key signs the UTF-8 bytes of

```
{"head_at_ms":1792487100000,"head_hash":"5eb86cc984a6f26a21fb079f9f2013ade24f46f10eed45a515666c24cf253338"}
```

giving `head_signature` = `OEZO75LvXW8Ru_RyUy-z_EcxnGe_NUNTaqAX2_OCbzlkD_srSDUc3W5sFRnSSepJTvVv0O-WizonguhmDyiZBg`.

**6. The Merkle root.** With one leaf, the root is the leaf: `merkle_root` = `sha256:ff8830c039e250b817fb49c9519538833f26be1ce937f30e82b7d332d8a0b860`.

**7. The schemas.** The envelope stand-in schema hashes to `sha256:9c194518ee1400ebae0a836be356827fc37eb8a669a0a5fc61f7c9e954c114b2` and the mission stand-in schema to `sha256:94d5c6691fa6e8a1cd0aba98e364fd41b7419d6bd6656775ff478c7148717a74`. Each is copied into `schemas_inline` and pinned in `schema_versions`.

**8. The content hash.** The skeleton (Section 7.2) of the manifest has a canonical length of 1797 bytes. `content_hash` = `sha256:c62334a564c80d5b8e50b21652c1c00783e077b38e302e11188e5b1beb7b00d8`.

**9. The pack claim.** The pack claim is the envelope (`claim_type` `evidence_pack`, `subject` `stack://operator/op_example`) whose payload holds `pack_id` `pck_example`, the content hash, the scope `{"kind":"mission","ref":"ms_example"}`, `claim_count` `1`, `included_review_claim_ids` `[]`, the Merkle root, the audit anchor and the schema pins. It is signed by the operator key and the result is the manifest's `claim`.

**10. The co-signature.** The system key signs the same payload bytes as the pack claim, with its own `kid`, producing a second COSE_Sign1. It is added as `{"signer_kid":"stack-passport-v1","signer_role":"operator_attestation","cose_sign1":"..."}`.

**11. Verification.** A verifier following Section 8.2 records, in order: `manifest-shape` pass; `pack-claim-signature` pass (`kid=op_example:claim:v1`); `co-signature` pass (role `operator_attestation`); `content-hash` pass; `claim-count` pass; `claim-ids` pass; `merkle-root` pass; `per-claim-hashes` pass; `per-claim-signatures` pass; `included-review-ids` pass; `audit-chain-proofs` warn (`AUDIT_PROOFS_INCOMPLETE`, because the proof is the placeholder); `schemas-inline` pass; `schema-hash-attestation` pass; `unknown-claim-type` pass; `audit-chain-anchor` pass; `external-anchor` warn (`EXTERNAL_ANCHORS_MISSING`); `revocation-snapshot` pass.

The result is `valid: true`, `complete: false`, with the two warnings above and no errors. The pack is internally sound; it is not complete because it carries no inclusion proof that can be evaluated and no external anchor.

**12. Tampering.** Three edits were applied to the manifest and run through the reference verifier:

| Edit | Result |
|---|---|
| `claims[0].claim_hash` replaced by 64 `f` characters | `valid: false`; errors `CONTENT_HASH_MISMATCH`, `MERKLE_ROOT_MISMATCH`, `CLAIM_HASH_MISMATCH`. |
| `claims[0].revoked_at_ms` set to `5` | `valid: false`; error `CONTENT_HASH_MISMATCH`. |
| `co_signatures` emptied | `valid: true`, `complete: false`; the warning `STACK_COSIGNATURE_MISSING` is added. |

## 13. Versioning and compatibility

This specification uses semantic versioning. A change to a byte-level definition that would make an existing valid record invalid, or that changes the meaning of an existing member, is a major version. A change that adds optional members, new claim types, new error or warning codes for new conditions, or new verifier checks that cannot fail an existing valid pack, is a minor version. Corrections and clarifications are patch versions.

The wire versions are named in the data: `envelope_version`, `claim_version`, `pack_version` and the audit `hash_version`. Each stays additive-only for at least 24 months from the first release of that wire version (4.8). Within that period:

- a verifier MUST ignore claim types, members and enumerated values it does not recognise, except where a hash covers them;
- a verifier MUST reject a `pack_version` other than `1`;
- a producer MUST NOT change the meaning of an existing member.

Adding a new kind of evidence (for example a hardware attestation) adds a claim type, a schema and a pin. It does not change the manifest, and it does not require a verifier upgrade to check the pack's hashes and signatures; under 7.10 a verifier that lacks the schema reports the type as unknown.

Everything in this specification that a verifier does not evaluate in this version is marked reserved: inclusion proof paths (5.6), receipts (4.3), cross-tenant references (7.8), external anchor fetching (7.7) and the `agent_self` and `witness` roles (4.7). A later minor version may define them.

## Appendix A. Example manifest

The complete manifest of Section 12, formatted for reading. It verifies with `valid: true` and `complete: false`.

```json
{
  "pack_version": 1,
  "claim": "hFgt2QEDowEnBFNvcF9leGFtcGxlOmNsYWltOnYxEHBzdGFjay9jbGFpbStjb3Nl2QEDoFkEeLkACXBlbnZlbG9wZV92ZXJzaW9uAWZpc3N1ZXJqb3BfZXhhbXBsZWdzdWJqZWN0eBtzdGFjazovL29wZXJhdG9yL29wX2V4YW1wbGVpaXNzdWVkX2F0-0J6FYkyJAAAamNsYWltX3R5cGVtZXZpZGVuY2VfcGFja21jbGFpbV92ZXJzaW9uAWdwYXlsb2FkuQAPZHR5cGVtZXZpZGVuY2VfcGFja2dwYWNrX2lka3Bja19leGFtcGxlbGNvbnRlbnRfaGFzaHhHc2hhMjU2OmM2MjMzNGE1NjRjODBkNWI4ZTUwYjIxNjUyYzFjMDA3ODNlMDc3YjM4ZTMwMmUxMTE4OGU1YjFiZWI3YjAwZDhlc2NvcGW5AAJka2luZGdtaXNzaW9uY3JlZmptc19leGFtcGxla3RpbWVfYm91bmRzuQACZXQwX21z-0J6FYifqAAAZXQxX21z-0J6FYkyJAAAa2NsYWltX2NvdW50AXgZaW5jbHVkZWRfcmV2aWV3X2NsYWltX2lkc4BrbWVya2xlX3Jvb3R4R3NoYTI1NjpmZjg4MzBjMDM5ZTI1MGI4MTdmYjQ5Yzk1MTk1Mzg4MzNmMjZiZTFjZTkzN2YzMGU4MmI3ZDMzMmQ4YTBiODYwcmF1ZGl0X2NoYWluX2FuY2hvcrkAA2loZWFkX2hhc2h4QDVlYjg2Y2M5ODRhNmYyNmEyMWZiMDc5ZjlmMjAxM2FkZTI0ZjQ2ZjEwZWVkNDVhNTE1NjY2YzI0Y2YyNTMzMzhuaGVhZF9zaWduYXR1cmV4Vk9FWk83NUx2WFc4UnVfUnlVeS16X0VjeG5HZV9OVU5UYXFBWDJfT0NiemxrRF9zclNEVWMzVzVzRlJuU1NlcEpUdlZ2ME8tV2l6b25ndWhtRHlpWkJnamhlYWRfYXRfbXP7QnoViOjmAAB4GXJldm9jYXRpb25fc25hcHNob3RfYXRfbXP7QnoViTIkAABvc2NoZW1hX3ZlcnNpb25zuQACaGVudmVsb3BluQACZ3ZlcnNpb24BbGNvbnRlbnRfaGFzaHhHc2hhMjU2OjljMTk0NTE4ZWUxNDAwZWJhZTBhODM2YmUzNTY4MjdmYzM3ZWI4YTY2OWEwYTVmYzYxZjdjOWU5NTRjMTE0YjJtYnlfY2xhaW1fdHlwZbkAAWdtaXNzaW9uuQACZ3ZlcnNpb24BbGNvbnRlbnRfaGFzaHhHc2hhMjU2Ojk0ZDVjNjY5MWZhNmU4YTFjZDBhYmE5OGUzNjRmZDQxYjc0MTlkNmJkNjY1Njc3NWZmNDc4YzcxNDg3MTdhNzR4GWNhbm9uaWNhbF9zY2hlbWFfYmFzZV91cmx4M2h0dHBzOi8vZXhhbXBsZS5pbnZhbGlkL3NjaGVtYXMvcGFzc3BvcnQtY2xhaW1zL3YxL2pzdXBlcnNlZGVz9nFjcm9zc190ZW5hbnRfcmVmc4B2ZXh0ZXJuYWxfY2hhaW5fYW5jaG9yc4BncmVjZWlwdPZtY29fc2lnbmF0dXJlc4BYQHre2rgr2yK6bLFeLiQrsCEI23XpCO9s03yWEnQqd1TCo8OLa2KLg7FRuBXGqKAaVaCrDgrIH_AhzF0EDWu0dQQ",
  "co_signatures": [
    {
      "signer_kid": "stack-passport-v1",
      "signer_role": "operator_attestation",
      "cose_sign1": "hFgr2QEDowEnBFFzdGFjay1wYXNzcG9ydC12MRBwc3RhY2svY2xhaW0rY29zZdkBA6BZBHi5AAlwZW52ZWxvcGVfdmVyc2lvbgFmaXNzdWVyam9wX2V4YW1wbGVnc3ViamVjdHgbc3RhY2s6Ly9vcGVyYXRvci9vcF9leGFtcGxlaWlzc3VlZF9hdPtCehWJMiQAAGpjbGFpbV90eXBlbWV2aWRlbmNlX3BhY2ttY2xhaW1fdmVyc2lvbgFncGF5bG9hZLkAD2R0eXBlbWV2aWRlbmNlX3BhY2tncGFja19pZGtwY2tfZXhhbXBsZWxjb250ZW50X2hhc2h4R3NoYTI1NjpjNjIzMzRhNTY0YzgwZDViOGU1MGIyMTY1MmMxYzAwNzgzZTA3N2IzOGUzMDJlMTExODhlNWIxYmViN2IwMGQ4ZXNjb3BluQACZGtpbmRnbWlzc2lvbmNyZWZqbXNfZXhhbXBsZWt0aW1lX2JvdW5kc7kAAmV0MF9tc_tCehWIn6gAAGV0MV9tc_tCehWJMiQAAGtjbGFpbV9jb3VudAF4GWluY2x1ZGVkX3Jldmlld19jbGFpbV9pZHOAa21lcmtsZV9yb290eEdzaGEyNTY6ZmY4ODMwYzAzOWUyNTBiODE3ZmI0OWM5NTE5NTM4ODMzZjI2YmUxY2U5MzdmMzBlODJiN2QzMzJkOGEwYjg2MHJhdWRpdF9jaGFpbl9hbmNob3K5AANpaGVhZF9oYXNoeEA1ZWI4NmNjOTg0YTZmMjZhMjFmYjA3OWY5ZjIwMTNhZGUyNGY0NmYxMGVlZDQ1YTUxNTY2NmMyNGNmMjUzMzM4bmhlYWRfc2lnbmF0dXJleFZPRVpPNzVMdlhXOFJ1X1J5VXktel9FY3huR2VfTlVOVGFxQVgyX09DYnpsa0Rfc3JTRFVjM1c1c0ZSblNTZXBKVHZWdjBPLVdpem9uZ3VobUR5aVpCZ2poZWFkX2F0X21z-0J6FYjo5gAAeBlyZXZvY2F0aW9uX3NuYXBzaG90X2F0X21z-0J6FYkyJAAAb3NjaGVtYV92ZXJzaW9uc7kAAmhlbnZlbG9wZbkAAmd2ZXJzaW9uAWxjb250ZW50X2hhc2h4R3NoYTI1Njo5YzE5NDUxOGVlMTQwMGViYWUwYTgzNmJlMzU2ODI3ZmMzN2ViOGE2NjlhMGE1ZmM2MWY3YzllOTU0YzExNGIybWJ5X2NsYWltX3R5cGW5AAFnbWlzc2lvbrkAAmd2ZXJzaW9uAWxjb250ZW50X2hhc2h4R3NoYTI1Njo5NGQ1YzY2OTFmYTZlOGExY2QwYWJhOThlMzY0ZmQ0MWI3NDE5ZDZiZDY2NTY3NzVmZjQ3OGM3MTQ4NzE3YTc0eBljYW5vbmljYWxfc2NoZW1hX2Jhc2VfdXJseDNodHRwczovL2V4YW1wbGUuaW52YWxpZC9zY2hlbWFzL3Bhc3Nwb3J0LWNsYWltcy92MS9qc3VwZXJzZWRlc_ZxY3Jvc3NfdGVuYW50X3JlZnOAdmV4dGVybmFsX2NoYWluX2FuY2hvcnOAZ3JlY2VpcHT2bWNvX3NpZ25hdHVyZXOAWEDV6Pi6NP3iAiw8NQvI12seMJVLxRon0k3svrSS4a0qiaAfXvmabuBMIMHddG6nQwfrH-PpwX_yrkER3HRgLaQD"
    }
  ],
  "claims": [
    {
      "claim_id": "pc_example1",
      "claim_hash": "ff8830c039e250b817fb49c9519538833f26be1ce937f30e82b7d332d8a0b860",
      "envelope_cose": "hFgt2QEDowEnBFNvcF9leGFtcGxlOmNsYWltOnYxEHBzdGFjay9jbGFpbStjb3Nl2QEDoFjquQAJcGVudmVsb3BlX3ZlcnNpb24BZmlzc3VlcmpvcF9leGFtcGxlZ3N1YmplY3R4LnN0YWNrOi8vb3BlcmF0b3Ivb3BfZXhhbXBsZS9taXNzaW9uL21zX2V4YW1wbGVpaXNzdWVkX2F0-0J6FYifqAAAamNsYWltX3R5cGVnbWlzc2lvbm1jbGFpbV92ZXJzaW9uAWdwYXlsb2FkuQADZHR5cGVnbWlzc2lvbmptaXNzaW9uX2lkam1zX2V4YW1wbGVudGVybWluYWxfc3RhdGX2Z3JlY2VpcHT2bWNvX3NpZ25hdHVyZXOAWEB74uHpaCQ1WEfqs31GGi8Eh1JGA_mzYcrilbgSTLMmu_RC7ZkeQ2huQwQX0TgxE8SqbeIeEEi_JvBkA55X_4UP",
      "revoked_at_ms": null
    }
  ],
  "audit_chain_proofs": [
    {
      "claim_hash": "ff8830c039e250b817fb49c9519538833f26be1ce937f30e82b7d332d8a0b860",
      "audit_position": 0,
      "merkle_path": []
    }
  ],
  "verification_material": {
    "operator_jwks_url": "https://api.getstack.run/v1/operators/op_example/jwks.json",
    "operator_jwks_inline": {
      "keys": [
        {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "rDRf8ubnmxRWVrlTHwNYAZFwNTP7wIcuR9qHEdZvjSU",
          "kid": "op_example:claim:v1",
          "alg": "EdDSA",
          "use": "sig"
        }
      ]
    },
    "stack_system_jwks_url": "https://api.getstack.run/v1/.well-known/jwks.json",
    "stack_system_jwks_inline": {
      "keys": [
        {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "68D41oAx3bk2cbG_dKSz5yNzqIr6IupMKgzi7Q3oC-0",
          "kid": "stack-passport-v1",
          "alg": "EdDSA",
          "use": "sig"
        }
      ]
    }
  },
  "schemas_inline": {
    "envelope": {
      "$schema": "http://json-schema.org/draft-07/schema#",
      "content_hash": "sha256:9c194518ee1400ebae0a836be356827fc37eb8a669a0a5fc61f7c9e954c114b2",
      "json_schema": {
        "$id": "https://example.invalid/schemas/envelope",
        "type": "object"
      }
    },
    "mission": {
      "$schema": "http://json-schema.org/draft-07/schema#",
      "content_hash": "sha256:94d5c6691fa6e8a1cd0aba98e364fd41b7419d6bd6656775ff478c7148717a74",
      "json_schema": {
        "$id": "https://example.invalid/schemas/mission",
        "type": "object"
      }
    }
  }
}
```
