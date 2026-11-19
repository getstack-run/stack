# Changelog

All notable changes to the STACK Record Format are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Versioning

This specification uses [semantic versioning](https://semver.org/). A change that would make a previously valid record invalid, or that changes the meaning of an existing member, is a major version. Added optional members, new claim types and new codes for new conditions are minor versions. Corrections and clarifications are patch versions.

`envelope_version` and `pack_version` are the wire versions, written into the data itself, and the audit `hash_version` is the wire version of the audit chain. Wire changes are additive for at least 24 months from the first release of each wire version: only optional members may be added, and nothing is removed, renamed, retyped or given a new meaning. Breaking a wire version after that period requires a new version number, a published migration window and the re-signing of affected historical claims.

## 1.0.0 - 2026-10-21

Initial public release.

- Claim envelope, `envelope_version` 1: members, constraints, the `stack://` subject URI grammar and the receipt slot.
- COSE_Sign1 profile: EdDSA (`alg` `-8`), protected header labels 1 (`alg`), 4 (`kid`, UTF-8 bytes) and 16 (`typ`, `stack/claim+cose`), CBOR payload carrying the envelope, `Sig_structure1` construction and base64url transport.
- Key identifiers and key set resolution: operator claim keys and STACK system keys, the two public JWKS locations, inline key sets in packs, and the rules for which key set may sign which claim.
- `claim_hash` as the SHA-256 of the COSE message bytes; co-signatures and the `operator_attestation`, `agent_self` and `witness` roles.
- Canonical JSON and the encoding rules used for hashes.
- Audit hash chain: entry hash versions 1 and 2 with their exact member order, the genesis value, per-operator `prev_entry_hash` linkage, claim binding, the chain head and the signed head.
- Merkle rule for claim sets: unpaired nodes promoted unchanged, single-leaf root equals the leaf, defined empty root.
- Evidence pack format, `pack_version` 1: manifest, `content_hash`, pack claim, scope kinds, schema pinning and inline schemas, `supersedes`, external anchors, cross-tenant references and review claim identifiers.
- Verifier outcomes: the ordered verification procedure, the full error and warning code lists, the `valid` and `complete` verdicts, the default, strict, ignore-unknown and air-gap modes, and the exit codes of the reference command line.
- Optional activity reconstruction from a verified mission pack.
- Conformance levels 1 to 3 and the conformance kit contract.
- JSON Schemas for the envelope, manifest, pack claim, co-signature, receipt and each claim type.
