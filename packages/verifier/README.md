# @getstackrun/verify

Offline verifier for STACK Signed records. It checks internal signatures,
hashes, exact claim links, and record completeness. It has zero STACK runtime
dependencies.

## Docs for agents

How-to guides for every STACK service and for controls are published as markdown. The list is at https://getstack.run/llms.txt, and one service's guide is at https://getstack.run/docs/account/<service>.md (for example https://getstack.run/docs/account/email.md).

## Install

```bash
npx @getstackrun/verify pack.json
```

Or as a library:

```bash
npm install @getstackrun/verify
```

## CLI

```
stack-verify <pack.json> [flags]
stack-verify - < pack.json       # stdin

--air-gap          use embedded material; external trust can stay incomplete
--strict           fail on any claim_type without an inline schema
--ignore-unknown   skip unknown claim_types with one warning
--fresh-jwks       re-fetch JWKS from URL (reserved for v2)
--activity         reconstruct mission activity from signed claim envelopes
--replay           compatibility alias for --activity
--json             machine-readable output
--help             this text
```

Exit code: `0` on `valid: true`, `1` on `valid: false`, `2` on usage error.

## Library

```ts
import { verifyPack } from '@getstackrun/verify';
import { readFileSync } from 'node:fs';

const manifest = JSON.parse(readFileSync('pack.json', 'utf8'));
const result = await verifyPack(manifest, { airGap: true });

if (result.valid) {
  console.log(`Pack ${result.pack_id} verifies: ${result.claim_count} claims`);
} else {
  for (const err of result.errors) {
    console.error(`[${err.code}] ${err.message}`);
  }
}
```

## What this verifies

The verifier checks the internal integrity of a Signed record. It does not
claim that all facts are independently true. Offline checks use the signed
COSE envelopes, inline keys, inline schemas, and audit chain head signature.

Per the producer's threat model, the verifier confirms:

1. **Manifest shape** — `pack_version: 1`, required fields present.
2. **Pack-claim signature** — primary COSE_Sign1 verifies against the
   operator's inline JWKS.
3. **Co-signatures** — each STACK signature verifies against the same
   payload bytes. A missing signature makes the result incomplete.
4. **Content hash** — sha256 over the canonical manifest with `claim`
   + `co_signatures` stripped matches `EvidencePackClaim.content_hash`.
5. **Merkle root** — recomputed over ordered claim_hashes matches
   `EvidencePackClaim.merkle_root`.
6. **Per-claim signatures** — every inner envelope verifies against
   the operator's JWKS.
7. **Per-claim hashes** — sha256(envelope_cose) matches the row's
   claim_hash.
8. **Schema content hashes** — each entry in `schemas_inline` hashes to
   its own `content_hash` and matches the corresponding
   `schema_versions` pin (`envelope` or `by_claim_type`). A pin that is the
   all-zero placeholder (older packs) or has no inline schema to recompute
   is reported as `SCHEMA_HASH_NOT_ATTESTED` or `SCHEMA_PIN_UNCHECKED`: the
   result stays valid and is marked incomplete. A pin that disagrees with
   its inline schema fails.
9. **Unknown-claim-type handling** — claims whose claim_type lacks an
   inline schema are flagged (default), failed (`--strict`), or
   silently skipped (`--ignore-unknown`).
10. **Audit chain anchor** — operator-signed `head_signature`
    verifies over the canonical (head_hash + head_at_ms) tuple.
11. **Exact relationships** — claim count, claim IDs, review revisions,
    signed decisions, checkpoints, detector alerts, and prior reviews match.
12. **Completeness** — missing external anchors and placeholder audit proofs
    produce `valid: true` and `complete: false`.
13. **Activity** — `--activity` reconstructs mission activity and reviews
    from the included signed claim envelopes. `--replay` is the same command.

## What this does NOT verify

- **Revocation freshness.** The pack carries a snapshot of revocation
  state at export time. For live revocation, hit the operator's
  passport-verify endpoint with a cached decorator.
- **External anchor availability.** The current verifier does not fetch an
  anchor permalink. It reports the result as incomplete.
- **Placeholder audit proofs.** The producer can include placeholder proof
  rows. The verifier reports the result as incomplete.
- **Operator + STACK collusion.** A coordinated bad actor controlling
  both signing keys can produce a self-consistent false pack. This
  is the same trust model as any two-party attestation.

## License

Apache-2.0.
