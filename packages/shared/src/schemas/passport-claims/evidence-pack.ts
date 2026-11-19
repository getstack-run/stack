/**
 * EvidencePackClaim.
 *
 * The signed claim recording the export of an evidence pack. Sits at
 * the centre of the claims registry: a portable cryptographic
 * bundle that turns "we keep cryptographic logs" into "here, verify it
 * yourself."
 *
 * Three artefacts kept rigorously separate per the 5.4.0 ADR
 * (the evidence pack design Design decision 1):
 *
 *   - DossierClaim (5.4.1)   — operator's voice on a mission. Argument
 *                              and interpretation, NOT evidence.
 *   - EvidencePackClaim      — this file. Records "an evidence pack
 *                              was exported with these properties."
 *                              Lives in passport_claims like any other
 *                              claim. Operator-scoped envelope.
 *   - EvidencePackManifest   — the JSON file an auditor receives. Wraps
 *                              the signed EvidencePackClaim with the
 *                              claim envelopes themselves, Merkle
 *                              inclusion proofs, JWKS, and inline
 *                              schemas. See pack-manifest below.
 *
 * The claim records the EXPORT EVENT — content hash of the manifest,
 * scope, time bounds, claim count, Merkle root, audit-chain anchor,
 * revocation snapshot timestamp, schema-version pinning, supersedes
 * pointer, cross-tenant references, external chain anchor references.
 * The manifest carries the bytes the verifier actually consumes; the
 * claim is the registry's record-of-export.
 *
 * A controls feature: the evidence pack routes refuse an account without
 * controls (CONTROLS_REQUIRED); the registry itself signs any type.
 *
 * Wire-shape invariant: schema is additive-only for 24 months per
 * envelope.ts:22. Any future evidence type (runtime attestation via
 * `rats_evidence` when SEV-SNP hardware lands, future
 * `zk_aggregate_proof`, etc.) ships as a NEW claim type via the
 * existing envelope_cose slot — the pack format does NOT change.
 * See 5.4.0 ADR Design decision 9 for the forward-compatibility
 * principle.
 *
 * Threat model lock (per 5.4.0 ADR Design decision 12): the pack proves
 * integrity / authenticity / internal-completeness / two-party-
 * attestation / per-claim-revocation-state / non-equivocation-via-
 * daily-anchor / bounded-omission-resistance. The pack does NOT prove
 * trustless verification in the maximal sense while the chain head is operator-asserted.
 */

import { z } from 'zod';
import { ClaimType } from './types.js';
import { ClaimEnvelope, CoSignature } from './envelope.js';

// ─── Scope ────────────────────────────────────────────────────────

/**
 * Pack scope discriminator. Four kinds covered by 5.4.0 ADR Design
 * decision 3 (scope-boundary rules):
 *
 *   - `mission`: claims for one mission's passport JTIs between
 *     mission.started_at and mission.{completed_at | revoked_at | now}.
 *   - `session`: claims with `session_id` matching scope.ref. Exact
 *     bounds (no straddling rules).
 *   - `incident`: claims linked via an explicit incident_id field on
 *     the claim or via a security event whose incident_id matches.
 *     may defer the incident-substrate read path; the
 *     pack format accommodates it without manifest-shape change.
 *   - `period`: time-window scope. Includes any claim whose
 *     `issued_at` falls in `[t0, t1)` plus the boundary-anchor claim
 *     immediately preceding scope (chain continuity) plus in-window
 *     revocations of in-window-issued claims.
 */
export const EvidencePackScope = z.object({
  kind: z.enum(['mission', 'session', 'incident', 'period']),
  /**
   * Free-form reference string. Producer side picks a stable shape per
   * kind:
   *   - mission:  `ms_*`     (mission id, matches MissionClaim.mission_id)
   *   - session:  `ses_*`    (session id from passports.session_id)
   *   - incident: `incident:I-2026-04-15` or similar
   *   - period:   `period:2026-Q1` / `period:2026-05` /
   *               `period:2026-04-15/2026-04-22`
   * The schema does NOT lock per-kind ref shape because incident +
   * period vocabularies are still settling (5.4.4 picks finals). The
   * pack content hash binds the exact ref, so divergence between
   * producers and verifiers becomes a content_hash mismatch — caught
   * at the verifier layer rather than at schema-parse time.
   */
  ref: z.string().min(1).max(256),
});
export type EvidencePackScope = z.infer<typeof EvidencePackScope>;

// ─── Audit chain anchor ───────────────────────────────────────────

/**
 * Operator-signed snapshot of the audit chain head at pack export
 * time. The head_hash is the chain-walk endpoint a verifier reproduces
 * to confirm "this pack was exported against THIS chain state." The
 * head_signature attests the head_hash + head_at_ms tuple under the
 * operator's claim signing key (per operator EdDSA from).
 *
 * Verifier flow:
 *   1. Use audit_chain_proofs[].merkle_path to walk each included
 *      claim hash to a root.
 *   2. Confirm root matches `audit_chain_anchor.head_hash` (or is
 *      reachable in the prefix-chain that leads to head_hash).
 *   3. Verify head_signature against the operator's JWKS.
 *
 * Until a transparency-log receipt exists the chain head is operator-asserted. An earlier change adds a
 * Rekor-style transparency-log receipt (the existing
 * ClaimEnvelope.receipt slot) which closes the trustless-verification
 * gap. See 5.4.0 ADR Design decision 12.
 */
export const AuditChainAnchor = z.object({
  /** Hex-encoded sha256 hash of the audit chain head entry. */
  head_hash: z.string().regex(/^[0-9a-f]{64}$/, 'head_hash must be 64 hex chars (sha256)'),
  /**
   * Operator-signed signature over `head_hash + head_at_ms` (concat,
   * base64url COSE_Sign1 or compact JWS). Producer + verifier agree on
   * the exact signing surface in 5.4.4 + 5.4.8; v1 schema locks the
   * field shape only.
   */
  head_signature: z.string().min(1),
  /** unix ms when the chain head was sampled. */
  head_at_ms: z.number().int().nonnegative(),
});
export type AuditChainAnchor = z.infer<typeof AuditChainAnchor>;

// ─── Schema versions ──────────────────────────────────────────────

/**
 * One pinned schema descriptor. Content hash binds the pack to a
 * specific schema bytes; the canonical URL is reference-only. The
 * canonical schema bytes are ALSO carried inline in the manifest's
 * `schemas_inline` map (see EvidencePackManifest below), so a verifier
 * never depends on a URL resolving.
 */
export const SchemaVersionEntry = z.object({
  version: z.number().int().min(1),
  /** `sha256:` prefix + 64 hex chars. Catches malformed hash strings at parse time. */
  content_hash: z.string().regex(
    /^sha256:[0-9a-f]{64}$/,
    'content_hash must be sha256:<64 hex chars>',
  ),
});
export type SchemaVersionEntry = z.infer<typeof SchemaVersionEntry>;

/**
 * The pinned-schema descriptor table for one pack. `envelope` is
 * mandatory (every claim shares the envelope wrapper); `by_claim_type`
 * lists every claim type appearing in the pack's claims[] with its
 * specific pinned version + content hash.
 *
 * Per the 5.4.0 ADR Design decision 6: pack producers MUST populate
 * `by_claim_type` for every claim_type present in the pack. The
 * verifier rejects any pack carrying claim envelopes whose claim_type
 * is missing from `by_claim_type` — the schema mapping cannot be
 * inferred. Pack producers also copy the schema bodies into
 * `EvidencePackManifest.schemas_inline` (see below).
 */
export const PackSchemaVersions = z.object({
  envelope: SchemaVersionEntry,
  by_claim_type: z.record(ClaimType, SchemaVersionEntry),
});
export type PackSchemaVersions = z.infer<typeof PackSchemaVersions>;

// ─── Cross-tenant references ──────────────────────────────────────

/**
 * One reference to a claim signed by a different operator.
 * chunk D (A2A dispatch), (skill
 * marketplace), and the delegation primitive (always-cross-tenant in
 * principle) all produce claims that link to foreign claim hashes.
 *
 * The pack does NOT embed the foreign claim envelopes. It embeds
 * references. The verifier can resolve the foreign envelope by
 * fetching the foreign operator's JWKS at `foreign_jwks_url` (online
 * verification) or by asking the foreign operator for a complementary
 * pack scoped to the same incident (offline verification).
 *
 * See 5.4.0 ADR Design decision 8.
 */
export const CrossTenantRef = z.object({
  /** sha256 hex of the foreign claim envelope (matches claim_hash on the foreign side). */
  foreign_claim_hash: z.string().regex(/^[0-9a-f]{64}$/, 'foreign_claim_hash must be 64 hex chars (sha256)'),
  /** `op_*` operator id of the foreign issuer. */
  foreign_issuer_op_id: z.string().regex(/^op_[\w-]+$/, 'foreign_issuer_op_id must be an operator id (op_*)'),
  /** URL to the foreign operator's claim-signing JWKS endpoint. */
  foreign_jwks_url: z.string().url(),
  /**
   * Relationship between this pack's claim set and the foreign claim.
   * Additive enum — future relations (e.g. `dropoff_handoff`) ship as
   * new values. Verifier defaults to graceful handling of unknown
   * relations.
   */
  relation: z.enum(['delegation_parent', 'a2a_dispatch', 'skill_invocation']),
});
export type CrossTenantRef = z.infer<typeof CrossTenantRef>;

// ─── External chain anchor ────────────────────────────────────────

/**
 * Reference to one public anchor of the audit chain head.
 * lands a daily cron that pushes each operator's chain head to
 * a public registry such as `example-org/anchors` (a public GitHub repo). The pack carries
 * the most-recent anchor that committed to a chain head reachable in
 * the prefix-chain leading to the pack's `audit_chain_anchor.head_hash`.
 *
 * Closes (per 5.4.0 ADR Design decision 12):
 *   - non-equivocation against STACK for chain head (STACK cannot
 *     show two different heads to two parties without producing two
 *     observable anchor commits)
 *   - bounded omission resistance (post-hoc omission requires
 *     replacing a public anchor — observable via force-push or
 *     missing-commit detection)
 *
 * Does NOT close:
 *   - sub-24h omissions inserted before the next anchor cycle
 *   - operator + STACK collusion
 *
 * Additive `registry` value catalog — v1 ships `github:example-org/anchors`;
 * v2 may mirror to Bluesky / IPFS / Cloudflare R2.
 */
export const ExternalChainAnchorRef = z.object({
  registry: z.string().min(1).max(128),
  /** Permalink to the commit + file containing the anchored chain head. */
  permalink: z.string().url(),
  anchored_at_ms: z.number().int().nonnegative(),
  anchored_chain_head_hash: z.string().regex(
    /^[0-9a-f]{64}$/,
    'anchored_chain_head_hash must be 64 hex chars (sha256)',
  ),
});
export type ExternalChainAnchorRef = z.infer<typeof ExternalChainAnchorRef>;

// ─── EvidencePackClaim ────────────────────────────────────────────

/**
 * The signed record of an evidence-pack export. Lives in
 * passport_claims alongside every other claim type. Operator-scoped
 * envelope (`subjectOverride: 'operator'` in registry parlance) — the
 * pack belongs to the operator, not to a single passport.
 */
export const EvidencePackClaim = z.object({
  type: z.literal('evidence_pack'),

  /** `pck_*` pack id. Mint-once, never reused. */
  pack_id: z.string().regex(/^pck_[\w-]+$/, 'pack_id must be a pack id (pck_*)'),

  /**
   * Content hash of the canonical manifest JSON (RFC 8785 JCS
   * canonicalisation, sha256). Identity of the pack at the
   * byte-level — two packs with the same content_hash ARE the same
   * pack. Pack-vs-pack relationships (Design decision 7) treat
   * content_hash as identity; supersedes is the forward arrow.
   */
  content_hash: z.string().regex(
    /^sha256:[0-9a-f]{64}$/,
    'content_hash must be sha256:<64 hex chars>',
  ),

  /** What the pack covers. See EvidencePackScope. */
  scope: EvidencePackScope,

  /**
   * Time bounds of the pack's claim set. `t0_ms` is inclusive,
   * `t1_ms` is exclusive. For mission scope these mirror
   * mission.started_at / mission.{completed_at | revoked_at | now}.
   * For period scope these are the period's `[t0, t1)` bounds.
   */
  time_bounds: z
    .object({
      t0_ms: z.number().int().nonnegative(),
      t1_ms: z.number().int().nonnegative(),
    })
    .refine((b) => b.t1_ms > b.t0_ms, { message: 't1_ms must be > t0_ms' }),

  /** Number of claim envelopes carried in the pack's claims[] array. */
  claim_count: z.number().int().nonnegative(),

  /** Exact review revisions included in this immutable pack snapshot. */
  included_review_claim_ids: z
    .array(z.string().regex(/^pc_[\w-]+$/, 'review claim id must be a claim id (pc_*)'))
    .default([]),

  /**
   * Base64url sha256 root over the ordered list of claim_hashes in
   * `claims[]`. Producer + verifier agree on the binary-tree shape
   * (Design decision in 5.4.4; locked here for the schema field name).
   * Empty packs (claim_count === 0) carry the conventional empty-root
   * `'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'`
   * shape per RFC 6234.
   */
  merkle_root: z.string().regex(
    /^sha256:[0-9a-f]{64}$/,
    'merkle_root must be sha256:<64 hex chars>',
  ),

  /** Operator-signed snapshot of the audit chain head at export time. */
  audit_chain_anchor: AuditChainAnchor,

  /**
   * unix ms when the per-claim revocation state was sampled. The
   * `claims[]` array's `revoked_at_ms` per entry reflects revocations
   * up to this timestamp. Re-exporting the same scope produces a new
   * pack with a fresher snapshot.
   */
  revocation_snapshot_at_ms: z.number().int().nonnegative(),

  /** Pinned schema descriptors for every claim type in the pack. */
  schema_versions: PackSchemaVersions,

  /**
   * Reference-only URL to the schema-registry root (e.g.
   * `https://getstack.run/schemas/passport-claims/v1/`). The verifier
   * uses inline schemas as the primary path; the URL exists for
   * discoverability and as a fallback when `schemas_inline` is missing
   * a needed schema AND `--air-gap` is not set. Per 5.4.0 ADR Design
   * decision 11.
   */
  canonical_schema_base_url: z.string().url(),

  /**
   * Forward arrow to the previous pack at this scope, when re-exporting.
   * `pck_*` id or null on the first export. The earlier pack stays
   * valid as a point-in-time snapshot; the new one carries fresher
   * revocation snapshot / schema / dossier additions / etc.
   */
  supersedes: z.string().regex(/^pck_[\w-]+$/, 'supersedes must be a pack id (pck_*)').nullable(),

  /**
   * References to claim hashes signed by foreign operators that
   * appear in this pack's claim set (via delegation, A2A dispatch, or
   * skill invocation cross-tenancy). Default empty for packs with no
   * cross-tenant activity.
   */
  cross_tenant_refs: z.array(CrossTenantRef).default([]),

  /**
   * References to public anchors of the audit chain head. Populated
   * from the in-DB anchor log at export time.
   * Default empty for packs exported before the daily anchor cron
   * runs for the operator OR when no anchors are reachable (the
   * pack's audit-chain head is too recent).
   */
  external_chain_anchors: z.array(ExternalChainAnchorRef).default([]),
});

export type EvidencePackClaim = z.infer<typeof EvidencePackClaim>;

// ─── EvidencePackManifest ─────────────────────────────────────────

/**
 * The JSON file an auditor receives — the pack itself. NOT a claim
 * type (does not go through ClaimRegistryService.registerClaim).
 * Carries the signed EvidencePackClaim plus the claim envelopes
 * themselves, Merkle inclusion proofs, JWKS, and inline schemas.
 *
 * Shape locked verbatim in the evidence pack design
 * Design decision 2. Producer populates this; open
 * source verifier consumes this. The verifier never
 * fetches over the network in the default path — every byte it needs
 * lives in the manifest.
 */

/**
 * One row in the manifest's `claims[]` array. Carries the signed
 * envelope plus the revocation snapshot value at export time. The
 * `claim_hash` is sha256 of `envelope_cose` (reproducible by the
 * verifier; carried inline for fast index).
 */
export const ManifestClaimEntry = z.object({
  /** Exact registry id. Optional only for manifests created before this field shipped. */
  claim_id: z.string().regex(/^pc_[\w-]+$/, 'claim_id must be a claim id (pc_*)').optional(),
  claim_hash: z.string().regex(/^[0-9a-f]{64}$/, 'claim_hash must be 64 hex chars (sha256)'),
  /** base64url COSE_Sign1 envelope bytes. */
  envelope_cose: z.string().min(1),
  /** Revocation timestamp at export time. Null = not revoked. */
  revoked_at_ms: z.number().int().nullable(),
});
export type ManifestClaimEntry = z.infer<typeof ManifestClaimEntry>;

/**
 * One row in the manifest's `audit_chain_proofs[]` array. Lets a
 * verifier walk a sparse audit-chain inclusion proof for each claim
 * back to the anchor's head_hash without needing the full chain
 * history. `audit_position` is the chain position recorded in the
 * audit_log when the claim was attached.
 */
export const ManifestAuditChainProof = z.object({
  claim_hash: z.string().regex(/^[0-9a-f]{64}$/, 'claim_hash must be 64 hex chars (sha256)'),
  audit_position: z.number().int().nonnegative(),
  /**
   * Sibling-hash path from this claim's leaf to the anchor head_hash.
   * Each entry is `sha256:<64 hex>`. Length depends on chain depth +
   * Merkle layout; v1 schema does not lock the per-step shape beyond
   * "string array of canonical sibling hashes."
   */
  merkle_path: z.array(z.string().regex(/^sha256:[0-9a-f]{64}$/)),
});
export type ManifestAuditChainProof = z.infer<typeof ManifestAuditChainProof>;

/**
 * JWKS shape carried inline. Mirrors the public RFC 7517 JWK Set —
 * `{ keys: [...] }`. Schema accepts any object with a `keys` array of
 * unknown items because the JWK shape varies by `kty` (EdDSA / RSA /
 * post-quantum) and the producer just embeds whatever the operator /
 * STACK system JWKS endpoint returned. The verifier validates per-key
 * shape at signature-verification time, not at manifest parse time.
 */
export const InlineJwks = z.object({
  keys: z.array(z.record(z.string(), z.unknown())),
});
export type InlineJwks = z.infer<typeof InlineJwks>;

/**
 * Verification material — both URL pointers AND inline copies. The
 * verifier prefers inline by default; `--fresh-jwks` flag in 5.4.8
 * forces a re-fetch from the URL. `--air-gap` rejects packs missing
 * inline material. Per 5.4.0 ADR Design decision 11.
 */
export const ManifestVerificationMaterial = z.object({
  operator_jwks_url: z.string().url(),
  operator_jwks_inline: InlineJwks,
  stack_system_jwks_url: z.string().url(),
  stack_system_jwks_inline: InlineJwks,
});
export type ManifestVerificationMaterial = z.infer<typeof ManifestVerificationMaterial>;

/**
 * One inline schema entry in `schemas_inline`. Carries the canonical
 * JSON Schema body, the `$schema` URI metadata, and the content hash
 * (which MUST match the corresponding entry in
 * `EvidencePackClaim.schema_versions`).
 *
 * The verifier resolves schemas by:
 *   1. Read this entry from `schemas_inline[<key>]`.
 *   2. Canonicalise json_schema, compute sha256, prefix `sha256:`.
 *   3. Compare against `content_hash` AND against the matching pinned
 *      hash in the pack claim's `schema_versions`. Any divergence
 *      fails verification.
 *   4. Validate every claim envelope of the matching claim_type
 *      against `json_schema`.
 */
export const ManifestInlineSchemaEntry = z.object({
  /** `$schema` metadata URI from the canonical JSON Schema body. */
  $schema: z.string().min(1),
  content_hash: z.string().regex(
    /^sha256:[0-9a-f]{64}$/,
    'content_hash must be sha256:<64 hex chars>',
  ),
  /** The JSON Schema body itself, canonicalised. Free-form object. */
  json_schema: z.record(z.string(), z.unknown()),
});
export type ManifestInlineSchemaEntry = z.infer<typeof ManifestInlineSchemaEntry>;

/**
 * The full pack manifest — the file an auditor opens. Carries every
 * byte the verifier needs in the default (offline) path.
 *
 * Top-level keys in this exact order matter for human-readable
 * inspection but the canonicalisation rule (RFC 8785 JCS) is what
 * makes `content_hash` deterministic — JCS sorts keys
 * lexicographically before hashing, so insertion order at write time
 * does not affect the hash.
 */
export const EvidencePackManifest = z.object({
  /**
   * Format version of the manifest envelope itself. v1 is the only
   * shipped version while the additive-only rule (mirror of
   * envelope.ts:22) holds. New evidence types ship as new claim types
   * — pack_version does NOT bump for content additions. See 5.4.0
   * ADR Design decision 9.
   */
  pack_version: z.literal(1),

  /**
   * The signed EvidencePackClaim envelope. base64url COSE_Sign1.
   * Primary signed by the operator's per-operator claim key. Per
   * 5.4.0 ADR Design decision 5.
   *
   * Schema field is a base64url string here because the manifest's
   * other slots already carry the structured ClaimEnvelope shape
   * indirectly (via the inline schemas + the pack claim's pinned
   * envelope content hash). Storing the COSE bytes as a string keeps
   * the canonicalisation rule simple — no nested envelope object to
   * traverse during JCS sort.
   */
  claim: z.string().min(1),

  /**
   * STACK system co-signatures attesting the same payload bytes as
   * `claim`. The CoSignature wire is the existing shape from
   * envelope.ts:86. Default empty for v1 producers running without a
   * wired STACK system signer (the pack still verifies on the primary
   * alone; the two-party-attestation property of 5.4.0 ADR Design
   * decision 5 lights up when the system signer is wired).
   */
  co_signatures: z.array(CoSignature).default([]),

  /** Every claim envelope included in the pack, in producer-defined order. */
  claims: z.array(ManifestClaimEntry),

  /** Sparse Merkle inclusion proofs from each claim leaf to the audit-chain head. */
  audit_chain_proofs: z.array(ManifestAuditChainProof),

  /** JWKS for both signing parties — inline + URL pointers. */
  verification_material: ManifestVerificationMaterial,

  /**
   * Per-claim-type schema bodies + content hashes. Keyed by
   * claim_type string (envelope plus every claim_type appearing in
   * `claims[]`). The verifier's first-stop schema source; URL fallback
   * runs only when an entry is missing.
   */
  schemas_inline: z.record(z.string(), ManifestInlineSchemaEntry),
});
export type EvidencePackManifest = z.infer<typeof EvidencePackManifest>;

// ─── Re-exports for downstream callers ────────────────────────────

/**
 * Convenience re-exports so a downstream verifier package
 * can import from one place.
 * Some shapes (ClaimEnvelope, CoSignature) live in envelope.ts but the
 * pack-manifest verifier needs them too.
 */
export type { ClaimEnvelope, CoSignature };
