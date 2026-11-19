/**
 * Wire-shape mirrors of the EvidencePackManifest + EvidencePackClaim
 * + CoSignature shapes (producer in `@stack/shared/schemas/passport-
 * claims/evidence-pack.ts`). Duplicated here intentionally — this
 * package is standalone.
 *
 * Types are loose (`Record<string, unknown>` for opaque slots, plain
 * arrays without nominal types for claim bodies) because the
 * verifier validates structure at runtime rather than at the
 * type-system level. The point of the verifier is to ACCEPT
 * arbitrary bytes claiming to be a pack and decide whether they
 * verify — TypeScript types are dev-side helpers, not gates.
 */

export interface CoSignature {
  signer_kid: string;
  signer_role: 'operator_attestation' | 'agent_self' | 'witness' | string;
  cose_sign1: string;
}

export interface InlineJwks {
  keys: Array<Record<string, unknown>>;
}

export interface ManifestClaimEntry {
  claim_id?: string;
  claim_hash: string;
  envelope_cose: string;
  revoked_at_ms: number | null;
}

export interface ManifestAuditChainProof {
  claim_hash: string;
  audit_position: number;
  merkle_path: string[];
}

export interface ManifestVerificationMaterial {
  operator_jwks_url: string;
  operator_jwks_inline: InlineJwks;
  stack_system_jwks_url: string;
  stack_system_jwks_inline: InlineJwks;
}

export interface ManifestInlineSchemaEntry {
  $schema: string;
  content_hash: string;
  json_schema: Record<string, unknown>;
}

export interface EvidencePackManifest {
  pack_version: 1;
  claim: string;
  co_signatures: CoSignature[];
  claims: ManifestClaimEntry[];
  audit_chain_proofs: ManifestAuditChainProof[];
  verification_material: ManifestVerificationMaterial;
  schemas_inline: Record<string, ManifestInlineSchemaEntry>;
}

export interface AuditChainAnchor {
  head_hash: string;
  head_signature: string;
  head_at_ms: number;
}

export interface ExternalChainAnchorRef {
  registry: string;
  permalink: string;
  anchored_at_ms: number;
  anchored_chain_head_hash: string;
}

export interface EvidencePackClaim {
  type: 'evidence_pack';
  pack_id: string;
  content_hash: string;
  scope: { kind: 'mission' | 'session' | 'incident' | 'period'; ref: string };
  time_bounds: { t0_ms: number; t1_ms: number };
  claim_count: number;
  /** Absent only on packs created before exact review ids shipped. */
  included_review_claim_ids?: string[];
  merkle_root: string;
  audit_chain_anchor: AuditChainAnchor;
  revocation_snapshot_at_ms: number;
  schema_versions: {
    envelope: { version: number; content_hash: string };
    by_claim_type: Record<string, { version: number; content_hash: string }>;
  };
  canonical_schema_base_url: string;
  supersedes: string | null;
  cross_tenant_refs: Array<Record<string, unknown>>;
  external_chain_anchors: ExternalChainAnchorRef[];
}

// ─── Verifier output ────────────────────────────────────────────────

export type VerifyCheckOutcome = 'pass' | 'fail' | 'skip' | 'warn';

export interface VerifyCheck {
  name: string;
  outcome: VerifyCheckOutcome;
  detail?: string;
}

export interface VerifyResult {
  valid: boolean;
  /** True only when every check passes. Warnings and skipped trust checks make it incomplete. */
  complete: boolean;
  pack_id: string | null;
  scope: { kind: string; ref: string } | null;
  claim_count: number;
  timespan: [number, number] | null;
  revoked_at_export: number;
  unknown_claim_types: number;
  external_anchors_verified: number;
  checks: VerifyCheck[];
  errors: Array<{ code: string; message: string }>;
  warnings: Array<{ code: string; message: string }>;
  /** Present when --activity or its --replay compatibility alias is requested. */
  activity?: ReplayedTimeline | null;
}

export type ReplayedEventKind =
  | 'mission_open'
  | 'mission_close'
  | 'intent_submitted'
  | 'intent_outcome'
  | 'intent_denial'
  | 'intent_simulation'
  | 'entity_observation'
  | 'detector_signal'
  | 'checkpoint_approval'
  | 'skill_invocation'
  | 'behavioral_genome'
  | 'operator_decision'
  | 'operator_review'
  | 'dossier'
  | 'twin_divergence';

export interface ReplayedEvent {
  kind: ReplayedEventKind;
  at_ms: number;
  claim_id?: string | null;
  claim_hash?: string | null;
  body: Record<string, unknown>;
}

export interface ReconstructClaimInput {
  type: string;
  body: Record<string, unknown>;
  issued_at_ms: number;
  claim_id?: string | null;
  claim_hash?: string | null;
}

export interface ReplayedTimeline {
  mission: {
    mission_id: string;
    operator_id: string;
    open?: Record<string, unknown>;
    close?: Record<string, unknown>;
    closed: boolean;
  };
  events: ReplayedEvent[];
  behavioral_diff: {
    max_z: number;
    l2_norm: number;
    per_dimension: Record<string, number>;
  } | null;
  cap_usage: {
    max_actions: number | null;
    max_dropoff_bytes: number | null;
    coverage_cap_cents: number | null;
    observed_wallet_cents: number;
    observed_action_count: number;
  };
  dossiers: ReplayedEvent[];
  operator_reviews: ReplayedEvent[];
  twin_divergence: ReplayedEvent | null;
}

export interface VerifyOptions {
  /**
   * Use embedded verification material only. Missing required inline
   * keys or schemas fail. External trust checks that need a network
   * stay incomplete without making an internally valid pack invalid.
   */
  airGap?: boolean;
  /**
   * Fail on any claim_type appearing in `claims[]` whose schema is
   * not present inline. Default flags but continues.
   */
  strict?: boolean;
  /**
   * Silently skip unknown claim types with a single warning instead
   * of flagging them as a top-level concern. Mutually exclusive with
   * `strict` at semantic level — passing both throws.
   */
  ignoreUnknown?: boolean;
  /**
   * Re-fetch JWKS from `*_jwks_url` even when inline copy is present.
   * Useful for revocation-state-aware verification on hot paths;
   * default uses inline (offline-friendly).
   */
  freshJwks?: boolean;
  /**
   * When true, the verifier additionally reconstructs the forensic
   * timeline from the pack's claim envelopes (`reconstructTimeline`
   * helper). The timeline is attached to the result via the optional
   * `timeline` field; it does NOT affect `valid` or `complete`.
   */
  activity?: boolean;
  /** Compatibility alias for activity. */
  replay?: boolean;
}
