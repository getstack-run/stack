// EvidencePacksService TS SDK wrapper.
//
// Four methods over /v1/evidence-packs:
//
//   export()  → POST /v1/evidence-packs
//   get()     → GET  /v1/evidence-packs/:pack_id
//   download()→ GET  /v1/evidence-packs/:pack_id/download
//   list()    → GET  /v1/evidence-packs?scope=...
//
// The export call returns the full canonical manifest JSON inline —
// callers can write it straight to disk for handoff to auditors. The
// open-source verifier (`@getstackrun/verify`) consumes the same
// bytes verbatim.

import type { HttpClient } from '../client.js';

export type EvidencePackScopeKind = 'mission' | 'session' | 'incident' | 'period';

export interface EvidencePackScope {
  kind: EvidencePackScopeKind;
  ref: string;
}

export interface ExportPackInput {
  scope: EvidencePackScope;
  /** When set, the new pack's `supersedes` field points at this prior pack id. */
  supersedes?: string;
  /**
   * Reserved hint for the consumer. v1 producer always emits inline
   * JWKS + inline schemas regardless of the flag — `--air-gap` is a
   * verifier-side mode in `@getstackrun/verify`. The flag rides on
   * the pack claim for the consumer's record.
   */
  air_gap?: boolean;
}

// The pack manifest is large and varies by scope. SDK consumers
// usually persist the bytes to disk rather than introspect, so we
// keep the type loose at the SDK boundary. Downstream verifier
// carries the tight schema.
export interface EvidencePackManifest {
  pack_version: 1;
  claim: string;
  co_signatures: Array<{ signer_kid: string; signer_role: string; cose_sign1: string }>;
  claims: Array<{
    claim_id?: string;
    claim_hash: string;
    envelope_cose: string;
    revoked_at_ms: number | null;
  }>;
  audit_chain_proofs: Array<{ claim_hash: string; audit_position: number; merkle_path: string[] }>;
  verification_material: {
    operator_jwks_url: string;
    operator_jwks_inline: { keys: Array<Record<string, unknown>> };
    stack_system_jwks_url: string;
    stack_system_jwks_inline: { keys: Array<Record<string, unknown>> };
  };
  schemas_inline: Record<string, { $schema: string; content_hash: string; json_schema: Record<string, unknown> }>;
}

export interface EvidencePackClaim {
  type: 'evidence_pack';
  pack_id: string;
  content_hash: string;
  scope: EvidencePackScope;
  time_bounds: { t0_ms: number; t1_ms: number };
  claim_count: number;
  merkle_root: string;
  audit_chain_anchor: { head_hash: string; head_signature: string; head_at_ms: number };
  revocation_snapshot_at_ms: number;
  schema_versions: {
    envelope: { version: number; content_hash: string };
    by_claim_type: Record<string, { version: number; content_hash: string }>;
  };
  canonical_schema_base_url: string;
  supersedes: string | null;
  cross_tenant_refs: Array<Record<string, unknown>>;
  external_chain_anchors: Array<Record<string, unknown>>;
  included_review_claim_ids?: string[];
}

export interface ExportPackResult {
  pack_id: string;
  claim_id: string;
  pack_claim: EvidencePackClaim;
  manifest: EvidencePackManifest;
}

export interface PackListItem {
  pack_id: string;
  claim_id: string;
  content_hash: string;
  scope: EvidencePackScope;
  time_bounds: { t0_ms: number; t1_ms: number };
  claim_count: number;
  supersedes: string | null;
  issued_at_ms: number | null;
  /** Old rows have only the claim receipt. New rows have exact stored bytes. */
  artifact_state: 'stored_manifest' | 'receipt_only';
  included_review_claim_ids?: string[];
}

export interface ListPacksQuery {
  /**
   * `<kind>:<ref>` filter (e.g. 'mission:ms_abc'). Omit to list every
   * pack the operator has exported.
   */
  scope?: string;
}

export interface ListPacksResult {
  items: PackListItem[];
}

export interface GetPackResult {
  claim_id: string;
  envelope_cose: string | null;
  revoked_at: string | null;
  pack_claim: EvidencePackClaim;
}

export class EvidencePacksService {
  constructor(private client: HttpClient) {}

  /**
   * Export an evidence pack. Returns the pack_id + the full canonical
   * manifest JSON inline. Callers writing the manifest to disk for
   * auditor handoff should use the standard one-file convention
   * (`${pack_id}.json`).
   *
   * Signed records are a controls feature: every call here throws
   * `ControlsRequiredError` (402 `CONTROLS_REQUIRED`) without controls,
   * and a self-managed install also needs its licence to export
   * (`LICENCE_REQUIRED`). Incident scope and malformed period refs get a
   * `StackError` with `status` 400.
   */
  async export(input: ExportPackInput): Promise<ExportPackResult> {
    return this.client.post<ExportPackResult>('/v1/evidence-packs', input);
  }

  /**
   * Fetch one pack by `pack_id`. Returns the signed claim envelope
   * bytes alongside the parsed `pack_claim` for convenient
   * introspection. v1 does NOT return the full manifest here — call
   * `export()` again with `supersedes: pack_id` to get a fresh
   * manifest (re-snapshots revocation state at the new call time).
   */
  async get(packId: string): Promise<GetPackResult> {
    return this.client.get<GetPackResult>(
      `/v1/evidence-packs/${encodeURIComponent(packId)}`,
    );
  }

  /** Download the exact immutable manifest bytes created at export time. */
  async download(packId: string): Promise<Uint8Array> {
    return this.client.getBytes(
      `/v1/evidence-packs/${encodeURIComponent(packId)}/download`,
    );
  }

  /**
   * List packs for the calling operator. With a `scope` filter,
   * returns only packs matching that scope kind + ref. Newest first
   * by `issued_at_ms`.
   */
  async list(query: ListPacksQuery = {}): Promise<ListPacksResult> {
    const params = new URLSearchParams();
    if (query.scope) params.set('scope', query.scope);
    const suffix = params.toString();
    return this.client.get<ListPacksResult>(
      `/v1/evidence-packs${suffix ? `?${suffix}` : ''}`,
    );
  }
}
