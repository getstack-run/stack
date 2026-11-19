// ExternalAnchorService.
//
// Daily cron-driven anchor publisher for non-equivocation and bounded
// omission-resistance. Every UTC day,
// the worker picks each operator with recent claim activity and:
//
//   1. Reads the operator's audit chain head (AuditService.getChainHead).
//   2. Signs the (chain_head_hash, anchored_at_ms,
//      chain_head_at_audit_position) tuple with the operator's claim key
//      (same key the pack export uses for audit_chain_anchor head_signature
//      — verifier resolves via the operator's JWKS).
//   3. Optionally co-signs with the STACK system key
//      (signer_role='operator_attestation') for two-party attestation.
//   4. Hands the signed anchor payload to a pluggable AnchorPublisher
//      (a deployment that publishes wires its own; the engine ships
//      NoopAnchorPublisher, which returns a synthetic permalink +
//      commit_sha so the DB pipeline exercises end-to-end).
//   5. Writes a row to the `external_anchors` table for downstream
//      retrieval by EvidencePackService.export.
//
// What this closes (per the 5.4.0 ADR Design decision 12):
//   - Non-equivocation against STACK for chain head — STACK can't show
//     two heads to two parties without producing two observable anchor
//     commits to a public repo.
//   - Bounded omission resistance — any post-hoc omission requires
//     replacing a public anchor file, which is observable (force-push
//     to a public repo, missing-commit detection).
//
// What this does NOT close: sub-24h omissions inserted before the
// next anchor cycle; single point of failure on the publisher's
// registry (v2 mirrors to a second registry); operator+STACK
// collusion (orthogonal transparency log).
//
// Publishing is a hook: a deployment that publishes wires its own publisher
// into the worker (a public registry, with the file format and a verification
// recipe documented beside it). The engine ships the substrate with the noop
// publisher so the pipeline runs without a registry existing.

import {
  canonicalize,
  ids,
  type EvidencePackClaim,
} from '@stack/shared';
import type { ClaimSigner } from '../crypto/claim-signer.js';
import type { AuditService } from './audit-service.js';
import type {
  ExternalAnchorRepository,
  ExternalAnchorRow,
} from '../repositories/external-anchor-repo.js';

// ─── Public types ───────────────────────────────────────────────────

/**
 * Canonical anchor file payload published to the registry. The file
 * shape is locked here (and documented with the registry) so
 * independent parties can verify without running STACK code.
 */
export interface AnchorPayload {
  operator_id: string;
  chain_head_hash: string;            // 64-hex sha256 (no `sha256:` prefix for file readability)
  chain_head_signature: string;       // base64url Ed25519 over canonicalize({chain_head_hash, anchored_at_ms, chain_head_at_audit_position})
  anchored_at_ms: number;
  anchored_at_audit_position: number;
  stack_system_attestation?: string;  // optional, when stackSystemSigner wired
}

/**
 * Pluggable publisher interface. A deployment that publishes wires its
 * own; tests + dev use `NoopAnchorPublisher` (returns synthetic permalink +
 * commit_sha so the rest of the pipeline runs).
 *
 * `publish` is idempotent on (operatorId, UTC-date) by convention: a
 * same-day re-run overwrites the existing file. The returned
 * permalink + commit_sha refer to the NEW commit; old anchor rows in
 * `external_anchors` stay as forensic trail.
 */
export interface AnchorPublisher {
  /** v1 registry identifier (e.g. 'github:example-org/audit-anchors'). */
  readonly registry: string;
  /**
   * Publish the anchor payload. Returns the permalink to the
   * resulting file in the registry + the commit sha for tamper-
   * evidence against force-push.
   */
  publish(input: {
    operatorId: string;
    dateKey: string;                    // UTC date YYYY-MM-DD (file path component)
    payload: AnchorPayload;
  }): Promise<{ permalink: string; commit_sha: string }>;
}

/**
 * Default publisher when no real registry is wired. Does NOT make a
 * network call. Returns a deterministic synthetic permalink so the
 * pipeline runs end-to-end in dev + tests + early prod. A deployment
 * that wants the tamper-evidence properties of the daily anchor MUST
 * swap in a real publisher.
 *
 * Synthetic permalink shape:
 *   `noop://anchor/${operatorId}/${dateKey}`
 *
 * Downstream verifier treats `noop://` permalinks as
 * a "anchor not externally verifiable" condition — pack verification
 * with `--strict` fails; default mode flags.
 */
export class NoopAnchorPublisher implements AnchorPublisher {
  readonly registry = 'noop:local';

  async publish(input: {
    operatorId: string;
    dateKey: string;
    payload: AnchorPayload;
  }): Promise<{ permalink: string; commit_sha: string }> {
    const permalink = `noop://anchor/${input.operatorId}/${input.dateKey}`;
    // Deterministic synthetic sha — content-addressable so the
    // permalink + commit_sha pair stays consistent across same-input
    // re-runs in tests.
    const synthSha = hashHex(canonicalize(input.payload));
    return { permalink, commit_sha: synthSha };
  }
}

function hashHex(s: string): string {
  // Lightweight inline hex hash — used only for synthetic commit_sha
  // generation. Cryptographic anchor signing happens upstream via
  // ClaimSigner.signBytes; this is a deterministic identifier, not a
  // signature.
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) >>> 0;
  }
  return h.toString(16).padStart(8, '0').repeat(5);
}

// ─── Service ────────────────────────────────────────────────────────

export interface ExternalAnchorServiceDeps {
  anchorRepo: ExternalAnchorRepository;
  auditService: AuditService;
  operatorSignerResolver: (operatorId: string) => Promise<ClaimSigner>;
  stackSystemSigner?: ClaimSigner;
  publisher: AnchorPublisher;
  /** Override of `() => Date.now()` for tests. */
  now?: () => number;
}

export interface AnchorResult {
  row: ExternalAnchorRow;
  /** Whether the publisher returned a non-noop permalink. */
  publishedExternally: boolean;
}

export class ExternalAnchorService {
  constructor(private deps: ExternalAnchorServiceDeps) {}

  /**
   * Anchor one operator's chain head. Pure-ish: reads chain head, signs,
   * publishes, writes one DB row. Idempotent on (operator, UTC-date) at
   * the PUBLISHER level (same-day re-run overwrites the registry file);
   * the DB log accumulates rows so re-runs are visible as forensic
   * trail.
   *
   * Returns null when the operator has no audit chain (no rows in
   * audit_log yet — nothing to anchor). The cron loop skips silently.
   */
  async anchorOperator(operatorId: string): Promise<AnchorResult | null> {
    const head = await this.deps.auditService.getChainHead(operatorId);
    if (!head.latest_entry_hash) return null;

    const now = (this.deps.now ?? Date.now)();
    const anchored_at_audit_position = head.total_entries;
    const chain_head_hash = head.latest_entry_hash;

    // Signing surface: canonicalize the tuple. Same canonicalisation
    // rule as EvidencePackService head_signature (so verifier code
    // can reuse one helper across both surfaces).
    const signingBytes = Buffer.from(
      canonicalize({
        chain_head_hash,
        anchored_at_ms: now,
        chain_head_at_audit_position: anchored_at_audit_position,
      }),
      'utf8',
    );

    const operatorSigner = await this.deps.operatorSignerResolver(operatorId);
    const chain_head_signature = await operatorSigner.signBytes(signingBytes);

    let stack_system_attestation: string | undefined;
    if (this.deps.stackSystemSigner) {
      stack_system_attestation = await this.deps.stackSystemSigner.signBytes(signingBytes);
    }

    const payload: AnchorPayload = {
      operator_id: operatorId,
      chain_head_hash,
      chain_head_signature,
      anchored_at_ms: now,
      anchored_at_audit_position,
      ...(stack_system_attestation ? { stack_system_attestation } : {}),
    };

    const dateKey = toUtcDateKey(now);
    const { permalink, commit_sha } = await this.deps.publisher.publish({
      operatorId,
      dateKey,
      payload,
    });

    const row = await this.deps.anchorRepo.insert({
      id: ids.pack().replace(/^pck_/, 'anc_'), // anc_* prefix
      operator_id: operatorId,
      anchored_at_ms: now,
      chain_head_hash,
      chain_head_at_audit_position: anchored_at_audit_position,
      registry: this.deps.publisher.registry,
      permalink,
      commit_sha,
      chain_head_signature,
      stack_system_attestation: stack_system_attestation ?? null,
    });

    return {
      row,
      publishedExternally: !permalink.startsWith('noop://'),
    };
  }

  /** Most-recent anchor for an operator, or null. */
  async getLatestAnchor(operatorId: string): Promise<ExternalAnchorRow | null> {
    return this.deps.anchorRepo.findLatest(operatorId);
  }

  /**
   * The anchor in effect at time `tMs`. Used by
   * EvidencePackService.export to populate
   * EvidencePackClaim.external_chain_anchors[] with the most-recent
   * anchor at or before the export timestamp.
   */
  async getAnchorAtOrBefore(operatorId: string, tMs: number): Promise<ExternalAnchorRow | null> {
    return this.deps.anchorRepo.findAtOrBefore(operatorId, tMs);
  }

  /**
   * Convert a row to the schema's ExternalChainAnchorRef shape (for
   * EvidencePackClaim.external_chain_anchors[]).
   */
  static rowToRef(row: ExternalAnchorRow): EvidencePackClaim['external_chain_anchors'][number] {
    return {
      registry: row.registry,
      permalink: row.permalink,
      anchored_at_ms: row.anchored_at_ms,
      anchored_chain_head_hash: row.chain_head_hash,
    };
  }
}

function toUtcDateKey(ms: number): string {
  const d = new Date(ms);
  return (
    d.getUTCFullYear() +
    '-' +
    String(d.getUTCMonth() + 1).padStart(2, '0') +
    '-' +
    String(d.getUTCDate()).padStart(2, '0')
  );
}
