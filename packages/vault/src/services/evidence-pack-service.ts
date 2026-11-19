// EvidencePackService.
//
// Producer for the claims registry's portable cryptographic bundle:
// it turns "we keep cryptographic logs" into "here, verify it yourself."
// The service
// creates and verifies immutable manifest artifacts. Its main methods are:
//
//   export(operatorId, scope, options?) → { pack_id, claim_id,
//                                            manifest, pack_claim }
//   getStoredManifest(operatorId, packId) → exact verified bytes
//
// Steps (numbered to match the 5.4.4 plan):
//
//   1. Resolve scope to a claim set via PassportClaimsRepository
//      (one of three repo methods per scope.kind). Incident scope
//      throws NotImplemented in v1 (requires incident-substrate
//      that hasn't shipped).
//   2. Claims arrive ordered by (issued_at_ms ASC, claim_id ASC)
//      — the repo methods enforce this.
//   3. Snapshot revocation state per claim at export time via the
//      row's `revoked_at` column.
//   4. Build a Merkle tree over the ordered claim_hashes; root goes
//      into the pack claim's `merkle_root` field.
//   5. Capture audit chain head via AuditService.getChainHead. Sign
//      the (head_hash, head_at_ms) tuple with the operator's claim
//      key via ClaimSigner.signBytes — this is the
//      `audit_chain_anchor.head_signature` value.
//   6. Cross-tenant ref resolution: v1 always emits []. Scanning for
//      foreign claim hashes requires structured cross-tenant ref
//      fields on individual claim types (delegation_parent / A2A /
//      skill chain) which aren't surfaced uniformly yet. Lights up
// later.
// 7. External chain anchor refs: v1 always emits [].
//      A later change lands the daily anchor cron + the lookup. Pack format
//      reserves the slot now so that change is purely additive.
//   8. Build the pre-signature manifest skeleton (claims +
//      audit_chain_proofs + verification_material + schemas_inline).
//      Canonicalise via RFC 8785-style sorted-keys serialiser
//      (@stack/shared canonicalize). Compute content_hash =
//      sha256:<hex>.
//   9. Build the EvidencePackClaim payload carrying content_hash +
//      merkle_root + audit_chain_anchor + schema_versions + scope +
//      time_bounds + revocation_snapshot_at_ms + supersedes.
//   10. registerClaim with subjectOverride='operator' → primary
//       COSE_Sign1 envelope_cose bytes.
//   11. If a STACK system signer is wired, co-sign the primary
//       envelope_cose with signer_role='operator_attestation'. v1
//       runs gracefully without it (co_signatures = []).
//   12. Assemble the final manifest with the signed claim + any
//       co-signatures.
//   13. Store the final canonical bytes in the audit object store.
//       Persist the claim and immutable artifact metadata in one DB
//       transaction. Delete the object if the transaction fails.
//
// Content-hash binding rule: content_hash is over the canonicalised
// manifest with the `claim` and `co_signatures` fields STRIPPED. This
// breaks the circularity ("manifest contains the signed pack claim
// which itself carries content_hash"). The verifier
// reproduces by stripping the same fields before hashing.
//
// PII discipline (per 5.4.0 ADR Design decision 4): the pack carries
// claim envelopes only. Any PII lives crypto-shred-capable in the
// identity_claim's `assertion_encrypted` row under operator CMEK; the
// envelope carries `assertion_hash` not plaintext. CMEK revoke
// invalidates the underlying PII while the pack stays valid for
// non-PII verification. The producer never decrypts any payload — it
// shuttles envelope bytes verbatim.

import { createHash } from 'node:crypto';
import {
  NotFoundError,
  SchemaValidationError,
  ServiceUnavailableError,
  StackError,
  safeErrorSummary,
  canonicalize,
  computeMerkleRoot,
  ids,
  PASSPORT_CLAIM_SCHEMAS,
  type ClaimType,
  type CoSignature,
  type EvidencePackClaim,
  type EvidencePackManifest,
  type EvidencePackScope,
  type ManifestClaimEntry,
  type ManifestAuditChainProof,
  type ManifestInlineSchemaEntry,
  type ManifestVerificationMaterial,
  type SchemaVersionEntry,
} from '@stack/shared';
import type { ClaimSigner } from '../crypto/claim-signer.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import type { AuditService } from './audit-service.js';
import type { ExternalAnchorService } from './external-anchor-service.js';
import { ExternalAnchorService as ExternalAnchorServiceClass } from './external-anchor-service.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { EvidencePackArtifactRepository } from '../repositories/evidence-pack-artifact-repo.js';
import { ObjectStoreUnavailableError, type ObjectStore } from './object-store.js';

// ─── Dependency shape ───────────────────────────────────────────────

/**
 * Inline JWKS as carried on the pack manifest. Matches
 * `ManifestVerificationMaterial.operator_jwks_inline` shape.
 */
export interface InlineJwksMaterial {
  keys: Array<Record<string, unknown>>;
}

/**
 * Resolver for the per-operator claim signer used to sign the audit
 * chain anchor head. Service-layer wiring at
 * `apps/api/src/config/services.ts` reuses the same factory
 * `ClaimRegistryService` consumes — every claim by the operator
 * signs under the same key, so the head_signature is independently
 * verifiable against the operator's existing JWKS endpoint.
 */
export type OperatorSignerResolver = (operatorId: string) => Promise<ClaimSigner>;

/**
 * Resolver returning the inline schema entries for a pack: the envelope
 * under `envelope` plus one entry per claim type. An export refuses (503)
 * when any is missing or does not hash to its own content_hash.
 */
export type InlineSchemasResolver = (
  claimTypes: ReadonlySet<string>,
) => Promise<Record<string, ManifestInlineSchemaEntry>>;

export interface EvidencePackMissionLookup {
  findById(missionId: string): Promise<{
    mission_id: string;
    operator_id: string;
    started_at: Date;
    completed_at: Date | null;
    revoked_at: Date | null;
  } | null | undefined>;
}

export interface EvidencePackServiceDeps {
  claimRegistry: ClaimRegistryService;
  passportClaimsRepo: PassportClaimsRepository;
  missionRepo: EvidencePackMissionLookup;
  auditService: AuditService;

  /**
   * Resolves to the operator's per-operator claim signer
   * substrate). Used to sign the audit chain anchor head bytes via
   * ClaimSigner.signBytes. Same key the registry's signer factory
   * uses for the pack claim's primary signature, so verifier
   * resolution via the operator's JWKS endpoint covers both surfaces.
   */
  operatorSignerResolver: OperatorSignerResolver;

  /**
   * Optional STACK system signer for the operator-attestation
   * co-signature on the pack claim. When omitted, the manifest ships
   * with `co_signatures: []` and only the operator's primary
   * signature attests the pack. v1 production wiring provides this
   * once the system signer is exposed from
   * `apps/api/src/config/services.ts`; tests pass undefined.
   */
  stackSystemSigner?: ClaimSigner;

  /**
   * Returns the operator's JWKS for inline embedding in the manifest.
   * The operator's JWKS endpoint at
   * `/v1/operators/${operator_id}/jwks.json` returns the same payload.
   */
  getOperatorJwks: (operatorId: string) => Promise<InlineJwksMaterial>;

  /**
   * Returns the STACK system JWKS for inline embedding. Mirrors
   * `/v1/.well-known/jwks.json`. Required even when stackSystemSigner
   * is undefined — verifier wants the system JWKS to verify any
   * pre-existing op_stack_system claims that surface in the pack.
   */
  getStackSystemJwks: () => Promise<InlineJwksMaterial>;

  /** Public URL for the operator's JWKS. Reference-only in the manifest. */
  getOperatorJwksUrl: (operatorId: string) => string;

  /** Public URL for the STACK system JWKS. Reference-only in the manifest. */
  stackSystemJwksUrl: string;

  /**
   * Base URL for the canonical schema registry. Reference-only — the
   * verifier prefers schemas_inline. publishes the
   * actual files; v1 callers can pass any URL.
   */
  canonicalSchemaBaseUrl: string;

  /**
   * Returns the inline schemas + content hashes for the envelope and the
   * set of claim_type values appearing in the pack. The producer pins
   * these hashes in the signed pack claim, so a catalog that is empty,
   * partial or inconsistent refuses the export.
   */
  getInlineSchemas: InlineSchemasResolver;

  /**
   * Optional resolver from passports.session_id to mission_id / scope
   * info. v1 doesn't use it; reserved for incident-scope substrate.
   */

  /**
   * Optional external-anchor service. When wired
   * `export` queries `getAnchorAtOrBefore(operatorId, exportTimeMs)`
   * and includes the result in `EvidencePackClaim.external_chain_anchors[]`.
   * When unwired, the field stays empty — the pack format reserves
   * the slot regardless.
   */
  externalAnchor?: ExternalAnchorService;

  /** Transaction owner for the pack claim and immutable artifact metadata. */
  artifactRepo: EvidencePackArtifactRepository;

  /** Existing audit object store used for exact final manifest bytes. */
  objectStore: ObjectStore;
}

// ─── Public types ───────────────────────────────────────────────────

export interface ExportOptions {
  /** When set, the new pack's `supersedes` field points at this prior pack id. */
  supersedes?: string;
  /**
   * v1 no-op marker. The producer always populates inline JWKS +
   * inline schemas (when the resolver returns them) regardless. The
   * flag signals downstream callers that the consumer intends to
   * verify offline; 5.4.8 verifier reads its own --air-gap flag.
   * Reserved here for future producer-side enforcement (e.g. fail
   * the export when inline schemas are missing in air-gap mode).
   */
  airGap?: boolean;
}

export interface ExportResult {
  pack_id: string;
  /** The passport_claims.claim_id of the persisted EvidencePackClaim row. */
  claim_id: string;
  manifest: EvidencePackManifest;
  pack_claim: EvidencePackClaim;
}

export interface StoredEvidencePackManifest {
  pack_id: string;
  claim_id: string;
  manifest_sha256: string;
  byte_size: number;
  body: Buffer;
}

// ─── Implementation ─────────────────────────────────────────────────

export class EvidencePackService {
  constructor(private deps: EvidencePackServiceDeps) {}

  /**
   * Every call into the object store goes through here, so whichever store is
   * wired, a failure answers as a retriable 503 with a fixed message: the
   * store's own error text (bucket names, request ids) never reaches a caller.
   * A typed error from the store (or the service) passes through unchanged.
   */
  private async storeCall<T>(operation: string, run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (err) {
      if (err instanceof StackError) throw err;
      throw new ObjectStoreUnavailableError(operation, 'unreachable', err);
    }
  }

  async export(
    operatorId: string,
    scope: EvidencePackScope,
    options: ExportOptions = {},
  ): Promise<ExportResult> {
    if (options.supersedes) {
      await this.validateSupersedes(operatorId, scope, options.supersedes);
    }

    // 1. Resolve scope → claim set.
    const resolvedScope = await this.resolveScope(operatorId, scope);
    const claimRows = resolvedScope.claimRows;

    // 2-3. Build manifest claim entries with revocation snapshot per row.
    const revocationSnapshotAtMs = Date.now();
    const includedClaimRows = claimRows
      .filter((row) => row.envelope_cose !== null && row.envelope_cose !== undefined);
    const claimEntries: ManifestClaimEntry[] = includedClaimRows
      .map((row) => ({
        claim_id: row.claim_id,
        claim_hash: row.claim_hash,
        envelope_cose: row.envelope_cose!,
        revoked_at_ms: row.revoked_at ? row.revoked_at.getTime() : null,
      }));
    const included_review_claim_ids = includedClaimRows
      .filter((row) => row.type === 'operator_review' || row.type === 'dossier')
      .map((row) => row.claim_id);

    // 4. Merkle root over ordered claim_hashes.
    const merkle_root = computeMerkleRoot(claimEntries.map((c) => c.claim_hash));

    // 5. Audit chain anchor (head_hash + head_at_ms signed by operator).
    const chainHead = await this.deps.auditService.getChainHead(operatorId);
    const head_hash = chainHead.latest_entry_hash ?? '0'.repeat(64);
    const head_at_ms = chainHead.latest_timestamp ?? revocationSnapshotAtMs;
    const operatorSigner = await this.deps.operatorSignerResolver(operatorId);
    const headSigningSurface = Buffer.from(
      canonicalize({ head_hash, head_at_ms }),
      'utf8',
    );
    const head_signature = await operatorSigner.signBytes(headSigningSurface);

    // 6. Cross-tenant refs. v1: always empty. Plan-locked deferral;
    //    see service docstring step 6.
    const cross_tenant_refs: EvidencePackClaim['cross_tenant_refs'] = [];

    // 7. External chain anchors. Populated from the in-DB anchor log
    //    (5.4.4b substrate) via the anchor-in-effect-at-export-time
    //    lookup. Empty when no anchor service is wired OR no anchor
    //    has been published for this operator yet (cold start before
    //    the first daily cron tick).
    const external_chain_anchors: EvidencePackClaim['external_chain_anchors'] = [];
    if (this.deps.externalAnchor) {
      const anchorRow = await this.deps.externalAnchor.getAnchorAtOrBefore(
        operatorId,
        revocationSnapshotAtMs,
      );
      if (anchorRow) {
        external_chain_anchors.push(ExternalAnchorServiceClass.rowToRef(anchorRow));
      }
    }

    // 5b. Per-claim audit chain proofs. v1 stub: each claim gets a
    //     placeholder entry. The pack claim's primary signature
    //     attests the claim set + head_hash as a single unit; sparse
    //     per-claim Merkle proofs are a future enhancement that
    //     lights up alongside richer audit_log indexing.
    const audit_chain_proofs: ManifestAuditChainProof[] = claimEntries.map((c) => ({
      claim_hash: c.claim_hash,
      audit_position: 0,
      merkle_path: [],
    }));

    // 8. Verification material (URLs + inline JWKS).
    const operatorJwksInline = await this.deps.getOperatorJwks(operatorId);
    const stackSystemJwksInline = await this.deps.getStackSystemJwks();
    const verification_material: ManifestVerificationMaterial = {
      operator_jwks_url: this.deps.getOperatorJwksUrl(operatorId),
      operator_jwks_inline: operatorJwksInline,
      stack_system_jwks_url: this.deps.stackSystemJwksUrl,
      stack_system_jwks_inline: stackSystemJwksInline,
    };

    // 8b. Inline schemas keyed by claim_type. Build envelope hash from
    //     the registered Zod definitions.
    const claimTypesInPack = new Set<string>(includedClaimRows.map((row) => row.type));
    const schemasInline = await this.deps.getInlineSchemas(claimTypesInPack);

    // 8c. Schema version pinning. Every pin is the sha256 of the
    //      canonicalised inline schema it names, recomputed here rather
    //      than trusted from the catalog. A missing or inconsistent
    //      schema refuses the export: a pack never pins a placeholder
    //      hash, because that would sign a claim ("these claims were
    //      written against these schemas") that nothing backs.
    assertSchemaCatalogComplete(schemasInline, claimTypesInPack);
    const envelope_schema_entry = schemasInline['envelope']!.content_hash;
    const by_claim_type: Record<string, SchemaVersionEntry> = {};
    for (const claimType of claimTypesInPack) {
      by_claim_type[claimType] = {
        version: 1,
        content_hash: schemasInline[claimType]!.content_hash,
      };
    }

    // 9. Build the manifest skeleton (claim field still empty — gets
    //    populated AFTER we sign the pack claim, but content_hash
    //    excludes it so we can compute the hash now).
    const skeletonForHashing = {
      pack_version: 1 as const,
      claims: claimEntries,
      audit_chain_proofs,
      verification_material,
      schemas_inline: schemasInline,
    };
    const skeletonCanonical = canonicalize(skeletonForHashing);
    const content_hash = `sha256:${sha256Hex(skeletonCanonical)}`;

    // 10. Build the EvidencePackClaim payload.
    const pack_id = ids.pack();
    const time_bounds = this.resolveTimeBounds(
      claimRows,
      resolvedScope.timeBounds,
      revocationSnapshotAtMs,
    );
    const packPayload: EvidencePackClaim = {
      type: 'evidence_pack',
      pack_id,
      content_hash,
      scope,
      time_bounds,
      claim_count: claimEntries.length,
      included_review_claim_ids,
      merkle_root,
      audit_chain_anchor: {
        head_hash,
        head_signature,
        head_at_ms,
      },
      revocation_snapshot_at_ms: revocationSnapshotAtMs,
      schema_versions: {
        envelope: { version: 1, content_hash: envelope_schema_entry },
        by_claim_type: by_claim_type as Record<ClaimType, SchemaVersionEntry>,
      },
      canonical_schema_base_url: this.deps.canonicalSchemaBaseUrl,
      supersedes: options.supersedes ?? null,
      cross_tenant_refs,
      external_chain_anchors,
    };

    // 11. Register via claimRegistry (tier-gate + payload schema check
    //     + primary signature + persist). registerClaim guarantees the
    //     payload validates against PASSPORT_CLAIM_SCHEMAS['evidence_pack']
    //     — defensive parse here would be redundant work.
    void PASSPORT_CLAIM_SCHEMAS;
    const objectKey = evidencePackObjectKey(operatorId, pack_id);
    let objectWriteAttempted = false;
    try {
      return await this.deps.artifactRepo.transaction(async ({
        artifacts,
        claimPersistence,
      }) => {
        const registered = await this.deps.claimRegistry.registerClaim({
          operatorId,
          claimType: 'evidence_pack',
          payload: packPayload,
          subjectOverride: 'operator',
        }, { persistence: claimPersistence });
        const claim_cose = registered.envelopeCose;

        const co_signatures: CoSignature[] = [];
        if (this.deps.stackSystemSigner) {
          const coSig = await this.deps.stackSystemSigner.coSign(
            claim_cose,
            'operator_attestation',
          );
          co_signatures.push(coSig);
        }

        const manifest: EvidencePackManifest = {
          pack_version: 1,
          claim: claim_cose,
          co_signatures,
          claims: claimEntries,
          audit_chain_proofs,
          verification_material,
          schemas_inline: schemasInline,
        };
        const manifestBytes = Buffer.from(canonicalize(manifest), 'utf8');
        const manifestSha256 = sha256Hex(manifestBytes);

        if (await this.storeCall('exists', () => this.deps.objectStore.exists(objectKey))) {
          throw new Error(`evidence-pack object key collision for ${pack_id}`);
        }
        objectWriteAttempted = true;
        await this.storeCall('put', () => this.deps.objectStore.put(objectKey, manifestBytes, {
          contentType: 'application/json',
        }));

        const readBack = await this.storeCall('get', () => this.deps.objectStore.get(objectKey));
        if (
          !readBack ||
          readBack.length !== manifestBytes.length ||
          sha256Hex(readBack) !== manifestSha256
        ) {
          throw new ServiceUnavailableError(
            'Evidence-pack artifact storage failed verification',
          );
        }

        await artifacts.create({
          pack_id,
          claim_id: registered.claimId,
          operator_id: operatorId,
          object_key: objectKey,
          byte_size: manifestBytes.length,
          manifest_sha256: manifestSha256,
        });

        return {
          pack_id,
          claim_id: registered.claimId,
          manifest,
          pack_claim: packPayload,
        };
      });
    } catch (error) {
      if (objectWriteAttempted) {
        try {
          await this.deps.objectStore.delete(objectKey);
        } catch (cleanupError) {
          // A failed export that also cannot clean up its object still answers
          // with the export's own error (a store outage stays a 503); the
          // orphaned key is logged for the operator.
          console.error(
            '[evidence-pack] export failed and object cleanup failed:', pack_id,
            safeErrorSummary(cleanupError),
          );
          if (error instanceof StackError) throw error;
          throw new AggregateError(
            [error, cleanupError],
            `evidence-pack export failed and object cleanup failed for ${pack_id}`,
            { cause: cleanupError },
          );
        }
      }
      throw error;
    }
  }

  async getStoredManifest(
    operatorId: string,
    packId: string,
  ): Promise<StoredEvidencePackManifest> {
    const artifact = await this.deps.artifactRepo.findByPackIdAndOperator(
      packId,
      operatorId,
    );
    if (!artifact) throw new NotFoundError('evidence-pack artifact', packId);

    const body = await this.storeCall('get', () => this.deps.objectStore.get(artifact.object_key));
    if (
      !body ||
      body.length !== artifact.byte_size ||
      sha256Hex(body) !== artifact.manifest_sha256
    ) {
      throw new ServiceUnavailableError(
        'Evidence-pack artifact is missing or failed hash verification',
      );
    }

    return {
      pack_id: artifact.pack_id,
      claim_id: artifact.claim_id,
      manifest_sha256: artifact.manifest_sha256,
      byte_size: artifact.byte_size,
      body,
    };
  }

  async getArtifactStates(
    operatorId: string,
    packIds: string[],
  ): Promise<Map<string, 'stored_manifest'>> {
    const rows = await this.deps.artifactRepo.findByPackIdsAndOperator(packIds, operatorId);
    return new Map(rows.map((row) => [row.pack_id, 'stored_manifest' as const]));
  }

  /** Validate the signed predecessor before any new pack bytes are signed. */
  private async validateSupersedes(
    operatorId: string,
    scope: EvidencePackScope,
    supersededPackId: string,
  ): Promise<void> {
    const row = await this.deps.passportClaimsRepo.findEvidencePackByPackId(
      supersededPackId,
      operatorId,
    );
    if (!row) throw new NotFoundError('evidence pack', supersededPackId);

    const verified = await this.deps.claimRegistry.verifyClaim(row.claim_id);
    const envelope = verified.envelope;
    const payload = envelope?.payload;
    if (
      !verified.valid ||
      !envelope ||
      envelope.issuer !== operatorId ||
      envelope.claim_type !== 'evidence_pack' ||
      !payload ||
      typeof payload !== 'object' ||
      Array.isArray(payload)
    ) {
      throw new SchemaValidationError({
        message: `superseded evidence pack ${supersededPackId} has no valid signed payload`,
        claim_type: 'evidence_pack',
      });
    }

    const signedPayload = payload as unknown as Record<string, unknown>;
    const signedScope = signedPayload['scope'];
    if (
      signedPayload['type'] !== 'evidence_pack' ||
      signedPayload['pack_id'] !== supersededPackId ||
      !signedScope ||
      typeof signedScope !== 'object' ||
      Array.isArray(signedScope)
    ) {
      throw new SchemaValidationError({
        message: `superseded evidence pack ${supersededPackId} has no valid signed payload`,
        claim_type: 'evidence_pack',
      });
    }

    const priorScope = signedScope as Record<string, unknown>;
    if (priorScope['kind'] !== scope.kind || priorScope['ref'] !== scope.ref) {
      throw new SchemaValidationError({
        message: 'a superseded evidence pack must have the exact same scope',
        claim_type: 'evidence_pack',
      });
    }
  }

  /**
   * Resolve a scope to its claim set per the 5.4.0 ADR Design
   * decision 3 boundary rules. Incident scope throws because its
   * substrate has not shipped.
   */
  private async resolveScope(
    operatorId: string,
    scope: EvidencePackScope,
  ): Promise<{
    claimRows: Array<{
      claim_id: string;
      passport_id: string | null;
      claim_hash: string;
      type: string;
      envelope_cose: string | null;
      issued_at_ms: number | null;
      revoked_at: Date | null;
    }>;
    timeBounds?: EvidencePackClaim['time_bounds'];
  }> {
    switch (scope.kind) {
      case 'mission': {
        const mission = await this.deps.missionRepo.findById(scope.ref);
        if (!mission || mission.operator_id !== operatorId) {
          throw new NotFoundError('mission', scope.ref);
        }
        const t0Ms = mission.started_at.getTime();
        const t1Ms = (mission.revoked_at ?? mission.completed_at)?.getTime() ?? Date.now();
        if (t1Ms <= t0Ms) {
          throw new SchemaValidationError({
            message: `mission ${scope.ref} has invalid evidence time bounds`,
            claim_type: 'evidence_pack',
          });
        }
        return {
          claimRows: await this.deps.passportClaimsRepo.findInMissionScope(
            scope.ref,
            operatorId,
            t0Ms,
            t1Ms,
          ),
          timeBounds: { t0_ms: t0Ms, t1_ms: t1Ms },
        };
      }
      case 'session':
        return {
          claimRows: await this.deps.passportClaimsRepo.findInSessionScope(scope.ref, operatorId),
        };
      case 'period': {
        const { t0_ms, t1_ms } = parsePeriodRef(scope.ref);
        const inWindow = await this.deps.passportClaimsRepo.findInTimeWindow(
          operatorId,
          t0_ms,
          t1_ms,
        );
        const passportIds = [
          ...new Set(
            inWindow
              .map((row) => row.passport_id)
              .filter((passportId): passportId is string => typeof passportId === 'string'),
          ),
        ];
        const boundaryClaims = await this.deps.passportClaimsRepo.findPeriodBoundaryClaims(
          operatorId,
          passportIds,
          t0_ms,
        );
        const byClaimId = new Map(
          [...boundaryClaims, ...inWindow].map((row) => [row.claim_id, row]),
        );
        const claimRows = [...byClaimId.values()].sort((a, b) => {
          const aTime = a.issued_at_ms ?? Number.MAX_SAFE_INTEGER;
          const bTime = b.issued_at_ms ?? Number.MAX_SAFE_INTEGER;
          return aTime - bTime || a.claim_id.localeCompare(b.claim_id);
        });
        return {
          claimRows,
          timeBounds: { t0_ms, t1_ms },
        };
      }
      case 'incident':
        throw new SchemaValidationError({
          message:
            "scope.kind='incident' is reserved in the pack format but the producer is not yet wired. " +
 'Incident substrate ships later; the pack schema already accommodates it.',
          claim_type: 'evidence_pack',
        });
      default: {
        const _exhaustive: never = scope.kind;
        throw new SchemaValidationError({
          message: `unknown scope.kind '${String(_exhaustive)}'`,
          claim_type: 'evidence_pack',
        });
      }
    }
  }

  /**
   * Derive `time_bounds` per scope kind. v1 rules:
   *   - mission: [min issued_at, max issued_at + 1] of included claims
   *     when the set is non-empty; falls back to [now, now+1] for empty
   *     packs (claim_count === 0, valid per schema).
   *   - session: same as mission.
   *   - period: parse the ref's date range.
   *   - incident: never reached (resolveScope throws).
   */
  private resolveTimeBounds(
    claimRows: Array<{ issued_at_ms: number | null }>,
    resolvedBounds: EvidencePackClaim['time_bounds'] | undefined,
    fallbackMs: number,
  ): EvidencePackClaim['time_bounds'] {
    if (resolvedBounds) return resolvedBounds;
    const issuedAt = claimRows
      .map((row) => row.issued_at_ms)
      .filter((value): value is number => typeof value === 'number');
    if (issuedAt.length === 0) {
      return { t0_ms: fallbackMs, t1_ms: fallbackMs + 1 };
    }
    // Without issued_at_ms on the manifest entry we'd need a back-
    // lookup; we don't carry it through. Fall back to fallbackMs ±
    // half a second so the refine passes. Producer + verifier
    // re-derive bounds from the claim entries directly in 5.4.5 / 5.4.8.
    return {
      t0_ms: Math.min(...issuedAt),
      t1_ms: Math.max(...issuedAt) + 1,
    };
  }
}

// ─── Helpers ────────────────────────────────────────────────────────

function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function evidencePackObjectKey(operatorId: string, packId: string): string {
  if (!/^op_[\w-]+$/.test(operatorId) || !/^pck_[\w-]+$/.test(packId)) {
    throw new SchemaValidationError({
      message: 'invalid operator or pack id for evidence-pack artifact storage',
      claim_type: 'evidence_pack',
    });
  }
  return `audit/${operatorId}/evidence-packs/${packId}.json`;
}

const SHA256_PIN = /^sha256:[0-9a-f]{64}$/;

/**
 * Every schema a pack pins must be present inline with a content_hash
 * that is the sha256 of its own canonicalised body: the envelope plus one
 * entry per claim type in the pack. Throws a retriable 503 naming the
 * offending keys otherwise (the catalog is a deployment artefact, so the
 * fault is on STACK's side and a re-export after a fix produces a sound pack).
 */
function assertSchemaCatalogComplete(
  schemasInline: Record<string, ManifestInlineSchemaEntry>,
  claimTypes: ReadonlySet<string>,
): void {
  const required = ['envelope', ...claimTypes];
  const missing = required.filter((key) => schemasInline[key] === undefined);
  if (missing.length > 0) {
    throw new ServiceUnavailableError(
      `Evidence-pack schema catalog is incomplete (missing: ${missing.join(', ')})`,
    );
  }
  const inconsistent = required.filter((key) => {
    const entry = schemasInline[key]!;
    return (
      !SHA256_PIN.test(entry.content_hash) ||
      entry.content_hash !== `sha256:${sha256Hex(canonicalize(entry.json_schema))}`
    );
  });
  if (inconsistent.length > 0) {
    throw new ServiceUnavailableError(
      `Evidence-pack schema catalog is inconsistent (hash mismatch: ${inconsistent.join(', ')})`,
    );
  }
}

/**
 * Parse a period-scope ref into time bounds. Accepts three shapes:
 *   - `period:YYYY-Qn` — calendar quarter
 *   - `period:YYYY-MM` — calendar month
 *   - `period:YYYY-MM-DD/YYYY-MM-DD` — explicit half-open range
 *
 * Throws SchemaValidationError on malformed refs so the export
 * surface fails closed.
 */
function parsePeriodRef(ref: string): { t0_ms: number; t1_ms: number } {
  if (!ref.startsWith('period:')) {
    throw new SchemaValidationError({
      message: `period scope ref must start with 'period:' (got '${ref}')`,
      claim_type: 'evidence_pack',
    });
  }
  const body = ref.slice('period:'.length);

  // Quarter shape: YYYY-Qn
  const quarter = /^(\d{4})-Q([1-4])$/.exec(body);
  if (quarter) {
    const year = Number(quarter[1]);
    const q = Number(quarter[2]);
    const startMonth = (q - 1) * 3; // 0, 3, 6, 9
    const t0 = Date.UTC(year, startMonth, 1);
    const t1 = Date.UTC(year, startMonth + 3, 1);
    return { t0_ms: t0, t1_ms: t1 };
  }

  // Month shape: YYYY-MM
  const month = /^(\d{4})-(\d{2})$/.exec(body);
  if (month) {
    const year = Number(month[1]);
    const m = Number(month[2]);
    if (m < 1 || m > 12) {
      throw new SchemaValidationError({
        message: `period month must be 1..12 (got '${ref}')`,
        claim_type: 'evidence_pack',
      });
    }
    const t0 = Date.UTC(year, m - 1, 1);
    const t1 = Date.UTC(year, m, 1);
    return { t0_ms: t0, t1_ms: t1 };
  }

  // Range shape: YYYY-MM-DD/YYYY-MM-DD
  const range = /^(\d{4}-\d{2}-\d{2})\/(\d{4}-\d{2}-\d{2})$/.exec(body);
  if (range) {
    const t0 = Date.parse(range[1]!);
    const t1 = Date.parse(range[2]!);
    if (Number.isNaN(t0) || Number.isNaN(t1)) {
      throw new SchemaValidationError({
        message: `period range dates must be ISO YYYY-MM-DD (got '${ref}')`,
        claim_type: 'evidence_pack',
      });
    }
    if (t1 <= t0) {
      throw new SchemaValidationError({
        message: `period range end must be > start (got '${ref}')`,
        claim_type: 'evidence_pack',
      });
    }
    return { t0_ms: t0, t1_ms: t1 };
  }

  throw new SchemaValidationError({
    message:
      `period scope ref '${ref}' does not match any supported shape. ` +
      `Use 'period:YYYY-Qn' | 'period:YYYY-MM' | 'period:YYYY-MM-DD/YYYY-MM-DD'.`,
    claim_type: 'evidence_pack',
  });
}
