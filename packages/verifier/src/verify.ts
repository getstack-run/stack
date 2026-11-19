/**
 * Main verifier orchestrator. Public API at `./index.ts` re-exports
 * this. The CLI in `./cli.ts` wraps this with argv parsing + output
 * formatting.
 *
 * Verification order matches the 5.4.0 ADR's threat model:
 *
 *   1. Manifest shape — parse + structural validate.
 *   2. Pack-claim COSE_Sign1 — decode the primary signature.
 *   3. Co-signatures — verify each independently.
 *   4. Content hash — re-derive sha256 over canonical manifest
 *      with `claim` + `co_signatures` stripped; compare to pack
 *      claim's `content_hash`.
 *   5. Merkle root — re-compute over ordered claim_hashes; compare
 *      to pack claim's `merkle_root`.
 *   6. Per-claim envelopes — verify legacy claims against operator or
 *      system JWKS. Require operator keys for decisions and reviews.
 *   7. Per-claim hashes — sha256(envelope_cose) matches claim_hash.
 *   8. Schema content hashes — every entry in `schemas_inline`
 *      content_hash equals the recomputed hash of its body and the
 *      pinned `schema_versions` content_hash. Pins that are the all-zero
 *      placeholder, or that have no inline schema to recompute, are
 *      reported as not attested (a warning, never a pass).
 *   9. Unknown-claim-type handling — count claims whose claim_type
 *      lacks a schemas_inline entry. Strict / ignore-unknown flags
 *      adjust the outcome.
 *   10. Audit chain anchor — verify the operator-signed head bytes.
 *   11. External chain anchors — fetch each permalink (or skip on
 *       --air-gap) and confirm `anchored_chain_head_hash`.
 */

import { createHash } from 'node:crypto';
import {
  decodeCoseSign1,
  verifyCoseSign1,
  verifyDetachedEd25519,
  type JwkLike,
} from './cose.js';
import { canonicalize } from './canonicalize.js';
import { computeMerkleRoot } from './merkle.js';
import { reconstructTimeline as reconstructActivity } from './activity.js';
import type {
  EvidencePackClaim,
  EvidencePackManifest,
  VerifyCheck,
  VerifyOptions,
  VerifyResult,
  ReconstructClaimInput,
} from './types.js';

/** Early producers pinned this value when they had no schema catalog to hash. */
const ZERO_SCHEMA_HASH = `sha256:${'0'.repeat(64)}`;

interface DecodedManifestClaim {
  claim_id?: string;
  claim_hash: string;
  issuer: string | null;
  claim_type: string | null;
  issued_at_ms: number | null;
  payload: Record<string, unknown> | null;
}

// ─── Public entry point ─────────────────────────────────────────────

export async function verifyPack(
  manifest: EvidencePackManifest,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  if (options.strict && options.ignoreUnknown) {
    throw new Error('--strict and --ignore-unknown are mutually exclusive');
  }

  const checks: VerifyCheck[] = [];
  const errors: VerifyResult['errors'] = [];
  const warnings: VerifyResult['warnings'] = [];

  function pass(name: string, detail?: string): void {
    checks.push({ name, outcome: 'pass', ...(detail !== undefined ? { detail } : {}) });
  }
  function fail(name: string, code: string, message: string): void {
    checks.push({ name, outcome: 'fail', detail: message });
    errors.push({ code, message });
  }
  function skip(name: string, detail: string): void {
    checks.push({ name, outcome: 'skip', detail });
  }
  function warn(name: string, code: string, message: string): void {
    checks.push({ name, outcome: 'warn', detail: message });
    warnings.push({ code, message });
  }

  // ── 1. Manifest shape ───────────────────────────────────────────
  if (!manifest || manifest.pack_version !== 1) {
    return finalise({
      pack_id: null,
      scope: null,
      claim_count: 0,
      timespan: null,
      revoked_at_export: 0,
      unknown_claim_types: 0,
      external_anchors_verified: 0,
      checks: [{ name: 'manifest-shape', outcome: 'fail', detail: 'pack_version is not 1' }],
      errors: [{ code: 'INVALID_MANIFEST', message: 'pack_version is not 1' }],
      warnings: [],
    });
  }
  if (typeof manifest.claim !== 'string' || manifest.claim.length === 0) {
    return finalise({
      pack_id: null,
      scope: null,
      claim_count: 0,
      timespan: null,
      revoked_at_export: 0,
      unknown_claim_types: 0,
      external_anchors_verified: 0,
      checks: [{ name: 'manifest-shape', outcome: 'fail', detail: '`claim` field missing or empty' }],
      errors: [{ code: 'INVALID_MANIFEST', message: '`claim` field missing or empty' }],
      warnings: [],
    });
  }
  pass('manifest-shape');

  // ── 2. Decode + verify primary pack-claim signature ─────────────
  let decoded: ReturnType<typeof decodeCoseSign1>;
  try {
    decoded = decodeCoseSign1(manifest.claim);
  } catch (err) {
    fail('pack-claim-decode', 'COSE_DECODE_FAILED', (err as Error).message);
    return finalise({
      pack_id: null,
      scope: null,
      claim_count: 0,
      timespan: null,
      revoked_at_export: 0,
      unknown_claim_types: 0,
      external_anchors_verified: 0,
      checks,
      errors,
      warnings,
    });
  }
  const packClaim = decoded.envelope as { payload?: EvidencePackClaim };
  const pack: EvidencePackClaim | undefined = packClaim.payload;
  if (!pack || pack.type !== 'evidence_pack') {
    fail('pack-claim-decode', 'NOT_EVIDENCE_PACK', 'payload is not an evidence_pack claim');
    return finalise({
      pack_id: null,
      scope: null,
      claim_count: 0,
      timespan: null,
      revoked_at_export: 0,
      unknown_claim_types: 0,
      external_anchors_verified: 0,
      checks,
      errors,
      warnings,
    });
  }

  const operatorResolver = makeJwksResolver(
    manifest.verification_material.operator_jwks_inline,
    options,
  );
  const systemResolver = makeJwksResolver(
    manifest.verification_material.stack_system_jwks_inline,
    options,
  );
  const primaryVerify = await verifyCoseWithResolvers(
    decoded,
    [operatorResolver, systemResolver],
  );
  if (!primaryVerify.valid) {
    fail('pack-claim-signature', 'PRIMARY_SIG_INVALID', primaryVerify.error ?? 'unknown failure');
  } else {
    pass('pack-claim-signature', `kid=${decoded.kid}`);
  }

  // ── 3. Co-signatures ────────────────────────────────────────────
  if ((manifest.co_signatures ?? []).length === 0) {
    warn(
      'co-signature',
      'STACK_COSIGNATURE_MISSING',
      'The Signed record has no STACK system co-signature.',
    );
  }
  for (const cosig of manifest.co_signatures ?? []) {
    try {
      const cosigDecoded = decodeCoseSign1(cosig.cose_sign1);
      if (cosigDecoded.kid !== cosig.signer_kid) {
        fail('co-signature', 'KID_MISMATCH', `manifest kid '${cosig.signer_kid}' != decoded kid '${cosigDecoded.kid}'`);
        continue;
      }
      if (!cosigDecoded.payloadBytes.equals(decoded.payloadBytes)) {
        fail('co-signature', 'COSIG_PAYLOAD_MISMATCH', `${cosig.signer_kid}: payload does not match the primary claim`);
        continue;
      }
      const verifyOut = await verifyCoseSign1(cosigDecoded, { resolveJwk: systemResolver });
      if (verifyOut.valid && cosig.signer_role === 'operator_attestation') {
        pass('co-signature', `kid=${cosig.signer_kid}, role=${cosig.signer_role}`);
      } else if (verifyOut.valid) {
        fail('co-signature', 'COSIG_ROLE_INVALID', `${cosig.signer_kid}: expected operator_attestation role`);
      } else {
        fail('co-signature', 'COSIG_SIG_INVALID', `${cosig.signer_kid}: ${verifyOut.error ?? 'unknown'}`);
      }
    } catch (err) {
      fail('co-signature', 'COSIG_DECODE_FAILED', `${cosig.signer_kid}: ${(err as Error).message}`);
    }
  }

  // ── 4. Content hash ─────────────────────────────────────────────
  // The producer hashes `canonicalize(manifest minus claim + co_signatures)`.
  // We reproduce by lifting the rest of the manifest into a skeleton
  // and re-hashing.
  const skeleton = {
    pack_version: manifest.pack_version,
    claims: manifest.claims,
    audit_chain_proofs: manifest.audit_chain_proofs,
    verification_material: manifest.verification_material,
    schemas_inline: manifest.schemas_inline,
  };
  const recomputed = `sha256:${createHash('sha256').update(canonicalize(skeleton)).digest('hex')}`;
  if (recomputed !== pack.content_hash) {
    fail(
      'content-hash',
      'CONTENT_HASH_MISMATCH',
      `expected ${pack.content_hash}, recomputed ${recomputed}`,
    );
  } else {
    pass('content-hash', pack.content_hash);
  }

  if (pack.claim_count !== manifest.claims.length) {
    fail(
      'claim-count',
      'CLAIM_COUNT_MISMATCH',
      `signed claim_count ${pack.claim_count} does not match ${manifest.claims.length} manifest claims`,
    );
  } else {
    pass('claim-count', `${manifest.claims.length} claims`);
  }

  const presentClaimIds = manifest.claims
    .map((entry) => entry.claim_id)
    .filter((claimId): claimId is string => claimId !== undefined);
  const malformedClaimIds = presentClaimIds.filter((claimId) => !/^pc_[\w-]+$/.test(claimId));
  if (malformedClaimIds.length > 0) {
    fail('claim-ids', 'CLAIM_ID_INVALID', `${malformedClaimIds.length} claim ids are malformed`);
  } else if (new Set(presentClaimIds).size !== presentClaimIds.length) {
    fail('claim-ids', 'CLAIM_ID_DUPLICATE', 'manifest claim ids must be unique');
  } else if (presentClaimIds.length !== manifest.claims.length) {
    warn(
      'claim-ids',
      'CLAIM_IDS_MISSING',
      `${manifest.claims.length - presentClaimIds.length} legacy manifest entries have no exact claim id`,
    );
  } else {
    pass('claim-ids', `${presentClaimIds.length} exact claim ids`);
  }

  // ── 5. Merkle root ──────────────────────────────────────────────
  try {
    const recomputedRoot = computeMerkleRoot(manifest.claims.map((c) => c.claim_hash));
    if (recomputedRoot !== pack.merkle_root) {
      fail(
        'merkle-root',
        'MERKLE_ROOT_MISMATCH',
        `expected ${pack.merkle_root}, recomputed ${recomputedRoot}`,
      );
    } else {
      pass('merkle-root', `${manifest.claims.length} leaves → ${pack.merkle_root}`);
    }
  } catch (err) {
    fail('merkle-root', 'MERKLE_COMPUTE_FAILED', (err as Error).message);
  }

  // ── 6 + 7. Per-claim signatures + hashes ────────────────────────
  let claimSigFailures = 0;
  let claimHashFailures = 0;
  const decodedManifestClaims: DecodedManifestClaim[] = [];
  const expectedOperatorId = typeof decoded.envelope['issuer'] === 'string'
    ? decoded.envelope['issuer']
    : null;
  for (const entry of manifest.claims) {
    // Hash check first — cheap deterministic byte work.
    const envBytes = Buffer.from(entry.envelope_cose, 'base64url');
    const expectedHash = createHash('sha256').update(envBytes).digest('hex');
    if (expectedHash !== entry.claim_hash) {
      claimHashFailures += 1;
      continue;
    }
    // Signature check.
    try {
      const claimDecoded = decodeCoseSign1(entry.envelope_cose);
      const envelope = claimDecoded.envelope as {
        issuer?: unknown;
        issued_at?: unknown;
        claim_type?: unknown;
        payload?: unknown;
      };
      const claimType = typeof envelope.claim_type === 'string' ? envelope.claim_type : null;
      const requiresOperatorSignature =
        claimType === 'operator_decision' || claimType === 'operator_review';
      const result = await verifyCoseWithResolvers(
        claimDecoded,
        requiresOperatorSignature
          ? [operatorResolver]
          : [operatorResolver, systemResolver],
      );
      if (!result.valid) claimSigFailures += 1;
      const issuer = typeof envelope.issuer === 'string' ? envelope.issuer : null;
      if (expectedOperatorId && issuer !== expectedOperatorId) claimSigFailures += 1;
      decodedManifestClaims.push({
        ...(entry.claim_id !== undefined ? { claim_id: entry.claim_id } : {}),
        claim_hash: entry.claim_hash,
        issuer,
        claim_type: claimType,
        issued_at_ms: typeof envelope.issued_at === 'number' ? envelope.issued_at : null,
        payload:
          envelope.payload !== null &&
          typeof envelope.payload === 'object' &&
          !Array.isArray(envelope.payload)
            ? envelope.payload as Record<string, unknown>
            : null,
      });
    } catch {
      claimSigFailures += 1;
    }
  }
  if (claimHashFailures > 0) {
    fail(
      'per-claim-hashes',
      'CLAIM_HASH_MISMATCH',
      `${claimHashFailures} of ${manifest.claims.length} claim_hash values do not match sha256(envelope_cose)`,
    );
  } else if (manifest.claims.length > 0) {
    pass('per-claim-hashes', `${manifest.claims.length} hashes verified`);
  }
  if (claimSigFailures > 0) {
    fail(
      'per-claim-signatures',
      'CLAIM_SIG_INVALID',
      `${claimSigFailures} of ${manifest.claims.length} claim envelope signatures failed`,
    );
  } else if (manifest.claims.length > 0) {
    pass('per-claim-signatures', `${manifest.claims.length} signatures verified`);
  }

  const hasReviewClaims = decodedManifestClaims.some((claim) =>
    claim.claim_type === 'dossier' || claim.claim_type === 'operator_review');
  if (hasReviewClaims && presentClaimIds.length !== manifest.claims.length) {
    warn(
      'review-relationships',
      'REVIEW_RELATIONSHIPS_UNVERIFIABLE',
      'The Signed record has review claims, but at least one manifest claim has no exact claim id.',
    );
  } else {
    const relationshipErrors = verifyReviewRelationships(
      pack,
      expectedOperatorId,
      decodedManifestClaims,
    );
    if (relationshipErrors.length > 0) {
      fail('review-relationships', 'REVIEW_REFERENCE_INVALID', relationshipErrors.join('; '));
    } else if (hasReviewClaims) {
      pass('review-relationships', 'all review references resolve inside the Signed record');
    }
  }

  const actualReviewIds = decodedManifestClaims
    .filter((claim) => claim.claim_type === 'dossier' || claim.claim_type === 'operator_review')
    .map((claim) => claim.claim_id)
    .filter((claimId): claimId is string => claimId !== undefined)
    .sort();
  if (pack.included_review_claim_ids === undefined) {
    warn(
      'included-review-ids',
      'INCLUDED_REVIEW_IDS_MISSING',
      'This legacy pack claim does not name included review revisions.',
    );
  } else if (
    !Array.isArray(pack.included_review_claim_ids) ||
    pack.included_review_claim_ids.some((claimId) => typeof claimId !== 'string')
  ) {
    fail('included-review-ids', 'INCLUDED_REVIEW_IDS_INVALID', 'included review claim ids are malformed');
  } else {
    const signedReviewIds = [...pack.included_review_claim_ids].sort();
    if (JSON.stringify(signedReviewIds) !== JSON.stringify(actualReviewIds)) {
      fail(
        'included-review-ids',
        'INCLUDED_REVIEW_IDS_MISMATCH',
        'signed included review claim ids do not match the manifest review claims',
      );
    } else {
      pass('included-review-ids', `${signedReviewIds.length} review revisions`);
    }
  }

  const proofByHash = new Map(manifest.audit_chain_proofs.map((proof) => [proof.claim_hash, proof]));
  const incompleteProofCount = manifest.claims.filter((claim) => {
    const proof = proofByHash.get(claim.claim_hash);
    return !proof || (proof.audit_position === 0 && proof.merkle_path.length === 0);
  }).length;
  if (incompleteProofCount > 0 || proofByHash.size !== manifest.claims.length) {
    warn(
      'audit-chain-proofs',
      'AUDIT_PROOFS_INCOMPLETE',
      `${incompleteProofCount} claim proofs are missing or placeholders`,
    );
  } else {
    warn(
      'audit-chain-proofs',
      'AUDIT_PROOFS_UNVERIFIED',
      `${manifest.claims.length} proof entries are present, but this format lacks path-direction data`,
    );
  }

  // ── 8. Schema content hashes ────────────────────────────────────
  let schemaHashFailures = 0;
  for (const [key, entry] of Object.entries(manifest.schemas_inline)) {
    const recomputedSchemaHash = `sha256:${createHash('sha256').update(canonicalize(entry.json_schema)).digest('hex')}`;
    if (recomputedSchemaHash !== entry.content_hash) {
      schemaHashFailures += 1;
      fail(
        'schema-content-hash',
        'SCHEMA_HASH_MISMATCH',
        `${key}: inline content_hash ${entry.content_hash} != recomputed ${recomputedSchemaHash}`,
      );
    }
    // Compare against the pinned schema_versions entry.
    const pinned =
      key === 'envelope'
        ? pack.schema_versions.envelope?.content_hash
        : pack.schema_versions.by_claim_type[key]?.content_hash;
    if (!pinned) {
      schemaHashFailures += 1;
      fail(
        'schema-pin-missing',
        'SCHEMA_PIN_MISSING',
        `${key}: inline schema has no signed schema version pin`,
      );
    } else if (pinned !== entry.content_hash) {
      schemaHashFailures += 1;
      fail(
        'schema-pin-mismatch',
        'SCHEMA_PIN_MISMATCH',
        `${key}: pinned ${pinned} != inline ${entry.content_hash}`,
      );
    }
  }
  if (schemaHashFailures === 0) {
    pass('schemas-inline', `${Object.keys(manifest.schemas_inline).length} entries`);
  }

  // A pin only attests something when it is the real hash of a schema the
  // verifier can recompute offline. An all-zero pin is the placeholder that
  // early producers wrote when they had no schema catalog: such a pack stays
  // valid, but it never counts as attesting its schemas. A non-zero pin with
  // no inline schema cannot be recomputed here, so it is reported too.
  const schemaPins: Array<[string, string | undefined]> = [
    ['envelope', pack.schema_versions?.envelope?.content_hash],
    ...Object.entries(pack.schema_versions?.by_claim_type ?? {}).map(
      ([key, entry]): [string, string | undefined] => [key, entry?.content_hash],
    ),
  ];
  const placeholderPins: string[] = [];
  const uncheckedPins: string[] = [];
  for (const [key, pinned] of schemaPins) {
    if (key in manifest.schemas_inline) continue; // checked above
    if (pinned === undefined || pinned === ZERO_SCHEMA_HASH) placeholderPins.push(key);
    else uncheckedPins.push(key);
  }
  if (placeholderPins.length > 0) {
    warn(
      'schema-hash-attestation',
      'SCHEMA_HASH_NOT_ATTESTED',
      `schema hash not attested: ${placeholderPins.join(', ')} ` +
        `${placeholderPins.length === 1 ? 'carries' : 'carry'} the all-zero placeholder hash, ` +
        'so the pack does not say which schemas its claims were written against',
    );
  }
  if (uncheckedPins.length > 0) {
    warn(
      'schema-hash-attestation',
      'SCHEMA_PIN_UNCHECKED',
      `${uncheckedPins.join(', ')} ${uncheckedPins.length === 1 ? 'is' : 'are'} pinned by hash ` +
        'but carry no inline schema, so the hash cannot be recomputed offline',
    );
  }
  if (placeholderPins.length === 0 && uncheckedPins.length === 0 && schemaHashFailures === 0) {
    pass('schema-hash-attestation', `${schemaPins.length} schema pins match their inline schemas`);
  }

  // ── 9. Unknown-claim-type handling ──────────────────────────────
  // For every distinct claim_type appearing in claims[], require a
  // matching schemas_inline entry (when --air-gap, this is strict
  // regardless). Default mode flags; --strict fails; --ignore-unknown
  // warns once.
  const claimTypesInPack = new Set<string>();
  for (const entry of manifest.claims) {
    try {
      const decodedClaim = decodeCoseSign1(entry.envelope_cose);
      const env = decodedClaim.envelope as { claim_type?: unknown };
      if (typeof env.claim_type === 'string') {
        claimTypesInPack.add(env.claim_type);
      }
    } catch {
      // already counted under per-claim-signatures
    }
  }
  let unknownClaimTypes = 0;
  for (const claimType of claimTypesInPack) {
    if (!(claimType in manifest.schemas_inline)) {
      unknownClaimTypes += 1;
      if (options.strict || options.airGap) {
        fail(
          'unknown-claim-type',
          'UNKNOWN_CLAIM_TYPE',
          `claim_type '${claimType}' has no inline schema (--strict / --air-gap rejects)`,
        );
      } else if (options.ignoreUnknown) {
        // single warning aggregated below
      } else {
        warn(
          'unknown-claim-type',
          'UNKNOWN_CLAIM_TYPE',
          `claim_type '${claimType}' has no inline schema; fetch from ${pack.canonical_schema_base_url}${claimType}.json to verify`,
        );
      }
    }
  }
  if (unknownClaimTypes > 0 && options.ignoreUnknown) {
    warn(
      'unknown-claim-type',
      'UNKNOWN_CLAIM_TYPE',
      `${unknownClaimTypes} unknown claim_type${unknownClaimTypes === 1 ? '' : 's'} skipped (--ignore-unknown)`,
    );
  } else if (unknownClaimTypes === 0 && claimTypesInPack.size > 0) {
    pass('unknown-claim-type', `${claimTypesInPack.size} claim types, all schemas inline`);
  }

  // ── 10. Audit chain anchor head signature ───────────────────────
  const headBytes = Buffer.from(
    canonicalize({
      head_hash: pack.audit_chain_anchor.head_hash,
      head_at_ms: pack.audit_chain_anchor.head_at_ms,
    }),
    'utf8',
  );
  // Legacy deployment packs can use either the operator key or the
  // STACK system key for this detached signature.
  const anchorJwks = [
    ...(manifest.verification_material.operator_jwks_inline?.keys ?? []),
    ...(manifest.verification_material.stack_system_jwks_inline?.keys ?? []),
  ] as JwkLike[];
  if (anchorJwks.length === 0) {
    fail('audit-chain-anchor', 'NO_ANCHOR_JWK', 'no inline JWK can verify the audit anchor');
  } else {
    const anchorVerify = await verifyDetachedWithJwks(
      headBytes,
      pack.audit_chain_anchor.head_signature,
      anchorJwks,
    );
    if (anchorVerify.valid) {
      pass(
        'audit-chain-anchor',
        `head_hash=${pack.audit_chain_anchor.head_hash.slice(0, 16)}…, at=${new Date(pack.audit_chain_anchor.head_at_ms).toISOString()}`,
      );
    } else {
      fail('audit-chain-anchor', 'ANCHOR_SIG_INVALID', anchorVerify.error ?? 'unknown');
    }
  }

  // ── 11. External chain anchors ──────────────────────────────────
  const externalAnchorsVerified = 0;
  if ((pack.external_chain_anchors ?? []).length === 0) {
    warn(
      'external-anchor',
      'EXTERNAL_ANCHORS_MISSING',
      'The Signed record contains no external chain anchor.',
    );
  }
  for (const anchor of pack.external_chain_anchors ?? []) {
    if (anchor.permalink.startsWith('noop://')) {
      // Noop publisher — synthetic permalink, not externally verifiable.
      warn(
        'external-anchor',
        'NOOP_ANCHOR',
        `${anchor.permalink} is a noop publisher anchor (substrate-only); ` +
          `treat as 'anchor not externally verifiable' until production publisher wires the GitHub commit`,
      );
      continue;
    }
    if (options.airGap) {
      skip('external-anchor', `${anchor.permalink} (air-gap; fetch deferred)`);
      continue;
    }
    // Network fetch path. Production verifier fetches the raw JSON,
    // compares `anchored_chain_head_hash`. For v1, we skip the actual
    // fetch and warn — the protocol surface ships, the fetch logic
    // is a small follow-up.
    skip(
      'external-anchor',
      `${anchor.permalink} (network fetch not implemented; internal checks only)`,
    );
  }

  // ── Revocation snapshot count (informational) ──
  const revokedAtExport = manifest.claims.filter((c) => c.revoked_at_ms !== null).length;
  pass(
    'revocation-snapshot',
    `${revokedAtExport} of ${manifest.claims.length} claims marked revoked at export time`,
  );

  let activity: VerifyResult['activity'];
  if (options.activity || options.replay) {
    const activityClaims: ReconstructClaimInput[] = decodedManifestClaims
      .filter((claim): claim is DecodedManifestClaim & {
        claim_type: string;
        issued_at_ms: number;
        payload: Record<string, unknown>;
      } => claim.claim_type !== null && claim.issued_at_ms !== null && claim.payload !== null)
      .map((claim) => ({
        type: claim.claim_type,
        body: claim.payload,
        issued_at_ms: claim.issued_at_ms,
        claim_id: claim.claim_id ?? null,
        claim_hash: claim.claim_hash,
      }));
    activity =
      errors.length === 0 &&
      pack.scope.kind === 'mission' &&
      expectedOperatorId !== null
        ? reconstructActivity(pack.scope.ref, expectedOperatorId, activityClaims)
        : null;
  }

  return finalise({
    pack_id: pack.pack_id,
    scope: pack.scope,
    claim_count: pack.claim_count,
    timespan: [pack.time_bounds.t0_ms, pack.time_bounds.t1_ms],
    revoked_at_export: revokedAtExport,
    unknown_claim_types: unknownClaimTypes,
    external_anchors_verified: externalAnchorsVerified,
    checks,
    errors,
    warnings,
    ...((options.activity || options.replay) ? { activity: activity ?? null } : {}),
  });
}

// ─── Helpers ────────────────────────────────────────────────────────

function verifyReviewRelationships(
  pack: EvidencePackClaim,
  operatorId: string | null,
  claims: readonly DecodedManifestClaim[],
): string[] {
  if (claims.some((claim) => claim.claim_id === undefined) || pack.scope.kind !== 'mission') return [];

  const errors: string[] = [];
  const missionId = pack.scope.ref;
  const byId = new Map(claims.map((claim) => [claim.claim_id!, claim]));
  const hasMission = (claim: DecodedManifestClaim | undefined): boolean =>
    claim?.payload?.['mission_ref'] === missionId ||
    (claim?.claim_type === 'mission' && claim.payload?.['mission_id'] === missionId);

  const resolve = (
    ref: unknown,
    expectedType: string | readonly string[],
    label: string,
  ): DecodedManifestClaim | undefined => {
    if (typeof ref !== 'string') {
      errors.push(`${label} is not an exact claim id`);
      return undefined;
    }
    const source = byId.get(ref);
    const expectedTypes = typeof expectedType === 'string' ? [expectedType] : expectedType;
    if (!source || !source.claim_type || !expectedTypes.includes(source.claim_type)) {
      errors.push(`${label} ${ref} does not resolve to ${expectedTypes.join(' or ')}`);
      return undefined;
    }
    if (!hasMission(source)) {
      errors.push(`${label} ${ref} does not belong to mission ${missionId}`);
      return undefined;
    }
    return source;
  };

  for (const claim of claims) {
    const payload = claim.payload;
    if (!payload) continue;
    if (claim.claim_type === 'operator_decision') {
      if (!hasMission(claim) || (operatorId && payload['operator_id'] !== operatorId)) {
        errors.push(`operator decision ${claim.claim_id} has the wrong mission or operator`);
      }
      const sourceRefs = payload['source_refs'];
      const action = typeof payload['action'] === 'string' ? payload['action'] : '';
      const policy: Record<string, {
        effect: string;
        scope: 'mission' | 'agent_global';
        sources: 'checkout' | 'security' | 'governance';
      }> = {
        checkout_approved: { effect: 'checkout_released', scope: 'mission', sources: 'checkout' },
        checkout_blocked: { effect: 'checkout_blocked_and_agent_blocked', scope: 'agent_global', sources: 'checkout' },
        security_events_dismissed: { effect: 'security_events_resolved', scope: 'mission', sources: 'security' },
        agent_suspended: { effect: 'agent_suspended_and_events_resolved', scope: 'agent_global', sources: 'security' },
        future_warning_block_enabled: {
          effect: 'checkouts_released_and_agent_warning_policy_set_to_block',
          scope: 'agent_global',
          sources: 'checkout',
        },
        future_critical_block_enabled: {
          effect: 'checkouts_released_and_agent_critical_policy_set_to_block',
          scope: 'agent_global',
          sources: 'checkout',
        },
        governance_approved: { effect: 'governance_approval_approved', scope: 'mission', sources: 'governance' },
        governance_rejected: { effect: 'governance_approval_rejected', scope: 'mission', sources: 'governance' },
      };
      const expected = policy[action];
      if (!expected) {
        errors.push(`operator decision ${claim.claim_id} has an unknown action`);
      } else {
        if (payload['effect'] !== expected.effect) {
          errors.push(`operator decision ${claim.claim_id} effect does not match its action`);
        }
        if (payload['effect_scope'] !== expected.scope) {
          errors.push(`operator decision ${claim.claim_id} scope does not match its action`);
        }
        if (typeof payload['target_agent_id'] !== 'string' || payload['target_agent_id'].length === 0) {
          errors.push(`operator decision ${claim.claim_id} has no exact target agent`);
        }
      }
      if (sourceRefs && typeof sourceRefs === 'object' && !Array.isArray(sourceRefs)) {
        const refs = sourceRefs as Record<string, unknown>;
        const checkoutIds = Array.isArray(refs['checkout_ids']) ? refs['checkout_ids'] : [];
        const securityEventIds = Array.isArray(refs['security_event_ids']) ? refs['security_event_ids'] : [];
        const detectorIds = Array.isArray(refs['detector_claim_ids']) ? refs['detector_claim_ids'] : [];
        const approvalIds = Array.isArray(refs['approval_ids']) ? refs['approval_ids'] : [];
        const validSourceShape = expected?.sources === 'checkout'
          ? checkoutIds.length > 0 && securityEventIds.length === 0 && detectorIds.length === 0 && approvalIds.length === 0
          : expected?.sources === 'security'
            ? checkoutIds.length === 0 && securityEventIds.length > 0 && detectorIds.length === securityEventIds.length && approvalIds.length === 0
            : expected?.sources === 'governance'
              ? checkoutIds.length === 0 && securityEventIds.length === 0 && detectorIds.length === 0 && approvalIds.length === 1
              : false;
        if (!validSourceShape) {
          errors.push(`operator decision ${claim.claim_id} sources do not match its action`);
        }
        if (Array.isArray(detectorIds)) {
          for (const detectorId of detectorIds) resolve(detectorId, 'detector_signal', 'decision detector');
        }
      } else {
        errors.push(`operator decision ${claim.claim_id} has no exact source references`);
      }
      continue;
    }
    if (claim.claim_type === 'operator_review') {
      if (!hasMission(claim) || (operatorId && payload['operator_id'] !== operatorId)) {
        errors.push(`operator review ${claim.claim_id} has the wrong mission or operator`);
      }
      const checkpointNotes = payload['checkpoint_notes'];
      if (Array.isArray(checkpointNotes)) {
        for (const note of checkpointNotes) {
          if (note && typeof note === 'object') {
            resolve((note as { checkpoint_claim_id?: unknown }).checkpoint_claim_id, 'checkpoint_approval', 'review checkpoint');
          }
        }
      }
      const rationales = payload['decision_rationales'];
      if (Array.isArray(rationales)) {
        for (const rationale of rationales) {
          if (rationale && typeof rationale === 'object') {
            resolve((rationale as { operator_decision_claim_id?: unknown }).operator_decision_claim_id, 'operator_decision', 'review decision');
          }
        }
      }
      const explanations = payload['alert_explanations'];
      if (Array.isArray(explanations)) {
        for (const explanation of explanations) {
          if (explanation && typeof explanation === 'object') {
            resolve((explanation as { detector_claim_id?: unknown }).detector_claim_id, 'detector_signal', 'review detector');
          }
        }
      }
      if (payload['prior_review_ref'] !== null && payload['prior_review_ref'] !== undefined) {
        resolve(payload['prior_review_ref'], ['operator_review', 'dossier'], 'prior review');
      }
      continue;
    }
    if (claim.claim_type === 'dossier') {
      if (!hasMission(claim)) errors.push(`dossier ${claim.claim_id} has the wrong mission`);
      const decisions = payload['decision_tree'];
      if (Array.isArray(decisions)) {
        for (const decision of decisions) {
          const checkpointId = decision && typeof decision === 'object'
            ? (decision as { checkpoint_id?: unknown }).checkpoint_id
            : undefined;
          const source = claims.find((candidate) =>
            candidate.claim_type === 'checkpoint_approval' &&
            candidate.payload?.['checkpoint_id'] === checkpointId &&
            hasMission(candidate));
          if (!source) errors.push(`dossier checkpoint ${String(checkpointId)} does not resolve inside the mission`);
        }
      }
      const alerts = payload['alerts_walkthrough'];
      if (Array.isArray(alerts)) {
        for (const alert of alerts) {
          if (!alert || typeof alert !== 'object') continue;
          const entry = alert as { detector_signal_claim_id?: unknown; severity?: unknown };
          const source = resolve(entry.detector_signal_claim_id, 'detector_signal', 'dossier detector');
          if (source && source.payload?.['severity'] !== entry.severity) {
            errors.push(`dossier detector ${String(entry.detector_signal_claim_id)} severity does not match`);
          }
        }
      }
      if (payload['prior_dossier_ref'] !== null && payload['prior_dossier_ref'] !== undefined) {
        resolve(payload['prior_dossier_ref'], ['dossier', 'operator_review'], 'prior dossier');
      }
    }
  }

  return errors;
}

function makeJwksResolver(
  jwks: { keys: Array<Record<string, unknown>> } | undefined,
  options: VerifyOptions,
): (kid: string) => Promise<readonly JwkLike[] | null> {
  return async (kid: string) => {
    if (jwks?.keys) {
      const matches = jwks.keys.filter((k) => (k as { kid?: string }).kid === kid);
      if (matches.length > 0) return matches as JwkLike[];
    }
    if (options.airGap) {
      return null;
    }
    // v1 does not fetch JWKS from the URL — the producer always
    // emits inline JWKS for the head + operator keys, so missing
    // inline is itself a fail-closed condition. --fresh-jwks is
    // reserved here for a follow-up that adds the fetch path.
    return null;
  };
}

async function verifyCoseWithResolvers(
  decoded: ReturnType<typeof decodeCoseSign1>,
  resolvers: ReadonlyArray<
    (kid: string) => Promise<JwkLike | readonly JwkLike[] | null>
  >,
): Promise<{ valid: boolean; error?: string }> {
  const failures: string[] = [];
  for (const resolveJwk of resolvers) {
    const result = await verifyCoseSign1(decoded, { resolveJwk });
    if (result.valid) return result;
    if (result.error?.startsWith('ambiguous signature verification:')) return result;
    if (result.error) failures.push(result.error);
  }
  return {
    valid: false,
    error: failures.length > 0
      ? [...new Set(failures)].join('; ')
      : 'signature verification failed',
  };
}

async function verifyDetachedWithJwks(
  data: Buffer,
  signatureBase64Url: string,
  jwks: readonly JwkLike[],
): Promise<{ valid: boolean; error?: string }> {
  const failures: string[] = [];
  for (const jwk of jwks) {
    const result = await verifyDetachedEd25519(data, signatureBase64Url, jwk);
    if (result.valid) return result;
    if (result.error) failures.push(result.error);
  }
  return {
    valid: false,
    error: failures.length > 0
      ? [...new Set(failures)].join('; ')
      : 'no inline JWK can verify the audit anchor',
  };
}

function finalise(
  partial: Omit<VerifyResult, 'valid' | 'complete'>,
): VerifyResult {
  const valid = partial.errors.length === 0;
  const complete = valid && partial.checks.every((check) => check.outcome === 'pass');
  return { ...partial, valid, complete };
}
