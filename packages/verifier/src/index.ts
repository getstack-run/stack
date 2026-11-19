// @getstackrun/verify — offline evidence-pack verifier.
//
// Public API:
//
//   import { verifyPack } from '@getstackrun/verify';
//   const result = await verifyPack(manifest, { airGap: true });
//   if (!result.valid) console.error(result.errors);
//
// CLI:
//
//   npx @getstackrun/verify pack.json
//   npx @getstackrun/verify pack.json --air-gap --strict --json
//
// Part of the Signed Primitive epic. See
// the evidence pack design (5.4.0 ADR) for the threat
// model + verification rules this package enforces.

export { verifyPack } from './verify.js';
export {
  decodeCoseSign1,
  verifyCoseSign1,
  verifyDetachedEd25519,
  type JwkLike,
  type CoseDecodeResult,
} from './cose.js';
export { canonicalize } from './canonicalize.js';
export { computeMerkleRoot } from './merkle.js';
export { reconstructTimeline as reconstructActivity } from './activity.js';
export type {
  EvidencePackManifest,
  EvidencePackClaim,
  AuditChainAnchor,
  ExternalChainAnchorRef,
  CoSignature,
  InlineJwks,
  ManifestClaimEntry,
  ManifestAuditChainProof,
  ManifestVerificationMaterial,
  ManifestInlineSchemaEntry,
  VerifyResult,
  VerifyCheck,
  VerifyCheckOutcome,
  VerifyOptions,
  ReconstructClaimInput,
  ReplayedEvent,
  ReplayedEventKind,
  ReplayedTimeline,
} from './types.js';
