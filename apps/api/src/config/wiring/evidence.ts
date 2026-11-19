import { deployment, type Database } from '@stack/shared';
import {
  DossierService,
  OperatorDecisionRepository,
  OperatorDecisionService,
  OperatorReviewRepository,
  OperatorReviewService,
  ReplayService,
  EvidencePackService,
  EvidencePackArtifactRepository,
  ExternalAnchorRepository,
  ExternalAnchorService,
  NoopAnchorPublisher,
  dedupePublicJwksByThumbprint,
  type AuditService,
  type ClaimRegistryService,
  type MissionRepository,
  type ObjectStore,
  type OperatorDecisionServiceDeps,
  type OperatorSigningKeyService,
  type PassportService,
} from '@stack/vault';
import type { ClaimSigning, DeploymentSigningConfig } from './crypto-and-signing.js';
import type { CoreRepositories } from './repositories.js';
import { resolveInlineSchemas } from './schemas-bundle.js';

export interface EvidenceServices {
  /** Mission-scoped post-mortem narrative CRUD surface. */
  dossier: DossierService;
  operatorDecision: OperatorDecisionService;
  operatorReview: OperatorReviewService;
  /**
   * Forensic timeline reconstruction over a mission's signed claim set. The
   * live DB path and the open-source verifier share one helper in
   * @stack/shared, so the dashboard and the verifier produce identical output.
   */
  replay: ReplayService;
  /**
   * Read side of the external chain anchors. The daily-cron WRITE path lives in
   * the worker, so the API never publishes anchors itself.
   */
  externalAnchor: ExternalAnchorService;
  /** Signed, co-signed evidence-pack export (POST /v1/evidence-packs). */
  evidencePack: EvidencePackService;
}

/**
 * Dossiers, operator decisions and reviews, replay, and evidence-pack export.
 *
 * The evidence pack reuses the claim-registry signer resolver so
 * head_signature on audit_chain_anchor verifies against the same JWKS endpoint
 * as the pack claim's primary signature. The deployment signer co-signs the
 * pack under signer_role='operator_attestation' for the two-party-attestation
 * property. Inline JWKS come from the operator signing keys and the deployment
 * public JWK; the JWKS URLs are reference-only (verifiers prefer the inline
 * copy).
 */
export function createEvidenceServices(deps: {
  db: Database;
  repos: Pick<CoreRepositories, 'passportClaimsRepo' | 'memberRepo'>;
  missionRepo: MissionRepository;
  claimRegistry: ClaimRegistryService;
  claimSigning: Pick<
    ClaimSigning,
    'signerPublicJwk' | 'deploymentClaimSigner' | 'operatorSigningKey' | 'operatorSignerResolver'
  >;
  deploymentSigningConfig: DeploymentSigningConfig;
  audit: AuditService;
  passport: PassportService;
  auditObjectStore: ObjectStore;
  /** Told after a governance approval is decided (a held action's review follows its decision at once). */
  onGovernanceDecided?: OperatorDecisionServiceDeps['onGovernanceDecided'];
}): EvidenceServices {
  const { db, repos, missionRepo, claimRegistry, claimSigning, deploymentSigningConfig, audit, passport, auditObjectStore } =
    deps;
  const { passportClaimsRepo, memberRepo } = repos;
  const { signerPublicJwk, deploymentClaimSigner, operatorSigningKey, operatorSignerResolver } =
    claimSigning;

  const dossier = new DossierService({
    claimRegistry,
    missionRepo,
    passportClaimsRepo,
    memberRepo,
  });

  const operatorDecisionRepo = new OperatorDecisionRepository(db);
  const operatorReviewRepo = new OperatorReviewRepository(db);
  const operatorDecision = new OperatorDecisionService({
    repo: operatorDecisionRepo,
    claimRegistry,
    claimVerifier: claimRegistry,
    audit,
    passportRevocation: passport,
    ...(deps.onGovernanceDecided ? { onGovernanceDecided: deps.onGovernanceDecided } : {}),
  });
  const operatorReview = new OperatorReviewService({
    claimRegistry,
    claimVerifier: claimRegistry,
    missionRepo,
    memberRepo,
    passportClaimsRepo,
    reviewRepo: operatorReviewRepo,
    audit,
  });

  const replay = new ReplayService({
    passportClaimsRepo,
    claimVerifier: claimRegistry,
    missionRepo,
  });

  // Read-side wiring so EvidencePackService.export can call
  // getAnchorAtOrBefore at pack-build time. The publisher is the noop (the API
  // never publishes anchors).
  const externalAnchorRepo = new ExternalAnchorRepository(db);
  const externalAnchor = new ExternalAnchorService({
    anchorRepo: externalAnchorRepo,
    auditService: audit,
    operatorSignerResolver,
    publisher: new NoopAnchorPublisher(),
  });

  // Reference-only base URL for the inline JWKS URLs in pack manifests.
  // Verifier prefers inline JWKS; the URL is informational.
  const apiBaseUrl = deployment().apiBaseUrl;
  const evidencePackArtifactRepo = new EvidencePackArtifactRepository(db);
  const evidencePack = new EvidencePackService({
    claimRegistry,
    passportClaimsRepo,
    missionRepo,
    auditService: audit,
    operatorSignerResolver,
    stackSystemSigner: deploymentClaimSigner,
    getOperatorJwks: createOperatorJwksResolver(operatorSigningKey),
    getStackSystemJwks: async () => ({
      keys: dedupePublicJwksByThumbprint([
        signerPublicJwk,
        ...deploymentSigningConfig.trustedHistoricalPublicJwks,
      ]).map((jwk) => jwk as unknown as Record<string, unknown>),
    }),
    getOperatorJwksUrl: (operatorId: string) =>
      `${apiBaseUrl}/v1/operators/${operatorId}/jwks.json`,
    stackSystemJwksUrl: `${apiBaseUrl}/v1/.well-known/jwks.json`,
    canonicalSchemaBaseUrl: 'https://getstack.run/schemas/passport-claims/v1/',
    getInlineSchemas: resolveInlineSchemas,
    externalAnchor,
    artifactRepo: evidencePackArtifactRepo,
    objectStore: auditObjectStore,
  });

  return { dossier, operatorDecision, operatorReview, replay, externalAnchor, evidencePack };
}

function createOperatorJwksResolver(operatorSigningKey: OperatorSigningKeyService) {
  return async (operatorId: string) => {
    const jwks = await operatorSigningKey.getPublicJwksForOperator(operatorId);
    // Wrap each JWK as a plain record — the manifest schema uses
    // `Record<string, unknown>` for individual key entries.
    return {
      keys: jwks.map((j) => j as unknown as Record<string, unknown>),
    };
  };
}
