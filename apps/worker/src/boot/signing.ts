import { deployment } from '@stack/shared';
import {
  ClaimRegistryService,
  ClaimSigner,
  OperatorSigningKeyRepository,
  OperatorSigningKeyService,
  PassportSigner,
  deploymentJwkCandidates,
  readDeploymentSigningConfig,
  resolveSigningKeyPem,
  type DeploymentPublicJwk,
  type KmsService,
  type PassportClaimsRepository,
} from '@stack/vault';
import type { WorkerDb, WorkerRedis } from '../redis.js';

/**
 * Claim signing for the worker. Mirrors the API's `services.ts` wire-up,
 * condensed: the worker only needs the write-side signer
 * (not the public JWKS resolver path, which is read-side and only matters at
 * verify time, which the worker never does).
 *
 * The deployment signing key comes from `SESSION_SIGNING_KEY_WRAPPED` (KMS
 * envelope) or `SESSION_SIGNING_KEY`; production refuses to boot without one.
 */
export async function buildClaimSigning(deps: {
  db: WorkerDb;
  redis: WorkerRedis;
  kms: KmsService;
  passportClaimsRepo: PassportClaimsRepository;
  stackSystemOperatorId: string;
}) {
  const { db, redis, kms, passportClaimsRepo, stackSystemOperatorId } = deps;
  const operatorSigningKeyRepoWorker = new OperatorSigningKeyRepository(db);
  const deploymentSigningConfig = readDeploymentSigningConfig(process.env);
  const deploymentSigner = new PassportSigner({ kid: deploymentSigningConfig.kid });
  const deploymentSigningPem = await resolveSigningKeyPem({
    wrapped: process.env['SESSION_SIGNING_KEY_WRAPPED'],
    file: process.env['SESSION_SIGNING_KEY_FILE'],
    plaintext: process.env['SESSION_SIGNING_KEY'],
    kms,
    systemOperatorId: stackSystemOperatorId,
    allowFile: deployment().selfManaged,
  });
  if (deploymentSigningPem === undefined && process.env['NODE_ENV'] === 'production') {
    throw new Error(
      '[WORKER BOOT] Neither SESSION_SIGNING_KEY_WRAPPED nor SESSION_SIGNING_KEY set in prod. ' +
        'Mission auto-expiry claim emission cannot wire.',
    );
  }
  await deploymentSigner.init(deploymentSigningPem);
  const deploymentSignerPublicJwk = await deploymentSigner.getPublicJwk();
  const deploymentSignerKid = deploymentSignerPublicJwk.kid!;
  const deploymentSignerPrivateJwk = await deploymentSigner.getPrivateJwk();
  const deploymentClaimSigner = new ClaimSigner({
    privateKeyJwk: deploymentSignerPrivateJwk,
    kid: deploymentSignerKid,
  });
  const workerOperatorSigningKey = new OperatorSigningKeyService({
    repo: operatorSigningKeyRepoWorker,
    kms,
    systemOperatorId: stackSystemOperatorId,
    redis,
  });
  const workerPerOperatorSigningEnabled =
    process.env['PER_OPERATOR_CLAIM_SIGNING_ENABLED'] === 'true';
  // The system operator and (unless per-operator signing is on) every operator
  // sign with the deployment key. Claims and external anchors share this rule.
  const signerForOperator = async (operatorId: string) => {
    if (
      !workerPerOperatorSigningEnabled ||
      !stackSystemOperatorId ||
      operatorId === stackSystemOperatorId
    ) {
      return deploymentClaimSigner;
    }
    return workerOperatorSigningKey.getSigner(operatorId);
  };
  const workerClaimRegistry = new ClaimRegistryService({
    repo: passportClaimsRepo,
    signerForOperator,
    resolvePublicJwk: async (operatorId: string, kid: string) => {
      // Worker does not currently verify claims. Keep this resolver
      // identical to the API so a future read path cannot drift.
      if (kid.includes(':claim:')) {
        const jwks = await workerOperatorSigningKey.getPublicJwksForOperator(operatorId);
        const found = jwks.find((j) => j.kid === kid);
        return found ? [found as unknown as DeploymentPublicJwk] : [];
      }
      return deploymentJwkCandidates(
        kid,
        deploymentSignerPublicJwk as unknown as DeploymentPublicJwk,
        deploymentSigningConfig.trustedHistoricalPublicJwks,
      );
    },
  });
  return { claimRegistry: workerClaimRegistry, signerForOperator };
}
