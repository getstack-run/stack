import type { Database } from '@stack/shared';
import { deployment, safeErrorSummary } from '@stack/shared';
import {
  PassportSigner,
  ClaimSigner,
  ClaimRegistryService,
  OperatorSigningKeyRepository,
  OperatorSigningKeyService,
  SIGNING_KEY_ROTATED_CHANNEL,
  CmekService,
  CmekMigrationRepository,
  deploymentJwkCandidates,
  readDeploymentSigningConfig,
  resolveSigningKeyPem,
  type KmsService,
  type OperatorRepository,
  type PassportClaimsRepository,
} from '@stack/vault';
import * as Sentry from '@sentry/node';
import type { JWK } from 'jose';
import { env } from '../env.js';
import type { RedisClient } from './infra.js';

export type DeploymentSigningConfig = ReturnType<typeof readDeploymentSigningConfig>;

export interface PassportSigning {
  signer: PassportSigner;
  deploymentSigningConfig: DeploymentSigningConfig;
}

/**
 * Builds the passport signer. Boot path:
 *   1. SESSION_SIGNING_KEY_WRAPPED → kms.decryptDirect unwrap → PEM.
 *   2. SESSION_SIGNING_KEY (plaintext PEM, dev fallback).
 *   3. Hard-fail in prod; generate ephemeral keypair in dev.
 * Different machines generating independent ephemeral keys in prod would
 * produce a JWKS-vs-signature race; the prod hard-fail prevents that.
 */
export async function createPassportSigner(kms: KmsService): Promise<PassportSigning> {
  const deploymentSigningConfig = readDeploymentSigningConfig(env);
  const signer = new PassportSigner({ kid: deploymentSigningConfig.kid });
  const signingKeyPem = await resolveSigningKeyPem({
    wrapped: env.SESSION_SIGNING_KEY_WRAPPED,
    file: env.SESSION_SIGNING_KEY_FILE,
    plaintext: env.SESSION_SIGNING_KEY,
    kms,
    systemOperatorId: env.STACK_SYSTEM_OPERATOR_ID,
    allowFile: deployment().selfManaged,
  });
  if (signingKeyPem === undefined && !env.isDev) {
    throw new Error(
      '[BOOT] Neither SESSION_SIGNING_KEY_WRAPPED nor SESSION_SIGNING_KEY is set. ' +
        'Prod requires the KMS-wrapped key ' +
        '(a self-managed install can use SESSION_SIGNING_KEY_FILE).',
    );
  }
  await signer.init(signingKeyPem);
  return { signer, deploymentSigningConfig };
}

export interface ClaimSigning {
  /** Public JWK of the deployment signing key. */
  signerPublicJwk: Awaited<ReturnType<PassportSigner['getPublicJwk']>>;
  /** Key id of the deployment signing key. */
  signerKid: string;
  /** Signs claims under the deployment key. */
  deploymentClaimSigner: ClaimSigner;
  operatorSigningKey: OperatorSigningKeyService;
  /** Deployment signer for the system operator or when per-operator keys are off. */
  operatorSignerResolver: (operatorId: string) => Promise<ClaimSigner>;
  claimRegistry: ClaimRegistryService;
}

/**
 * The COSE_Sign1 envelope path for claims attached to passports. It shares the
 * signing key of PassportSigner (one cryptographic identity per STACK
 * deployment; one JWKS endpoint serves both passport JWTs and claim
 * envelopes). Non-system operators get their own EdDSA keypair, lazy-generated
 * on first claim and KMS-wrapped at rest with AAD
 * {operator_id, kid, purpose: 'claim_signing'}.
 */
export async function createClaimSigning(deps: {
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  signing: PassportSigning;
  passportClaimsRepo: PassportClaimsRepository;
}): Promise<ClaimSigning> {
  const { db, redis, kms, signing, passportClaimsRepo } = deps;
  const { signer, deploymentSigningConfig } = signing;
  const signerPublicJwk = await signer.getPublicJwk();
  const signerKid = signerPublicJwk.kid;
  if (!signerKid) {
    throw new Error('PassportSigner public JWK is missing the kid field; claim signer cannot wire');
  }
  const signerPrivateJwk = await signer.getPrivateJwk();
  const deploymentClaimSigner = new ClaimSigner({
    privateKeyJwk: signerPrivateJwk,
    kid: signerKid,
  });

  const operatorSigningKeyRepo = new OperatorSigningKeyRepository(db);
  const operatorSigningKey = new OperatorSigningKeyService({
    repo: operatorSigningKeyRepo,
    kms,
    systemOperatorId: env.STACK_SYSTEM_OPERATOR_ID,
    redis,
  });
  const perOperatorSigningEnabled = env.PER_OPERATOR_CLAIM_SIGNING_ENABLED === 'true';

  // Carve-out:
  //   1. Feature flag off → deployment signer (rollback path).
  //   2. System operator → deployment signer (no per-operator key).
  //   3. STACK_SYSTEM_OPERATOR_ID unset (dev/test) → deployment signer.
  const operatorSignerResolver = async (operatorId: string): Promise<ClaimSigner> => {
    if (
      !perOperatorSigningEnabled ||
      !env.STACK_SYSTEM_OPERATOR_ID ||
      operatorId === env.STACK_SYSTEM_OPERATOR_ID
    ) {
      return deploymentClaimSigner;
    }
    return operatorSigningKey.getSigner(operatorId);
  };

  const claimRegistry = new ClaimRegistryService({
    repo: passportClaimsRepo,
    signerForOperator: operatorSignerResolver,
    resolvePublicJwk: async (operatorId: string, kid: string) => {
      // Kid prefix routing:
      //   stack-passport-v* → deployment JWKS (passport tokens + system
      //                       claims + operator claims signed before per-operator keys).
      //   <op>:claim:v*     → per-operator JWKS.
      // The resolver is forward-deployed even when the factory flag is
      // off — historical operator-kid claims must keep verifying after
      // a flag flip-back (one-way door for the resolver).
      if (kid.includes(':claim:')) {
        const jwks = await operatorSigningKey.getPublicJwksForOperator(operatorId);
        const match = jwks.find((j) => j.kid === kid);
        return match ? [match as JWK] : [];
      }
      return deploymentJwkCandidates(
        kid,
        signerPublicJwk,
        deploymentSigningConfig.trustedHistoricalPublicJwks,
      );
    },
  });

  // Cross-machine cache eviction for per-operator signing-key rotation.
  // Subscriber listens on a dedicated Redis connection (redis.duplicate
  // mirrors the CMEK pattern below).
  const signingKeySubscriber = redis.duplicate();
  await signingKeySubscriber.subscribe(SIGNING_KEY_ROTATED_CHANNEL);
  signingKeySubscriber.on('message', (channel: string, message: string) => {
    if (channel === SIGNING_KEY_ROTATED_CHANNEL && message) {
      operatorSigningKey.evictSigner(message);
    }
  });

  return {
    signerPublicJwk,
    signerKid,
    deploymentClaimSigner,
    operatorSigningKey,
    operatorSignerResolver,
    claimRegistry,
  };
}

export interface Cmek {
  cmek: CmekService;
  cmekMigrationRepo: CmekMigrationRepository;
}

/**
 * Customer-Managed Encryption Keys. CmekService is wired after kms and
 * operatorRepo exist; the resolver is set on kms post-construction (late-wiring
 * pattern). The publish hook pushes operator_id onto the `stack:cmek-updated`
 * Redis channel so other API machines and the worker invalidate their
 * per-operator cache.
 */
export async function createCmek(deps: {
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  operatorRepo: OperatorRepository;
  /** Stores of ciphertext the deployment adds to the engine's (its skills), seeded with the rest. */
  extraStores?: readonly string[];
  /** Ephemeral stores the deployment adds (per-call rows), marked completed straight away. */
  extraEphemeralStores?: readonly string[];
}): Promise<Cmek> {
  const { db, redis, kms, operatorRepo, extraStores, extraEphemeralStores } = deps;
  const cmekMigrationRepo = new CmekMigrationRepository(db);
  const cmek = new CmekService({
    operatorRepo,
    migrationRepo: cmekMigrationRepo,
    kms,
    stackSystemOperatorId: env.STACK_SYSTEM_OPERATOR_ID,
    ...(extraStores ? { extraLongLivedStores: extraStores } : {}),
    ...(extraEphemeralStores ? { extraEphemeralStores } : {}),
    publishCmekUpdated: async (operatorId) => {
      try {
        await redis.publish('stack:cmek-updated', operatorId);
      } catch (err) {
        console.warn(
          '[CMEK] publish stack:cmek-updated failed non-fatal:',
          safeErrorSummary(err),
        );
      }
    },
  });
  // Wire the resolver into KmsService now that operatorRepo exists. The
  // resolver consults a small in-process cache (Redis-invalidated) so
  // encrypt/decrypt do not hit the DB on every call.
  const cmekResolverCache = new Map<
    string,
    {
      state: {
        keyArn: string | null;
        status: 'none' | 'migrating' | 'active' | 'revoking' | 'revoked';
      };
      expiresAt: number;
    }
  >();
  const CACHE_TTL_MS = 5 * 60 * 1000;
  kms.setOperatorKeyHandlers({
    resolve: async (operatorId: string) => {
      const hit = cmekResolverCache.get(operatorId);
      const now = Date.now();
      if (hit && hit.expiresAt > now) return hit.state;
      const state = await operatorRepo.getCmekState(operatorId);
      cmekResolverCache.set(operatorId, { state, expiresAt: now + CACHE_TTL_MS });
      return state;
    },
    // Evict on KMS AccessDenied (customer revoked our IAM grant) BEFORE the
    // CmekRevokedError surfaces, so the next request on this machine refetches
    // the operator's status instead of routing to the same revoked key.
    evict: (operatorId: string) => {
      cmekResolverCache.delete(operatorId);
    },
    // Sentry breadcrumb when decryptDirect redeems a legacy row via
    // the no-context fallback. We want this rate to trend toward zero as the
    // worker drains old rows; new rows hitting this path is a forward-only
    // AAD-rule violation.
    onLegacyFallback: (info) => {
      Sentry.addBreadcrumb({
        category: 'kms.legacy-fallback',
        message: 'decryptDirect succeeded without context after context-mismatch',
        level: 'info',
        data: info,
      });
    },
  });
  // Invalidate cache on pub/sub. Each API machine + the worker subscribes
  // and drops its local cache for the named operator on the next request.
  const cmekSubscriber = redis.duplicate();
  await cmekSubscriber.subscribe('stack:cmek-updated');
  cmekSubscriber.on('message', (channel: string, message: string) => {
    if (channel === 'stack:cmek-updated' && message) {
      cmekResolverCache.delete(message);
    }
  });
  return { cmek, cmekMigrationRepo };
}
