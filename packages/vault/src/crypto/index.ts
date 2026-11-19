export { KmsService, type KmsConfig } from './kms.js';
export type { EncryptionContext, KeyFailure, KeyProvider } from './key-provider.js';
export { AwsKeyProvider, parseKmsRegion } from './aws-key-provider.js';
export { resolveSigningKeyPem, type SigningKeySourceInput } from './signing-key-source.js';
export {
  LOCAL_DEFAULT_KEY_ID,
  keyProviderEnvFrom,
  selectKeyProvider,
  type KeyProviderEnv,
  type KeyProviderSelection,
} from './key-provider-config.js';
export {
  LocalKeyProvider,
  LocalKeyError,
  loadLocalKeys,
  parseKeyEncryptionKey,
  parseKeyList,
  type LocalKeySource,
} from './local-key-provider.js';
export {
  PassportSigner,
  type PassportPayload,
  type SignedPassport,
  type ProviderOAuthStateClaims,
  type DriveLinkClaims,
} from './passport-signer.js';
export {
  ClaimSigner,
  type ClaimSignAlg,
  type ClaimSignerOptions,
  type ClaimVerifyResult,
  type ClaimJwksResolver,
} from './claim-signer.js';
export {
  LEGACY_DEPLOYMENT_SIGNING_KID,
  MAX_TRUSTED_HISTORICAL_DEPLOYMENT_KEYS,
  dedupePublicJwksByThumbprint,
  deploymentJwkCandidates,
  parseTrustedDeploymentJwks,
  publicJwkThumbprint,
  readDeploymentSigningConfig,
  validateDeploymentSigningKid,
  type DeploymentSigningConfig,
  type DeploymentPublicJwk,
} from './deployment-signing-config.js';
export {
  AgentSigner,
  AgentNotFoundError,
  AgentSignerCustomerManagedError,
  AgentSignerNotCustomerManagedError,
  AgentSignerNoPubkeyError,
  bundleCoSignatures,
  type AgentSignerDeps,
} from './agent-signer.js';
