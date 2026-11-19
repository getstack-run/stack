export type {
  IdentityVerificationProvider,
  VerificationContext,
  InitiateResult,
  VerificationResult,
  VerifiedClaim,
  ServiceRequirementRecord,
  ClaimMatchResult,
  ClaimMatch,
  WorkloadIdentityProvider,
  WorkloadProviderConfig,
  WorkloadAcceptResult,
} from './types.js';
export { IdentityProviderRegistry } from './provider-registry.js';
export { ClaimMatchingService } from './claim-matching.js';
export { IdentityVerificationService } from './identity-verification-service.js';
export { IdentityRepository } from './identity-repo.js';
// SPIFFE consumer (workload identity, P1.3+)
export {
  SpiffeSvidValidator,
  SpiffeValidationError,
  type SpiffeValidationCode,
  type SvidValidationResult,
  type TrustDomainConfig,
  type JwksPersistor,
  type FetchFn,
} from './spiffe-svid-validator.js';
export { WorkloadProviderRegistry } from './workload-provider-registry.js';
export { SpiffeWorkloadProvider } from './providers/spiffe.js';

// WIMSE consumer (Part of the Signed Primitive epic)
export {
  WimseWitValidator,
  WimseValidationError,
  type WimseValidationCode,
  type WitValidationResult,
  type WimseIssuerConfig,
  type WimseJwksPersistor,
} from './wimse-wit-validator.js';
export { WimseWorkloadProvider, type WimseAcceptResult } from './providers/wimse.js';

// OIDC IdP federation (Part of the Signed Primitive epic)
export {
  OidcIdpProvider,
  type OidcFetchFn,
  type OidcTokenResponse,
  type VerifiedOidcAuthorityEvidence,
} from './providers/oidc-idp.js';
export {
  EnterpriseOidcAuthorityAdapter,
  ENTERPRISE_OIDC_AUTHORITY_ADAPTER_KEY,
  ENTERPRISE_OIDC_AUTHORITY_ADAPTER_VERSION,
  type EnterpriseOidcAuthoritySigner,
  type EnterpriseOidcAuthorityVerifier,
} from './providers/enterprise-oidc-authority.js';
export {
  StackIdentityAuthorityAdapter,
  STACK_IDENTITY_AUTHORITY_ADAPTER_KEY,
  STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION,
  type StackIdentityAuthoritySigner,
} from './providers/stack-identity-authority.js';
