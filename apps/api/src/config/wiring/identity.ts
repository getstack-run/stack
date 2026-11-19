import type { Database } from '@stack/shared';
import {
  IdentityProviderRegistry,
  IdentityVerificationService,
  ClaimMatchingService,
  SpiffeSvidValidator,
  SpiffeWorkloadProvider,
  WorkloadProviderRegistry,
  SpiffeTrustDomainRepository,
  WimseWitValidator,
  WimseWorkloadProvider,
  WimseIssuerRepository,
  OidcIdpProvider,
  OidcIdpConfigRepository,
  SsoDomainRepository,
  SsoDomainService,
  systemDnsTxtResolver,
  type AuditService,
  type ClaimRegistryService,
  type DnsTxtResolver,
  type KmsService,
} from '@stack/vault';
import { env } from '../env.js';
import type { CoreRepositories } from './repositories.js';
import type { RedisClient } from './infra.js';

export interface IdentityCore {
  providerRegistry: IdentityProviderRegistry;
  claimMatcher: ClaimMatchingService;
  identity: IdentityVerificationService;
  workloadProviderRegistry: WorkloadProviderRegistry;
  spiffeValidator: SpiffeSvidValidator;
  spiffeTrustDomainRepo: SpiffeTrustDomainRepository;
  wimseValidator: WimseWitValidator;
  wimseWorkloadProvider: WimseWorkloadProvider;
  wimseIssuerRepo: WimseIssuerRepository;
  oidcIdpConfigRepo: OidcIdpConfigRepository;
  oidcIdpProvider: OidcIdpProvider;
  /** The e-mail domains an account has proved for its single sign-on (DNS TXT records). */
  ssoDomains: SsoDomainService;
}

/**
 * Identity verification and the workload-identity registries (SPIFFE, WIMSE,
 * OIDC federation). Real vendor providers register later, once vault
 * credentials are bootstrapped; see registerIdentityProviders.
 */
export function createIdentityCore(deps: {
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  repos: Pick<CoreRepositories, 'identityRepo' | 'operatorRepo'>;
  claimRegistry: ClaimRegistryService;
  audit: Pick<AuditService, 'write'>;
  /** Where DNS records are read from; the machine's resolver (or `SSO_DNS_SERVERS`) when omitted. */
  dnsTxtResolver?: DnsTxtResolver;
}): IdentityCore {
  const { db, redis, kms, repos, claimRegistry, audit } = deps;
  // Identity provider registry — pluggable. Real providers register after
  // bootstrap (vault-first credentials). The opt-in simulated providers register
  // after all of them, so they never shadow a real one.
  const providerRegistry = new IdentityProviderRegistry();

  const claimMatcher = new ClaimMatchingService();
  const identity = new IdentityVerificationService(db, providerRegistry, repos.identityRepo, kms);

  identity.setOperatorRepo(repos.operatorRepo);
  // Complete, completeWithToken and grantDelegation dual-write an
  // operator-scoped identity_claim envelope. PII never enters the envelope
  // (assertion_hash only).
  identity.setClaimRegistryService(claimRegistry);

  // ── Workload-identity registry (SPIFFE consumer) ───
  // The validator's fail-open path persists last-known-good JWKS to the
  // spiffe_trust_domains row via the trust-domain repo's JwksPersistor
  // implementation. Persistor failures are non-fatal (validator wraps
  // the call in try/catch + logs a warn) — Redis cache stays authoritative.
  const spiffeTrustDomainRepo = new SpiffeTrustDomainRepository(db);
  const spiffeValidator = new SpiffeSvidValidator(redis, spiffeTrustDomainRepo);
  const workloadProviderRegistry = new WorkloadProviderRegistry();
  workloadProviderRegistry.register(new SpiffeWorkloadProvider(spiffeValidator));

  // WIMSE consumer. Standalone — not registered through workloadProviderRegistry
  // because the SPIFFE-shaped interface doesn't fit the WIT shape cleanly.
  // Same dual-role repo pattern as SpiffeTrustDomainRepository.
  const wimseIssuerRepo = new WimseIssuerRepository(db);
  const wimseValidator = new WimseWitValidator(redis, wimseIssuerRepo);
  const wimseWorkloadProvider = new WimseWorkloadProvider(wimseValidator);

  // OIDC IdP federation. Single provider class registered with the
  // identity-provider registry; the provider looks up the per-operator
  // oidc_idp_configs row at initiate-time so one class serves all operators'
  // federated IdPs.
  // The provider guards every outbound call with assertPublicUrl by
  // default — issuer_uri is operator-supplied, and token_endpoint
  // / jwks_uri come from a discovery document whose host the operator
  // chose. In dev ONLY, swap in a parse-only guard so the local test-IdP
  // harness (http://localhost) works; production always gets the real one.
  const oidcIdpConfigRepo = new OidcIdpConfigRepository(db);
  const oidcUrlGuard = env.isDev
    ? (url: string) => {
        new URL(url);
      }
    : undefined;
  if (env.isDev) {
    console.warn('[SECURITY] Dev mode relaxes the OIDC outbound SSRF guard:', 'this is for the local test IdP.');
  }
  const oidcIdpProvider = new OidcIdpProvider(
    redis,
    oidcIdpConfigRepo,
    kms,
    undefined,
    env.DASHBOARD_URL,
    oidcUrlGuard,
  );
  providerRegistry.register(oidcIdpProvider);

  // Verified e-mail domains for single sign-on: an address at a domain the account proved with a DNS record counts as
  // verified for a first sign-in when the provider's ID token does not say (spec/sso-login/SPEC.md section 9.5).
  const dnsServers = env.SSO_DNS_SERVERS.split(',').map((address) => address.trim()).filter((address) => address.length > 0);
  const ssoDomains = new SsoDomainService(
    new SsoDomainRepository(db),
    deps.dnsTxtResolver ?? systemDnsTxtResolver({ servers: dnsServers }),
    audit,
  );

  return {
    providerRegistry,
    claimMatcher,
    identity,
    workloadProviderRegistry,
    spiffeValidator,
    spiffeTrustDomainRepo,
    wimseValidator,
    wimseWorkloadProvider,
    wimseIssuerRepo,
    oidcIdpConfigRepo,
    oidcIdpProvider,
    ssoDomains,
  };
}
