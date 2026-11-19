import { deployment, staging, type Database } from '@stack/shared';
import {
  ServiceConnectionService,
  ConnectionVerifierService,
  OauthAppRepository,
  OauthAppService,
  ProxyService,
  ProxyOperationRepository,
  ProxyOperationService,
  ProxyPostResponseService,
  type AuditService,
  type AuthorityService,
  type ClaimRegistryService,
  type EgressSigner,
  type ExternalAgentGuard,
  type ProxyHoldLedger,
  type KmsService,
  type MissionService,
  type PassportClaimsRepository,
  type PassportSigner,
  type ReconnectRequiredHandler,
  type ServiceConnectionHooks,
  type SecurityEventService,
  type PlanLimitsReader,
} from '@stack/vault';
import { ProviderOAuthService, appServesProvider, type SystemAppScopes } from '../../services/provider-oauth-service.js';
import type { AnalyticsSink } from '../../lib/analytics-sink.js';
import type { BootstrapDeps, BootstrapResult, CredentialsDeps, DeploymentCredentials } from '../../extension.js';
import { env } from '../env.js';
import { systemAppGrantHooks } from './system-app-grants.js';
import { assertProductionEmailService } from '../email-service-policy.js';
import type { CoreRepositories } from './repositories.js';
import type { RedisClient } from './infra.js';
import { resolveProviderConfigs, type ProviderConfigs, type ProviderEnvFallbacks } from './provider-config.js';

export interface CredentialServices {
  serviceConnection: ServiceConnectionService;
  connectionVerifier: ConnectionVerifierService;
  oauthApp: OauthAppService;
  providerOAuth: ProviderOAuthService;
}

/**
 * Vaulted service connections, their verification, and the hosted OAuth connect
 * flow.
 *
 * The connection service takes three hooks at construction, and each reaches a
 * collaborator that is built from it or after it: the hosted OAuth connect flow
 * (below) holds the connection service, and the fleet guard and the reconnect
 * notifier come from later wiring factories. The first is a forward reference in
 * this function; the other two arrive as functions from the composition root.
 */
export function createCredentialServices(deps: {
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  signer: PassportSigner;
  repos: Pick<CoreRepositories, 'serviceRepo' | 'agentRepo'>;
  externalAgentGuard: ExternalAgentGuard;
  reconnectRequired: ReconnectRequiredHandler;
  /** How many connections a tier may hold. */
  planLimits: PlanLimitsReader;
  /** Operators whose decrypted credentials may be cached in memory. Absent: none. */
  cachedDecryptOperatorIds?: readonly string[];
  /** Holds the system operator's own OAuth apps to a list of scopes. Absent: none is narrowed. */
  systemAppScopes?: SystemAppScopes;
  /** Ends a grant of the system operator's app at the provider (a refresh token). Absent: nothing is ended there. */
  revokeSystemAppGrant?: (appProvider: string, refreshToken: string) => Promise<void>;
  /** What the deployment does beside a connection when it is made and before it is closed. Absent: nothing. */
  connectionHooks?: Pick<ServiceConnectionHooks, 'connectionOpened' | 'connectionClosing'>;
}): CredentialServices {
  const { db, redis, kms, signer, repos } = deps;
  const { serviceRepo, agentRepo } = repos;
  const serviceConnection: ServiceConnectionService = new ServiceConnectionService(serviceRepo, agentRepo, kms, redis, {
    externalAgentGuard: deps.externalAgentGuard,
    // providerOAuth is built just below from this service; it exists before any
    // credential is retrieved.
    oauthClientResolver: (operatorId, fields, connection) =>
      providerOAuth.resolveRenewalClient(operatorId, fields, connection),
    reconnectRequired: deps.reconnectRequired,
    oauthAppRetired: (binding) => providerOAuth.isRetiredBinding(binding),
    oauthAppScopesExceeded: (binding, provider, scopes) => providerOAuth.exceedsAppScopes(binding, provider, scopes),
    oauthAppServes: appServesProvider,
    ...systemAppGrantHooks({
      ...(deps.revokeSystemAppGrant ? { revokeSystemAppGrant: deps.revokeSystemAppGrant } : {}),
    }),
    planLimits: deps.planLimits,
    ...(deps.connectionHooks ?? {}),
    ...(deps.cachedDecryptOperatorIds ? { cachedDecryptOperatorIds: deps.cachedDecryptOperatorIds } : {}),
  });
  const connectionVerifier = new ConnectionVerifierService(serviceRepo, {
    current: (connection) => serviceConnection.currentCredential(connection),
  });
  const oauthApp = new OauthAppService(new OauthAppRepository(db), kms);
  const providerOAuth: ProviderOAuthService = new ProviderOAuthService({
    catalog: {
      findByProvider: (operatorId, provider) =>
        provider.startsWith('custom_')
          ? serviceRepo.findOwnedCustomServiceByProvider(operatorId, provider)
          : serviceRepo.findCatalogServiceByProvider(provider),
      findById: (operatorId, id) => serviceRepo.findAccessibleServiceById(id, operatorId),
    },
    oauthApps: oauthApp,
    signer,
    connections: serviceConnection,
    systemOperatorId: env.STACK_SYSTEM_OPERATOR_ID,
    dashboardUrl: env.DASHBOARD_URL,
    microsoftTenant: env.OAUTH_MICROSOFT_TENANT,
    ...(deps.systemAppScopes ? { systemAppScopes: deps.systemAppScopes } : {}),
    ...(deps.revokeSystemAppGrant ? { revokeGrant: deps.revokeSystemAppGrant } : {}),
  });
  return { serviceConnection, connectionVerifier, oauthApp, providerOAuth };
}

export interface PlatformCredentials {
  bootstrapped: DeploymentCredentials;
  providers: ProviderConfigs;
  /** Which credential the deployment's own surfaces' reply connection holds. */
  surfaceCredential: 'dedicated' | 'sentinel' | 'unavailable';
}

/**
 * Dogfooding: the credentials STACK itself runs on are stored as connected
 * services on the system operator, not as env vars. A deployment reads them
 * through its extension (`credentials`) and provisions its own surfaces
 * (`bootstrapSurfaces`); an install keeps none and resolves its providers from
 * the environment. Boot refuses in production when no auth-grade email service
 * is configured.
 */
export async function bootstrapPlatformCredentials(deps: {
  db: Database;
  kms: KmsService;
  serviceConnection: ServiceConnectionService;
  oauthApp: OauthAppService;
  /** Reads the credentials a deployment keeps in its vault. Absent on an install, which keeps none. */
  readCredentials?: (deps: CredentialsDeps) => Promise<DeploymentCredentials>;
  /** The deployment's own surfaces, seeded once the credentials are read (STACK's public sandbox and challenge). Absent on an install. */
  bootstrapSurfaces?: (deps: BootstrapDeps) => Promise<BootstrapResult>;
  /** What the deployment's environment says of its providers, when the vault holds none. */
  providerFallbacks?: ProviderEnvFallbacks;
}): Promise<PlatformCredentials> {
  const { serviceConnection, oauthApp } = deps;
  // An install keeps nothing in a vault: every credential a deployment's record would hold is absent, and the readers use `?.` and `??`.
  const bootstrapped = deps.readCredentials
    ? await deps.readCredentials({ connections: serviceConnection, oauthApps: oauthApp })
    : ({} as DeploymentCredentials);
  const providers = resolveProviderConfigs(bootstrapped, deps.providerFallbacks);
  const { resendKey } = providers;
  // A self-managed install may run with no email at all, or with its own SMTP
  // relay (config/email-transport.ts), so the hosted rule does not apply to it.
  if (!deployment().selfManaged) assertProductionEmailService(env.NODE_ENV, resendKey, staging().enabled);

  // A deployment that extends the engine has public surfaces of its own.
  // A self-managed install seeds none and serves none.
  const surfaces = deps.bootstrapSurfaces
    ? await deps.bootstrapSurfaces({ db: deps.db, kms: deps.kms, mailKey: resendKey })
    : { surfaceCredential: 'unavailable' as const };

  return { bootstrapped, providers, surfaceCredential: surfaces.surfaceCredential };
}

export interface ProxyServices {
  proxy: ProxyService;
  proxyOperation: ProxyOperationService;
  proxyPostResponse: ProxyPostResponseService;
}

/**
 * The credential proxy: durable admission and replay for writes, and the
 * resumable post-response bookkeeping that can never dispatch provider traffic.
 */
export function createProxyServices(deps: {
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  /** The hold bookkeeping of an operation that crossed into paid overage. */
  holds: ProxyHoldLedger;
  audit: AuditService;
  claimRegistry: ClaimRegistryService;
  authority: AuthorityService;
  securityEvent: SecurityEventService;
  passportClaimsRepo: PassportClaimsRepository;
  mission: MissionService;
  /** Signs the requests of an agent that has an account, so sites that check can tell whose they are. Null: requests leave unsigned. */
  egressSigner: EgressSigner | null;
  /** Where activation milestones go. */
  analytics: AnalyticsSink;
}): ProxyServices {
  const { db, redis, kms, holds, analytics } = deps;
  const proxy = new ProxyService(deps.egressSigner);
  const proxyOperation = new ProxyOperationService(new ProxyOperationRepository(db), kms, holds);
  const proxyPostResponse = new ProxyPostResponseService({
    proxyOperation,
    redis,
    audit: deps.audit,
    claimRegistry: deps.claimRegistry,
    authority: deps.authority,
    securityEvent: deps.securityEvent,
    passportClaimsRepo: deps.passportClaimsRepo,
    mission: deps.mission,
    analytics,
  });
  return { proxy, proxyOperation, proxyPostResponse };
}
