import type { FastifyInstance } from 'fastify';
import type { HealthAnswer } from './lib/health-probe.js';
import type { RequestAnswer } from './lib/request-answer.js';
import type { Database, JobReport, OpenRouterService } from '@stack/shared';
import {
  ContractPlanEntitlements,
  NO_ACCOUNTS,
  NO_ACCOUNT_CALL_SETTLEMENT,
  NO_ACCOUNT_DETECTION,
  NO_ACCOUNT_LIFECYCLE,
  NO_ACTION_LIMITS,
  NO_MISSION_SPEND,
  NO_PROXY_HOLDS,
  NO_SPEND_LEDGER,
  type AccountDirectory,
  type ActionLimitCounter,
  type ArchiveStoreProbeResult,
  type AuditArchiveService,
  type AuditService,
  type AuthorityService,
  type BudgetLimitResolver,
  type ClaimRegistryService,
  type ControlPolicyRepository,
  type DetectorService,
  type EntitlementResolver,
  type HeldPaymentChat,
  type IdentityProviderRegistry,
  type IntentDeviationGrader,
  type KmsService,
  type LlmUsageRepository,
  type LlmUsageService,
  type MemberService,
  type MissionActionCounter,
  type MissionService,
  type MissionSpendSource,
  type NotificationSendMeter,
  type NotificationService,
  type StreamingObjectStore,
  type OauthAppService,
  type OperatorRepository,
  type OperatorRepositoryOptions,
  type OperatorService,
  type PassportService,
  type PartnerTenantServiceDeps,
  type PassportSigner,
  type PlanLimitsReader,
  type ProxyHoldLedger,
  type SecurityEventService,
  type ServiceConnectionHooks,
  type ServiceConnectionService,
  type SpendLedger,
  type AgentService,
  type SmsTransport,
  type UsageRepositoryOptions,
} from '@stack/vault';
import { NO_METER, type ActionMeter } from './lib/action-meter.js';
import { NO_ANALYTICS, type AnalyticsSink } from './lib/analytics-sink.js';
import { NO_BROWSER_SESSIONS, NO_CONSOLE_BRIDGE, type BrowserSessions, type ConsoleBridge } from './lib/browser-session.js';
import { NO_IDENTITY_CHARGE, type IdentityVerificationCharge } from './lib/identity-verification-charge.js';
import { CUSTOMER_KEY_ONLY, type ModelAccessPolicy } from './lib/model-access-policy.js';
import { NO_GENERATED_FILES, type GeneratedFileSink } from './lib/generated-files.js';
import type { L3ClassifierSource } from './detectors/l3-classifier.js';
import type { EngineRegistries } from './config/registries.js';
import type { LlmUsageFactory } from './config/wiring/llm.js';
import type { CoreRepositories } from './config/wiring/repositories.js';
import type { RedisClient } from './config/wiring/infra.js';
import type { ProviderConfigs, ProviderEnvFallbacks } from './config/wiring/provider-config.js';
import type { ControlCore } from './config/wiring/control-socket.js';
import type { CredentialServices, ProxyServices } from './config/wiring/credentials-and-proxy.js';
import type { LlmServices } from './config/wiring/llm.js';
import type { InboundServices } from './config/wiring/inbound.js';
import type { Notifications } from './config/wiring/notifications.js';
import type { MissionServices } from './config/wiring/missions.js';
import type { Detectors } from './config/wiring/audit-and-detectors.js';
import type { EvidenceServices } from './config/wiring/evidence.js';
import type { AccountSecurityServices } from './config/wiring/account-security.js';
import type { PartnerServices, FleetServices } from './config/wiring/partners-and-fleets.js';
import type { NetworkClientServices } from './config/network-client.js';
import type { FeatureGate } from './config/licence-service.js';
import type { createAuthMiddleware } from './middleware/auth.js';
import type { Services } from './config/wiring/services-type.js';
import type { SystemAppScopes } from './services/provider-oauth-service.js';

/**
 * How a deployment adds to the engine. The engine entry (`dist/server.js`) runs
 * `startApi(null)`: a self-managed install, with a contract plan, no meter, no
 * wallet and no accounts. STACK's own deployment starts from its own entry
 * point with its own extension, which fills every hook
 * below and puts its business behind the engine's seams.
 *
 * The hooks run at the points of the composition root where the hosted pieces
 * were built before the split, in the same order, so nothing a request reaches
 * is built differently.
 */

/** The guard the engine puts in front of its operator-scope routes; a deployment's routes use the same one. */
export type AuthMiddleware = ReturnType<typeof createAuthMiddleware>;

/** What a hook is given before any service exists: the connections every hook needs. */
export interface BaseDeps {
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  repos: CoreRepositories;
}

export interface EntitlementDeps extends BaseDeps {
  /** The account service, whose billing-changed hook the engine points at the resolver it gets back. */
  operator: OperatorService;
}

/**
 * What the engine reads of the credentials a deployment keeps in its own vault: the providers it resolves
 * (identity vendors, mail, text and model keys). A deployment's record holds more, which only the deployment reads.
 */
export interface DeploymentCredentials {
  resend?: { apiKey: string } | null;
  openrouter?: { apiKey: string } | null;
}

export interface CredentialsDeps {
  connections: ServiceConnectionService;
  oauthApps: OauthAppService;
}

export interface BootstrapDeps {
  db: Database;
  kms: KmsService;
  /** The deployment's own mail key, when it has one: a surface that sends mail may start from it. */
  mailKey: string | null | undefined;
}

export interface BootstrapResult {
  /** Which credential the deployment's own surfaces' reply connection holds. */
  surfaceCredential: 'dedicated' | 'sentinel' | 'unavailable';
}

export interface MoneyDeps extends BaseDeps {
  providers: ProviderConfigs;
  claimRegistry: ClaimRegistryService;
  /** What an agent account's credit hold is checked against: the policy's limits and the account budget. */
  budgetLimits: BudgetLimitResolver;
}

/** What the money hook puts behind the engine's money seams. */
export interface MoneyParts {
  spend: SpendLedger;
  /** The hold bookkeeping of a proxy operation that crossed into paid overage. */
  proxyHolds: ProxyHoldLedger;
  /** What a Mission has spent on credit, and whether it is an account's standing Mission: the Mission's cost cap reads it. */
  missionSpend: MissionSpendSource;
  /** The usage ledger's persistence with the wallet's side of it (fee accrual). Null: the engine's own, which owes no wallet fee. */
  llmUsageRepo: LlmUsageRepository | null;
  /** The usage ledger that holds and charges the calls that run on a key of the deployment's own. Null: the engine's, which has none. */
  llmUsage: LlmUsageFactory | null;
  meter: ActionMeter;
  accounts: AccountDirectory;
  limits: ActionLimitCounter;
  /** Counts a Mission's action limits per Mission with one conditional update. Null: an install, where the gate counts intent claims. */
  missionActions: MissionActionCounter | null;
  /** Offers a held payment to the owner's chat, once the chat is built (the hook answers late). */
  heldPaymentChat: HeldPaymentChat | null;
  /** Signs the requests an account's agent makes through the proxy; absent on an install. */
  egressSigner: ProxySigner | null;
}

type ProxySigner = NonNullable<ConstructorParameters<typeof import('@stack/vault').ProxyService>[0]>;

/** The text transport and the send cap of the notification service. */
export interface NotificationSeams {
  /** How a text message is sent. Null: the SMS channel answers that delivery is unavailable. */
  sms: SmsTransport | null;
  /** Caps every send that costs vendor money. Null: sends are not metered. */
  sendMeter: NotificationSendMeter | null;
}

/**
 * Everything the engine has built when the deployment's own services are built:
 * the connections, the engine's services, and the results of the earlier hooks.
 */
export interface HostedBuildContext {
  /** The one handle. A deployment whose tables it opened checks that at its own boundary. */
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  repos: CoreRepositories;
  signer: PassportSigner;
  features: FeatureGate;
  networkClient: NetworkClientServices;
  audit: AuditService;
  auditArchive: AuditArchiveService;
  auditObjectStore: StreamingObjectStore;
  providers: ProviderConfigs;
  surfaceCredential: BootstrapResult['surfaceCredential'];
  claimRegistry: ClaimRegistryService;
  claimSigning: Awaited<ReturnType<typeof import('./config/wiring/crypto-and-signing.js').createClaimSigning>>;
  signing: Awaited<ReturnType<typeof import('./config/wiring/crypto-and-signing.js').createPassportSigner>>;
  operator: OperatorService;
  member: MemberService;
  agent: AgentService;
  passport: PassportService;
  authority: AuthorityService;
  mission: MissionService;
  missions: MissionServices;
  securityEvent: SecurityEventService;
  notification: NotificationService;
  notifications: Notifications;
  detector: DetectorService;
  detectors: Detectors;
  credentials: CredentialServices;
  llm: LlmServices;
  inbound: InboundServices;
  proxy: ProxyServices;
  controlCore: ControlCore;
  evidence: EvidenceServices;
  accountSecurity: AccountSecurityServices;
  partners: PartnerServices;
  fleets: FleetServices;
  identityRegistry: IdentityProviderRegistry;
  /** The engine's `Services` as far as it goes. The deployment's services are added to it. */
  engine: Services;
}

export interface ApiExtension<H extends object = object> {
  /** The deployment's tables, merged with the engine's into the one database handle. */
  readonly dbSchema: Record<string, unknown>;
  /** What the deployment's environment says of its providers (identity, payments, text, models), when the vault holds none. */
  readonly providerFallbacks?: ProviderEnvFallbacks;
  /** The actions a plan includes in a month (`Infinity`: none named), snapshotted beside a plan write. Absent: the contract plan's. */
  readonly monthlyActionLimit?: OperatorRepositoryOptions['monthlyActionLimit'];
  /** The counts a tier allows (agents, connections, seats, tenants), with a deal's overrides. Absent: the contract plan's, no cap. */
  readonly planLimits?: PlanLimitsReader;
  /**
   * The billing of a partner's accounts: the first month of an account's plan is taken from the partner's wallet in the
   * transaction that opens the account, and each account's plan is read for its partner. Absent: accounts have no plan.
   */
  readonly partnerAccountPlans?: PartnerTenantServiceDeps['accountPlans'];
  /** The deployment's own account service, built on the engine's operator repository. Absent: the engine's. */
  readonly operatorService?: (repo: OperatorRepository) => OperatorService;
  /** The audit actions the deployment's meter counts, for the usage reads. Absent: none. */
  readonly meteredActions?: UsageRepositoryOptions['meteredActions'];
  /** The policy repository, with the agent accounts it can see. Absent: the engine's, which sees none. */
  readonly policyRepository?: (db: Database) => ControlPolicyRepository;
  /** Operators whose decrypted credentials may be cached in memory (a traffic simulator's). Absent: none. */
  readonly cachedDecryptOperatorIds?: readonly string[];
  /** A line the platform A2A card opens its description with, before the engine's own sentence. Absent: the card says only the engine's sentence. */
  readonly agentCardTagline?: string;
  /**
   * The secrets the deployment's own servers (its Console, its MCP server) sign the client address of the calls they forward
   * with (`x-stack-forwarded-client`): a header that verifies under any one of them is trusted, read only by the global rate
   * limit's key. Absent or empty: an install without such a server, where every call is keyed by its source address as before.
   */
  readonly forwardedClientSecrets?: readonly string[];
  /** Holds the system operator's own OAuth apps to a list of scopes per service. Absent: no app is narrowed (an install has no such app). */
  readonly systemAppScopes?: SystemAppScopes;
  /** Ends a grant of one of the system operator's own OAuth apps at the provider, given the app's provider and the refresh token. Absent: nothing is ended there. */
  readonly revokeSystemAppGrant?: (appProvider: string, refreshToken: string) => Promise<void>;
  /**
   * What the deployment does beside a service connection when one is made and before one is closed (STACK registers where RentAHuman
   * delivers the account's events, and ends it at RentAHuman on a disconnect). Each hook answers for the providers it acts for. Absent: nothing.
   */
  readonly connectionHooks?: Pick<ServiceConnectionHooks, 'connectionOpened' | 'connectionClosing'>;
  /** Fills the engine registries before any service is built. */
  register(registries: EngineRegistries, deps: BaseDeps): void;
  /** The plan behind each call: STACK's billing accounts. */
  entitlements(deps: EntitlementDeps): Promise<EntitlementResolver>;
  /** The deployment's identity verification providers, registered before the opt-in simulated ones. */
  identityProviders(registry: IdentityProviderRegistry, providers: ProviderConfigs): Promise<void>;
  /** Reads the credentials the deployment keeps in its vault under the system operator (moving its environment's into it) and seeds the OAuth apps it signs in with. An install keeps none. */
  credentials?(deps: CredentialsDeps): Promise<DeploymentCredentials>;
  /** The deployment's own surfaces seeded once the platform credentials are read (a hosted deployment's public surfaces). */
  bootstrap(deps: BootstrapDeps): Promise<BootstrapResult>;
  /** The text transport and the send cap of the notification service. */
  notificationSeams(deps: { providers: ProviderConfigs; redis: RedisClient }): NotificationSeams;
  /** Money: the wallet, the meter, the accounts and their limits, behind the engine's seams. */
  money(deps: MoneyDeps): MoneyParts;
  /**
   * The deployment's own third detector layer, one classifier per scan (its prompt, its model and the budget the call is
   * paid from). Absent or null: the engine's only third layer is STACK's network classifier, when an install chose it.
   */
  l3Classifier?(deps: {
    redis: RedisClient;
    openRouter: OpenRouterService | null;
    llmUsage: LlmUsageService;
    billingAccounts: EntitlementResolver;
  }): L3ClassifierSource | null;
  /**
   * The deployment's own grader of declared-versus-observed behaviour at checkout (its prompt, its model and the
   * ledger the call is paid from). Absent or null: the review rules alone decide.
   */
  intentDeviationGrader?(deps: {
    openRouter: OpenRouterService | null;
    llmUsage: LlmUsageService;
    /** The one controls decision: intent_deviation runs only for an account with controls on. */
    controlsEnabled: (operatorId: string) => Promise<boolean>;
  }): IntentDeviationGrader | null;
  /** The deployment's own seams: the Console's sessions, the identity charge, whose key a model call runs on, the analytics. */
  seams(deps: { redis: RedisClient }): Promise<DeploymentSeams>;
  /** Builds the deployment's own services. Called after the engine's, returns what routes of the deployment read. */
  services(context: HostedBuildContext): Promise<H>;
  /** Plugins the deployment's routes need, registered before any route (the call relay's WebSocket). */
  plugins(app: FastifyInstance): Promise<void>;
  /** The deployment's routes, after the engine's. */
  routes(app: FastifyInstance, services: Services & H, auth: AuthMiddleware): Promise<void>;
  /** The deployment's background work; the function it returns stops it. */
  runners(services: Services & H): () => Promise<void>;
  /** Told the verdict of each health probe (database and Redis), for the deployment's record of its systems. Must not throw. Absent: nothing is recorded. */
  readonly observeHealthProbe?: (services: Services & H, answer: HealthAnswer) => void;
  /** Told each finished answer (route template, status, and for a 501 the vault service that is not configured), for the deployment's count of errors. Must not throw or wait. Absent: nothing is counted. */
  readonly observeRequestEnd?: (services: Services & H, answer: RequestAnswer) => void;
  /** Told the verdict of each audit object store probe. Must not throw. Absent: nothing is recorded. */
  readonly observeArchiveStoreProbe?: (services: Services & H, result: ArchiveStoreProbeResult) => void;
  /** Told how each pass of a background runner ended (the engine's runners and the deployment's own). Must not throw. Absent: nothing is recorded. */
  readonly observeJob?: (services: Services & H, report: JobReport) => void;
}

/** The seams that are plain objects of the deployment, not built from the services. */
export interface DeploymentSeams {
  browserSessions: BrowserSessions;
  consoleBridge: ConsoleBridge | null;
  identityVerificationCharge: IdentityVerificationCharge;
  modelAccessPolicy: ModelAccessPolicy;
  /** Where an image or a file a model made is saved (the agent's drive). Null: it is returned to the caller. */
  generatedFiles: GeneratedFileSink | null;
  analytics: AnalyticsSink;
}

/**
 * Refuses a money hook that left a seam on its null implementation. The hold ledger of a proxy
 * operation and the Mission's credit spend are read inside services, not from the bundle, so
 * `assertHostedSeams` cannot see them: without these a hosted boot would take no hold for an
 * operation that crossed into overage and count no credit against a Mission's cost cap.
 */
export function assertHostedMoney(parts: Pick<MoneyParts, 'spend' | 'proxyHolds' | 'missionSpend' | 'llmUsage'>): void {
  const missing: string[] = [];
  if (parts.spend === NO_SPEND_LEDGER) missing.push('spend');
  if (parts.proxyHolds === NO_PROXY_HOLDS) missing.push('proxyHolds');
  if (parts.missionSpend === NO_MISSION_SPEND) missing.push('missionSpend');
  if (parts.llmUsage === null) missing.push('llmUsage');
  if (missing.length > 0) {
    throw new Error(`[BOOT] The hosted deployment's money hook left engine seams on their null implementation: ${missing.join(', ')}`);
  }
}

/** The fields of the extension itself that a hosted boot must not be missing (the others are hooks the boot calls). */
export type HostedExtensionSeams = Pick<
  ApiExtension,
  'planLimits' | 'monthlyActionLimit' | 'meteredActions' | 'policyRepository' | 'l3Classifier' | 'operatorService' | 'intentDeviationGrader'
>;

/**
 * Refuses a hosted boot that left a seam on its null implementation. A seam that
 * is still null means the deployment's own object was not wired, and the engine
 * would run that part unmetered, unbilled or without accounts; STACK's
 * deployment must never boot like that, so it names the first one and stops.
 *
 * The text transport is not checked: it is null on a deployment without a
 * phone provider account, and that is a configuration the deployment may have. The
 * third detector layer is checked as a hook (it may answer null without a
 * model key), not by what it builds.
 *
 * The extension's own fields are checked as well as what the services read
 * from them: a deployment that left out its plan limits, its action limit, its
 * metered actions, its policy repository, its third layer, its account service,
 * its behaviour grader or the notification send cap would otherwise boot on the
 * engine's defaults (no cap, no meter, no agent accounts in the policies, no
 * trial expiry, no grading) and serve customers with them.
 */
export function assertHostedSeams(
  services: Pick<
    Services,
    | 'actionMeter'
    | 'spend'
    | 'entitlements'
    | 'accountDirectory'
    | 'actionLimits'
    | 'browserSessions'
    | 'consoleBridge'
    | 'identityVerificationCharge'
    | 'modelAccessPolicy'
    | 'generatedFiles'
    | 'analytics'
    | 'registries'
    | 'accountDetection'
    | 'agentAccounts'
    | 'accountModelBilling'
    | 'notification'
  >,
  extension: HostedExtensionSeams,
): void {
  const missing: string[] = [];
  if (services.actionMeter === NO_METER) missing.push('actionMeter');
  if (services.spend === NO_SPEND_LEDGER) missing.push('spend');
  if (services.entitlements instanceof ContractPlanEntitlements) missing.push('entitlements');
  if (services.accountDirectory === NO_ACCOUNTS) missing.push('accountDirectory');
  if (services.actionLimits === NO_ACTION_LIMITS) missing.push('actionLimits');
  if (services.browserSessions === NO_BROWSER_SESSIONS) missing.push('browserSessions');
  if (services.consoleBridge === NO_CONSOLE_BRIDGE) missing.push('consoleBridge');
  if (services.identityVerificationCharge === NO_IDENTITY_CHARGE) missing.push('identityVerificationCharge');
  if (services.modelAccessPolicy === CUSTOMER_KEY_ONLY) missing.push('modelAccessPolicy');
  if (services.generatedFiles === NO_GENERATED_FILES) missing.push('generatedFiles');
  if (services.analytics === NO_ANALYTICS) missing.push('analytics');
  if (services.accountDetection === NO_ACCOUNT_DETECTION) missing.push('accountDetection');
  if (services.agentAccounts === NO_ACCOUNT_LIFECYCLE) missing.push('agentAccounts');
  if (services.accountModelBilling === NO_ACCOUNT_CALL_SETTLEMENT) missing.push('accountModelBilling');
  if (!extension.planLimits) missing.push('planLimits');
  if (!extension.monthlyActionLimit) missing.push('monthlyActionLimit');
  if (!extension.meteredActions) missing.push('meteredActions');
  if (!extension.policyRepository) missing.push('policyRepository');
  if (typeof extension.l3Classifier !== 'function') missing.push('l3Classifier');
  if (typeof extension.operatorService !== 'function') missing.push('operatorService');
  if (typeof extension.intentDeviationGrader !== 'function') missing.push('intentDeviationGrader');
  if (!services.notification.hasSendMeter()) missing.push('notification sendMeter');
  if (!services.registries.sealed) missing.push('registries (not sealed)');
  if (missing.length > 0) {
    throw new Error(`[BOOT] The hosted deployment started with engine seams still on their null implementation: ${missing.join(', ')}`);
  }
}
