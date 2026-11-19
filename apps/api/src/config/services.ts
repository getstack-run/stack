import { createCoreRepositories } from './wiring/repositories.js';
import { ONE_SHOT_REDIS_ATTEMPTS, createInfrastructure } from './wiring/infra.js';
import { createPassportSigner, createClaimSigning, createCmek } from './wiring/crypto-and-signing.js';
import {
  createAuditTrail,
  createSecurityEvents,
  bindAuditToClaims,
  createDetectors,
} from './wiring/audit-and-detectors.js';
import { createOperatorAccounts } from './wiring/operators-and-billing.js';
import { createIdentityCore } from './wiring/identity.js';
import { createAgentsAndPassports, createAccountability } from './wiring/agents-and-passports.js';
import {
  createCredentialServices,
  bootstrapPlatformCredentials,
  createProxyServices,
} from './wiring/credentials-and-proxy.js';
import { createNotifications } from './wiring/notifications.js';
import {
  bridgeAuditToNotifications,
  createReconnectNotifier,
} from './wiring/notification-bridges.js';
import { createLlmServices } from './wiring/llm.js';
import { createDropoffServices } from './wiring/dropoffs.js';
import { createMissionServices, createIntentGate } from './wiring/missions.js';
import { createAuthority } from './wiring/authority.js';
import { createInboundServices } from './wiring/inbound.js';
import { createPartnerServices, createFleetServices } from './wiring/partners-and-fleets.js';
import { createAccountSecurityServices } from './wiring/account-security.js';
import { createEvidenceServices } from './wiring/evidence.js';
import { createControlCore, createControlSocketServices } from './wiring/control-socket.js';
import { deployment } from '@stack/shared';
import { createFeatureGate } from './licence-service.js';
import { createNetworkClientServices, readNetworkClientConfig } from './network-client.js';
import { chooseInstallIntentGrader, readIntentModelConfig } from './intent-deviation-model.js';
import { assertSelfManagedBoot, ensureSelfManagedPlan } from './self-managed.js';
import { EngineRegistries } from './registries.js';
import { NO_METER } from '../lib/action-meter.js';
import { decisionAnnouncer } from '../lib/decision-reached.js';
import { NO_ANALYTICS } from '../lib/analytics-sink.js';
import { NO_BROWSER_SESSIONS, NO_CONSOLE_BRIDGE } from '../lib/browser-session.js';
import { NO_IDENTITY_CHARGE } from '../lib/identity-verification-charge.js';
import { CUSTOMER_KEY_ONLY } from '../lib/model-access-policy.js';
import { NO_GENERATED_FILES } from '../lib/generated-files.js';
import { assertHostedMoney, type ApiExtension, type MoneyParts } from '../extension.js';
import type { Services } from './wiring/services-type.js';
import {
  ContractPlanEntitlements,
  contractPlanLimits,
  ControlLimitResolver,
  MissionRepository,
  NO_ACCOUNTS,
  NO_ACCOUNT_CALL_SETTLEMENT,
  NO_ACCOUNT_DETECTION,
  NO_ACCOUNT_LIFECYCLE,
  NO_ACTION_LIMITS,
  NO_MISSION_SPEND,
  NO_PROXY_HOLDS,
  NO_SPEND_LEDGER,
  type ControlReviewService,
  type ReconnectRequiredHandler,
} from '@stack/vault';

export type { Services } from './wiring/services-type.js';

/** What money is on an install: no wallet, no meter, no accounts, no limits. */
const INSTALL_MONEY: MoneyParts = {
  spend: NO_SPEND_LEDGER,
  proxyHolds: NO_PROXY_HOLDS,
  missionSpend: NO_MISSION_SPEND,
  llmUsageRepo: null,
  llmUsage: null,
  meter: NO_METER,
  accounts: NO_ACCOUNTS,
  limits: NO_ACTION_LIMITS,
  missionActions: null,
  heldPaymentChat: null,
  egressSigner: null,
};

/**
 * The composition root: builds the whole service graph by calling one factory
 * per domain, in dependency order. Each factory lives in `./wiring/` and
 * returns the slice of `Services` it owns.
 *
 * `ext` is what a deployment adds to the engine (`ApiExtension`): the engine
 * entry passes null and gets an install (a contract plan, no meter, no wallet,
 * no accounts); STACK's own deployment passes its extension, which fills each
 * hook at the point of the sequence where its piece was built before the split.
 *
 * Every dependency a service needs is passed to its constructor. Where two
 * services need each other, the one built first receives a function that reads
 * the other at call time (`() => securityEvent`), and the other is a `const`
 * declared further down. The PassportService and the ServiceConnectionService
 * are built early and reach six such collaborators this way:
 *
 *   - security events block agents through the passport service;
 *   - the Mission service builds its twin runtime on the passport service;
 *   - the authority service verifies presentations through the passport service;
 *   - the fleet service issues passports and guards grants for both services;
 *   - the hosted OAuth connect flow holds the connection service (in its factory);
 *   - the credential bootstrap that reads provider keys uses the connection
 *     service before notifications, which they need, can exist.
 *
 * A call made before its collaborator exists throws, so no check is skipped for
 * want of a dependency. Nothing calls any of them while the graph is built.
 *
 * Boot refuses (throws) before the process serves traffic when production
 * configuration is unsafe: no KMS key, no signing key, a non-durable audit
 * store, a missing auth email service, an incomplete skill runner, or the mock
 * identity flag. The KMS, signing-key and audit-store refusals run first, before
 * any other service is built.
 */
export async function createServices<H extends object = object>(
  ext: ApiExtension<H> | null,
  options: { redisAttempts?: number } = {},
): Promise<Services & H> {
  // The licence is read first, so it is the first thing a self-managed boot says.
  const selfManaged = deployment().selfManaged;
  // A hosted extension on a self-managed deployment would run STACK's business under an install's licence rules and plans.
  if (ext && selfManaged) throw new Error('[BOOT] The hosted extension cannot run with STACK_DEPLOYMENT=self_managed.');
  if (selfManaged) assertSelfManagedBoot(process.env);
  // The gate follows the extension, not the environment: only a hosted extension gets the gate that never refuses.
  const features = createFeatureGate(Boolean(ext));
  // STACK's hosted network (live rules, L3 classifier) is for self-managed
  // installs only, and only when they configured it.
  const networkClient = createNetworkClientServices(selfManaged ? readNetworkClientConfig(process.env) : null);
  // An install can grade intent deviation with a model of its own (an OpenAI-compatible endpoint and key it configures).
  const intentModel = selfManaged ? readIntentModelConfig(process.env) : null;
  const { db, redis, kms } = await createInfrastructure(ext?.dbSchema, { redisAttempts: options.redisAttempts ?? ONE_SHOT_REDIS_ATTEMPTS });
  const signing = await createPassportSigner(kms);
  const { signer } = signing;
  // What the deployment adds to the engine is registered before any service that reads it exists. The registries
  // are made first so the repository can read the deployment's erasure steps when an account is deleted.
  const registries = new EngineRegistries();
  const repos = createCoreRepositories(
    db,
    {
      deleteSteps: () => registries.operatorDeleteSlots.list(),
      ...(ext?.monthlyActionLimit ? { monthlyActionLimit: ext.monthlyActionLimit } : {}),
    },
    ext?.meteredActions ? { meteredActions: ext.meteredActions } : {},
  );
  // The counts a tier allows: the deployment's plans, or the contract plan's (no cap).
  const planLimits = ext?.planLimits ?? contractPlanLimits;
  const base = { db, redis, kms, repos };
  ext?.register(registries, base);
  // A self-managed install has no plans: every operator is on the contract plan
  // (no meter refuses them, controls are included, nothing is charged) and the
  // licence gates what it gates.
  if (selfManaged) await ensureSelfManagedPlan(db, repos.operatorRepo);
  const { audit, auditArchive, auditObjectStore } = await createAuditTrail(db, registries.archiveErasePrefixes.list());

  const { operator, operatorErasure, member } = createOperatorAccounts({
    db,
    operatorRepo: repos.operatorRepo,
    memberRepo: repos.memberRepo,
    audit,
    auditArchive,
    erasureBefore: registries.erasureBefore.list(),
    ...(ext?.operatorService ? { operatorService: ext.operatorService } : {}),
  });
  // The plan each call is metered against: the deployment's billing accounts, or the contract plan.
  const entitlements = ext
    ? await ext.entitlements({ ...base, operator })
    : new ContractPlanEntitlements(repos.operatorRepo);
  operator.setBillingChangedHook((operatorId: string) => entitlements.invalidate(operatorId));
  // The customer's socket, the posture that says which of STACK's hosted checks
  // apply to a kind of action, and their policies. Built here because the
  // wallet's holds, the detectors and the data trail read them; the decision
  // engine that uses them comes later (createControlSocketServices).
  const controlCore = createControlCore({ db, redis, kms, entitlements, ...(ext?.policyRepository ? { policyRepository: ext.policyRepository } : {}) });
  // What a spend of an agent account is checked against: the policy's limits,
  // and the account budget, which follow the customer's per-kind choice.
  const budgetLimits = new ControlLimitResolver({
    posture: controlCore.controlPosture,
    policies: controlCore.controlPolicies,
    accounts: controlCore.controlPolicyRepo,
    missions: new MissionRepository(db),
  });
  const claimSigning = await createClaimSigning({
    db,
    redis,
    kms,
    signing,
    passportClaimsRepo: repos.passportClaimsRepo,
  });
  const { claimRegistry } = claimSigning;
  const identityCore = createIdentityCore({
    db,
    redis,
    kms,
    repos,
    claimRegistry,
    audit,
  });
  const { identity, claimMatcher, oidcIdpProvider } = identityCore;
  const { agent, passport } = createAgentsAndPassports({
    db,
    redis,
    signer,
    repos,
    identity,
    claimMatcher,
    lookups: {
      missionLookup: () => missions.missionLookup,
      securityEvent: () => securityEvent,
      authorityLookup: () => authority,
      fleetLookup: () => fleets.fleet,
    },
    planLimits,
  });
  const credentials = createCredentialServices({
    db,
    redis,
    kms,
    signer,
    repos,
    externalAgentGuard: (operatorId, agentId) => fleets.fleet.assertExternalAgent(operatorId, agentId),
    // The notifier needs the notification service, which needs the provider
    // credentials this service bootstraps below. A reconnect raised during that
    // bootstrap is held and delivered once the notifier exists, so a boot-time
    // reconnect is neither dropped nor a reference error.
    reconnectRequired: async (event) => {
      if (reconnectNotifier) await reconnectNotifier(event);
      else heldReconnectEvents.push(event);
    },
    planLimits,
    ...(ext?.cachedDecryptOperatorIds ? { cachedDecryptOperatorIds: ext.cachedDecryptOperatorIds } : {}),
    ...(ext?.systemAppScopes ? { systemAppScopes: ext.systemAppScopes } : {}),
    ...(ext?.revokeSystemAppGrant ? { revokeSystemAppGrant: ext.revokeSystemAppGrant } : {}),
    ...(ext?.connectionHooks ? { connectionHooks: ext.connectionHooks } : {}),
  });
  const heldReconnectEvents: Parameters<ReconnectRequiredHandler>[0][] = [];
  let reconnectNotifier: ReconnectRequiredHandler | undefined;
  const { serviceConnection } = credentials;

  const { providers, surfaceCredential } = await bootstrapPlatformCredentials({
    db,
    kms,
    serviceConnection,
    oauthApp: credentials.oauthApp,
    ...(ext?.credentials ? { readCredentials: (deps: Parameters<NonNullable<ApiExtension['credentials']>>[0]) => ext.credentials!(deps) } : {}),
    ...(ext ? { bootstrapSurfaces: (deps: Parameters<ApiExtension['bootstrap']>[0]) => ext.bootstrap(deps) } : {}),
    ...(ext?.providerFallbacks ? { providerFallbacks: ext.providerFallbacks } : {}),
  });
  // The deployment's own identity vendors (and any simulated ones it opts into) register on top of the engine's.
  await ext?.identityProviders(identityCore.providerRegistry, providers);

  // Money: the wallet, the meter, the accounts and their limits behind the engine's seams, or the install's none.
  const money = ext ? ext.money({ ...base, providers, claimRegistry, budgetLimits }) : INSTALL_MONEY;
  if (ext) assertHostedMoney(money);
  const seams = ext
    ? await ext.seams({ redis })
    : {
        browserSessions: NO_BROWSER_SESSIONS,
        consoleBridge: NO_CONSOLE_BRIDGE,
        identityVerificationCharge: NO_IDENTITY_CHARGE,
        modelAccessPolicy: CUSTOMER_KEY_ONLY,
        generatedFiles: NO_GENERATED_FILES,
        analytics: NO_ANALYTICS,
      };
  // The price shown beside each identity provider is the deployment's; an install shows none.
  identity.setVerificationPricing((providerKey) => seams.identityVerificationCharge.priceCents(providerKey));
  const notificationSeams = ext ? ext.notificationSeams({ providers, redis }) : { sms: null, sendMeter: null };
  const notifications = createNotifications({
    db,
    kms,
    providers,
    sms: notificationSeams.sms,
    sendMeter: notificationSeams.sendMeter,
  });
  const { notification } = notifications;
  reconnectNotifier = createReconnectNotifier(notification);
  for (const event of heldReconnectEvents.splice(0)) await reconnectNotifier(event);

  const securityEvent = createSecurityEvents({
    securityEventRepo: repos.securityEventRepo,
    agentRepo: repos.agentRepo,
    passport,
    redis,
    notification,
    claimRegistry,
  });
  const llm = createLlmServices({
    redis,
    llmUsageRepo: money.llmUsageRepo ?? repos.llmUsageRepo,
    llmUsage: money.llmUsage,
    securityEvent,
    openRouterKey: providers.openRouterKey,
  });
  const { openRouter, llmUsage } = llm;
  const { dropoff } = createDropoffServices(db, kms);

  const missions = createMissionServices({
    db,
    redis,
    kms,
    repos,
    passport,
    claimRegistry,
    securityEvent,
    missionSpend: money.missionSpend,
    missionActions: money.missionActions,
    notification,
    audit,
    registries,
  });
  const { mission, behavioralGenome } = missions;
  const accountability = createAccountability({
    db,
    redis,
    repos,
    passport,
    claimRegistry,
    behavioralGenome,
    // STACK's own grader on the hosted deployment; on an install, its own model when one is configured, else STACK's
    // network when its classifier is switched on, else none (intent_deviation is off).
    intentDeviation: ext?.intentDeviationGrader?.({
      openRouter,
      llmUsage,
      controlsEnabled: (operatorId: string) => entitlements.controlsEnabled(operatorId),
    }) ?? chooseInstallIntentGrader(intentModel, networkClient.intentDeviation),
  });
  const detectors = createDetectors({
    db,
    redis,
    securityEvent,
    l3Source: ext?.l3Classifier?.({ redis, openRouter, llmUsage, billingAccounts: entitlements }) ?? null,
    networkClient,
  });
  // Held actions' reviews, built with the control socket below; a governance decision reaches them through this.
  let heldActionReviews: Pick<ControlReviewService, 'followDecision'> | null = null;
  const intents = createIntentGate({
    db,
    kms,
    passportClaimsRepo: repos.passportClaimsRepo,
    passport,
    agent,
    claimRegistry,
    entitlements,
    meter: money.meter,
    detector: detectors.detector,
    mission,
    notification,
    onDecision: decisionAnnouncer(registries),
  });
  const authority = createAuthority({
    db,
    kms,
    signer,
    signerKid: claimSigning.signerKid,
    claimRegistry,
    passport,
    identity,
    oidcIdpProvider,
    receiverDirectories: registries.receiverDirectories.list(),
  });
  const proxy = createProxyServices({
    egressSigner: money.egressSigner,
    analytics: seams.analytics,
    db,
    redis,
    kms,
    holds: money.proxyHolds,
    audit,
    claimRegistry,
    authority,
    securityEvent,
    passportClaimsRepo: repos.passportClaimsRepo,
    mission,
  });

  bindAuditToClaims({ audit, passportClaimsRepo: repos.passportClaimsRepo, securityEvent });
  bridgeAuditToNotifications(audit, notification);

  const inbound = createInboundServices({
    db,
    kms,
    repos,
    agent,
    detector: detectors.detector,
    audit,
    meter: money.meter,
    entitlements,
    extractors: registries.inboundExtractors,
    deliveries: registries.inboundDeliveries,
    managedEnds: registries.inboundManagedEnds,
  });
  const partners = createPartnerServices({ db, repos, planLimits, ...(ext?.partnerAccountPlans ? { accountPlans: ext.partnerAccountPlans } : {}) });
  const accountSecurity = createAccountSecurityServices({
    db,
    redis,
    audit,
    notification,
    accountEmail: notifications.accountEmail,
    actions: registries.governanceActions,
  });
  const evidence = createEvidenceServices({
    db,
    repos,
    missionRepo: missions.missionRepo,
    claimRegistry,
    claimSigning,
    deploymentSigningConfig: signing.deploymentSigningConfig,
    audit,
    passport,
    auditObjectStore,
    // A person's decision on a held action's approval reaches its review at once, so the agent is told without waiting.
    onGovernanceDecided: async (decided) => {
      if (decided.action !== 'control_review') return;
      if (!heldActionReviews) throw new Error('[BOOT] a held action was decided before its reviews were built');
      await heldActionReviews.followDecision(decided.operatorId, decided.resourceId);
    },
  });
  const { cmek, cmekMigrationRepo } = await createCmek({
    db,
    redis,
    kms,
    operatorRepo: repos.operatorRepo,
    extraStores: registries.cmekSteps.list().map((step) => step.table),
    extraEphemeralStores: registries.cmekEphemeralStores.list(),
  });
  const fleets = createFleetServices({
    db,
    redis,
    passport,
    agent,
    mission,
    entitlements,
    claimRegistry,
    intentApproval: intents.intentApproval,
    approvalGate: intents.approvalGate,
  });

  // The control socket: who decides for a customer (hosted, their own server or
  // nobody), and where their record is streamed. Offers every audit row to its
  // events outbox from here on.
  const controlSocket = await createControlSocketServices({
    db,
    redis,
    audit,
    entitlements,
    meter: money.meter,
    limits: money.limits,
    governanceApprovals: accountSecurity.governanceApprovals,
    notification,
    core: controlCore,
    chat: money.heldPaymentChat,
    onDecision: decisionAnnouncer(registries),
  });
  heldActionReviews = controlSocket.controlReviews;

  const engine: Services = {
    db,
    // What the engine reads of the deployment's accounts and its own provider key. A deployment's services replace these
    // below; an install keeps the nulls, which no engine path reaches with an account in hand.
    accountDetection: NO_ACCOUNT_DETECTION,
    agentAccounts: NO_ACCOUNT_LIFECYCLE,
    accountModelBilling: NO_ACCOUNT_CALL_SETTLEMENT,
    features,
    networkClient,
    actionMeter: money.meter,
    spend: money.spend,
    entitlements,
    accountDirectory: money.accounts,
    actionLimits: money.limits,
    browserSessions: seams.browserSessions,
    consoleBridge: seams.consoleBridge,
    identityVerificationCharge: seams.identityVerificationCharge,
    modelAccessPolicy: seams.modelAccessPolicy,
    generatedFiles: seams.generatedFiles,
    smsTransport: notificationSeams.sms,
    registries,
    auditObjectStore,
    controlSocket: controlCore.controlSocket,
    controlSocketRepo: controlCore.controlSocketRepo,
    controlPosture: controlCore.controlPosture,
    controlPolicies: controlCore.controlPolicies,
    controlPolicyRepo: controlCore.controlPolicyRepo,
    controlReviews: controlSocket.controlReviews,
    controlDecisions: controlSocket.controlDecisions,
    controlRemote: controlSocket.controlRemote,
    controlEvents: controlSocket.controlEvents,
    fleet: fleets.fleet,
    fleetRepo: fleets.fleetRepo,
    fleetAdmission: fleets.fleetAdmission,
    redis,
    operator,
    operatorErasure,
    agent,
    passport,
    authority,
    serviceConnection,
    member,
    authEmail: notifications.authEmail,
    providerOAuth: credentials.providerOAuth,
    connectionVerifier: credentials.connectionVerifier,
    oauthApp: credentials.oauthApp,
    dropoff,
    accountability,
    securityEvent,
    proxy: proxy.proxy,
    proxyOperation: proxy.proxyOperation,
    proxyPostResponse: proxy.proxyPostResponse,
    notificationChannel: notifications.notificationChannel,
    notificationDestination: notifications.notificationDestination,
    notification,
    audit,
    usageRepo: repos.usageRepo,
    signer,
    identity,
    claimMatcher,
    workloadProviderRegistry: identityCore.workloadProviderRegistry,
    spiffeValidator: identityCore.spiffeValidator,
    spiffeTrustDomainRepo: identityCore.spiffeTrustDomainRepo,
    wimseValidator: identityCore.wimseValidator,
    wimseWorkloadProvider: identityCore.wimseWorkloadProvider,
    wimseIssuerRepo: identityCore.wimseIssuerRepo,
    oidcIdpConfigRepo: identityCore.oidcIdpConfigRepo,
    ssoDomains: identityCore.ssoDomains,
    // Exposed so the OIDC config route can wrap the client secret under
    // the SAME {operator_id, provider:'oidc'} context the provider
    // decrypts with. contextsMatch is exact, so the two must agree.
    kms,
    passportClaimsRepo: repos.passportClaimsRepo,
    claimRegistry,
    operatorSigningKey: claimSigning.operatorSigningKey,
    intentSimulation: intents.intentSimulation,
    intentApproval: intents.intentApproval,
    approvalGate: intents.approvalGate,
    mission,
    behavioralGenome,
    llmGateway: llm.llmGateway,
    piiRedactor: llm.piiRedactor,
    llmUsage,
    openRouterPricing: llm.openRouterPricing,
    twinOrchestration: missions.twinOrchestration,
    inboundWebhooks: inbound.inboundWebhooks,
    partnerTenants: partners.partnerTenants,
    emailChange: accountSecurity.emailChange,
    governanceApprovals: accountSecurity.governanceApprovals,
    cmek,
    cmekMigrationRepo,
    openRouter,
    operatorDetectorConfig: detectors.operatorDetectorConfig,
    operatorPiiConfig: detectors.operatorPiiConfig,
    detector: detectors.detector,
    l3Classifier: detectors.l3Classifier,
    analytics: seams.analytics,
    dossier: evidence.dossier,
    operatorDecision: evidence.operatorDecision,
    operatorReview: evidence.operatorReview,
    replay: evidence.replay,
    externalAnchor: evidence.externalAnchor,
    evidencePack: evidence.evidencePack,
  };

  // What only STACK's own deployment builds, in the order it was built before the split. The engine entry has none of it:
  // a route that still reads one gets the install's answer (config/wiring/install-services.ts) or NOT_CONFIGURED.
  const hosted = ext
    ? await ext.services({
        db,
        redis,
        kms,
        repos,
        signer,
        signing,
        claimSigning,
        features,
        networkClient,
        audit,
        auditArchive,
        auditObjectStore,
        providers,
        surfaceCredential,
        claimRegistry,
        operator,
        member,
        agent,
        passport,
        authority,
        mission,
        missions,
        securityEvent,
        notification,
        notifications,
        detector: detectors.detector,
        detectors,
        credentials,
        llm,
        inbound,
        proxy,
        controlCore,
        evidence,
        accountSecurity,
        partners,
        fleets,
        identityRegistry: identityCore.providerRegistry,
        engine,
      })
    : null;

  // What a deployment adds is filled by now; nothing changes it while the server is serving.
  registries.seal();
  // A deployment's service may be a getter (one that is off until its credential loads): the descriptors are copied, never the values.
  return Object.defineProperties({}, { ...Object.getOwnPropertyDescriptors(engine), ...(hosted ? Object.getOwnPropertyDescriptors(hosted) : {}) }) as Services & H;
}
