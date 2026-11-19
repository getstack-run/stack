import type { Database, OpenRouterService } from '@stack/shared';
import type { ControlDecisionEngine } from '../../lib/control-socket/engine.js';
import type { RemoteDecider } from '../../lib/control-socket/remote-decider.js';
import type { ControlEventsDelivery, ControlPolicyRepository, ControlPolicyService, ControlPosture, ControlReviewService, ControlSocketRepository, ControlSocketService, UsageRepository, OperatorService, OperatorErasureService, AgentService, FleetService, FleetRepository, FleetAdmissionService, PassportService, ServiceConnectionService, MemberService, AuditService, ConnectionVerifierService, OauthAppService, AccountabilityService, NotificationChannelRepository, NotificationDestinationRepository, SecurityEventService, ProxyService, ProxyOperationService, ProxyPostResponseService, NotificationService, EmailSender, EmailChangeService, OperatorDetectorConfigService, OperatorPiiConfigService, KmsService, StreamingObjectStore, PassportSigner, IdentityVerificationService, ClaimMatchingService, SpiffeSvidValidator, WorkloadProviderRegistry, SpiffeTrustDomainRepository, WimseWitValidator, WimseWorkloadProvider, WimseIssuerRepository, OidcIdpConfigRepository, SsoDomainService, PassportClaimsRepository, ClaimRegistryService, OperatorSigningKeyService, IntentSimulationService, IntentApprovalService, ApprovalGateService, MissionService, BehavioralGenomeService, LlmGatewayService, PiiRedactor, LlmUsageService, OpenRouterPricingResolver, TwinOrchestrationService, InboundWebhookService, PartnerTenantService, GovernanceApprovalService, CmekService, CmekMigrationRepository, DetectorService, DossierService, OperatorDecisionService, OperatorReviewService, ReplayService, EvidencePackService, ExternalAnchorService, AuthorityService } from '@stack/vault';
import type { DropoffService } from '@stack/dropoff';
import type { ProviderOAuthService } from '../../services/provider-oauth-service.js';
import type { AnalyticsSink } from '../../lib/analytics-sink.js';
import type { ActionMeter } from '../../lib/action-meter.js';
import type { BrowserSessions, ConsoleBridge } from '../../lib/browser-session.js';
import type { IdentityVerificationCharge } from '../../lib/identity-verification-charge.js';
import type { ModelAccessPolicy } from '../../lib/model-access-policy.js';
import type { EngineRegistries } from '../registries.js';
import type { AccountDirectory, ActionLimitCounter, EntitlementResolver, SmsTransport, SpendLedger } from '@stack/vault';
import type { L3ClassifierSource } from '../../detectors/l3-classifier.js';
import type { GeneratedFileSink } from '../../lib/generated-files.js';
import type { RedisClient } from './infra.js';
import type { StepUpWaiver } from '../../middleware/governance-stepup.js';
import type { FeatureGate } from '../licence-service.js';
import type { NetworkClientServices } from '../network-client.js';
import type { AccountDetection, AgentAccountLifecycle, AccountCallSettlement } from '@stack/vault';

/**
 * What the engine builds, and what its routes read. STACK's own deployment adds its services on top
 * (the deployment's own services type); the engine alone never has them.
 */
export interface Services {
  db: Database;
  /**
   * The seams. Each is the engine's interface with the deployment's object behind it: STACK's own
   * hosted objects on its deployment, the null implementations on an install. Callers still read the
   * hosted fields below; they move to these as each caller is switched.
   */
  /** Counts every agent action once (the plan behind it is the deployment's). */
  actionMeter: ActionMeter;
  /** What engine services ask of a wallet. */
  spend: SpendLedger;
  /** The plan behind each call. `billingAccounts` below is the same object. */
  entitlements: EntitlementResolver;
  /** Which agent belongs to which account. */
  accountDirectory: AccountDirectory;
  /** The counters of an agent account's action and cents windows. */
  actionLimits: ActionLimitCounter;
  /** The Console's browser sessions. */
  browserSessions: BrowserSessions;
  /** The Console's server glue, when there is a Console. */
  consoleBridge: ConsoleBridge | null;
  /** What a verified identity costs, charged after the first. */
  identityVerificationCharge: IdentityVerificationCharge;
  /** Whose key a model gateway call runs on. */
  modelAccessPolicy: ModelAccessPolicy;
  /** Where a file a model made is saved; null on a deployment with no drive. */
  generatedFiles: GeneratedFileSink | null;
  /** How a text message is sent. */
  smsTransport: SmsTransport | null;
  /** What a deployment adds to the engine, filled before the first request and sealed. */
  registries: EngineRegistries;
  /** Lets the owner's own API key through a governance step-up. Absent on an install: every step-up asks for its approval. */
  stepUpWaiver?: StepUpWaiver;
  /**
   * Which enterprise features are on. STACK's hosted deployment gates them by
   * plan where it always did, so its gate says yes; a self-managed install's
   * licence key decides (config/licence-service.ts).
   */
  features: FeatureGate;
  /** STACK's hosted network, for a self-managed install that chose it: live detection rules and the L3 classifier. */
  networkClient: NetworkClientServices;
  redis: RedisClient;
  /** The audit and evidence object store (S3 in production); the health probe reads it. */
  auditObjectStore: StreamingObjectStore;
  operator: OperatorService;
  /** Account erasure, with the steps a deployment adds; `stack-engine erasures reapply` reads the erased list through it. */
  operatorErasure: OperatorErasureService;
  agent: AgentService;
  passport: PassportService;
  /** Principal, proof, mandate, receiver, presentation, and runtime authority rails. */
  authority: AuthorityService;
  serviceConnection: ServiceConnectionService;
  member: MemberService;
  /** Auth-grade transactional delivery. Null only in local development. */
  authEmail?: EmailSender | null;
  /** API-owned third-party OAuth exchange and vault-write boundary. */
  providerOAuth: ProviderOAuthService;
  connectionVerifier: ConnectionVerifierService;
  oauthApp: OauthAppService;
  dropoff: DropoffService;
  accountability: AccountabilityService;
  securityEvent: SecurityEventService;
  proxy: ProxyService;
  /** Durable admission, dispatch fencing, replay, and accounting for proxy writes. */
  proxyOperation: ProxyOperationService;
  /** Resumable bookkeeping that can never dispatch provider traffic. */
  proxyPostResponse: ProxyPostResponseService;
  notificationChannel: NotificationChannelRepository;
  notificationDestination: NotificationDestinationRepository;
  notification: NotificationService;
  audit: AuditService;
  /** Durable closed-day usage plus the live current UTC day. */
  usageRepo: UsageRepository;
  signer: PassportSigner;
  identity: IdentityVerificationService;
  claimMatcher: ClaimMatchingService;
  /** Workload-identity dispatch (SPIFFE today; future providers extend).
   * The /v1/workload/passport route resolves the trust-domain config
   * from DB and passes it through registry.get('spiffe').acceptSvid().
   * Separate from `identityProviderRegistry` because workload-flow and
   * human-flow have fundamentally different shapes. */
  workloadProviderRegistry: WorkloadProviderRegistry;
  /** SPIFFE JWT-SVID validator — held by the workload provider but
   * exposed in the bundle so the trust-domain repo can wire its
   * persistor and the route layer can stub it in tests. */
  spiffeValidator: SpiffeSvidValidator;
  /** spiffe_trust_domains repo. Doubles as the JwksPersistor for the
   * validator's fail-open durability layer. */
  spiffeTrustDomainRepo: SpiffeTrustDomainRepository;
  /** WIMSE Workload Identity Token validator. Standalone class (not
   * registered through the WorkloadProviderRegistry because the
   * SPIFFE-shaped interface does not fit the WIT shape cleanly). */
  wimseValidator: WimseWitValidator;
  /** WIMSE issuer provider. Used directly by /v1/workload/wit. */
  wimseWorkloadProvider: WimseWorkloadProvider;
  /** wimse_issuers repo. Doubles as the WimseJwksPersistor for the
   * WIT validator's fail-open durability layer. */
  wimseIssuerRepo: WimseIssuerRepository;
  /** OIDC IdP configuration repo. One IdP per operator
   * in v1; CRUD + JWKS last-known-good persistor for the OIDC provider's
   * fail-open path. */
  oidcIdpConfigRepo: OidcIdpConfigRepository;
  ssoDomains: SsoDomainService;
  kms: KmsService;
  /** passport_claims repo. attachClaim writes here; revoke cascades
   * here; audit middleware reads claim hashes from here at write time. */
  passportClaimsRepo: PassportClaimsRepository;
  /** COSE_Sign1 envelope path for signed claims.
   * New SVID attestations + future claim types attach via
   * claimRegistry.registerClaim(). Coexists with the legacy
   * passport.attachClaim path during the cutover window; both write
   * to the same passport_claims table but with different shapes
   * (envelope_cose set vs claim_hash + signature set). */
  claimRegistry: ClaimRegistryService;
  /** Per-operator EdDSA signing-key service. The
   *  signerForOperator factory inside ClaimRegistryService delegates
   *  here for non-system operators when PER_OPERATOR_CLAIM_SIGNING_ENABLED
   *  is true. Exposed on the bundle so the rotation endpoint and
   *  the per-operator JWKS endpoint can read it directly. */
  operatorSigningKey: OperatorSigningKeyService;
  /** pre-execution dry-run producer.
   * Mirrors proxy.ts policy chain statically (scope + constraints +
   * accountability + tier_limit), emits a signed intent_simulation claim
   * via claimRegistry. Wire-up: takes the passport JWT as
   * input (full ServiceScope[] lives only in the signed token, NOT on
   * the passports row). */
  intentSimulation: IntentSimulationService;
  /** pre-execution approval gate.
   * submit() registers the intent_claim + (by default) attaches an
   * intent_simulation claim, then writes an intent_approvals row with
   * status='pending'. approve()/reject() transition via atomic CAS.
   * Reject auto-revokes the passport via the onReject hook wired here.
   * Opt-in for v1: existing producers (proxy/skills/a2a) do NOT call
   * this; only callers that explicitly hit POST /v1/intents/submit. */
  intentApproval: IntentApprovalService;
  /** universal producer-side
   * approval gate. Consumes from intent_approvals rows that
   * /v1/intents/submit + /approve created. Producer routes (proxy,
   * skills, a2a) call services.approvalGate.check() to either skip
   * (non-enforced mode), continue with an approved IntentClaim in
   * hand (matching call shape), or 403 with a signed intent_denial.
   * markConsumed() flips approved → consumed via atomic CAS after a
   * successful 2xx-3xx outcome. */
  approvalGate: ApprovalGateService;
  /** mission lifecycle owner. Sub-passport
   * bounded units of agent work with declared scope, six resource caps,
   * output shape contract, counterparty allowlist. The signed mission
   * claim is operator-scoped (subjectOverride='operator'); passports
   * issued under a mission carry `mission_ids[]` in their JWT and the
   * proxy gate enforces mission scope + caps on every action.
   *
   * every agent Passport is bound to exactly one Mission, and
   * complete()/revoke() revoke the Mission's Passports in the same
   * transaction (passportRevoker, wired in wiring/missions.ts). */
  mission: MissionService;
  /** The engine's view of the deployment's agentAccounts (the null implementation on an install). */
  agentAccounts: AgentAccountLifecycle;
  /** The engine's view of the deployment's accountDetection (the null implementation on an install). */
  accountDetection: AccountDetection;
  fleet: FleetService;
  fleetRepo: FleetRepository;
  fleetAdmission: FleetAdmissionService;
  /** passport-scoped behavioral fingerprint producer.
   * Wired into AccountabilityService via setBehavioralGenomeService so
   * submitCheckpoint fires a fire-and-forget genome emit per checkpoint.
   * Also constructed identically in the worker for the daily UTC rollup
   * cron (apps/worker/src/worker.ts). A controls feature: the rollup asks for the
   * passports of accounts with controls on only. */
  behavioralGenome: BehavioralGenomeService;
  /** LLM gateway substrate. Provider URL resolution +
   * header injection + streaming SSE passthrough for the
   * /v1/llm/<provider>/* route family. Stateless; takes API key as an
   * argument on each call (operator's vault credential, not STACK's). */
  llmGateway: LlmGatewayService;
  /** PII redactor. Replaces every PII match in user
   * messages with `[REDACTED:<category>]`. Idempotent (placeholders don't match any catalog
   * pattern). Catalog + scanForPii live in @stack/shared. */
  piiRedactor: PiiRedactor;
  /** The engine's view of the deployment's accountModelBilling (the null implementation on an install). */
  accountModelBilling: AccountCallSettlement;
  /** Cost authorization and usage records for customer-key gateway calls
   * and STACK-key product calls. Wallet-funded work creates an atomic hold
   * before the provider call. */
  llmUsage: LlmUsageService;
  /** OpenRouter price feed. Public /api/v1/models
   * endpoint cached in Redis for 24h. Consumed by LlmUsageService.lookup
   * for openrouter-provider calls. */
  openRouterPricing: OpenRouterPricingResolver;
  /** Twin runtime orchestration substrate. MissionService.open starts a
   * twin run (gated by agent.twin_policy) and a ClaimRegistryService
   * post-persist hook mirrors each intent claim into the active twin run. */
  twinOrchestration: TwinOrchestrationService;
  /** hosted inbound webhook receiver. Operator creates a
   * webhook row + gets back a URL + HMAC secret; providers
   * POST inbound to /v1/inbound/:provider/:slug; STACK verifies
   * the signature, runs the detector, writes security_event on block,
   * forwards to operator's configured downstream URL on clean. Closes
   * the gap left by service connectors (which only cover agent-initiated
   * calls; webhook is server-initiated push). */
  inboundWebhooks: InboundWebhookService;
  /** partner-tenancy. A platform partner provisions isolated child operators
   * on behalf of their customers. The partner has is_partner=true on their operator
   * row; child operators have parent_operator_id=partner.id. Children
   * have their own audit chain, KMS context, signing key, and webhook
   * surface. The partner sees aggregate counters but NEVER child audit
   * content. Routes mounted under /v1/partner/* via requirePartner. */
  partnerTenants: PartnerTenantService;
  /** Transferring the address an account signs in with. */
  emailChange: EmailChangeService;
  /** operate-vs-govern step-up: pending/approve/consume for
   * the four gated governance actions. Decide is dashboard-session-only. */
  governanceApprovals: GovernanceApprovalService;
  /** Customer-Managed Encryption Keys. Lets enterprise operators bring
   * their own AWS KMS key as the KEK for every operator-owned ciphertext
   * store. The KmsService consumes the operator state via a resolver wired
   * in wiring/crypto-and-signing.ts; the worker process consumes
   * CmekService directly to run the eager re-encryption migration. */
  cmek: CmekService;
  cmekMigrationRepo: CmekMigrationRepository;
  /** Operator-level customization of detectors (custom regex,
   * whitelist, severity overrides, master-switch). Tier-gated at the
   * API route layer to studio+; service itself is unrestricted so
   * background workers can read it regardless of operator tier. */
  operatorDetectorConfig: OperatorDetectorConfigService;
  /**
   * Per-operator PII redaction config (threshold + country scope). Read on
   * the LLM gateway hot path, so it is cache-fronted the same way the
   * detector config is.
   */
  operatorPiiConfig: OperatorPiiConfigService;
  /** Prompt-injection detector orchestration. Both proxy.ts and the
   * LLM gateway call into this
   * single service so the detector chain stays consistent across
   * inbound surfaces. Scanner functions are injected at bootstrap
   * from apps/api/src/detectors/* — the service owns orchestration,
   * the detector files own pattern catalogs + LLM funnels. */
  detector: DetectorService;
  /** The classifier of a scan's third layer, one per scan, or null when this deployment runs none. */
  l3Classifier: L3ClassifierSource | null;
  /** OpenRouter client for LLM-backed work (sealed execution, accountability
   * checkpoint summaries, L3 prompt-injection classifier). Null if no
   * credential is configured (dev without OPENROUTER_API_KEY) — callers
   * must handle null and gracefully skip LLM-dependent features. */
  openRouter: OpenRouterService | null;
  /** PostHog server-side capture for activation milestones. Routes the
   * first_* events (first_passport_issued, first_proxy_call,
   * first_service_connected, mcp_setup_completed). Silent no-op when no
   * POSTHOG_API_KEY env var is set. The deployment supplies the sink. */
  analytics: AnalyticsSink;
  /** DossierService. Mission-scoped post-mortem narrative
   * read/write surface. The dashboard reads through findByMission; create
   * + update go through the POST /v1/missions/:id/dossier route. */
  dossier: DossierService;
  operatorDecision: OperatorDecisionService;
  operatorReview: OperatorReviewService;
  /** ReplayService. Forensic timeline reconstruction over
   * a mission's signed claim set. Live DB path consumes
   * PassportClaimsRepository.findInMissionScope; the from-claims path
   * shares the same @stack/shared helper as the open-source verifier
   * for byte-identical output between dashboard + verifier. */
  replay: ReplayService;
  /** ExternalAnchorService. Read-side wiring in the api
   * (consumed by EvidencePackService.export to populate
   * external_chain_anchors[]). The daily-cron WRITE path lives in the
   * worker (apps/worker/src/worker.ts) so the api never publishes
   * anchors itself. */
  externalAnchor: ExternalAnchorService;
  /** EvidencePackService. Production wiring with
   * full deps: operator signer resolver + STACK system signer for
   * co-sig + inline JWKS + inline schemas + external chain anchor
   * lookup. POST /v1/evidence-packs calls export() here. */
  evidencePack: EvidencePackService;
  /** The control socket's configuration: who decides for a customer, the addresses, secrets and checked kinds (wiring/control-socket.ts). */
  controlSocket: ControlSocketService;
  controlSocketRepo: ControlSocketRepository;
  /** Which of STACK's hosted checks apply to a kind of action: the one reading the decision engine and every inline check share. */
  controlPosture: ControlPosture;
  /** Policies: the configuration behind hosted controls, per agent and one default per customer. */
  controlPolicies: ControlPolicyService;
  controlPolicyRepo: ControlPolicyRepository;
  /** Actions a policy held for a person, and their approvals. */
  controlReviews: ControlReviewService;
  /** The counters of a policy's action limits. */
  /** Asks the customer's decider once per checked action (`decideControl` in lib/control-decision.ts is the call sites' entry). */
  controlDecisions: ControlDecisionEngine;
  /** The customer's own decision server, for the setup check and the test button. */
  controlRemote: RemoteDecider;
  /** Delivers the customer's record to their events address. */
  controlEvents: ControlEventsDelivery;
}
