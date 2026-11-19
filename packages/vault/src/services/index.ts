export { OperatorService, assertOperatorActive } from './operator-service.js';
export {
  OperatorErasureService,
  type OperatorErasureServiceDeps,
  type OperatorErasureClaim,
  type OperatorErasureResult,
  type OperatorErasureErrorCode,
  type ErasureStep,
  type ErasureReplayReport,
  type OperatorErasureTransaction,
  type BeginOperatorErasureOptions,
} from './operator-erasure-service.js';
export { AgentService } from './agent-service.js';
export { FleetAdmissionService, decideFleetRequest, type FleetAdmission, type FleetPolicyAuthorization, type PrepareFleetAdmission } from './fleet-admission-service.js';
export {
  PassportService,
  REVOCATION_CHANNEL,
  identityClaimIdsForRefresh,
  identityClaimIsExpired,
  preserveIdentityClaimsForDelegation,
  revokePassportsByCarriedClaim,
  createMissionPassportRevoker,
  PassportRevokeFlagsError,
  type PassportRevokeOutcome,
  type RevocationEvent,
  type MissionLookup,
  type PassportAuthorityLookup,
  type PassportFleetLookup,
  type PassportJWTPayload,
  type PassportServiceDependencies,
} from './passport-service.js';
export {
  ServiceConnectionService,
  ConnectionPrincipalConflictError,
  standaloneServiceConnectionHooks,
  type ConnectionClosingHook,
  type ConnectionLifecycleEvent,
  type ConnectionOpenedHook,
  type ConnectionPrincipalConflictReason,
  type ExternalAgentGuard,
  type OAuthAppBinding,
  type OAuthAppRetiredCheck,
  type ProxyEligibility,
  type OAuthClientResolver,
  type ReconnectRequiredHandler,
  type ServiceConnectionHooks,
} from './service-connection-service.js';
export { OAuthLifecycleError, oauthClientIdDigest, type CredentialFields, type ReconnectReason } from './oauth-token-lifecycle.js';
export { AuditService } from './audit-service.js';
export type { AuditContext, AuditInput, AuditNotifyCallback } from './audit-service.js';
export { MemberService, type EmailVouchedBy } from './member-service.js';
export { SsoDomainService, type SsoDomainServiceOptions } from './sso-domain/sso-domain-service.js';
export { DnsNameAbsentError, systemDnsTxtResolver, type DnsTxtResolver, type SystemDnsTxtResolverOptions } from './sso-domain/dns-txt.js';
export {
  ConnectionVerifierService,
  type ConnectionVerificationResult,
} from './connection-verifier.js';
export { OauthAppService } from './oauth-app-service.js';
export { AccountabilityService } from './accountability-service.js';
export { NO_INTENT_DEVIATION_GRADER, type IntentDeviationGrader, type IntentDeviationInput } from './accountability/intent-deviation.js';
export {
  INTENT_DEVIATION_MAX_OUTPUT_TOKENS,
  INTENT_DEVIATION_SYSTEM_PROMPT,
  declaredAndObservedOf,
  intentDeviationFlagOf,
  intentDeviationUserInput,
  parseIntentDeviationResponse,
  type DeclaredAndObserved,
} from './accountability/intent-deviation-prompt.js';
export { SecurityEventService, DISMISSAL_SUPPRESS_SECONDS, DISMISSIBLE_SEVERITIES } from './security-event-service.js';
export type { SignalType, Severity, RecordEventInput } from './security-event-service.js';
export { ProxyService, pickSafeProxyResponseHeaders, type EgressSigner, type EgressSubject, type ProxyResult } from './proxy-service.js';
export {
  ProxyOperationService,
  SAFE_PROXY_REPLAY_HEADERS,
  PROXY_REPLACEMENT_WARNING,
  PROXY_REPLACEMENT_WARNING_HASH,
  PROXY_REPLACEMENT_WARNING_VERSION,
  hashProxyOperationKey,
  admissionOwnerHashFor,
  preparedAad,
  responseAad,
  scopeAad,
  postResponseAad,
  proxyOwnerTokenMatches,
  type PreparedProxyRequest,
  type AdmitProxyOperationInput,
  type AdmitProxyOperationResult,
  type ProxyReplayResult,
  type ProxyScopeDescriptor,
  type FreshProxyAuthority,
  type ProxyOperationMetadata,
  type StripeReconciliationTarget,
  type ProxyPostResponseContext,
  type ClaimedProxyPostResponseWork,
} from './proxy-operation-service.js';
export {
  ProxyPostResponseService,
  type ProxyPostResponseDeps,
  type ProxyPostResponseResult,
} from './proxy-post-response-service.js';
export {
  RuntimeAuthorityCompletionService,
  authorityBindingDigest,
} from './runtime-authority-completion-service.js';
export {
  NotificationService,
  type NotificationEvent,
  type NotificationSendMeter,
} from './notification-service.js';
export { ResendEmailService, observeResendSends, type ResendSendOutcome } from './resend-email-service.js';
export type { EmailSender } from './email-sender.js';
export {
  SmtpEmailError,
  SmtpEmailService,
  smtpConfigFromUrl,
  type SmtpConfig,
} from './smtp-email-service.js';
export { OperatorDetectorConfigService } from './operator-detector-config-service.js';
export { OperatorPiiConfigService } from './operator-pii-config-service.js';
export {
  DetectorService,
  type DetectorServiceDeps,
  type DetectorCtx,
  type DetectorOperatorOverrides,
  type PromptInjectionMatch,
  type PromptInjectionLlmResult,
  type InputScanResult,
  type InputScanner,
  type InputScanHandle,
  type InputScanStarter,
  type PendingInputScan,
  type ScanInputArgs,
  type OutputInjectionMatch,
  type OutputScanner,
  type OutputRedactor,
  type ScanInputResult,
  type ScanOutputResult,
} from './detector-service.js';
export {
  ClaimRegistryService,
  type RegisterClaimInput,
  type RegisterClaimResult,
  type RegisterClaimOptions,
  type ListBySubjectEntry,
  type ClaimRegistryDeps,
  type SimulationDivergenceHook,
  type BehavioralDriftHook,
} from './claim-registry-service.js';
// per-operator EdDSA signing keys for COSE_Sign1 claim
// envelopes. Used by ClaimRegistryService.signerForOperator factory
// for non-system operators; deployment key still signs everything for
// op_stack_system (wiring-layer carve-out in apps/api/src/config/services.ts).
export {
  OperatorSigningKeyService,
  SIGNING_KEY_ROTATED_CHANNEL,
  type OperatorSigningKeyServiceDeps,
} from './operator-signing-key-service.js';
// divergence detector
export {
  SimulationDivergenceDetector,
  type SimulationDivergenceDetectorDeps,
} from './simulation-divergence-detector.js';
// behavioral drift detector
export {
  BehavioralDriftDetector,
  type BehavioralDriftDetectorDeps,
  BEHAVIORAL_DRIFT_Z_MAX_THRESHOLD,
  BEHAVIORAL_DRIFT_L2_NORM_THRESHOLD,
  BEHAVIORAL_DRIFT_MIN_PRIOR_CALL_COUNT,
  BEHAVIORAL_DRIFT_FIRE_ONCE_TTL_SECONDS,
} from './behavioral-drift-detector.js';
// behavioral genome rollup (moved from apps/worker/src for
// reuse by both the worker poll loop AND apps/api/src/scripts smokes).
export { maybeRunBehavioralGenomeRollup } from './behavioral-genome-rollup.js';
// LLM gateway substrate (provider URL resolution + header
// injection + streaming SSE passthrough for /v1/llm/<provider>/* routes).
export {
  LlmGatewayService,
  LLM_PROVIDERS,
  LLM_IMAGE_ENDPOINTS,
  type LlmProvider,
  type LlmImageResult as LlmGatewayImageResult,
  type LlmProviderConfig,
  type LlmUsage,
  type LlmGatewayResult,
  type LlmGatewayForwardArgs,
  type LlmGatewayStreamingResult,
} from './llm-gateway-service.js';
// PII redactor (catalog + scanForPii live in @stack/shared
// the PiiRedactor instance is constructed in apps/api/src/config/services.ts
// and passed to LlmGatewayService.redactUserMessages).
export { PiiRedactor, type RedactResult } from './pii-redactor.js';
// Twin runtime orchestration substrate. NO call sites
// invoke this yet — 5.3.3 wires startTwinForMission into MissionService.open
// (gated by agent.twin_policy) + mirrorIntent into a ClaimRegistryService
// post-persist hook for intent_claim. 5.3.4 replaces evaluateDivergence
// stub with real math. 5.3.5 wires the twin EXECUTION runtime.
export {
  TwinOrchestrationService,
  type TwinOrchestrationServiceDeps,
  type StartTwinForMissionInput,
  type StartTwinForMissionResult,
  type MirrorIntentInput,
  type EvaluateDivergenceInput,
  type EvaluateDivergenceResult,
} from './twin-orchestration-service.js';
// LLM gateway cost rollup. Stateless service composed
// from LlmUsageRepository + the hosted wallet's durable fee settlement +
// SecurityEventService + OpenRouterPricingResolver. Called from the
// /v1/llm/<provider>/* route handler's writePostCallTelemetry hook
// after every successful forward.
export {
  LlmUsageService,
  type LlmUsageServiceDeps,
  type RecordUsageInput,
  type RecordUsageResult,
  type GatewayAuthorization,
  type AuthorizeGatewayInput,
} from './llm-usage-service.js';
export { OpenRouterPricingResolver } from './openrouter-pricing.js';
// DossierService. Mission-scoped human-authored
// post-mortem surface (create + findByMission + update). Routes through
// ClaimRegistryService.registerClaim with subjectOverride='operator';
// enforces mission terminal-state gate before accepting a dossier.
export {
  DossierService,
  type DossierServiceDeps,
  type DossierMissionLookup,
  type CreateDossierInput,
  type UpdateDossierInput,
  type CreateDossierResult,
  type UpdateDossierResult,
  type DossierEnvelope,
} from './dossier-service.js';
// EvidencePackService. Producer for the portable cryptographic bundle. Resolves scope → claim set, builds
// Merkle root, signs audit chain anchor head, builds canonical
// manifest JSON, persists the signed EvidencePackClaim, optionally
// adds the STACK system co-signature.
export {
  EvidencePackService,
  type EvidencePackServiceDeps,
  type ExportOptions,
  type ExportResult,
  type StoredEvidencePackManifest,
  type InlineJwksMaterial,
  type OperatorSignerResolver,
  type InlineSchemasResolver,
} from './evidence-pack-service.js';
// ExternalAnchorService. Daily-cron-driven publisher
// for operator chain-head anchors, handed to a pluggable publisher: the engine ships
// the noop one and a deployment that publishes wires its own.
export {
  ExternalAnchorService,
  NoopAnchorPublisher,
  type ExternalAnchorServiceDeps,
  type AnchorPublisher,
  type AnchorPayload,
  type AnchorResult,
} from './external-anchor-service.js';
// ReplayService. Interpretation layer over a mission's
// signed claim set. Live DB path + from-claims path both route through
// the shared reconstructTimeline helper in @stack/shared so dashboard
// + verifier package emit byte-identical timelines.
export { ReplayService, type ReplayServiceDeps } from './replay-service.js';
export {
  OperatorDecisionService,
  type OperatorDecisionServiceDeps,
  type GovernanceDecided,
  type OperatorDecisionRequest,
  type OperatorDecisionResult,
  type GovernanceOperatorDecisionResult,
} from './operator-decision-service.js';
export {
  OperatorReviewService,
  type OperatorReviewServiceDeps,
  type OperatorReviewMissionLookup,
  type OperatorReviewMemberLookup,
  type OperatorReviewEnvelope,
  type OperatorReviewWriteResult,
  type OperatorReviewSource,
} from './operator-review-service.js';
// pre-execution dry-run producer.
export {
  IntentSimulationService,
  type IntentSimulationDeps,
  type SimulateInput,
  type SimulateResult,
  type SimulateDiagnostics,
  type OveragePeekSnapshot,
  type SimulableMeter,
} from './intent-simulation-service.js';
// pre-execution approval gate.
export {
  IntentApprovalService,
  type IntentApprovalDeps,
  type SubmitInput as IntentApprovalSubmitInput,
  type SubmitResult as IntentApprovalSubmitResult,
  type ApproveInput as IntentApproveInput,
  type RejectInput as IntentRejectInput,
  type DecisionResult as IntentApprovalDecisionResult,
  type ApprovalRowView,
} from './intent-approval-service.js';
// universal approval gate +
// requires_unmet enforcement helper. Shared substrate for producer
// (proxy/skills/a2a) and simulator (section 2g).
export {
  ApprovalGateService,
  type ApprovalGateDeps,
  type GateInput,
  type GateResult,
  type GateReason,
  type GateDenialMetadata,
} from './approval-gate-service.js';
export {
  enforceRequires,
  type RequiresEnforcerDeps,
  type RequiresInput,
  type RequiresResult,
} from './requires-enforcer.js';
// CMEK (deferral 1 of the Signed Primitive epic)
export {
  CmekService,
  CMEK_LONG_LIVED_STORES,
  CMEK_EPHEMERAL_STORES,
  type CmekStore,
  type CmekStatusSnapshot,
  type CmekServiceDeps,
} from './cmek-service.js';
export { CmekMigrationWorker, type CmekMigrationStep } from './cmek-migration-worker.js';
// Mission substrate (of the Signed Primitive epic)
export {
  MissionService,
  DEFAULT_CAP_BEHAVIOR,
  effectiveCapBehavior,
  missionReviewId,
  coverageWindowStart,
  MissionRecipientPinReader,
  PassportLineageReader,
  type MissionRecipients,
  type MissionServiceDeps,
  type MissionPassportRevoker,
  type MissionActionCounter,
  type MissionActionReservation,
  type MissionPausedEvent,
  type ReviewInput as MissionReviewServiceInput,
  type ReviewResult as MissionReviewResult,
  type MissionView,
  type MissionListItem,
  type MissionListResult,
  type OpenInput as MissionOpenInput,
  type OpenResult as MissionOpenResult,
  type CompleteInput as MissionCompleteInput,
  type CompleteResult as MissionCompleteResult,
  type RevokeInput as MissionRevokeInput,
  type RevokeResult as MissionRevokeResult,
  type GateReason as MissionGateReason,
  type GateVerdict as MissionGateVerdict,
} from './mission-service.js';
// Behavioral genome producer (sub chunk of the Signed Primitive epic)
export {
  BehavioralGenomeService,
  type BehavioralGenomeServiceDeps,
  type BehavioralDiffResult,
} from './behavioral-genome-service.js';
// hosted inbound webhook receiver
export {
  InboundWebhookService,
  type InboundWebhookServiceDeps,
  type ReceiveInput as InboundWebhookReceiveInput,
  type ReceiveResult as InboundWebhookReceiveResult,
} from './inbound-webhook-service.js';
// partner-tenancy primitive (platform partner provisions
// isolated child operators on behalf of their customers).
export {
  PartnerTenantService,
  type PartnerTenantServiceDeps,
  type CreateTenantInput,
  type CreateTenantResult,
  type TenantView,
  type TenantPlanView,
  TenantTierNotAllowedError,
  TenantLimitReachedError,
  TENANT_BILLING,
} from './partner-tenant-service.js';
// operate-vs-govern step-up (governance approvals).
export {
  GovernanceApprovalService,
  hashGovernancePayload,
  type GovernanceActionPreviews,
  type GovernanceApprovalDeps,
} from './governance-approval-service.js';
export {
  getExtractor as getInboundWebhookExtractor,
  genericExtractor,
} from './inbound-webhook-extractors/index.js';
export type {
  InboundWebhookExtractor,
  SignatureVerificationInput,
  SignatureVerificationResult,
  ExtractScanContentInput,
  ExtractScanContentResult,
  ExtractDedupeKeyInput,
  InboundExtractorSource,
  InboundDeliveryHandler,
  InboundDeliverySource,
  InboundManagedEnd,
  InboundManagedEndSource,
} from './inbound-webhook-extractors/index.js';
export { ManagedInboundWebhooks, type ManagedInboundWebhooksDeps } from './inbound-webhook-managed-rows.js';

// cold archive for the audit chain.
export { AuditArchiveService, type ArchiveErasePrefix } from './audit-archive-service.js';
export {
  guardedDownload,
  presentGeneratedFile,
  INLINE_FILE_MAX_BYTES,
  type FileDownload,
  type FileOwner,
  type GeneratedFileSink,
} from './generated-files.js';
export type {
  ArchiveResult,
  ArchiveSegment,
  ArchivedRow,
  AuditArchiveServiceDeps,
} from './audit-archive-service.js';
export { MemoryObjectStore, S3ObjectStore, STREAM_PART_BYTES, ObjectStoreUnavailableError, isDurable } from './object-store.js';
export type {
  ObjectStore,
  ObjectStoreFailureReason,
  StreamingObjectStore,
} from './object-store.js';
export {
  ARCHIVE_STORE_SITES,
  ARCHIVE_STORE_STATUS_TTL_SECONDS,
  archiveStoreStatusKey,
  probeObjectStore,
  readArchiveStoreStatus,
} from './object-store-health.js';
export type { ArchiveStoreProbeResult, ArchiveStoreSite, ArchiveStoreStatus } from './object-store-health.js';
export { EmailChangeService } from './email-change-service.js';
export type { EmailChangeAuditContext, EmailChangeDeliveryClaim } from './email-change-service.js';
export {
  AuthorityService,
  PinnedAuthorityApprovalDecisionVerifier,
  StackDirectPostJwtV1Protocol,
  STACK_DIRECT_POST_PROTOCOL_KEY,
  STACK_DIRECT_POST_PROTOCOL_VERSION,
  STACK_DIRECT_POST_REQUEST_AUTH_METHOD,
  STACK_DIRECT_POST_DELIVERY_MODE,
  STACK_PROXY_BRIDGE_PROTOCOL_KEY,
  STACK_PROXY_BRIDGE_PROTOCOL_VERSION,
  AUTHORITY_CLOCK_TOLERANCE_SECONDS,
  AUTHORITY_ASSERTION_MAX_SECONDS,
  AUTHORITY_PRESENTATION_MAX_SECONDS,
  AUTHORITY_RECEIPT_MAX_SECONDS,
  AUTHORITY_VERIFICATION_CHALLENGE_SECONDS,
  authorityAgentKeyThumbprint,
  authorityMandateTermsDigest,
  type AuthorityServiceDeps,
  type AuthorityRepositoryPort,
  type AuthorityClaimIssuer,
  type AuthorityProofAdapter,
  type AuthorityProofRecord,
  type AuthorityProofProfileVersionRecord,
  type AuthorityBindingRecord,
  type AuthorityBindingProofRecord,
  type AuthorityUseInsert,
  type AuthorityUseRecord,
  type AuthorityReceiverRecord,
  type AuthorityReceiverProfileRecord,
  type ReceiverTransactionReceiptRecord,
  type AuthorityRuntimeBoundary,
  type AuthorityMutationActor,
  type AuthorityEvaluationResult,
  type AuthorityReceiverAuthContext,
  type AuthorityPresentationSigner,
  type AuthorityPresentationTransport,
  type AuthorityPresentationProtocol,
  type AuthorityProofCollectionWorkflowRecord,
} from './authority-service.js';
export {
  authorityConstraintIsNarrower,
  authorityScopeIsNarrower,
  disclosurePolicyIsNarrower,
  authorityDelegationViolations,
} from './authority-policy.js';
export {
  assertBrowserDecisionSession,
  type BrowserDecisionSession,
} from './browser-decision-session.js';
export {
  ProxyAccountingReconciler,
  type ProxyAccountingProjectionStore,
  type ProxyAccountingReconcileResult,
} from './proxy-accounting-reconciler.js';

export { FleetService } from './fleet-service.js';






// The control socket: who decides for a customer, and where their record goes.
export * from './control-socket/index.js';
export * from './control-policy/index.js';

// The seams the engine reaches a deployment's money, plan and messaging through (each has a null for an install with none).
export * from './spend/spend-ledger.js';
export * from './spend/account-model-ports.js';
export * from './entitlements/entitlements.js';
export * from './entitlements/plan-limits.js';
export * from './sms-transport.js';
