import { HttpClient, type ClientOptions } from './client.js';
import { AgentService } from './services/agents.js';
import { PassportService } from './services/passports.js';
import { ServiceService } from './services/services.js';
import { CredentialService } from './services/credentials.js';
import { DropoffService } from './services/dropoffs.js';
import { SkillService } from './services/skills.js';
import { IdentityService } from './services/identity.js';
import { TeamService } from './services/team.js';
import { DeliveryMethodService } from './services/delivery-methods.js';
import { NotificationService } from './services/notifications.js';
import { SecurityEventService } from './services/security-events.js';
import { ProxyService } from './services/proxy.js';
import { ScanService } from './services/scan.js';
import { UsageService } from './services/usage.js';
import { BillingService } from './services/billing.js';
import { GovernanceService } from './services/governance.js';
import { AuditService } from './services/audit.js';
import { DetectorConfigService } from './services/detector-config.js';
import { PiiConfigService } from './services/pii-config.js';
import { IntentsService } from './services/intents.js';
import { MissionsService } from './services/missions.js';
export { MISSION_RECIPIENT_ANY_PATH } from './services/missions.js';
export { createAgentTokenProvider } from './agent-auth.js';
export { delegationScopesFromToken } from './delegation-scopes.js';
import { FleetsService } from './services/fleets.js';
export * from './services/fleets.js';
import { EvidencePacksService } from './services/evidence-packs.js';
import { LlmService } from './services/llm.js';
import { InboundWebhookService } from './services/inbound-webhooks.js';
import { AccountsService } from './services/accounts.js';
import { ChatChannelsService } from './services/chat-channels.js';
import { DriveService } from './services/drive.js';
import { MemoryService } from './services/memory.js';
import { BrainService } from './services/brain.js';
import { FlaggedContentService } from './services/flagged-content.js';
import { CatalogueService } from './services/catalogue.js';
import { WebsiteService } from './services/website.js';
import { AgentIdentityService } from './services/agent-identity.js';
import { PaymentsService } from './services/payments.js';
import { PostService } from './services/post.js';
import { ControlSocketService } from './services/control-socket.js';
import { NetworkService } from './services/network.js';
import { ControlPoliciesService, ControlReviewsService } from './services/control-policies.js';
import { WakesService } from './services/wake.js';
import { MessageAccessService } from './services/message-access.js';
import { TrustService } from './services/trust.js';
import { CalendarService } from './services/calendar.js';
import { MeetingsService } from './services/meetings.js';
import { RentAHumanService } from './services/rentahuman.js';
import {
  PartnerAccountsService,
  mintOutboundPassportImpl,
  type MintOutboundPassportInput,
  type MintOutboundPassportResult,
} from './services/partner-accounts.js';
import { PassportSession } from './services/passport-session.js';
import type { IssuePassportInput, IssuedPassport } from './types.js';
import { AuthorityService } from './services/authority.js';

export class Stack {
  private readonly client: HttpClient;

  readonly agents: AgentService;
  readonly passports: PassportService;
  /** Operator authority principals, proofs, bindings, receivers, and evidence reads. */
  readonly authority: AuthorityService;
  readonly services: ServiceService;
  readonly credentials: CredentialService;
  readonly dropoffs: DropoffService;
  readonly skills: SkillService;
  readonly identity: IdentityService;
  readonly team: TeamService;
  readonly deliveryMethods: DeliveryMethodService;
  readonly notifications: NotificationService;
  readonly securityEvents: SecurityEventService;
  readonly proxy: ProxyService;
  readonly scan: ScanService;
  readonly usage: UsageService;
  /** Agent-account subscriptions: platform and controls checkout, status, resume without controls. */
  readonly billing: BillingService;
  /** Read one governance approval: its status, the hash of the change it covers and its link. */
  readonly governance: GovernanceService;
  readonly audit: AuditService;
  readonly detectorConfig: DetectorConfigService;
  readonly piiConfig: PiiConfigService;
  /** intent simulate / submit / approve / reject. */
  readonly intents: IntentsService;
  /** Mission lifecycle, activity, and Operator review reads. */
  readonly missions: MissionsService;
  readonly fleets: FleetsService;
  /** Create, read, download, and list portable Signed records. */
  readonly evidencePacks: EvidencePacksService;
  /** LLM gateway. Provider-compatible call shape +
   * usage observability. Pair with `issuePassport(...)` for
   * lifecycle-managed passports across many calls. */
  readonly llm: LlmService;
  /** hosted inbound webhook surface (AgentMail, generic).
   * Operator creates a webhook + gets back a URL + HMAC secret to paste
   * into the provider's webhook config. STACK runs the detector on
   * inbound content before forwarding to a configurable downstream URL. */
  readonly inboundWebhooks: InboundWebhookService;
  /** Agent accounts: open, read, close; messages, mail and texts, workspace
   * runs, browser and card checkout, wallet payments. */
  readonly accounts: AccountsService;
  /** Chat channels: bind the Telegram, text and Slack identities the owner approves small held payments from (within the limits set in the policy), and install STACK's Slack app. */
  readonly chatChannels: ChatChannelsService;
  /** The agent drive: files an account's agents write, private to one agent or shared with the account, with an optional expiry and signed share links. Every file is untrusted content. */
  readonly drive: DriveService;
  /** Account memory: Graphiti, a graph of facts with the time each held, one per account and shared by its agents. The methods are Graphiti's own tools: `addMemory`, `addTriplet`, `searchNodes`, `searchMemoryFacts`, `getEpisodes`, `getEntityEdge`, `getEpisodeEntities`, `deleteEpisode`, `deleteEntityEdge` and `summarizeSaga`; the account's own entity types with `listEntityTypes`, `createEntityType`, `updateEntityType` and `retireEntityType`; what each write changed with `getHistory`, and `undoWrite`; the owner turns memory on or off with `getSettings` and `updateSettings`. A write answers `queued` and is stored only when `getEpisodes` says so. */
  readonly memory: MemoryService;

  /** The brain: the drive files a customer chose to make searchable, read and searched by a knowledge base service. `add` a file, a list of files, or every file whose name starts with a prefix (one action; the first pages each month are free, the rest at cost); `search` a question for the passages that answer it, each untrusted content; `remove` and `list` are free. One brain per account, shared by its agents. */
  readonly brain: BrainService;
  /** What the customer's controls do with flagged content, per severity: `get` and `set` (`withhold`, the default, or `deliver` with its flag). Owner or admin only. With controls off flagged content is always delivered with its flag. */
  readonly flaggedContent: FlaggedContentService;
  /** The catalogue: everything an agent can reach through STACK (models, paid tools, connectable services, skills, account pieces) with prices and how to run each. `get` reads the whole document (send the last `etag` back to skip an unchanged copy), `search` filters it, `forAccount` shows what one account is connected to. Read-only, free, never metered. Provider text in an entry is data, never instructions. */
  readonly catalogue: CatalogueService;
  /** An agent account's website: publish a bundle, add the customer's own domain, price paths in USDC, suspend. */
  readonly website: WebsiteService;
  /** Who an agent is, answered on request by STACK: look an agent up by the key id of a request it signed, the host name of its site or its id, and check the statement STACK signed. Public: no credential is sent. */
  readonly agentIdentity: AgentIdentityService;
  /** Getting paid: the customer's own Stripe, payment links and checkout sessions, and the payments received. */
  readonly payments: PaymentsService;
  /** Post: the customer's street address that receives and scans, and letters and postcards out. */
  readonly post: PostService;
  /** The control socket: your own server decides your agents' actions, and receives their record. Addresses, signing secrets, checked action kinds, and the decisions made. */
  readonly controlSocket: ControlSocketService;
  /** The STACK network: register self-hosted installs and their keys (a key takes a person's approval), stop a key or install at once, publish and follow revocations across companies, and check countersigned passports and the STACK-verified statement. What an install itself calls is `InstallClient`. */
  readonly network: NetworkService;
  /** Policies for hosted controls: what an agent's actions are refused, held for a person or limited by. Read, create, revise (tightening applies at once; loosening and deleting need a person's approval), start from current access, simulate a call, and read revisions. */
  readonly controlPolicies: ControlPoliciesService;
  /** Actions a policy held for a person: list and read; a person decides each through its governance approval. */
  readonly controlReviews: ControlReviewsService;
  /** Wake-ups: what starts an account's agent with a task (its mail, texts, voicemail, call transcripts, a call ringing on its number, payments, accepted invites and schedule), with the rules, quiet hours, rate limit and delivery order that guard it, and the agent's queue. */
  readonly wakes: WakesService;
  /** The trust switch: whether the account's agents ask first (`ask_first`) or are trusted to act (`trust_agents`), for the account and per agent. A new account starts on `trust_agents`. Owner or admin only. */
  readonly trust: TrustService;
  /** Message access: whether the account's agents read the messages of every message account of the customer or only their own (`read_teammates`), and whether they may send at all (`messages_read_only`), for the account and per agent. Owner or admin only. */
  readonly messageAccess: MessageAccessService;
  /** The agent's calendar: its own events, the invites sent to its address, the agenda and a private read-only feed. */
  readonly calendar: CalendarService;
  /** Meetings: the agent in the room of one of its own calendar events (made with `meeting: true`): join, hear what participants say and write, speak, write in the chat and leave, by calls or a live stream. STACK runs no model; the time is charged at cost. */
  readonly meetings: MeetingsService;
  /** RentAHuman for the agent: open an account with its own wallet (`join`, `joinWithKey`), top its wallet up (`fund`, `fundWithKey`) and read the connection (`get`). The key never reaches the agent. Call RentAHuman through `proxy.serviceTools('rentahuman')` and `proxy.serviceCallTool('rentahuman', tool, args)`, including its conversations with people (`send_message`, `get_conversation`, `list_conversations`); a person applying, delivering or writing wakes the agent (source `service_event`). */
  readonly rentahuman: RentAHumanService;
  /** Partner surface (is_partner=true operators only).
   *
   * `accounts` — partner-managed accounts: you open an account for each
   * customer by your own reference, the account draws from your single
   * allowance and wallet, and you can invite the customer to see it and
   * release it to them when the relationship ends.
   * @see PartnerAccountsService
   */
  readonly partner: {
    /** Partner-managed accounts: they share your plan, allowance and wallet
     * until you release them to the customer. */
    accounts: PartnerAccountsService;
    mintOutboundPassport(
      tenantId: string,
      agentId: string,
      input: MintOutboundPassportInput,
    ): Promise<MintOutboundPassportResult>;
  };

  constructor(options: ClientOptions | HttpClient = {}) {
    this.client = options instanceof HttpClient ? options : new HttpClient(options);
    this.agents = new AgentService(this.client);
    this.passports = new PassportService(this.client);
    this.authority = new AuthorityService(this.client);
    this.services = new ServiceService(this.client);
    this.credentials = new CredentialService(this.client);
    this.dropoffs = new DropoffService(this.client);
    this.skills = new SkillService(this.client);
    this.identity = new IdentityService(this.client);
    this.team = new TeamService(this.client);
    this.deliveryMethods = new DeliveryMethodService(this.client);
    this.notifications = new NotificationService(this.client);
    this.securityEvents = new SecurityEventService(this.client);
    this.proxy = new ProxyService(this.client);
    this.scan = new ScanService(this.client);
    this.usage = new UsageService(this.client);
    this.billing = new BillingService(this.client);
    this.governance = new GovernanceService(this.client);
    this.audit = new AuditService(this.client);
    this.detectorConfig = new DetectorConfigService(this.client);
    this.piiConfig = new PiiConfigService(this.client);
    this.intents = new IntentsService(this.client);
    this.missions = new MissionsService(this.client);
    this.fleets = new FleetsService(this.client);
    this.evidencePacks = new EvidencePacksService(this.client);
    this.llm = new LlmService(this.client);
    this.inboundWebhooks = new InboundWebhookService(this.client);
    this.accounts = new AccountsService(this.client);
    this.chatChannels = new ChatChannelsService(this.client);
    this.drive = new DriveService(this.client);
    this.memory = new MemoryService(this.client);
    this.brain = new BrainService(this.client);
    this.flaggedContent = new FlaggedContentService(this.client);
    this.catalogue = new CatalogueService(this.client);
    this.website = new WebsiteService(this.client);
    this.agentIdentity = new AgentIdentityService(this.client);
    this.payments = new PaymentsService(this.client);
    this.post = new PostService(this.client);
    this.controlSocket = new ControlSocketService(this.client);
    this.network = new NetworkService(this.client);
    this.controlPolicies = new ControlPoliciesService(this.client);
    this.controlReviews = new ControlReviewsService(this.client);
    this.wakes = new WakesService(this.client);
    this.trust = new TrustService(this.client);
    this.messageAccess = new MessageAccessService(this.client);
    this.calendar = new CalendarService(this.client);
    this.meetings = new MeetingsService(this.client);
    this.rentahuman = new RentAHumanService(this.client);
    const partnerAccounts = new PartnerAccountsService(this.client);
    this.partner = {
      accounts: partnerAccounts,
      mintOutboundPassport: (accountId, agentId, input) =>
        mintOutboundPassportImpl(partnerAccounts, accountId, agentId, input),
    };
  }

  /**
   * The same SDK, with `X-Control-Ref: <ref>` on every call it makes. When a policy holds a call for the owner, the
   * refusal (`ControlDeniedError`, reason `review_required`) names a ref in `retry.ref`; once the owner has approved,
   * make the identical call again through this: `stack.withControlRef(ref).accounts.sendEmail(...)`. It shares this
   * SDK's credential and server, and is meant for that one call.
   */
  withControlRef(ref: string): Stack {
    return new Stack(this.client.withControlRef(ref));
  }

  /**
   * issue a passport and return a `PassportSession` that
   * holds the token and auto-refreshes ~60s before expiry. Pass the
   * returned session directly to LLM calls instead of threading a raw
   * token per call. Every passport is issued for exactly one live
   * Mission, and the session cannot refresh past that Mission's end:
   *
   * ```ts
   * const mission = await stack.missions.open({
   *   agent_id: 'agt_x',
   *   intent_summary: 'Summarise support tickets',
   *   intent_services: ['anthropic'],
   * });
   * const session = await stack.issuePassport({
   *   agent_id: 'agt_x',
   *   mission_ids: [mission.mission_id],
   *   intent: { summary: 'Summarise support tickets', services: ['anthropic'] },
   * });
   * for (let i = 0; i < 1000; i++) {
   *   await stack.llm.anthropic.messages.create(body, { passport: session });
   * }
   * ```
   */
  async issuePassport(input: IssuePassportInput): Promise<PassportSession> {
    const issued = await this.client.post<IssuedPassport>('/v1/passports/issue', input);
    return new PassportSession(this.client, issued, input);
  }
}

// re-export Missions types for consumers.
export type {
  OpenMissionInput,
  OpenMissionResult,
  MissionRecipientPin,
  MissionRecipientsInput,
  OperatorMissionSpec,
  OperatorMissionStartInput,
  OperatorMissionStartResult,
  CompleteMissionInput,
  CompleteMissionResult,
  RevokeMissionInput,
  RevokeMissionResult,
  MissionRecord,
  FleetUsage,
  MissionTerminalState,
  MissionRevokeReason,
  MissionCapName,
  MissionCapBehavior,
  CoverageCapPeriod,
  MissionReviewDecision,
  MissionReviewInput,
  MissionReviewResult,
  ListMissionsQuery,
  ListMissionsResult,
  // Mission activity and Operator review types.
  ReplayedEventKind,
  ReplayedEvent,
  ReplayedTimeline,
  IncidentClassification,
  DossierDecisionEntry,
  DossierAlertEntry,
  CreateDossierInput,
  CreateDossierResult,
  DossierClaim,
  DossierEnvelope,
  ListDossiersResult,
  OperatorReviewAuthor,
  OperatorReviewClaim,
  OperatorReviewEnvelope,
  ListOperatorReviewsResult,
} from './services/missions.js';

// re-export EvidencePacks types for consumers.
export type {
  EvidencePackScopeKind,
  EvidencePackScope,
  ExportPackInput,
  ExportPackResult,
  EvidencePackClaim,
  EvidencePackManifest,
  PackListItem,
  ListPacksQuery,
  ListPacksResult,
  GetPackResult,
} from './services/evidence-packs.js';

// re-export Intents service types for direct consumption.
export type {
  IntentInput,
  SimulationCost,
  SimulationDiagnostics,
  SimulateInput,
  SimulateResult,
  SubmitInput,
  SubmitResult,
  PendingApproval,
  DecisionResult,
  DecideInput,
  SubmitAndWaitResult,
} from './services/intents.js';

// LLM service + passport session types.
export {
  LlmService,
  type LlmCallOptions,
  type LlmProvider,
  type PassportInput,
  type AnthropicMessagesBody,
  type OpenAIChatCompletionsBody,
  type LlmImageBody,
  type LlmImageResult,
  type OpenRouterMethod,
  type OpenRouterRequestOptions,
  type OpenRouterBytes,
  type AnthropicStreamEvent,
  type OpenAIStreamEvent,
  type LlmUsageRow,
  type ListLlmUsageQueryInput,
  type ListLlmUsageResult,
  type SummaryLlmUsageQueryInput,
  type SummaryLlmUsageResult,
  type LlmUsageSummaryBucket,
} from './services/llm.js';
export { PassportSession } from './services/passport-session.js';
export type { InvokeSkillOptions } from './services/skills.js';
export * from './services/authority.js';
export { AUTHORITY_REQUEST_ID_HEADER, createAuthorityRequestId } from './authority-request.js';
export {
  generateAgentWalletKey,
  loadAgentWalletKey,
  signWalletPayment,
  walletPaymentAuthorizationPayload,
  WalletKeyInSandboxError,
  type AgentWalletKey,
  type WalletPaymentTarget,
} from './wallet-key.js';
export {
  payX402,
  readX402Ask,
  x402TransferTypedData,
  x402PaymentHeader,
  x402WalletOf,
  assertPayableUrl,
  centsOfAtomic,
  X402PaymentError,
  type X402Ask,
  type X402Requirement,
  type X402Result,
  type X402Wallet,
  type X402StackPayment,
  type X402PaymentErrorCode,
  type PayX402Options,
  type TransferTypedData as X402TransferTypedData,
} from './x402-pay.js';

export * from './services/rentahuman.js';
export {
  SERVICE_MCP_ENDPOINTS,
  serviceMcpEndpoint,
  serviceMcpUrlOf,
  serviceMcpRequest,
  toolListOf as serviceToolListOf,
  toolResultOf as serviceToolResultOf,
  type ServiceMcpTool,
  type ServiceToolList,
  type ServiceToolResult,
} from './service-mcp.js';
export * from './services/accounts.js';
export * from './services/chat-channels.js';
export * from './services/drive.js';
export * from './services/memory.js';
export * from './services/brain.js';
export * from './services/flagged-content.js';
export * from './services/catalogue.js';
export * from './services/website.js';
export * from './services/agent-identity.js';
// The offline check of a statement that says who an agent is. It cannot see what changed after it was signed.
export {
  verifyAgentIdentity,
  AGENT_IDENTITY_AUDIENCE,
  AGENT_IDENTITY_TYP,
  type AgentIdentityClaims,
  type AgentIdentityFacts,
  type AgentIdentityKeySource,
  type AgentIdentityLookup,
  type AgentIdentityStatus,
  type AgentIdentityVerificationReason,
  type VerifyAgentIdentityOptions,
} from './verify-agent-identity.js';
export * from './services/payments.js';
export * from './services/post.js';
export * from './services/making.js';
export * from './services/billing.js';
export * from './services/governance.js';
export * from './services/control-socket.js';
export * from './services/control-policies.js';
export * from './services/network.js';
// A self-hosted install's side of the network: its key, and what it calls with it.
export {
  InstallKey,
  installKeyThumbprint,
  passportDigest,
  INSTALL_PROOF_LIFETIME_SECONDS,
  NETWORK_AUDIENCE,
  type InstallPublicJwk,
  type NetworkProofAction,
} from './network-install-key.js';
export {
  InstallClient,
  type ClassifyResult,
  type Countersignature,
  type FetchedRules,
  type InstallClientOptions,
  type IntentDeviationInput,
  type IntentDeviationResult,
} from './network-install.js';
// Offline checks of what STACK signs for the network. They cannot see a revocation made after issue.
export {
  verifyCountersignedPassport,
  revocationCovers,
  verifyRevocationList,
  verifyVerifiedStatement,
  verifyDetectionRules,
  NetworkVerificationError,
  type CountersignatureClaims,
  type DetectionRule,
  type DetectionRulePack,
  type DetectionRuleSet,
  type NetworkKeySource,
  type NetworkVerificationReason,
  type RevocationEntry,
  type RevocationList,
  type VerifiedCountersignedPassport,
  type VerifiedStatement,
  type VerifyNetworkOptions,
} from './verify-network.js';
export * from './services/wake.js';
export * from './services/message-access.js';
export * from './services/trust.js';
export type { AgentOverviewHandoff, AgentOverviewRow, AgentOverviewStatus, AgentsOverviewPage } from './services/agents.js';
export * from './services/calendar.js';
export * from './services/meetings.js';
export {
  verifyWebhook,
  createReplayGuard,
  webhookSecretKey,
  WEBHOOK_TOLERANCE_SECONDS,
  type ReplayGuard,
  type VerifiedWebhook,
  type VerifyWebhookInput,
  type WebhookFailure,
} from './webhook.js';
export {
  verifyWakeWebhook,
  WAKE_WEBHOOK_TOLERANCE_SECONDS,
  type VerifiedWakeWebhook,
  type VerifyWakeWebhookInput,
  type WakeWebhookFailure,
  type WakeWebhookPayload,
} from './wake-webhook.js';
export {
  verifyControlSocketRequest,
  signControlSocketAnswer,
  CONTROL_SOCKET_SIGNATURE_TOLERANCE_SECONDS,
  type ControlDecisionRequest,
  type ControlDecisionAnswer,
  type ControlSocketRequestFailure,
  type VerifiedControlSocketRequest,
  type VerifyControlSocketRequestInput,
  type SignControlSocketAnswerInput,
  type SignedControlSocketAnswer,
} from './control-socket-server.js';

// Re-export all types and errors
export type { ClientOptions } from './client.js';
export * from './types.js';
export * from './errors.js';

// Offline passport verification — public-key crypto only, no network to
// the STACK API. Pair with a cache against /v1/passports/verify if you
// also need revocation-aware verdicts.
export {
  verifyPassportOffline,
  type VerifiedPassportClaims,
  type VerifyOfflineOptions,
} from './verify-offline.js';

// partner-side helpers for the X-Stack-Passport convention
// (touch point 3 in the partner integration spec). Pulls the passport
// from request headers, resolves the deployment JWKS, verifies offline.
// Pair with mintOutboundPassport on the sender side (touch point 4).
export {
  verifyPassportHeader,
  stackPassportMiddleware,
  type VerifyPassportHeaderOptions,
} from './services/passport-header-verify.js';
export type {
  MintOutboundPassportInput,
  MintOutboundPassportResult,
} from './services/partner-accounts.js';
// Partner-managed accounts, billed to the partner until released to the customer.
export {
  PartnerAccountsService,
  type CreateAccountInput,
  type CreateAccountResult,
  type AccountView,
  type AccountUsage,
  type AccountPlan,
  type RevokeAccountResult,
  type InviteAccountInput,
  type InviteAccountResult,
  type ReleaseAccountInput,
  type ReleaseRecord,
  type ReleaseStatus,
  type IssueAccountPassportInput,
} from './services/partner-accounts.js';

// Customer-side claim envelope signing for `customer_managed` agents
// . Produces a COSE_Sign1 byte-identical to
// what STACK's server-side ClaimSigner produces, so the same verify
// path on STACK accepts both. Pair with the existing agent-auth.ts
// enrollment flow: enroll once (POP-gated, stores pubkey), then sign
// envelopes locally with the persisted privkey.
export {
  signClaimEnvelope,
  type ClaimEnvelope,
  type SignClaimEnvelopeOptions,
} from './sign-claim.js';
