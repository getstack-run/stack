// ─── Agents ─────────────────────────────────────────────────────────

/** Whether an agent may retrieve raw secrets. `proxy_only` (and
 * `proxy_preferred`) block raw retrieval — all credential use is injected
 * at the STACK proxy boundary; `direct` allows `credentials.get`. */
export type CredentialAccess = 'direct' | 'proxy_preferred' | 'proxy_only';

/** How strictly the agent is monitored. `enforced` gates every call on an
 * approved intent; `logged` (the default for a new agent) records but does
 * not gate; `standard` is no accountability. A new agent starts `logged`;
 * strict modes are the owner's choice. */
export type AccountabilityMode = 'enforced' | 'logged' | 'standard';

/** Signing-key model. `stack_managed` (default) auto-provisions the
 * keypair on first sign — no enrollment. `customer_managed` = BYO keypair
 * (uses the enrollment flow). `co_signed` = stack_managed + a
 * co-signature. */
export type AgentKeyMode = 'stack_managed' | 'customer_managed' | 'co_signed';

/** Registration preset. `proxied-llm-bot` expands to
 * `credential_access: 'proxy_only'` + `accountability_mode: 'logged'` +
 * `key_mode: 'stack_managed'` so a bot that just calls an LLM through
 * STACK works on its first call with no key on the box. Explicit fields
 * override the preset. */
export type AgentProfile = 'proxied-llm-bot';

export interface Agent {
  id: string;
  operator_id: string;
  name: string;
  description: string | null;
  status: 'active' | 'suspended' | 'revoked';
  accountability_mode: AccountabilityMode;
  credential_access: CredentialAccess;
  /** Signing-key model (immutable after registration). `stack_managed` =
   * STACK holds the key; an on-box runtime authenticates with the operator
   * credential. `customer_managed` = an on-box agent keypair (enrolled),
   * the strongest "no operator credential on the box" posture. */
  key_mode: AgentKeyMode;
  /** Has no effect: STACK adds no system prompt to any `/v1/llm/*` gateway
   * call. Accepted and ignored; kept so existing clients keep working. */
  llm_inject_system_prompt: boolean;
  /** Whether STACK scans user-role message content and redacts PII before
   * forwarding `/v1/llm/*` gateway calls to the provider. Defaults to
   * `true` (fail-closed); `false` means user PII flows to the LLM provider
   * unredacted — an explicit operator decision. */
  llm_redact_pii: boolean;
  created_at: string;
  updated_at: string;
}

export interface RegisterAgentInput {
  name: string;
  description?: string;
  /** Safe-default preset; expands to a posture bundle before per-field
   * defaults. Explicit fields below override it. */
  profile?: AgentProfile;
  accountability_mode?: AccountabilityMode;
  credential_access?: CredentialAccess;
  key_mode?: AgentKeyMode;
  /** Has no effect: accepted and ignored. STACK adds no system prompt to
   * `/v1/llm/*` gateway calls. */
  llm_inject_system_prompt?: boolean;
  /** Redact PII from user-role message content before forwarding `/v1/llm/*`
   * gateway calls. Defaults to `true` (fail-closed) when omitted; `false`
   * means user PII flows to the LLM provider unredacted — an explicit
   * operator decision. */
  llm_redact_pii?: boolean;
  /** Mark the agent as test or benchmark traffic. Detection stays on and events stay visible, but warnings arrive
   * already resolved with no notification; criticals stay live. Set here it rides inside the registration approval. */
  eval_traffic?: boolean;
}

/**
 * One rule of a grant. A call is allowed when it meets the rule's intents and constraints together; a grant that lists
 * several rules allows a call that meets any one of them (a read rule and, beside it, a post rule that names its channel).
 */
export interface GrantAccessRule {
  intents?: unknown[];
  constraints?: unknown[];
}

/** A first grant in an agent setup: the `grant` input without the agent, which the setup is about to make. */
export interface AgentSetupGrant {
  service_connection_id: string;
  scopes: string[];
  /** Limits every call must meet, whichever rule allows it. */
  constraints?: unknown[];
  intents?: unknown[];
  /** Rules that each allow their own calls: a call must meet at least one. */
  alternatives?: GrantAccessRule[];
  allow_data_from?: string[];
}

/** The hosts one existing connection's credential may be sent to. */
export interface AgentSetupHosts {
  service_connection_id: string;
  allowed_hosts: string[];
}

/** Registration, first grants and credential hosts, decided once. */
export interface AgentSetupInput {
  agent: RegisterAgentInput;
  grants?: AgentSetupGrant[];
  allowed_hosts?: AgentSetupHosts[];
}

export interface AgentSetupResult {
  agent: Agent;
  grants: Array<{ id: string; service_connection_id: string }>;
  allowed_hosts: AgentSetupHosts[];
}

/** What dismissing an agent's open warnings did. */
export interface DismissWarningsResult {
  agent_id: string;
  dismissed: number;
  by_signal_type: Record<string, number>;
  /** New events of the dismissed kinds for this agent are hidden for this long. */
  repeats_hidden_for_seconds: number;
}

export interface UpdateAgentInput {
  name?: string;
  description?: string;
  status?: 'active' | 'suspended';
  accountability_mode?: AccountabilityMode;
  credential_access?: CredentialAccess;
  /** Mutable post-registration. See {@link RegisterAgentInput.llm_inject_system_prompt}. */
  llm_inject_system_prompt?: boolean;
  /** Mutable post-registration. See {@link RegisterAgentInput.llm_redact_pii}. */
  llm_redact_pii?: boolean;
  /** Mutable post-registration. Turning it on needs human approval. See {@link RegisterAgentInput.eval_traffic}. */
  eval_traffic?: boolean;
}

// ─── Passports ──────────────────────────────────────────────────────
export interface IssuedPassport {
  token: string;
  jti: string;
  expires_at: string;
}

/**
 * Opaque authority binding reference carried in a Passport. The reference
 * intentionally contains no principal identity, proof payload, mandate text,
 * action parameters, or personal data.
 */
export interface AuthorityReference {
  binding_id: string;
  binding_version: number;
  binding_claim_id: string;
  binding_digest: string;
  receiver_id: string;
  receiver_profile_version_id: string;
  expires_at: number;
}

/**
 * One per-connection scope entry on an issue or delegate call. Mirrors the
 * API's `IssuePassportInput.scopes[]` / `DelegatePassportInput.scopes[]`
 * object shape.
 */
export interface PassportIssueScope {
  /** The service connection (`scon_*`) this entry scopes. */
  service_connection_id: string;
  /** OAuth-style scope strings — a subset of the grant's scopes. */
  scopes: string[];
  /** Optional raw parameter-level constraints (tighten-only vs the grant). */
  constraints?: unknown[];
  /** Optional named intents that expand to constraints server-side. */
  intents?: unknown[];
  /**
   * Sources whose content may flow INTO this one (the data-flow
   * declaration, enforced by the scope wall): a service, or one connection of
   * a service written `service@<connection id>`. Content read through one
   * connection of a service needs such an entry before it may go out through
   * another connection of the same service. Omit to inherit the operator
   * grant; `[]` allows no cross-service flow. It must be a subset of the
   * grant and, on delegation, of the parent scope. A standing grant wildcard
   * is resolved to exact service names before signing and is never accepted
   * in this field.
   */
  allow_data_from?: string[];
}

export interface IssuePassportInput {
  agent_id: string;
  /**
   * The one Mission (`ms_*`) this passport is issued for. Required: the
   * list must hold exactly one id. The Mission must be live and assigned to
   * this agent (or unassigned). Open one with `stack.missions.open(...)`,
   * or use `stack.missions.start(...)` to open the Mission and issue the
   * passport in one call. The passport never outlives its Mission, and
   * completing or revoking the Mission revokes the passport.
   */
  mission_ids: [string];
  scopes?: PassportIssueScope[];
  ttl_seconds?: number;
  session_id?: string;
  /** Exact active authority bindings assigned to this agent. Maximum eight. */
  authority_binding_ids?: string[];
  /**
   * Intent declaration. REQUIRED when the agent's accountability_mode is
   * `enforced` or `logged` (the server rejects issuance with
   * `ACCOUNTABILITY_REQUIRED` without it). A `standard`-mode agent may omit
   * it. `summary` is a short human-readable description of what this
   * passport is for; `services` lists the provider slugs the work will
   * touch (must be a subset of what the agent is GRANTED); intent narrows,
   * it never grants.
   *
   * Send `intent: { summary, services }`; flat intent fields are not read.
   */
  intent?: {
    summary: string;
    services: string[];
    will_delegate?: boolean;
    estimated_duration_seconds?: number;
  };
}

export interface DelegatePassportInput {
  parent_token: string;
  child_agent_id: string;
  scopes?: PassportIssueScope[];
  ttl_seconds?: number;
}

export interface VerifyPassportResult {
  valid: boolean;
  jti: string;
  agent_id: string;
  expires_at: string;
  claims: Record<string, unknown>;
}

export interface ActivePassport {
  jti: string;
  agent_id: string;
  session_id: string | null;
  delegation_depth: number;
  parent_passport_id: string | null;
  issued_at: string;
  expires_at: string;
}

// ─── Services ───────────────────────────────────────────────────────
export interface Service {
  id: string;
  name: string;
  provider: string;
  category: string;
  available: boolean;
}

export interface ServiceConnection {
  id: string;
  operator_id: string;
  service_id: string;
  provider: string;
  /** What this connection is called among the service's connections (`default` for the first one). */
  name: string;
  status: string;
  verification_status: string | null;
  verified_at: string | null;
  proxy_enabled: boolean;
  connected_by: string | null;
  created_at: string;
  /** The address of the service's MCP endpoint (given when it was connected, or the default of a service STACK knows); null when it has none. */
  mcp_url?: string | null;
}

export interface ConnectServiceInput {
  service_id: string;
  /** Informational; the API resolves the provider from `service_id`. */
  provider?: string;
  credential: string;
  /** Required by the API (at least one). */
  scopes: string[];
  /** The address of the service's MCP endpoint, when it speaks MCP over HTTP: https, on one of the connection's allowed hosts. */
  mcp_url?: string;
  /** Names the connection when the service already has one: 1 to 40 letters, digits, spaces or dashes. Omit for the first connection (`default`). */
  connection_name?: string;
}

export type ConnectLinkMethod = 'oauth' | 'key';
export type ConnectLinkStatus = 'pending' | 'connected' | 'expired';

/**
 * The customer's own API, which takes a key or token. Never a credential: the person enters that on the page the
 * link opens.
 */
export interface CustomConnectLinkService {
  name: string;
  description?: string;
  /** Hosts the key may be sent to (1 to 100): bare hostnames (`api.example.com`) or dot-led domains (`.example.com`). The owner may correct them on the page before entering the key. */
  allowed_hosts: string[];
  /** A credential template whose fields the page asks for. Omitted: one API key field. */
  template?: string;
  /** The address of the API's MCP endpoint, when it speaks MCP over HTTP: https, on one of `allowed_hosts`. */
  mcp_url?: string;
  /** Names the connection the link makes (1 to 40 letters, digits, spaces or dashes). Omit for the first connection of the service (`default`). */
  connection_name?: string;
}

export type CreateConnectLinkInput =
  | {
    /** A catalog service id or provider name, for example `github`. */
    service_id: string;
    /** OAuth scopes to ask for when the service connects through the provider's own sign-in. Omit for the service defaults. */
    scopes?: string[];
    /** Names the connection the link makes (1 to 40 letters, digits, spaces or dashes). Omit for the first connection of the service (`default`). */
    connection_name?: string;
  }
  | {
    /** The customer's own API, connected with a key or token. A custom service that signs in with OAuth is not supported. */
    custom: CustomConnectLinkService;
  }
  | {
    /**
     * A key that belongs to one of the customer's own supplier accounts, entered on the page: a print-on-demand supplier
     * (`gelato`, `prodigi`, `printful` or `lulu`), an agent account's Telegram bot, or the street address's mailbox.bot key.
     * Owner or admin only.
     */
    connect: ConnectKeyTarget;
  };

/** What a key link is for. Names the key's use only, never the key. */
export type ConnectKeyTarget =
  | { kind: 'making_supplier'; supplier: 'gelato' | 'prodigi' | 'printful' | 'lulu' }
  | { kind: 'telegram_bot'; account_id: string }
  | { kind: 'post_address' };

/** A connect link as it reads back: never the URL and never a credential. */
export interface ConnectLink {
  link_id: string;
  provider: string;
  service_id: string;
  /** The name the connection will get. */
  connection_name: string;
  /** `oauth`: the person signs in on the provider's page. `key`: they enter the key on a STACK page. */
  method: ConnectLinkMethod;
  status: ConnectLinkStatus;
  /** The connection the link made, once `status` is `connected`. */
  connection_id: string | null;
  expires_at: string;
  created_at: string;
  completed_at: string | null;
}

/** A newly created connect link: the one and only copy of its URL. */
export interface CreatedConnectLink extends ConnectLink {
  /** Open it in a browser signed in to STACK. It carries a one-time token: show it to the person, never log it. */
  url: string;
}

export interface ConnectCustomServiceInput {
  name: string;
  description?: string;
  credential: string | Record<string, string>;
  scopes?: string[];
  /** Hosts the credential may be sent to (the API needs them for a custom service unless the credential carries a base_url). */
  allowed_hosts?: string[];
  /** The address of the service's MCP endpoint, when it speaks MCP over HTTP: https, on one of `allowed_hosts`. */
  mcp_url?: string;
  /** Names the connection when the service already has one: 1 to 40 letters, digits, spaces or dashes. */
  connection_name?: string;
}

export interface GrantAgentAccessInput {
  agent_id: string;
  /** The service connection (`scon_*`) to grant, as `service_connection_id` in `POST /v1/services/grant`. */
  service_connection_id: string;
  /** At least one scope; an explicit list is part of the grant's fail-closed contract. */
  scopes: string[];
  /** Limits every call must meet, whichever rule allows it. */
  constraints?: unknown[];
  /** Named intents that expand to constraints server-side; every one must hold. */
  intents?: unknown[];
  /** Rules that each allow their own calls: a call must meet at least one, so a read rule and a post rule can sit side by side. */
  alternatives?: GrantAccessRule[];
  /** Sources whose content may flow into this one: a service, or one connection of it as `service@<connection id>`. */
  allow_data_from?: string[];
}

// ─── Credentials ────────────────────────────────────────────────────
export interface CredentialResult {
  provider: string;
  credential?: string;
  credentials?: Record<string, string>;
}

// ─── Drop-offs ──────────────────────────────────────────────────────
export interface Dropoff {
  id: string;
  operator_id: string;
  from_agent_id: string;
  /** The first agent named. */
  to_agent_id: string;
  /** Every agent named, in the order named: each can see and collect it. */
  to_agent_ids: string[];
  /** The agent that collected it; null until one has. */
  collected_by_agent_id: string | null;
  schema: Record<string, unknown>;
  status: string;
  on_expire: 'notify' | 'retry' | 'fail';
  created_at: string;
  deposited_at: string | null;
  collected_at: string | null;
  expires_at: string;
  mission_id: string | null;
  deposited_bytes: number;
}

export interface DropoffStatus {
  id: string;
  from_agent: string;
  /** The first agent named. */
  to_agent: string;
  /** Every agent named, in the order named. */
  to_agents: string[];
  /** The agent that collected it; null until one has. */
  collected_by: string | null;
  status: string;
  created_at: string;
  deposited_at: string | null;
  collected_at: string | null;
  expires_at: string;
  mission_id: string | null;
  deposited_bytes: number;
}

export interface CreateDropoffInput {
  from_agent: string;
  /** The one agent it is for. Give this or `to_agents`, not both. */
  to_agent?: string;
  /**
   * Several of the customer's agents, 1 to 10, not the sender. Each can see it and is woken when it is deposited, and
   * the first to collect it takes it; the others get DROPOFF_ALREADY_COLLECTED naming who did. Give this or `to_agent`.
   */
  to_agents?: string[];
  schema: Record<string, unknown>;
  ttl_seconds?: number;
  /** Legacy compatibility field. Every value now uses expire-and-purge. */
  on_expire?: 'notify' | 'retry' | 'fail';
}

// ─── Skills ─────────────────────────────────────────────────────────
export interface Skill {
  id: string;
  operator_id: string;
  agent_id: string | null;
  name: string;
  description: string;
  tags: string[];
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  trust_level_required: string;
  status: string;
  execution_mode: string;
  credential_mode: string;
  price_per_invocation: number;
  invocation_count: number;
  average_rating: number | null;
  rating_count: number;
  created_at: string;
  updated_at: string;
}

export interface PublishSkillInput {
  name: string;
  description: string;
  version: string;
  tags?: string[];
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  trust_level_required?: string;
  agent_id?: string;
  execution_mode?: 'open' | 'sealed' | 'source';
  llm_enabled?: boolean;
  llm_model?: string;
  llm_config?: Record<string, unknown>;
  execution_runtime?: 'javascript' | 'python' | 'none';
  execution_script?: string;
  dependencies?: string;
  execution_steps?: Array<{
    type: 'script' | 'llm';
    label?: string;
    runtime?: 'javascript' | 'python';
    script?: string;
    dependencies?: string;
    llm_provider?: string;
    llm_model?: string;
    llm_config?: {
      system_prompt?: string;
      temperature?: number;
      max_tokens?: number;
    };
  }>;
  /** Only credentialless skills are accepted. Skill code never receives secrets. */
  credential_mode?: 'none';
  price_per_invocation?: number;
}

export interface BrowseSkillsQuery {
  query?: string;
  tags?: string;
  trust_level?: string;
  status?: string;
  limit?: string;
  offset?: string;
}

export interface SkillInvocation {
  id: string;
  skill_id: string;
  status: string;
  output?: unknown;
  error?: { code: string; message: string };
  expires_at: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  llm_tokens_input?: number;
  llm_tokens_output?: number;
  execution_duration_ms?: number;
}

export interface InvokeSkillInput {
  /** May be omitted when the authenticated Passport already binds the agent. */
  agent_id?: string;
  input: Record<string, unknown>;
  /** Required by the API whenever an agent_id or agent JWT is used. */
  passport_id?: string;
}

// ─── Skill Requests ─────────────────────────────────────────────────
export interface SkillRequest {
  id: string;
  operator_id: string;
  description: string;
  desired_input_schema: Record<string, unknown> | null;
  desired_output_schema: Record<string, unknown> | null;
  max_price_cents: number | null;
  tags: string[];
  status: string;
  created_at: string;
}

export interface PostSkillRequestInput {
  description: string;
  desired_input_schema?: Record<string, unknown>;
  desired_output_schema?: Record<string, unknown>;
  max_price_cents?: number;
  tags?: string[];
}

// ─── Identity Settings ──────────────────────────────────────────────
export interface IdentitySettings {
  identity_claim_ttl: '30d' | '90d' | '180d' | '1y';
  identity_claim_inheritance: 'auto' | 'opt_in';
  identity_auto_revoke: boolean;
}

export interface UpdateIdentitySettingsInput {
  identity_claim_ttl?: '30d' | '90d' | '180d' | '1y';
  identity_claim_inheritance?: 'auto' | 'opt_in';
  identity_auto_revoke?: boolean;
}

// ─── Identity ───────────────────────────────────────────────────────
export interface IdentityProvider {
  key: string;
  name: string;
  layers: string[];
  assurance: string;
  description: string;
}

export interface IdentityClaim {
  id: string;
  operator_id: string;
  provider_key: string;
  layer: string;
  claim_type: string;
  claim_ref: string;
  assurance_level: string;
  verified_at: string;
  expires_at: string | null;
}

export interface InitiateVerificationInput {
  provider_key: string;
  requested_claims?: string[];
  return_url?: string;
}

export interface VerificationResult {
  session_ref: string;
  authorization_url?: string;
  status: string;
}

/** Where a verification session stands; `completed`, `failed` and `expired` are final. */
export type IdentityVerificationSessionStatus = 'pending' | 'completed' | 'failed' | 'expired';

/** One identity verification session. No provider data and nothing about the person. */
export interface IdentityVerificationSession {
  session_id: string;
  provider_key: string;
  session_ref: string;
  status: IdentityVerificationSessionStatus;
  requested_claims: string[];
  created_at: string;
  expires_at: string;
  completed_at: string | null;
}

/** Canonical body for one service identity requirement. */
export interface SetServiceRequirementInput {
  layer: 'humanity' | 'identity' | 'delegation';
  requires_claim: string;
  minimum_assurance: 'low' | 'substantial' | 'high';
  accepted_providers?: string[];
  required_scopes?: string[];
  requires_pii?: boolean;
  lawful_basis?: string;
}

export interface ServiceRequirement {
  id: string;
  operator_id: string;
  service_id: string;
  layer: 'humanity' | 'identity' | 'delegation';
  requires_claim: string;
  minimum_assurance: 'low' | 'substantial' | 'high';
  accepted_providers: string[];
  required_scopes: string[] | null;
  requires_pii: boolean;
  lawful_basis: string | null;
}

export interface ReplaceServiceRequirementResult {
  requirements: ServiceRequirement[];
}

// ─── Team ───────────────────────────────────────────────────────────
export interface TeamMember {
  id: string;
  operator_id: string;
  email: string;
  name: string;
  role: 'readonly' | 'standard' | 'admin';
  status: 'invited' | 'active' | 'revoked';
  allowed_connections: string[] | null;
  invited_at: string;
  joined_at: string | null;
  revoked_at: string | null;
  /** The identity provider (its `iss`) the member signed in through; null until they have. */
  sso_issuer: string | null;
}

/** One member by id, or every member bound to one issuer. */
export type ClearSsoBindingsInput = { member_id: string; issuer?: never } | { issuer: string; member_id?: never };

export interface ClearSsoBindingsResult {
  /** The members whose binding was forgotten, each with the issuer it was bound to. */
  cleared: Array<{ id: string; email: string; sso_issuer: string }>;
}

/** The state of an e-mail domain claimed for the account's single sign-on. */
export type SsoDomainStatus = 'pending' | 'verified' | 'lapsed';

/** What one lookup of a domain's DNS record found: the record, no such record, or no answer. */
export type SsoDomainCheckResult = 'confirmed' | 'missing' | 'unavailable';

/** An e-mail domain of the account's single sign-on, with the DNS record that proves it. */
export interface SsoDomain {
  id: string;
  domain: string;
  status: SsoDomainStatus;
  /** Publish a TXT record at `name` with exactly `value`. */
  record: { type: 'TXT'; name: string; value: string };
  verified_at: string | null;
  last_checked_at: string | null;
  /** What the last lookup found; null before the first one. */
  last_check: SsoDomainCheckResult | null;
  /** Since when the record has been seen missing; null while it is there. */
  missing_since: string | null;
  created_at: string;
}

export interface SsoDomainCheck {
  domain: SsoDomain;
  check: SsoDomainCheckResult;
}

export interface InviteMemberInput {
  email: string;
  name: string;
  role?: 'readonly' | 'standard' | 'admin';
  /** Omit/null for unrestricted, [] for no connections, or list allowed ids. */
  allowed_connections?: string[] | null;
}

export interface UpdateMemberInput {
  role?: 'readonly' | 'standard' | 'admin';
  /** Omit to leave unchanged, null for unrestricted, [] for no connections. */
  allowed_connections?: string[] | null;
}

// ─── Delivery Methods ───────────────────────────────────────────────
export interface DeliveryMethod {
  id: string;
  operator_id: string;
  channel_type: 'email' | 'sms' | 'webhook';
  destination: string;
  verified: boolean;
  webhook_secret?: string | null;
  created_at: string;
}

export interface AddDeliveryMethodInput {
  channel_type: 'email' | 'sms' | 'webhook';
  destination: string;
}

// ─── Notification Rules ─────────────────────────────────────────────
export interface NotificationRule {
  id: string;
  operator_id: string;
  destination_ids: string[];
  events: string[];
  min_severity: string;
  delivery_methods?: DeliveryMethod[];
  created_at: string;
}

export interface CreateNotificationRuleInput {
  destination_ids: string[];
  events: string[];
  min_severity?: string;
}

export interface UpdateNotificationRuleInput {
  destination_ids?: string[];
  events?: string[];
  min_severity?: string;
}

/** @deprecated Use DeliveryMethod + NotificationRule instead */
export interface NotificationChannel {
  id: string;
  operator_id: string;
  channel_type: 'email' | 'sms' | 'webhook';
  destination: string;
  events: string[];
  min_severity: string;
  verified: boolean;
  created_at: string;
}

/** @deprecated Use AddDeliveryMethodInput + CreateNotificationRuleInput instead */
export interface CreateNotificationChannelInput {
  channel_type: 'email' | 'sms' | 'webhook';
  destination: string;
  events?: string[];
  min_severity?: string;
}

// ─── Security Events ────────────────────────────────────────────────
export interface SecurityEvent {
  id: string;
  operator_id: string;
  agent_id: string | null;
  passport_jti: string | null;
  signal_type: string;
  severity: string;
  message: string;
  metadata: Record<string, unknown> | null;
  resolved: boolean;
  resolved_at: string | null;
  created_at: string;
}

// ─── Audit ──────────────────────────────────────────────────────────
export interface AuditEntry {
  id: string;
  operator_id: string;
  agent_id: string | null;
  layer: string;
  action: string;
  outcome: string;
  duration_ms: number | null;
  created_at: string;
}

// ─── Proxy ──────────────────────────────────────────────────────────
interface ProxyRequestFields {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
  query?: Record<string, string>;
  /** The connection to use when the service has several: its name (any case) or its `scon_` id. Omit when there is one. */
  connection?: string;
}

/**
 * A request through STACK's credential-injecting proxy.
 *
 * `service` is the canonical API field. `provider` remains accepted for
 * compatibility with SDK versions that published that name, but callers must
 * supply exactly one selector so the SDK cannot silently choose between them.
 */
export type ProxyRequest = ProxyRequestFields & (
  | { service: string; provider?: never }
  | { service?: never; provider: string }
);

/**
 * Per-call options for `Stack.proxy.request`. These fields wire through
 * to HTTP headers; the API contract requires `passportToken` and
 * (under enforced-mode passports) `approvalId`..
 */
export interface ProxyRequestOptions {
  /** Passport JWT — sent as `X-Passport-Token`. */
  passportToken?: string;
  /** Approval id from `intents.submitAndWait` — sent as `X-Intent-Approval-Id`. */
  approvalId?: string;
  /** Stable, high-entropy runtime correlation id. Reuse it for exact retries. */
  authorityRequestId?: string;
  /**
   * Runs, and is awaited, before network I/O. Durable job runners should
   * persist the operation id here so response loss cannot also lose recovery.
   */
  onOperationId?: (operationId: string) => void | Promise<void>;
}

/** Options of `proxy.serviceTools` and `proxy.serviceCallTool`: the per-call options, plus the connection to use when the service has several. */
export interface ServiceCallOptions extends ProxyRequestOptions {
  /** The connection's name (any case) or `scon_` id. Omit when the service has one connection, or when all of them share one MCP address. */
  connection?: string;
}

export interface ProxyResponse {
  /** Wire-form recovery handle returned by the API for non-GET operations. */
  operation_id?: string;
  status: number;
  headers: Record<string, string>;
  body: unknown;
  /** Stable recovery handle for this non-GET operation. */
  operationId?: string;
}

export type ProxyDeliveryState = 'admitted' | 'dispatching' | 'response_received' | 'outcome_unknown';
export type ProxyReplayState = 'none' | 'screening' | 'available' | 'expired' | 'erased';
export type ProxyAccountingState = 'reserved' | 'committed' | 'released';

export interface ProxyOperation {
  operation_id: string;
  delivery_state: ProxyDeliveryState;
  replay_state: ProxyReplayState;
  accounting_state: ProxyAccountingState;
  provider: string;
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  created_at: string;
  dispatched_at: string | null;
  response_received_at: string | null;
  /** Set once the outcome stayed unknown for 7 days with nothing settling it: STACK never sends it again. */
  unresolved_at: string | null;
  provider_outcome: 'not_required' | 'pending' | 'confirmed' | 'not_found' | 'contradictory' | 'expired';
  provider_status: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled' | null;
  response?: {
    status: number;
    headers: Record<string, string>;
    body: unknown;
  };
}

export interface ProxyOperationOptions {
  /** Live Passport used to re-authorize the operation scope. */
  passportToken: string;
  /** Include the stored screened response when it remains available. */
  includeResponse?: boolean;
}

// ─── Content scan (/v1/scan — L1+L2 prompt-injection detector) ─────
export interface ScanRequest {
  /** The content to scan. Strings scanned directly; objects walked
   * one level deep, same as proxy bodies. */
  content: string | Record<string, unknown>;
  /** Optional context tag — recorded in security event metadata
   * so operators can filter by retrieval source class. */
  context?: 'email' | 'document' | 'webpage' | 'chat_log' | 'api_response' | 'calendar' | 'other';
  /** Optional source identifier (URL / sender / filename). Truncated
   * to 256 chars in security event metadata. */
  source?: string;
}

export interface ScanMatch {
  pattern_id: string;
  severity: 'warning' | 'critical';
  field_path: string;
  matched_excerpt: string;
  /** Set when L2 normalization revealed the match (base64_decode,
   * homoglyph, leetspeak, rot13, etc.). Absent when L1 caught the
   * raw text directly. */
  encoding?: string;
}

export interface ScanResponse {
  verdict: 'clean' | 'suspicious' | 'critical';
  scan_id: string;
  duration_ms: number;
  match: ScanMatch | null;
}

/**
 * The plan an account is on. `platform`: the platform plan is live (or a live grant stands in for it); `internal`:
 * STACK's own account; `contract`: a self-managed engine install; `none`: no live plan.
 */
export type AccountPlan = 'platform' | 'internal' | 'contract' | 'none';

export interface ScanUsage {
  /** The plan the account is on (a tenant reports the plan its billing account resolves to). */
  plan: AccountPlan;
  /** @deprecated No longer sent; read `plan`. */
  tier?: string;
  limit: number | null;
  used: number;
  remaining: number | null;
  period: string;
  /** Present on accounts of a partner on a negotiated hard cap: `used`/`limit` are the partner's shared pool. */
  pooled?: true;
}

/** GET /v1/proxy/usage. Same shape as the scan readout: one action pool. */
export type ProxyUsage = ScanUsage;

/**
 * One consumption meter: used against a tier cap (null = uncapped).
 * `created_in_window` is present only for inventory meters (agents, published
 * skills) when the request set a window — the count created in that range.
 */
export interface UsageMeter {
  used: number;
  limit: number | null;
  created_in_window?: number;
}

export type UsageDetailCoverage = 'complete' | 'partial' | 'unavailable';
export type UsageTotalCoverage = 'complete' | 'lower_bound';

/** The action allowance with durable detail when the window supports it. */
export interface ActionUsageMeter extends UsageMeter {
  /** Whether `limit` is the allowance recorded for this exact UTC month. */
  allowance_coverage: 'complete' | 'unavailable';
  /** The plan the limit belongs to: the account's plan for the current month, or null for any other month. */
  allowance_plan: AccountPlan | null;
  /** @deprecated No longer sent; read `allowance_plan`. */
  allowance_tier?: string | null;
  by_kind?: Record<string, number>;
  detail_coverage: UsageDetailCoverage;
  /**
   * Pooled accounts only (the accounts of a partner on a negotiated hard cap, and the partner). When
   * `pooled` is true, `used` is the whole pool the allowance applies to,
   * `own_used` is this account's share of it, and `tenants` is how many
   * tenant accounts share it.
   */
  pooled?: true;
  own_used?: number;
  tenants?: number;
}

/**
 * The full usage + spend + earnings rollup (GET /v1/usage). Money fields are
 * in cents. Consumption reports each meter against its tier cap; spend buckets
 * are positive amounts summed from the wallet ledger; earnings is always
 * present (zeros for non-publishers). `period_label` is "billing" for the
 * default period or "custom" when a since/until window was requested.
 */
export interface UsageResponse {
  /** The plan the account is on. */
  plan: AccountPlan;
  /** @deprecated No longer sent; read `plan`. */
  tier?: string;
  period_start: string;
  period_end: string | null;
  period_label: string;
  /** When the account was created (ISO-8601) — the floor for any
   * look-back window. */
  account_since: string;
  consumption: {
    /** Every audit event in the window. This is activity, not the allowance. */
    activity: {
      total: number;
      /** Null when a legacy rollup can prove only a lower bound. */
      non_metered: number | null;
      total_coverage: UsageTotalCoverage;
    };
    /**
     * The published allowance meter. Reads, configuration, governance,
     * revocation, checkpoints, and audit export do not enter this count.
     * Overage bills from the wallet at a hundredth of a cent.
     */
    actions: ActionUsageMeter;
    /** Ungated on every plan. `limit` is null; the count is for your own use. */
    agents: UsageMeter;
    /** Ungated on every plan. `limit` is null. */
    published_skills: UsageMeter;

    /**
     * @deprecated The five per-domain meters collapsed into `actions`. These
     * keys remain populated for one minor version so a pinned client does not
     * break, and every `limit` on them is null — none of these is capped
     * independently any more. Reading a limit here and rendering it as a quota
     * is the bug this shape is being retired to prevent. Removed in the next
     * major.
     */
    passports: UsageMeter;
    /** @deprecated see `actions` */
    proxy_calls: UsageMeter;
    /** @deprecated see `actions` */
    dropoffs: UsageMeter;
    /** @deprecated see `actions` */
    skill_invocations: UsageMeter;
  };
  /** Humans on the account, owner included. No plan caps them: `included` and `total` are null. */
  seats: {
    used: number;
    included: number | null;
    purchased: number;
    total: number | null;
  };
  /** Real vendor bills. Included amount, then the wallet at provider cost.
   * Null when a since/until window was requested: these counters only exist
   * for the current month, so a windowed request gets honest absence rather
   * than the wrong month's numbers. */
  passthrough: {
    l3_classifications: { used: number; included: number | null };
    sms: { used: number; included: number | null };
    email: { used: number; included: number | null };
  } | null;
  /** Never gated, always counted — so you can see what you are running. */
  unlimited: {
    agents: number;
    service_connections: number;
    published_skills: number;
    inbound_webhook_endpoints: number;
  };
  retention: { days: number | null; negotiated: boolean };
  spend_cents: {
    skills: number;
    llm_compute: number;
    identity: number;
    overage: number;
    total: number;
  };
  wallet_cents: { balance: number };
  earnings_cents: { unpaid: number; lifetime: number };
}

// ─── Detector configuration (L7) ────────────────────────────────────
export interface DetectorCustomPattern {
  id: string;
  regex: string;
  severity: 'warning' | 'critical';
  description: string;
}

export interface DetectorWhitelistPattern {
  id: string;
  regex: string;
  description: string;
}

export interface DetectorConfig {
  id: string;
  operator_id: string;
  detector_key: string;
  custom_patterns: DetectorCustomPattern[];
  whitelist_patterns: DetectorWhitelistPattern[];
  severity_overrides: Record<string, 'warning' | 'critical'>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * Per-operator PII redaction config. `threshold` is the confidence needed
 * before redacting (higher redacts less; built-in default 0.4); `countries`
 * is the set of national schemes to run, or null for every country.
 * `configured: false` means no row exists and these are the built-ins.
 */
export interface PiiConfig {
  configured: boolean;
  enabled: boolean;
  threshold: number;
  countries: string[] | null;
  created_at?: string;
  updated_at?: string;
  /** Present on a write: whether the change reduced redaction. */
  direction?: 'loosening' | 'tightening';
}

/** Partial update. Omit to leave untouched; null clears to the built-in. */
export interface PiiConfigUpdate {
  enabled?: boolean;
  threshold?: number | null;
  countries?: string[] | null;
}

export interface DetectorConfigUpsert {
  custom_patterns?: DetectorCustomPattern[];
  whitelist_patterns?: DetectorWhitelistPattern[];
  severity_overrides?: Record<string, 'warning' | 'critical'>;
  enabled?: boolean;
}

// ─── Accountability ─────────────────────────────────────────────────
/** One tool call an agent reports in a checkpoint or checkout. */
export interface ReportedToolCall {
  service: string;
  method: string;
  target?: string;
}

/** Progress report for a live passport (`POST /v1/passports/:jti/checkpoint`). */
export interface CheckpointInput {
  /** Provider slugs the agent used. */
  services_used: string[];
  tool_calls?: ReportedToolCall[];
  /** Number of actions this report covers. */
  actions_count: number;
  /** Agent ids the work was delegated to. */
  delegated_to?: string[];
  /** At most 1000 characters. */
  summary?: string;
}

/** Final report for a passport (`POST /v1/passports/:jti/checkout`). */
export interface CheckoutInput {
  services_used: string[];
  tool_calls?: ReportedToolCall[];
  actions_count: number;
  delegated_to?: string[];
  /** At most 2000 characters. */
  summary?: string;
}
