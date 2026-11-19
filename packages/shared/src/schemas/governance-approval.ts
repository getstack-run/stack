// governance approval wire shapes (operate-vs-govern step-up).

import { z } from 'zod';

export const GOVERNANCE_ACTIONS = [
  'fleet_policy_activate',
  'detector_config_upsert',
  'detector_config_reset',
  'review_decide_approve',
  'agent_unblock',
  // Agent and service authority changes use distinct action names so an
  // approval for one mutation class can never be replayed against another.
  // `agent_register` and `agent_skill_allow` are retired: registering an agent, whatever settings it starts with, and
  // allowing a skill (one at a time, or by widening an agent's skill access) need no approval; the owner's own session
  // or key does them directly. Kept so approvals stored before then still read.
  'agent_register',
  // Registering an agent together with its first grants and the hosts its connections' credentials may go to,
  // decided once. The card lists all of it and the approval binds the whole request. It may be confirmed in the
  // chat, as a grant, a widening and a host list each may on their own: the confirmation lists every part.
  'agent_setup',
  'agent_authority_expand',
  'agent_skill_allow',
  'agent_key_enroll',
  'agent_enrollment_ticket_mint',
  'service_grant_expand',
  'service_proxy_disable',
  'service_allowed_hosts_expand',
  // Account-owned routing and money changes must remain human decisions even
  // when an operator API key or OAuth token is being driven by an agent.
  'notification_config_mutate',
  'billing_mutate',
  // Loosening PII redaction asked for these until the owner's own change
  // applied at once. Kept so approvals stored before then still read;
  // PUT and DELETE /v1/pii/config no longer ask for them.
  'pii_config_upsert',
  'pii_config_reset',
  // Authority lifecycle and receiver trust changes are governance, never
  // agent-operational actions. Each is exact-payload-bound and single-use.
  'authority_binding_activate',
  'authority_principal_erase',
  'authority_binding_erase',
  'authority_proof_erase',
  'authority_presentation_erase',
  'authority_receiver_profile_activate',
  'authority_profile_activate',
  'authority_receiver_key_add',
  // Opening an agent account asked for this approval until opening became
  // one call with no Console step. Kept so approvals stored before then
  // still read; POST /v1/accounts no longer asks for it.
  'account_open',
  // Confirming a recipient's consent to be texted and called was an approval until
  // texts and calls stopped needing it. Kept so approvals stored before then still
  // read; nothing asks for it any more. Resuming a paused inbox or phone re-enables
  // sending after bounce, complaint or spam signals, and a human signs for it.
  'account_contact_consent_add',
  'account_piece_resume',
  // Submitting the owner's business details for toll-free verification
  // attests to its opt-in practice in the owner's name and, once approved,
  // lets the number text: a human signs for it.
  'account_toll_free_verification_submit',
  // Changes that transfer or destroy the account, move the control socket, or
  // loosen the account's controls are named here so an approval for one can
  // never be replayed against another. Each is browser-only (see
  // GOVERNANCE_BROWSER_ONLY_ACTIONS).
  'account_email_change',
  'account_delete',
  'control_socket_change',
  'account_control_loosen',
  // A hosted policy held one action of an agent for a person; the approval covers
  // exactly that one call. The held call can be money (a card checkout, a wallet
  // payment, a spend through the proxy), so deciding it is browser-only (see
  // GOVERNANCE_BROWSER_ONLY_ACTIONS), whatever the kind of the held action.
  'control_review',
  // Registering a key lets a self-hosted install vouch for passports in the
  // owner's name through STACK's countersignature, so a person approves, in a
  // browser, each time a key is to be registered for an install.
  'network_install_key_add',
  // Placing an order the customer's own supplier account will pay for spends
  // the customer's money. The order is held until a person approves exactly
  // that order, on the approval page (the link the command line opens) or in
  // the MCP confirmation.
  'making_order_approve',
  // Forgetting a member's single sign-on binding lets the next verified sign-in
  // with the provider in use become that person: whoever the provider says has
  // that address takes the seat. A person approves it, in a browser (see
  // GOVERNANCE_BROWSER_ONLY_ACTIONS).
  'member_sso_binding_clear',
  // Adding a domain to the account's single sign-on lets the sign-in treat an address at that domain as verified
  // once the DNS record proves it, so it loosens who the provider may vouch for. A person approves the exact domain,
  // in a browser (see GOVERNANCE_BROWSER_ONLY_ACTIONS). Removing a domain only tightens and needs no approval.
  'sso_domain_add',
  // Setting up or changing the identity provider of the account's single sign-on decides who the account lets in as any
  // member, the owner included, so whatever loosens it (a new provider, a changed issuer, client, address or role,
  // turning sign-in on) is approved by a person in a browser (see GOVERNANCE_BROWSER_ONLY_ACTIONS). Turning it off or
  // removing it only tightens and needs no approval.
  'sso_config_change',
  // Switching the account, or one agent, to "Trust my agents" from anywhere but a signed-in browser: the agents then
  // act without asking first. A person confirms it in the chat (the MCP confirmation the model cannot answer) or on
  // the approval page. Switching back to asking first needs nothing.
  'trust_widen',
  // `intent_approve` is retired: the owner's key, SDK, CLI or chat decides an intent directly. Kept so approvals stored
  // before then still read.
  'intent_approve',
  // Approving an intent that can move money (an onchain transaction, or a wallet or gas cost, read from its raw JSON when
  // STACK cannot read it as an intent, and assumed when even that cannot be read): browser-only, as a held payment is (see GOVERNANCE_BROWSER_ONLY_ACTIONS). A signed-in dashboard session is
  // the person and passes free. Rejecting only refuses and needs no approval.
  'intent_approve_payment',
  // Retired: loosening the identity settings, removing or weakening what a service requires of an agent, and
  // dismissing an agent's warnings need no approval. Kept so approvals stored before then still read.
  'identity_settings_loosen',
  'service_requirement_loosen',
  'agent_warnings_dismiss',
] as const;
export type GovernanceAction = (typeof GOVERNANCE_ACTIONS)[number];
export const GovernanceActionEnum = z.enum(GOVERNANCE_ACTIONS);

/**
 * Actions a person approves only on the approval page in a signed-in browser,
 * never through an in-chat confirmation. The in-chat confirmation is attested
 * by the MCP client, so it is only as strong as that client: anything that
 * moves the customer's own money through STACK (billing), deletes or transfers
 * the account, moves the control socket or loosens the account's controls
 * stays out of the chat. A held action
 * (`control_review`) is among them: what a policy holds may be a payment, and
 * no kind of held action is told apart in the chat. The chat-decision route
 * refuses to approve them; the MCP server opens the approval page instead of
 * asking in the chat. Pinned by a test.
 *
 * A print or making order (`making_order_approve`) is NOT in the set: the
 * approval binds exactly that order (its supplier, design hash, total, product,
 * quantity and destination), the
 * customer's own supplier account charges it and STACK's money pays nothing,
 * so the owner may approve it in the chat or on the approval page (the link
 * the command line opens). The confirmation names the supplier, product,
 * quantity, destination city and country, and amount.
 *
 * Widening an agent's access to a service the owner connected is NOT in the
 * set: a new grant, a wider grant, a wider host list and the combined agent
 * setup (`service_grant_expand`, `service_allowed_hosts_expand`, `agent_setup`)
 * are confirmed in the chat, which shows every part of the change (the scope,
 * the constraints, the data flow, the hosts, and the policy listing a grant
 * carries). A grant approval that also lists the service in the agent's own
 * policy is chat-confirmable only because that listing adds one rule for that
 * connection and touches nothing else of the policy (spend, review, block,
 * recipients, surfaces); the API builds it that way and refuses to build it any
 * other way, so a combined step that would touch those has no combined form
 * and goes through `account_control_loosen`, which stays in the browser.
 */
export const GOVERNANCE_BROWSER_ONLY_ACTIONS: ReadonlySet<GovernanceAction> = new Set<GovernanceAction>([
  'account_email_change',
  'account_delete',
  'billing_mutate',
  'control_socket_change',
  'account_control_loosen',
  'control_review',
  'member_sso_binding_clear',
  'sso_domain_add',
  'sso_config_change',
  'network_install_key_add',
  'intent_approve_payment',
]);

/**
 * The one browser-only action a chat APP (Telegram, a text, Slack) may also
 * carry, and then only for a held card or wallet payment, within the per-payment
 * and per-day limits the customer set (`review.chat`, none by default), from the
 * owner's bound chat identity, single-use and bound to the exact payment. It
 * stays in GOVERNANCE_BROWSER_ONLY_ACTIONS: the MCP confirmation and the
 * `chat-decision` route never approve it, and every other held action (a send,
 * a proxy call) stays on the approval page. Pinned by a test.
 */
export const GOVERNANCE_CHAT_APP_PAYMENT_ACTIONS: ReadonlySet<GovernanceAction> = new Set<GovernanceAction>(['control_review']);

export const GOVERNANCE_APPROVAL_STATUSES = [
  'pending',
  'approved',
  'rejected',
  'consumed',
  'expired',
] as const;
export type GovernanceApprovalStatus = (typeof GOVERNANCE_APPROVAL_STATUSES)[number];
export const GovernanceApprovalStatusEnum = z.enum(GOVERNANCE_APPROVAL_STATUSES);

/**
 * 24 hours. The person who decides is not the caller: they read the link in a
 * chat or a notification and may act hours later. The window stays bounded
 * because the decision itself needs a signed-in browser session (or a
 * client-attested chat confirmation), the approval is bound to the exact
 * payload hash and is single-use, so a longer window widens nothing.
 */
export const GOVERNANCE_APPROVAL_TTL_SECONDS = 24 * 60 * 60;

/** 24 hours for a white-label tenant's request: the deciding human
 *  is the partner's admin, who is not the caller and may not be watching. */
export const GOVERNANCE_TENANT_APPROVAL_TTL_SECONDS = 24 * 60 * 60;

export const GovernanceApprovalView = z.object({
  id: z.string(),
  action: GovernanceActionEnum,
  resource_id: z.string(),
  summary: z.string(),
  policy_preview: z.record(z.unknown()).nullable().optional(),
  /** present only on an `account_open` approval: what the human is asked to open. */
  account_preview: z
    .object({
      name: z.string(),
      /** Null when the account opens without a per-agent budget. */
      monthly_budget_cents: z.number().int().nullable(),
      pieces: z.array(z.string()),
    })
    .nullable()
    .optional(),
  /** present only on an `agent_setup` approval: everything the one decision covers, in full. */
  setup_preview: z.record(z.unknown()).nullable().optional(),
  /** present only on a `service_grant_expand` approval: the grant in full, and the policy listing it carries. */
  grant_preview: z.record(z.unknown()).nullable().optional(),
  /** present only on an `intent_approve` or `intent_approve_payment` approval: what the agent asked for, one line a field (`lines`), or the raw JSON of an intent STACK cannot read (`raw`). */
  intent_preview: z.record(z.unknown()).nullable().optional(),
  requested_via: z.enum(['operator_key', 'member_session', 'oauth', 'member_key']),
  status: GovernanceApprovalStatusEnum,
  expires_at: z.string(),
  created_at: z.string(),
  decided_at: z.string().nullable(),
  /** How the decision arrived: dashboard, chat_elicitation, bearer_reject, chat_telegram, chat_sms or chat_slack. Null while pending. */
  decided_via: z.string().nullable().optional(),
  /**
   * present only on a partner's list, for an approval that belongs
   * to one of its white-label tenants. `name` is the partner's own
   * external_customer_id for the tenant, or the tenant id when none was set.
   */
  tenant: z.object({ operator_id: z.string(), name: z.string() }).optional(),
});
export type GovernanceApprovalView = z.infer<typeof GovernanceApprovalView>;

export const GovernanceDecisionInput = z.object({
  decision: z.enum(['approve', 'reject']),
});
export type GovernanceDecisionInput = z.infer<typeof GovernanceDecisionInput>;

/** One approval with the payload hash a chat confirmation must bind to. */
export const GovernanceApprovalDetail = z.object({
  approval: GovernanceApprovalView,
  payload_hash: z.string().regex(/^[0-9a-f]{64}$/),
  approval_url: z.string(),
});
export type GovernanceApprovalDetail = z.infer<typeof GovernanceApprovalDetail>;

/**
 * A decision made in the chat client through MCP elicitation and relayed by
 * the hosted MCP server. An approval needs the MCP server's attestation over
 * every field; a rejection is always accepted from a non-agent caller.
 */
export const GovernanceChatDecisionInput = z.object({
  decision: z.enum(['approve', 'reject']),
  payload_hash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  mcp_session_hash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  elicitation_id: z.string().uuid().optional(),
  issued_at: z.number().int().positive().optional(),
  attestation: z.string().regex(/^[0-9a-f]{64}$/).optional(),
}).strict();
export type GovernanceChatDecisionInput = z.infer<typeof GovernanceChatDecisionInput>;
