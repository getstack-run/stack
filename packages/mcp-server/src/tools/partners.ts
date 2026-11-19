import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { OperatorStartPassportInput } from './mission-spec.js';
import { toolJson, safeProvisioningMetadata, webhookMetadataKeys } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const PARTNERS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Partner-managed accounts
  stack_partner_create_account: hint.write('Open partner account'),
  stack_partner_list_accounts: hint.read('List partner accounts'),
  stack_partner_get_account: hint.read('Get partner account'),
  stack_partner_revoke_account: hint.destructive('Close partner account'),
  stack_partner_invite_customer: hint.write('Invite customer to partner account'),
  stack_partner_release_account: hint.write('Release partner account to customer'),
  stack_partner_cancel_release: hint.write('Withdraw account release'),
  stack_partner_get_release: hint.read('Get account release'),
  stack_partner_list_releases: hint.read('List account releases'),
  stack_partner_create_account_webhook: hint.write('Create account inbound webhook'),
  stack_partner_issue_account_passport: hint.write('Issue account Passport'),
};

const WITHHELD = 'Needs partner:write, withheld from directory tokens: it opens, closes and releases accounts and issues account Passports.';

/** The tools of this group the directory profile leaves out, each with its reason. */
export const PARTNERS_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_partner_issue_account_passport: 'Returns a Passport bearer token into the conversation.',
  stack_partner_create_account: WITHHELD,
  stack_partner_revoke_account: WITHHELD,
  stack_partner_invite_customer: WITHHELD,
  stack_partner_release_account: WITHHELD,
  stack_partner_cancel_release: WITHHELD,
  stack_partner_create_account_webhook: WITHHELD,
};

/** Partner-managed accounts: open one for a customer, invite them to see it, release it to them. */
export function registerPartnersTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Partner-managed accounts ────────────────────────────────────
  //
  // Platform partners (operators with is_partner=true) open an isolated
  // account for each customer, under their own reference for the customer,
  // and pay for it. Each account has its own audit chain, KMS context,
  // signing key, webhook surface and passport issuance, and its own plan,
  // free amounts and usage like any customer's, which the partner's wallet
  // pays for. The partner sees account metadata, its plan and
  // month-to-date usage; NEVER account audit content, and MCP never returns
  // an account API key or secret (the key is returned once to the REST API
  // or SDK, which also replace a lost one). The customer holds no address
  // with STACK until the partner invites them or releases the account.
  // Non-partner operators get 403 on every tool below.

  server.tool(
    'stack_partner_create_account',
    "Open an account for one of your customers under your own reference. The account is an isolated STACK operator with its own audit chain, signing key and webhooks; it has its own plan, free amounts and usage like any customer's, and your wallet pays for it (billing: 'partner'). A wallet that cannot cover the account's first month refuses the call with 402 INSUFFICIENT_BALANCE and no account is made. Hosted controls are off unless controls is true, which switches them on as the account opens and takes their first month from the wallet with the plan's; a wallet that cannot cover both refuses the call. Repeating the call with the same external_ref returns the account that exists (created: false). It holds no email of the customer. Fails with TENANT_LIMIT_REACHED when the account cap is reached. Returns account metadata without an API key: account credentials are created through the REST API or SDK, never through MCP.",
    {
      external_ref: z
        .string()
        .min(1)
        .max(256)
        .describe('Your stable reference for this customer (e.g. inbox_id, customer_id). Unique per partner; it is the idempotency key of the call.'),
      controls: z.boolean().optional().describe("Switch the account's hosted controls on as it opens. Off when omitted."),
    },
    async (input) => {
      const result = await api('POST', '/v1/partner/accounts', input);
      return toolJson(safeProvisioningMetadata(result,
        ['account_id', 'external_ref', 'billing', 'status', 'created', 'created_at']));
    },
  );

  server.tool(
    'stack_partner_list_accounts',
    "List the accounts you opened, or the one under an external_ref. Returns each account's metadata (status, external_ref, billing: 'partner', whether the customer was invited and accepted) plus its own month-to-date usage and its plan (what you pay for it and where it stands). Never returns audit content or API keys.",
    {
      external_ref: z.string().min(1).max(256).optional().describe('Only the account under this reference.'),
    },
    async ({ external_ref }) => {
      const query = external_ref === undefined ? '' : `?external_ref=${encodeURIComponent(external_ref)}`;
      const result = await api('GET', `/v1/partner/accounts${query}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_partner_get_account',
    "Get one account by account_id. Returns its metadata, status, billing: 'partner', whether the customer was invited, its own month-to-date usage and its plan (what you pay for it and where it stands). Never returns audit content or API keys.",
    {
      account_id: z.string().describe('Account id (op_*)'),
    },
    async ({ account_id }) => {
      const result = await api('GET', `/v1/partner/accounts/${encodeURIComponent(account_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_partner_revoke_account',
    "Close an account. Its API key stops working, and every inbound webhook and passport under it is revoked in the same call. Returns transitioned plus the cascade counts (webhooks_revoked, passports_revoked). A repeated call completes a cascade that stopped part-way. The account's audit chain remains intact for the retention window. A closed account's reference is not reused.",
    {
      account_id: z.string().describe('Account id (op_*)'),
    },
    async ({ account_id }) => {
      const result = await api('DELETE', `/v1/partner/accounts/${encodeURIComponent(account_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_partner_invite_customer',
    "Invite your customer to see an account. An invitation is mailed to the address given; it becomes the customer's address with STACK only when they accept. The customer sees the account read-only: they can read it and change nothing. Counts against your hourly limit of invitations and releases (RATE_LIMITED).",
    {
      account_id: z.string().describe('Account id (op_*)'),
      email: z.string().email().describe("The customer's address, given at this moment."),
      name: z.string().min(1).max(100).optional().describe("The customer's name, shown on the account's member list."),
    },
    async ({ account_id, ...body }) => {
      const result = await api('POST', `/v1/partner/accounts/${encodeURIComponent(account_id)}/invite`, body);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_partner_release_account',
    "Release an account to its customer when the relationship ends. The customer is mailed a claim link; they start the platform trial with a card and the sanctions check runs, and only when both pass does the account move to them, with everything in it (agents, pieces, the record). Your access, key and billing end at that moment, and everything you set up in the account is removed, so the customer starts with none of it: service connections, the Stripe key (its payment links are turned off at Stripe first), the agent's Telegram bot token, Slack and chat approvers, supplier and OAuth app keys, the control socket's addresses and secrets, notification, wake and inbound webhook destinations and secrets, network installs and the payout destination. If a step at Stripe or Telegram cannot finish, the claim waits and the account stays yours. A claim that is not completed in time, or whose check does not clear, leaves the account with you and the release reads 'returned' without a reason. Without email the link goes to the one customer invited to the account (RELEASE_EMAIL_REQUIRED otherwise). Repeating the call inside ten minutes returns the pending release without mailing again. Read where it stands with stack_partner_get_release.",
    {
      account_id: z.string().describe('Account id (op_*)'),
      email: z.string().email().optional().describe("Where the claim link goes. Without it, the one customer invited to the account."),
    },
    async ({ account_id, ...body }) => {
      const result = await api('POST', `/v1/partner/accounts/${encodeURIComponent(account_id)}/release`, body);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_partner_cancel_release',
    "Withdraw a release you started and the customer has not claimed: the claim link stops working and the release reads 'cancelled'. Returns cancelled: false when none is pending. A release the customer asked for cannot be withdrawn (RELEASE_NOT_AVAILABLE).",
    {
      account_id: z.string().describe('Account id (op_*)'),
    },
    async ({ account_id }) => {
      const result = await api('DELETE', `/v1/partner/accounts/${encodeURIComponent(account_id)}/release`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_partner_get_release',
    "Get where the release of one account stands: status pending, completed (the customer claimed it and it is theirs), returned (the claim did not complete and the account is still yours; the reason is never given) or cancelled. It reads the record you keep, so it also answers after the account has moved and is no longer yours.",
    {
      account_id: z.string().describe('Account id (op_*)'),
    },
    async ({ account_id }) => {
      const result = await api('GET', `/v1/partner/accounts/${encodeURIComponent(account_id)}/release`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_partner_list_releases',
    'List every release you have a record of, newest first, with its status (pending, completed, returned or cancelled), who asked (partner or customer) and when it was requested and expires.',
    {},
    async () => {
      const result = await api('GET', '/v1/partner/releases');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_partner_create_account_webhook',
    'Create an inbound webhook under an account the partner owns and return its URL and metadata. The webhook belongs to the account: its audit chain and KMS context are the account\'s. Signing is configured by the partner owner or admin through the REST API or SDK (https://getstack.run/docs/api/inbound-webhooks); this tool returns no signing secret.',
    {
      account_id: z
        .string()
        .describe('Account id (op_*) — must belong to your partner operator.'),
      provider: z.enum(['agentmail', 'generic']).describe('Provider identifier.'),
      agent_id: z
        .string()
        .describe(
          'Agent under the account that security_events attribute to (e.g. agt_*). Must belong to the account.',
        ),
      forward_url: z
        .string()
        .url()
        .nullable()
        .optional()
        .describe('Downstream URL STACK POSTs to after a clean scan. Null = log-only.'),
      generic_config: z
        .object({
          signature_header: z.string().optional(),
          signature_algorithm: z.enum(['hmac-sha256', 'hmac-sha1']).optional(),
          dedupe_key_path: z.string().optional(),
          content_paths: z.array(z.string()).optional(),
        })
        .optional(),
    },
    async (input) => {
      const { account_id, ...body } = input;
      const result = await api('POST', `/v1/partner/accounts/${encodeURIComponent(account_id)}/inbound-webhooks`, body);
      return toolJson({ ...safeProvisioningMetadata(result, webhookMetadataKeys),
        setup_required: true, setup_url: 'https://getstack.run/docs/api/inbound-webhooks' });
    },
  );

  server.tool(
    'stack_partner_issue_account_passport',
    "Issue a STACK passport under an account on the customer's behalf. Like every passport it is signed with the deployment's signing key and verifies offline against the deployment's JWKS (/v1/.well-known/jwks.json, which verifyPassportHeader reads); its stk.operator_id is the account. The account's own signing keys sign claims, not passports. Issuance counts as an action of the account, on its own plan. mission_ids is required: exactly one live Mission under the account, and the Passport never outlives it. Fields match stack_issue_passport's API body (scopes, ttl_seconds, intent, checkpoint_interval_seconds, identity_claim_ids, authority_binding_ids). Returns the Passport token, which can be stamped on outbound mail as an X-Stack-Passport header.",
    {
      account_id: z
        .string()
        .describe('Account id (op_*) — must belong to your partner operator.'),
      agent_id: z.string().describe('Agent under the account that the passport is issued for.'),
      mission_ids: z
        .array(z.string().regex(/^ms_[\w-]+$/))
        .length(1)
        .describe(
          "Exactly one live Mission id (ms_*) opened under the account (with the account's API key), assigned to this agent or unassigned.",
        ),
      ...OperatorStartPassportInput.shape,
    },
    async (input) => {
      const { account_id, ...body } = input;
      const result = await api('POST', `/v1/partner/accounts/${encodeURIComponent(account_id)}/passports/issue`, body);
      return toolJson(result);
    },
  );
}
