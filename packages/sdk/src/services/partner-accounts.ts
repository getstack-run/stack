// Partner-managed accounts: the partner SDK surface.
//
// Platform partners (is_partner=true on their operator row) use this surface to run STACK under their own
// product: each customer gets an isolated account that the partner opens by its own reference, pays for and
// manages through the API, with no consent screen and no action from the customer. The account holds the
// partner's reference for the customer, not the customer's address. The customer can be invited to see it
// (read-only), and when the relationship ends the partner releases the account: the customer claims it through a
// mailed link and the platform checkout, and it moves to them with everything in it.
//
// Being a partner is free. Each account is billed like any customer's account, with your wallet paying: its own plan
// (the first month is taken from your wallet when it opens), its own free amounts and its own action bands, and what it
// costs past them is charged to your wallet. A renewal your wallet cannot pay pauses that account until it can.
//
// Errors worth handling (StackError.code):
//   TENANT_TIER_NOT_ALLOWED  (400) - `tier` was sent on create.
//   TENANT_LIMIT_REACHED     (409) - the partner's deal caps the number of accounts.
//   RELEASE_EMAIL_REQUIRED   (400) - a release with no invited customer and no `email`.
//   RELEASE_NOT_AVAILABLE    (409) - the account cannot be released now, or a customer's own release cannot be withdrawn.
//   RELEASE_CMEK_ACTIVE      (409) - the account's data is under a customer-managed key: turn the key off first.
//   RATE_LIMITED             (429) - too many releases and invitations this hour.
//   INSUFFICIENT_BALANCE     (402) - the wallet cannot cover the first month of a new account, or of controls.
//   ALLOWANCE_EXHAUSTED      (402) - the partner's negotiated hard cap was reached.
//   TENANT_BILLED_BY_PARTNER (403) - an account key called a billing mutation.
//   BILLING_ACCOUNT_INACTIVE (403) - the account's partner is suspended or removed.

import type { HttpClient } from '../client.js';

export interface CreateAccountInput {
  /** Your own reference for the customer (1-256 chars), unique per partner. A repeat returns the account that exists. */
  external_ref: string;
  /** Switch the account's hosted controls on as it opens: their first month is taken from your wallet with the plan's. Off when omitted. */
  controls?: boolean;
}

export interface CreateAccountResult {
  account_id: string;
  external_ref: string;
  /** The partner pays for the account; this is always 'partner'. */
  billing: 'partner';
  status: string;
  /** False when you already had an account under this reference: nothing was made, and there is no key. */
  created: boolean;
  created_at: string;
  /** Plaintext account API key: returned ONLY by the call that created the account. Store it immediately. */
  api_key?: string;
}

export interface AccountUsage {
  /** UTC month, `YYYY-MM`. */
  period: string;
  /** This account's own month-to-date metered actions. */
  actions: number;
}

/** What you pay for one account and where it stands. */
export interface AccountPlan {
  /** What a month of the account's plan costs, in cents. */
  monthly_cents: number;
  /** `active`: paid to its renewal. `paused`: your wallet did not cover a renewal, and the account waits for it. */
  status: 'active' | 'paused';
  renews_on: string | null;
  /** Hosted controls, the account's own, off unless you switched them on. */
  controls: { monthly_cents: number; status: 'off' | 'active' | 'paused'; renews_on: string | null };
}

export interface AccountView {
  account_id: string;
  external_ref: string | null;
  billing: 'partner';
  status: string;
  created_at: string;
  deleted_at: string | null;
  /** Whether the customer was invited to see the account, and whether they accepted. Never their address. */
  invite: { status: 'none' | 'invited' | 'active' };
  /** Absent when the usage readout is unavailable. */
  usage?: AccountUsage;
  /** The account's own plan, paid from your wallet. */
  plan?: AccountPlan;
}

export interface RevokeAccountResult {
  /** False when the account was already closed (the call is idempotent). */
  transitioned: boolean;
  /** The account's inbound webhooks closed by this call's cascade. */
  webhooks_revoked: number;
  /** The account's passports revoked by this call's cascade. */
  passports_revoked: number;
}

export interface InviteAccountInput {
  /** The customer's address, given at this moment. It is the customer's only when they accept. */
  email: string;
  name?: string;
}

export interface InviteAccountResult {
  status: 'invited';
  expires_at: string | null;
}

export interface ReleaseAccountInput {
  /** Where the claim link goes. Without it, the one customer invited to the account. */
  email?: string;
}

export type ReleaseStatus = 'pending' | 'completed' | 'returned' | 'cancelled';

/**
 * A release as you read it. `returned` means the claim did not complete (the link lapsed, or the check or the
 * checkout did not pass) and the account is still yours; the reason is never given.
 */
export interface ReleaseRecord {
  account_id: string;
  external_ref: string | null;
  status: ReleaseStatus;
  requested_by: 'partner' | 'customer';
  requested_at: string;
  expires_at: string;
  completed_at: string | null;
}

export interface IssueAccountPassportInput {
  agent_id: string;
  /**
   * The one live Mission (`ms_*`) under the account this passport is issued
   * for. Required, exactly one id. Open it with a client authenticated by
   * the account's API key (`missions.open({ agent_id, ... })`).
   */
  mission_ids: [string];
  ttl_seconds?: number;
  services?: unknown[];
  named_intents?: string[];
  accountability_mode?: 'enforced' | 'logged' | 'standard';
}

const account = (accountId: string) => `/v1/partner/accounts/${encodeURIComponent(accountId)}`;

export class PartnerAccountsService {
  constructor(private client: HttpClient) {}

  /** Open an account for a customer under your own reference. Idempotent on the reference. */
  async create(input: CreateAccountInput): Promise<CreateAccountResult> {
    return this.client.post<CreateAccountResult>('/v1/partner/accounts', input);
  }

  /** Your accounts, or the one under a reference. */
  async list(filter: { external_ref?: string } = {}): Promise<AccountView[]> {
    const query = filter.external_ref === undefined ? '' : `?external_ref=${encodeURIComponent(filter.external_ref)}`;
    const res = await this.client.get<{ accounts: AccountView[] }>(`/v1/partner/accounts${query}`);
    return res.accounts;
  }

  async get(accountId: string): Promise<AccountView> {
    return this.client.get<AccountView>(account(accountId));
  }

  /** Close an account. Cascades to the account's inbound webhooks and passports. */
  async revoke(accountId: string): Promise<RevokeAccountResult> {
    return this.client.delete<RevokeAccountResult>(account(accountId));
  }

  /** A new API key for an account, returned once; the one it replaces stops working at once. */
  async rotateKey(accountId: string): Promise<{ account_id: string; api_key: string }> {
    return this.client.post(`${account(accountId)}/rotate-key`, {});
  }

  /**
   * Switch hosted controls on or off for one account. On, its first month is taken from your wallet at once (402
   * INSUFFICIENT_BALANCE when it cannot be, and nothing changes); off, the charge ends. Direct partner administrator
   * authentication.
   */
  async setControls(accountId: string, enabled: boolean): Promise<{ account_id: string; plan?: AccountPlan }> {
    return this.client.put(`${account(accountId)}/controls`, { enabled });
  }

  /** Invite the customer to see the account, read-only. The invitation is mailed to the address given. */
  async invite(accountId: string, input: InviteAccountInput): Promise<InviteAccountResult> {
    return this.client.post<InviteAccountResult>(`${account(accountId)}/invite`, input);
  }

  /**
   * Release the account to its customer: they are mailed a claim link, and when they complete the checkout and the
   * sanctions check clears, the account is theirs and your access ends. Repeating the call inside ten minutes returns
   * the release that is pending without mailing again.
   */
  async release(accountId: string, input: ReleaseAccountInput = {}): Promise<ReleaseRecord> {
    const res = await this.client.post<{ release: ReleaseRecord }>(`${account(accountId)}/release`, input);
    return res.release;
  }

  /** Withdraw a release you started and the customer has not claimed. */
  async cancelRelease(accountId: string): Promise<{ cancelled: boolean }> {
    return this.client.delete<{ cancelled: boolean }>(`${account(accountId)}/release`);
  }

  /** Where the release of one account stands, also after the customer claimed it and it is no longer yours. */
  async getRelease(accountId: string): Promise<ReleaseRecord> {
    const res = await this.client.get<{ release: ReleaseRecord }>(`${account(accountId)}/release`);
    return res.release;
  }

  /** Every release you have a record of. */
  async listReleases(): Promise<ReleaseRecord[]> {
    const res = await this.client.get<{ releases: ReleaseRecord[] }>('/v1/partner/releases');
    return res.releases;
  }

  // Resources provisioned under an account. Stored as nested methods so
  // the call site reads naturally: `stack.partner.accounts.createInboundWebhook(accountId, ...)`.

  async createInboundWebhook(
    accountId: string,
    input: {
      provider: 'agentmail' | 'generic';
      agent_id: string;
      forward_url?: string | null;
      generic_config?: {
        signature_header?: string;
        signature_algorithm?: 'hmac-sha256' | 'hmac-sha1';
        dedupe_key_path?: string;
        content_paths?: string[];
      };
    },
  ): Promise<{
    id: string;
    provider: string;
    slug: string;
    webhook_url: string;
    webhook_secret: string;
    agent_id: string | null;
    forward_url: string | null;
    created_at: string;
  }> {
    return this.client.post(`${account(accountId)}/inbound-webhooks`, input);
  }

  /** A fresh downstream signing secret for an account's inbound webhook, returned once; the old one signs beside it for 24 hours. */
  async rotateInboundWebhookSecret(
    accountId: string, webhookId: string,
  ): Promise<{ webhook_secret: string; previous_valid_until: string }> {
    return this.client.post(
      `${account(accountId)}/inbound-webhooks/${encodeURIComponent(webhookId)}/rotate-secret`,
      {},
    );
  }

  /** Configure signing through a direct partner administrator client; secrets are never returned. */
  async setInboundWebhookSigningSecret(
    accountId: string, webhookId: string, signingSecret: string, downstreamSigningSecret?: string,
  ): Promise<{ configured: true }> {
    return this.client.put(
      `${account(accountId)}/inbound-webhooks/${encodeURIComponent(webhookId)}/provider-signing-secret`,
      { signing_secret: signingSecret, ...(downstreamSigningSecret !== undefined ? { downstream_signing_secret: downstreamSigningSecret } : {}) },
    );
  }

  async issuePassport(accountId: string, input: IssueAccountPassportInput): Promise<unknown> {
    return this.client.post(`${account(accountId)}/passports/issue`, input);
  }
}

/**
 * convenience helper for the MIME-stamping pattern (touch
 * point 4 in the partner integration spec).
 *
 * Mints a passport under the account (signed with the deployment's key like
 * every passport, `stk.operator_id` names the account) with a
 * default-narrow scope, returning the token along with the value ready
 * for direct header injection (`X-Stack-Passport: <token>`). The
 * receiver verifies offline via `verifyPassportHeader`. `mission_id` is
 * required: open the Mission under the account first, with the account's
 * API key.
 *
 * Defaults: 15-minute TTL, accountability_mode='enforced'. Override
 * `ttl_seconds` (max 3600) or `accountability_mode` when the use case
 * differs from short-lived outbound stamping (e.g. long-running A2A
 * sessions, audit-only logged passports).
 */
export interface MintOutboundPassportInput {
  /** The live account Mission (`ms_*`) the passport is issued for. Required. */
  mission_id: string;
  scopes?: string[];
  ttl_seconds?: number;
  accountability_mode?: 'enforced' | 'logged' | 'standard';
  named_intents?: string[];
}

export interface MintOutboundPassportResult {
  token: string;
  passport_id: string;
  expires_at: string;
  /**
   * The exact value to put in the `X-Stack-Passport` header on
   * outbound MIME / HTTP messages. Equivalent to `token` for v1; kept
   * separate so future variants (e.g. compact tokens, content
   * binding) don't break consumers.
   */
  header_value: string;
}

export async function mintOutboundPassportImpl(
  service: PartnerAccountsService,
  accountId: string,
  agentId: string,
  input: MintOutboundPassportInput,
): Promise<MintOutboundPassportResult> {
  const services = input.scopes && input.scopes.length > 0
    ? [{ scopes: input.scopes }]
    : undefined;

  const issued = await service.issuePassport(accountId, {
    agent_id: agentId,
    mission_ids: [input.mission_id],
    ttl_seconds: input.ttl_seconds ?? 900,
    accountability_mode: input.accountability_mode ?? 'enforced',
    ...(services ? { services } : {}),
    ...(input.named_intents ? { named_intents: input.named_intents } : {}),
  }) as {
    token?: string;
    passport?: string;
    jti?: string;
    passport_id?: string;
    exp?: number;
    expires_at?: string;
  };

  // The /passports/issue response shape uses `passport` (token) and
  // `jti` (id) in the legacy convention; newer call sites stamp
  // `token` + `passport_id`. Coerce both.
  const token = issued.token ?? issued.passport;
  const passportId = issued.passport_id ?? issued.jti;
  if (!token || !passportId) {
    throw new Error('mintOutboundPassport: API response missing token or passport_id');
  }

  const expiresAt =
    issued.expires_at ??
    (typeof issued.exp === 'number' ? new Date(issued.exp * 1000).toISOString() : new Date(Date.now() + (input.ttl_seconds ?? 900) * 1000).toISOString());

  return {
    token,
    passport_id: passportId,
    expires_at: expiresAt,
    header_value: token,
  };
}
