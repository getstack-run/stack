// PartnerTenantService: partner-managed accounts.
//
// A partner opens an account for each of its customers through the API and pays for it. The account is
// an isolated child operator (`parent_operator_id` is the partner) keyed by the partner's own reference
// (`external_customer_id` in the table, `external_ref` on the wire). It holds no email of the customer:
// the address it carries is a placeholder under a reserved domain that no mail flow can reach. The
// customer is invited to see the account (a read-only member, which is the only point where an address
// is stored, and only when the partner chooses to invite) and, when the relationship ends, the account is
// released to them (by the hosted release service, which moves the whole account with its chain and contents).
//
// An account is billed like any customer's, with its partner as the payer: it has its own plan and its own free
// amounts, and what it costs is taken from its partner's wallet (the hosted billing account and the partner plans;
// an engine install has no plans). A partner can not hand an account a plan of its own choosing (`tier`), and a deal's
// `maxTenants` caps how many may exist at once.
//
// The partner's own STACK API key authorises every operation; STACK enforces ownership at the
// repository layer (parent_operator_id == partner.id) on every read and write.
//
// Child operators have:
//   - Their own isolated audit chain (per-operator advisory locks +
//     hash chain entry per write, same shape as any other operator)
//   - Their own KMS context
//   - Their own per-operator signing key (lazy-created on first claim emission)
//   - Their own webhook + passport surface
//
// The partner does NOT see:
//   - The account's audit log content
//   - Intent_claim bodies
//   - Security_event metadata
//
// The partner DOES see:
//   - Month-to-date metered actions per account, and its plan (what it costs, and whether it is paid to its renewal)
//   - Account metadata (created_at, external_ref, status, whether the customer was invited)
//
// An account has no human user until its customer claims it. The partner keeps the account's API key
// server-side and uses it only when an action specifically requires the account's own auth context
// (most partner flows route through the partner's own key and the account id).

import {
  type Database,
  ids,
  hashApiKey,
  generateId,
  NotFoundError,
  ForbiddenError,
  InvalidRequestError,
  ConflictError,
  StackError,
  LimitOverrides,
  OperatorTier,
  TENANT_PLACEHOLDER_EMAIL_DOMAIN,
  acquireOAuthOperatorLock,
} from '@stack/shared';
import { contractPlanLimits, type PlanLimitsReader } from './entitlements/plan-limits.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';

export interface PartnerTenantServiceDeps {
  db: Database;
  operatorRepo: OperatorRepository;
  /** How many active accounts a partner's plan allows, with its deal's overrides; absent, the contract plan's (no cap). */
  planLimits?: PlanLimitsReader;
  /**
   * Month-to-date metered actions for the partner and its accounts, split per
   * operator. Optional so unit tests can omit it; account views then carry
   * no usage block.
   */
  poolUsage?: {
    getPoolMeteredTotals(
      billingOperatorId: string,
      since: Date,
      until?: Date,
    ): Promise<{ total: number; byOperator: Record<string, number>; tenantCount: number }>;
  };
  /**
   * Whether the customer of each account has been invited to see it, and has accepted. Absent, every view says
   * `none` (unit tests; the answer is only ever a status, never an address).
   */
  members?: {
    inviteStatuses(operatorIds: string[]): Promise<Map<string, 'invited' | 'active'>>;
  };
  /**
   * STACK's hosted billing of accounts: the first month of an account's plan is taken from the partner's wallet in the
   * transaction that makes the account (a wallet that cannot pay refuses the create with a 402 and no account is made),
   * and each account's plan is read for the partner. Absent (an engine install, unit tests): accounts have no plan.
   */
  accountPlans?: {
    chargeOpening(tx: unknown, input: { partnerId: string; accountId: string; controls?: boolean }): Promise<void>;
    views(partnerId: string, accountIds: readonly string[]): Promise<Map<string, TenantPlanView>>;
  };
}

/** What a partner reads of one account's plan: the plan, and its controls when the partner switched them on. */
export interface TenantPlanView {
  monthly_cents: number;
  /** `active`: paid to its renewal. `paused`: the wallet did not cover a renewal, and the account waits for it. */
  status: 'active' | 'paused';
  renews_on: string | null;
  controls: { monthly_cents: number; status: 'off' | 'active' | 'paused'; renews_on: string | null };
}

/** The partner pays for every account; this is the value every account view reports. */
export const TENANT_BILLING = 'partner' as const;

export interface CreateTenantInput {
  /** The partner's own reference for its customer (1 to 256 characters). Unique per partner: the idempotency key of a create. */
  external_ref: string;
  /** Switch the account's hosted controls on at opening: their first month is taken from the partner's wallet with the plan's. Off when absent. */
  controls?: boolean;
}

export interface CreateTenantResult {
  account_id: string;
  external_ref: string;
  /** Always 'partner': the partner pays for the account. */
  billing: typeof TENANT_BILLING;
  status: string;
  /** False when the partner already had an account under this reference: nothing was made. */
  created: boolean;
  created_at: string;
  /** Plaintext account API key: returned ONLY by the call that created the account. */
  api_key?: string;
}

export type InviteStatus = 'none' | 'invited' | 'active';

export interface TenantView {
  account_id: string;
  external_ref: string | null;
  /** Always 'partner': the partner pays for the account. */
  billing: typeof TENANT_BILLING;
  status: string;
  created_at: string;
  deleted_at: string | null;
  invite: { status: InviteStatus };
  /** This account's own metered actions, current UTC month. */
  usage?: { period: string; actions: number };
  /** The account's own plan, paid by the partner (absent where STACK does not bill accounts). */
  plan?: TenantPlanView;
}

export class TenantTierNotAllowedError extends StackError {
  constructor() {
    super(
      "An account's plan is not chosen by the partner. Remove `tier` from the request.",
      'TENANT_TIER_NOT_ALLOWED',
      400,
    );
  }
}

export class TenantLimitReachedError extends StackError {
  constructor(limit: number) {
    super(
      `This partner account may have at most ${limit} active accounts. Contact STACK to raise the limit.`,
      'TENANT_LIMIT_REACHED',
      409,
    );
  }
}

export class PartnerTenantService {
  constructor(private deps: PartnerTenantServiceDeps) {}

  /**
   * Open an isolated child operator owned by the partner under the partner's own reference. Returns the account id
   * and its plaintext API key (shown once). Repeating the call with the same reference returns the account that
   * exists, with `created: false` and no key (rotate it if it was lost), so a retried call opens nothing twice.
   *
   * A reference that belongs to a closed account is a conflict: a closed account's reference is never reused.
   */
  async createTenant(
    partnerOperatorId: string,
    input: CreateTenantInput,
  ): Promise<CreateTenantResult> {
    // A partner cannot hand an account a plan: that was a free paid plan with
    // no payment behind it. Refuse loudly rather than ignore the field, so an
    // older client that still sends one learns why.
    if (Object.prototype.hasOwnProperty.call(input, 'tier')) {
      throw new TenantTierNotAllowedError();
    }
    // Hosted controls are STACK's hosted deployment's: an install has none to switch on, and says so rather than ignore the request.
    if (input.controls && !this.deps.accountPlans) throw new InvalidRequestError('Hosted controls are not available on this deployment.');

    const id = ids.operator();
    const apiKeyPlain = generateId('sk_live', 32);
    const apiKeyHash = hashApiKey(apiKeyPlain);

    // A unique placeholder address. The account has no human user, but the operators table has a
    // NOT NULL UNIQUE email constraint that cannot be relaxed without a chain-binding migration. The
    // placeholder is opaque, under a reserved domain, and never addressable by any mail flow. It is
    // replaced by the customer's own address when the customer claims the account.
    const email = `tenant-${id}@${partnerOperatorId}${TENANT_PLACEHOLDER_EMAIL_DOMAIN}`;

    return this.deps.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, partnerOperatorId);

      // Recheck lifecycle and role while the shared operator lock is held.
      const partner = await this.deps.operatorRepo.findById(partnerOperatorId, tx);
      if (!partner) throw new NotFoundError('operator', partnerOperatorId);
      if (partner.status !== 'active') {
        throw new ForbiddenError('operator is not active');
      }
      if (!partner.is_partner) {
        throw new ForbiddenError('operator is not a partner');
      }

      // The repeat check, the duplicate check and the deal cap are in the same transaction as the insert,
      // under the partner lock, so concurrent creates cannot overshoot or open the same reference twice.
      const existing = await this.deps.operatorRepo.listChildren(partnerOperatorId, tx);
      const duplicate = existing.find((child) => child.external_customer_id === input.external_ref);
      if (duplicate) {
        if (duplicate.status !== 'active') {
          throw new ConflictError(`external_ref=${input.external_ref} belongs to a closed account and cannot be reused`);
        }
        return {
          account_id: duplicate.id,
          external_ref: input.external_ref,
          billing: TENANT_BILLING,
          status: duplicate.status,
          created: false,
          created_at: duplicate.created_at.toISOString(),
        };
      }

      const overrides = partner.limit_overrides == null
        ? null
        : LimitOverrides.safeParse(partner.limit_overrides);
      if (overrides && !overrides.success) {
        throw new StackError('Partner limits are unreadable', 'SERVICE_UNAVAILABLE', 503);
      }
      const maxTenants = (this.deps.planLimits ?? contractPlanLimits)(OperatorTier.safeParse(partner.tier).data ?? 'free', overrides?.data ?? null).maxTenants;
      const activeTenants = existing.filter((child) => child.status === 'active').length;
      if (activeTenants >= maxTenants) {
        throw new TenantLimitReachedError(maxTenants);
      }

      const row = await this.deps.operatorRepo.insertChild({
        id,
        email,
        api_key_hash: apiKeyHash,
        parent_operator_id: partnerOperatorId,
        external_customer_id: input.external_ref,
        // Never read for billing (accounts resolve through the billing account);
        // 'free' makes any reader that bypasses the resolver fail closed.
        tier: 'free',
      }, tx);
      // The first month of the account's plan, from the partner's wallet, in this transaction: a wallet that cannot pay
      // refuses the open and nothing is made.
      await this.deps.accountPlans?.chargeOpening(tx, { partnerId: partnerOperatorId, accountId: row.id, ...(input.controls ? { controls: true } : {}) });
      return {
        account_id: row.id,
        external_ref: input.external_ref,
        billing: TENANT_BILLING,
        status: row.status,
        created: true,
        created_at: row.created_at.toISOString(),
        api_key: apiKeyPlain,
      };
    });
  }

  /**
   * A new API key for an account, returned once. The key it replaces stops working at once. A partner that lost the
   * key of an account it opened (the key is shown only by the call that opened it) asks for another here.
   */
  async rotateKey(
    accountId: string,
    partnerOperatorId: string,
  ): Promise<{ account_id: string; api_key: string }> {
    await this.assertPartner(partnerOperatorId);
    const apiKeyPlain = generateId('sk_live', 32);
    return this.deps.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, accountId);
      const row = await this.deps.operatorRepo.findChildScoped(accountId, partnerOperatorId, tx);
      if (!row) throw new NotFoundError('account', accountId);
      if (row.status !== 'active') {
        throw new ForbiddenError(`account ${accountId} is not active (status=${row.status})`);
      }
      await this.deps.operatorRepo.replaceChildApiKey(accountId, partnerOperatorId, hashApiKey(apiKeyPlain), tx);
      return { account_id: accountId, api_key: apiKeyPlain };
    });
  }

  /**
   * List the partner's accounts, or the one under a reference. Returns metadata and each account's
   * month-to-date share of the pool only: audit content, intent bodies and security_event content are
   * NEVER exposed via this method.
   */
  async listTenants(partnerOperatorId: string, filter: { externalRef?: string } = {}): Promise<TenantView[]> {
    await this.assertPartner(partnerOperatorId);
    const [all, usage] = await Promise.all([
      this.deps.operatorRepo.listChildren(partnerOperatorId),
      this.monthToDate(partnerOperatorId),
    ]);
    const rows = filter.externalRef === undefined
      ? all
      : all.filter((row) => row.external_customer_id === filter.externalRef);
    const [invites, plans] = await Promise.all([
      this.inviteStatuses(rows.map((row) => row.id)),
      this.planViews(partnerOperatorId, rows.map((row) => row.id)),
    ]);
    return rows.map((r) => this.toView(r, usage, invites.get(r.id) ?? 'none', plans.get(r.id)));
  }

  async getTenant(accountId: string, partnerOperatorId: string): Promise<TenantView> {
    await this.assertPartner(partnerOperatorId);
    const [row, usage] = await Promise.all([
      this.deps.operatorRepo.findChildScoped(accountId, partnerOperatorId),
      this.monthToDate(partnerOperatorId),
    ]);
    if (!row) throw new NotFoundError('account', accountId);
    const [invites, plans] = await Promise.all([this.inviteStatuses([row.id]), this.planViews(partnerOperatorId, [row.id])]);
    return this.toView(row, usage, invites.get(row.id) ?? 'none', plans.get(row.id));
  }

  private async planViews(partnerOperatorId: string, accountIds: string[]): Promise<Map<string, TenantPlanView>> {
    if (!this.deps.accountPlans || accountIds.length === 0) return new Map();
    return this.deps.accountPlans.views(partnerOperatorId, accountIds);
  }

  private async inviteStatuses(operatorIds: string[]): Promise<Map<string, 'invited' | 'active'>> {
    if (!this.deps.members || operatorIds.length === 0) return new Map();
    return this.deps.members.inviteStatuses(operatorIds);
  }

  /** The partner's and its accounts' metered actions this UTC month, split per operator. */
  private async monthToDate(
    partnerOperatorId: string,
  ): Promise<{ period: string; byOperator: Record<string, number> } | null> {
    if (!this.deps.poolUsage) return null;
    const now = new Date();
    const since = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    const pool = await this.deps.poolUsage.getPoolMeteredTotals(partnerOperatorId, since, now);
    const period = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
    return { period, byOperator: pool.byOperator };
  }

  /**
   * Soft-revoke a child operator. Sets status='deleted' on the
   * operator row; existing audit chain entries remain visible to the
   * platform-staff audit verifier but the operator can no longer
   * authenticate. Webhook + passport cascade is handled by the route
   * layer (which calls into InboundWebhookService.revoke +
   * PassportService.revokeAll for the account).
   */
  async revokeTenant(accountId: string, partnerOperatorId: string): Promise<{ transitioned: boolean }> {
    await this.assertPartner(partnerOperatorId);
    return this.deps.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, accountId);

      const row = await this.deps.operatorRepo.findChildScoped(
        accountId,
        partnerOperatorId,
        tx,
      );
      if (!row) throw new NotFoundError('account', accountId);
      if (row.status !== 'active') return { transitioned: false };

      const transitioned = await this.deps.operatorRepo.revokeChild(
        accountId,
        partnerOperatorId,
        tx,
      );
      return { transitioned };
    });
  }

  /**
   * Verify ownership of an account. Returns the operator row when valid;
   * throws NotFoundError otherwise. Used by partner-scoped sub-routes
   * (webhooks, passports, invites, releases) to confirm the account belongs
   * to the caller before dispatching to downstream services.
   */
  async assertTenantOwnership(accountId: string, partnerOperatorId: string) {
    const row = await this.deps.operatorRepo.findChildScoped(accountId, partnerOperatorId);
    if (!row) throw new NotFoundError('account', accountId);
    if (row.status !== 'active') {
      throw new ForbiddenError(`account ${accountId} is not active (status=${row.status})`);
    }
    return row;
  }

  private async assertPartner(partnerOperatorId: string): Promise<void> {
    const partner = await this.deps.operatorRepo.findById(partnerOperatorId);
    if (!partner) throw new NotFoundError('operator', partnerOperatorId);
    if (!partner.is_partner) {
      throw new ForbiddenError('operator is not a partner');
    }
  }

  private toView(
    row: {
      id: string;
      parent_operator_id: string | null;
      external_customer_id: string | null;
      status: string;
      created_at: Date;
      deleted_at: Date | null;
    },
    usage: { period: string; byOperator: Record<string, number> } | null = null,
    invite: InviteStatus = 'none',
    plan?: TenantPlanView,
  ): TenantView {
    return {
      account_id: row.id,
      external_ref: row.external_customer_id,
      billing: TENANT_BILLING,
      status: row.status,
      created_at: row.created_at.toISOString(),
      deleted_at: row.deleted_at?.toISOString() ?? null,
      invite: { status: invite },
      ...(usage ? { usage: { period: usage.period, actions: usage.byOperator[row.id] ?? 0 } } : {}),
      ...(plan ? { plan } : {}),
    };
  }
}
