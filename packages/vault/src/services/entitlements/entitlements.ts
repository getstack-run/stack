import {
  type AccountPlan,
  BillingAccountInactiveError,
  CONTRACT_PLAN_LIMITS,
  ControlsStatus,
  NotFoundError,
  ServiceUnavailableError,
  StackError,
  type OperatorTier,
  type OverageMode,
  type PlanLimits,
} from '@stack/shared';
import type { OperatorRepository } from '../../repositories/operator-repo.js';
import { assertOperatorActive } from '../operator-service.js';

/**
 * The plan an operator's calls are metered against, as engine code reads it.
 * For a normal operator the billing account is the operator itself; for a
 * white-label tenant it is its partner. Written out as an interface, not as the
 * hosted billing class, so the engine can read a plan without knowing who sells
 * it; STACK's hosted billing account satisfies it structurally.
 */
export interface EntitlementAccount {
  actingOperatorId: string;
  /** The operator whose wallet pays for the call: the operator itself, or a partner-managed account's partner. */
  billingOperatorId: string;
  /**
   * The operator whose plan, free amounts and meters the call counts against. The operator itself, except for an account
   * that draws on its partner's one allowance (every account of an engine install; a hosted partner on a negotiated hard
   * cap), where it is the partner.
   */
  planOperatorId: string;
  /** The call counts against its partner's allowance, shared with the partner's other accounts. */
  pooled: boolean;
  tier: OperatorTier;
  /** The plan the account is on, as customer readouts name it: never derived from `tier`, which is a legacy column. */
  plan: AccountPlan;
  limits: PlanLimits & { maxTenants: number; overage: OverageMode };
  isTenant: boolean;
  controlsStatus: ControlsStatus;
  platformStatus: string;
}

/**
 * The one reader of a plan. `controlsEnabled` is the one decision about whether
 * a customer has controls; nothing else reads the controls status.
 */
export interface EntitlementResolver {
  /** Resolve the billing account for an acting operator. Fails closed: an inactive operator or partner refuses. */
  resolve(actingOperatorId: string): Promise<EntitlementAccount>;
  /** Controls on for the account this operator bills to. Fails closed. */
  controlsEnabled(actingOperatorId: string): Promise<boolean>;
  /** Drop every cached entry billed to this account, on this process only. */
  evict(billingOperatorId: string): void;
  /** Evict locally and tell every other process. */
  invalidate(billingOperatorId: string): Promise<void>;
}

interface CacheEntry {
  account: EntitlementAccount;
  expiresAt: number;
}

const DEFAULT_TTL_MS = 30_000;
const MAX_ENTRIES = 10_000;

/**
 * The plan of an install that has no plans: every operator is on the contract
 * plan (enterprise), which is never refused for payment, never charged, has no
 * allowance and has every control. A tenant is resolved to its partner with one
 * cached query, exactly as the hosted resolver does, and an inactive operator or
 * partner refuses the same way; only the limits are fixed.
 */
export class ContractPlanEntitlements implements EntitlementResolver {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(
    private readonly operators: Pick<OperatorRepository, 'findById'>,
    options: { ttlMs?: number; now?: () => number } = {},
  ) {
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.now = options.now ?? Date.now;
  }

  async resolve(actingOperatorId: string): Promise<EntitlementAccount> {
    const hit = this.cache.get(actingOperatorId);
    if (hit && hit.expiresAt > this.now()) return hit.account;
    const account = await this.load(actingOperatorId);
    if (this.cache.size >= MAX_ENTRIES) this.cache.clear();
    this.cache.set(actingOperatorId, { account, expiresAt: this.now() + this.ttlMs });
    return account;
  }

  async controlsEnabled(actingOperatorId: string): Promise<boolean> {
    await this.resolve(actingOperatorId);
    return true;
  }

  evict(billingOperatorId: string): void {
    for (const [acting, entry] of this.cache) {
      if (entry.account.billingOperatorId === billingOperatorId || acting === billingOperatorId) {
        this.cache.delete(acting);
      }
    }
  }

  async invalidate(billingOperatorId: string): Promise<void> {
    this.evict(billingOperatorId);
  }

  private async load(actingOperatorId: string): Promise<EntitlementAccount> {
    const acting = await this.read(actingOperatorId);
    if (!acting) throw new NotFoundError('Operator', actingOperatorId);
    assertOperatorActive(acting);
    if (!acting.parent_operator_id) return this.account(acting, acting, false);
    const partner = await this.read(acting.parent_operator_id);
    if (!partner || partner.status !== 'active' || !partner.is_partner || partner.parent_operator_id !== null) {
      throw new BillingAccountInactiveError();
    }
    return this.account(acting, partner, true);
  }

  private async read(id: string) {
    try {
      return await this.operators.findById(id);
    } catch (err) {
      if (err instanceof NotFoundError) return undefined;
      if (err instanceof StackError) throw err;
      throw new ServiceUnavailableError('Billing account is temporarily unavailable, please retry');
    }
  }

  private account(
    acting: { id: string },
    billing: { id: string; controls_status?: string | null },
    isTenant: boolean,
  ): EntitlementAccount {
    const controls = ControlsStatus.safeParse(billing.controls_status);
    return {
      actingOperatorId: acting.id,
      billingOperatorId: billing.id,
      planOperatorId: billing.id,
      pooled: isTenant,
      tier: 'enterprise',
      plan: 'contract',
      limits: { ...CONTRACT_PLAN_LIMITS, maxTenants: Infinity, overage: 'wallet' },
      isTenant,
      controlsStatus: controls.success ? controls.data : 'off',
      platformStatus: 'none',
    };
  }
}
