// What a spend is checked against, resolved before the spend reserves.
//
// The budget ledger holds the account's money. It does not know about
// controls, kinds of action or policies; it is handed, per reservation, what to
// check (see ResolvedBudgetLimits). This is where that comes from, through the
// same reading every other hosted check uses (ControlPosture):
//
//   - a kind that is not checked is not limited: no policy limit applies and,
//     with controls on, the account's monthly budget does not refuse it;
//   - a kind that is checked is limited by the agent's policy: the most one
//     action may cost, and the day, month and Mission windows of cents;
//   - with controls off altogether nothing of a policy applies, and a budget
//     set before a downgrade keeps enforcing (the documented rule).
//
// A failure to read the controls or the policy fails the reservation: a spend
// is never held without the limits it is checked against.

import { MISSION_SPEND_SCOPE, limitsOf, localDateIn, missionDaySpendScope, spendPlanFor, type ControlActionType, type PaymentFacts } from '@stack/shared';
import type { BudgetLimitResolver, ResolvedBudgetLimits } from './account-ports.js';
import type { ControlPolicyRepository } from '../../repositories/control-policy-repo.js';
import type { ControlPosture } from '../control-socket/posture.js';
import type { ControlPolicyService } from './control-policy-service.js';

export interface ControlLimitResolverDeps {
  posture: Pick<ControlPosture, 'hostedApplies' | 'budgetEnforced'>;
  policies: Pick<ControlPolicyService, 'effective'>;
  accounts: Pick<ControlPolicyRepository, 'agentOfAccount'>;
  /** The Missions' own limits: a spend is also held to the one of the Mission it runs under. */
  missions?: {
    findById(missionId: string): Promise<{
      coverage_cap_cents: number | null;
      coverage_cap_period?: string | null;
      cap_time_zone?: string | null;
    } | null | undefined>;
  };
  now?: () => Date;
}

export class ControlLimitResolver implements BudgetLimitResolver {
  /** An account's agent is fixed for the life of the account. */
  private readonly agents = new Map<string, string>();

  constructor(private readonly deps: ControlLimitResolverDeps) {}

  async resolve(input: {
    operatorId: string;
    accountId: string;
    action: ControlActionType | null;
    missionId: string | null;
    payment?: PaymentFacts | undefined;
  }): Promise<ResolvedBudgetLimits> {
    const enforceAccountBudget = await this.deps.posture.budgetEnforced(input.operatorId, input.action);
    const missionSpend = await this.missionSpendCap(input.missionId);
    const base: ResolvedBudgetLimits = {
      enforceAccountBudget,
      rules: [],
      missionId: input.missionId,
      // Whatever the account's controls say, the Mission's own spend limit holds: it is the one its owner or agent set.
      ...(missionSpend ? { missionSpendCapCents: missionSpend.cap, missionSpendScope: missionSpend.scope } : {}),
    };
    if (!(await this.deps.posture.hostedApplies(input.operatorId, input.action))) return base;

    const agentId = await this.agentOf(input.accountId);
    const effective = await this.deps.policies.effective(input.operatorId, agentId);
    if (!effective) return base;

    const { spend, surfaces } = effective.definition;
    // A payment is also held to the rules of the merchant, payee and category it may fall under: the tightest
    // per-payment ceiling, and a counter of its own for each day and month limit of each rule.
    const plan = input.payment ? spendPlanFor(effective.definition, input.payment) : null;
    const ceilings = [
      spend.max_per_action_cents,
      input.action === 'model.call' ? surfaces.models.max_cost_per_call_cents : undefined,
      plan?.perPayment?.limit,
    ].filter((value): value is number => value !== undefined);
    return {
      ...base,
      ...(ceilings.length > 0 ? { maxEntryCents: Math.min(...ceilings) } : {}),
      rules: [
        ...limitsOf(effective.definition, 'cents').map(({ kind, limit }) => ({ kind, limit })),
        ...(plan?.counters ?? []).map(({ kind, limit, scope }) => ({ kind, limit, scope })),
      ],
    };
  }

  /**
   * The Mission's money cap and the counter it is held in. Read for every spend, never kept: the owner can raise the
   * cap of a paused Mission, and a cap of one day counts in today's counter of the Mission's time zone.
   */
  private async missionSpendCap(missionId: string | null): Promise<{ cap: number; scope: string } | null> {
    if (!missionId || !this.deps.missions) return null;
    const mission = await this.deps.missions.findById(missionId);
    const cap = mission?.coverage_cap_cents ?? null;
    if (cap === null || !mission) return null;
    if (mission.coverage_cap_period !== 'day') return { cap, scope: MISSION_SPEND_SCOPE };
    const day = localDateIn(this.deps.now?.() ?? new Date(), mission.cap_time_zone ?? 'UTC');
    return { cap, scope: missionDaySpendScope(day) };
  }

  private async agentOf(accountId: string): Promise<string | null> {
    const known = this.agents.get(accountId);
    if (known) return known;
    const found = await this.deps.accounts.agentOfAccount(accountId);
    if (!found) return null;
    if (this.agents.size >= 50_000) this.agents.clear();
    this.agents.set(accountId, found.agentId);
    return found.agentId;
  }
}
