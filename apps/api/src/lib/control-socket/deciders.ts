// Two of the three deciders. The third, a customer's own server, is
// ./remote-decider.ts.

import type { ControlActionType } from '@stack/shared';
import { runSettle } from './settle.js';
import type { Decider, DecisionContext, DecisionResult, SettleHook } from './types.js';

/** No controls: zero limits. Every action is allowed with no check. */
export class NoneDecider implements Decider {
  readonly kind = 'none' as const;

  async decide(): Promise<DecisionResult> {
    return { verdict: 'allow' };
  }
}

/** One check STACK runs for a customer who has hosted controls on. */
export interface HostedCheck {
  readonly name: string;
  appliesTo(action: ControlActionType | 'test'): boolean;
  evaluate(context: DecisionContext): Promise<DecisionResult>;
}

/**
 * STACK's hosted controls: the checks a customer's controls subscription
 * buys, run in process under the same deadline, with STACK-side failure codes.
 *
 * Today the hosted checks (the detector classifier on third-party content, the
 * data-flow rule, budgets on the spend ledger) run where their data is, at
 * their own call sites, and follow the entitlements' `controlsEnabled`;
 * this decider is what makes each checked action one billable check. Hosted
 * policies plug in here as `HostedCheck`s: the first denying check decides, and
 * a check that throws is a STACK-side failure (the action is refused, handed
 * back and not charged), never an allow. What an allowing check leaves open
 * (a counted action, a reserved approval, a lease) is collected and returned,
 * and handed back at once when a later check refuses or fails.
 */
export class HostedDecider implements Decider {
  readonly kind = 'hosted' as const;

  constructor(private readonly checks: readonly HostedCheck[] = []) {}

  async decide(context: DecisionContext): Promise<DecisionResult> {
    const settle: SettleHook[] = [];
    let policyRef: string | null | undefined;
    try {
      for (const check of this.checks) {
        if (!check.appliesTo(context.request.action.type)) continue;
        const result = await check.evaluate(context);
        if (result.verdict !== 'allow') {
          await runSettle(settle, { ok: false, handedBack: true });
          return result;
        }
        settle.push(...(result.settle ?? []));
        policyRef ??= result.policyRef;
      }
      return { verdict: 'allow', ...(policyRef ? { policyRef } : {}), ...(settle.length > 0 ? { settle } : {}) };
    } catch {
      await runSettle(settle, { ok: false, handedBack: true });
      return { verdict: 'unavailable', cause: 'hosted_failure' };
    }
  }
}
