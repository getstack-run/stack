import { SpendRefusedError, type ControlActionType } from '@stack/shared';
import type { PreparedLlmWalletSettlement } from '../../repositories/llm-usage/types.js';
import type { ProxyAccountingReceipt } from '../../repositories/proxy-operation/types.js';
import type { DbTransaction } from '../../repositories/operator-repo.js';

/**
 * What engine services ask of a wallet: hold the worst case before a spend,
 * capture what was spent, release what was not. A deployment with prepaid
 * credit (STACK's hosted product) supplies its wallet; an install on the
 * contract plan has none, and the engine never reaches a hold there because a
 * call made on the customer's own key is never held (it is fee free).
 *
 * Written out method by method, not as a `Pick` of the wallet class, so the
 * engine does not import the wallet to name what it needs of it; the wallet
 * satisfies it structurally.
 */
export interface SpendLedger {
  /** Reserve funds for a spend; `agentBudget` also reserves the agent account's budget entry. */
  createHold(params: {
    id?: string;
    operatorId: string;
    amountCents: number;
    purpose: string;
    ttlSeconds?: number;
    agentBudget?: { accountId: string; action?: ControlActionType; missionId?: string | null };
    billTenantToPartner?: boolean;
  }): Promise<{ id: string }>;
  releaseHold(holdId: string, operatorId: string): Promise<string>;
  /** Charge a hold at an amount the caller fixed, with no usage row: a call that ran whose usage could not be recorded. */
  captureHold(params: {
    holdId: string;
    operatorId: string;
    amountCents: number;
    type: 'compute';
    meter?: string | null;
    description?: string;
  }): Promise<number>;
  /** Freeze what an LLM call cost and settle its whole-cent debit against the hold. */
  captureLlmFees(params: {
    holdId: string;
    operatorId: string;
    feeKind: string;
    meter: string;
    missionId?: string | null;
    skillId?: string | null;
    invocationId?: string | null;
    description?: string;
  }): Promise<PreparedLlmWalletSettlement>;
  markReconciliationWorkState(
    holdId: string,
    operatorId: string,
    invocationId: string,
    workState: 'none' | 'durable' | 'persistence_uncertain',
  ): Promise<string>;
  hasPaidSkillInvocationHold(invocationId: string, operatorId: string): Promise<boolean>;
}

const noWallet = (): Promise<never> =>
  Promise.reject(
    new SpendRefusedError(
      'This install has no wallet: nothing can be held or charged.',
      'NO_WALLET_ON_INSTALL',
    ),
  );

/** A deployment with no wallet. Every method refuses, so a path that should never spend proves it by failing closed. */
export const NO_SPEND_LEDGER: SpendLedger = {
  createHold: noWallet,
  releaseHold: noWallet,
  captureHold: noWallet,
  captureLlmFees: noWallet,
  markReconciliationWorkState: noWallet,
  hasPaidSkillInvocationHold: noWallet,
};

/**
 * The hold bookkeeping of a proxy operation that crossed into paid overage:
 * reserve inside the operation's own transaction and settle what was held.
 */
export interface ProxyHoldLedger {
  settlePendingHold(holdId: string, operatorId: string): Promise<unknown>;
  reserveInTransaction(
    input: { id: string; operator_id: string; amount_cents: number; purpose: string; expires_at: Date },
    transaction: DbTransaction,
  ): Promise<unknown>;
  prepareHoldSettlementInTransaction(
    input: {
      hold_id: string;
      operator_id: string;
      amount_cents: number;
      transaction: { id: string; type: 'overage'; meter?: string | null; description?: string | null };
    },
    transaction: DbTransaction,
  ): Promise<unknown>;
  /** The receipts whose whole-cent boundary has a durable hold (settlement pending or captured), oldest first. */
  listSettlementBoundaries(limit?: number): Promise<Array<{ receipt: ProxyAccountingReceipt; holdStatus: string }>>;
}

/**
 * No wallet: every method that would hold funds refuses, so a path that should never hold funds
 * fails closed. The listing is empty, not a refusal: the worker's reconciler asks it on every
 * tick, and an install has no wallet obligation to settle.
 */
export const NO_PROXY_HOLDS: ProxyHoldLedger = {
  settlePendingHold: noWallet,
  reserveInTransaction: noWallet,
  prepareHoldSettlementInTransaction: noWallet,
  async listSettlementBoundaries() {
    return [];
  },
};

/** What a Mission has spent on credit, so the Mission's cost cap counts it. */
export interface MissionSpendSource {
  /**
   * Credit spent under the Mission, in cents; with `before`, only what was recorded before that instant, and with
   * `since`, only what was recorded at or after it (a money cap of one day).
   */
  spentCents(operatorId: string, missionId: string, before?: Date, since?: Date): Promise<number>;
  /**
   * Whether the Mission is an agent account's standing Mission. The account's budget governs what
   * it spends, so the Mission's cost cap does not apply to it.
   */
  governedByAccountBudget(missionId: string): Promise<boolean>;
}

/** No wallet, no wallet spend, and no accounts: the engine adds the LLM usage it records itself, as it always did. */
export const NO_MISSION_SPEND: MissionSpendSource = {
  async spentCents() {
    return 0;
  },
  async governedByAccountBudget() {
    return false;
  },
};
