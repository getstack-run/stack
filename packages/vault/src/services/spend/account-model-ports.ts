import type { LlmCostBreakdown } from '@stack/shared';
import type { LlmUsage } from '../llm-gateway-service.js';
import type { GatewayAuthorization } from '../llm-usage-service.js';

/**
 * What the model gateway asks of a deployment that runs a model call on its own key
 * (an agent account's): how a finished call is charged. A call on the customer's own key
 * never reaches it, so an install gives the null below, which charges nothing.
 */

export interface AccountCallSettlementInput {
  operatorId: string;
  agentId: string;
  passportJti: string;
  missionId: string | null;
  model: string;
  status: number;
  usage: LlmUsage | null;
  generationId: string | null;
  /** A long-running job the call started (a video), whose cost is known only when it ends. */
  job?: { kind: 'video_job'; id: string } | null;
  streaming: boolean;
  /**
   * The caller hung up: if the call's cost never resolves, it is charged from the tokens its answer showed at the catalogue
   * price, and its hold is released only when no usage at all is known.
   */
  releaseIfUnresolved?: boolean;
  /** What the deployment's own hold returned for the call; the deployment's settlement reads its own fields of it. */
  authorization: GatewayAuthorization;
}

/** A call that ran whose own settlement failed, handed to the retry that reads its cost from the provider's record. */
export interface AccountCallRetryInput {
  operatorId: string;
  agentId: string;
  passportJti: string;
  missionId: string | null;
  model: string;
  /** What the deployment's own hold returned for the call. */
  hold: GatewayAuthorization;
  generationId: string | null;
  /** A long-running job the call started (a video), whose cost is known only when it ends. */
  job?: { kind: 'video_job'; id: string } | null;
  /** The call's own streaming flag, for the usage row written when it is priced. */
  streaming: boolean;
  /** What the call's answer said it used, charged at the catalogue price if its cost never resolves; null when it said nothing. */
  usage?: LlmUsage | null;
}

/** Settles one finished model call that was held against the deployment's own key. */
export interface AccountCallSettlement {
  settleCall(input: AccountCallSettlementInput): Promise<{ cost: LlmCostBreakdown | null }>;
  /**
   * Hands a call whose settlement failed to the retry that prices it later from the provider's record. A call with nothing to
   * look up is charged from the tokens its answer showed at the catalogue price, and has its hold given back only when no usage
   * at all is known. A cost that never resolves is charged the same way.
   */
  retrySettlement(input: AccountCallRetryInput): Promise<'retrying' | 'charged' | 'released'>;
}

/** A call is only held on the deployment's key when a deployment has one; an install is never asked. */
export const NO_ACCOUNT_CALL_SETTLEMENT: AccountCallSettlement = {
  async settleCall() {
    throw new Error('This install holds no model call on a key of its own, so there is nothing to settle.');
  },
  async retrySettlement() {
    throw new Error('This install holds no model call on a key of its own, so there is nothing to settle.');
  },
};
