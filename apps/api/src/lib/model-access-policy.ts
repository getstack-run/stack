import { ServiceUnavailableError } from '@stack/shared';
import type { WorstCaseListings } from '@stack/shared';
import type { GatewayAuthorization, LlmProvider } from '@stack/vault';

/**
 * Whose key a model gateway call runs on. By default the customer's own: the
 * operator brings a connection and every call uses it. STACK's hosted product
 * adds one more payer, STACK's own key for an agent account whose models piece
 * is ready, billed to the account at cost.
 */
export type ModelAccess =
  | { kind: 'customer' }
  | { kind: 'account'; accountId: string };

/**
 * What a call that runs on the deployment's own key is held to before it is sent: its worst case in cents, worked out from
 * the model's listed prices and the request (`openRouterWorstCase`), or the cap the caller named when that cannot be worked
 * out. The call is then charged what the provider reports it cost.
 */
export interface ModelCallHoldInput {
  operatorId: string;
  accountId: string;
  missionId: string | null;
  provider: LlmProvider;
  /** The model the call names, or an empty string when the endpoint takes none. */
  model: string;
  heldCents: number;
}

export interface ModelAccessPolicy {
  /** The payer of one call. Fails closed where the deployment says an agent may not run on any key. */
  resolve(operatorId: string, agentId: string, provider: LlmProvider): Promise<ModelAccess>;
  /** The key of a call that runs on the deployment's own account. Called only after every gate has passed. */
  stackKey(access: Extract<ModelAccess, { kind: 'account' }>): string;
  /**
   * Holds the worst case of a call that runs on the deployment's own key, before the key is read. An authorization that
   * is not `bounded` refuses the call.
   */
  hold(input: ModelCallHoldInput): Promise<GatewayAuthorization>;
  /**
   * The models the deployment lists with their prices, by id and whole, for the worst case of a call. Refused when the list
   * is not available: a call is never held at a price nobody read.
   */
  listings(): Promise<WorstCaseListings>;
  /** Gives back what `hold` took. Repeated releases are safe. */
  release(operatorId: string, authorization: GatewayAuthorization): Promise<void>;
  /**
   * Whether an account started a long-running job (a video) through the gateway. The deployment's key is one provider
   * account for every agent account, so a job is read only by the account that made it.
   */
  ownsJob(operatorId: string, accountId: string, jobId: string): Promise<boolean>;
}

/** Every call runs on the customer's own connection; there is no key of the deployment's to lend. */
export const CUSTOMER_KEY_ONLY: ModelAccessPolicy = {
  async resolve() {
    return { kind: 'customer' };
  },
  stackKey(access) {
    throw new ServiceUnavailableError(`Models for agent account ${access.accountId} are unavailable on this install.`);
  },
  async hold(input) {
    throw new ServiceUnavailableError(`Models for agent account ${input.accountId} are unavailable on this install.`);
  },
  async listings() {
    throw new ServiceUnavailableError('Models on the deployment\'s own key are unavailable on this install.');
  },
  async release() {},
  async ownsJob() {
    return false;
  },
};
