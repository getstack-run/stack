import type { Services } from '../../config/services.js';
import { meterAction } from '../../middleware/meter.js';
import type { ProxyAccounting, ProxyHttpRequest, VerifiedProxyPassport } from './types.js';

/**
 * 3. Every proxy call is one recorded action on the account action meter, for
 * every operator: the first actions of the month are included with the
 * platform subscription, then each is priced by band from credit. An operator
 * with no platform subscription (and no contract plan) is refused with
 * PLATFORM_SUBSCRIPTION_REQUIRED here, before the call is made.
 *
 * A mutation's evaluation receipt (allowance-accounting.ts) fences the
 * operation but charges nothing, and the mutation is counted once on the
 * account action meter under the operation's own key, so a retried operation
 * is never counted twice. The route commits that count right before dispatch.
 * Only a partner on a negotiated hard cap keeps the tier counter and counts a
 * mutation through its receipt.
 */
export async function meterProxyAction(
  services: Services,
  request: ProxyHttpRequest,
  isMutation: boolean,
  verified: Pick<VerifiedProxyPassport, 'agentId'>,
  accounting: Pick<ProxyAccounting, 'accountPriced' | 'accountingOperatorId' | 'accountingKey'>,
): Promise<void> {
  if (!isMutation) {
    await meterAction(services, request, undefined, undefined, verified.agentId);
    return;
  }
  if (accounting.accountPriced && accounting.accountingKey) {
    await meterAction(
      services,
      request,
      undefined,
      `proxy-mutation:${accounting.accountingOperatorId}:${accounting.accountingKey}`,
      verified.agentId,
    );
  }
}
