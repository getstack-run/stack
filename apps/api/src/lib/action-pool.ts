import { type AccountPlan } from '@stack/shared';
import type { Services } from '../config/services.js';

/**
 * The live recorded-actions pool for an operator's billing account: the
 * operator itself, or a white-label tenant's partner. The plan comes from the
 * entitlements and the count from the meter that wrote it, so the writer and
 * the reader cannot drift. A deployment with no meter has nothing to count: the
 * pool reads zero used with no limit.
 *
 * Backs the per-domain `/v1/proxy/usage` and `/v1/scan/usage` readouts.
 */
export async function actionPoolSnapshot(
  services: Pick<Services, 'actionMeter' | 'entitlements'>,
  operatorId: string,
  now: Date = new Date(),
): Promise<{
  plan: AccountPlan;
  limit: number | null;
  used: number;
  remaining: number | null;
  period: string;
  pooled?: true;
}> {
  const account = await services.entitlements.resolve(operatorId);
  const { limit, used } = await services.actionMeter.pool(account, now);
  const period = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
  return {
    plan: account.plan,
    limit: limit === Infinity ? null : limit,
    used,
    remaining: limit === Infinity ? null : Math.max(0, limit - used),
    period,
    ...(account.pooled ? { pooled: true as const } : {}),
  };
}
