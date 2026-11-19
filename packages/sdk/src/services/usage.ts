import type { HttpClient } from '../client.js';
import type { UsageResponse } from '../types.js';

/**
 * Usage service for the one-call rollup of total activity, metered actions,
 * money paid through STACK, and earnings (GET /v1/usage).
 *
 * Superset of the per-domain meters (`stack.scan.usage()`,
 * `stack.llm.usage.*`, `stack.proxy` counts): one authoritative shape the CLI
 * and dashboard read too. Money fields are in cents.
 *
 * `consumption.activity` is every audit event. `consumption.actions` is only
 * the published allowance meter. Its `allowance_coverage` states whether the
 * limit belongs to that exact UTC month. An old unknown month never borrows
 * the current plan. Pass `since` / `until` (ISO-8601 or unix-ms) to scope the
 * flow metrics to a window. Inventory metrics always report the current count,
 * plus `created_in_window` when a window is set.
 *
 * @example
 * ```ts
 * const u = await stack.usage.get();
 * console.log(`Spent this period: $${(u.spend_cents.total / 100).toFixed(2)}`);
 *
 * const week = await stack.usage.get({ since: '2026-07-07T00:00:00Z' });
 * ```
 */
export class UsageService {
  constructor(private client: HttpClient) {}

  /**
   * Usage, spend, and earnings. Defaults to the current billing period; pass
   * `since` (and optionally `until`) — ISO-8601 or unix-ms — for a window.
   */
  async get(opts?: { since?: string; until?: string }): Promise<UsageResponse> {
    return this.client.get<UsageResponse>('/v1/usage', {
      since: opts?.since,
      until: opts?.until,
    });
  }
}
