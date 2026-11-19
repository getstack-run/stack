import { ids } from '@stack/shared';
import type { WorkerRuntime } from '../runtime.js';

/** Expire overdue drop-offs and write one audit row per expiry in the same transaction. */
export async function expireDropoffs(
  deps: Pick<WorkerRuntime, 'db' | 'dropoffService' | 'audit'>,
): Promise<void> {
  const { db, dropoffService, audit } = deps;
  const expiredDropoffs = await db.transaction(async (tx) => {
    const rows = await dropoffService.expireOverdue(tx);
    for (const row of rows) {
      await audit.write(
        {
          ctx: {
            trace_id: ids.session(),
            span_id: ids.session(),
            operator_id: row.operator_id,
            agent_id: 'system',
            passport_jti: 'none',
          },
          layer: 'dropoff',
          action: 'dropoff.expire',
          outcome: 'success',
          payload_hash: row.id,
        },
        tx,
      );
    }
    return rows;
  });
  const dropoffCount = expiredDropoffs.length;
  if (dropoffCount > 0) {
    console.log(`Expired ${dropoffCount} overdue drop-offs`);
  }
}
