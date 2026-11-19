// Retention and erasure: scrub payload ciphertext once the replay window ends or an operator
// erases its data. The tombstone and hashes remain.

import { and, eq, lte, ne, or, sql } from 'drizzle-orm';
import { type Database, proxyOperations } from '@stack/shared';

export async function expireReplay(db: Database, now = new Date()): Promise<number> {
  const nowIso = now.toISOString();
  const rows = await db.update(proxyOperations).set({
    replay_state: 'expired', prepared_request_encrypted: null, prepared_request_key_ref: null,
    scope_descriptor_encrypted: null, scope_descriptor_key_ref: null,
    response_encrypted: null, response_key_ref: null, response_ciphertext_bytes: null,
    post_response_work_state: sql`case when ${proxyOperations.post_response_work_state} = 'completed'
      then 'completed' else 'expired' end`,
    post_response_context_encrypted: null, post_response_context_key_ref: null,
    post_response_owner_hash: null, post_response_lease_expires_at: null,
    post_response_next_attempt_at: null,
    capacity_used_bytes: 0, capacity_released_at: now,
    accounting_state: sql`case when ${proxyOperations.delivery_state} = 'admitted'
      and ${proxyOperations.accounting_state} = 'reserved' then 'released'
      else ${proxyOperations.accounting_state} end`,
    accounting_released_at: sql`case when ${proxyOperations.delivery_state} = 'admitted'
      and ${proxyOperations.accounting_state} = 'reserved' then ${nowIso}::timestamptz
      else ${proxyOperations.accounting_released_at} end`,
    updated_at: now,
  }).where(and(
    ne(proxyOperations.replay_state, 'erased'),
    or(
      and(
        eq(proxyOperations.replay_state, 'available'),
        lte(proxyOperations.response_readable_until, now),
      ),
      and(
        ne(proxyOperations.replay_state, 'available'),
        lte(proxyOperations.prepared_request_readable_until, now),
      ),
    ),
  ))
    .returning({ id: proxyOperations.id });
  return rows.length;
}

export async function erasePayloads(db: Database, operatorId: string, operationId?: string): Promise<number> {
  const now = new Date();
  const nowIso = now.toISOString();
  const rows = await db.update(proxyOperations).set({
    replay_state: 'erased', prepared_request_encrypted: null, prepared_request_key_ref: null,
    scope_descriptor_encrypted: null, scope_descriptor_key_ref: null,
    response_encrypted: null, response_key_ref: null, response_ciphertext_bytes: null,
    post_response_work_state: sql`case when ${proxyOperations.post_response_work_state} = 'completed'
      then 'completed' else 'expired' end`,
    post_response_context_encrypted: null, post_response_context_key_ref: null,
    post_response_owner_hash: null, post_response_lease_expires_at: null,
    post_response_next_attempt_at: null,
    capacity_used_bytes: 0, capacity_released_at: now, erased_at: now, updated_at: now,
    accounting_state: sql`case when ${proxyOperations.delivery_state} = 'admitted'
      and ${proxyOperations.accounting_state} = 'reserved' then 'released'
      else ${proxyOperations.accounting_state} end`,
    accounting_released_at: sql`case when ${proxyOperations.delivery_state} = 'admitted'
      and ${proxyOperations.accounting_state} = 'reserved' then ${nowIso}::timestamptz
      else ${proxyOperations.accounting_released_at} end`,
  }).where(and(eq(proxyOperations.operator_id, operatorId),
    operationId ? eq(proxyOperations.id, operationId) : undefined,
    ne(proxyOperations.replay_state, 'erased'))).returning({ id: proxyOperations.id });
  return rows.length;
}
