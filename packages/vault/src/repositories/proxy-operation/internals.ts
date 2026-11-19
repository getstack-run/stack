// Locking and fencing primitives shared by the proxy operation modules. Every write that changes
// an operation first takes the operator advisory lock, then a row lock, so concurrent dispatches
// for one operator serialize.

import { randomUUID } from 'node:crypto';
import { and, eq, inArray, sql } from 'drizzle-orm';
import { agents, proxyOperationAttempts, proxyOperations, serviceConnections } from '@stack/shared';
import { type ProxyOperationRow, type DbHandle, type FencedDispatch } from './types.js';

export function operationHasUnresolvedEffect(operation: ProxyOperationRow): boolean {
  const providerTerminal = operation.reconciliation_state === 'contradictory'
    || (operation.reconciliation_state === 'confirmed'
      && ['succeeded', 'failed', 'canceled'].includes(operation.reconciliation_provider_status ?? ''));
  if (providerTerminal) return false;
  if (operation.delivery_state === 'outcome_unknown') return true;
  return operation.adapter_kind === 'stripe'
    && operation.delivery_state === 'response_received'
    && ['pending', 'not_found', 'expired', 'confirmed'].includes(operation.reconciliation_state);
}

export function ownsDispatch(input: FencedDispatch, states: Array<ProxyOperationRow['delivery_state']>) {
  return and(eq(proxyOperations.id, input.operationId), eq(proxyOperations.operator_id, input.operatorId),
    eq(proxyOperations.dispatch_owner_hash, input.dispatchOwnerHash),
    eq(proxyOperations.dispatch_fence, input.dispatchFence), inArray(proxyOperations.delivery_state, states));
}

export async function lockOperator(db: DbHandle, operatorId: string): Promise<void> {
  await db.execute(sql`select pg_advisory_xact_lock(hashtextextended(${operatorId}, 73001))`);
}

export async function lockOperation(db: DbHandle, operatorId: string, operationId: string) {
  const [row] = await db.select().from(proxyOperations).where(and(
    eq(proxyOperations.id, operationId), eq(proxyOperations.operator_id, operatorId),
  )).for('update');
  return row;
}

export async function lockOperationByKey(
  db: DbHandle,
  operatorId: string,
  operationKeyHash: string,
) {
  const [row] = await db.select().from(proxyOperations).where(and(
    eq(proxyOperations.operator_id, operatorId),
    eq(proxyOperations.operation_key_hash, operationKeyHash),
  )).for('update');
  return row;
}

export async function governanceOperationIsCurrent(
  db: DbHandle,
  operation: ProxyOperationRow,
): Promise<boolean> {
  const [current] = await db.select({
    agentStatus: agents.status,
    connectionStatus: serviceConnections.status,
    credentialVersion: serviceConnections.credential_version,
  }).from(agents).innerJoin(serviceConnections, and(
    eq(serviceConnections.id, operation.service_connection_id),
    eq(serviceConnections.operator_id, operation.operator_id),
  )).where(and(
    eq(agents.id, operation.agent_id),
    eq(agents.operator_id, operation.operator_id),
  )).limit(1);
  return current?.agentStatus === 'active'
    && current.connectionStatus === 'active'
    && current.credentialVersion === operation.credential_version;
}

export async function insertAttempt(
  db: DbHandle,
  operation: ProxyOperationRow,
  ownerHash: string,
  leaseExpiresAt: Date,
  requestEvidenceHash: string,
): Promise<void> {
  await db.insert(proxyOperationAttempts).values({
    id: `poa_${randomUUID()}`,
    operator_id: operation.operator_id,
    operation_id: operation.id,
    attempt_number: operation.transport_attempts,
    dispatch_owner_hash: ownerHash,
    dispatch_fence: operation.dispatch_fence,
    lease_expires_at: leaseExpiresAt,
    request_evidence_hash: requestEvidenceHash,
  });
}
