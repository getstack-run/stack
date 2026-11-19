// Operator-scoped proxy operation reads: by operation key hash, by id, the passport check that
// gates replay, and the human-visible lookup that applies the member's connection ceiling.

import { and, eq, gt, inArray, isNull } from 'drizzle-orm';
import {
  agents,
  type Database,
  passports,
  proxyOperations,
  serviceConnections,
} from '@stack/shared';
import { type ProxyOperationTransaction, type ProxyOperationRow } from './types.js';

export async function findByOperationKey(
  db: Database,
  operatorId: string,
  operationKeyHash: string,
  transaction?: ProxyOperationTransaction,
): Promise<ProxyOperationRow | null> {
  return (await (transaction ?? db).query.proxyOperations.findFirst({
    where: and(
      eq(proxyOperations.operator_id, operatorId),
      eq(proxyOperations.operation_key_hash, operationKeyHash),
    ),
  })) ?? null;
}

export async function findById(
  db: Database,
  operatorId: string,
  operationId: string,
  transaction?: ProxyOperationTransaction,
): Promise<ProxyOperationRow | null> {
  return (await (transaction ?? db).query.proxyOperations.findFirst({
    where: and(eq(proxyOperations.id, operationId), eq(proxyOperations.operator_id, operatorId)),
  })) ?? null;
}

export async function originalPassportAllowsReplay(
  db: Database,
  operatorId: string,
  passportJti: string,
  agentId: string,
  now = new Date(),
): Promise<boolean> {
  const [row] = await db.select({ jti: passports.jti }).from(passports).where(and(
    eq(passports.jti, passportJti),
    eq(passports.operator_id, operatorId),
    eq(passports.agent_id, agentId),
    isNull(passports.revoked_at),
    gt(passports.expires_at, now),
  )).limit(1);
  return Boolean(row);
}

/** Current human visibility is an active originating agent plus the member's connection ceiling. */
export async function findVisibleByOperationKey(
  db: Database,
  operatorId: string,
  operationKeyHash: string,
  allowedConnections?: readonly string[],
  transaction?: ProxyOperationTransaction,
): Promise<ProxyOperationRow | null> {
  if (allowedConnections !== undefined && allowedConnections.length === 0) return null;
  const [row] = await (transaction ?? db).select({ operation: proxyOperations })
    .from(proxyOperations)
    .innerJoin(agents, and(
      eq(agents.id, proxyOperations.agent_id),
      eq(agents.operator_id, proxyOperations.operator_id),
      eq(agents.status, 'active'),
    ))
    .innerJoin(serviceConnections, and(
      eq(serviceConnections.id, proxyOperations.service_connection_id),
      eq(serviceConnections.operator_id, proxyOperations.operator_id),
    ))
    .where(and(
      eq(proxyOperations.operator_id, operatorId),
      eq(proxyOperations.operation_key_hash, operationKeyHash),
      allowedConnections === undefined
        ? undefined
        : inArray(proxyOperations.service_connection_id, [...allowedConnections]),
    ))
    .limit(1);
  return row?.operation ?? null;
}
