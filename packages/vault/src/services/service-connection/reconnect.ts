import type { ServiceRepository } from '../../repositories/service-repo.js';
import type { ReconnectReason } from '../oauth-token-lifecycle.js';
import type { ServiceConnectionContext } from './context.js';

type LockTransaction = Parameters<ServiceRepository['recordReconnectRequired']>[1];
type LockedConnection = Parameters<ServiceRepository['recordReconnectRequired']>[0];

/**
 * Record, inside the credential lock, that a connection can no longer renew.
 * The connection is marked expired and unhealthy and a reconnect event is
 * written, so the operator is told once and every later call is refused
 * without trying the provider again. The caller returns the error instead of
 * throwing it so the transaction COMMITS this terminal state; throwing inside
 * the lock would roll it back and prompt on every call.
 */
export async function markReconnectRequired(
  ctx: ServiceConnectionContext,
  current: LockedConnection & { id: string },
  tx: LockTransaction,
  reason?: ReconnectReason,
): Promise<string> {
  await ctx.serviceRepo.updateConnection(
    current.id,
    {
      status: 'expired',
      verification_status: 'unhealthy',
    },
    tx,
  );
  return ctx.serviceRepo.recordReconnectRequired(current, tx, reason);
}

/**
 * Mark an active connection reconnect-required now, rather than on its next
 * use: the same terminal state in the same lock, and the same notice once it
 * has committed. False when the connection is not active (nothing to mark).
 */
export async function flagReconnectRequired(
  ctx: ServiceConnectionContext,
  operatorId: string,
  connectionId: string,
  reason: ReconnectReason,
): Promise<boolean> {
  const outcome = await ctx.serviceRepo.withCredentialLock(connectionId, operatorId, async (current, tx) => {
    if (!current || current.status !== 'active') return null;
    const eventId = await markReconnectRequired(ctx, current, tx, reason);
    return { connection: current, eventId };
  });
  if (!outcome) return false;
  await notifyReconnectRequired(ctx, outcome.connection, outcome, reason);
  return true;
}

/** Tell the operator after the terminal state has committed. */
export async function notifyReconnectRequired(
  ctx: ServiceConnectionContext,
  conn: { id: string; operator_id: string; provider: string },
  committed: { connection: { credential_version: number }; eventId: string },
  reason?: ReconnectReason,
): Promise<void> {
  await ctx.hooks.reconnectRequired({
    operatorId: conn.operator_id,
    connectionId: conn.id,
    provider: conn.provider,
    credentialVersion: committed.connection.credential_version,
    eventId: committed.eventId,
    ...(reason ? { reason } : {}),
  });
}
