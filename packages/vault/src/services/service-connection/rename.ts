import { ConnectionName, InvalidRequestError, NotFoundError } from '@stack/shared';
import { ConnectionPrincipalConflictError } from './connect.js';
import type { ServiceConnectionContext } from './context.js';

/**
 * Gives an active connection of the operator a new name. The name is checked against the principal's other active
 * connections of the provider (any case), so the refusal names the cause; the unique index still decides a race.
 */
export async function renameConnection(
  ctx: ServiceConnectionContext,
  operatorId: string,
  connectionId: string,
  name: string,
) {
  const parsed = ConnectionName.safeParse(name);
  if (!parsed.success) {
    throw new InvalidRequestError('connection_name must be 1 to 40 characters: letters, digits, spaces and hyphens, on one line');
  }
  const conn = await ctx.serviceRepo.findConnectionById(connectionId);
  if (!conn || conn.operator_id !== operatorId || conn.status !== 'active') {
    throw new NotFoundError('ServiceConnection', connectionId);
  }
  const wanted = parsed.data.toLowerCase();
  const siblings = await ctx.serviceRepo.findActiveConnectionsForPrincipal(operatorId, conn.provider, conn.member_id);
  if (siblings.some((other) => other.id !== conn.id && other.name.toLowerCase() === wanted)) {
    throw new ConnectionPrincipalConflictError(
      'connection_name_taken',
      `A connection of this service is already named "${parsed.data}": pass a different connection_name.`,
    );
  }
  const renamed = await ctx.serviceRepo.renameConnection(conn.id, operatorId, parsed.data);
  if (!renamed) throw new NotFoundError('ServiceConnection', connectionId);
  return renamed;
}
