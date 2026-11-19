import { ForbiddenError, NotFoundError } from '@stack/shared';
import { assertConnectionAccess, type ServiceConnectionContext } from './context.js';
import { getConnectionScoped } from './queries.js';

export async function checkProxyEnabled(
  ctx: ServiceConnectionContext,
  operatorId: string,
  provider: string,
): Promise<boolean | null> {
  const conn = await ctx.serviceRepo.findActiveConnectionByOperatorAndProvider(operatorId, provider);
  if (!conn) return null;
  return (conn as Record<string, unknown>).proxy_enabled !== false;
}

/** Whether this change turns proxy enforcement off, which needs human approval. */
export async function proxyChangeWeakens(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  enabled: boolean,
  allowedConnections?: string[],
): Promise<boolean> {
  const conn = await getConnectionScoped(ctx, connectionId, operatorId, allowedConnections);
  if (!conn) throw new NotFoundError('ServiceConnection', connectionId);
  return enabled === false;
}

export async function setProxyEnabled(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  enabled: boolean,
  allowedConnections?: string[],
  weakeningApproved = false,
) {
  assertConnectionAccess(allowedConnections, connectionId);
  return ctx.serviceRepo.withOperatorGrantLock(operatorId, async (tx) => {
    const conn = await ctx.serviceRepo.findConnectionById(connectionId, tx);
    if (!conn || conn.operator_id !== operatorId)
      throw new NotFoundError('ServiceConnection', connectionId);
    if (enabled === false && !weakeningApproved) {
      throw new ForbiddenError('Disabling proxy enforcement requires human approval');
    }
    return ctx.serviceRepo.updateConnection(connectionId, { proxy_enabled: enabled }, tx);
  });
}
