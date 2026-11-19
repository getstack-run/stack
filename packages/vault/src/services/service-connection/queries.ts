import { ForbiddenError, NotFoundError } from '@stack/shared';
import { assertConnectionAccess, type ServiceConnectionContext } from './context.js';
import { releaseGrant } from './grant-release.js';

export async function listConnectedServices(
  ctx: ServiceConnectionContext,
  operatorId: string,
  allowedConnections?: string[],
) {
  const rows = await ctx.serviceRepo.findConnectionsByOperator(operatorId);
  if (allowedConnections === undefined) return rows;
  const allowed = new Set(allowedConnections);
  return rows.filter((row) => allowed.has(row.id));
}

/**
 * Operator-scoped connection lookup for the route-layer provenance guards.
 * Returns undefined for foreign/missing ids so the caller can 404 without an
 * enumeration signal.
 */
export async function getConnectionScoped(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  allowedConnections?: string[],
) {
  assertConnectionAccess(allowedConnections, connectionId);
  const conn = await ctx.serviceRepo.findConnectionById(connectionId);
  if (!conn || conn.operator_id !== operatorId) return undefined;
  return conn;
}

export async function disconnectConnection(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  allowedConnections?: string[],
) {
  assertConnectionAccess(allowedConnections, connectionId);
  const conn = await ctx.serviceRepo.findConnectionById(connectionId);
  if (!conn) throw new NotFoundError('ServiceConnection', connectionId);
  if (conn.operator_id !== operatorId) throw new ForbiddenError();

  // What the deployment set up at the provider is ended first; if it cannot be, the connection stays.
  if (conn.status === 'active' && ctx.hooks.connectionClosing) {
    await ctx.hooks.connectionClosing({
      operatorId,
      connection: { id: conn.id, provider: conn.provider, service_id: conn.service_id },
      credential: () => ctx.decryptCredential(conn.operator_id, conn.id, conn.credential_encrypted, conn.provider),
    });
  }
  const revoked = await ctx.serviceRepo.revokeConnection(connectionId);
  // The credential row is kept, so a grant the deployment ends at the provider is read from it. Only a connection
  // made through an OAuth app has one, so any other disconnect never touches the KMS here.
  if (conn.oauth_managed) await releaseGrant(ctx, conn);
  return revoked;
}

/**
 * The connection's name as an approval shows it: the name its owner gave it, but only while the account holds
 * two or more active connections of that service. With one, the service alone says which connection is meant.
 */
export async function connectionNameWhenSeveral(
  ctx: ServiceConnectionContext,
  connection: { operator_id: string; provider: string; name: string },
): Promise<string | null> {
  const active = await ctx.serviceRepo.findActiveConnectionsByOperatorAndProvider(connection.operator_id, connection.provider);
  return active.length >= 2 ? connection.name : null;
}
