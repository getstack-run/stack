import { ids, ConflictError, NotFoundError } from '@stack/shared';
import type { ServiceConnectionContext } from './context.js';
import { listConnectedServices } from './queries.js';

export async function configureService(
  ctx: ServiceConnectionContext,
  operatorId: string,
  serviceId: string,
  provider: string,
  mode: 'shared' | 'per_member',
) {
  const service = await ctx.serviceRepo.findAccessibleServiceById(serviceId, operatorId);
  if (!service) throw new NotFoundError('Service', serviceId);
  if (service.provider !== provider) {
    throw new ConflictError(`Service "${serviceId}" does not use provider "${provider}"`);
  }

  const activeConnections = await ctx.serviceRepo.findActiveConnectionsByOperatorAndProvider(
    operatorId,
    provider,
  );
  const conflicts =
    mode === 'shared'
      ? activeConnections.some((connection) => connection.member_id !== null)
      : activeConnections.some((connection) => connection.member_id === null);
  if (conflicts) {
    throw new ConflictError(
      `Mode "${mode}" conflicts with an active ${mode === 'shared' ? 'member' : 'shared'} connection. Disconnect it first.`,
    );
  }

  return ctx.serviceRepo.upsertConfiguration({
    id: ids.serviceConfiguration(),
    operator_id: operatorId,
    service_id: serviceId,
    provider,
    mode,
  });
}

export async function getServiceConfigurations(
  ctx: ServiceConnectionContext,
  operatorId: string,
  allowedConnections?: string[],
) {
  const configurations = await ctx.serviceRepo.findConfigurationsByOperator(operatorId);
  if (allowedConnections === undefined) return configurations;
  // A member limited to named connections never sees the account-wide list:
  // only the configurations of providers it holds an allowed connection
  // for, and none when the list is empty. Refusing outright (a2fbb3b1)
  // kept the boundary but broke every read that loads services.
  const providers = new Set(
    (await listConnectedServices(ctx, operatorId, allowedConnections)).map((row) => row.provider),
  );
  return configurations.filter((row) => providers.has(row.provider));
}

export async function disableService(
  ctx: ServiceConnectionContext,
  operatorId: string,
  provider: string,
) {
  const deleted = await ctx.serviceRepo.deleteConfiguration(operatorId, provider);
  if (!deleted) throw new NotFoundError('ServiceConfiguration', provider);
  return { disabled: true, provider };
}
