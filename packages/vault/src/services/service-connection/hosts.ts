import {
  ForbiddenError,
  InvalidServiceMcpUrlError,
  NotFoundError,
  checkServiceMcpUrl,
  normalizeAllowedHosts,
  deriveConnectionHosts,
  defaultHostsForProvider,
  isPerTenantHostProvider,
} from '@stack/shared';
import { assertConnectionAccess, type ServiceConnectionContext } from './context.js';
import { getConnectionScoped } from './queries.js';

function hostAuthorityCovers(existing: string, requested: string): boolean {
  if (existing === requested) return true;
  if (!existing.startsWith('.')) return false;
  const suffix = existing.slice(1);
  if (requested.startsWith('.')) {
    const requestedSuffix = requested.slice(1);
    return requestedSuffix === suffix || requestedSuffix.endsWith(`.${suffix}`);
  }
  return requested === suffix || requested.endsWith(`.${suffix}`);
}

/** Whether `requested` names a destination `existing` does not already cover. */
export function allowedHostsWiden(existing: string[], requested: string[]): boolean {
  return requested.some((host) => !existing.some((oldHost) => hostAuthorityCovers(oldHost, host)));
}

/**
 * Decide the hosts a new connection's credential may be sent to.
 *
 * One rule for every connect path, so none of them can create a connection
 * that cannot proxy and none can create one that is wide open.
 *
 *   1. What the operator declared, validated.
 *   2. What the credential itself carries: a per-tenant provider puts its
 *      host in `instance_url` / `url` / `host`, and the proxy already reads
 *      those same fields to build the outbound URL.
 *   3. The catalogue, for the 119 providers we ship a host for.
 *   4. Refuse, when the provider is per-tenant and none of the above
 *      answered. STACK genuinely cannot know your Okta org or your
 *      self-hosted Grafana, so the operator is asked at the connect dialog
 *      rather than discovering a denied call later.
 *
 * Returns null only for a provider that is neither catalogued nor
 * per-tenant. `createConnection` then falls back to the catalogue, and a
 * connection with nothing declared denies at the proxy. Fail closed.
 */
export function resolveConnectionHosts(
  provider: string,
  declared: string[] | undefined,
  credential: string | Record<string, string> | undefined,
  serviceName: string,
): string[] | null {
  if (declared && declared.length > 0) {
    try {
      const cleaned = normalizeAllowedHosts(declared);
      if (cleaned.length > 0) return cleaned;
    } catch (err) {
      throw new ForbiddenError(err instanceof Error ? err.message : 'Invalid allowed_hosts');
    }
  }

  const derived = deriveConnectionHosts(
    provider,
    typeof credential === 'string' ? undefined : credential,
  );
  if (derived && derived.length > 0) return derived;

  const catalogue = defaultHostsForProvider(provider);
  if (catalogue && catalogue.length > 0) return [...catalogue];

  if (isPerTenantHostProvider(provider)) {
    throw new ForbiddenError(
      `${serviceName} is hosted at an address only you know, so STACK cannot tell your ` +
        `instance from an attacker's. Give the API host this credential may be sent to ` +
        `(allowed_hosts), or include it in the credential as a url / host / instance_url field.`,
    );
  }

  return null;
}

/**
 * The `mcp_url` a new connection carries, or null when none was given. It must be https and on one of the hosts the
 * connection's credential may be sent to (`hosts`, or the catalogue's for a provider that has them), so the address cannot
 * send the key anywhere the customer did not allow; the proxy checks the same again on every call.
 */
export function resolveConnectionMcpUrl(
  declared: string | undefined,
  provider: string,
  hosts: readonly string[] | null,
): string | null {
  if (declared === undefined) return null;
  try {
    return checkServiceMcpUrl(declared, hosts ?? defaultHostsForProvider(provider) ?? []);
  } catch (err) {
    if (err instanceof InvalidServiceMcpUrlError) throw new ForbiddenError(err.message);
    throw err;
  }
}

/**
 * Whether declaring these hosts would widen where the connection's credential
 * may be sent. Entries are validated with the same rule as the declaration.
 */
export async function allowedHostsChangeWidens(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  hosts: string[],
  allowedConnections?: string[],
): Promise<boolean> {
  const conn = await getConnectionScoped(ctx, connectionId, operatorId, allowedConnections);
  if (!conn) throw new NotFoundError('ServiceConnection', connectionId);
  try {
    return allowedHostsWiden(conn.allowed_hosts ?? [], normalizeAllowedHosts(hosts));
  } catch (err) {
    throw new ForbiddenError(err instanceof Error ? err.message : 'Invalid allowed_hosts');
  }
}

/**
 * Declare the hosts this connection's credential may be sent to.
 *
 * Required for providers whose API host is per-tenant (a Shopify store, a
 * Zendesk subdomain, self-hosted Grafana) and for any provider the repo has
 * no grounded default for. Until it is set, the proxy refuses every
 * destination for that connection: deny by default, not fail open.
 *
 * Each entry is either an exact host (`api.stripe.com`) or a dot-led suffix
 * (`.amazonaws.com`) matching that domain and its subdomains. Entries are
 * validated here so a malformed or dangerously broad declaration is
 * rejected at the point of declaration rather than silently never matching,
 * or worse, matching far too much. Widening the set needs human approval.
 */
export async function setAllowedHosts(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  hosts: string[],
  allowedConnections?: string[],
  expansionApproved = false,
) {
  assertConnectionAccess(allowedConnections, connectionId);
  // Shared validator: the custom-connect path uses the same one, so a looser
  // rule here could never become the way around the tighter one.
  let cleaned: string[];
  try {
    cleaned = normalizeAllowedHosts(hosts);
  } catch (err) {
    throw new ForbiddenError(err instanceof Error ? err.message : 'Invalid allowed_hosts');
  }

  return ctx.serviceRepo.withOperatorGrantLock(operatorId, async (tx) => {
    const conn = await ctx.serviceRepo.findConnectionById(connectionId, tx);
    if (!conn || conn.operator_id !== operatorId)
      throw new NotFoundError('ServiceConnection', connectionId);
    if (allowedHostsWiden(conn.allowed_hosts ?? [], cleaned) && !expansionApproved) {
      throw new ForbiddenError('Expanding credential destinations requires human approval');
    }
    return ctx.serviceRepo.updateConnection(
      connectionId,
      {
        allowed_hosts: cleaned.length > 0 ? cleaned : null,
      },
      tx,
    );
  });
}

/** The hosts a connection's credential may be sent to now, as stored (none: an empty list). */
export async function allowedHostsOf(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  allowedConnections?: string[],
): Promise<string[]> {
  assertConnectionAccess(allowedConnections, connectionId);
  const conn = await getConnectionScoped(ctx, connectionId, operatorId, allowedConnections);
  if (!conn) throw new NotFoundError('ServiceConnection', connectionId);
  return conn.allowed_hosts ?? [];
}

const sameHosts = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && [...a].sort().every((host, index) => host === [...b].sort()[index]);

/**
 * Put a connection's hosts back to `previous` after a setup that widened them failed, but only while they are still
 * what that setup wrote (`wrote`): a connection someone changed since is left as they changed it. Answers whether it
 * restored. Restoring narrows or keeps, so it needs no approval, and it is never a way to widen.
 */
export async function restoreAllowedHosts(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  previous: string[],
  wrote: string[],
  allowedConnections?: string[],
): Promise<boolean> {
  assertConnectionAccess(allowedConnections, connectionId);
  let cleanedWrote: string[];
  try {
    cleanedWrote = normalizeAllowedHosts(wrote);
  } catch {
    return false;
  }
  return ctx.serviceRepo.withOperatorGrantLock(operatorId, async (tx) => {
    const conn = await ctx.serviceRepo.findConnectionById(connectionId, tx);
    if (!conn || conn.operator_id !== operatorId) return false;
    if (!sameHosts(conn.allowed_hosts ?? [], cleanedWrote)) return false;
    if (sameHosts(previous, conn.allowed_hosts ?? [])) return true;
    await ctx.serviceRepo.updateConnection(connectionId, { allowed_hosts: previous.length > 0 ? previous : null }, tx);
    return true;
  });
}
