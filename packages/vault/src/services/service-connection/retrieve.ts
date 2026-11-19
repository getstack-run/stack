import { ConflictError, ConnectionAmbiguousError, ForbiddenError, NotFoundError } from '@stack/shared';
import { decodeStoredCredential } from '../credential-fields.js';
import { assertConnectionAccess, type ServiceConnectionContext } from './context.js';
import { applyTokenLifecycle } from './oauth-renewal.js';

/** `credential` for a single-token credential, `credentials` for a multi-field one. */
function credentialPayload(
  credential: string | Record<string, string>,
): { credential: string } | { credentials: Record<string, string> } {
  return typeof credential === 'string' ? { credential } : { credentials: credential };
}

/**
 * Which connections of a provider a caller may be offered; the resolver chooses among these and never outside them.
 * - `connections`: a Passport's grants for the provider (the `connection_id`s of its services). `sharedFallback` is a
 *   grant that names no connection: it stands for the provider's one shared active connection, and for nothing when
 *   the account holds several. Only shared connections are offered, as before.
 * - `shared`: an owner API key, or STACK's own system operator: the account's shared connections.
 * - `member`: a team member: their own connections, else the shared ones, narrowed by the member's
 *   `allowedConnections` (an empty list denies all; undefined is unrestricted).
 */
export type ProxyEligibility =
  | { kind: 'connections'; connectionIds: readonly string[]; sharedFallback?: boolean }
  | { kind: 'shared' }
  | { kind: 'member'; memberId: string; allowedConnections?: readonly string[] };

type ConnectionRow = Awaited<
  ReturnType<ServiceConnectionContext['serviceRepo']['findEligibleProxyConnections']>
>[number];

/**
 * The one place that picks a connection when a service has several. Returns the chosen row; refuses before any
 * credential is decrypted. A selector (an id, else a name without case) is looked for inside the eligible set only, and
 * a miss is the same NotFound an unknown service gets, so it never shows which other connections exist. With no selector
 * exactly one eligible connection is taken, none is NotFound and several are ConnectionAmbiguousError, listing only the
 * eligible ones.
 */
async function pickConnection(
  ctx: ServiceConnectionContext,
  operatorId: string,
  provider: string,
  eligibility: ProxyEligibility,
  selector?: string,
): Promise<ConnectionRow> {
  const repo = ctx.serviceRepo;
  // Tiers are tried in order: a member's own connections win over the shared ones.
  let tiers: ConnectionRow[][];
  if (eligibility.kind === 'connections') {
    const ids = new Set(eligibility.connectionIds);
    const sharedFallback = eligibility.sharedFallback === true;
    const shared = sharedFallback || ids.size > 0
      ? await repo.findEligibleProxyConnections(
        operatorId,
        provider,
        'shared',
        sharedFallback ? undefined : [...ids],
      )
      : [];
    const unpinned = sharedFallback && shared.length === 1 ? shared : [];
    tiers = [shared.filter((row) => ids.has(row.id) || unpinned.includes(row))];
  } else if (eligibility.kind === 'shared') {
    tiers = [await repo.findEligibleProxyConnections(operatorId, provider, 'shared')];
  } else {
    const rows = await repo.findEligibleProxyConnections(
      operatorId,
      provider,
      { memberId: eligibility.memberId },
      eligibility.allowedConnections,
    );
    tiers = [
      rows.filter((row) => row.member_id === eligibility.memberId),
      rows.filter((row) => row.member_id === null),
    ];
  }

  if (selector !== undefined) {
    const wanted = selector.toLowerCase();
    for (const tier of tiers) {
      const hit = tier.find((row) => row.id === selector) ?? tier.find((row) => row.name.toLowerCase() === wanted);
      if (hit) return hit;
    }
    throw new NotFoundError('ServiceConnection', provider);
  }
  const tier = tiers.find((rows) => rows.length > 0);
  if (!tier) throw new NotFoundError('ServiceConnection', provider);
  if (tier.length > 1) throw new ConnectionAmbiguousError(provider, tier);
  return tier[0]!;
}

/**
 * Retrieve and decrypt a credential for a given provider, for callers that hold exactly one connection of it (STACK's
 * own system operator). If memberId is set, takes the personal connection first, then the shared one. More than one
 * eligible connection is ConnectionAmbiguousError, never a silent pick. If allowedConnections is set, verifies the
 * connection is in the list. An empty list intentionally denies every connection; undefined is the unrestricted
 * operator/member state.
 */
export async function retrieveCredential(
  ctx: ServiceConnectionContext,
  operatorId: string,
  provider: string,
  allowedConnections?: string[],
  memberId?: string,
) {
  const conn = await pickConnection(
    ctx,
    operatorId,
    provider,
    memberId ? { kind: 'member', memberId } : { kind: 'shared' },
  );

  // Enforce member access restrictions
  if (allowedConnections !== undefined && !allowedConnections.includes(conn.id)) {
    throw new ForbiddenError('You do not have access to this service connection');
  }

  const decryptedRaw = await ctx.decryptCredential(
    conn.operator_id,
    conn.id,
    conn.credential_encrypted,
    conn.provider,
  );
  // Apply OAuth lifecycle (refresh-token rotation, client_credentials
  // grant) before handing the credential to the proxy / caller. No-op
  // for non-OAuth credentials.
  const lifecycle = await applyTokenLifecycle(ctx, decryptedRaw, {
    id: conn.id,
    operator_id: conn.operator_id,
    provider: conn.provider,
    service_id: conn.service_id,
    credential_version: conn.credential_version,
    oauth_managed: conn.oauth_managed,
    scopes: conn.scopes,
  });

  return {
    provider: conn.provider,
    connection_id: conn.id,
    ...credentialPayload(decodeStoredCredential(lifecycle.credential)),
  };
}

/**
 * Resolve, authorize, decrypt and version-pin the one connection a proxy
 * operation will bind. A refresh that cannot durably advance the semantic
 * credential version fails closed.
 */
export async function retrieveCredentialPinned(
  ctx: ServiceConnectionContext,
  operatorId: string,
  provider: string,
  eligibility: ProxyEligibility,
  selector?: string,
) {
  const selected = await resolveProxyConnection(ctx, operatorId, provider, eligibility, selector);
  return retrieveCredentialPinnedByConnectionId(
    ctx,
    operatorId,
    selected.connection_id,
    selected.credential_version,
    eligibility.kind === 'member' ? eligibility.allowedConnections : undefined,
  );
}

/** Select non-secret connection metadata before any credential decryption. */
export async function resolveProxyConnection(
  ctx: ServiceConnectionContext,
  operatorId: string,
  provider: string,
  eligibility: ProxyEligibility,
  selector?: string,
) {
  const conn = await pickConnection(ctx, operatorId, provider, eligibility, selector);
  return {
    provider: conn.provider,
    service_id: conn.service_id,
    connection_id: conn.id,
    name: conn.name,
    credential_version: conn.credential_version,
    proxy_enabled: conn.proxy_enabled,
    allowed_hosts: conn.allowed_hosts,
    member_id: conn.member_id,
  };
}

/** Decrypt only the connection/version that already passed policy gates. */
export async function retrieveCredentialPinnedByConnectionId(
  ctx: ServiceConnectionContext,
  operatorId: string,
  connectionId: string,
  expectedVersion: number,
  allowedConnections?: readonly string[],
) {
  assertConnectionAccess(allowedConnections ? [...allowedConnections] : undefined, connectionId);
  const conn = await ctx.serviceRepo.findConnectionById(connectionId);
  if (
    !conn ||
    conn.operator_id !== operatorId ||
    conn.status !== 'active' ||
    conn.credential_version !== expectedVersion
  ) {
    throw new ConflictError('Service connection changed after proxy policy evaluation');
  }

  const decryptedRaw = await ctx.decryptCredential(
    conn.operator_id,
    conn.id,
    conn.credential_encrypted,
    conn.provider,
  );
  const lifecycle = await applyTokenLifecycle(
    ctx,
    decryptedRaw,
    {
      id: conn.id,
      operator_id: conn.operator_id,
      provider: conn.provider,
      service_id: conn.service_id,
      credential_version: conn.credential_version,
      oauth_managed: conn.oauth_managed,
      scopes: conn.scopes,
    },
    true,
  );

  return {
    provider: conn.provider,
    service_id: conn.service_id,
    connection_id: conn.id,
    credential_version: lifecycle.credentialVersion,
    proxy_enabled: conn.proxy_enabled,
    allowed_hosts: conn.allowed_hosts,
    mcp_url: conn.mcp_url ?? null,
    ...credentialPayload(decodeStoredCredential(lifecycle.credential)),
  };
}

/**
 * The current plaintext credential of a connection row the caller has already
 * authorised: decrypted, and renewed first when it is an OAuth token that is
 * expired or about to be. Renewal that cannot complete throws OAuthLifecycleError.
 */
export async function currentCredential(
  ctx: ServiceConnectionContext,
  conn: {
    id: string;
    operator_id: string;
    provider: string;
    service_id: string;
    credential_version: number;
    oauth_managed?: boolean;
    scopes?: readonly string[];
    credential_encrypted: string;
  },
): Promise<string> {
  const decrypted = await ctx.decryptCredential(
    conn.operator_id,
    conn.id,
    conn.credential_encrypted,
    conn.provider,
  );
  const lifecycle = await applyTokenLifecycle(ctx, decrypted, {
    id: conn.id,
    operator_id: conn.operator_id,
    provider: conn.provider,
    service_id: conn.service_id,
    credential_version: conn.credential_version,
    oauth_managed: conn.oauth_managed,
    scopes: conn.scopes,
  });
  return lifecycle.credential;
}

/** Retrieve and decrypt a credential by connection ID. */
export async function retrieveCredentialByConnectionId(
  ctx: ServiceConnectionContext,
  operatorId: string,
  connectionId: string,
  allowedConnections?: string[],
) {
  const conn = await ctx.serviceRepo.findConnectionById(connectionId);
  if (!conn || conn.operator_id !== operatorId || conn.status !== 'active') {
    throw new NotFoundError('ServiceConnection', connectionId);
  }

  if (allowedConnections !== undefined && !allowedConnections.includes(conn.id)) {
    throw new ForbiddenError('You do not have access to this service connection');
  }

  const decryptedRaw = await ctx.decryptCredential(
    conn.operator_id,
    conn.id,
    conn.credential_encrypted,
    conn.provider,
  );
  const lifecycle = await applyTokenLifecycle(ctx, decryptedRaw, {
    id: conn.id,
    operator_id: conn.operator_id,
    provider: conn.provider,
    service_id: conn.service_id,
    credential_version: conn.credential_version,
    oauth_managed: conn.oauth_managed,
    scopes: conn.scopes,
  });

  return {
    provider: conn.provider,
    connection_id: conn.id,
    ...credentialPayload(decodeStoredCredential(lifecycle.credential)),
  };
}
