import {
  ids,
  type ConnectServiceInput,
  type ConnectCustomServiceInput,
  NotFoundError,
  ForbiddenError,
  ScopeEscalationError,
  invalidChildScopes,
  defaultConnectionScopes,
  ConflictError,
  type OperatorTier,
  TierLimitExceededError,
} from '@stack/shared';
import { contractPlanLimits } from '../entitlements/plan-limits.js';
import { credentialExpiresAt, type CredentialFields } from '../oauth-token-lifecycle.js';
import { parseCredentialObject } from '../credential-fields.js';
import type { ServiceConnectionContext } from './context.js';
import { resolveConnectionHosts, resolveConnectionMcpUrl } from './hosts.js';

/**
 * Why a principal may not hold a new connection to a provider. A 409
 * CONFLICT like any other ConflictError; the reason lets the hosted OAuth
 * flow refuse before the consent screen and tell the user what to change.
 */
export type ConnectionPrincipalConflictReason =
  | 'member_not_active'
  | 'service_shared_mode'
  | 'service_per_member_mode'
  | 'connection_name_taken';

export class ConnectionPrincipalConflictError extends ConflictError {
  constructor(
    readonly reason: ConnectionPrincipalConflictReason,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Whether this principal (the operator, or one member) may hold a new
 * connection to the provider. connect() re-checks it; the hosted OAuth
 * flow also calls it before sending the user to the consent screen.
 */
export async function assertConnectionPrincipal(
  ctx: ServiceConnectionContext,
  operatorId: string,
  provider: string,
  memberId?: string,
  connectionName?: string,
): Promise<string> {
  if (memberId) {
    const member = await ctx.serviceRepo.findMemberById(memberId);
    if (!member || member.operator_id !== operatorId || member.status !== 'active') {
      throw new ConnectionPrincipalConflictError(
        'member_not_active',
        'The member principal is not active for this operator',
      );
    }
  }

  const configuration = await ctx.serviceRepo.findConfigurationByOperatorAndProvider(
    operatorId,
    provider,
  );
  if (configuration?.mode === 'shared' && memberId) {
    throw new ConnectionPrincipalConflictError(
      'service_shared_mode',
      `Service "${provider}" uses shared mode and cannot store a member connection`,
    );
  }
  if (configuration?.mode === 'per_member' && !memberId) {
    throw new ConnectionPrincipalConflictError(
      'service_per_member_mode',
      `Service "${provider}" uses per-member mode and requires a member connection`,
    );
  }

  // The name the new connection will carry. A principal's first connection of a service may leave it out (it is
  // named `default`); a further one must give a name no active connection of the same principal holds, in any case.
  const existing = await ctx.serviceRepo.findActiveConnectionsForPrincipal(
    operatorId,
    provider,
    memberId ?? null,
  );
  if (existing.length > 0) {
    if (connectionName === undefined) {
      throw new ConnectionPrincipalConflictError(
        'connection_name_taken',
        'This service already has a connection: pass a different connection_name to add another.',
      );
    }
    const wanted = connectionName.toLowerCase();
    if (existing.some((connection) => connection.name.toLowerCase() === wanted)) {
      throw new ConnectionPrincipalConflictError(
        'connection_name_taken',
        `A connection of this service is already named "${connectionName}": pass a different connection_name.`,
      );
    }
  }
  return connectionName ?? DEFAULT_CONNECTION_NAME;
}

/** What the first connection of a service is called when the customer gave no name. */
export const DEFAULT_CONNECTION_NAME = 'default';

/**
 * Initiate service connection. In production this returns an OAuth URL
 * the user visits. For MVP, we accept a token directly.
 */
export async function connectService(
  ctx: ServiceConnectionContext,
  operatorId: string,
  operatorTier: OperatorTier,
  input: ConnectServiceInput & { oauth_token: string },
  connectedBy?: string,
  memberId?: string,
  managedOAuthBinding?: CredentialFields['oauth_app_binding'],
) {
  const service = await ctx.serviceRepo.findAccessibleServiceById(input.service_id, operatorId);
  if (!service) throw new NotFoundError('Service', input.service_id);
  const connectionName = await assertConnectionPrincipal(ctx, operatorId, service.provider, memberId, input.connection_name);

  // Validate requested scopes against available scopes.
  // '*' in scopes_available permits any requested scope; the error surfaces
  // which scopes were rejected and the available set.
  const invalidScopes = invalidChildScopes(input.scopes, service.scopes_available);
  if (invalidScopes.length > 0) {
    throw new ScopeEscalationError({
      requested_invalid: invalidScopes,
      parent_scopes: service.scopes_available,
    });
  }

  // Check tier limits
  const count = await ctx.serviceRepo.countConnectionsByOperator(operatorId);
  const limit = (ctx.hooks.planLimits ?? contractPlanLimits)(operatorTier).services;
  if (count >= limit) {
    throw new TierLimitExceededError('service connections', limit);
  }

  // Encrypt the OAuth token via KMS envelope encryption. The context binds
  // the ciphertext to this operator+provider so an envelope cannot be
  // transplanted onto another operator's row and decrypted.
  // Where may this credential go? Resolved before we encrypt, so a
  // per-tenant provider with no declared host fails here rather than
  // creating a connection that can never proxy.
  const connectHosts = resolveConnectionHosts(
    service.provider,
    input.allowed_hosts,
    undefined,
    service.name,
  );
  const mcpUrl = resolveConnectionMcpUrl(input.mcp_url, service.provider, connectHosts);

  // A JSON token response carries managed OAuth metadata; a bare token has none.
  let credentialInput = input.oauth_token;
  const fields = parseCredentialObject<CredentialFields>(credentialInput);
  if (fields) {
    delete fields.oauth_app_binding;
    if (managedOAuthBinding) fields.oauth_app_binding = managedOAuthBinding;
    credentialInput = JSON.stringify(fields);
  }
  const { ciphertext, keyRef } = await ctx.kms.encrypt(credentialInput, {
    operator_id: operatorId,
    provider: service.provider,
  });

  // Raw provider tokens have no expiry metadata.
  let tokenExpiry: Date | null = null;
  const parsed = parseCredentialObject<CredentialFields>(input.oauth_token);
  const expiry = parsed ? credentialExpiresAt(parsed) : null;
  if (expiry !== null) tokenExpiry = new Date(expiry);

  return ctx.serviceRepo.createConnection({
    id: ids.serviceConnection(),
    operator_id: operatorId,
    service_id: service.id,
    provider: service.provider,
    name: connectionName,
    scopes: input.scopes,
    credential_ref: keyRef,
    credential_encrypted: ciphertext,
    expires_at: tokenExpiry,
    oauth_managed: managedOAuthBinding !== undefined,
    connected_by: connectedBy ?? null,
    member_id: memberId ?? null,
    status: 'active',
    allowed_hosts: connectHosts,
    mcp_url: mcpUrl,
  });
}

/**
 * Connect an application-credentials catalog service (Microsoft Entra App,
 * GCP Service Account, etc) by providing application-level credentials
 * directly. Unlike connectCustom this BINDS to an existing catalog
 * service entry instead of creating a new custom_ provider. The
 * credential JSON is shaped to trigger oauth-token-lifecycle's
 * client_credentials path on every retrieval: STACK mints fresh
 * application access tokens transparently.
 *
 * Caller passes { service_id, credential, scopes } where credential is
 * the JSON object with client_id + client_secret + tenant_id? + cc_scope
 * + cc_token_url?. See oauth-token-lifecycle.ts for the exact shape.
 */
export async function connectApplication(
  ctx: ServiceConnectionContext,
  operatorId: string,
  operatorTier: OperatorTier,
  input: {
    service_id: string;
    credential: Record<string, string>;
    scopes?: string[];
    allowed_hosts?: string[];
    mcp_url?: string;
    connection_name?: string;
  },
  connectedBy?: string,
  memberId?: string,
) {
  const service = await ctx.serviceRepo.findAccessibleServiceById(input.service_id, operatorId);
  if (!service) throw new NotFoundError('Service', input.service_id);
  const connectionName = await assertConnectionPrincipal(ctx, operatorId, service.provider, memberId, input.connection_name);

  // Tier-limit gate (mirrors connect / connectCustom)
  const count = await ctx.serviceRepo.countConnectionsByOperator(operatorId);
  const limit = (ctx.hooks.planLimits ?? contractPlanLimits)(operatorTier).services;
  if (count >= limit) {
    throw new TierLimitExceededError('service connections', limit);
  }

  // Same host rule as every other connect path. The credential map is
  // passed in, so a per-tenant provider that carries its host in a
  // url / host / instance_url field resolves with no question asked.
  const appHosts = resolveConnectionHosts(
    service.provider,
    input.allowed_hosts,
    input.credential,
    service.name,
  );
  const appMcpUrl = resolveConnectionMcpUrl(input.mcp_url, service.provider, appHosts);

  const credentialString = JSON.stringify(input.credential);
  const { ciphertext, keyRef } = await ctx.kms.encrypt(credentialString, {
    operator_id: operatorId,
    provider: service.provider,
  });

  return ctx.serviceRepo.createConnection({
    id: ids.serviceConnection(),
    operator_id: operatorId,
    service_id: service.id,
    provider: service.provider,
    name: connectionName,
    scopes: input.scopes ?? defaultConnectionScopes(service.scopes_available),
    allowed_hosts: appHosts,
    mcp_url: appMcpUrl,
    credential_ref: keyRef,
    credential_encrypted: ciphertext,
    connected_by: connectedBy ?? null,
    member_id: memberId ?? null,
    status: 'active',
  });
}

export interface ConnectCustomOptions {
  /**
   * STACK's own provider keys (the system operator's bootstrap) are stored under `custom_<name>`, where STACK's own
   * code reads them, even when the catalogue also lists a service of that name. The catalogue guard is for a customer's
   * stale client; it is skipped only on this path, which no route reaches.
   */
  allowCatalogueProvider?: boolean;
}

/**
 * Connect a custom service: the operator provides a name and a credential
 * directly. Creates both a service entry and a connection in one shot.
 */
export async function connectCustom(
  ctx: ServiceConnectionContext,
  operatorId: string,
  operatorTier: OperatorTier,
  input: ConnectCustomServiceInput,
  connectedBy?: string,
  memberId?: string,
  options: ConnectCustomOptions = {},
) {
  // Create or reuse the service entry (provider = sanitized name)
  const provider = input.name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_|_$/g, '');

  // Guard: refuse to mint a `custom_<slug>` shadow when the slug
  // collides with a real catalog provider. Without this, a stale
  // dashboard tab (or any future client bug) calling /v1/services/custom
  // for a catalog service will silently create a duplicate row with
  // its credential isolated from the canonical service, and renaming the
  // provider afterwards breaks the credential's encryption context (the
  // context is bound to the ciphertext, so the provider cannot change).
  const collision = options.allowCatalogueProvider ? null : await ctx.serviceRepo.findCatalogServiceByProvider(provider);
  if (collision) {
    throw new ForbiddenError(
      `Provider "${provider}" already exists in the catalog. Use POST /v1/services/connect-application with service_id=${collision.id} instead of /v1/services/custom.`,
      { field: 'name' },
    );
  }

  let connectionName = DEFAULT_CONNECTION_NAME;
  if (input.credential) {
    connectionName = await assertConnectionPrincipal(ctx, operatorId, `custom_${provider}`, memberId, input.connection_name);
  }

  // Every check that can refuse the connection runs BEFORE the service row is written, so a connect that fails
  // leaves an existing custom service of the same name exactly as it was.
  let customHosts: string[] = [];
  let customMcpUrl: string | null = null;
  if (input.mcp_url !== undefined && !input.credential) {
    throw new ForbiddenError('mcp_url belongs to a connection: give the credential with it.');
  }
  if (input.credential) {
    // Credential-to-destination binding for the ONE case STACK cannot resolve
    // on the operator's behalf: their own API. Catalogue providers come from
    // PROVIDER_API_HOSTS and per-tenant providers are derived from the
    // credential, so this is the only place an operator is ever asked.
    //
    // Refuse rather than create a connection that cannot proxy. A row with no
    // declared hosts is dead on arrival (every proxy call through it denies),
    // and discovering that at first call is a much worse experience than being
    // told here. The dashboard makes this a required field on the connect
    // dialog so an operator meets it there, not later.
    customHosts =
      resolveConnectionHosts(
        `custom_${provider}`,
        input.allowed_hosts,
        input.credential,
        input.name,
      ) ?? [];
    if (customHosts.length === 0) {
      throw new ForbiddenError(
        `allowed_hosts is required for a custom service: STACK cannot know where "${input.name}" ` +
          `lives, so it cannot tell your API from an attacker's. Give the hostname(s) this ` +
          `credential may be sent to (for example api.${provider}.com), or include a base_url ` +
          `field in the credential and it will be taken from there.`,
        { field: 'allowed_hosts' },
      );
    }

    customMcpUrl = resolveConnectionMcpUrl(input.mcp_url, `custom_${provider}`, customHosts);

    // Check tier limits (only when creating a connection)
    const count = await ctx.serviceRepo.countConnectionsByOperator(operatorId);
    const limit = (ctx.hooks.planLimits ?? contractPlanLimits)(operatorTier).services;
    if (count >= limit) {
      throw new TierLimitExceededError('service connections', limit);
    }
  }

  const service = await ctx.serviceRepo.upsertCustomService(operatorId, {
    id: ids.service(),
    provider: `custom_${provider}`,
    name: input.name,
    description: input.description ?? `Custom service: ${input.name}`,
    oauth_auth_url: input.oauth_auth_url ?? '',
    oauth_token_url: input.oauth_token_url ?? '',
    scopes_available: input.scopes ?? ['*'],
  });

  // If no credential provided, return service entry only (enable without connecting)
  if (!input.credential) {
    return { id: service.id, provider: service.provider, name: service.name, registered: true };
  }

  // Normalize credential: object → JSON string for encryption
  const credentialString =
    typeof input.credential === 'string' ? input.credential : JSON.stringify(input.credential);

  // Encrypt the credential via KMS. Bind to operator+provider so the
  // envelope can only be decrypted against the same row it was created for.
  const { ciphertext, keyRef } = await ctx.kms.encrypt(credentialString, {
    operator_id: operatorId,
    provider: service.provider,
  });

  return ctx.serviceRepo.createConnection({
    id: ids.serviceConnection(),
    operator_id: operatorId,
    service_id: service.id,
    provider: service.provider,
    name: connectionName,
    scopes: input.scopes ?? ['*'],
    credential_ref: keyRef,
    credential_encrypted: ciphertext,
    connected_by: connectedBy ?? null,
    member_id: memberId ?? null,
    status: 'active',
    // Declared or derived above; a custom service never reaches here
    // without one, so this connection can actually proxy.
    allowed_hosts: customHosts,
    mcp_url: customMcpUrl,
  });
}
