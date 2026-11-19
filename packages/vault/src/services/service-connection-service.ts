import type {
  ConnectServiceInput,
  ConnectCustomServiceInput,
  GrantAgentAccessInput,
  OperatorTier,
} from '@stack/shared';
import type { Redis } from 'ioredis';
import type { ServiceRepository } from '../repositories/service-repo.js';
import type { AgentRepository } from '../repositories/agent-repo.js';
import type { KmsService } from '../crypto/kms.js';
import type { CredentialFields, ReconnectReason } from './oauth-token-lifecycle.js';
import { flagReconnectRequired } from './service-connection/reconnect.js';
import { sharesAppGrant, type GrantApp } from './service-connection/shared-grant.js';
import {
  connectApplication,
  connectCustom,
  connectService,
  assertConnectionPrincipal,
  type ConnectCustomOptions,
} from './service-connection/connect.js';
import {
  assertConnectionAccess,
  createCredentialDecryptor,
  type ServiceConnectionContext,
} from './service-connection/context.js';
import {
  configureService,
  disableService,
  getServiceConfigurations,
} from './service-connection/configuration.js';
import {
  getAgentPermissions,
  getGrantsByConnection,
  grantAccessWidens,
  grantAgentAccess,
  revokeAgentAccess,
} from './service-connection/grants.js';
import {
  allowedHostsChangeWidens,
  allowedHostsOf,
  restoreAllowedHosts,
  setAllowedHosts,
} from './service-connection/hosts.js';
import { renameConnection } from './service-connection/rename.js';
import { checkSetup, type SetupConnection } from './service-connection/setup.js';
import {
  assertServiceConnectionHooks,
  type ServiceConnectionHooks,
} from './service-connection/hooks.js';
import {
  checkProxyEnabled,
  proxyChangeWeakens,
  setProxyEnabled,
} from './service-connection/proxy-settings.js';
import {
  disconnectConnection,
  getConnectionScoped,
  connectionNameWhenSeveral,
  listConnectedServices,
} from './service-connection/queries.js';
import {
  currentCredential,
  resolveProxyConnection,
  type ProxyEligibility,
  retrieveCredential,
  retrieveCredentialByConnectionId,
  retrieveCredentialPinned,
  retrieveCredentialPinnedByConnectionId,
} from './service-connection/retrieve.js';

// The pieces of connection management live in ./service-connection/, one module
// per concern. This file is the one class the rest of the codebase constructs,
// plus the names other packages import from it.
export type { ProxyEligibility } from './service-connection/retrieve.js';
export {
  ConnectionPrincipalConflictError,
  type ConnectCustomOptions,
  type ConnectionPrincipalConflictReason,
} from './service-connection/connect.js';
export { grantAuthorityWidens } from './service-connection/grants.js';
export { allowedHostsWiden } from './service-connection/hosts.js';
export {
  standaloneServiceConnectionHooks,
  type ConnectionClosingHook,
  type ConnectionLifecycleEvent,
  type ConnectionOpenedHook,
  type ExternalAgentGuard,
  type OAuthAppBinding,
  type OAuthAppRetiredCheck,
  type OAuthClientResolver,
  type ReconnectRequiredHandler,
  type ServiceConnectionHooks,
} from './service-connection/hooks.js';

export class ServiceConnectionService {
  private readonly ctx: ServiceConnectionContext;

  constructor(
    serviceRepo: ServiceRepository,
    agentRepo: AgentRepository,
    kms: KmsService,
    redis: Redis | undefined,
    /**
     * The collaborators this service cannot build itself: the fleet guard for
     * grant changes, the OAuth application behind a managed connection, and
     * the notifier for a credential that must be reconnected. See
     * `standaloneServiceConnectionHooks` for a process that hosts none of them.
     */
    hooks: ServiceConnectionHooks,
  ) {
    assertServiceConnectionHooks(hooks);
    this.ctx = {
      serviceRepo,
      agentRepo,
      kms,
      redis,
      hooks,
      decryptCredential: createCredentialDecryptor(kms, hooks.cachedDecryptOperatorIds),
    };
  }

  /** Undefined means owner-wide access; a present list is an exact connection ceiling. */
  assertConnectionAccess(allowedConnections: string[] | undefined, connectionId?: string): void {
    assertConnectionAccess(allowedConnections, connectionId);
  }

  /**
   * Active service connections. Never a gate: connections are unlimited on
   * every tier. They are counted so staff can see whether "unlimited" is being
   * used the way we assumed when we decided not to cap it.
   */
  async countActive(operatorId: string): Promise<number> {
    const rows = await this.listConnectedServices(operatorId);
    return rows.length;
  }

  async listAvailableServices() {
    return this.ctx.serviceRepo.listCatalogServices();
  }

  async listConnectedServices(operatorId: string, allowedConnections?: string[]) {
    return listConnectedServices(this.ctx, operatorId, allowedConnections);
  }

  /**
   * Whether this principal (the operator, or one member) may hold a new
   * connection to the provider. connect() re-checks it; the hosted OAuth
   * flow also calls it before sending the user to the consent screen.
   */
  async assertConnectionPrincipal(
    operatorId: string,
    provider: string,
    memberId?: string,
    connectionName?: string,
  ): Promise<void> {
    await assertConnectionPrincipal(this.ctx, operatorId, provider, memberId, connectionName);
  }

  /**
   * Initiate service connection. In production this returns an OAuth URL
   * the user visits. For MVP, we accept a token directly.
   */
  async connect(
    operatorId: string,
    operatorTier: OperatorTier,
    input: ConnectServiceInput & { oauth_token: string },
    connectedBy?: string,
    memberId?: string,
    managedOAuthBinding?: CredentialFields['oauth_app_binding'],
  ) {
    const connection = await connectService(
      this.ctx,
      operatorId,
      operatorTier,
      input,
      connectedBy,
      memberId,
      managedOAuthBinding,
    );
    return this.opened(operatorId, connection);
  }

  /**
   * Run the deployment's hook for a connection just made. When it throws the connection is removed (no credential stays that did not
   * work) and the error reaches the caller.
   */
  private async opened<C extends { id: string; provider: string; service_id: string; credential_encrypted: string; operator_id: string }>(
    operatorId: string,
    connection: C,
    options?: { skipLifecycle?: boolean },
  ): Promise<C & { notice?: string }> {
    const hook = this.ctx.hooks.connectionOpened;
    if (!hook || options?.skipLifecycle) return connection;
    let notice: string | undefined;
    try {
      const told = await hook({
        operatorId,
        connection: { id: connection.id, provider: connection.provider, service_id: connection.service_id },
        credential: () => this.ctx.decryptCredential(connection.operator_id, connection.id, connection.credential_encrypted, connection.provider),
      });
      notice = told?.notice;
    } catch (error) {
      await this.ctx.serviceRepo.revokeConnection(connection.id).catch(() => undefined);
      throw error;
    }
    return notice === undefined ? connection : { ...connection, notice };
  }

  /**
   * Operator-scoped connection lookup for the route-layer provenance guards.
   * Returns undefined for foreign/missing ids so the caller can 404 without an
   * enumeration signal.
   */
  async getConnectionScoped(
    connectionId: string,
    operatorId: string,
    allowedConnections?: string[],
  ) {
    return getConnectionScoped(this.ctx, connectionId, operatorId, allowedConnections);
  }

  /**
   * The name an approval shows for a connection: the owner's name for it, only while the account holds two or more
   * active connections of that service, else null. Null too when the connection is not found.
   */
  async connectionNameWhenSeveral(
    connectionId: string,
    operatorId: string,
    allowedConnections?: string[],
  ): Promise<string | null> {
    const connection = await getConnectionScoped(this.ctx, connectionId, operatorId, allowedConnections);
    return connection ? connectionNameWhenSeveral(this.ctx, connection) : null;
  }

  /**
   * Connect an application-credentials catalog service (Microsoft Entra App,
   * GCP Service Account, etc) by providing application-level credentials
   * directly. Binds to an existing catalog service entry instead of creating a
   * new custom_ provider.
   */
  async connectApplication(
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
    /** `skipLifecycle`: the caller sets up what the provider needs beside the key itself (STACK's own join, which must not lose a key to a failed hook). */
    options?: { skipLifecycle?: boolean },
  ) {
    const connection = await connectApplication(this.ctx, operatorId, operatorTier, input, connectedBy, memberId);
    return this.opened(operatorId, connection, options);
  }

  /**
   * Connect a custom service: the operator provides a name and a credential
   * directly. Creates both a service entry and a connection in one shot.
   */
  async connectCustom(
    operatorId: string,
    operatorTier: OperatorTier,
    input: ConnectCustomServiceInput,
    connectedBy?: string,
    memberId?: string,
    options?: ConnectCustomOptions,
  ) {
    const connection = await connectCustom(this.ctx, operatorId, operatorTier, input, connectedBy, memberId, options);
    // A service registered without a credential has no connection to set anything up beside.
    return 'registered' in connection ? connection : this.opened(operatorId, connection);
  }

  /**
   * Retrieve and decrypt a credential for a given provider.
   * If memberId is set, tries personal connection first, then falls back to shared.
   * If allowedConnections is set, verifies the connection is in the list.
   * An empty list intentionally denies every connection; undefined is the
   * unrestricted operator/member state.
   */
  async retrieveCredential(
    operatorId: string,
    provider: string,
    allowedConnections?: string[],
    memberId?: string,
  ) {
    return retrieveCredential(this.ctx, operatorId, provider, allowedConnections, memberId);
  }

  /**
   * Resolve, authorize, decrypt and version-pin the one connection a proxy
   * operation will bind. A refresh that cannot durably advance the semantic
   * credential version fails closed.
   */
  async retrieveCredentialPinned(
    operatorId: string,
    provider: string,
    eligibility: ProxyEligibility,
    selector?: string,
  ) {
    return retrieveCredentialPinned(this.ctx, operatorId, provider, eligibility, selector);
  }

  /**
   * Select non-secret connection metadata before any credential decryption: the one connection `selector` (an id or a
   * name) names among the caller's eligible ones, or the only eligible one. Several eligible and no selector is
   * ConnectionAmbiguousError; a selector outside the eligible set is the same NotFound an unknown service gets.
   */
  async resolveProxyConnection(
    operatorId: string,
    provider: string,
    eligibility: ProxyEligibility,
    selector?: string,
  ) {
    return resolveProxyConnection(this.ctx, operatorId, provider, eligibility, selector);
  }

  /** Renames an active connection of the account. NotFound when it is not one; ConnectionPrincipalConflictError (`connection_name_taken`) when the principal's other connection holds the name. */
  async renameConnection(operatorId: string, connectionId: string, name: string) {
    return renameConnection(this.ctx, operatorId, connectionId, name);
  }

  /** Decrypt only the connection/version that already passed policy gates. */
  async retrieveCredentialPinnedByConnectionId(
    operatorId: string,
    connectionId: string,
    expectedVersion: number,
    allowedConnections?: readonly string[],
  ) {
    return retrieveCredentialPinnedByConnectionId(
      this.ctx,
      operatorId,
      connectionId,
      expectedVersion,
      allowedConnections,
    );
  }

  /** Retrieve and decrypt a credential by connection ID. */
  async retrieveCredentialByConnectionId(
    operatorId: string,
    connectionId: string,
    allowedConnections?: string[],
  ) {
    return retrieveCredentialByConnectionId(this.ctx, operatorId, connectionId, allowedConnections);
  }

  /**
   * The plaintext credential of a connection row the caller already
   * authorised, renewed first when it is an expired OAuth token. For checks
   * that must see the token the proxy would send.
   */
  async currentCredential(conn: Parameters<typeof currentCredential>[1]): Promise<string> {
    return currentCredential(this.ctx, conn);
  }

  /** Marks an active connection reconnect-required now, with the notice a lazy mark would give. False when it is not active. */
  async flagReconnectRequired(operatorId: string, connectionId: string, reason: ReconnectReason): Promise<boolean> {
    return flagReconnectRequired(this.ctx, operatorId, connectionId, reason);
  }

  /** Whether the operator holds a live connection within its app's list through this app: ending a grant of the app at the provider could end that one's too. */
  async sharesAppGrant(operatorId: string, app: GrantApp, exceptConnectionId?: string): Promise<boolean> {
    return sharesAppGrant(this.ctx, operatorId, app, exceptConnectionId);
  }

  async checkProxyEnabled(operatorId: string, provider: string): Promise<boolean | null> {
    return checkProxyEnabled(this.ctx, operatorId, provider);
  }

  /**
   * Find the active connection for (operator, provider). Returns the row so
   * callers can access service_id (for identity-requirements enforcement),
   * proxy_enabled, member_id, etc. without making a second query.
   */
  async findActiveByProvider(operatorId: string, provider: string) {
    return this.ctx.serviceRepo.findActiveConnectionByOperatorAndProvider(operatorId, provider);
  }

  /**
   * Whether this operator holds an active connection to a catalog
   * service_id. Gates identity-requirement writes.
   */
  async findActiveByServiceId(operatorId: string, serviceId: string) {
    return this.ctx.serviceRepo.findActiveConnectionByOperatorAndServiceId(operatorId, serviceId);
  }

  async proxyChangeWeakens(
    connectionId: string,
    operatorId: string,
    enabled: boolean,
    allowedConnections?: string[],
  ): Promise<boolean> {
    return proxyChangeWeakens(this.ctx, connectionId, operatorId, enabled, allowedConnections);
  }

  async setProxyEnabled(
    connectionId: string,
    operatorId: string,
    enabled: boolean,
    allowedConnections?: string[],
    weakeningApproved = false,
  ) {
    return setProxyEnabled(
      this.ctx,
      connectionId,
      operatorId,
      enabled,
      allowedConnections,
      weakeningApproved,
    );
  }

  /**
   * Check an agent setup's grants and host lists against the customer's own connections before a person is asked
   * to approve it. Writes nothing; returns the connections the setup names.
   */
  async checkSetup(
    operatorId: string,
    setup: Parameters<typeof checkSetup>[2],
    allowedConnections?: string[],
  ): Promise<Map<string, SetupConnection>> {
    return checkSetup(this.ctx, operatorId, setup, allowedConnections);
  }

  /** The hosts a connection's credential may be sent to now (none: an empty list). */
  async allowedHostsOf(connectionId: string, operatorId: string, allowedConnections?: string[]): Promise<string[]> {
    return allowedHostsOf(this.ctx, connectionId, operatorId, allowedConnections);
  }

  /**
   * Put a connection's hosts back to `previous` after a setup that widened them failed, only while they are still what
   * the setup wrote. Answers whether it restored.
   */
  async restoreAllowedHosts(
    connectionId: string,
    operatorId: string,
    previous: string[],
    wrote: string[],
    allowedConnections?: string[],
  ): Promise<boolean> {
    return restoreAllowedHosts(this.ctx, connectionId, operatorId, previous, wrote, allowedConnections);
  }

  /** Whether declaring these hosts would widen where the credential may be sent. */
  async allowedHostsChangeWidens(
    connectionId: string,
    operatorId: string,
    hosts: string[],
    allowedConnections?: string[],
  ): Promise<boolean> {
    return allowedHostsChangeWidens(this.ctx, connectionId, operatorId, hosts, allowedConnections);
  }

  /**
   * Declare the hosts this connection's credential may be sent to. Until it is
   * set, the proxy refuses every destination for that connection.
   */
  async setAllowedHosts(
    connectionId: string,
    operatorId: string,
    hosts: string[],
    allowedConnections?: string[],
    expansionApproved = false,
  ) {
    return setAllowedHosts(
      this.ctx,
      connectionId,
      operatorId,
      hosts,
      allowedConnections,
      expansionApproved,
    );
  }

  async disconnect(connectionId: string, operatorId: string, allowedConnections?: string[]) {
    return disconnectConnection(this.ctx, connectionId, operatorId, allowedConnections);
  }

  /**
   * Whether granting an agent access to a connected service would add
   * authority the agent does not already hold.
   */
  async grantAccessWidens(
    operatorId: string,
    input: GrantAgentAccessInput,
    allowedConnections?: string[],
  ): Promise<boolean> {
    return grantAccessWidens(this.ctx, operatorId, input, allowedConnections);
  }

  /**
   * Grant an agent access to a connected service with specific scopes.
   * Agent scopes must be a subset of the connection's scopes. Optional
   * constraints (raw or via intents) become the grant's baseline ceiling:
   * issued passports can only tighten further.
   */
  async grantAgentAccess(
    operatorId: string,
    input: GrantAgentAccessInput,
    options?: { authorityExpansionApproved?: boolean; allowedConnections?: string[] },
  ) {
    return grantAgentAccess(this.ctx, operatorId, input, options);
  }

  async getGrantsByConnection(
    connectionId: string,
    operatorId: string,
    allowedConnections?: string[],
  ) {
    return getGrantsByConnection(this.ctx, connectionId, operatorId, allowedConnections);
  }

  async revokeAgentAccess(agentId: string, operatorId: string, allowedConnections?: string[]) {
    return revokeAgentAccess(this.ctx, agentId, operatorId, allowedConnections);
  }

  async configureService(
    operatorId: string,
    serviceId: string,
    provider: string,
    mode: 'shared' | 'per_member',
  ) {
    return configureService(this.ctx, operatorId, serviceId, provider, mode);
  }

  async getServiceConfigurations(operatorId: string, allowedConnections?: string[]) {
    return getServiceConfigurations(this.ctx, operatorId, allowedConnections);
  }

  async disableService(operatorId: string, provider: string) {
    return disableService(this.ctx, operatorId, provider);
  }

  async getAgentPermissions(agentId: string, operatorId: string, allowedConnections?: string[]) {
    return getAgentPermissions(this.ctx, agentId, operatorId, allowedConnections);
  }
}
