import { eq, and, or, isNull, isNotNull, asc, desc, inArray, sql } from 'drizzle-orm';
import { createHash } from 'node:crypto';
import {
  type Database,
  services,
  serviceConnections,
  securityEvents,
  serviceConfigurations,
  agentServiceGrants,
  teamMembers,
  defaultHostsForProvider,
  ConflictError,
  acquireOAuthOperatorLock,
  reconnectMessage,
  type ReconnectReason,
} from '@stack/shared';

const CONNECTION_NAME_TAKEN_MESSAGE =
  'An active connection of this service already has that name: pass a different connection_name';

export type ServiceRepositoryTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export class ServiceRepository {
  constructor(private db: Database) {}

  /**
   * The reason, when it is more than a renewal that failed, changes what the
   * person is told: the app STACK used to connect this service is gone, so the
   * way back is a key or token, or their own OAuth app.
   */
  async recordReconnectRequired(
    connection: typeof serviceConnections.$inferSelect,
    tx: ServiceRepositoryTransaction,
    reason?: ReconnectReason,
  ) {
    const id = `sec_${createHash('sha256').update(JSON.stringify([
      connection.operator_id, connection.id, connection.credential_version, 'credential_reconnect_required',
    ])).digest('hex')}`;
    const [event] = await tx.insert(securityEvents).values({
      id, operator_id: connection.operator_id, agent_id: 'connection', signal_type: 'credential_reconnect_required',
      severity: 'warning',
      message: reconnectMessage(reason),
      metadata: {
        connection_id: connection.id, provider: connection.provider, credential_version: connection.credential_version,
        status: 'reconnect_required', action: 'reconnect', action_path: '/services',
        ...(reason ? { reason } : {}),
      },
    }).onConflictDoNothing({ target: securityEvents.id }).returning();
    return event?.id ?? id;
  }

  /** Serialize grant replacement and online passport freshness per operator. */
  async withOperatorGrantLock<T>(
    operatorId: string,
    work: (tx: ServiceRepositoryTransaction) => Promise<T>,
  ): Promise<T> {
    return this.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, operatorId);
      return work(tx);
    });
  }

  // ── Service catalog ────────────────────────────────────────────────

  async listCatalogServices() {
    return this.db.query.services.findMany({
      where: and(
        isNull(services.operator_id),
        eq(services.available, true),
      ),
    });
  }

  async findCatalogServiceById(id: string) {
    return this.db.query.services.findFirst({
      where: and(
        eq(services.id, id),
        isNull(services.operator_id),
      ),
    });
  }

  async findCatalogServiceByProvider(provider: string) {
    return this.db.query.services.findFirst({
      where: and(
        eq(services.provider, provider),
        isNull(services.operator_id),
      ),
    });
  }

  /**
   * Resolve a service definition that an operator may use. Catalog rows are
   * shared read-only definitions; custom rows are visible only to their owner.
   */
  async findAccessibleServiceById(id: string, operatorId: string, transaction?: ServiceRepositoryTransaction) {
    return (transaction ?? this.db).query.services.findFirst({
      where: and(
        eq(services.id, id),
        or(
          isNull(services.operator_id),
          eq(services.operator_id, operatorId),
        ),
      ),
    });
  }

  async findOwnedCustomServiceByProvider(operatorId: string, provider: string) {
    return this.db.query.services.findFirst({
      where: and(
        eq(services.operator_id, operatorId),
        eq(services.provider, provider),
      ),
    });
  }

  async upsertCatalogService(data: Omit<typeof services.$inferInsert, 'operator_id'>) {
    const [row] = await this.db
      .insert(services)
      .values({ ...data, operator_id: null })
      .onConflictDoUpdate({
        target: services.provider,
        targetWhere: isNull(services.operator_id),
        set: {
          name: data.name,
          description: data.description,
          oauth_auth_url: data.oauth_auth_url,
          oauth_token_url: data.oauth_token_url,
          scopes_available: data.scopes_available,
          available: data.available,
        },
      })
      .returning();
    return row!;
  }

  async upsertCustomService(
    operatorId: string,
    data: Omit<typeof services.$inferInsert, 'operator_id' | 'available'>,
  ) {
    if (!data.provider.startsWith('custom_')) {
      throw new Error('Custom service providers must use the custom_ prefix');
    }
    const [row] = await this.db
      .insert(services)
      .values({ ...data, operator_id: operatorId, available: false })
      .onConflictDoUpdate({
        target: [services.operator_id, services.provider],
        targetWhere: isNotNull(services.operator_id),
        set: {
          name: data.name,
          description: data.description,
          oauth_auth_url: data.oauth_auth_url,
          oauth_token_url: data.oauth_token_url,
          scopes_available: data.scopes_available,
          available: false,
        },
      })
      .returning();
    return row!;
  }

  // ── Service connections ────────────────────────────────────────────

  /**
   * Insert a connection.
   *
   * `allowed_hosts` is seeded HERE rather than at each connect path, so a
   * future connect path cannot ship without the credential-to-destination
   * binding by forgetting a field. An explicit value from the caller always
   * wins; otherwise we fall back to the grounded catalog default, and to NULL
   * when we have none. NULL is not a wildcard — the proxy denies until the
   * operator declares the hosts.
   */
  async createConnection(data: typeof serviceConnections.$inferInsert) {
    const catalogDefault = defaultHostsForProvider(data.provider);
    const seeded =
      data.allowed_hosts !== undefined
        ? data
        : { ...data, allowed_hosts: catalogDefault ? [...catalogDefault] : null };
    try {
      const [row] = await this.db.insert(serviceConnections).values(seeded).returning();
      return row!;
    } catch (error) {
      if (postgresUniqueConstraint(error) === 'scon_active_principal_name_idx') {
        throw new ConflictError(CONNECTION_NAME_TAKEN_MESSAGE);
      }
      throw error;
    }
  }

  /** Renames an active connection of the operator. Undefined when there is none; refuses a name another active connection of the same principal holds. */
  async renameConnection(id: string, operatorId: string, name: string) {
    try {
      const [row] = await this.db
        .update(serviceConnections)
        .set({ name })
        .where(and(
          eq(serviceConnections.id, id),
          eq(serviceConnections.operator_id, operatorId),
          eq(serviceConnections.status, 'active'),
        ))
        .returning();
      return row;
    } catch (error) {
      if (postgresUniqueConstraint(error) === 'scon_active_principal_name_idx') {
        throw new ConflictError(CONNECTION_NAME_TAKEN_MESSAGE);
      }
      throw error;
    }
  }

  async findConnectionById(id: string, transaction?: ServiceRepositoryTransaction) {
    return (transaction ?? this.db).query.serviceConnections.findFirst({
      where: eq(serviceConnections.id, id),
    });
  }

  // Single-query JOIN of an agent's active grants with their full connection
  // rows. Replaces an N+1 (findGrantsByAgent + per-grant findConnectionById
  // under Promise.all) that fanned out 1+N concurrent connection queries per
  // request and exhausted the pool (Sentry STACK-API-E: query_wait_timeout,
  // 2026-06). Used by passport issue/refresh + getAgentPermissions. `connection`
  // is nullable (leftJoin) — callers must keep the existing null/status guard.
  async findGrantsWithConnectionByAgent(agentId: string, transaction?: Parameters<Parameters<Database['transaction']>[0]>[0]) {
    return (transaction ?? this.db)
      .select({ grant: agentServiceGrants, connection: serviceConnections })
      .from(agentServiceGrants)
      .leftJoin(
        serviceConnections,
        eq(serviceConnections.id, agentServiceGrants.service_connection_id),
      )
      .where(
        and(eq(agentServiceGrants.agent_id, agentId), isNull(agentServiceGrants.revoked_at)),
      );
  }

  async findConnectionsByOperator(operatorId: string) {
    return this.db.query.serviceConnections.findMany({
      where: and(
        eq(serviceConnections.operator_id, operatorId),
        eq(serviceConnections.status, 'active'),
      ),
      orderBy: [asc(serviceConnections.provider), asc(serviceConnections.member_id), asc(serviceConnections.id)],
    });
  }

  async revokeConnection(id: string) {
    const [row] = await this.db
      .update(serviceConnections)
      .set({ status: 'revoked' })
      .where(eq(serviceConnections.id, id))
      .returning();
    return row;
  }

  async findActiveConnectionByOperatorAndProvider(operatorId: string, provider: string) {
    return this.db.query.serviceConnections.findFirst({
      where: and(
        eq(serviceConnections.operator_id, operatorId),
        eq(serviceConnections.provider, provider),
        isNull(serviceConnections.member_id),
        eq(serviceConnections.status, 'active'),
      ),
      orderBy: [desc(serviceConnections.connected_at), asc(serviceConnections.id)],
    });
  }

  /** Cross-process rotation lock. Reread only after the lock, so waiters use
   * the committed successor and never present the consumed refresh token. */
  async withCredentialLock<T>(
    id: string,
    operatorId: string,
    work: (connection: typeof serviceConnections.$inferSelect | undefined, tx: ServiceRepositoryTransaction) => Promise<T>,
  ): Promise<T> {
    const deadline = Date.now() + 30_000;
    for (;;) {
      try {
        return await this.db.transaction(async (tx) => {
          const [connection] = await tx.select().from(serviceConnections).where(and(
            eq(serviceConnections.id, id), eq(serviceConnections.operator_id, operatorId),
          )).for('update', { noWait: true });
          return work(connection, tx);
        });
      } catch (error) {
        let cause: unknown = error;
        let locked = false;
        for (let depth = 0; depth < 5 && cause && typeof cause === 'object'; depth++) {
          if ((cause as { code?: string }).code === '55P03') { locked = true; break; }
          cause = (cause as { cause?: unknown }).cause;
        }
        if (!locked) throw error;
        if (Date.now() >= deadline) throw new ConflictError('Credential refresh is pending; retry policy evaluation');
        // Release the pool connection while waiting. The lock holder may need
        // a cold CMEK metadata lookup through the same pool before committing.
        await new Promise(resolve => setTimeout(resolve, 50 + Math.floor(Math.random() * 100)));
      }
    }
  }

  /**
   * Every active connection of the provider a caller may be offered, in one query, for the resolver to choose among.
   * `shared` is the account's shared rows; `member` is the member's own rows and the shared ones. `connectionIds`
   * narrows to those ids (an empty list is none). Newest first, so a listing is stable.
   */
  async findEligibleProxyConnections(
    operatorId: string,
    provider: string,
    principal: 'shared' | { memberId: string },
    connectionIds?: readonly string[],
    transaction?: ServiceRepositoryTransaction,
  ) {
    if (connectionIds?.length === 0) return [];
    const principalWhere = principal === 'shared'
      ? isNull(serviceConnections.member_id)
      : or(eq(serviceConnections.member_id, principal.memberId), isNull(serviceConnections.member_id));
    return (transaction ?? this.db).query.serviceConnections.findMany({
      where: and(
        eq(serviceConnections.operator_id, operatorId),
        eq(serviceConnections.provider, provider),
        eq(serviceConnections.status, 'active'),
        principalWhere,
        connectionIds ? inArray(serviceConnections.id, [...connectionIds]) : undefined,
      ),
      orderBy: [desc(serviceConnections.connected_at), asc(serviceConnections.id)],
    });
  }

  async findMemberById(id: string) {
    return this.db.query.teamMembers.findFirst({
      where: eq(teamMembers.id, id),
    });
  }

  /** The active connections of one principal (the shared rows when `memberId` is null) of a provider: their names are what a new one must not repeat. */
  async findActiveConnectionsForPrincipal(
    operatorId: string,
    provider: string,
    memberId: string | null,
  ) {
    return this.db.query.serviceConnections.findMany({
      where: and(
        eq(serviceConnections.operator_id, operatorId),
        eq(serviceConnections.provider, provider),
        memberId === null
          ? isNull(serviceConnections.member_id)
          : eq(serviceConnections.member_id, memberId),
        eq(serviceConnections.status, 'active'),
      ),
      orderBy: [desc(serviceConnections.connected_at), asc(serviceConnections.id)],
    });
  }

  async findActiveConnectionsByOperatorAndProvider(operatorId: string, provider: string) {
    return this.db.query.serviceConnections.findMany({
      where: and(
        eq(serviceConnections.operator_id, operatorId),
        eq(serviceConnections.provider, provider),
        eq(serviceConnections.status, 'active'),
      ),
      orderBy: [asc(serviceConnections.member_id), asc(serviceConnections.id)],
    });
  }

  /**
   * Does this operator hold an active connection to this catalog
   * service_id? Used to gate identity-requirement writes: an
   * operator may only set requirements on a service it has actually
   * connected — not on any global-catalog id it can enumerate.
   */
  async findActiveConnectionByOperatorAndServiceId(operatorId: string, serviceId: string) {
    return this.db.query.serviceConnections.findFirst({
      where: and(
        eq(serviceConnections.operator_id, operatorId),
        eq(serviceConnections.service_id, serviceId),
        eq(serviceConnections.status, 'active'),
      ),
    });
  }

  async updateConnection(
    id: string,
    data: Partial<Omit<typeof serviceConnections.$inferInsert,
      'credential_encrypted' | 'credential_ref' | 'credential_version'>>,
    transaction?: ServiceRepositoryTransaction,
  ) {
    const [row] = await (transaction ?? this.db)
      .update(serviceConnections)
      .set(data)
      .where(eq(serviceConnections.id, id))
      .returning();
    return row;
  }

  /** Replace semantic credential material and advance its version atomically. */
  async replaceCredential(
    id: string,
    operatorId: string,
    expectedVersion: number,
    data: {
      credential_encrypted: string;
      credential_ref: string;
      expires_at?: Date | null;
      scopes?: string[];
    },
    transaction?: ServiceRepositoryTransaction,
  ) {
    const [row] = await (transaction ?? this.db)
      .update(serviceConnections)
      .set({
        ...data,
        credential_version: sql`${serviceConnections.credential_version} + 1`,
      })
      .where(and(
        eq(serviceConnections.id, id),
        eq(serviceConnections.operator_id, operatorId),
        eq(serviceConnections.credential_version, expectedVersion),
      ))
      .returning();
    return row;
  }

  async updateConnectionVerification(id: string, status: string) {
    const [row] = await this.db
      .update(serviceConnections)
      .set({ verification_status: status, verified_at: new Date() })
      .where(eq(serviceConnections.id, id))
      .returning();
    return row;
  }

  async countConnectionsByOperator(operatorId: string): Promise<number> {
    const rows = await this.db.query.serviceConnections.findMany({
      where: and(
        eq(serviceConnections.operator_id, operatorId),
        eq(serviceConnections.status, 'active'),
      ),
      columns: { id: true },
    });
    return rows.length;
  }

  // ── Service configurations ──────────────────────────────────────────

  async upsertConfiguration(data: typeof serviceConfigurations.$inferInsert) {
    const [row] = await this.db
      .insert(serviceConfigurations)
      .values(data)
      .onConflictDoUpdate({
        target: [serviceConfigurations.operator_id, serviceConfigurations.provider],
        set: {
          mode: data.mode,
          service_id: data.service_id,
          updated_at: new Date(),
        },
      })
      .returning();
    return row!;
  }

  async findConfigurationsByOperator(operatorId: string) {
    return this.db.query.serviceConfigurations.findMany({
      where: eq(serviceConfigurations.operator_id, operatorId),
    });
  }

  async findConfigurationByOperatorAndProvider(operatorId: string, provider: string) {
    return this.db.query.serviceConfigurations.findFirst({
      where: and(
        eq(serviceConfigurations.operator_id, operatorId),
        eq(serviceConfigurations.provider, provider),
      ),
    });
  }

  async deleteConfiguration(operatorId: string, provider: string) {
    const deleted = await this.db
      .delete(serviceConfigurations)
      .where(
        and(
          eq(serviceConfigurations.operator_id, operatorId),
          eq(serviceConfigurations.provider, provider),
        ),
      )
      .returning();
    return deleted[0] ?? null;
  }

  // ── Agent grants ───────────────────────────────────────────────────

  async createGrant(data: typeof agentServiceGrants.$inferInsert, transaction?: ServiceRepositoryTransaction) {
    const [row] = await (transaction ?? this.db).insert(agentServiceGrants).values(data).returning();
    return row!;
  }

  async findGrantsByAgent(agentId: string) {
    return this.db.query.agentServiceGrants.findMany({
      where: and(eq(agentServiceGrants.agent_id, agentId), isNull(agentServiceGrants.revoked_at)),
    });
  }

  async findGrantByAgentAndConnection(
    agentId: string,
    connectionId: string,
    transaction?: ServiceRepositoryTransaction,
  ) {
    return (transaction ?? this.db).query.agentServiceGrants.findFirst({
      where: and(
        eq(agentServiceGrants.agent_id, agentId),
        eq(agentServiceGrants.service_connection_id, connectionId),
        isNull(agentServiceGrants.revoked_at),
      ),
    });
  }

  async revokeGrant(id: string) {
    const [row] = await this.db
      .update(agentServiceGrants)
      .set({ revoked_at: new Date() })
      .where(eq(agentServiceGrants.id, id))
      .returning();
    return row;
  }

  /** Find all active grants for a given service connection (to know which agents are affected). */
  async findGrantsByConnection(connectionId: string) {
    return this.db.query.agentServiceGrants.findMany({
      where: and(
        eq(agentServiceGrants.service_connection_id, connectionId),
        isNull(agentServiceGrants.revoked_at),
      ),
    });
  }

  async revokeAllGrantsForAgent(agentId: string, transaction?: ServiceRepositoryTransaction) {
    await (transaction ?? this.db)
      .update(agentServiceGrants)
      .set({ revoked_at: new Date() })
      .where(and(eq(agentServiceGrants.agent_id, agentId), isNull(agentServiceGrants.revoked_at)));
  }

  async deleteGrant(id: string, transaction?: ServiceRepositoryTransaction) {
    await (transaction ?? this.db).delete(agentServiceGrants).where(eq(agentServiceGrants.id, id));
  }

  async deleteRevokedGrantsForAgentConnection(
    agentId: string,
    connectionId: string,
    transaction?: ServiceRepositoryTransaction,
  ) {
    await (transaction ?? this.db).delete(agentServiceGrants).where(
      and(
        eq(agentServiceGrants.agent_id, agentId),
        eq(agentServiceGrants.service_connection_id, connectionId),
        isNotNull(agentServiceGrants.revoked_at),
      ),
    );
  }
}

function postgresUniqueConstraint(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  if (
    'code' in error
    && error.code === '23505'
    && 'constraint_name' in error
    && typeof error.constraint_name === 'string'
  ) {
    return error.constraint_name;
  }
  if ('cause' in error) return postgresUniqueConstraint(error.cause);
  return undefined;
}
