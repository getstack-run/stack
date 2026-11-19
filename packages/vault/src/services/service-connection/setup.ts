import {
  ForbiddenError,
  NotFoundError,
  ScopeEscalationError,
  expandGrantRules,
  invalidChildScopes,
  normalizeAllowedHosts,
  type AgentSetupGrant,
  type AgentSetupHosts,
} from '@stack/shared';
import type { ServiceConnectionContext } from './context.js';
import { connectionNameWhenSeveral, getConnectionScoped } from './queries.js';

/** The connection a setup names, as far as the approval card needs to show it. */
export interface SetupConnection {
  id: string;
  /** The service the connection reaches (its provider key). */
  provider: string;
  /** The connection's own name, as the owner gave it; set only while the account holds two or more active connections of this service. */
  name?: string;
}

/**
 * Check a setup's grants and host lists against the customer's own connections BEFORE anyone is asked to approve
 * it, with the same rules the individual grant and host calls apply, so a person is never asked to decide a
 * request that was always going to fail and an approval is never spent on one. Throws the same errors those calls
 * throw. Returns the connections it names, for the card.
 *
 * Nothing is written. Widening is not judged here: a setup is a first grant by an agent that does not exist yet,
 * so every grant in it is new authority and the person approves all of it as one.
 */
export async function checkSetup(
  ctx: ServiceConnectionContext,
  operatorId: string,
  setup: { grants: readonly AgentSetupGrant[]; allowed_hosts: readonly AgentSetupHosts[] },
  allowedConnections?: string[],
): Promise<Map<string, SetupConnection>> {
  const named = new Map<string, SetupConnection>();
  // One count per service for this call; the name is shown only where the account holds several connections of it.
  const shown = new Map<string, Promise<string | null>>();
  const nameOf = async (conn: { id: string; operator_id: string; provider: string; name: string }): Promise<SetupConnection> => {
    let name = shown.get(conn.provider);
    if (!name) {
      name = connectionNameWhenSeveral(ctx, conn);
      shown.set(conn.provider, name);
    }
    const several = await name;
    return { id: conn.id, provider: conn.provider, ...(several === null ? {} : { name: conn.name }) };
  };
  const connection = async (connectionId: string) => {
    if (named.has(connectionId)) return;
    const conn = await getConnectionScoped(ctx, connectionId, operatorId, allowedConnections);
    if (!conn) throw new NotFoundError('ServiceConnection', connectionId);
    named.set(conn.id, await nameOf(conn));
  };

  for (const grant of setup.grants) {
    const conn = await getConnectionScoped(ctx, grant.service_connection_id, operatorId, allowedConnections);
    if (!conn) throw new NotFoundError('ServiceConnection', grant.service_connection_id);
    named.set(conn.id, await nameOf(conn));
    const invalidScopes = invalidChildScopes(grant.scopes, conn.scopes);
    if (invalidScopes.length > 0) {
      throw new ScopeEscalationError({ requested_invalid: invalidScopes, parent_scopes: conn.scopes });
    }
    const merged = expandGrantRules(grant);
    if (merged.length > 32) {
      throw new ForbiddenError(
        `Too many constraints: ${merged.length} (max 32 per grant). Reduce intents + constraints combined.`,
      );
    }
  }

  for (const entry of setup.allowed_hosts) {
    await connection(entry.service_connection_id);
    try {
      normalizeAllowedHosts(entry.allowed_hosts);
    } catch (err) {
      throw new ForbiddenError(err instanceof Error ? err.message : 'Invalid allowed_hosts');
    }
  }
  return named;
}
