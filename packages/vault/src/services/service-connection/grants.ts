import {
  ids,
  type GrantAgentAccessInput,
  type Constraint,
  NotFoundError,
  ForbiddenError,
  ScopeEscalationError,
  invalidChildScopes,
  expandGrantRules,
  grantIntentRefs,
  allowDataFromGrantWidens,
  constraintsAreSubset,
} from '@stack/shared';
import { assertConnectionAccess, type ServiceConnectionContext } from './context.js';
import { getConnectionScoped } from './queries.js';

type ExistingGrantAuthority =
  | {
      scopes: string[];
      constraints: Constraint[] | null;
      allow_data_from: string[] | null;
    }
  | undefined;

export function grantAuthorityWidens(
  existing: ExistingGrantAuthority,
  requested: {
    scopes: string[];
    constraints: Constraint[];
    allow_data_from: string[];
  },
): boolean {
  if (!existing) return true;
  if (invalidChildScopes(requested.scopes, existing.scopes).length > 0) return true;
  if (!constraintsAreSubset(requested.constraints, existing.constraints ?? [])) return true;
  return allowDataFromGrantWidens(requested.allow_data_from, existing.allow_data_from ?? []);
}

/**
 * The checks that refuse a grant request whatever a person decides: its scopes must lie within the connection's, and its
 * constraints (the grant's own and its intents' expansion) are bounded. They need nobody's judgment, so they run before an
 * approval is asked for (`grantAccessWidens`, which the route calls first) and again, unchanged, when the grant is made
 * (`grantAgentAccess`, which an approved retry reaches): nobody is asked to approve a request that cannot be granted.
 * Returns the merged constraints.
 */
function assertGrantRequestAllowed(connectionScopes: string[], input: GrantAgentAccessInput): Constraint[] {
  // '*' in the connection scopes permits any child scope; the error
  // surfaces exactly which scopes were rejected and the parent set.
  const invalidScopes = invalidChildScopes(input.scopes, connectionScopes);
  if (invalidScopes.length > 0) {
    throw new ScopeEscalationError({
      requested_invalid: invalidScopes,
      parent_scopes: connectionScopes,
    });
  }

  // Resolve parameter-level constraints: the grant's own intents and raw
  // constraints (all of them must hold), then, when the grant names several
  // rules, one `any_of` of them (a call must fit at least one).
  const mergedConstraints = expandGrantRules(input);
  if (mergedConstraints.length > 32) {
    throw new ForbiddenError(
      `Too many constraints: ${mergedConstraints.length} (max 32 per grant). Reduce intents + constraints combined.`,
    );
  }
  return mergedConstraints;
}

/**
 * Whether granting an agent access would add authority the agent does not
 * already hold. Agent scopes must be a subset of the connection's scopes.
 *
 * Optional parameter-level constraints (raw or via intents) become the
 * grant's baseline ceiling: issued passports can only tighten further.
 *
 * Everything that refuses the request without a person is checked here, so the route asks for an approval only for a
 * request that can be granted (`assertGrantRequestAllowed`).
 */
export async function grantAccessWidens(
  ctx: ServiceConnectionContext,
  operatorId: string,
  input: GrantAgentAccessInput,
  allowedConnections?: string[],
): Promise<boolean> {
  await ctx.hooks.externalAgentGuard(operatorId, input.agent_id);
  assertConnectionAccess(allowedConnections, input.service_connection_id);
  const agent = await ctx.agentRepo.findById(input.agent_id);
  if (!agent) throw new NotFoundError('Agent', input.agent_id);
  if (agent.operator_id !== operatorId) throw new ForbiddenError();

  const conn = await ctx.serviceRepo.findConnectionById(input.service_connection_id);
  if (!conn) throw new NotFoundError('ServiceConnection', input.service_connection_id);
  if (conn.operator_id !== operatorId) throw new ForbiddenError();

  const existing = await ctx.serviceRepo.findGrantByAgentAndConnection(
    input.agent_id,
    input.service_connection_id,
  );
  const mergedConstraints = assertGrantRequestAllowed(conn.scopes, input);
  return grantAuthorityWidens(existing, {
    scopes: input.scopes,
    constraints: mergedConstraints,
    allow_data_from: input.allow_data_from ?? [],
  });
}

export async function grantAgentAccess(
  ctx: ServiceConnectionContext,
  operatorId: string,
  input: GrantAgentAccessInput,
  options?: { authorityExpansionApproved?: boolean; allowedConnections?: string[] },
) {
  await ctx.hooks.externalAgentGuard(operatorId, input.agent_id);
  assertConnectionAccess(options?.allowedConnections, input.service_connection_id);
  return ctx.serviceRepo.withOperatorGrantLock(operatorId, async (tx) => {
    const agent = await ctx.agentRepo.findById(input.agent_id, tx);
    if (!agent) throw new NotFoundError('Agent', input.agent_id);
    if (agent.operator_id !== operatorId) throw new ForbiddenError();

    const conn = await ctx.serviceRepo.findConnectionById(input.service_connection_id, tx);
    if (!conn) throw new NotFoundError('ServiceConnection', input.service_connection_id);
    if (conn.operator_id !== operatorId) throw new ForbiddenError();

    // The scopes within the connection's, and the constraints bounded: the checks the route already ran before it asked
    // for an approval, run again here on the request that is actually being granted.
    const mergedConstraints = assertGrantRequestAllowed(conn.scopes, input);

    // Check for existing grant (active or revoked); delete old before creating new
    const existing = await ctx.serviceRepo.findGrantByAgentAndConnection(
      input.agent_id,
      input.service_connection_id,
      tx,
    );
    if (
      grantAuthorityWidens(existing, {
        scopes: input.scopes,
        constraints: mergedConstraints,
        allow_data_from: input.allow_data_from ?? [],
      }) &&
      options?.authorityExpansionApproved !== true
    ) {
      throw new ForbiddenError('Expanding a service grant requires human approval');
    }
    if (existing) {
      await ctx.serviceRepo.deleteGrant(existing.id, tx);
    }
    // Also clean up any revoked grants for this pair (unique index includes revoked rows)
    await ctx.serviceRepo.deleteRevokedGrantsForAgentConnection(
      input.agent_id,
      input.service_connection_id,
      tx,
    );

    return ctx.serviceRepo.createGrant(
      {
        id: ids.serviceConnection(), // reuse ID generator
        agent_id: input.agent_id,
        service_connection_id: input.service_connection_id,
        scopes: input.scopes,
        constraints: mergedConstraints.length > 0 ? mergedConstraints : null,
        // Standing data-flow authority. Empty/absent means no cross-service
        // movement; '*' is resolved to exact active providers at Passport issue.
        allow_data_from:
          input.allow_data_from && input.allow_data_from.length > 0 ? input.allow_data_from : null,
        // The named intents, verbatim. `constraints` above holds their
        // expansion and is what enforcement reads; this is the readable
        // record of the same decision, for the console's agent page.
        intent_refs: (() => {
          const refs = grantIntentRefs(input);
          return refs.length > 0 ? refs.map((r) => ({ name: r.name, params: r.params ?? {} })) : null;
        })(),
      },
      tx,
    );
  });
}

export async function getGrantsByConnection(
  ctx: ServiceConnectionContext,
  connectionId: string,
  operatorId: string,
  allowedConnections?: string[],
) {
  await getConnectionScoped(ctx, connectionId, operatorId, allowedConnections);
  return ctx.serviceRepo.findGrantsByConnection(connectionId);
}

export async function revokeAgentAccess(
  ctx: ServiceConnectionContext,
  agentId: string,
  operatorId: string,
  allowedConnections?: string[],
) {
  await ctx.hooks.externalAgentGuard(operatorId, agentId);
  assertConnectionAccess(allowedConnections);
  const agent = await ctx.agentRepo.findById(agentId);
  if (!agent) throw new NotFoundError('Agent', agentId);
  if (agent.operator_id !== operatorId) throw new ForbiddenError();

  await ctx.serviceRepo.withOperatorGrantLock(operatorId, async (tx) => {
    await ctx.serviceRepo.revokeAllGrantsForAgent(agentId, tx);
  });
}

export async function getAgentPermissions(
  ctx: ServiceConnectionContext,
  agentId: string,
  operatorId: string,
  allowedConnections?: string[],
) {
  const agent = await ctx.agentRepo.findById(agentId);
  if (!agent) throw new NotFoundError('Agent', agentId);
  if (agent.operator_id !== operatorId) throw new ForbiddenError();

  // Single JOIN query, NOT an N+1 fan-out. See repo method note.
  const allowed = allowedConnections === undefined ? null : new Set(allowedConnections);
  const rows = (await ctx.serviceRepo.findGrantsWithConnectionByAgent(agentId)).filter(
    ({ grant }) => allowed === null || allowed.has(grant.service_connection_id),
  );
  return rows.map(({ grant, connection }) => ({
    grant_id: grant.id,
    service_connection_id: grant.service_connection_id,
    provider: connection?.provider ?? undefined,
    connection_name: connection?.name ?? undefined,
    scopes: grant.scopes,
    // The full ceiling, not a summary: a passport may only narrow these,
    // so a reader of this response knows exactly what any passport this
    // agent holds can have been allowed to do.
    constraints: grant.constraints ?? [],
    allow_data_from: grant.allow_data_from ?? [],
    // The named intents the grant was made with. Grants made before intents
    // were recorded return [] and render as constraint sentences only.
    intent_refs: grant.intent_refs ?? [],
    granted_at: grant.granted_at,
  }));
}
