import type { FastifyInstance, FastifyRequest } from 'fastify';
import { denyAgentContexts } from '../middleware/require-platform.js';
import { ConnectServiceInput, ConnectCustomServiceInput, ConnectionName, ForbiddenError, GrantAgentAccessInput, CREDENTIAL_TEMPLATES, PER_TENANT_HOST_PROVIDERS, oneLine, quotedText, serviceMcpEndpoint, type OperatorTier } from '@stack/shared';
import { z } from 'zod';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { requireRole } from '../middleware/require-role.js';
import { enforceGovernanceStepUp } from '../middleware/governance-stepup.js';
import { grantControlPolicyNotice } from '../lib/control-policy/grant-notice.js';
import { applyGrantListing, grantApproval, grantServiceName, planGrantListing } from '../lib/control-policy/grant-listing.js';

function serializeConnection(connection: unknown): unknown {
  if (typeof connection !== 'object' || connection === null || Array.isArray(connection)) {
    return connection;
  }
  const row = connection as Record<string, unknown>;
  if (!('credential_encrypted' in row) && !('credential_ref' in row)) return connection;
  const {
    credential_encrypted: credentialEncrypted,
    credential_ref: credentialRef,
    ...safe
  } = row;
  // The service's MCP endpoint: the one its connection carries, or the default of a service STACK knows. What
  // stack_service_tools and stack_service_call_tool send their calls to; null for a service that has none.
  const provider = typeof safe['provider'] === 'string' ? safe['provider'] : null;
  const mcpUrl = typeof safe['mcp_url'] === 'string' && safe['mcp_url'] !== '' ? safe['mcp_url'] : (provider ? serviceMcpEndpoint(provider) : null);
  return {
    ...safe,
    mcp_url: mcpUrl,
    credential_present:
      typeof credentialEncrypted === 'string'
      && credentialEncrypted.length > 0
      && typeof credentialRef === 'string'
      && credentialRef.length > 0,
  };
}

// Catalog connect: the credential travels as `oauth_token`, outside the shared
// input schema. `member_id` is accepted only to be checked against the caller.
const ConnectServiceBody = ConnectServiceInput.extend({
  oauth_token: z.string(),
  member_id: z.unknown().optional(),
});

// Custom connect: the shared schema carries a refinement, so `member_id` is
// read with its own small schema from the same body.
const MemberIdBody = z.object({ member_id: z.unknown().optional() });

// The new name goes through the same schema as a name given at connect time; the service re-checks it.
const RenameConnectionBody = z.object({ connection_name: ConnectionName }).strict();

const ProxyToggleBody = z.object({ proxy_enabled: z.boolean() });

const AllowedHostsBody = z.object({ allowed_hosts: z.array(z.string()) });

function connectionMemberId(request: { memberId?: string }, requestedMemberId: unknown): string | undefined {
  if (
    requestedMemberId !== undefined
    && (typeof requestedMemberId !== 'string' || requestedMemberId !== request.memberId)
  ) {
    throw new ForbiddenError('This route cannot connect a service for another member');
  }
  return request.memberId;
}

// Application-credentials connect — for catalog providers like
// microsoft_entra_app where there is no browser OAuth dance, just
// operator-supplied client_id + client_secret + tenant_id + scope.
// Creates a connection bound to the existing catalog service_id.
const ConnectApplicationBody = z.object({
  service_id: z.string().min(1),
  credential: z.record(z.string().min(1), z.string().min(1)).refine(
    (credential) => Object.keys(credential).length > 0,
    { message: 'credential must contain at least one non-empty field' },
  ),
  scopes: z.array(z.string()).optional(),
  // Per-tenant providers only (your Okta org, your Zendesk subdomain).
  // Catalogued providers resolve from PROVIDER_API_HOSTS and need nothing.
  allowed_hosts: z.array(z.string().min(1).max(253)).optional(),
  // The address of the service's MCP endpoint, when it speaks MCP over HTTP: https, on one of its allowed hosts.
  mcp_url: z.string().min(1).max(2048).optional(),
  // What to call this connection; a service's first connection may leave it out.
  connection_name: ConnectionName.optional(),
});

const ConfigureBody = z.object({
  service_id: z.string().min(1),
  provider: z.string().min(1),
  mode: z.enum(['shared', 'per_member']),
});

/**
 * The connection as an approval's summary names it: the name its owner gave it, read now, on one line and in quotes
 * (it is a value a person wrote), only when the account has several connections of that service, else its id.
 * Display only: the id stays what the approval binds and what is acted on, and a connection that cannot be read
 * here is refused by the change itself.
 */
async function connectionLabel(
  services: Pick<Services, 'serviceConnection'>,
  request: Pick<FastifyRequest, 'operatorId' | 'allowedConnections'>,
  connectionId: string,
): Promise<string> {
  try {
    const name = await services.serviceConnection.connectionNameWhenSeveral(connectionId, request.operatorId, request.allowedConnections);
    if (name && oneLine(name)) return quotedText(name);
  } catch {
    // Fall through to the id.
  }
  return connectionId;
}

export function registerServiceRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.get('/v1/services/templates', { preHandler: auth }, async () => {
    // `per_tenant_host_providers` is served rather than duplicated in the
    // dashboard because the dashboard is workspace-excluded and cannot import
    // @stack/shared. One source of truth, no drift. The connect dialog uses it
    // to render a required API-host field for providers whose host is the
    // operator's own instance.
    return {
      templates: CREDENTIAL_TEMPLATES,
      per_tenant_host_providers: [...PER_TENANT_HOST_PROVIDERS],
    };
  });

  app.get('/v1/services', { preHandler: auth }, async () => {
    const catalogue = await services.serviceConnection.listAvailableServices();
    // What STACK's own app will request for the service (null where it has no list): the Connect page shows it
    // beside the scopes the service offers, so a person is told what the consent screen will ask for.
    return catalogue.map((row) => ({
      ...row,
      stack_app_scopes: services.providerOAuth.stackAppScopes(row.provider, row.scopes_available),
    }));
  });

  app.get('/v1/services/connected', { preHandler: auth }, async (request) => {
    const connections = await services.serviceConnection.listConnectedServices(
      request.operatorId,
      request.allowedConnections,
    );
    return connections.map(serializeConnection);
  });

  app.post('/v1/services/connect', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    requireRole(request, 'standard');
    services.serviceConnection.assertConnectionAccess(request.allowedConnections);
    const { oauth_token: oauthToken, member_id: requestedMemberId, ...input } = ConnectServiceBody.parse(request.body);
    const memberId = connectionMemberId(request, requestedMemberId);
    const start = Date.now();

    const connection = await services.serviceConnection.connect(
      request.operatorId,
      request.operatorTier as OperatorTier,
      { ...input, oauth_token: oauthToken },
      request.memberId,
      memberId,
    );

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'service.connect',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    services.analytics.fireOnce(request.operatorId, 'first_service_connected', {
      service_id: input.service_id,
      kind: 'oauth',
    });

    return reply.status(201).send(serializeConnection(connection));
  });

  app.post('/v1/services/custom', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    requireRole(request, 'standard');
    services.serviceConnection.assertConnectionAccess(request.allowedConnections);
    const input = ConnectCustomServiceInput.parse(request.body);
    const memberId = connectionMemberId(request, MemberIdBody.parse(request.body).member_id);
    const start = Date.now();

    const connection = await services.serviceConnection.connectCustom(
      request.operatorId,
      request.operatorTier as OperatorTier,
      input,
      request.memberId,
      memberId,
    );

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'service.connect_custom',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    services.analytics.fireOnce(request.operatorId, 'first_service_connected', {
      name: input.name,
      kind: 'custom',
    });

    return reply.status(201).send(serializeConnection(connection));
  });

  app.post('/v1/services/connect-application', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    requireRole(request, 'standard');
    services.serviceConnection.assertConnectionAccess(request.allowedConnections);
    const input = ConnectApplicationBody.parse(request.body);
    const start = Date.now();

    const connection = await services.serviceConnection.connectApplication(
      request.operatorId,
      request.operatorTier as OperatorTier,
      input,
      request.memberId,
      request.memberId,
    );

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'service.connect_application',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    services.analytics.fireOnce(request.operatorId, 'first_service_connected', {
      service_id: input.service_id,
      kind: 'application',
    });

    return reply.status(201).send(serializeConnection(connection));
  });

  app.post('/v1/services/configure', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    requireRole(request, 'standard');
    services.serviceConnection.assertConnectionAccess(request.allowedConnections);
    const { service_id: serviceId, provider, mode } = ConfigureBody.parse(request.body);

    const config = await services.serviceConnection.configureService(
      request.operatorId,
      serviceId,
      provider,
      mode,
    );

    return reply.status(200).send(config);
  });

  app.get('/v1/services/configurations', { preHandler: auth }, async (request) => {
    return services.serviceConnection.getServiceConfigurations(
      request.operatorId,
      request.allowedConnections,
    );
  });

  app.delete<{ Params: { provider: string } }>(
    '/v1/services/configurations/:provider',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'standard');
      services.serviceConnection.assertConnectionAccess(request.allowedConnections);
      return services.serviceConnection.disableService(request.operatorId, request.params.provider);
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/v1/services/:id/disconnect',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'standard');
      const start = Date.now();

      // Find which agents have grants to this connection BEFORE disconnecting
      const affectedGrants = await services.serviceConnection.getGrantsByConnection(
        request.params.id,
        request.operatorId,
        request.allowedConnections,
      );
      const affectedAgentIds = [...new Set(affectedGrants.map((g) => g.agent_id))];

      const result = await services.serviceConnection.disconnect(
        request.params.id,
        request.operatorId,
        request.allowedConnections,
      );

      // Cascade: revoke active passports for all agents that had grants to this connection
      for (const agentId of affectedAgentIds) {
        await services.passport.revokeAllForAgent(agentId, `Service connection ${request.params.id} disconnected`);
      }

      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'service.disconnect',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return serializeConnection(result);
    },
  );

  app.post('/v1/services/grant', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    requireRole(request, 'standard');
    const input = GrantAgentAccessInput.parse(request.body);
    const start = Date.now();

    const widensAuthority = await services.serviceConnection.grantAccessWidens(
      request.operatorId,
      input,
      request.allowedConnections,
    );
    // The agent's own policy may have to list this connection before it can be called: then the grant and that
    // listing are one approval, which binds the exact policy change and lists it on the card.
    const listing = widensAuthority ? await planGrantListing(services, request.operatorId, input) : null;
    const serviceName = widensAuthority
      ? await grantServiceName(services, request, input)
      : { service: input.service_connection_id, connectionName: null };
    if (widensAuthority) {
      await enforceGovernanceStepUp(services, request, {
        action: 'service_grant_expand',
        resourceId: `${input.agent_id}:${input.service_connection_id}`,
        ...grantApproval(input, serviceName.service, listing, serviceName.connectionName),
      });
    }

    const grant = await services.serviceConnection.grantAgentAccess(
      request.operatorId,
      input,
      {
        authorityExpansionApproved: widensAuthority,
        allowedConnections: request.allowedConnections,
      },
    );

    const listedInPolicy = listing ? await applyGrantListing(services, request, listing, input, start) : null;

    await services.audit.write({
      ctx: auditCtx(request, { agent_id: input.agent_id }),
      layer: 'vault',
      action: 'service.grant',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    // A connection the policy of the agent does not list yet is not callable: say what it still needs.
    const controlPolicy = await grantControlPolicyNotice(services, request.operatorId, input.agent_id, input.service_connection_id);
    return reply.status(201).send({
      ...grant,
      ...(listedInPolicy ? { policy_listed: listedInPolicy } : {}),
      ...(controlPolicy ? { control_policy: controlPolicy } : {}),
    });
  });

  app.delete<{ Params: { agentId: string } }>(
    '/v1/services/agents/:agentId/revoke',
    { preHandler: auth },
    async (request) => {
      requireRole(request, 'standard');
      const start = Date.now();
      await services.serviceConnection.revokeAgentAccess(
        request.params.agentId,
        request.operatorId,
        request.allowedConnections,
      );

      // Cascade: revoke active passports — agent lost its service grants
      await services.passport.revokeAllForAgent(
        request.params.agentId,
        'Service grants revoked',
      );

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: request.params.agentId }),
        layer: 'vault',
        action: 'service.revoke',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return { success: true };
    },
  );

  app.get<{ Params: { agentId: string } }>(
    '/v1/agents/:agentId/permissions',
    { preHandler: auth },
    async (request) => {
      return services.serviceConnection.getAgentPermissions(
        request.params.agentId,
        request.operatorId,
        request.allowedConnections,
      );
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/services/:id/verify',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'standard');
      services.serviceConnection.assertConnectionAccess(request.allowedConnections, request.params.id);
      const start = Date.now();

      const result = await services.connectionVerifier.verify(
        request.params.id,
        request.operatorId,
      );

      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'service.verify',
        outcome: result.status === 'healthy' ? 'success' : 'failure',
        duration_ms: Date.now() - start,
      });

      return serializeConnection(result);
    },
  );

  // ─── Rename ────────────────────────────────────────────────────────
  //
  // Changes only the label a call's `connection` can name; it widens nothing, so there is no approval. An agent could
  // otherwise steer which connection a name points at, so agent contexts are refused. The audit row records that a
  // rename happened, not either name.
  app.patch<{ Params: { id: string } }>(
    '/v1/services/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'admin');
      services.serviceConnection.assertConnectionAccess(request.allowedConnections, request.params.id);
      const { connection_name: connectionName } = RenameConnectionBody.parse(request.body);
      const start = Date.now();

      const result = await services.serviceConnection.renameConnection(
        request.operatorId,
        request.params.id,
        connectionName,
      );

      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'service.connection.rename',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return serializeConnection(result);
    },
  );

  // ─── Proxy Toggle ──────────────────────────────────────────────────
  app.post<{ Params: { id: string } }>(
    '/v1/services/:id/proxy-toggle',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'standard');
      const { proxy_enabled } = ProxyToggleBody.parse(request.body);

      const weakens = await services.serviceConnection.proxyChangeWeakens(
        request.params.id,
        request.operatorId,
        proxy_enabled,
        request.allowedConnections,
      );
      if (weakens) {
        await enforceGovernanceStepUp(services, request, {
          action: 'service_proxy_disable',
          resourceId: request.params.id,
          payload: { connection_id: request.params.id, proxy_enabled },
          summary: `Disable proxy enforcement for connection ${await connectionLabel(services, request, request.params.id)}`,
        });
      }

      const result = await services.serviceConnection.setProxyEnabled(
        request.params.id,
        request.operatorId,
        proxy_enabled,
        request.allowedConnections,
        weakens,
      );

      return serializeConnection(result);
    },
  );

  // ─── Credential-to-destination binding ─────────────────────────────
  //
  // Declares which hosts this connection's credential may be sent to. Agent
  // contexts are denied: choosing where a credential may travel is the
  // operator's decision about the watched system, never the watched system's
  // own. Same reasoning as — an agent that could widen this could
  // undo the control by asking.
  app.post<{ Params: { id: string } }>(
    '/v1/services/:id/allowed-hosts',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'standard');
      const start = Date.now();
      const { allowed_hosts } = AllowedHostsBody.parse(request.body);

      const widens = await services.serviceConnection.allowedHostsChangeWidens(
        request.params.id,
        request.operatorId,
        allowed_hosts,
        request.allowedConnections,
      );
      if (widens) {
        await enforceGovernanceStepUp(services, request, {
          action: 'service_allowed_hosts_expand',
          resourceId: request.params.id,
          payload: { connection_id: request.params.id, allowed_hosts },
          // Every host is in the line: this approval may be confirmed in the chat, which shows only this text.
          summary: `Expand credential destinations for connection ${await connectionLabel(services, request, request.params.id)} to: ${allowed_hosts.join(', ')}`,
        });
      }

      const result = await services.serviceConnection.setAllowedHosts(
        request.params.id,
        request.operatorId,
        allowed_hosts,
        request.allowedConnections,
        widens,
      );

      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'service.set_allowed_hosts',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return serializeConnection(result);
    },
  );
}
