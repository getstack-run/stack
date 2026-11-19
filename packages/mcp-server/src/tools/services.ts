import { z } from 'zod';
import { AccessAlternative, ConnectionName, Constraint, IntentRef, MAX_ANY_OF_PER_SCOPE, listIntents } from '@stack/shared';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson, approvalFlow } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const SERVICES_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Services and grants. Connect service starts the same connect link as
  // stack_create_connect_link: the link is made inside the STACK account.
  stack_connect_service: hint.write('Connect service'),
  stack_list_services: hint.read('List service catalog'),
  stack_list_connected_services: hint.read('List connected services'),
  stack_disconnect_service: hint.destructive('Disconnect service'),
  stack_grant_agent_access: hint.destructive('Grant agent service access'),
  stack_list_intents: hint.read('List named intents'),
  stack_revoke_agent_access: hint.destructive('Revoke agent service access'),
  // A link is created and read inside the STACK account; the person opens it
  // in their own browser. It carries no credential.
  stack_create_connect_link: hint.write('Create connect link'),
  stack_get_connect_link: hint.read('Get connect link'),
  stack_set_connection_proxy: hint.destructive('Turn credential proxy on or off for a connection'),
  stack_rename_connection: hint.write('Rename a connection'),
  stack_list_service_configurations: hint.read('List service configurations'),
  stack_save_service_configuration: hint.destructive('Save service configuration'),
  stack_delete_service_configuration: hint.destructive('Delete service configuration'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const SERVICES_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_connect_service: 'Same as stack_create_connect_link, which the directory profile serves. Kept on the standard profile under its old name for existing users.',
  stack_rename_connection: 'Owner administration of a connection. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_set_connection_proxy: 'Turning the proxy off weakens enforcement and needs a person\'s approval. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_list_service_configurations: 'Owner administration of how the team connects a provider. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_save_service_configuration: 'Owner administration of how the team connects a provider. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_delete_service_configuration: 'Owner administration of how the team connects a provider. Kept out of the directory profile, whose reviewed tool set does not change.',
};

/** Service connections, per-agent service grants and the intent catalog. */
export function registerServicesTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // One code path for both connect tools: the person finishes the connection on
  // a STACK page, so no credential ever passes through the conversation.
  const connectLinkShape = {
    service_id: z.string().min(1).max(200).describe('Catalog service id or provider name (e.g. "github", "slack")'),
    scopes: z.array(z.string().min(1).max(512)).max(100).optional().describe('OAuth scopes to ask for when the service connects through the provider sign-in. Omit for the service defaults.'),
  };
  // The name a connection is given, so a service can hold several. It is an addition to the standard shape only: the
  // directory profile keeps the shape it was reviewed with.
  const connectionNameField = ConnectionName.optional().describe('What to call this connection (letters, digits, spaces and hyphens, up to 40 characters). Needed to add a second connection of a service the account already has; the first one is named default. Never a credential.');
  // The body of the one request both tools send, so they cannot drift apart. Each
  // handler keeps its own call line, which the deployment's tool-scope test
  // reads to find the route a tool needs.
  const connectLinkBody = ({ service_id, scopes, connection_name }: { service_id: string; scopes?: string[] | undefined; connection_name?: string | undefined }) =>
    ({ service_id, ...(scopes ? { scopes } : {}), ...(connection_name !== undefined ? { connection_name } : {}) });

  server.tool(
    'stack_connect_service',
    'Connect a catalog service such as Slack, GitHub or Notion to the STACK account. This is the same as stack_create_connect_link and keeps its name for existing users: it returns a one-time link, the person opens it in their browser while signed in to STACK and gives the credential there, and the connection is stored when they finish. The credential never passes through this conversation, so the tool accepts only service_id, scopes and connection_name and refuses any other argument. A service can hold several connections, each with its own name: connection_name names this one. Returns link_id, provider, method (oauth or key), status, connection_name, expires_at and url.',
    { ...connectLinkShape, connection_name: connectionNameField },
    async (args) => toolJson(await api('POST', '/v1/services/connect-links', connectLinkBody(args))),
    {
      refuseUnknownArguments:
        'stack_connect_service takes no credential, token or secret. Never put one in this conversation: call it with only service_id, scopes and connection_name, then give the person the returned connect link to open and connect the service there (stack_create_connect_link does the same).',
    },
  );

  server.tool(
    'stack_list_services',
    'List the catalog of services that can be connected. The catalog does not include the connections the account holds; stack_list_connected_services returns those.',
    {},
    async () => {
      const result = await api('GET', '/v1/services');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_connected_services',
    "List the account's service connections with each connection's id, name, provider, status and stored scopes. A service can hold several connections, each with its own name. An agent grant's scopes must be a subset of the connection's stored scopes; a connection with scopes ['*'] permits any child scope.",
    {},
    async () => {
      const result = await api('GET', '/v1/services/connected');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_disconnect_service',
    'Disconnect a service connection by its id (scon_*). Deletes the stored credential and revokes the active Passports of agents that had grants to this connection. Connection ids come from stack_list_connected_services.',
    {
      connection_id: z.string().describe('The service connection id (scon_*) to disconnect'),
    },
    async ({ connection_id }) => {
      const result = await api(
        'DELETE',
        `/v1/services/${encodeURIComponent(connection_id)}/disconnect`,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_grant_agent_access',
    `Create or replace an agent's grant on a service connection. A new grant, or any expansion of scopes, constraints or data-flow authority, requires human approval. ${approvalFlow} Pure narrowing applies immediately. Active Passports are checked against the current grant on their next STACK verification. With controls on and a policy of the agent's own that lists connections, the same approval also lists the service in that policy and the response carries policy_listed (policy_id, revision). When the policy in force is the account's default, which governs other agents too, it is not edited: the grant is made but the connection is not callable until a revision of that policy lists it, the response carries control_policy (policy_id, policy_revision, revision_needed, message), and a call on the connection is refused with CONTROL_DENIED reason connection_not_listed until a person adds it, a loosening they approve in their browser. The named-intent catalog is returned by stack_list_intents.`,
    {
      agent_id: z.string().describe('Agent ID'),
      service_connection_id: z.string().describe('Service connection ID'),
      scopes: z
        .array(z.string())
        .describe('OAuth-style scope strings (subset of the connection scopes)'),
      constraints: z
        .array(Constraint)
        .max(32)
        .optional()
        .describe(
          'Raw parameter-level constraints. Each is { path, op, value }. path e.g. "body.channel", "url.pathname", "method". op one of eq|not_eq|in|not_in|matches|starts_with|lt|lte|gt|gte|exists|not_exists. A choice of rules can also be given here as { path: "any_of", op: "any_of", value: [[constraint, ...], ...] } (a call must meet every constraint of at least one group); use `alternatives` for that. At most ' + MAX_ANY_OF_PER_SCOPE + ' such choices to a grant. See stack_list_intents for a higher-level alternative.',
        ),
      intents: z
        .array(IntentRef)
        .max(32)
        .optional()
        .describe(
          'Named intents that expand to constraints server-side. Each is { name, params }. E.g. { name: "slack.post_to_channel", params: { channel: ["C0123","C0456"] } }. Combined with `constraints` by concatenation: every one must hold, so use `alternatives` for rules that each allow their own calls.',
        ),
      alternatives: z
        .array(AccessAlternative)
        .min(1)
        .max(16)
        .optional()
        .describe(
          'Several rules on this connection, any one of which allows a call: for example a read rule and a post rule. Each is { intents?, constraints? } and holds in full when it is used. The `intents` and `constraints` above apply to every rule. A call that fits none is refused.',
        ),
      allow_data_from: z
        .array(z.string().min(1).max(128))
        .max(32)
        .optional()
        .describe(
          'Data-flow baseline: the sources whose content may flow INTO this one. Each entry is an exact service name, or one connection of a service written service@<connection id>. Content read through one connection of a service needs such an entry before it may go out through another connection of the same service. Omit or pass [] for no cross-service flow. Pass ["*"] alone to cover every service currently granted to the agent; Passport issuance resolves it to exact names and never signs the wildcard. Adding a source to an existing grant requires human approval.',
        ),
      governance_approval_id: z
        .string()
        .optional()
        .describe('Approval id (gvr_*) from the first call, after a human approved it in the dashboard'),
    },
    async ({ governance_approval_id, ...grant }) => {
      const result = await api(
        'POST',
        '/v1/services/grant',
        grant,
        governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_intents',
    'List the named intents accepted by stack_grant_agent_access and by Passport issuance. Each intent maps a semantic name such as "slack.post_to_channel" to a set of parameter-level constraints. Returns each intent name and description.',
    {},
    async () => {
      const catalog = listIntents().map((i) => ({
        name: i.name,
        description: i.description,
      }));
      return toolJson(catalog);
    },
  );

  server.tool(
    'stack_revoke_agent_access',
    'Revoke every service grant held by an agent.',
    {
      agent_id: z.string().describe('Agent ID to revoke'),
    },
    async ({ agent_id }) => {
      const result = await api('DELETE', `/v1/services/agents/${encodeURIComponent(agent_id)}/revoke`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_create_connect_link',
    'Create a one-time link that connects a service to the STACK account without the credential passing through this conversation. Give service_id for a catalog service, or custom for the account\'s own API that takes a key or token: its name, the hosts the key may be sent to and, when it speaks MCP over HTTP, the address of its MCP endpoint (mcp_url, https and on one of those hosts) so stack_service_tools and stack_service_call_tool work for it. The person opens the link in their browser while signed in to STACK, then either signs in on the provider\'s own page or enters the key on a STACK page, which shows the hosts first, and the owner may correct them there. A custom service connects with a key or token only, not with OAuth; scopes are ignored for it. A service_id that names an existing custom service of the account connects it again, as it was made, to the hosts it already has. Give connect for the key of one of the account\'s own supplier accounts, so it never passes through this conversation: a print-on-demand supplier (gelato, prodigi, printful or lulu), an agent account\'s Telegram bot, or the key of the street address\'s post supplier; only the owner or an admin may. The link is bound to this account and member, works once and expires after 10 minutes; any number can be open at once. A service can hold several connections: connection_name names the one this link makes, and is needed when the account already has a connection of that service. Returns link_id, provider, method (oauth or key), status, connection_name, expires_at and url. The credential is never returned.',
    {
      service_id: connectLinkShape.service_id.optional().describe('Catalog service id or provider name (e.g. "github", "slack"). Omit when custom is given.'),
      scopes: connectLinkShape.scopes,
      connection_name: connectionNameField,
      custom: z.object({
        name: z.string().trim().min(1).max(200).describe('Name of the service'),
        description: z.string().max(2000).optional().describe('What the service is'),
        allowed_hosts: z.array(z.string().min(1).max(253)).min(1).max(100)
          .describe('Hosts the key may be sent to: bare hostnames such as api.example.com, or a dot-led domain such as .example.com. No scheme, port or path. The owner may correct them on the page.'),
        template: z.string().min(1).max(100).optional().describe('Name of a credential template whose fields the page asks for (stack_list_credential_templates). Omitted: one API key field.'),
        mcp_url: z.string().min(1).max(2048).optional().describe('The address of the MCP endpoint of the service, when it speaks MCP over HTTP: https, on one of allowed_hosts. Omit for a service that does not speak MCP.'),
      }).strict().optional().describe('The account\'s own API. Never put a key or token here: the person enters it on the page.'),
      connect: z.discriminatedUnion('kind', [
        z.object({ kind: z.literal('making_supplier'), supplier: z.enum(['gelato', 'prodigi', 'printful', 'lulu']) }).strict(),
        z.object({ kind: z.literal('telegram_bot'), account_id: z.string().min(1).max(100).describe('The agent account (acct_*) whose bot it is') }).strict(),
        z.object({ kind: z.literal('post_address') }).strict(),
      ]).optional().describe('A key of one of the account\'s own supplier accounts, entered by the owner or an admin on the page: a print-on-demand supplier (making_supplier), an agent account\'s Telegram bot token (telegram_bot) or the key of the street address\'s post supplier (post_address). Never put the key here.'),
    },
    async ({ service_id, scopes, connection_name, custom, connect }) => {
      if ([service_id, custom, connect].filter((value) => value !== undefined).length !== 1) throw new Error('Give exactly one of service_id, custom or connect.');
      if (connect !== undefined && connection_name !== undefined) throw new Error('connection_name applies to a service_id or custom link, not to connect.');
      return toolJson(await api(
        'POST',
        '/v1/services/connect-links',
        custom !== undefined ? { custom: { ...custom, ...(connection_name !== undefined ? { connection_name } : {}) } } : connect !== undefined ? { connect } : connectLinkBody({ service_id: service_id!, scopes, connection_name }),
      ));
    },
    {
      forDirectory: {
        description: 'Create a one-time link that connects a catalog service to the STACK account without the credential passing through this conversation. The person opens the link in their browser while signed in to STACK, then either signs in on the provider\'s own page or enters the key on a STACK page. The link is bound to this account and member, works once and expires after 10 minutes; any number can be open at once. Returns link_id, provider, method (oauth or key), status, expires_at and url. The credential is never returned. Custom services connect in the Console.',
        shape: connectLinkShape,
      },
    },
  );

  server.tool(
    'stack_get_connect_link',
    'Read the status of a connect link: pending, connected or expired, with the connection id once connected. Returns link_id, provider, method, status, connection_id, connection_name, expires_at and completed_at. It never returns the link URL or any credential.',
    {
      link_id: z.string().min(1).max(128).describe('Connect link id (cnl_*) from the link creation response'),
    },
    async ({ link_id }) => {
      const result = await api('GET', `/v1/services/connect-links/${encodeURIComponent(link_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_set_connection_proxy',
    `Turn STACK's credential proxy on or off for one service connection (scon_*). On, agents reach the service only through the proxy, which injects the credential and checks every call. Turning it on applies at once. Turning it off weakens enforcement and needs a person's approval. ${approvalFlow}`,
    {
      connection_id: z.string().min(1).max(200).describe('Service connection id (scon_*) from stack_list_connected_services'),
      proxy_enabled: z.boolean().describe('true routes agent calls through the proxy; false turns it off'),
      governance_approval_id: z.string().optional().describe('Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a person approved it'),
    },
    async ({ connection_id, proxy_enabled, governance_approval_id }) => toolJson(await api(
      'POST',
      `/v1/services/${encodeURIComponent(connection_id)}/proxy-toggle`,
      { proxy_enabled },
      governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined,
    )),
  );

  server.tool(
    'stack_rename_connection',
    'Rename one service connection (scon_*). A service can hold several connections, each with its own name; the name is what an agent passes as connection to choose among them. The new name is compared without case and must not be used by another active connection of the same service for the same member. The owner or an admin; an agent cannot. Returns the connection.',
    {
      connection_id: z.string().min(1).max(200).describe('Service connection id (scon_*) from stack_list_connected_services'),
      connection_name: ConnectionName.describe('The new name: letters, digits, spaces and hyphens, up to 40 characters'),
    },
    async ({ connection_id, connection_name }) => toolJson(await api(
      'PATCH',
      `/v1/services/${encodeURIComponent(connection_id)}`,
      { connection_name },
    )),
  );

  server.tool(
    'stack_list_service_configurations',
    "List the account's stored service configurations: for each provider, whether the team shares one connection (shared) or each member connects their own (per_member).",
    {},
    async () => toolJson(await api('GET', '/v1/services/configurations')),
  );

  server.tool(
    'stack_save_service_configuration',
    'Save how the team uses one provider: shared (one connection for the whole account) or per_member (each member connects their own). It replaces any configuration stored for the provider and deletes no connection. Returns the configuration.',
    {
      service_id: z.string().min(1).max(200).describe('Catalog service id, from stack_list_services'),
      provider: z.string().min(1).max(200).describe('Provider name, for example "slack"'),
      mode: z.enum(['shared', 'per_member']).describe('shared or per_member'),
    },
    async ({ service_id, provider, mode }) => toolJson(await api('POST', '/v1/services/configure', { service_id, provider, mode })),
  );

  server.tool(
    'stack_delete_service_configuration',
    'Delete the stored configuration of one provider. Existing connections are not deleted.',
    {
      provider: z.string().min(1).max(200).describe('Provider name, for example "slack"'),
    },
    async ({ provider }) => toolJson(await api('DELETE', `/v1/services/configurations/${encodeURIComponent(provider)}`)),
  );
}
