import type { HttpClient } from '../client.js';
import type {
  Service,
  ServiceConnection,
  ConnectServiceInput,
  ConnectCustomServiceInput,
  GrantAgentAccessInput,
  ConnectLink,
  CreateConnectLinkInput,
  CreatedConnectLink,
} from '../types.js';
import type { GrantAgentAccessResult } from './control-policies.js';

export class ServiceService {
  constructor(private client: HttpClient) {}

  async listAvailable(): Promise<Service[]> {
    return this.client.get<Service[]>('/v1/services');
  }

  async listConnected(): Promise<ServiceConnection[]> {
    return this.client.get<ServiceConnection[]>('/v1/services/connected');
  }

  /** The API reads the credential from `oauth_token`; `provider` is not sent. */
  async connect(input: ConnectServiceInput): Promise<ServiceConnection> {
    const { service_id, scopes, credential, mcp_url, connection_name } = input;
    return this.client.post<ServiceConnection>('/v1/services/connect', {
      service_id,
      scopes,
      oauth_token: credential,
      ...(mcp_url !== undefined ? { mcp_url } : {}),
      ...(connection_name !== undefined ? { connection_name } : {}),
    });
  }

  /** Rename a connection (owner or admin). Calls name it by the new name from then on; the id never changes. */
  async rename(connectionId: string, connectionName: string): Promise<ServiceConnection> {
    return this.client.patch<ServiceConnection>(`/v1/services/${encodeURIComponent(connectionId)}`, { connection_name: connectionName });
  }

  /**
   * Connect a service without the credential passing through this program or
   * a chat: create a one-time link the person opens in their own browser,
   * signed in to STACK. It is bound to this account and member, works once,
   * expires after 10 minutes, and any number can be open at once. The returned `url` is the only copy; read the
   * outcome with {@link ServiceService.getConnectLink}. Pass `custom` instead
   * of `service_id` for the customer's own API that takes a key or token: its
   * name and the hosts the key may be sent to, which the page shows and the
   * owner may correct there. Pass `connect` for a key of one of the customer's own supplier accounts (a print-on-demand
   * supplier, an agent's Telegram bot, the street address's mailbox.bot key): the owner or an admin enters it on the page,
   * so it never passes through this program or a chat. An agent context is refused: an agent never adds credentials.
   */
  async createConnectLink(input: CreateConnectLinkInput): Promise<CreatedConnectLink> {
    // The API takes the name at the top level for a catalog link, inside `custom` for a custom one, and not at all for a key link.
    if ('custom' in input) {
      return this.client.post<CreatedConnectLink>('/v1/services/connect-links', { custom: input.custom });
    }
    if ('connect' in input) {
      return this.client.post<CreatedConnectLink>('/v1/services/connect-links', { connect: input.connect });
    }
    const { service_id, scopes, connection_name } = input;
    return this.client.post<CreatedConnectLink>('/v1/services/connect-links', {
      service_id,
      ...(scopes ? { scopes } : {}),
      ...(connection_name !== undefined ? { connection_name } : {}),
    });
  }

  /** The state of a connect link: pending, connected (with the connection id) or expired. Never the URL. */
  async getConnectLink(linkId: string): Promise<ConnectLink> {
    return this.client.get<ConnectLink>(`/v1/services/connect-links/${encodeURIComponent(linkId)}`);
  }

  /** The connect links still waiting for the person: pending and not yet expired, newest first, at most 50. Never a URL or a token. */
  async listConnectLinks(): Promise<ConnectLink[]> {
    const answer = await this.client.get<{ links: ConnectLink[] }>('/v1/services/connect-links');
    return answer.links;
  }

  async connectCustom(input: ConnectCustomServiceInput): Promise<ServiceConnection> {
    return this.client.post<ServiceConnection>('/v1/services/custom', input);
  }

  async disconnect(connectionId: string): Promise<{ disconnected: boolean }> {
    return this.client.delete(`/v1/services/${connectionId}/disconnect`);
  }

  /**
   * Create or replace an agent's grant on a connection. With hosted controls on
   * and a policy that lists connections, the answer carries `control_policy`:
   * the connection is not callable until a revision of that policy lists it,
   * a loosening a person approves in a browser (`controlPolicies.set`).
   */
  async grantAgentAccess(input: GrantAgentAccessInput): Promise<GrantAgentAccessResult> {
    return this.client.post<GrantAgentAccessResult>('/v1/services/grant', input);
  }

  async revokeAgentAccess(agentId: string): Promise<{ success: boolean }> {
    return this.client.delete(`/v1/services/agents/${agentId}/revoke`);
  }

  async verify(connectionId: string): Promise<{ status: string }> {
    return this.client.post(`/v1/services/${connectionId}/verify`);
  }

  async listTemplates(): Promise<{ templates: unknown[] }> {
    return this.client.get('/v1/services/templates');
  }
}
