import type { HttpClient } from '../client.js';
import type {
  ProxyOperation,
  ProxyOperationOptions,
  ProxyRequest,
  ProxyRequestOptions,
  ProxyResponse,
  ProxyUsage,
  ServiceCallOptions,
} from '../types.js';
import { authorityRequestHeaders, createAuthorityRequestId } from '../authority-request.js';
import {
  serviceMcpRequest,
  serviceMcpUrlOf,
  toolListOf,
  toolResultOf,
  type ServiceToolList,
  type ServiceToolResult,
} from '../service-mcp.js';

type ProxyRequestWire = Omit<ProxyRequest, 'service' | 'provider'> & { service: string };

function normalizeProxyRequest(input: ProxyRequest): ProxyRequestWire {
  const candidate = input as ProxyRequest & { service?: unknown; provider?: unknown };
  const hasService = candidate.service !== undefined;
  const hasProvider = candidate.provider !== undefined;

  if (hasService === hasProvider) {
    throw new TypeError('ProxyRequest must include exactly one of service or provider');
  }

  const service = hasService ? candidate.service : candidate.provider;
  if (typeof service !== 'string' || service.trim().length === 0) {
    throw new TypeError('ProxyRequest service must be a non-empty string');
  }

  const { service: _service, provider: _provider, ...request } = candidate;
  return { ...request, service } as ProxyRequestWire;
}

/** The `connection` selector of a call's options, sent only when given. */
function connectionOf(options?: ServiceCallOptions): { connection?: string } {
  return options?.connection !== undefined ? { connection: options.connection } : {};
}

export class ProxyService {
  constructor(private client: HttpClient) {}

  /**
   * Make a credentialed proxy request through STACK.
   *
   * @param input - service (or legacy provider)/method/url/body shape, validated server-side
   * @param options - optional headers:
   *   - `passportToken`: passport JWT (REQUIRED by /v1/proxy — sent as
   *     `X-Passport-Token`).
   *   - `approvalId`: approval id from `intents.submitAndWait`
   *     . Sent as `X-Intent-Approval-Id`. Required when
   *     the calling passport is in enforced mode — submit the intent
   *     first via `stack.intents.submitAndWait` and pass the returned
   *     `final.id` here.
   *   - `input.connection`: the connection to use when the service has several (its name, any case, or its `scon_` id); sent only
   *     when given.
   *   - `authorityRequestId`: stable operation handle. Non-GET calls create
   *     one before network I/O when omitted and expose it as
   *     `response.operationId` or `error.operationId`. Persist it and reuse
   *     it only for an unchanged retry.
   */
  async request(input: ProxyRequest, options?: ProxyRequestOptions): Promise<ProxyResponse> {
    const wireInput = normalizeProxyRequest(input);
    const operationId = options?.authorityRequestId
      ?? (input.method.toUpperCase() === 'GET' ? undefined : createAuthorityRequestId());
    if (operationId && options?.onOperationId) await options.onOperationId(operationId);
    const headers: Record<string, string> = authorityRequestHeaders(operationId);
    if (options?.passportToken) headers['X-Passport-Token'] = options.passportToken;
    if (options?.approvalId) headers['X-Intent-Approval-Id'] = options.approvalId;
    try {
      const response = await this.client.post<ProxyResponse>(
        '/v1/proxy',
        wireInput,
        Object.keys(headers).length > 0 ? { headers } : undefined,
      );
      return operationId ? { ...response, operationId } : response;
    } catch (error) {
      if (!operationId) throw error;
      const recoverable = error instanceof Error ? error : new Error(String(error));
      Object.defineProperty(recoverable, 'operationId', {
        configurable: true,
        enumerable: true,
        value: operationId,
      });
      throw recoverable;
    }
  }

  /**
   * The tools a connected service that speaks MCP over HTTP offers (`tools/list`), sent through the credential proxy: the Passport,
   * the Mission, the grant, the customer's decider, the meter and the audit record all apply. Works for any connected service whose
   * connection carries its MCP address (`mcp_url`, given when it was connected) and for RentAHuman, whose address STACK knows. What comes
   * back is the provider's words: `untrusted` is always true.
   */
  async serviceTools(service: string, options?: ServiceCallOptions): Promise<ServiceToolList> {
    const response = await this.request(
      { service, url: await this.mcpUrl(service, options?.connection), method: 'POST', body: serviceMcpRequest('tools/list'), ...connectionOf(options) },
      options,
    );
    return toolListOf(service, response);
  }

  /**
   * Call one tool of a connected service (`tools/call`) through the credential proxy. Reuse `authorityRequestId` for an exact retry of
   * a call with an effect (posting or funding a bounty, sending a message): one id is one operation. A service's own error is thrown;
   * a tool that reports an error in its result comes back with `is_error` true. The result is the provider's words: `untrusted`.
   */
  async serviceCallTool(service: string, tool: string, args: Record<string, unknown> = {}, options?: ServiceCallOptions): Promise<ServiceToolResult> {
    const response = await this.request(
      { service, url: await this.mcpUrl(service, options?.connection), method: 'POST', body: serviceMcpRequest('tools/call', { name: tool, arguments: args }), ...connectionOf(options) },
      options,
    );
    return toolResultOf(service, tool, response);
  }

  /** The service's MCP address: its connection's own (never one a caller names; the proxy checks it against the connection's allowed hosts). */
  private async mcpUrl(service: string, connection?: string): Promise<string> {
    return serviceMcpUrlOf(await this.client.get<unknown>('/v1/services/connected'), service, connection);
  }

  /** Read delivery state and, when authorized, the stored screened response. */
  async getOperation(operationId: string, options: ProxyOperationOptions): Promise<ProxyOperation> {
    authorityRequestHeaders(operationId);
    return this.client.post<ProxyOperation>(
      '/v1/proxy/operations/get',
      { operation_id: operationId, include_response: options.includeResponse ?? false },
      { headers: { 'X-Passport-Token': options.passportToken } },
    );
  }

  /** Month-to-date action pool. `pooled` is set on the accounts of a partner on a negotiated hard cap. */
  async usage(): Promise<ProxyUsage> {
    return this.client.get<ProxyUsage>('/v1/proxy/usage');
  }
}
