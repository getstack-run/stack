import type { HttpClient } from '../client.js';

export interface CreateInboundWebhookInput {
  provider: 'agentmail' | 'generic';
  agent_id: string;
  forward_url?: string | null;
  generic_config?: {
    signature_header?: string;
    signature_algorithm?: 'hmac-sha256' | 'hmac-sha1';
    dedupe_key_path?: string;
    content_paths?: string[];
  };
}

export interface CreateInboundWebhookResult {
  id: string;
  provider: 'agentmail' | 'generic';
  slug: string;
  webhook_url: string;
  /** Downstream verification secret — returned ONLY at create time. */
  webhook_secret: string;
  /** Generic inbound signing secret — returned ONLY at create time. */
  incoming_signing_secret?: string;
  signing_configured: boolean;
  agent_id: string | null;
  forward_url: string | null;
  created_at: string;
}

export interface InboundWebhookView {
  id: string;
  /** `agentmail` or `generic`, or the provider of a webhook STACK manages itself (`rentahuman`). */
  provider: string;
  /** True for a webhook STACK registered itself (RentAHuman's events); revoking it also ends the endpoint at the provider. */
  managed: boolean;
  slug: string;
  webhook_url: string;
  agent_id: string | null;
  forward_url: string | null;
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  last_block_at: string | null;
  total_calls: number;
  total_blocked: number;
  signing_configured: boolean;
}

export class InboundWebhookService {
  constructor(private client: HttpClient) {}

  /**
   * Create a hosted inbound webhook. STACK returns a URL and a downstream
   * verification secret. Generic endpoints also return a distinct
   * incoming_signing_secret. Both are shown ONCE. For AgentMail, register webhook_url there,
   * then call setProviderSigningSecret with AgentMail's signing secret.
   * After this call there is no way to retrieve the plaintext secret;
   * if lost, revoke + recreate.
   */
  async create(input: CreateInboundWebhookInput): Promise<CreateInboundWebhookResult> {
    return this.client.post<CreateInboundWebhookResult>('/v1/operator/inbound-webhooks', input);
  }

  async list(): Promise<InboundWebhookView[]> {
    const res = await this.client.get<{ webhooks: InboundWebhookView[] }>('/v1/operator/inbound-webhooks');
    return res.webhooks;
  }

  /** Owner/admin setup outside MCP. STACK generates a new downstream key when a generic key is reconfigured without one. */
  async setProviderSigningSecret(
    id: string,
    signingSecret: string,
    downstreamSigningSecret?: string,
  ): Promise<{ configured: true; webhook_secret?: string }> {
    return this.client.put(`/v1/operator/inbound-webhooks/${encodeURIComponent(id)}/provider-signing-secret`, {
      signing_secret: signingSecret, ...(downstreamSigningSecret !== undefined ? { downstream_signing_secret: downstreamSigningSecret } : {}),
    });
  }

  /**
   * A fresh downstream signing secret, returned once, for an API key or a dashboard session. The
   * one it replaces keeps signing the forwards beside it for 24 hours.
   */
  async rotateSecret(id: string): Promise<{ webhook_secret: string; previous_valid_until: string }> {
    return this.client.post(`/v1/operator/inbound-webhooks/${encodeURIComponent(id)}/rotate-secret`, {});
  }

  async get(id: string): Promise<InboundWebhookView> {
    return this.client.get<InboundWebhookView>(`/v1/operator/inbound-webhooks/${id}`);
  }

  async revoke(id: string): Promise<{ transitioned: boolean }> {
    return this.client.delete<{ transitioned: boolean }>(`/v1/operator/inbound-webhooks/${id}`);
  }
}
