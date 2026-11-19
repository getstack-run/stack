import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson, safeProvisioningMetadata, webhookMetadataKeys } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const WEBHOOKS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Inbound webhooks
  stack_create_inbound_webhook: hint.write('Create inbound webhook'),
  stack_list_inbound_webhooks: hint.read('List inbound webhooks'),
  stack_get_inbound_webhook: hint.read('Get inbound webhook'),
  stack_revoke_inbound_webhook: hint.destructive('Revoke inbound webhook'),
};

/** Hosted inbound webhooks. */
export function registerWebhooksTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Inbound Webhooks ────────────────────────────────────────────
  //
  // Hosted inbound webhook surface. Operator creates a webhook row +
  // gets back a STACK-hosted URL + downstream HMAC secret. Generic senders
  // share that secret; AgentMail has a separate provider-signing setup. STACK verifies
  // signatures, runs the prompt-injection detector on the content,
  // writes a security_event claim on block, and forwards to the
  // operator's configured downstream URL on clean. Closes the gap that
  // service connectors don't cover (server-initiated webhook push).

  server.tool(
    'stack_create_inbound_webhook',
    'Create a hosted inbound webhook and return its URL and metadata. STACK verifies signatures on received calls, scans the content for prompt injection and forwards clean calls to forward_url. Signing is configured by an owner or admin through the REST API or SDK (https://getstack.run/docs/api/inbound-webhooks); this tool returns no signing secret.',
    {
      provider: z
        .enum(['agentmail', 'generic'])
        .describe(
          "Provider identifier. 'agentmail' uses AgentMail's payload shape; 'generic' accepts any JSON webhook with HMAC-SHA256 + X-Webhook-Signature header (configurable).",
        ),
      agent_id: z
        .string()
        .describe(
          'Agent ID to attribute security_events to (e.g. agt_*). The agent must belong to the calling operator.',
        ),
      forward_url: z
        .string()
        .url()
        .nullable()
        .optional()
        .describe(
          'Downstream URL STACK POSTs to after a clean scan. Leave null/unset for log-only mode (scan runs, decision recorded, no forward). Must be publicly accessible (no localhost/private ranges).',
        ),
      generic_config: z
        .object({
          signature_header: z
            .string()
            .optional()
            .describe("Header name carrying the HMAC signature (default 'X-Webhook-Signature')."),
          signature_algorithm: z
            .enum(['hmac-sha256', 'hmac-sha1'])
            .optional()
            .describe("HMAC algorithm (default 'hmac-sha256')."),
          dedupe_key_path: z
            .string()
            .optional()
            .describe("JSON dot-path for the dedupe message ID (default 'id')."),
          content_paths: z
            .array(z.string())
            .optional()
            .describe(
              'JSON dot-paths to concatenate as scan content. Empty = scan the stringified whole body.',
            ),
        })
        .optional()
        .describe(
          "Only valid when provider='generic'. Configures HMAC scheme + scan content extraction.",
        ),
    },
    async (input) => {
      const result = await api('POST', '/v1/operator/inbound-webhooks', input);
      return toolJson({ ...safeProvisioningMetadata(result, webhookMetadataKeys),
        setup_required: true, setup_url: 'https://getstack.run/docs/api/inbound-webhooks' });
    },
  );

  server.tool(
    'stack_list_inbound_webhooks',
    "List the account's hosted inbound webhooks, active and revoked, with counters (total_calls, total_blocked, last_used_at). Signing secrets are never returned.",
    {},
    async () => {
      const result = await api('GET', '/v1/operator/inbound-webhooks');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_inbound_webhook',
    'Get one inbound webhook with its counters and signing_configured status. Signing is configured by an owner or admin through the REST API or SDK (https://getstack.run/docs/api/inbound-webhooks). Signing secrets are never returned.',
    {
      id: z.string().describe('Inbound webhook id (iwh_*)'),
    },
    async ({ id }) => {
      const result = await api('GET', `/v1/operator/inbound-webhooks/${encodeURIComponent(id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_revoke_inbound_webhook',
    'Revoke an inbound webhook. The public receiver returns 404 for it from then on, and in-flight requests return 410 Gone. Revoking an already revoked webhook succeeds without change.',
    {
      id: z.string().describe('Inbound webhook id (iwh_*)'),
    },
    async ({ id }) => {
      const result = await api('DELETE', `/v1/operator/inbound-webhooks/${encodeURIComponent(id)}`);
      return toolJson(result);
    },
  );
}
