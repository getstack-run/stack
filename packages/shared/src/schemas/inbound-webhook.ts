// hosted inbound webhook surface.
//
// AgentMail (and future providers) POST inbound payloads to
// `https://api.getstack.run/v1/inbound/:provider/:slug`. STACK verifies
// the HMAC against the per-webhook secret, runs DetectorService against
// extracted content, writes a security_event claim on block, and
// forwards to the operator-configured downstream URL on clean.
//
// Incoming authentication and downstream STACK signing always use distinct,
// KMS-bound secrets. Create returns each generated value once and never exposes
// either value through list/get.

import { z } from 'zod';

export const INBOUND_WEBHOOK_PROVIDERS = ['agentmail', 'generic'] as const;

export type InboundWebhookProvider = (typeof INBOUND_WEBHOOK_PROVIDERS)[number];

export const InboundWebhookProviderEnum = z.enum(INBOUND_WEBHOOK_PROVIDERS);

/** Operator-facing create input. */
export const CreateInboundWebhookInput = z.object({
  provider: InboundWebhookProviderEnum,
  /**
   * REQUIRED — security_event attribution for blocks lands under this
   * agent. Deleting an agent that's referenced by an active inbound
   * webhook is blocked at AgentService.delete (cascade-block in service
   * layer, distinct from the ON DELETE SET NULL FK behaviour which
   * only fires if the cascade-block is bypassed).
   */
  agent_id: z.string().min(1),
  /**
   * Optional. When null, receive runs in log-only mode: scan happens,
   * decision returned to the provider, but no downstream forward.
   * Useful for testing or for operators who want a pure-audit deployment.
   */
  forward_url: z.string().url().nullable().optional(),
  /**
   * For provider='generic' only — optional config telling the generic
   * extractor how to verify the signature, where to find content for
   * scanning, and where to find the dedupe key in the JSON body.
   */
  generic_config: z
    .object({
      signature_header: z.string().min(1).default('X-Webhook-Signature'),
      signature_algorithm: z.enum(['hmac-sha256', 'hmac-sha1']).default('hmac-sha256'),
      /** JSON path (dot-notation) for the dedupe key; default: 'id' */
      dedupe_key_path: z.string().min(1).default('id'),
      /** JSON paths (dot-notation) to concatenate as scan content; default: stringified full body */
      content_paths: z.array(z.string().min(1)).default([]),
    })
    .optional(),
});
export type CreateInboundWebhookInput = z.infer<typeof CreateInboundWebhookInput>;

/** View shape returned at create time — INCLUDES the plaintext secret. */
export const CreateInboundWebhookResult = z.object({
  id: z.string(),
  provider: InboundWebhookProviderEnum,
  slug: z.string(),
  webhook_url: z.string().url(),
  /** Downstream services use this to verify the Standard Webhooks signature. Returned once. */
  webhook_secret: z.string(),
  /** Generic senders use this to sign inbound requests. Returned once. */
  incoming_signing_secret: z.string().optional(),
  signing_configured: z.boolean(),
  agent_id: z.string().nullable(),
  forward_url: z.string().nullable(),
  created_at: z.string(),
});
export type CreateInboundWebhookResult = z.infer<typeof CreateInboundWebhookResult>;

/** View shape for list / get — never includes the plaintext secret. */
export const InboundWebhookView = z.object({
  id: z.string(),
  /** `agentmail` or `generic`, or the provider of a webhook STACK manages itself (`rentahuman`). */
  provider: z.string(),
  /** True for a webhook STACK registered itself (RentAHuman's events): it has no agent or forward address, and revoking it also ends the endpoint at the provider. */
  managed: z.boolean(),
  slug: z.string(),
  webhook_url: z.string().url(),
  agent_id: z.string().nullable(),
  forward_url: z.string().nullable(),
  created_at: z.string(),
  revoked_at: z.string().nullable(),
  last_used_at: z.string().nullable(),
  last_block_at: z.string().nullable(),
  total_calls: z.number().int().nonnegative(),
  total_blocked: z.number().int().nonnegative(),
  signing_configured: z.boolean(),
});
export type InboundWebhookView = z.infer<typeof InboundWebhookView>;

export const ListInboundWebhooksResult = z.object({
  webhooks: z.array(InboundWebhookView),
});
export type ListInboundWebhooksResult = z.infer<typeof ListInboundWebhooksResult>;

/** Wire shape of the public receiver's response. */
export const ReceiveInboundResponse = z.object({
  decision: z.enum(['clean', 'blocked', 'deduplicated', 'revoked_during_flight']),
  reason: z.string().optional(),
  detector_signals: z.array(z.string()).optional(),
  message_id: z.string().nullable().optional(),
  forwarded: z.boolean(),
  downstream_status: z.number().int().optional(),
  security_event_claim_id: z.string().optional(),
  truncated_for_scan: z.boolean().optional(),
});
export type ReceiveInboundResponse = z.infer<typeof ReceiveInboundResponse>;

/**
 * AgentMail event envelope. Official events nest message fields under
 * `message`; the receiver scans the complete raw JSON and deduplicates the
 * authenticated svix-id header. https://docs.agentmail.to/webhooks-overview
 */
export const AgentMailInboundPayload = z
  .object({
    event_id: z.string(),
    event_type: z.string(),
    message: z.object({
      message_id: z.string().optional(),
      inbox_id: z.string().optional(),
      from: z.string().optional(),
      to: z.union([z.string(), z.array(z.string())]).optional(),
      subject: z.string().optional(),
      text: z.string().optional(),
      html: z.string().optional(),
      attachments: z.array(z.object({
        filename: z.string().optional(),
        content_type: z.string().optional(),
        text: z.string().optional(),
      })).optional(),
      received_at: z.string().optional(),
    }).passthrough().optional(),
  })
  .passthrough();
export type AgentMailInboundPayload = z.infer<typeof AgentMailInboundPayload>;

/** Content extraction cap (truncated at this size before scanning). */
export const INBOUND_WEBHOOK_SCAN_CONTENT_MAX_BYTES = 64 * 1024;
/** Receiver route body limit (Fastify routeOptions.config.bodyLimit). */
export const INBOUND_WEBHOOK_BODY_LIMIT_BYTES = 1 * 1024 * 1024;
/** Idempotency dedupe window. */
export const INBOUND_WEBHOOK_DEDUPE_TTL_SECONDS = 48 * 3600;
/** Outbound forward timeout. */
export const INBOUND_WEBHOOK_FORWARD_TIMEOUT_MS = 10_000;
