// Inbound webhook extractor registry.
//
// Per-provider plugins for the hosted inbound webhook receiver. Each
// extractor exports four hooks that the receive handler consults:
//
//   - contentType:   the expected Content-Type header. Default
//                    'application/json'. Override for providers that
//                    push form-urlencoded (Twilio) or other shapes.
//   - verifySignature: HMAC-style auth check over the raw body + the
//                    operator's per-webhook secret. Generic default:
//                    HMAC-SHA256 over raw body, header X-Webhook-Signature
//                    (`sha256=<hex>`). Twilio override: HMAC-SHA1 over
//                    URL + sorted form fields, header X-Twilio-Signature.
//   - extractScanContent: byte-string the detector should scan. For
//                    AgentMail: complete decoded JSON event payload.
//                    For generic JSON: stringified body OR a configured
//                    set of JSON paths.
//   - extractDedupeKey: the provider's stable message ID, used for
//                    the (webhook_id, provider_message_id) idempotency
//                    pair. Returns null when the provider doesn't ship
//                    one (caller falls back to body hash).
//
// The engine ships 'generic'; a deployment registers the providers of its
// own. Adding Twilio / Resend / SendGrid /
// Slack = one extractor file each.

import { genericExtractor } from './generic.js';

export interface SignatureVerificationInput {
  /** Raw request body bytes (Buffer). The encapsulated parser at
   *  /v1/inbound/* keeps this as a buffer. */
  rawBody: Buffer;
  /** The HTTP path the request hit (some providers sign over path + body). */
  requestPath: string;
  /** Request headers map (lowercased keys via Fastify). */
  headers: Record<string, string | string[] | undefined>;
  /** Plaintext webhook secret, after KMS decrypt. */
  secret: string;
}

export interface SignatureVerificationResult {
  ok: boolean;
  /** Human-readable reason on failure. */
  reason?: string;
}

export interface ExtractScanContentInput {
  /** Parsed JSON body (or form-fields object for non-JSON providers). */
  parsedBody: unknown;
  /** Raw bytes — for providers that scan over the wire format directly. */
  rawBody: Buffer;
  /** Optional per-row extractor config (only set for provider='generic'). */
  config?: GenericExtractorConfig;
}

export interface ExtractScanContentResult {
  /** UTF-8 string fed to the detector. */
  content: string;
  /** True when the extractor truncated the content to the cap. */
  truncated: boolean;
}

export interface ExtractDedupeKeyInput {
  parsedBody: unknown;
  headers?: Record<string, string | string[] | undefined>;
  config?: GenericExtractorConfig;
}

export interface GenericExtractorConfig {
  signature_header: string;
  signature_algorithm: 'hmac-sha256' | 'hmac-sha1';
  dedupe_key_path: string;
  content_paths: string[];
}

export interface InboundWebhookExtractor {
  provider: string;
  /**
   * Expected content-type. The encapsulated parser at /v1/inbound/*
   * is JSON-buffer by default; non-JSON providers (Twilio: form-urlencoded)
   * require a different parser, which the per-route encapsulation will
   * branch on once Bucket C lands. v1 = JSON-only.
   */
  contentType: 'application/json';
  verifySignature(input: SignatureVerificationInput, config?: GenericExtractorConfig): SignatureVerificationResult;
  extractScanContent(input: ExtractScanContentInput): ExtractScanContentResult;
  extractDedupeKey(input: ExtractDedupeKeyInput): string | null;
  /**
   * A provider whose own signing secret has a shape of its own: why this secret is refused, or null when it fits.
   * Absent: any secret of the right length is accepted.
   */
  signingSecretProblem?(secret: string): string | null;
}

/**
 * What a deployment does with a verified, de-duplicated delivery of one of its own providers, in place of forwarding it: the
 * deployment's own code takes the event (STACK wakes an agent with the facts of it). It throws to have the delivery answered 502, so
 * the provider sends it again; it is called at most once for a delivery that was handled.
 */
export type InboundDeliveryHandler = (delivery: {
  operatorId: string;
  webhookId: string;
  provider: string;
  parsedBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  /** The provider's own delivery id, or the body's hash when it sends none. */
  deliveryId: string;
}) => Promise<void>;

/** What ends a managed provider's side of one of its rows when the owner revokes the row (the endpoint registered at the provider). Throws when it cannot, and the row stays. */
export type InboundManagedEnd = (operatorId: string, webhookId: string) => Promise<void>;

/** Where a deployment's managed providers' ends are looked up, by provider. */
export interface InboundManagedEndSource {
  get(provider: string): InboundManagedEnd | undefined;
}

/** Where a deployment's delivery handlers are looked up, by provider. A provider with one is managed by the deployment: no owner creates its rows, the owner sees them marked managed, and revoking one ends the provider's side too (`InboundManagedEnd`). */
export interface InboundDeliverySource {
  get(provider: string): InboundDeliveryHandler | undefined;
}

/** Where a deployment's own providers are looked up, beside the engine's. */
export interface InboundExtractorSource {
  get(provider: string): InboundWebhookExtractor | undefined;
}

// The engine ships the generic extractor. A provider of a deployment's own is registered by it.
const REGISTRY: Record<string, InboundWebhookExtractor> = {
  generic: genericExtractor,
};

export function getExtractor(provider: string): InboundWebhookExtractor | null {
  return Object.hasOwn(REGISTRY, provider) ? REGISTRY[provider]! : null;
}

export { genericExtractor };
