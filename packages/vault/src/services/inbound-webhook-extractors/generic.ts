// Generic inbound webhook extractor.
//
// For any provider that pushes JSON + signs with HMAC-SHA256 or
// HMAC-SHA1 over the raw body, using a configurable header name. Lets
// operators wire any JSON-webhook provider STACK doesn't ship a
// dedicated extractor for, without code changes.
//
// Config (per inbound_webhooks row, validated at create time):
//   - signature_header: header name to read (default 'X-Webhook-Signature')
//   - signature_algorithm: 'hmac-sha256' | 'hmac-sha1'
//   - dedupe_key_path: dot-notation JSON path for the dedupe key
//                      (default 'id', e.g. 'data.event_id')
//   - content_paths: list of dot-notation paths to concatenate as
//                    scan content (empty = stringify the whole body)
//
// Falls back to the cross-provider conventions when no config is set.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { INBOUND_WEBHOOK_SCAN_CONTENT_MAX_BYTES } from '@stack/shared';
import type {
  InboundWebhookExtractor,
  SignatureVerificationInput,
  SignatureVerificationResult,
  ExtractScanContentInput,
  ExtractScanContentResult,
  ExtractDedupeKeyInput,
  GenericExtractorConfig,
} from './index.js';

const DEFAULT_CONFIG: GenericExtractorConfig = {
  signature_header: 'X-Webhook-Signature',
  signature_algorithm: 'hmac-sha256',
  dedupe_key_path: 'id',
  content_paths: [],
};

function resolveConfig(config?: GenericExtractorConfig): GenericExtractorConfig {
  return {
    signature_header: config?.signature_header ?? DEFAULT_CONFIG.signature_header,
    signature_algorithm: config?.signature_algorithm ?? DEFAULT_CONFIG.signature_algorithm,
    dedupe_key_path: config?.dedupe_key_path ?? DEFAULT_CONFIG.dedupe_key_path,
    content_paths: config?.content_paths ?? DEFAULT_CONFIG.content_paths,
  };
}

function resolveJsonPath(body: unknown, path: string): unknown {
  if (!body || typeof body !== 'object') return undefined;
  let cur: unknown = body;
  for (const part of path.split('.')) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    if (!Object.hasOwn(cur, part)) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

export const genericExtractor: InboundWebhookExtractor = {
  provider: 'generic',
  contentType: 'application/json',
  verifySignature(input: SignatureVerificationInput, configOverride?: GenericExtractorConfig): SignatureVerificationResult {
    // The service loads the persisted configuration before signature checking.
    const config = resolveConfig(configOverride);
    const headerKey = config.signature_header.toLowerCase();
    const rawHeader = input.headers[headerKey];
    if (!rawHeader || typeof rawHeader !== 'string') {
      return { ok: false, reason: `missing_signature_header(${config.signature_header})` };
    }
    const signature = rawHeader.startsWith('sha256=')
      ? rawHeader.slice(7)
      : rawHeader.startsWith('sha1=')
      ? rawHeader.slice(5)
      : rawHeader;
    if (!/^[a-f0-9]+$/i.test(signature)) {
      return { ok: false, reason: 'malformed_signature' };
    }
    const algo = config.signature_algorithm === 'hmac-sha1' ? 'sha1' : 'sha256';
    const computed = createHmac(algo, input.secret).update(input.rawBody).digest('hex');
    if (signature.length !== computed.length) {
      return { ok: false, reason: 'signature_length_mismatch' };
    }
    let signatureBuf: Buffer;
    let computedBuf: Buffer;
    try {
      signatureBuf = Buffer.from(signature, 'hex');
      computedBuf = Buffer.from(computed, 'hex');
    } catch {
      return { ok: false, reason: 'signature_decode_failed' };
    }
    if (!timingSafeEqual(signatureBuf, computedBuf)) {
      return { ok: false, reason: 'signature_mismatch' };
    }
    return { ok: true };
  },
  extractScanContent(input: ExtractScanContentInput): ExtractScanContentResult {
    const config = resolveConfig(input.config);
    let content: string;
    if (config.content_paths.length === 0) {
      // No paths configured — scan the full body, stringified.
      try {
        content = JSON.stringify(input.parsedBody);
      } catch {
        content = input.rawBody.toString('utf8');
      }
    } else {
      // Concatenate configured paths.
      const parts: string[] = [];
      for (const path of config.content_paths) {
        const v = resolveJsonPath(input.parsedBody, path);
        if (typeof v === 'string' && v.length > 0) {
          parts.push(`${path}: ${v}`);
        } else if (v !== undefined && v !== null) {
          parts.push(`${path}: ${JSON.stringify(v)}`);
        }
      }
      content = parts.join('\n\n');
    }
    const max = INBOUND_WEBHOOK_SCAN_CONTENT_MAX_BYTES;
    let truncated = false;
    if (Buffer.byteLength(content, 'utf8') > max) {
      const buf = Buffer.from(content, 'utf8');
      content = buf.slice(0, max - 32).toString('utf8') + '\n\n[...truncated]';
      truncated = true;
    }
    return { content, truncated };
  },
  extractDedupeKey(input: ExtractDedupeKeyInput): string | null {
    const config = resolveConfig(input.config);
    const v = resolveJsonPath(input.parsedBody, config.dedupe_key_path);
    if (typeof v === 'string' && v.length > 0) return v;
    if (typeof v === 'number') return String(v);
    return null;
  },
};
