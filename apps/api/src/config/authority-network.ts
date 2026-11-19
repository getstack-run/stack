import { createHash } from 'node:crypto';
import { publicFetch } from '@stack/shared';
import type {
  AuthorityPresentationTransport,
  AuthorityServiceDeps,
} from '@stack/vault';

const RESPONSE_LIMIT_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;

interface PinnedRequestInput {
  url: string;
  resolvedAddresses: string[];
  method: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
}

interface PinnedRequestResult {
  status: number;
  body: string;
  location?: string;
}

/**
 * Make one HTTPS request while pinning the TCP connection to an address that
 * was already resolved and checked by the authority service. TLS SNI and
 * certificate verification still use the registered hostname. Redirects are
 * returned to the caller and never followed.
 */
async function pinnedHttpsRequest(input: PinnedRequestInput): Promise<PinnedRequestResult> {
  const url = new URL(input.url);
  if (url.protocol !== 'https:' || input.resolvedAddresses.length === 0) {
    throw new Error('authority network request requires a pinned HTTPS destination');
  }
  const response = await publicFetch(url, {
    method: input.method,
    headers: input.headers,
    body: input.body,
    redirect: 'manual',
  }, {
    resolvedAddresses: input.resolvedAddresses,
    maxResponseBytes: RESPONSE_LIMIT_BYTES,
    timeoutMs: REQUEST_TIMEOUT_MS,
  });
  const location = response.headers.get('location');
  return { status: response.status, body: await response.text(), ...(location ? { location } : {}) };
}

export function createAuthorityReceiverOriginVerifier(): AuthorityServiceDeps['receiverOriginVerifier'] {
  return {
    async fetchWellKnown(input) {
      return pinnedHttpsRequest({
        url: input.url,
        resolvedAddresses: input.resolvedAddresses,
        method: 'GET',
        headers: { accept: 'application/json' },
      });
    },
  };
}

export function createAuthorityPresentationTransport(): AuthorityPresentationTransport {
  return {
    async deliver(input) {
      const body = new URLSearchParams({ response: input.compactJwe }).toString();
      const result = await pinnedHttpsRequest({
        url: input.endpoint,
        resolvedAddresses: input.resolvedAddresses,
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': String(Buffer.byteLength(body)),
          'idempotency-key': input.presentationId,
        },
        body,
      });
      if (result.status < 200 || result.status >= 300) {
        throw new Error(`authority receiver rejected delivery with HTTP ${result.status}`);
      }
      return {
        deliveredAt: new Date(),
        responseHash: `sha256:${createHash('sha256').update(result.body).digest('hex')}`,
      };
    },
  };
}
