// The call to OpenRouter itself. The host is fixed (it comes from `OPENROUTER_API_BASE`, never from the caller), the key
// goes in the one header it belongs in and nowhere else, redirects are never followed, and the answer is read as a
// stream with a clock on it: a total time for the call and a time without a byte (its keep-alive comments count). The
// answer's size is not cut: it is streamed, never held whole.

import {
  OPENROUTER_CALL_TIMEOUT_MS,
  OPENROUTER_IDLE_TIMEOUT_MS,
  StackError,
} from '@stack/shared';
import type { OpenRouterCall } from './request.js';

/**
 * What the caller sends that does not go on to OpenRouter: the credentials it used here (`authorization`, `cookie`, STACK's
 * Passport in `x-passport-token`) and every `x-stack-*` header, which are STACK's own; `host` and the headers of one hop of a
 * connection (RFC 9110 section 7.6.1), the two the transport sets from the body it sends (`content-length`, `expect`), and
 * the headers STACK's own infrastructure adds in front of the caller's (`forwarded`, `x-forwarded-*`, `x-real-ip`, `via`, `fly-*`),
 * which are not the caller's. Every other header goes on, on STACK's key as on the customer's.
 */
const NOT_FORWARDED_REQUEST_HEADERS = new Set([
  'authorization', 'cookie', 'x-passport-token', 'host',
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade',
  'content-length', 'expect',
  'forwarded', 'x-real-ip', 'via',
]);
/** What of OpenRouter's answer the caller gets as headers. Cookies, CORS and caching are not OpenRouter's to set here. */
const FORWARDED_RESPONSE_HEADERS = /^(?:content-type|content-disposition|content-language|retry-after|request-id|x-generation-id|x-provider-name|x-openrouter-[a-z0-9-]+|x-ratelimit-[a-z0-9-]+|etag|last-modified)$/;

/** The one host the key and the caller's bytes go to. Pinned here as well as in the request (`egress-mediation.test.ts`). */
const OPENROUTER_HOST = 'openrouter.ai';

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface UpstreamAnswer {
  status: number;
  /** The headers the caller gets, already filtered. */
  headers: Record<string, string>;
  contentType: string;
  /** `X-Generation-Id`, when OpenRouter sent it. */
  generationIdHeader: string | null;
  /** The answer's bytes, with the clocks and the size cap on them; null when there is no body. */
  body: AsyncIterable<Uint8Array> | null;
  /** Stops reading and closes the connection to OpenRouter. */
  cancel(): void;
}

/** The caller's headers that go on to OpenRouter: all of them, but its credentials, its cookies, STACK's own headers and those of one hop. */
export function forwardedRequestHeaders(incoming: Record<string, string | string[] | undefined>): Record<string, string> {
  // A header the `Connection` header names is one of this hop's, whatever it is called.
  const named = new Set<string>();
  const connection = incoming['connection'];
  for (const token of (Array.isArray(connection) ? connection.join(',') : connection ?? '').split(',')) {
    if (token.trim() !== '') named.add(token.trim().toLowerCase());
  }
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(incoming)) {
    const lower = name.toLowerCase();
    if (NOT_FORWARDED_REQUEST_HEADERS.has(lower) || lower.startsWith('x-stack-') || lower.startsWith('x-forwarded-') || lower.startsWith('fly-') || named.has(lower)) continue;
    const text = Array.isArray(value) ? value.join(', ') : value;
    if (typeof text === 'string') out[lower] = text;
  }
  return out;
}

function guarded(
  stream: ReadableStream<Uint8Array>,
  controller: AbortController,
  timers: { total: ReturnType<typeof setTimeout> },
): AsyncIterable<Uint8Array> {
  return {
    async *[Symbol.asyncIterator]() {
      const reader = stream.getReader();
      try {
        for (;;) {
          let idle: ReturnType<typeof setTimeout> | undefined;
          const timeout = new Promise<never>((_, reject) => {
            idle = setTimeout(() => reject(new StackError('OpenRouter sent nothing for too long.', 'UPSTREAM_TIMEOUT', 504)), OPENROUTER_IDLE_TIMEOUT_MS);
          });
          let read: Awaited<ReturnType<typeof reader.read>>;
          try {
            read = await Promise.race([reader.read(), timeout]);
          } finally {
            clearTimeout(idle);
          }
          if (read.done) return;
          yield read.value;
        }
      } catch (error) {
        controller.abort();
        throw error;
      } finally {
        clearTimeout(timers.total);
        try {
          reader.releaseLock();
        } catch {
          // A read still pending when the call was cut off settles by itself.
        }
      }
    },
  };
}

/** Sends the call and returns OpenRouter's answer with its headers filtered and its body as a guarded stream. */
export async function callOpenRouter(input: {
  call: OpenRouterCall;
  apiKey: string;
  incomingHeaders: Record<string, string | string[] | undefined>;
  /** Aborts the call (the caller hung up): before OpenRouter answers, the call fails and nothing is read. */
  signal?: AbortSignal;
  fetchImpl?: FetchLike;
}): Promise<UpstreamAnswer> {
  const { call, apiKey } = input;
  // Whatever built the call, the key goes nowhere but OpenRouter, over https.
  if (call.upstream.protocol !== 'https:' || call.upstream.host !== OPENROUTER_HOST) {
    throw new StackError('The call does not go to OpenRouter.', 'INVALID_REQUEST', 400);
  }
  const controller = new AbortController();
  const total = setTimeout(() => controller.abort(), OPENROUTER_CALL_TIMEOUT_MS);
  if (input.signal) {
    if (input.signal.aborted) controller.abort();
    else input.signal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  let response: Response;
  try {
    response = await (input.fetchImpl ?? ((url, init) => fetch(url, init)))(call.upstream.toString(), {
      method: call.method,
      // The key goes in the one header it belongs in, after the caller's own, so nothing the caller sent can stand in for it.
      headers: { ...forwardedRequestHeaders(input.incomingHeaders), authorization: `Bearer ${apiKey}` },
      ...(call.rawBody && call.method !== 'GET' && call.method !== 'HEAD' ? { body: new Uint8Array(call.rawBody) } : {}),
      redirect: 'manual',
      signal: controller.signal,
    });
  } catch {
    clearTimeout(total);
    // Nothing OpenRouter or the network said, and nothing of the key, in the answer.
    throw new StackError('OpenRouter could not be reached. Nothing was charged.', 'SERVICE_UNAVAILABLE', 503, { retry_after_seconds: 30 }, { stackSide: true });
  }
  const headers: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    if (FORWARDED_RESPONSE_HEADERS.test(name.toLowerCase())) headers[name.toLowerCase()] = value;
  });
  // A redirect is never followed; the caller is told where OpenRouter pointed, in terms of this gateway.
  const location = response.headers.get('location');
  if (location && response.status >= 300 && response.status < 400) {
    const gateway = rewriteLocation(location);
    if (gateway) headers['location'] = gateway;
  }
  if (!response.body) clearTimeout(total);
  return {
    status: response.status,
    headers,
    contentType: response.headers.get('content-type') ?? '',
    generationIdHeader: response.headers.get('x-generation-id'),
    body: response.body ? guarded(response.body, controller, { total }) : null,
    cancel: () => {
      clearTimeout(total);
      controller.abort();
    },
  };
}

/** OpenRouter's `/api/v1/...` redirect target as a path on this gateway, or null when it points anywhere else. */
export function rewriteLocation(location: string): string | null {
  try {
    const url = new URL(location, 'https://openrouter.ai');
    if (url.host !== 'openrouter.ai' || !url.pathname.startsWith('/api/v1/')) return null;
    return `/v1/llm/openrouter/${url.pathname.slice('/api/v1/'.length)}${url.search}`;
  } catch {
    return null;
  }
}
