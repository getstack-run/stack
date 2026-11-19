// LlmGatewayService.
//
// Substrate for the /v1/llm/<provider>/* route family. Parallel to
// ProxyService in proxy-service.ts (which forwards HTTP requests for
// the generic /v1/proxy route). Handles:
//   - Provider URL resolution (anthropic → api.anthropic.com, etc.)
//   - Provider-specific header injection (x-api-key + anthropic-version
//     for Anthropic; Authorization: Bearer for OpenAI + OpenRouter)
//   - Non-streaming upstream call + JSON response parsing
//   - Streaming (SSE) upstream call with usage extraction from the
//     terminal event
//
// An earlier change added: redactUserMessages (provider-specific PII scrub on
// user/tool roles before forward) + assistant-text extraction on
// forwardStreaming, so the route handler could run scanOutput on a
// streamed response.
//
// An earlier change changed WHEN that text is available. 5.2.3 tee'd the upstream and
// resolved the text at end-of-stream, which is too late to refuse anything.
// forwardStreaming now walks the stream once and yields complete SSE event
// blocks paired with their text, so the caller decides per block whether the
// bytes leave.
//
// Out of scope for 5.2.3:
//   - Cost rollup + recordUsage (5.2.4 — adds recordUsage method)
//
// Stateless service (no deps): forward methods take the API key as an
// argument, provider URLs are in the LLM_PROVIDERS constant. Caller
// (route handler) owns credential retrieval + audit + claim emission.

export type LlmProvider = 'anthropic' | 'openai' | 'openrouter';

export interface LlmProviderConfig {
  /** Absolute URL for the provider's completions endpoint. */
  url: string;
  /** Header name carrying the API key. */
  authHeader: string;
  /** Optional auth-header value formatter. Default: identity. */
  formatAuth: (apiKey: string) => string;
  /** Additional headers required by the provider (e.g. anthropic-version). */
  extraHeaders: Record<string, string>;
  /**
   * Extracts a normalised usage object from the provider's non-streaming
   * response body. Returns null when the provider hasn't included usage
   * (e.g. error responses). Both Anthropic and OpenAI surface usage on
   * successful completions; OpenRouter passes OpenAI's shape through.
   */
  extractUsage: (body: unknown) => LlmUsage | null;
}

export interface LlmUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  /**
   * what the provider says it actually charged, in USD, when it says
   * so. OpenRouter returns this on every response and it is the billed amount:
   * cache discounts, provider routing and promo rates already applied. We were
   * throwing it away and recomputing from list price, which recorded several
   * times the real bill. Absent for providers that do not report cost.
   */
  provider_cost_usd?: number;
  /**
   * Prompt tokens served from the provider's cache, when reported. Cache reads
   * bill at a fraction of the input rate, so a cost estimated without them is
   * an over-estimate — badly so for an agent that re-sends its context every
   * turn, which is the normal shape.
   */
  cached_prompt_tokens?: number;
}

export interface LlmGatewayResult {
  status: number;
  /** Provider's JSON response body. Pass-through, no shape conversion. */
  body: unknown;
  /** Normalised usage if extractable; null otherwise. */
  usage: LlmUsage | null;
  /** Echoed model from the response if present. */
  model: string | null;
  /**
   * OpenRouter's generation id (`X-Generation-Id`, else a `gen-` body id), or
   * null. A STACK-key call that ends without reported usage is settled later
   * from the generation record under this id.
   */
  generationId: string | null;
}

/** OpenRouter generation ids, as its generation endpoint accepts them. */
const GENERATION_ID = /^gen-[0-9A-Za-z-]{1,124}$/;

function generationIdFrom(value: unknown): string | null {
  return typeof value === 'string' && GENERATION_ID.test(value) ? value : null;
}

export const LLM_PROVIDERS: Record<LlmProvider, LlmProviderConfig> = {
  anthropic: {
    url: 'https://api.anthropic.com/v1/messages',
    authHeader: 'x-api-key',
    formatAuth: (key) => key,
    extraHeaders: { 'anthropic-version': '2023-06-01' },
    extractUsage: (body) => {
      const b = body as { usage?: { input_tokens?: number; output_tokens?: number } };
      if (!b.usage || typeof b.usage.input_tokens !== 'number' || typeof b.usage.output_tokens !== 'number') {
        return null;
      }
      return {
        prompt_tokens: b.usage.input_tokens,
        completion_tokens: b.usage.output_tokens,
        total_tokens: b.usage.input_tokens + b.usage.output_tokens,
      };
    },
  },
  openai: {
    url: 'https://api.openai.com/v1/chat/completions',
    authHeader: 'authorization',
    formatAuth: (key) => `Bearer ${key}`,
    extraHeaders: {},
    extractUsage: (body) => {
      const b = body as {
        usage?: {
          prompt_tokens?: number;
          completion_tokens?: number;
          total_tokens?: number;
          prompt_tokens_details?: { cached_tokens?: number };
        };
      };
      if (!b.usage || typeof b.usage.prompt_tokens !== 'number' || typeof b.usage.completion_tokens !== 'number') {
        return null;
      }
      return {
        prompt_tokens: b.usage.prompt_tokens,
        completion_tokens: b.usage.completion_tokens,
        total_tokens: b.usage.total_tokens ?? b.usage.prompt_tokens + b.usage.completion_tokens,
        ...(typeof b.usage.prompt_tokens_details?.cached_tokens === 'number'
          ? { cached_prompt_tokens: b.usage.prompt_tokens_details.cached_tokens }
          : {}),
      };
    },
  },
  openrouter: {
    url: 'https://openrouter.ai/api/v1/chat/completions',
    authHeader: 'authorization',
    formatAuth: (key) => `Bearer ${key}`,
    extraHeaders: {},
    extractUsage: (body) => {
      // OpenRouter passes OpenAI's shape through and adds `cost` — the amount
      // it actually billed, which is the only figure worth recording.
      const b = body as {
        usage?: {
          prompt_tokens?: number;
          completion_tokens?: number;
          total_tokens?: number;
          cost?: number;
          prompt_tokens_details?: { cached_tokens?: number };
        };
      };
      if (!b.usage || typeof b.usage.prompt_tokens !== 'number' || typeof b.usage.completion_tokens !== 'number') {
        return null;
      }
      return {
        prompt_tokens: b.usage.prompt_tokens,
        completion_tokens: b.usage.completion_tokens,
        total_tokens: b.usage.total_tokens ?? b.usage.prompt_tokens + b.usage.completion_tokens,
        ...(typeof b.usage.cost === 'number' ? { provider_cost_usd: b.usage.cost } : {}),
        ...(typeof b.usage.prompt_tokens_details?.cached_tokens === 'number'
          ? { cached_prompt_tokens: b.usage.prompt_tokens_details.cached_tokens }
          : {}),
      };
    },
  },
};

/** The images endpoints, which are constants for the same reason the chat endpoints are: no caller names where a key goes. */
export const LLM_IMAGE_ENDPOINTS: Record<LlmImageProvider, { url: string }> = {
  openai: { url: 'https://api.openai.com/v1/images/generations' },
};

/** A generation can take as long as the model; this is the most STACK waits. */
const IMAGE_TIMEOUT_MS = 150_000;
/** Images come back as base64: this is the most of one answer STACK reads. */
const IMAGE_RESPONSE_MAX_BYTES = 40 * 1024 * 1024;

export interface LlmImageResult {
  status: number;
  /** The provider's JSON, as it came. */
  body: unknown;
}

/** The body of a response up to `max` bytes, or null when it is longer. */
async function readCapped(response: Response, max: number): Promise<string | null> {
  const declared = Number(response.headers.get('content-length') ?? '0');
  if (declared > max) return null;
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export interface LlmGatewayForwardArgs {
  provider: LlmProvider;
  apiKey: string;
  /** Request body already validated against the provider's Zod schema. */
  body: unknown;
}

export interface LlmGatewayStreamingResult {
  /**
   * complete SSE event blocks, in upstream order, each paired
   * with the assistant text it carries. Nothing is yielded until a block
   * is WHOLE, which is what lets the caller scan the text before it
   * forwards a single byte of that block. Replaces the tee'd
   * forward-branch + accumulatedTextPromise pair: with a tee, the bytes
   * had already left by the time the text was known, so an output scan on
   * a streamed response could only ever be a post-hoc notice.
   */
  events: AsyncGenerator<LlmStreamEvent>;
  /**
   * Parsed usage. Call AFTER the generator is exhausted — it returns null
   * until the terminal usage event has been walked (Anthropic's
   * `message_delta` carries it; OpenAI's penultimate chunk before [DONE]
   * carries it when stream_options.include_usage=true), and null forever
   * if the stream ends without one.
   */
  usage(): LlmUsage | null;
  /** Upstream HTTP status. 200 for happy path; 4xx/5xx for errors. */
  status: number;
  /**
   * OpenRouter's generation id: the `X-Generation-Id` header when sent,
   * otherwise the first `gen-` chunk id walked so far. Null for providers
   * without one, or when nothing identified the generation.
   */
  generationId(): string | null;
}

import type { LlmImageProvider, PiiScanOptions } from '@stack/shared';

/** One complete SSE event block plus the assistant text it carries. */
export interface LlmStreamEvent {
  /** Exact bytes to forward, separator included. */
  bytes: Uint8Array;
  /** Assistant text in this block; '' for usage/control/tool-only blocks. */
  text: string;
}

/**
 * Structural, not `PiiRedactor` itself: this package must not depend on the
 * concrete class to redact, and the tests inject a stub. Kept in sync with
 * PiiRedactor.redact by the compiler at the call site in apps/api.
 */
export interface PiiRedactorLike {
  redact(
    text: string,
    options?: PiiScanOptions,
  ): {
    redactedText: string;
    hits: number;
    categories: readonly string[];
    nearMisses: number;
    nearMissCategories: readonly string[];
  };
}

/** Running totals across every message in one request body. */
interface RedactionTally {
  hits: number;
  nearMisses: number;
  nearMissCategories: Set<string>;
}

export class LlmGatewayService {
  /**
   * walk user-role messages in the body and redact PII
   * via the injected PiiRedactor. Provider-specific (Anthropic has
   * `system` as a top-level field so user content is always role:user
   * in messages[]; OpenAI may include role:tool messages that carry
   * tool-output text we should also redact). System + assistant
   * messages are NEVER touched.
   *
   * Returns a deep clone — the caller's `body` reference stays
   * unchanged.
   *
   * `scanOptions` carries the operator's PII config (threshold + country
   * scope) down to the scanner. Omitted means built-in defaults, which is
   * what every caller did before per-operator config existed.
   */
  redactUserMessages(args: {
    provider: LlmProvider;
    body: unknown;
    redactor: PiiRedactorLike;
    scanOptions?: PiiScanOptions;
  }): { body: unknown; totalHits: number; nearMisses: number; nearMissCategories: string[] } {
    const body = JSON.parse(JSON.stringify(args.body)) as Record<string, unknown>;
    const acc: RedactionTally = { hits: 0, nearMisses: 0, nearMissCategories: new Set<string>() };
    if (args.provider === 'anthropic') {
      this.redactAnthropicUserMessages(body, args.redactor, acc, args.scanOptions);
    } else {
      // openai + openrouter share the messages-array shape
      this.redactOpenAIUserMessages(body, args.redactor, acc, args.scanOptions);
    }
    return {
      body,
      totalHits: acc.hits,
      nearMisses: acc.nearMisses,
      nearMissCategories: Array.from(acc.nearMissCategories),
    };
  }

  /** Fold one redact() result into the running tally and return the text to
   *  write back, or null when nothing changed. Near-misses accumulate even
   *  when there were no hits — a message can be all near-miss. */
  private tally(
    r: { redactedText: string; hits: number; nearMisses: number; nearMissCategories: readonly string[] },
    acc: RedactionTally,
  ): string | null {
    acc.nearMisses += r.nearMisses;
    for (const c of r.nearMissCategories) acc.nearMissCategories.add(c);
    if (r.hits === 0) return null;
    acc.hits += r.hits;
    return r.redactedText;
  }

  private redactAnthropicUserMessages(
    body: Record<string, unknown>,
    redactor: PiiRedactorLike,
    acc: RedactionTally,
    scanOptions?: PiiScanOptions,
  ): void {
    const messages = body.messages;
    if (!Array.isArray(messages)) return;
    for (const msg of messages as Array<Record<string, unknown>>) {
      if (msg.role !== 'user') continue;
      if (typeof msg.content === 'string') {
        const next = this.tally(redactor.redact(msg.content, scanOptions), acc);
        if (next !== null) msg.content = next;
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content as Array<Record<string, unknown>>) {
          if (block.type === 'text' && typeof block.text === 'string') {
            const next = this.tally(redactor.redact(block.text, scanOptions), acc);
            if (next !== null) block.text = next;
          }
        }
      }
    }
  }

  private redactOpenAIUserMessages(
    body: Record<string, unknown>,
    redactor: PiiRedactorLike,
    acc: RedactionTally,
    scanOptions?: PiiScanOptions,
  ): void {
    const messages = body.messages;
    if (!Array.isArray(messages)) return;
    for (const msg of messages as Array<Record<string, unknown>>) {
      // Only user + tool messages carry user-supplied text. System +
      // assistant are STACK-injected or prior model output.
      if (msg.role !== 'user' && msg.role !== 'tool') continue;
      if (typeof msg.content === 'string') {
        const next = this.tally(redactor.redact(msg.content, scanOptions), acc);
        if (next !== null) msg.content = next;
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content as Array<Record<string, unknown>>) {
          if (part.type === 'text' && typeof part.text === 'string') {
            const next = this.tally(redactor.redact(part.text, scanOptions), acc);
            if (next !== null) part.text = next;
          }
        }
      }
    }
  }

  /**
   * extract ONLY the untrusted-role text for the inbound
   * injection scan. The same trust boundary the PII redactor uses:
   * user + tool messages are attacker-influenceable; system + assistant
   * are the operator's own runtime prompt / prior model output and must
   * NOT be classified. Scanning the full transcript (the old behavior)
   * made L3 flag an agent's own OpenClaw system prompt as injection —
   * 5x critical@92 on FamilyBot's normal traffic — which would deny all
   * of it under `enforced`.
   *
   * SECURITY: the trust anchor is the ROLE the provider assigns, and a
   * client cannot forge a `system`/`assistant` role for content it wants
   * scanned-around: STACK controls the system message (5.2.2 injection
   * runs after this) and assistant messages are prior model output. A
   * caller putting an attack in a fake assistant message only poisons
   * its OWN next turn's context, which is its prerogative — the threat
   * model is protecting the agent from EXTERNAL data (retrieved docs,
   * user input, tool output), all of which stay in scanned roles.
   *
   * Returns the concatenated untrusted text (newline-joined) for the
   * detector, plus the count of untrusted messages seen (0 → the caller
   * may skip L3 entirely).
   */
  extractUntrustedText(args: { provider: LlmProvider; body: unknown }): {
    text: string;
    untrustedCount: number;
  } {
    const body = args.body as Record<string, unknown> | null;
    const messages = body?.messages;
    if (!Array.isArray(messages)) return { text: '', untrustedCount: 0 };
    const parts: string[] = [];
    let untrustedCount = 0;
    for (const msg of messages as Array<Record<string, unknown>>) {
      // Anthropic has no role:tool (system is a top-level field, so all
      // messages[] entries are user/assistant); openai/openrouter add
      // role:tool for tool output. Both: user + tool are untrusted.
      if (msg.role !== 'user' && msg.role !== 'tool') continue;
      untrustedCount++;
      if (typeof msg.content === 'string') {
        parts.push(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content as Array<Record<string, unknown>>) {
          if (block.type === 'text' && typeof block.text === 'string') parts.push(block.text);
        }
      }
    }
    return { text: parts.join('\n'), untrustedCount };
  }

  /**
   * Forward a non-streaming LLM call to the provider. The body must be
   * pre-validated against the provider's Zod schema; this method makes
   * no assumptions about shape beyond what extractUsage expects.
   *
   * Returns { status, body, usage, model }. Error responses from the
   * provider propagate as-is (status + body); the caller decides how
   * to surface them. Network/parse errors throw.
   */
  async forward(args: LlmGatewayForwardArgs): Promise<LlmGatewayResult> {
    const config = LLM_PROVIDERS[args.provider];
    const headers: Record<string, string> = {
      [config.authHeader]: config.formatAuth(args.apiKey),
      'content-type': 'application/json',
      ...config.extraHeaders,
    };
    const response = await fetch(config.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(args.body),
    });
    const body = await response.json().catch(() => ({ error: 'invalid_json_response' }));
    // Usage is read on error responses too: a provider that billed a failed
    // call reports what it charged, and a STACK-key call must pass that on.
    // The customer-key path records usage only on success, as before.
    const usage = config.extractUsage(body);
    const model = (body as { model?: string }).model ?? null;
    const generationId = generationIdFrom(response.headers.get('x-generation-id'))
      ?? generationIdFrom((body as { id?: unknown } | null)?.id);
    return {
      status: response.status,
      body,
      usage,
      model,
      generationId,
    };
  }

  /**
   * Forward an image request to the provider's images endpoint with the customer's own key (never STACK's:
   * the account's STACK-key images are made by the image client of the tools). The host is a constant, the body is
   * what the route built from the fields it accepts, the key goes in the provider's own header and nowhere else, and
   * the answer is read whole, capped, and handed back as it came: the route decides what the caller sees of it.
   * A request that never leaves (no network) throws; a provider's refusal comes back as its status and body.
   */
  async forwardImages(args: { provider: LlmImageProvider; apiKey: string; body: Record<string, unknown>; fetch?: typeof fetch }): Promise<LlmImageResult> {
    const target = LLM_IMAGE_ENDPOINTS[args.provider];
    const auth = LLM_PROVIDERS[args.provider];
    const response = await (args.fetch ?? fetch)(target.url, {
      method: 'POST',
      headers: {
        [auth.authHeader]: auth.formatAuth(args.apiKey),
        'content-type': 'application/json',
        ...auth.extraHeaders,
      },
      body: JSON.stringify(args.body),
      redirect: 'error',
      signal: AbortSignal.timeout(IMAGE_TIMEOUT_MS),
    });
    const text = await readCapped(response, IMAGE_RESPONSE_MAX_BYTES);
    let body: unknown;
    try {
      body = text === null ? { error: 'response_too_large' } : JSON.parse(text);
    } catch {
      body = { error: 'invalid_json_response' };
    }
    return { status: text === null ? 502 : response.status, body };
  }

  /**
   * Forward a streaming LLM call to the provider. Returns a generator of
   * complete SSE event blocks, each carrying both the bytes to forward and
   * the assistant text inside them, so the caller decides per block whether
   * those bytes leave.
   *
   * An earlier change replaced a `tee` here. The old shape handed the caller one
   * branch to pipe verbatim and parsed the other in parallel, which meant
   * the text was only known once every byte of it had already been written
   * to the client. An output scan on that shape cannot refuse anything; it
   * can only describe what already happened. One pass, blocks held until
   * whole, and the decision moves in front of the write.
   *
   * Usage still comes from the terminal event (Anthropic's `message_delta`;
   * OpenAI's penultimate chunk before `[DONE]` when
   * stream_options.include_usage=true) and is readable via `usage()` once
   * the generator is exhausted.
   */
  async forwardStreaming(args: LlmGatewayForwardArgs): Promise<LlmGatewayStreamingResult> {
    const config = LLM_PROVIDERS[args.provider];
    const headers: Record<string, string> = {
      [config.authHeader]: config.formatAuth(args.apiKey),
      'content-type': 'application/json',
      accept: 'text/event-stream',
      ...config.extraHeaders,
    };
    const response = await fetch(config.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(args.body),
    });

    if (!response.body) {
      throw new Error(`[LlmGatewayService] upstream returned no body (status ${response.status})`);
    }

    const state: StreamState = {
      usage: null,
      generationId: generationIdFrom(response.headers.get('x-generation-id')),
    };
    return {
      events: streamSseEvents(response.body, args.provider, state),
      usage: () => state.usage,
      status: response.status,
      generationId: () => state.generationId,
    };
  }
}

/**
 * Walk an SSE stream once, yielding one complete event block at a time with
 * the assistant text it carries. Provider-specific event shapes:
 *
 *   Anthropic:
 *     - `event: content_block_delta\ndata: {"delta":{"type":"text_delta","text":"..."}}` — text chunks
 *     - `event: message_delta\ndata: {"usage":{...}}` — final usage
 *   OpenAI / OpenRouter:
 *     - `data: {"choices":[{"delta":{"content":"..."}}]}` — text chunks
 *     - penultimate `data: {...,"usage":{...}}` before `data: [DONE]` — usage
 *       (requires stream_options.include_usage=true; null otherwise)
 *
 * A block is held until its separator arrives, because a caller cannot decide
 * whether to forward bytes whose text it has not seen. The separator is
 * whichever of `\n\n` or `\r\n\r\n` appears first: the old parser looked only
 * for `\n\n`, so a CRLF provider silently accumulated its whole response into
 * one final flush and never extracted a single text delta.
 *
 * `usage` is written through the shared state object rather than returned, so
 * the caller can read it after exhausting the generator without a second
 * promise to await.
 */
interface StreamState {
  usage: LlmUsage | null;
  generationId: string | null;
}

async function* streamSseEvents(
  stream: ReadableStream<Uint8Array>,
  provider: LlmProvider,
  state: StreamState,
): AsyncGenerator<LlmStreamEvent> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const config = LLM_PROVIDERS[provider];
  let buffer = '';

  /** Earliest event separator in `buffer`, or null when none is complete yet. */
  function nextSeparator(): { at: number; len: number } | null {
    const lf = buffer.indexOf('\n\n');
    const crlf = buffer.indexOf('\r\n\r\n');
    if (lf === -1 && crlf === -1) return null;
    if (crlf !== -1 && (lf === -1 || crlf < lf)) return { at: crlf, len: 4 };
    return { at: lf, len: 2 };
  }

  /** Assistant text carried by one event block; also harvests usage. */
  function textOf(block: string): string {
    let text = '';
    for (const line of block.split('\n')) {
      const trimmed = line.endsWith('\r') ? line.slice(0, -1) : line;
      if (!trimmed.startsWith('data: ')) continue;
      const payload = trimmed.slice(6).trim();
      if (payload === '[DONE]' || payload === '') continue;
      try {
        const parsed = JSON.parse(payload) as Record<string, unknown>;
        if (state.generationId === null) state.generationId = generationIdFrom(parsed.id);
        if (parsed.usage) {
          const candidate = config.extractUsage(parsed);
          if (candidate) state.usage = candidate;
        }
        if (provider === 'anthropic') {
          const delta = (parsed as { delta?: { type?: string; text?: string } }).delta;
          if (delta?.type === 'text_delta' && typeof delta.text === 'string') text += delta.text;
        } else {
          // openai + openrouter share the chat-completion shape
          const choices = (parsed as { choices?: Array<{ delta?: { content?: unknown } }> }).choices;
          if (Array.isArray(choices)) {
            for (const ch of choices) {
              const content = ch.delta?.content;
              if (typeof content === 'string') text += content;
            }
          }
        }
      } catch {
        // ignore non-JSON data lines (e.g. partial chunks at boundaries)
      }
    }
    return text;
  }

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let sep = nextSeparator();
      while (sep) {
        const block = buffer.slice(0, sep.at + sep.len);
        buffer = buffer.slice(sep.at + sep.len);
        yield { bytes: encoder.encode(block), text: textOf(block) };
        sep = nextSeparator();
      }
    }
    // Trailing bytes with no separator: a provider that ends without a final
    // blank line, or an error body that is not SSE at all. Forward it, having
    // read it, rather than dropping it.
    buffer += decoder.decode();
    if (buffer.length > 0) {
      yield { bytes: encoder.encode(buffer), text: textOf(buffer) };
    }
  } finally {
    reader.releaseLock();
  }
}
