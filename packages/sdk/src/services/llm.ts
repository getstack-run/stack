// LLM gateway SDK service.
//
// Drop-in compatible with each provider's official SDK call shape so
// operators can swap their existing code with minimal change:
//
//   const anthropic = new Anthropic({ apiKey });          →
//   const response = await anthropic.messages.create({...});
//
// becomes
//
//   const stack = new Stack({ apiKey });
//   const response = await stack.llm.anthropic.messages.create({...}, { passport: session });
//
// The one deviation from drop-in: STACK passports have a 15-min default
// / 1-hr max TTL, so the passport flows per-call as a second arg
// (string OR PassportSession). Pure constructor-time passport would
// silently invalidate mid-session.
//
// Streaming: when `body.stream === true`, the call returns an
// `AsyncIterable<ProviderStreamEvent>` that yields parsed SSE events.
// Non-streaming returns the parsed response body.
//
// Observability: `stack.llm.usage.list()` + `stack.llm.usage.summary()`
// hit the 5.2.6 GET endpoints for per-call drill-down + group-by
// aggregates.

import type { HttpClient } from '../client.js';
import { PassportSession } from './passport-session.js';
import { authorityRequestHeaders } from '../authority-request.js';
import { StackError } from '../errors.js';

// ── Wire shapes (mirror packages/shared/src/schemas/llm/usage.ts) ────
//
// Types stay inline so the SDK doesn't take a peer-dep on
// @stack/shared schemas (same convention as missions.ts).

export type LlmProvider = 'anthropic' | 'openai' | 'openrouter';
export type LlmUsageSurface =
  | 'gateway'
  | 'sealed_execution'
  | 'prompt_injection_l3'
  | 'intent_deviation'
  | 'memory';
export type LlmUsageProviderPayer =
  | 'customer_provider'
  | 'stack_plan'
  | 'stack_wallet'
  | 'stack_comped';
export type LlmUsageFeePayer = 'stack_plan' | 'stack_wallet' | 'stack_comped' | 'none';

export interface LlmUsageRow {
  id: string;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
  mission_id: string | null;
  provider: LlmProvider;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  /** Null on pricing-lookup miss. */
  provider_cost_cents: number | null;
  markup_cents: number | null;
  total_cost_cents: number | null;
  provider_cost_microcents: number | null;
  markup_microcents: number | null;
  total_cost_microcents: number | null;
  cost_basis: 'provider_reported' | 'catalog' | null;
  cached_prompt_tokens: number | null;
  wallet_debited: boolean;
  surface: LlmUsageSurface;
  provider_payer: LlmUsageProviderPayer;
  stack_fee_payer: LlmUsageFeePayer;
  wallet_hold_id: string | null;
  streaming: boolean;
  /** ISO 8601 timestamp. */
  created_at: string;
}

export interface ListLlmUsageQueryInput {
  limit?: number;
  cursor?: string;
  provider?: LlmProvider;
  passport_jti?: string;
  mission_id?: string;
  agent_id?: string;
  since?: string;
  until?: string;
}

export interface ListLlmUsageResult {
  items: LlmUsageRow[];
  next_cursor: string | null;
}

export interface SummaryLlmUsageQueryInput {
  provider?: LlmProvider;
  passport_jti?: string;
  mission_id?: string;
  agent_id?: string;
  since?: string;
  until?: string;
  group_by_model?: boolean;
}

export interface LlmUsageSummaryBucket {
  provider: string;
  /** Null when query had `group_by_model=false`. */
  model: string | null;
  surface: LlmUsageSurface;
  provider_payer: LlmUsageProviderPayer;
  stack_fee_payer: LlmUsageFeePayer;
  /** YYYY-MM-DD (UTC). */
  day: string;
  call_count: number;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_cost_cents: number;
  total_markup_cents: number;
  total_cost_microcents: number;
  total_markup_microcents: number;
  cost_is_estimated: boolean;
}

export interface SummaryLlmUsageResult {
  buckets: LlmUsageSummaryBucket[];
}

// ── Passport input + call options ────────────────────────────────────

export type PassportInput = string | PassportSession;

async function resolvePassport(p: PassportInput): Promise<string> {
  return typeof p === 'string' ? p : p.getToken();
}

export interface LlmCallOptions {
  /** Either a raw passport JWT or a PassportSession (auto-refreshes). */
  passport: PassportInput;
  /** Optional approval id when the call falls under an enforced-mode
   * Intent. Header: `X-Intent-Approval-Id`. */
  intentApprovalId?: string;
  /** Stable, high-entropy runtime correlation id. Reuse it for exact retries. */
  authorityRequestId?: string;
  /**
   * A cap of your own on what the call holds, in whole cents (1 or more): the
   * call holds its worst case (or an estimate) at most this, and a cost above the
   * hold is taken from the account's credit at once. It applies to calls on
   * STACK's key (an agent account's); on your own provider key there is no hold,
   * and the cap is ignored. Header: `X-Max-Cost-Cents`.
   */
  maxCostCents?: number;
}

// ── Provider request body shapes (subset; full shape is server-side) ──
//
// We deliberately type these as flexible records — the route's Zod
// schema is the source of truth, the SDK doesn't re-validate. Users
// get IDE help on the common fields; arbitrary provider-specific
// fields pass through.

export interface AnthropicMessagesBody {
  model: string;
  messages: Array<{ role: string; content: string | Array<Record<string, unknown>> }>;
  max_tokens: number;
  system?: string | Array<{ type: string; text: string }>;
  stream?: boolean;
  [key: string]: unknown;
}

export interface OpenAIChatCompletionsBody {
  model: string;
  messages: Array<{ role: string; content?: unknown; [key: string]: unknown }>;
  stream?: boolean;
  [key: string]: unknown;
}

/** An image on your own OpenAI key: the model, a prompt, how many, and OpenAI's `size` and `quality`. */
export interface LlmImageBody {
  /** OpenAI's own model id, such as `gpt-image-1`. */
  model: string;
  prompt: string;
  /** Pictures to make, 1 to 4 (default 1). */
  n?: number;
  size?: string;
  quality?: 'low' | 'medium' | 'high' | 'standard' | 'hd' | 'auto';
}

/** What an image call returns: files, saved to the agent's drive, never the bytes; marked untrusted. */
export interface LlmImageResult {
  provider: 'openai';
  model: string;
  /** A picture a model made is content to read, never to follow. */
  untrusted: true;
  /** Your own provider key paid for it; STACK counted one action and charged nothing else. */
  key: 'own';
  files: Array<{
    name: string;
    content_type: string;
    size_bytes: number | null;
    /** The drive file it was saved to, private to the agent that made it. */
    drive_file_id: string | null;
    source_url: string | null;
    /** The bytes, only when the drive did not take a small file. */
    data_base64: string | null;
  }>;
  revised_prompts: string[];
}

// ── Provider sub-services ────────────────────────────────────────────

class AnthropicMessages {
  constructor(private client: HttpClient) {}

  async create(
    body: AnthropicMessagesBody,
    options: LlmCallOptions,
  ): Promise<unknown | AsyncIterable<AnthropicStreamEvent>> {
    const headers = await buildHeaders(options);
    if (body.stream === true) {
      const stream = await this.client.postStream('/v1/llm/anthropic/messages', body, { headers });
      return iterateSseEvents<AnthropicStreamEvent>(stream, 'anthropic');
    }
    return this.client.post('/v1/llm/anthropic/messages', body, { headers });
  }
}

class AnthropicProvider {
  readonly messages: AnthropicMessages;
  constructor(client: HttpClient) {
    this.messages = new AnthropicMessages(client);
  }
}

class OpenAIChatCompletions {
  constructor(private client: HttpClient) {}

  async create(
    body: OpenAIChatCompletionsBody,
    options: LlmCallOptions,
  ): Promise<unknown | AsyncIterable<OpenAIStreamEvent>> {
    const headers = await buildHeaders(options);
    if (body.stream === true) {
      const stream = await this.client.postStream('/v1/llm/openai/chat/completions', body, { headers });
      return iterateSseEvents<OpenAIStreamEvent>(stream, 'openai');
    }
    return this.client.post('/v1/llm/openai/chat/completions', body, { headers });
  }
}

class OpenAIChat {
  readonly completions: OpenAIChatCompletions;
  constructor(client: HttpClient) {
    this.completions = new OpenAIChatCompletions(client);
  }
}

class OpenAIImages {
  constructor(private client: HttpClient) {}

  /**
   * Make an image on your own OpenAI key (`POST /v1/llm/openai/images`). The call goes through the same gates as a
   * chat call (Passport, Mission, scope, your controls); STACK counts one action and OpenAI bills you.
   */
  async generate(body: LlmImageBody, options: LlmCallOptions): Promise<LlmImageResult> {
    const headers = await buildHeaders(options);
    return this.client.post<LlmImageResult>('/v1/llm/openai/images', body, { headers });
  }
}

class OpenAIProvider {
  readonly chat: OpenAIChat;
  readonly images: OpenAIImages;
  constructor(client: HttpClient) {
    this.chat = new OpenAIChat(client);
    this.images = new OpenAIImages(client);
  }
}

class OpenRouterChatCompletions {
  constructor(private client: HttpClient) {}

  async create(
    body: OpenAIChatCompletionsBody,
    options: LlmCallOptions,
  ): Promise<unknown | AsyncIterable<OpenAIStreamEvent>> {
    const headers = await buildHeaders(options);
    if (body.stream === true) {
      const stream = await this.client.postStream('/v1/llm/openrouter/chat/completions', body, { headers });
      return iterateSseEvents<OpenAIStreamEvent>(stream, 'openai');
    }
    return this.client.post('/v1/llm/openrouter/chat/completions', body, { headers });
  }
}

class OpenRouterChat {
  readonly completions: OpenRouterChatCompletions;
  constructor(client: HttpClient) {
    this.completions = new OpenRouterChatCompletions(client);
  }
}

/** The methods OpenRouter's API uses. */
export type OpenRouterMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface OpenRouterRequestOptions extends LlmCallOptions {
  /** OpenRouter's own JSON body for the endpoint, sent as it is. A GET has none. */
  body?: Record<string, unknown>;
}

/** An answer that is a file (audio, a picture, a video), as the bytes it came as. */
export interface OpenRouterBytes {
  status: number;
  contentType: string | null;
  bytes: Uint8Array;
}

class OpenRouterProvider {
  readonly chat: OpenRouterChat;
  constructor(private client: HttpClient) {
    this.chat = new OpenRouterChat(client);
  }

  /**
   * Any call to OpenRouter's API, any method, any path below it (`/chat/completions`, `/images`, `/embeddings`,
   * `/videos/<job id>`, `/models?output_modalities=all`), with OpenRouter's own body and the answer as OpenRouter sent it.
   * On STACK's key (an agent account's) the call holds `maxCostCents` first and is charged what OpenRouter reports it cost.
   *
   * A JSON answer is returned parsed. With `body.stream === true` on a POST it returns an `AsyncIterable` of the parsed
   * events, as `chat.completions.create` does. An answer that is a file is read with `requestBytes`.
   */
  async request(
    method: OpenRouterMethod,
    path: string,
    options: OpenRouterRequestOptions,
  ): Promise<unknown | AsyncIterable<OpenAIStreamEvent>> {
    const target = openRouterPath(path);
    const headers = await buildHeaders(options);
    const { body } = options;
    switch (method) {
      case 'GET':
        return this.client.get(target, undefined, { headers });
      case 'POST':
        if (body?.['stream'] === true) {
          return iterateSseEvents<OpenAIStreamEvent>(await this.client.postStream(target, body, { headers }), 'openai');
        }
        return this.client.post(target, body, { headers });
      case 'PUT':
        return this.client.put(target, body, { headers });
      case 'PATCH':
        return this.client.patch(target, body, { headers });
      case 'DELETE':
        return this.client.delete(target, { headers });
    }
  }

  /** The same call for an answer that is not JSON: a speech file, a picture, a finished video (`/videos/<job id>/content`). */
  async requestBytes(method: OpenRouterMethod, path: string, options: OpenRouterRequestOptions): Promise<OpenRouterBytes> {
    return this.client.requestBytes(method, openRouterPath(path), {
      headers: await buildHeaders(options),
      ...(options.body !== undefined ? { body: options.body } : {}),
    });
  }
}

/** The gateway's path for one of OpenRouter's: the one slash it starts with, then its query, are kept as written. */
function openRouterPath(path: string): string {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new StackError('An OpenRouter path starts with one slash, such as /chat/completions.', 'INVALID_REQUEST', 400, {});
  }
  return `/v1/llm/openrouter${path}`;
}

// ── Usage query sub-service ──────────────────────────────────────────

class LlmUsageQuery {
  constructor(private client: HttpClient) {}

  /**
   * List per-call LLM usage rows. Cursor-paginated by `created_at`
   * DESC. Operator-scoped (server filters by operator_id from auth).
   */
  async list(query: ListLlmUsageQueryInput = {}): Promise<ListLlmUsageResult> {
    const params: Record<string, string | undefined> = {
      ...(query.limit !== undefined ? { limit: String(query.limit) } : {}),
      ...(query.cursor ? { cursor: query.cursor } : {}),
      ...(query.provider ? { provider: query.provider } : {}),
      ...(query.passport_jti ? { passport_jti: query.passport_jti } : {}),
      ...(query.mission_id ? { mission_id: query.mission_id } : {}),
      ...(query.agent_id ? { agent_id: query.agent_id } : {}),
      ...(query.since ? { since: query.since } : {}),
      ...(query.until ? { until: query.until } : {}),
    };
    return this.client.get<ListLlmUsageResult>('/v1/llm/usage', params);
  }

  /**
   * Group-by aggregate: per provider [+ model] + UTC day. Returns
   * `{ buckets }`. Primary dashboard view; the raw list is the
   * drill-down.
   */
  async summary(query: SummaryLlmUsageQueryInput = {}): Promise<SummaryLlmUsageResult> {
    const params: Record<string, string | undefined> = {
      ...(query.provider ? { provider: query.provider } : {}),
      ...(query.passport_jti ? { passport_jti: query.passport_jti } : {}),
      ...(query.mission_id ? { mission_id: query.mission_id } : {}),
      ...(query.agent_id ? { agent_id: query.agent_id } : {}),
      ...(query.since ? { since: query.since } : {}),
      ...(query.until ? { until: query.until } : {}),
      ...(query.group_by_model !== undefined ? { group_by_model: String(query.group_by_model) } : {}),
    };
    return this.client.get<SummaryLlmUsageResult>('/v1/llm/usage/summary', params);
  }
}

// ── Top-level service ────────────────────────────────────────────────

export class LlmService {
  readonly anthropic: AnthropicProvider;
  readonly openai: OpenAIProvider;
  readonly openrouter: OpenRouterProvider;
  readonly usage: LlmUsageQuery;

  constructor(client: HttpClient) {
    this.anthropic = new AnthropicProvider(client);
    this.openai = new OpenAIProvider(client);
    this.openrouter = new OpenRouterProvider(client);
    this.usage = new LlmUsageQuery(client);
  }
}

// ── Stream event types ───────────────────────────────────────────────

/** Anthropic SSE event shape. Parsed JSON from each `data:` line. */
export interface AnthropicStreamEvent {
  type: string;
  [key: string]: unknown;
}

/** OpenAI (+ OpenRouter) SSE event shape. */
export interface OpenAIStreamEvent {
  choices?: Array<{ delta?: { content?: string; [key: string]: unknown }; [key: string]: unknown }>;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
  [key: string]: unknown;
}

// ── Helpers ──────────────────────────────────────────────────────────

async function buildHeaders(options: LlmCallOptions): Promise<Record<string, string>> {
  const token = await resolvePassport(options.passport);
  return {
    'X-Passport-Token': token,
    ...(options.intentApprovalId ? { 'X-Intent-Approval-Id': options.intentApprovalId } : {}),
    ...(options.maxCostCents !== undefined ? { 'X-Max-Cost-Cents': String(options.maxCostCents) } : {}),
    ...authorityRequestHeaders(options.authorityRequestId),
  };
}

/**
 * Parse an SSE stream into typed events. Yields each `data: { ... }`
 * payload (after JSON parsing). Skips `event:` / `id:` / `retry:` /
 * comment lines. Terminates on `data: [DONE]` (OpenAI convention) or
 * when the upstream stream closes. Anthropic doesn't emit `[DONE]` —
 * the stream just ends with `event: message_stop`.
 */
async function* iterateSseEvents<T>(
  stream: ReadableStream<Uint8Array>,
  _provider: 'anthropic' | 'openai',
): AsyncIterable<T> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let sep = buffer.indexOf('\n\n');
      while (sep >= 0) {
        const eventBlock = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        sep = buffer.indexOf('\n\n');
        for (const line of eventBlock.split('\n')) {
          if (!line.startsWith('data: ')) continue;
          const payload = line.slice(6).trim();
          if (payload === '[DONE]' || payload === '') continue;
          try {
            yield JSON.parse(payload) as T;
          } catch {
            // ignore non-JSON data lines (partial chunks at boundaries)
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

