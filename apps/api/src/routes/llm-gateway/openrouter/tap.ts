// What the gateway reads of an OpenRouter answer while it passes it on: what the call cost, which generation it was, and
// (for the data trail) a bounded sample of the words in it. The bytes themselves are never changed or held back by this.
//
// Cost is `usage.cost`, which OpenRouter puts in the body of every answer that has a body of its own (text, embeddings,
// rerank, images, transcription) and in the last event of a stream, in a message or a response event as well as a chat
// chunk. An answer with no body of the kind (speech: audio bytes) has no cost here; the generation id from its headers
// is what prices it later.

import type { LlmUsage } from '@stack/vault';

const HEAD_BYTES = 64 * 1024;
const TAIL_BYTES = 128 * 1024;
/** A JSON answer up to this size is parsed whole; a larger one is read for its `usage` object from the end of it. */
const WHOLE_JSON_BYTES = 8 * 1024 * 1024;
/** An event line larger than this is read for its `usage` object only. */
const PARSE_LINE_BYTES = 256 * 1024;
const TEXT_SAMPLE_CHARS = 64 * 1024;

const GENERATION_ID = /"id"\s*:\s*"(gen-[A-Za-z0-9-]{1,124})"/;
/** The last `usage` object in a piece of text: one level of nesting inside it is read (cost details, token details). */
const USAGE_OBJECT = /"usage"\s*:\s*(\{(?:[^{}]|\{[^{}]*\})*\})/g;

function number(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value)) && Number(value) >= 0) return Number(value);
  return undefined;
}

function tokens(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

/** A `usage` object read as the gateway records usage; `provider_cost_usd` only when OpenRouter reported a cost. */
export function readUsage(usage: unknown): LlmUsage | null {
  if (usage === null || typeof usage !== 'object' || Array.isArray(usage)) return null;
  const record = usage as Record<string, unknown>;
  const prompt = tokens(record['prompt_tokens'] ?? record['input_tokens']);
  const completion = tokens(record['completion_tokens'] ?? record['output_tokens']);
  const total = tokens(record['total_tokens']) || prompt + completion;
  const cost = number(record['cost']);
  const details = record['prompt_tokens_details'];
  const cached = details && typeof details === 'object' ? number((details as Record<string, unknown>)['cached_tokens']) : undefined;
  if (cost === undefined && prompt === 0 && completion === 0 && total === 0) return null;
  return {
    prompt_tokens: prompt,
    completion_tokens: completion,
    total_tokens: total,
    ...(cost !== undefined ? { provider_cost_usd: cost } : {}),
    ...(cached !== undefined ? { cached_prompt_tokens: Math.floor(cached) } : {}),
  };
}

/** Where an answer keeps its `usage`: at the top (chat, embeddings, images), or in a response or message event. */
function usageIn(parsed: unknown): LlmUsage | null {
  if (parsed === null || typeof parsed !== 'object') return null;
  const record = parsed as Record<string, unknown>;
  return readUsage(record['usage'])
    ?? readUsage((record['response'] as Record<string, unknown> | undefined)?.['usage'])
    ?? readUsage((record['message'] as Record<string, unknown> | undefined)?.['usage']);
}

/** The last `usage` object in a text, for an answer too large to parse whole. */
export function usageFromText(text: string): LlmUsage | null {
  let found: LlmUsage | null = null;
  for (const match of text.matchAll(USAGE_OBJECT)) {
    try {
      found = readUsage(JSON.parse(match[1]!)) ?? found;
    } catch {
      // An object cut off by the window is not one; the next match, if any, is.
    }
  }
  return found;
}

/** The words an event of a stream carries: a chat delta, an Anthropic text delta, a Responses text delta. */
function wordsIn(parsed: unknown): string {
  if (parsed === null || typeof parsed !== 'object') return '';
  const record = parsed as Record<string, unknown>;
  let out = '';
  if (Array.isArray(record['choices'])) {
    for (const choice of record['choices'] as unknown[]) {
      const delta = choice && typeof choice === 'object' ? (choice as Record<string, unknown>)['delta'] : null;
      const content = delta && typeof delta === 'object' ? (delta as Record<string, unknown>)['content'] : null;
      if (typeof content === 'string') out += content;
    }
  }
  const delta = record['delta'];
  if (typeof delta === 'string' && typeof record['type'] === 'string' && (record['type'] as string).endsWith('.delta')) out += delta;
  else if (delta && typeof delta === 'object' && typeof (delta as Record<string, unknown>)['text'] === 'string') {
    out += (delta as Record<string, string>)['text'];
  }
  return out;
}

export interface TapResult {
  /** Bytes of the answer's body that passed through. */
  bytes: number;
  /** The usage the answer carried; it counts as a reported cost only with `provider_cost_usd`. */
  usage: LlmUsage | null;
  /** The generation the answer belongs to (`X-Generation-Id`, else the id in the body), or null. */
  generationId: string | null;
  /** The answer parsed whole, when it is JSON and small enough; null otherwise. */
  json: unknown;
  /** Up to 64 KiB of the words in the answer, when the tap was asked for them. */
  text: string;
  /** The start of the answer as text, for the audit record's entropy. */
  sample: string;
}

export class ResponseTap {
  private bytes = 0;
  private readonly head: Buffer[] = [];
  private headBytes = 0;
  private readonly tail: Buffer[] = [];
  private tailBytes = 0;
  private whole: Buffer[] | null = [];
  private readonly sse: boolean;
  private readonly decoder = new TextDecoder('utf-8');
  private pending = '';
  private streamUsage: LlmUsage | null = null;
  private streamGeneration: string | null = null;
  private streamText = '';

  constructor(
    private readonly options: { contentType: string; generationIdHeader: string | null; wantText: boolean },
  ) {
    this.sse = /^text\/event-stream/i.test(options.contentType);
    if (this.sse) this.whole = null;
  }

  push(chunk: Uint8Array): void {
    this.bytes += chunk.byteLength;
    const buffer = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    if (this.headBytes < HEAD_BYTES) {
      const take = buffer.subarray(0, HEAD_BYTES - this.headBytes);
      this.head.push(take);
      this.headBytes += take.length;
    }
    if (this.sse) {
      this.pending += this.decoder.decode(buffer, { stream: true });
      this.readLines();
      return;
    }
    this.tail.push(buffer);
    this.tailBytes += buffer.length;
    while (this.tail.length > 1 && this.tailBytes - this.tail[0]!.length >= TAIL_BYTES) {
      this.tailBytes -= this.tail.shift()!.length;
    }
    if (this.whole) {
      if (this.bytes > WHOLE_JSON_BYTES) this.whole = null;
      else this.whole.push(buffer);
    }
  }

  private readLines(): void {
    for (;;) {
      const at = this.pending.indexOf('\n');
      if (at === -1) break;
      const line = this.pending.slice(0, at).replace(/\r$/, '');
      this.pending = this.pending.slice(at + 1);
      this.readLine(line);
    }
    // A line with no end in sight is read for its usage from its tail, then dropped, so memory stays bounded.
    if (this.pending.length > PARSE_LINE_BYTES) {
      this.readLine(this.pending.slice(-TAIL_BYTES));
      this.pending = '';
    }
  }

  private readLine(line: string): void {
    if (!line.startsWith('data:')) return;
    const payload = line.slice(5).trim();
    if (payload === '' || payload === '[DONE]') return;
    if (this.streamGeneration === null) this.streamGeneration = GENERATION_ID.exec(payload.slice(0, 2048))?.[1] ?? null;
    const mayCarryUsage = payload.includes('"usage"');
    if (!mayCarryUsage && !(this.options.wantText && this.streamText.length < TEXT_SAMPLE_CHARS)) return;
    if (payload.length > PARSE_LINE_BYTES) {
      if (mayCarryUsage) this.streamUsage = usageFromText(payload.slice(-TAIL_BYTES)) ?? this.streamUsage;
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      return;
    }
    if (mayCarryUsage) this.streamUsage = usageIn(parsed) ?? this.streamUsage;
    if (this.options.wantText && this.streamText.length < TEXT_SAMPLE_CHARS) {
      this.streamText = (this.streamText + wordsIn(parsed)).slice(0, TEXT_SAMPLE_CHARS);
    }
  }

  result(): TapResult {
    const sample = Buffer.concat(this.head).toString('utf8').slice(0, 4096);
    const generationId = this.options.generationIdHeader
      ?? (this.sse ? this.streamGeneration : GENERATION_ID.exec(Buffer.concat(this.head).toString('utf8'))?.[1] ?? null);
    if (this.sse) {
      if (this.pending) {
        this.readLine(this.pending.replace(/\r$/, ''));
        this.pending = '';
      }
      return { bytes: this.bytes, usage: this.streamUsage, generationId, json: null, text: this.streamText, sample };
    }
    let json: unknown = null;
    let usage: LlmUsage | null = null;
    if (this.whole && this.whole.length > 0 && /json/i.test(this.options.contentType)) {
      try {
        json = JSON.parse(Buffer.concat(this.whole).toString('utf8'));
        usage = usageIn(json);
      } catch {
        json = null;
      }
    }
    if (json === null && /json/i.test(this.options.contentType)) {
      usage = usageFromText(Buffer.concat(this.tail).toString('utf8'));
    }
    return { bytes: this.bytes, usage, generationId, json, text: '', sample };
  }
}
