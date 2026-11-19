// What one call on STACK's OpenRouter key holds on the wallet before it is sent: the most it can cost where that can be worked
// out, and an estimate built from the model's own listed prices and a named assumption where it cannot, the way a picture
// counts as 2,000 tokens. Nothing a request asks for is refused for want of a price. The call is then charged what OpenRouter
// reports: what is not charged of the hold is given back, and a cost above the hold is taken from the wallet at once (it may
// take the available balance below zero, and the wallet then holds nothing new until a top-up repays it). The request body is
// never changed to make the hold true: this is a bound or an estimate, not a promise OpenRouter keeps.
//
// The rules, one place, so a reader can check each:
//
//   Input tokens   Text: at most one token per byte of the request plus `TEMPLATE_ALLOWANCE_TOKENS` for the role and special
//                  tokens a provider adds. A picture, a PDF page, audio and video each have a figure of their own
//                  (`IMAGE_INPUT_TOKENS`, `PDF_PAGE_INPUT_TOKENS`, `AUDIO_INPUT_TOKENS_PER_MB`, `VIDEO_INPUT_TOKENS_PER_MB`). What a
//                  web search or fetch adds is counted too (`WEB_RESULT_INPUT_TOKENS` a result, `WEB_FETCH_INPUT_TOKENS` a page).
//                  The whole is never more than the model's context length.
//   Output tokens  The largest of the request's own limits, else the smaller of the model's listed maximum completion and
//                  `ASSUMED_OUTPUT_TOKENS`, else `ASSUMED_OUTPUT_TOKENS` (or, for a model that makes pictures or video, their own
//                  estimates below); plus the reasoning budget the request names; times `n`. An auto-router's or a fallback list's
//                  dearest candidate is held the same way.
//   Prices         Every line the model lists, at the dearest line of its side; a long-context tier counts when the input could
//                  pass its threshold, a tier on any other condition always. A per-request, per-image, per-character,
//                  per-second or per-search line is counted by what the request names, or by the assumptions below.
//   Estimates      Audio priced per audio unit: from the audio's size or stated length (transcription) or the input text's
//                  length (speech), the unit read as a token, a second or an hour by its price (`AUDIO_UNIT_*`).
//                  Video: the requested duration, else `VIDEO_ASSUMED_SECONDS`, and for a price per video token the requested
//                  resolution, else 1080p at 24 frames a second. A ranking model OpenRouter lists with no price: its documents
//                  at `RERANK_USD_MICROS_PER_SEARCH` and `RERANK_USD_MICROS_PER_MILLION_TOKENS`. A router: the dearest model it
//                  could pick. A tool OpenRouter or the provider runs itself: `SERVER_TOOL_PRICES`, else
//                  `SERVER_TOOL_USE_ALLOWANCE_USD_MICROS` a use. A plugin with a charge of its own:
//                  `PLUGIN_USE_ALLOWANCE_USD_MICROS`. A search or fetch tool with no `max_uses`: `WEB_TOOL_USES_ASSUMED` uses.
//                  A model the catalogue does not list, lists with no price, or a request that names none:
//                  `UNPRICED_CALL_HOLD_USD_MICROS`.
//
// The caller's `X-Max-Cost-Cents` lowers the hold to it when it is below the bound or the estimate.

import type { CataloguePriceLine } from '../schemas/catalogue.js';

/** Tokens a provider may add around a request (roles, separators, tool wrappers) that its bytes do not show. */
export const TEMPLATE_ALLOWANCE_TOKENS = 1024;

// What a picture, a page, a sound or a film costs in input tokens. Providers charge these by what they make of the media, not by
// its size on the wire, so a request cannot say what they will be; each figure is the largest the providers document. A call that
// costs more is charged the rest from the wallet at once.

/**
 * One picture. Anthropic scales an image to at most about 1.15 megapixels, about 1,600 tokens; OpenAI's high-detail tiling and
 * Gemini's tiles come to less. A picture is priced at the model's input price for these tokens, or at its per-image price when it
 * lists one, whichever is dearer.
 */
export const IMAGE_INPUT_TOKENS = 2_000;

/** One page of a PDF. Anthropic documents 1,500 to 3,000 tokens a page, the text plus the page's image. */
export const PDF_PAGE_INPUT_TOKENS = 3_000;

/**
 * One megabyte of audio. Gemini documents 32 tokens a second of audio; a megabyte of audio at a low bitrate (64 kilobits a
 * second, about 130 seconds) is about 4,200 tokens, and 8,000 covers lower bitrates still.
 */
export const AUDIO_INPUT_TOKENS_PER_MB = 8_000;

/**
 * One megabyte of video. Gemini documents about 263 tokens a second of video; a megabyte of video at a low bitrate (1 megabit a
 * second, about 8 seconds) is about 2,100 tokens, and 10,000 covers lower bitrates still.
 */
export const VIDEO_INPUT_TOKENS_PER_MB = 10_000;

/** When a request states how long its audio or video is, the duration is used with the providers' own per-second figures. */
export const AUDIO_INPUT_TOKENS_PER_SECOND = 32;
export const VIDEO_INPUT_TOKENS_PER_SECOND = 263;

/** Seconds in a megabyte of audio whose length the request does not state: speech at 32 kilobits a second, a low bitrate. */
export const AUDIO_SECONDS_PER_MB = 262;

/** A PDF is never counted at fewer pages than one for every 100 KB of it, whatever the file says of its own pages. */
export const PDF_FALLBACK_BYTES_PER_PAGE = 100 * 1024;

/**
 * A file the request names by address, not by content, has a size the request does not say. It is counted as this many bytes (for
 * a PDF page count, audio and video alike): an assumption, since the request cannot tell, kept as one named number.
 */
export const REFERENCED_MEDIA_ASSUMED_BYTES = 5 * 1024 * 1024;

/**
 * What one web search result adds to the input. OpenRouter's web search documents that Exa returns highlights of typically 2,000
 * to 4,000 characters a result; counted at a token a character, with the title, the address and the words OpenRouter puts
 * around the results, 5,000 covers the largest of them.
 */
export const WEB_RESULT_INPUT_TOKENS = 5_000;

/**
 * The results one search by a provider's own search tool returns. Providers do not document it; one Exa request includes up to
 * 10 results (OpenRouter's web search documentation), so a search is counted as that many.
 */
export const WEB_RESULTS_PER_SEARCH = 10;

/**
 * What one fetched page adds to the input when the request sets no `max_content_tokens`. Anthropic's web fetch documentation puts
 * a 100 KB documentation page at about 25,000 tokens; a larger page counts up to the model's context like everything else.
 */
export const WEB_FETCH_INPUT_TOKENS = 25_000;

/** The web plugin's results when the request does not say (OpenRouter: max_results defaults to 5). */
export const WEB_PLUGIN_DEFAULT_RESULTS = 5;

/**
 * The uses a web search or fetch tool with no `max_uses` is counted at. Providers set no default limit (Anthropic: "no default
 * limit"), so this is STACK's assumption of a long research turn; a call that searches more is charged the rest at once.
 */
export const WEB_TOOL_USES_ASSUMED = 10;

/**
 * What OpenRouter's search engines charge for one web plugin request, in micro-dollars, from its web search documentation: Exa's
 * dearest request (Deep Reasoning, $0.015, 10 results included, then $0.001 a result), Parallel's and Perplexity's dearest
 * ($0.005), and Firecrawl ($0.005 a search and $0.0125 a result). An engine not named here is held at the dearest of them.
 */
export const WEB_ENGINE_PRICES = {
  exa: { request: 15_000, included: 10, perExtraResult: 1_000 },
  parallel: { request: 5_000, included: Infinity, perExtraResult: 0 },
  perplexity: { request: 5_000, included: Infinity, perExtraResult: 0 },
  firecrawl: { request: 5_000, included: 0, perExtraResult: 12_500 },
} as const;

/**
 * One PDF page parsed by OpenRouter's OCR engine (`mistral-ocr`), which it uses by default on a model that does not read files
 * itself: $2 per 1,000 pages, or $2.20 for a request pinned to the US, the dearer of the two. An engine STACK does not know is
 * held at this price too.
 */
export const PDF_OCR_USD_MICROS_PER_PAGE = 2_200;

/**
 * Tools OpenRouter or the provider runs itself, by what one use costs at the provider that offers them (OpenAI's published
 * prices): a code interpreter container $0.03, a file search call $0.0025, a generated picture at most $0.25 (GPT Image at high
 * quality and its largest size). Each is counted `max_uses` times, else `SERVER_TOOL_USES_ASSUMED` times.
 */
export const SERVER_TOOL_PRICES: Readonly<Record<string, number>> = {
  code_interpreter: 30_000,
  file_search: 2_500,
  image_generation: 250_000,
};

/** A use of a server tool not in `SERVER_TOOL_PRICES` (computer use, a remote MCP server and the like): STACK's allowance, 10 cents. */
export const SERVER_TOOL_USE_ALLOWANCE_USD_MICROS = 100_000;

/** The uses of a server tool counted when the request sets no `max_uses`: STACK's assumption of one turn's calls. */
export const SERVER_TOOL_USES_ASSUMED = 5;

/** A plugin STACK does not know the charge of: STACK's allowance for one use, 10 cents. */
export const PLUGIN_USE_ALLOWANCE_USD_MICROS = 100_000;

/**
 * A call with nothing to price it by: a model the catalogue does not list (it is at most one refresh behind OpenRouter, or the id
 * is one OpenRouter refuses at no cost), a model OpenRouter lists with no price that is not a router or a ranking model (a music
 * model), a body that names no model. One dollar: STACK's assumption, as the hold the gateway once took when nothing was said.
 */
export const UNPRICED_CALL_HOLD_USD_MICROS = 1_000_000;

/**
 * Output tokens a call that sets no limit is held at: the smaller of this and the model's listed maximum completion, or this
 * alone where the model lists none. A call that writes more is charged the rest from the wallet at once.
 */
export const ASSUMED_OUTPUT_TOKENS = 8_192;

/** Output tokens of one picture a model makes, at a price per image token: a 2048 by 2048 picture at 256 pixels a token. */
export const IMAGE_OUTPUT_TOKENS_PER_IMAGE = 16_384;

/**
 * A price per audio unit is an audio token, a second or an hour of audio, as the model prices it (OpenRouter's list does not say
 * which), read by its size. Audio token prices are at most about $10 a million (under 30 micro-dollars a unit). OpenRouter lists
 * transcription and speech by the second, from about 60 micro-dollars (Deepgram, $0.0043 a minute) to a few thousand (a voice at
 * $0.15 a minute); a few models are listed by the hour (Microsoft's $0.36), and 50,000 micro-dollars a second ($3 a minute) is
 * no price any of them charges by the second. The bounds between them are these.
 */
export const AUDIO_UNIT_SECOND_MIN_USD_MICROS = 30;
export const AUDIO_UNIT_HOUR_MIN_USD_MICROS = 50_000;

/** How many of a price's audio units one second of audio is, read by the unit's price; a token is counted apart. */
function audioUnitsPerSecond(perUnit: number): number {
  return perUnit >= AUDIO_UNIT_HOUR_MIN_USD_MICROS ? 1 / 3_600 : 1;
}

/** Characters of text spoken in a second: a slow speaking rate (about 130 words a minute), so speech is not counted short. */
export const SPEECH_CHARS_PER_SECOND = 12;

/** Audio tokens in a second of generated speech: Gemini documents 32 tokens a second of audio. */
export const AUDIO_OUTPUT_TOKENS_PER_SECOND = 32;

/** The length of a video whose request states none: the longest clip the video models OpenRouter lists offer (Seedance, 15 s). */
export const VIDEO_ASSUMED_SECONDS = 15;

/** A video priced per video token: ByteDance counts width times height times frames, over 1,024 pixels a token. */
export const VIDEO_PIXELS_PER_TOKEN = 1_024;
/** The frame rate and size a video is counted at when the request names none: 24 frames a second at 1080p. */
export const VIDEO_ASSUMED_FPS = 24;
export const VIDEO_ASSUMED_WIDTH = 1_920;
export const VIDEO_ASSUMED_HEIGHT = 1_080;

/** A video priced per megapixel second (an upscale) is counted at 4K, about 8.3 megapixels a frame. */
export const VIDEO_ASSUMED_MEGAPIXELS = 8.3;

/**
 * A ranking model OpenRouter lists with no price: Cohere charges $2 per 1,000 searches of up to 100 documents and Voyage up to
 * $0.10 a million tokens, so a call is held at both: a search for every 100 documents, and its bytes as tokens.
 */
export const RERANK_USD_MICROS_PER_SEARCH = 2_000;
export const RERANK_DOCUMENTS_PER_SEARCH = 100;
export const RERANK_USD_MICROS_PER_MILLION_TOKENS = 100_000;

/** An auto-router's `allowed_models` is read when it has at most this many patterns, each at most this long; else ignored. */
export const ROUTER_ALLOWED_MODELS_MAX = 100;
export const ROUTER_PATTERN_MAX_CHARS = 200;

const MB = 1024 * 1024;

const MICROS_PER_CENT = 10_000;

/** A price tier the model switches to on a condition: above a number of prompt tokens, or at some other time. */
export interface WorstCasePriceTier {
  /** The tier applies when the prompt has more tokens than this; absent, it may apply to any call. */
  above_prompt_tokens?: number | undefined;
  lines: readonly CataloguePriceLine[];
}

/** What of a catalogue model entry the hold reads. */
export interface WorstCaseListing {
  id: string;
  modalities?: { input: string[]; output: string[] } | undefined;
  context_length?: number | undefined;
  max_completion_tokens?: number | undefined;
  price: {
    unit: string;
    provider_cost: {
      input_per_million_tokens_usd_micros?: number | undefined;
      output_per_million_tokens_usd_micros?: number | undefined;
      lines?: readonly CataloguePriceLine[] | undefined;
      tiers?: readonly WorstCasePriceTier[] | undefined;
    } | null;
  };
}

/** What a hold rests on where the most a call can cost could not be worked out from the listing and the request alone. */
export type HoldAssumption =
  | 'model_not_listed'
  | 'price_unlisted'
  | 'router'
  | 'rerank'
  | 'output_tokens_assumed'
  | 'audio_estimated'
  | 'video_estimated'
  | 'image_output_estimated'
  | 'web_uses_assumed'
  | 'web_engine_unknown'
  | 'server_tool'
  | 'plugin'
  | 'pdf_engine_unknown'
  | 'unit_unknown';

export interface WorstCase {
  ok: true;
  usdMicros: number;
  cents: number;
  /** The assumptions the hold rests on, empty when it is a bound worked out from the listing and the request alone. */
  assumptions: HoldAssumption[];
}

/** The catalogue's models, found by id and listed whole (a router's candidates). */
export interface WorstCaseListings {
  find(id: string): WorstCaseListing | null;
  all(): readonly WorstCaseListing[];
}

export interface WorstCaseInput {
  /** The JSON body the caller sent; `{}` when it sent none or not JSON. */
  body: Record<string, unknown>;
  /** The size of the body exactly as sent. */
  bodyBytes: number;
  listings: WorstCaseListings;
  /** A multipart form's model and the size of its file (a transcription sent as a file), when the body is one. */
  form?: { model: string | null; fileBytes: number } | undefined;
}

const MODEL_VARIANTS = new Set(['online', 'nitro', 'floor', 'exacto', 'thinking', 'extended', 'free', 'batch']);
const INPUT_ITEMS = new Set(['prompt', 'input_cache_read', 'input_cache_write', 'input_cache_write_1h', 'audio', 'input_audio_cache', 'image_token']);
const OUTPUT_ITEMS = new Set(['completion', 'internal_reasoning', 'audio_output', 'image_output']);
/** OpenRouter plugins that add no charge of their own. */
const FREE_PLUGINS = new Set(['auto-router', 'response-healing', 'context-compression', 'moderation']);
/** PDF engines of the file-parser plugin that charge nothing beyond the tokens of the text they make. */
const FREE_PDF_ENGINES = new Set(['pdf-text', 'cloudflare-ai']);

function positiveInt(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** The largest output limit a body names (chat, completions and the Responses API alike), or null when it names none. */
export function requestedOutputTokens(body: Record<string, unknown>): number | null {
  const limits = [body['max_completion_tokens'], body['max_tokens'], body['max_output_tokens']]
    .map(positiveInt)
    .filter((value): value is number => value !== null);
  return limits.length > 0 ? Math.max(...limits) : null;
}

/** The reasoning budget a body names (OpenRouter's `reasoning.max_tokens`, Anthropic's `thinking.budget_tokens`), else 0. */
export function reasoningBudgetTokens(body: Record<string, unknown>): number {
  const reasoning = isObject(body['reasoning']) ? positiveInt(body['reasoning']['max_tokens']) : null;
  const thinking = isObject(body['thinking']) ? positiveInt(body['thinking']['budget_tokens']) : null;
  return Math.max(reasoning ?? 0, thinking ?? 0);
}

/** The lines a price is made of and its tiers, or null when the catalogue lists none it could read. */
function priceOf(listing: WorstCaseListing): { lines: CataloguePriceLine[]; tiers: readonly WorstCasePriceTier[] } | null {
  const { unit, provider_cost: cost } = listing.price;
  if (unit === 'free') return { lines: [], tiers: [] };
  if (unit === 'token' && cost) {
    const lines: CataloguePriceLine[] = [];
    if (cost.input_per_million_tokens_usd_micros !== undefined) {
      lines.push({ item: 'prompt', per: 'token', per_count: 1_000_000, cost_usd_micros: cost.input_per_million_tokens_usd_micros });
    }
    if (cost.output_per_million_tokens_usd_micros !== undefined) {
      lines.push({ item: 'completion', per: 'token', per_count: 1_000_000, cost_usd_micros: cost.output_per_million_tokens_usd_micros });
    }
    return { lines: [...lines, ...(cost.lines ?? [])], tiers: cost.tiers ?? [] };
  }
  if (unit === 'lines' && cost?.lines) return { lines: [...cost.lines], tiers: cost.tiers ?? [] };
  return null;
}

/** Per line item, the dearest of the base price and every tier that may apply to this call. */
function effectiveLines(base: CataloguePriceLine[], tiers: readonly WorstCasePriceTier[], inTokens: number): CataloguePriceLine[] {
  const byItem = new Map<string, CataloguePriceLine>();
  const take = (line: CataloguePriceLine) => {
    const known = byItem.get(`${line.item}\0${line.per}`);
    if (!known || line.cost_usd_micros / line.per_count > known.cost_usd_micros / known.per_count) {
      byItem.set(`${line.item}\0${line.per}`, line);
    }
  };
  base.forEach(take);
  for (const tier of tiers) {
    // OpenRouter: a tier applies when the prompt has strictly more tokens than its threshold.
    if (tier.above_prompt_tokens === undefined || inTokens > tier.above_prompt_tokens) tier.lines.forEach(take);
  }
  return [...byItem.values()];
}

/** micro-dollars for `count` units of one line. */
function lineMicros(line: CataloguePriceLine, count: number): number {
  return (count * line.cost_usd_micros) / line.per_count;
}

/** What a call's answer said about the tokens it used. */
export interface TokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  /** Prompt tokens read from the provider's cache, billed at the cache-read line when the model lists one. */
  cached_prompt_tokens?: number | undefined;
}

/**
 * What tokens already used cost at a catalogue listing's prices, in micro-dollars, for a call whose provider never reported
 * its own cost. The prompt tokens are priced at the listing's `prompt` line (the cached ones at its `input_cache_read` line
 * when it has one), the completion tokens at its `completion` line; a tier whose prompt threshold the prompt passed
 * replaces the base price when it is dearer. Null when the model is not listed or lists no token price to read: there is
 * then nothing to price the usage by. A free model costs nothing.
 */
export function tokenUsageUsdMicros(listing: WorstCaseListing | null, usage: TokenUsage): number | null {
  if (!listing) return null;
  if (listing.price.unit === 'free') return 0;
  const price = priceOf(listing);
  if (!price) return null;
  const lines = effectiveLines(price.lines, price.tiers, usage.prompt_tokens)
    .filter((line) => line.per === 'token');
  const rate = (item: string) => lines.find((line) => line.item === item);
  const prompt = rate('prompt');
  const completion = rate('completion');
  if (!prompt && !completion) return null;
  const cached = Math.min(Math.max(usage.cached_prompt_tokens ?? 0, 0), usage.prompt_tokens);
  const cacheRead = rate('input_cache_read');
  let micros = 0;
  if (prompt) micros += lineMicros(prompt, cacheRead ? usage.prompt_tokens - cached : usage.prompt_tokens);
  if (cacheRead) micros += lineMicros(cacheRead, cached);
  if (completion) micros += lineMicros(completion, usage.completion_tokens);
  return micros;
}

type MediaKind = 'image' | 'pdf' | 'audio' | 'video';

interface MediaItem {
  kind: MediaKind;
  /** The bytes the file has, when the request carries them (base64 or a data URL); null when it only names an address. */
  bytes: number | null;
  /** The pages of a PDF, worked out once. */
  pages: number;
  /** The length the request states, in seconds. */
  seconds: number | null;
  /** The characters of the request this media's content takes: they are not text. */
  payloadChars: number;
}

interface Media {
  items: MediaItem[];
  images: number;
  pdfPages: number;
  payloadChars: number;
}

const DATA_URL = /^data:([^;,]*)(?:;[^,]*)?,/i;

/** The base64 of a data URL or a bare base64 string, decoded in full only for a PDF; the size is worked out from its length. */
function payloadOf(value: unknown): { chars: number; bytes: number | null; mime: string | null; base64: string | null } {
  if (typeof value !== 'string') return { chars: 0, bytes: null, mime: null, base64: null };
  const data = DATA_URL.exec(value);
  if (data) {
    const body = value.slice(data[0].length);
    return { chars: value.length, bytes: decodedLength(body), mime: (data[1] ?? '').toLowerCase(), base64: body };
  }
  if (/^https?:\/\//i.test(value) || value.length < 64) return { chars: 0, bytes: null, mime: null, base64: null };
  // Anything else long is taken as a bare base64 payload.
  return { chars: value.length, bytes: decodedLength(value), mime: null, base64: value };
}

/** The bytes a base64 string decodes to. */
function decodedLength(base64: string): number {
  const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
  return Math.floor((base64.length * 3) / 4) - padding;
}

function secondsOf(node: Record<string, unknown>): number | null {
  for (const key of ['duration', 'duration_seconds', 'seconds']) {
    const value = node[key];
    if (typeof value === 'number' && value > 0) return value;
  }
  return null;
}

/**
 * The pages of a PDF: the most of what the file says (its page objects, the largest page count it states) and one for every
 * 100 KB of it, so a file that hides its pages is not counted as fewer than its size allows.
 */
function pdfPages(base64: string | null, bytes: number | null): number {
  const size = bytes ?? REFERENCED_MEDIA_ASSUMED_BYTES;
  let pages = Math.max(1, Math.ceil(size / PDF_FALLBACK_BYTES_PER_PAGE));
  if (base64 !== null) {
    const text = Buffer.from(base64, 'base64').toString('latin1');
    const objects = text.match(/\/Type\s*\/Page(?![A-Za-z])/g)?.length ?? 0;
    let stated = 0;
    for (const match of text.matchAll(/\/Count\s+(\d{1,9})/g)) stated = Math.max(stated, Number(match[1]));
    pages = Math.max(pages, objects, stated);
  }
  return pages;
}

function itemOf(kind: MediaKind, payload: ReturnType<typeof payloadOf>, node: Record<string, unknown>): MediaItem {
  return {
    kind,
    bytes: payload.bytes,
    pages: kind === 'pdf' ? pdfPages(payload.base64, payload.bytes) : 0,
    seconds: secondsOf(node),
    payloadChars: payload.chars,
  };
}

/** What a part of a request is, as media, in the shapes the chat, responses and messages APIs use; null when it is text. */
function mediaOf(node: Record<string, unknown>): MediaItem | null {
  const type = typeof node['type'] === 'string' ? node['type'].toLowerCase() : '';
  const named = (value: unknown): unknown => (isObject(value) ? value['url'] ?? value['data'] ?? value['file_data'] : value);
  // An Anthropic block: { type, source: { type: base64 | url, media_type, data | url } }.
  const source = isObject(node['source']) ? node['source'] : null;
  if (source && /image|document|audio|video/.test(type)) {
    const payload = payloadOf(source['data'] ?? source['url']);
    const mime = String(source['media_type'] ?? payload.mime ?? '').toLowerCase();
    const kind: MediaKind = /image/.test(type) ? 'image' : /audio/.test(type) ? 'audio' : /video/.test(type) ? 'video' : mime.includes('pdf') ? 'pdf' : 'image';
    if (type === 'document' && !mime.includes('pdf')) return null;
    return itemOf(kind, payload, node);
  }
  if ('image_url' in node || 'input_image' in node || /image/.test(type)) {
    return itemOf('image', payloadOf(named(node['image_url'] ?? node['input_image'] ?? node['url'])), node);
  }
  if ('input_audio' in node || /audio/.test(type)) {
    const audio = isObject(node['input_audio']) ? node['input_audio'] : node;
    return itemOf('audio', payloadOf(audio['data'] ?? audio['url']), { ...node, ...audio });
  }
  if ('video_url' in node || /video/.test(type)) {
    return itemOf('video', payloadOf(named(node['video_url'] ?? node['url'])), node);
  }
  if ('file' in node || 'file_data' in node || /file|document/.test(type)) {
    const file = isObject(node['file']) ? node['file'] : node;
    const payload = payloadOf(file['file_data'] ?? file['data'] ?? file['url']);
    const name = String(file['filename'] ?? file['name'] ?? '').toLowerCase();
    if (payload.mime?.includes('pdf') || name.endsWith('.pdf') || (payload.base64 !== null && Buffer.from(payload.base64.slice(0, 16), 'base64').toString('latin1').startsWith('%PDF'))) {
      return itemOf('pdf', payload, node);
    }
    // Any other file is text as far as its tokens go: they are bounded by its bytes, which the request already counts.
    return null;
  }
  return null;
}

function walkMedia(value: unknown, media: Media, depth = 0): void {
  if (depth > 64) return;
  if (Array.isArray(value)) {
    for (const item of value) walkMedia(item, media, depth + 1);
    return;
  }
  if (!isObject(value)) return;
  const item = mediaOf(value);
  if (item) {
    media.items.push(item);
    media.payloadChars += item.payloadChars;
    if (item.kind === 'image') media.images += 1;
    if (item.kind === 'pdf') media.pdfPages += item.pages;
    return;
  }
  for (const child of Object.values(value)) walkMedia(child, media, depth + 1);
}

/** The input tokens of every picture-free part of the media, and nothing for the pictures: they are priced apart. */
function mediaTokens(media: Media): number {
  let tokens = 0;
  for (const item of media.items) {
    const bytes = item.bytes ?? REFERENCED_MEDIA_ASSUMED_BYTES;
    if (item.kind === 'pdf') {
      tokens += item.pages * PDF_PAGE_INPUT_TOKENS;
    } else if (item.kind === 'audio') {
      tokens += item.seconds !== null ? item.seconds * AUDIO_INPUT_TOKENS_PER_SECOND : (bytes / MB) * AUDIO_INPUT_TOKENS_PER_MB;
    } else if (item.kind === 'video') {
      tokens += item.seconds !== null ? item.seconds * VIDEO_INPUT_TOKENS_PER_SECOND : (bytes / MB) * VIDEO_INPUT_TOKENS_PER_MB;
    }
  }
  return Math.ceil(tokens);
}

type WebEngine = keyof typeof WEB_ENGINE_PRICES;

/** What a request's web features, tools and plugins add, read once for every model it may run on. */
interface Extras {
  /** Searches priced at the model's own `web_search` line (or an engine's price on a model that lists none). */
  modelSearches: number;
  /** The web plugin's requests, with their results and engine: priced at the dearer of the model's line and the engine. */
  pluginRequests: Array<{ results: number; engine: WebEngine | 'native' | 'unknown' | null }>;
  /** Input tokens that search results and fetched pages add. */
  resultTokens: number;
  /** The PDF engine the file-parser plugin names, or null for OpenRouter's default. */
  pdfEngine: string | null;
  /** What tools OpenRouter or the provider runs, and plugins with a charge of their own, add, in micro-dollars. */
  toolMicros: number;
  assumptions: Set<HoldAssumption>;
}

/** A tool OpenRouter or the provider runs itself, by its type, or null when the tool is the caller's own function. */
function serverToolOf(tool: Record<string, unknown>): string | null {
  const type = typeof tool['type'] === 'string' ? tool['type'].toLowerCase() : '';
  // A function or custom tool, or an Anthropic tool that is just a name and a schema: the caller runs it.
  if (type === '' || type === 'function' || type === 'custom') return null;
  return type;
}

function readExtras(body: Record<string, unknown>, online: boolean): Extras {
  const extras: Extras = { modelSearches: 0, pluginRequests: [], resultTokens: 0, pdfEngine: null, toolMicros: 0, assumptions: new Set() };
  if (online) {
    extras.pluginRequests.push({ results: WEB_PLUGIN_DEFAULT_RESULTS, engine: null });
    extras.resultTokens += WEB_PLUGIN_DEFAULT_RESULTS * WEB_RESULT_INPUT_TOKENS;
  }
  for (const entry of Array.isArray(body['plugins']) ? body['plugins'] : []) {
    if (!isObject(entry)) continue;
    const id = String(entry['id'] ?? '');
    if (FREE_PLUGINS.has(id)) continue;
    if (id === 'web') {
      const results = positiveInt(entry['max_results']) ?? WEB_PLUGIN_DEFAULT_RESULTS;
      const named = entry['engine'];
      let engine: Extras['pluginRequests'][number]['engine'] = null;
      if (named === 'native') engine = 'native';
      else if (typeof named === 'string' && named in WEB_ENGINE_PRICES) engine = named as WebEngine;
      else if (named !== undefined) {
        engine = 'unknown';
        extras.assumptions.add('web_engine_unknown');
      }
      extras.pluginRequests.push({ results, engine });
      extras.resultTokens += results * WEB_RESULT_INPUT_TOKENS;
      continue;
    }
    if (id === 'file-parser') {
      const pdf = isObject(entry['pdf']) ? entry['pdf'] : {};
      extras.pdfEngine = typeof pdf['engine'] === 'string' ? pdf['engine'] : null;
      continue;
    }
    extras.toolMicros += PLUGIN_USE_ALLOWANCE_USD_MICROS;
    extras.assumptions.add('plugin');
  }
  if (body['web_search_options'] !== undefined) {
    extras.modelSearches += 1;
    extras.resultTokens += WEB_RESULTS_PER_SEARCH * WEB_RESULT_INPUT_TOKENS;
  }
  for (const tool of Array.isArray(body['tools']) ? body['tools'] : []) {
    if (!isObject(tool)) continue;
    const type = serverToolOf(tool);
    if (type === null) continue;
    const params = isObject(tool['parameters']) ? tool['parameters'] : {};
    const uses = positiveInt(tool['max_uses']) ?? positiveInt(params['max_uses']);
    if (/^(?:openrouter:)?web_search/.test(type)) {
      if (uses === null) extras.assumptions.add('web_uses_assumed');
      const searches = uses ?? WEB_TOOL_USES_ASSUMED;
      extras.modelSearches += searches;
      extras.resultTokens += searches * WEB_RESULTS_PER_SEARCH * WEB_RESULT_INPUT_TOKENS;
      continue;
    }
    if (/^(?:openrouter:)?web_fetch/.test(type)) {
      if (uses === null) extras.assumptions.add('web_uses_assumed');
      const perPage = positiveInt(tool['max_content_tokens']) ?? WEB_FETCH_INPUT_TOKENS;
      extras.resultTokens += (uses ?? WEB_TOOL_USES_ASSUMED) * perPage;
      continue;
    }
    // A tool OpenRouter or the provider runs: its price a use, or STACK's allowance, times its uses.
    extras.assumptions.add('server_tool');
    extras.toolMicros += (SERVER_TOOL_PRICES[type] ?? SERVER_TOOL_USE_ALLOWANCE_USD_MICROS) * (uses ?? SERVER_TOOL_USES_ASSUMED);
  }
  return extras;
}

function textBytesOf(value: unknown): number {
  return typeof value === 'string' ? Buffer.byteLength(value, 'utf8') : 0;
}

/** What a request is, read once: its media, its own limits and what an estimate is built from. */
interface RequestFacts {
  media: Media;
  requested: number | null;
  reasoning: number;
  n: number;
  chars: number;
  duration: number | null;
  /** Seconds and tokens of the audio the request carries (a transcription's input). */
  audioSeconds: number;
  audioTokens: number;
  /** The video size the request names, else the assumed one. */
  videoWidth: number;
  videoHeight: number;
  /** Documents of a ranking request. */
  documents: number;
}

const RESOLUTIONS: Record<string, [number, number]> = {
  '480p': [854, 480], '540p': [960, 540], '720p': [1_280, 720], '1080p': [1_920, 1_080], '1440p': [2_560, 1_440],
  '2k': [2_560, 1_440], '4k': [3_840, 2_160], '2160p': [3_840, 2_160],
};

function videoSizeOf(body: Record<string, unknown>): [number, number] {
  for (const key of ['resolution', 'size']) {
    const value = typeof body[key] === 'string' ? (body[key] as string).toLowerCase() : null;
    if (!value) continue;
    if (RESOLUTIONS[value]) return RESOLUTIONS[value]!;
    const sized = /^(\d{2,5})\s*[x*]\s*(\d{2,5})$/.exec(value);
    if (sized) return [Number(sized[1]), Number(sized[2])];
  }
  return [VIDEO_ASSUMED_WIDTH, VIDEO_ASSUMED_HEIGHT];
}

function factsOf(input: WorstCaseInput): RequestFacts {
  const { body } = input;
  const media: Media = { items: [], images: 0, pdfPages: 0, payloadChars: 0 };
  // The tools and plugins a request names are not media, whatever their type says (an image_generation tool).
  walkMedia({ ...body, tools: undefined, plugins: undefined }, media);
  let audioSeconds = 0;
  let audioTokens = 0;
  for (const item of media.items) {
    if (item.kind !== 'audio') continue;
    const bytes = item.bytes ?? REFERENCED_MEDIA_ASSUMED_BYTES;
    audioSeconds += item.seconds ?? (bytes / MB) * AUDIO_SECONDS_PER_MB;
    audioTokens += item.seconds !== null ? item.seconds * AUDIO_INPUT_TOKENS_PER_SECOND : (bytes / MB) * AUDIO_INPUT_TOKENS_PER_MB;
  }
  // A file sent as a form (a transcription) is audio of its own size.
  if (input.form && input.form.fileBytes > 0) {
    audioSeconds += (input.form.fileBytes / MB) * AUDIO_SECONDS_PER_MB;
    audioTokens += (input.form.fileBytes / MB) * AUDIO_INPUT_TOKENS_PER_MB;
  }
  const [videoWidth, videoHeight] = videoSizeOf(body);
  const documents = Array.isArray(body['documents']) ? body['documents'].length : 0;
  return {
    media,
    requested: requestedOutputTokens(body),
    reasoning: reasoningBudgetTokens(body),
    n: positiveInt(body['n']) ?? 1,
    chars: textBytesOf(body['input']) > 0 ? [...String(body['input'])].length : 0,
    duration: typeof body['duration'] === 'number' && body['duration'] > 0 ? body['duration'] : null,
    audioSeconds: Math.ceil(audioSeconds),
    audioTokens: Math.ceil(audioTokens),
    videoWidth,
    videoHeight,
    documents,
  };
}

interface Priced {
  usdMicros: number;
  assumptions: Set<HoldAssumption>;
}

const unpriced = (assumption: HoldAssumption): Priced => ({ usdMicros: UNPRICED_CALL_HOLD_USD_MICROS, assumptions: new Set([assumption]) });

/** A ranking model with no listed price: a search for every 100 documents, and the request's bytes as tokens. */
function rerankEstimate(facts: RequestFacts, input: WorstCaseInput): Priced {
  const searches = Math.max(1, Math.ceil(facts.documents / RERANK_DOCUMENTS_PER_SEARCH));
  const micros = searches * RERANK_USD_MICROS_PER_SEARCH + (input.bodyBytes * RERANK_USD_MICROS_PER_MILLION_TOKENS) / 1_000_000;
  return { usdMicros: micros, assumptions: new Set(['rerank']) };
}

/** The most one call can cost against one listed model, or the estimate where the listing and the request do not settle it. */
function listingEstimate(listing: WorstCaseListing, facts: RequestFacts, extras: Extras, input: WorstCaseInput): Priced {
  const outputs = listing.modalities?.output ?? [];
  const price = priceOf(listing);
  if (!price) return outputs.includes('rerank') ? rerankEstimate(facts, input) : unpriced('price_unlisted');
  const assumptions = new Set<HoldAssumption>(extras.assumptions);
  const { media } = facts;
  const context = positiveInt(listing.context_length);

  // Text at a token a byte (what the media's own content takes in the body is not text), the pages, sound and film at their
  // figures and what searches and fetches bring in; the whole never above the context. Pictures are added at their own price.
  let inTokens = Math.max(0, input.bodyBytes - media.payloadChars) + TEMPLATE_ALLOWANCE_TOKENS + mediaTokens(media) + extras.resultTokens;
  if (context !== null) inTokens = Math.min(inTokens, context);
  const lines = effectiveLines(price.lines, price.tiers, inTokens);

  const needsOutputTokens = lines.some((l) => l.per === 'token' && OUTPUT_ITEMS.has(l.item) && l.cost_usd_micros > 0)
    || lines.some((l) => l.per === 'token' && !INPUT_ITEMS.has(l.item) && !OUTPUT_ITEMS.has(l.item) && l.cost_usd_micros > 0);
  const seconds = facts.duration ?? VIDEO_ASSUMED_SECONDS;
  let outTokens = 0;
  if (needsOutputTokens) {
    const listed = positiveInt(listing.max_completion_tokens);
    const limit = facts.requested ?? (listed !== null ? Math.min(listed, ASSUMED_OUTPUT_TOKENS) : null);
    const capped = (tokens: number) => (context !== null ? Math.min(tokens, context) : tokens) * facts.n;
    if (limit !== null) {
      outTokens = capped(limit + facts.reasoning);
    } else if (outputs.includes('video')) {
      // ByteDance counts a video's tokens as width times height times frames over 1,024 pixels.
      assumptions.add('video_estimated');
      outTokens = Math.ceil((facts.videoWidth * facts.videoHeight * VIDEO_ASSUMED_FPS * seconds) / VIDEO_PIXELS_PER_TOKEN);
    } else if (outputs.length > 0 && outputs.every((o) => o === 'image')) {
      assumptions.add('image_output_estimated');
      outTokens = facts.n * IMAGE_OUTPUT_TOKENS_PER_IMAGE;
    } else {
      assumptions.add('output_tokens_assumed');
      outTokens = capped(ASSUMED_OUTPUT_TOKENS + facts.reasoning);
    }
  }

  let inRate = 0;
  let outRate = 0;
  let micros = 0;
  let secondRate = 0;
  let megapixelRate = 0;
  let imageLine = 0;
  let searchLine = 0;
  let unknownUnit = false;
  for (const line of lines) {
    if (line.cost_usd_micros === 0) continue;
    const perUnit = line.cost_usd_micros / line.per_count;
    switch (line.per) {
      case 'token':
        if (INPUT_ITEMS.has(line.item)) inRate = Math.max(inRate, perUnit);
        else if (OUTPUT_ITEMS.has(line.item)) outRate = Math.max(outRate, perUnit);
        else { inRate = Math.max(inRate, perUnit); outRate = Math.max(outRate, perUnit); }
        break;
      case 'request':
        micros += lineMicros(line, 1);
        break;
      case 'generation':
        micros += lineMicros(line, facts.n);
        break;
      case 'image':
        imageLine = Math.max(imageLine, perUnit);
        break;
      case 'search':
        searchLine = Math.max(searchLine, perUnit);
        break;
      case 'character':
        micros += lineMicros(line, facts.chars);
        break;
      case 'second':
        // A video lists one second price per resolution, and one applies: the dearest is the bound.
        if (facts.duration === null) assumptions.add('video_estimated');
        secondRate = Math.max(secondRate, perUnit);
        break;
      case 'megapixel_second':
        assumptions.add('video_estimated');
        megapixelRate = Math.max(megapixelRate, perUnit);
        break;
      case 'audio_unit': {
        // A second or an audio token, read by its price: the input's audio for a transcription, the speech for a voice.
        assumptions.add('audio_estimated');
        const timed = perUnit >= AUDIO_UNIT_SECOND_MIN_USD_MICROS;
        if (INPUT_ITEMS.has(line.item)) {
          const audioSeconds = facts.audioSeconds > 0 ? facts.audioSeconds : Math.ceil((input.bodyBytes / MB) * AUDIO_SECONDS_PER_MB);
          const audioTokens = facts.audioTokens > 0 ? facts.audioTokens : Math.ceil((input.bodyBytes / MB) * AUDIO_INPUT_TOKENS_PER_MB);
          micros += perUnit * (timed ? Math.max(1, audioSeconds) * audioUnitsPerSecond(perUnit) : Math.max(1, audioTokens));
        } else {
          const spoken = Math.max(1, Math.ceil(facts.chars / SPEECH_CHARS_PER_SECOND));
          const listed = positiveInt(listing.max_completion_tokens);
          const tokens = spoken * AUDIO_OUTPUT_TOKENS_PER_SECOND;
          micros += perUnit * (timed ? spoken * audioUnitsPerSecond(perUnit) : listed !== null ? Math.min(tokens, listed) : tokens);
        }
        break;
      }
      default:
        unknownUnit = true;
    }
  }
  if (unknownUnit) {
    assumptions.add('unit_unknown');
    micros += UNPRICED_CALL_HOLD_USD_MICROS;
  }

  // Web search: the model's own line per search, or an engine's dearest request on a model that lists none.
  const exa = WEB_ENGINE_PRICES.exa;
  const enginePrice = (engine: WebEngine, results: number) => {
    const table = WEB_ENGINE_PRICES[engine];
    return table.request + Math.max(0, results - table.included) * table.perExtraResult;
  };
  if (extras.modelSearches > 0) {
    if (searchLine === 0) assumptions.add('web_engine_unknown');
    micros += extras.modelSearches * (searchLine > 0 ? searchLine : exa.request);
  }
  for (const request of extras.pluginRequests) {
    if (request.engine === 'native') {
      micros += request.results * (searchLine > 0 ? searchLine : enginePrice('exa', request.results));
      continue;
    }
    const engines: WebEngine[] = request.engine === null ? ['exa']
      : request.engine === 'unknown' ? (Object.keys(WEB_ENGINE_PRICES) as WebEngine[])
        : [request.engine];
    let dearest = request.engine === null ? request.results * searchLine : 0;
    for (const engine of engines) dearest = Math.max(dearest, enginePrice(engine, request.results));
    micros += dearest;
  }

  // A PDF on a model that does not read files itself is parsed by OpenRouter's OCR engine unless the request names a free one.
  if (media.pdfPages > 0) {
    const readsFiles = (listing.modalities?.input ?? []).includes('file');
    const engine = extras.pdfEngine ?? (readsFiles ? 'native' : 'mistral-ocr');
    if (engine !== 'native' && engine !== 'mistral-ocr' && !FREE_PDF_ENGINES.has(engine)) assumptions.add('pdf_engine_unknown');
    const ocr = engine === 'native' ? !readsFiles : !FREE_PDF_ENGINES.has(engine);
    if (ocr) micros += media.pdfPages * PDF_OCR_USD_MICROS_PER_PAGE;
  }

  // Each picture: its tokens at the input price, or the model's per-image price when it has one, whichever is dearer.
  const perImage = Math.max(IMAGE_INPUT_TOKENS * inRate, imageLine);
  micros += inTokens * inRate + outTokens * outRate + seconds * secondRate + seconds * VIDEO_ASSUMED_MEGAPIXELS * megapixelRate
    + media.images * perImage + extras.toolMicros;
  return { usdMicros: micros, assumptions };
}

/**
 * Whether a model id matches a pattern in which `*` stands for any run of characters. Linear in the id: the pieces between the
 * stars are found left to right with indexOf, the first anchored at the start and the last at the end, which for a pattern made
 * only of literals and stars finds a match whenever there is one. No regular expression is built from what a caller sent.
 */
export function wildcardMatches(pattern: string, id: string): boolean {
  const pieces = pattern.split('*');
  if (pieces.length === 1) return pattern === id;
  const first = pieces[0]!;
  const last = pieces[pieces.length - 1]!;
  if (first.length + last.length > id.length || !id.startsWith(first) || !id.endsWith(last)) return false;
  let at = first.length;
  const end = id.length - last.length;
  for (let index = 1; index < pieces.length - 1; index += 1) {
    const piece = pieces[index]!;
    if (piece === '') continue;
    const found = id.indexOf(piece, at);
    if (found < 0 || found + piece.length > end) return false;
    at = found + piece.length;
  }
  return true;
}

/**
 * The auto-router's `allowed_models`, or null when it names none or names them in a way the hold does not read (not a list, more
 * than `ROUTER_ALLOWED_MODELS_MAX`, a pattern longer than `ROUTER_PATTERN_MAX_CHARS`): every model it could pick is then counted.
 */
function allowedModelsOf(body: Record<string, unknown>): string[] | null {
  const patterns: string[] = [];
  for (const plugin of Array.isArray(body['plugins']) ? body['plugins'] : []) {
    if (!isObject(plugin) || plugin['id'] !== 'auto-router' || plugin['allowed_models'] === undefined) continue;
    const list = plugin['allowed_models'];
    if (!Array.isArray(list)) return null;
    for (const item of list) {
      if (typeof item !== 'string' || item.length === 0 || item.length > ROUTER_PATTERN_MAX_CHARS) return null;
      patterns.push(item);
    }
  }
  if (patterns.length === 0 || patterns.length > ROUTER_ALLOWED_MODELS_MAX) return null;
  return patterns;
}

/**
 * A model OpenRouter lists with no price that makes text (and no sound, as a music model does): a router that picks another
 * model (OpenRouter lists its routers, `openrouter/auto` among them, with a price of -1).
 */
function isRouter(listing: WorstCaseListing): boolean {
  const outputs = listing.modalities?.output ?? [];
  return listing.price.unit === 'varies' && outputs.includes('text') && !outputs.includes('audio') && !outputs.includes('rerank');
}

/** The model id a body names and whether it asks for web search by a suffix; variant suffixes of an id the catalogue lacks are stripped. */
function resolveListing(
  id: string,
  listings: WorstCaseInput['listings'],
): { listing: WorstCaseListing; online: boolean } | null {
  let online = false;
  let name = id;
  for (;;) {
    const listing = listings.find(name);
    if (listing) return { listing, online };
    const colon = name.lastIndexOf(':');
    if (colon <= 0) return null;
    const suffix = name.slice(colon + 1);
    if (!MODEL_VARIANTS.has(suffix)) return null;
    if (suffix === 'online') online = true;
    name = name.slice(0, colon);
  }
}

/**
 * What a call's known token usage costs at the catalogue's price for the model it named, in micro-dollars: null when the model
 * is not listed (a variant suffix of an unlisted id is stripped, as for a hold), is a router that picks another model, or lists no
 * token price. See `tokenUsageUsdMicros`.
 */
export function modelTokenUsageUsdMicros(listings: WorstCaseListings, modelId: string, usage: TokenUsage): number | null {
  const found = resolveListing(modelId, listings);
  if (!found || isRouter(found.listing)) return null;
  return tokenUsageUsdMicros(found.listing, usage);
}

function done(priced: Priced): WorstCase {
  const usdMicros = Math.ceil(priced.usdMicros);
  return { ok: true, usdMicros, cents: Math.max(1, Math.ceil(usdMicros / MICROS_PER_CENT)), assumptions: [...priced.assumptions].sort() };
}

/**
 * What the call holds: the most it can cost, or the estimate where that cannot be worked out, never a refusal. The model comes
 * from the body (or a form's `model` field); a request that names a list of fallback `models` holds the dearest of them.
 */
export function openRouterWorstCase(input: WorstCaseInput): WorstCase {
  const named: string[] = [];
  if (typeof input.body['model'] === 'string' && input.body['model'] !== '') named.push(input.body['model']);
  else if (input.form?.model) named.push(input.form.model);
  if (Array.isArray(input.body['models'])) {
    for (const item of input.body['models']) if (typeof item === 'string' && item !== '') named.push(item);
  }
  if (named.length === 0) return done(unpriced('model_not_listed'));

  const facts = factsOf(input);
  let best: Priced | null = null;
  for (const id of named) {
    const found = resolveListing(id, input.listings);
    const extras = readExtras(input.body, found?.online ?? false);
    let priced: Priced;
    if (!found) {
      priced = unpriced('model_not_listed');
    } else if (isRouter(found.listing)) {
      // A router picks another model: the hold is that of the dearest priced text model it could pick (a model listed with no
      // price is another router or a music model, which a router does not pick; a call that costs more is charged the rest).
      const allowed = allowedModelsOf(input.body);
      const candidates = input.listings.all().filter((candidate) => (
        candidate.id !== found.listing.id
        && (candidate.modalities?.output ?? []).includes('text')
        && candidate.price.unit !== 'varies'
        && (allowed === null || allowed.some((pattern) => wildcardMatches(pattern, candidate.id)))
      ));
      priced = unpriced('router');
      let dearest: Priced | null = null;
      for (const candidate of candidates) {
        const one = listingEstimate(candidate, facts, extras, input);
        if (dearest === null || one.usdMicros > dearest.usdMicros) dearest = one;
      }
      if (dearest) priced = { usdMicros: dearest.usdMicros, assumptions: new Set([...dearest.assumptions, 'router']) };
    } else {
      priced = listingEstimate(found.listing, facts, extras, input);
    }
    if (best === null || priced.usdMicros > best.usdMicros) best = priced;
  }
  return done(best!);
}
