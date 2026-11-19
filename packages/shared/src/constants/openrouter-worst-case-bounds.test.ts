// The cases a review found where the worst case was not an upper bound, each held to a bound now.
import { describe, expect, it } from 'vitest';
import {
  AUDIO_INPUT_TOKENS_PER_MB,
  AUDIO_SECONDS_PER_MB,
  IMAGE_OUTPUT_TOKENS_PER_IMAGE,
  RERANK_USD_MICROS_PER_MILLION_TOKENS,
  RERANK_USD_MICROS_PER_SEARCH,
  VIDEO_ASSUMED_FPS,
  VIDEO_ASSUMED_SECONDS,
  VIDEO_PIXELS_PER_TOKEN,
  PDF_FALLBACK_BYTES_PER_PAGE,
  SERVER_TOOL_USE_ALLOWANCE_USD_MICROS,
  SERVER_TOOL_USES_ASSUMED,
  UNPRICED_CALL_HOLD_USD_MICROS,
  WEB_TOOL_USES_ASSUMED,
  PDF_OCR_USD_MICROS_PER_PAGE,
  PDF_PAGE_INPUT_TOKENS,
  ROUTER_ALLOWED_MODELS_MAX,
  ROUTER_PATTERN_MAX_CHARS,
  TEMPLATE_ALLOWANCE_TOKENS,
  WEB_FETCH_INPUT_TOKENS,
  WEB_RESULT_INPUT_TOKENS,
  WEB_RESULTS_PER_SEARCH,
  openRouterWorstCase,
  wildcardMatches,
  type WorstCaseListing,
  type WorstCaseListings,
} from './openrouter-worst-case.js';

function catalogue(...listings: WorstCaseListing[]): WorstCaseListings {
  const byId = new Map(listings.map((l) => [l.id, l]));
  return { find: (id) => byId.get(id) ?? null, all: () => listings };
}

/** $3 per million input tokens, $15 per million output, a search at a cent, a million-token context. */
const chat: WorstCaseListing = {
  id: 'acme/chat-1',
  modalities: { input: ['text', 'image'], output: ['text'] },
  context_length: 1_000_000,
  max_completion_tokens: 8_000,
  price: {
    unit: 'token',
    provider_cost: {
      input_per_million_tokens_usd_micros: 3_000_000,
      output_per_million_tokens_usd_micros: 15_000_000,
      lines: [{ item: 'web_search', per: 'search', per_count: 1, cost_usd_micros: 10_000 }],
    },
  },
};
const size = (b: Record<string, unknown>) => Buffer.byteLength(JSON.stringify(b));
const worst = (b: Record<string, unknown>, ...listings: WorstCaseListing[]) =>
  openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(...(listings.length > 0 ? listings : [chat])) });
const micros = (b: Record<string, unknown>, ...listings: WorstCaseListing[]) => {
  const result = worst(b, ...listings);
  return result.usdMicros;
};
const base = { model: 'acme/chat-1', messages: [{ role: 'user', content: 'hello' }] };

describe('output limits', () => {
  it('holds the largest of every output limit the body names, not the first', () => {
    const b = { ...base, max_completion_tokens: 16, max_tokens: 64_000 };
    expect(micros(b)).toBe(Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 64_000 * 15));
  });

  it('adds the reasoning budget a body names to its output limit', () => {
    const b = { ...base, max_tokens: 1_000, reasoning: { max_tokens: 5_000 } };
    expect(micros(b)).toBe(Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 6_000 * 15));
    const thinking = { ...base, max_tokens: 1_000, thinking: { type: 'enabled', budget_tokens: 9_000 } };
    expect(micros(thinking)).toBe(Math.ceil((size(thinking) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 10_000 * 15));
  });
});

describe('long-context price tiers', () => {
  const tiered: WorstCaseListing = {
    ...chat,
    id: 'acme/tiered',
    price: {
      unit: 'token',
      provider_cost: {
        input_per_million_tokens_usd_micros: 3_000_000,
        output_per_million_tokens_usd_micros: 15_000_000,
        tiers: [{ above_prompt_tokens: 200_000, lines: [
          { item: 'prompt', per: 'token', per_count: 1_000_000, cost_usd_micros: 6_000_000 },
          { item: 'completion', per: 'token', per_count: 1_000_000, cost_usd_micros: 22_500_000 },
        ] }],
      },
    },
  };

  it('prices a call whose input cannot pass the threshold at the base price', () => {
    const b = { ...base, model: 'acme/tiered', max_tokens: 100 };
    expect(micros(b, tiered)).toBe(Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 100 * 15));
  });

  it('prices a call whose input could pass the threshold at the dearer tier, input and output alike', () => {
    const long = 'x'.repeat(250_000);
    const b = { ...base, model: 'acme/tiered', messages: [{ role: 'user', content: long }], max_tokens: 100 };
    expect(micros(b, tiered)).toBe(Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 6 + 100 * 22.5));
  });

  it('counts a tier on any other condition (the time of day) for every call', () => {
    const night: WorstCaseListing = {
      ...tiered,
      id: 'acme/night',
      price: { ...tiered.price, provider_cost: { ...tiered.price.provider_cost!, tiers: [{ lines: [{ item: 'completion', per: 'token', per_count: 1_000_000, cost_usd_micros: 30_000_000 }] }] } },
    };
    const b = { ...base, model: 'acme/night', max_tokens: 100 };
    expect(micros(b, night)).toBe(Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 100 * 30));
  });
});

describe('web search and fetch results', () => {
  it('adds the results a search tool brings into the input, per search', () => {
    const plain = { ...base, max_tokens: 100 };
    const searched = { ...plain, tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 3 }] };
    const added = micros(searched) - micros(plain) - (size(searched) - size(plain)) * 3;
    expect(added).toBe(3 * 10_000 + 3 * WEB_RESULTS_PER_SEARCH * WEB_RESULT_INPUT_TOKENS * 3);
  });

  it('adds a fetched page at max_content_tokens, else WEB_FETCH_INPUT_TOKENS, and counts a fetch tool with no limit at WEB_TOOL_USES_ASSUMED', () => {
    const plain = { ...base, max_tokens: 100 };
    const fetched = { ...plain, tools: [{ type: 'web_fetch_20250910', name: 'web_fetch', max_uses: 2 }] };
    expect(micros(fetched) - micros(plain) - (size(fetched) - size(plain)) * 3).toBe(2 * WEB_FETCH_INPUT_TOKENS * 3);
    const capped = { ...plain, tools: [{ type: 'web_fetch_20250910', name: 'web_fetch', max_uses: 2, max_content_tokens: 1_000 }] };
    expect(micros(capped) - micros(plain) - (size(capped) - size(plain)) * 3).toBe(2 * 1_000 * 3);
    const open = { ...plain, tools: [{ type: 'web_fetch_20250910', name: 'web_fetch' }] };
    expect(worst(open)).toMatchObject({ ok: true, assumptions: ['web_uses_assumed'] });
    expect(micros(open) - micros(plain) - (size(open) - size(plain)) * 3).toBe(WEB_TOOL_USES_ASSUMED * WEB_FETCH_INPUT_TOKENS * 3);
  });

  it("prices the web plugin at the engine it names, at the dearest engine when it names one STACK does not know, and at the dearer of Exa and the model's line by default", () => {
    const plain = { ...base, max_tokens: 100 };
    const firecrawl = { ...plain, plugins: [{ id: 'web', engine: 'firecrawl', max_results: 4 }] };
    expect(micros(firecrawl) - micros(plain) - (size(firecrawl) - size(plain)) * 3).toBe(5_000 + 4 * 12_500 + 4 * WEB_RESULT_INPUT_TOKENS * 3);
    const mystery = { ...plain, plugins: [{ id: 'web', engine: 'mystery' }] };
    expect(worst(mystery)).toMatchObject({ ok: true, assumptions: ['web_engine_unknown'] });
    // Five results: Firecrawl is the dearest engine at $0.005 a search and $0.0125 a result.
    expect(micros(mystery) - micros(plain) - (size(mystery) - size(plain)) * 3).toBe(5_000 + 5 * 12_500 + 5 * WEB_RESULT_INPUT_TOKENS * 3);
    const one = { ...plain, plugins: [{ id: 'web', max_results: 1 }] };
    // One result at the model's 1 cent line is below Exa's dearest request (1.5 cents): the hold takes Exa's.
    expect(micros(one) - micros(plain) - (size(one) - size(plain)) * 3).toBe(15_000 + WEB_RESULT_INPUT_TOKENS * 3);
  });
});

describe('tools that run at OpenRouter or the provider', () => {
  it('holds code execution, image generation and file search at their price a use, and any other server tool at the allowance', () => {
    const plain = { ...base, max_tokens: 100 };
    const added = (type: string, extra: Record<string, unknown> = {}) => {
      const b = { ...plain, tools: [{ type, ...extra }] };
      expect(worst(b)).toMatchObject({ ok: true, assumptions: ['server_tool'] });
      return micros(b) - micros(plain) - (size(b) - size(plain)) * 3;
    };
    expect(added('code_interpreter')).toBe(SERVER_TOOL_USES_ASSUMED * 30_000);
    expect(added('image_generation')).toBe(SERVER_TOOL_USES_ASSUMED * 250_000);
    expect(added('file_search')).toBe(SERVER_TOOL_USES_ASSUMED * 2_500);
    expect(added('mcp')).toBe(SERVER_TOOL_USES_ASSUMED * SERVER_TOOL_USE_ALLOWANCE_USD_MICROS);
    expect(added('computer_use_preview', { max_uses: 2 })).toBe(2 * SERVER_TOOL_USE_ALLOWANCE_USD_MICROS);
  });

  it("lets the caller's own function tools through, even one named web_search, at their tokens only", () => {
    const b = { ...base, max_tokens: 100, tools: [{ type: 'function', function: { name: 'web_search', parameters: {} } }, { name: 'lookup', input_schema: {} }] };
    expect(micros(b)).toBe(Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 100 * 15));
  });
});

describe('PDF parsing', () => {
  const pdf = (content: Buffer) => ({ ...base, max_tokens: 100, messages: [{ role: 'user', content: [{ type: 'file', file: { filename: 'a.pdf', file_data: `data:application/pdf;base64,${content.toString('base64')}` } }] }] });
  const file = Buffer.from('%PDF-1.4\n<< /Type /Pages /Count 2 >>\n<< /Type /Page >>\n<< /Type /Page >>\n%%EOF');

  it('charges no OCR on a model that reads files itself, or when the file-parser names a free engine', () => {
    const reader: WorstCaseListing = { ...chat, id: 'acme/reader', modalities: { input: ['text', 'file'], output: ['text'] } };
    const ocr = micros(pdf(file));
    expect(ocr - micros({ ...pdf(file), model: 'acme/reader' }, reader)).toBe(2 * PDF_OCR_USD_MICROS_PER_PAGE);
    const free = { ...pdf(file), plugins: [{ id: 'file-parser', pdf: { engine: 'cloudflare-ai' } }] };
    expect(ocr - (micros(free) - (size(free) - size(pdf(file))) * 3)).toBe(2 * PDF_OCR_USD_MICROS_PER_PAGE);
    const mystery = { ...pdf(file), plugins: [{ id: 'file-parser', pdf: { engine: 'mystery' } }] };
    expect(worst(mystery)).toMatchObject({ ok: true, assumptions: ['pdf_engine_unknown'] });
    expect(micros(mystery) - (size(mystery) - size(pdf(file))) * 3).toBe(ocr);
  });

  it('never counts a PDF at fewer pages than its size allows, however few it says it has', () => {
    const decoy = Buffer.concat([Buffer.from('%PDF-1.4\n<< /Type /Page >>\n'), Buffer.alloc(5 * PDF_FALLBACK_BYTES_PER_PAGE, 32)]);
    const pages = Math.ceil(decoy.length / PDF_FALLBACK_BYTES_PER_PAGE);
    expect(pages).toBe(6);
    const b = pdf(decoy);
    const payload = `data:application/pdf;base64,${decoy.toString('base64')}`.length;
    expect(micros(b)).toBe(Math.ceil((size(b) - payload + TEMPLATE_ALLOWANCE_TOKENS + pages * PDF_PAGE_INPUT_TOKENS) * 3 + 100 * 15 + pages * PDF_OCR_USD_MICROS_PER_PAGE));
  });
});

describe('router models', () => {
  const router: WorstCaseListing = { id: 'openrouter/auto', modalities: { input: ['text'], output: ['text'] }, price: { unit: 'varies', provider_cost: null } };
  const unpriced: WorstCaseListing = { id: 'acme/mystery', modalities: { input: ['text'], output: ['text'] }, price: { unit: 'varies', provider_cost: null } };

  it('holds every model OpenRouter lists with no price that makes only text as a router, at the dearest model it could pick', () => {
    const b = { model: 'openrouter/auto', messages: [], max_tokens: 100 };
    const viaRouter = worst(b, router, chat, unpriced);
    expect(viaRouter).toMatchObject({ ok: true, assumptions: ['router'] });
    const asChat = openRouterWorstCase({ body: { ...b, model: 'acme/chat-1' }, bodyBytes: size(b), listings: catalogue(router, chat, unpriced) });
    expect(viaRouter.usdMicros).toBe(asChat.usdMicros);
    const fusion: WorstCaseListing = { ...router, id: 'openrouter/fusion' };
    const viaFusion = { model: 'openrouter/fusion', messages: [], max_tokens: 100 };
    expect(worst(viaFusion, fusion, chat).usdMicros)
      .toBe(openRouterWorstCase({ body: { ...viaFusion, model: 'acme/chat-1' }, bodyBytes: size(viaFusion), listings: catalogue(fusion, chat) }).usdMicros);
    // A router with nothing it could pick is held at the unpriced allowance.
    expect(worst({ model: 'acme/mystery', messages: [], max_tokens: 10 }, unpriced)).toMatchObject({ ok: true, usdMicros: UNPRICED_CALL_HOLD_USD_MICROS, assumptions: ['router'] });
  });

  it('holds a model listed with no price that makes more than text (music) at the unpriced allowance', () => {
    const music: WorstCaseListing = { id: 'acme/music', modalities: { input: ['text'], output: ['text', 'audio'] }, price: { unit: 'varies', provider_cost: null } };
    expect(worst({ model: 'acme/music', messages: [] }, music)).toMatchObject({ ok: true, usdMicros: UNPRICED_CALL_HOLD_USD_MICROS, assumptions: ['price_unlisted'] });
  });

  it('ignores allowed_models it does not read (too many, too long, not a list) and counts every model the router could pick', () => {
    const cheap: WorstCaseListing = { ...chat, id: 'acme/cheap', price: { unit: 'token', provider_cost: { input_per_million_tokens_usd_micros: 1, output_per_million_tokens_usd_micros: 1 } } };
    const b = (patterns: unknown) => ({ model: 'openrouter/auto', messages: [], max_tokens: 10, plugins: [{ id: 'auto-router', allowed_models: patterns }] });
    // What the dearest model it could pick holds for the same request.
    const dearest = (body: Record<string, unknown>) => openRouterWorstCase({ body: { ...body, model: 'acme/chat-1' }, bodyBytes: size(body), listings: catalogue(router, chat, cheap) }).usdMicros;
    const narrowed = b(['acme/cheap']);
    expect(worst(narrowed, router, chat, cheap).usdMicros).toBeLessThan(dearest(narrowed));
    for (const ignored of [b(Array.from({ length: ROUTER_ALLOWED_MODELS_MAX + 1 }, () => 'acme/cheap')), b(['a'.repeat(ROUTER_PATTERN_MAX_CHARS + 1)]), b('acme/cheap')]) {
      expect(worst(ignored, router, chat, cheap).usdMicros).toBe(dearest(ignored));
    }
  });

  it('matches a pattern that backtracks a regular expression in linear time', () => {
    const hostile = `${'*a'.repeat(99)}!`;
    const id = `acme/${'a'.repeat(176)}`;
    const started = performance.now();
    for (let i = 0; i < 1_000; i += 1) wildcardMatches(hostile, id);
    expect(performance.now() - started).toBeLessThan(1_000);
    const b = { model: 'openrouter/auto', messages: [], max_tokens: 10, plugins: [{ id: 'auto-router', allowed_models: Array.from({ length: ROUTER_ALLOWED_MODELS_MAX }, () => hostile.slice(0, ROUTER_PATTERN_MAX_CHARS)) }] };
    const many = Array.from({ length: 500 }, (_, i): WorstCaseListing => ({ ...chat, id: `acme/${'a'.repeat(150)}${i}` }));
    const timed = performance.now();
    worst(b, router, ...many);
    expect(performance.now() - timed).toBeLessThan(5_000);
  });

  it('matches stars as any run of characters, anchored at both ends', () => {
    expect(wildcardMatches('anthropic/*', 'anthropic/claude-x')).toBe(true);
    expect(wildcardMatches('anthropic/*', 'openai/gpt')).toBe(false);
    expect(wildcardMatches('*/gpt-*-mini', 'openai/gpt-5-mini')).toBe(true);
    expect(wildcardMatches('*/gpt-*-mini', 'openai/gpt-5-mini-x')).toBe(false);
    expect(wildcardMatches('a*b*c', 'abc')).toBe(true);
    expect(wildcardMatches('a*b*c', 'acb')).toBe(false);
    expect(wildcardMatches('ab*ba', 'aba')).toBe(false);
    expect(wildcardMatches('exact/id', 'exact/id')).toBe(true);
    expect(wildcardMatches('*', '')).toBe(true);
    expect(wildcardMatches('a.b', 'aXb')).toBe(false);
  });
});

describe('estimates for what the listing does not price', () => {
  it('holds a transcription from the size of its audio, the unit read as a second or a token by its price', () => {
    const perSecond: WorstCaseListing = { id: 'acme/stt', modalities: { input: ['audio'], output: ['transcription'] }, price: { unit: 'lines', provider_cost: { lines: [{ item: 'prompt', per: 'audio_unit', per_count: 1, cost_usd_micros: 100 }] } } };
    const audio = Buffer.alloc(1024 * 1024, 1).toString('base64');
    const b = { model: 'acme/stt', input_audio: { data: audio, format: 'mp3' } };
    expect(worst(b, perSecond)).toMatchObject({ ok: true, usdMicros: AUDIO_SECONDS_PER_MB * 100, assumptions: ['audio_estimated'] });
    const timed = { model: 'acme/stt', input_audio: { data: audio, format: 'mp3', duration: 30 } };
    expect(worst(timed, perSecond).usdMicros).toBe(30 * 100);
    const perToken: WorstCaseListing = { ...perSecond, id: 'acme/stt-2', price: { unit: 'lines', provider_cost: { lines: [{ item: 'prompt', per: 'audio_unit', per_count: 1_000_000, cost_usd_micros: 2_500_000 }] } } };
    expect(worst({ ...b, model: 'acme/stt-2' }, perToken).usdMicros).toBe(Math.ceil(AUDIO_INPUT_TOKENS_PER_MB * 2.5));
    // A transcription sent as a form: the model from its field and the audio at the file's size.
    const form = openRouterWorstCase({ body: {}, bodyBytes: 1024 * 1024, listings: catalogue(perSecond), form: { model: 'acme/stt', fileBytes: 1024 * 1024 } });
    expect(form.usdMicros).toBe(AUDIO_SECONDS_PER_MB * 100);
  });

  it('holds a video priced per video token at the requested resolution and length, else 1080p for VIDEO_ASSUMED_SECONDS', () => {
    const tokens: WorstCaseListing = { id: 'acme/vt', modalities: { input: ['text'], output: ['video'] }, price: { unit: 'lines', provider_cost: { lines: [{ item: 'video_tokens', per: 'token', per_count: 1_000_000, cost_usd_micros: 7_000_000 }] } } };
    const none = { model: 'acme/vt', prompt: 'a cat' };
    const estimate = worst(none, tokens);
    expect(estimate.assumptions).toEqual(['video_estimated']);
    const expected = (w: number, h: number, s: number) => (w * h * VIDEO_ASSUMED_FPS * s) / VIDEO_PIXELS_PER_TOKEN;
    expect(estimate.usdMicros).toBe(Math.ceil((size(none) + TEMPLATE_ALLOWANCE_TOKENS) * 7 + Math.ceil(expected(1_920, 1_080, VIDEO_ASSUMED_SECONDS)) * 7));
    const small = { model: 'acme/vt', prompt: 'a cat', resolution: '720p', duration: 5 };
    expect(worst(small, tokens).usdMicros).toBe(Math.ceil((size(small) + TEMPLATE_ALLOWANCE_TOKENS) * 7 + Math.ceil(expected(1_280, 720, 5)) * 7));
  });

  it('holds a picture model priced per image token with no limit at IMAGE_OUTPUT_TOKENS_PER_IMAGE a picture', () => {
    const images: WorstCaseListing = { id: 'acme/img', modalities: { input: ['text'], output: ['image'] }, price: { unit: 'lines', provider_cost: { lines: [{ item: 'image_output', per: 'token', per_count: 1_000_000, cost_usd_micros: 10_000_000 }] } } };
    const two = { model: 'acme/img', prompt: 'a lighthouse', n: 2 };
    expect(worst(two, images)).toMatchObject({ ok: true, usdMicros: 2 * IMAGE_OUTPUT_TOKENS_PER_IMAGE * 10, assumptions: ['image_output_estimated'] });
  });

  it('holds a ranking model with no listed price at a search for every 100 documents and its bytes as tokens', () => {
    const rerank: WorstCaseListing = { id: 'acme/rerank', modalities: { input: ['text'], output: ['rerank'] }, price: { unit: 'varies', provider_cost: null } };
    const b = { model: 'acme/rerank', query: 'q', documents: Array.from({ length: 150 }, (_, i) => `document ${i}`) };
    expect(worst(b, rerank)).toMatchObject({
      ok: true, usdMicros: Math.ceil(2 * RERANK_USD_MICROS_PER_SEARCH + size(b) * RERANK_USD_MICROS_PER_MILLION_TOKENS / 1_000_000), assumptions: ['rerank'],
    });
  });
});
