import { describe, expect, it } from 'vitest';
import {
  ASSUMED_OUTPUT_TOKENS,
  AUDIO_INPUT_TOKENS_PER_MB,
  AUDIO_INPUT_TOKENS_PER_SECOND,
  IMAGE_INPUT_TOKENS,
  PDF_FALLBACK_BYTES_PER_PAGE,
  PDF_OCR_USD_MICROS_PER_PAGE,
  PDF_PAGE_INPUT_TOKENS,
  PLUGIN_USE_ALLOWANCE_USD_MICROS,
  UNPRICED_CALL_HOLD_USD_MICROS,
  VIDEO_ASSUMED_SECONDS,
  WEB_TOOL_USES_ASSUMED,
  REFERENCED_MEDIA_ASSUMED_BYTES,
  TEMPLATE_ALLOWANCE_TOKENS,
  VIDEO_INPUT_TOKENS_PER_MB,
  WEB_RESULT_INPUT_TOKENS,
  modelTokenUsageUsdMicros,
  openRouterWorstCase,
  tokenUsageUsdMicros,
  type WorstCaseListing,
  type WorstCaseListings,
} from './openrouter-worst-case.js';

const tokenPrice = (input: number, output: number, lines?: ReadonlyArray<{ item: string; per: 'token' | 'search' | 'image'; per_count: 1 | 1_000_000; cost_usd_micros: number }>): WorstCaseListing['price'] => ({
  unit: 'token',
  provider_cost: { input_per_million_tokens_usd_micros: input, output_per_million_tokens_usd_micros: output, ...(lines ? { lines } : {}) },
});

function catalogue(...listings: WorstCaseListing[]): WorstCaseListings {
  const byId = new Map(listings.map((l) => [l.id, l]));
  return { find: (id) => byId.get(id) ?? null, all: () => listings };
}

const chat: WorstCaseListing = {
  id: 'acme/chat-1',
  modalities: { input: ['text', 'image'], output: ['text'] },
  context_length: 200_000,
  max_completion_tokens: 8_000,
  // $3 per million input tokens, $15 per million output tokens.
  price: tokenPrice(3_000_000, 15_000_000, [
    { item: 'input_cache_read', per: 'token', per_count: 1_000_000, cost_usd_micros: 300_000 },
    { item: 'web_search', per: 'search', per_count: 1, cost_usd_micros: 10_000 },
    { item: 'image', per: 'image', per_count: 1, cost_usd_micros: 4_800 },
  ]),
};
const plain: WorstCaseListing = {
  id: 'acme/plain-1',
  modalities: { input: ['text'], output: ['text'] },
  context_length: 32_000,
  max_completion_tokens: 4_000,
  price: tokenPrice(1_000_000, 2_000_000),
};

const body = (extra: Record<string, unknown> = {}) => ({ model: 'acme/chat-1', messages: [{ role: 'user', content: 'hello' }], ...extra });
const size = (b: Record<string, unknown>) => Buffer.byteLength(JSON.stringify(b));

describe('openRouterWorstCase', () => {
  it('holds the request bytes plus the template allowance as input and the listed maximum completion as output when the request sets none', () => {
    const b = body();
    const result = openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(chat) });
    const micros = (size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 8_000 * 15;
    expect(result).toEqual({ ok: true, usdMicros: Math.ceil(micros), cents: Math.ceil(micros / 10_000), assumptions: [] });
  });

  it("uses the request's own output limit, times n, and never more than the context length", () => {
    const b = body({ max_tokens: 1_000, n: 3 });
    const result = openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(chat) });
    expect(result).toMatchObject({ ok: true, usdMicros: Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 3_000 * 15) });
    const huge = body({ max_completion_tokens: 50_000_000 });
    const capped = openRouterWorstCase({ body: huge, bodyBytes: size(huge), listings: catalogue(chat) });
    expect(capped).toMatchObject({ ok: true, usdMicros: Math.ceil((size(huge) + TEMPLATE_ALLOWANCE_TOKENS) * 3 + 200_000 * 15) });
  });

  describe('media in the request', () => {
    const cost = (b: Record<string, unknown>, listing: WorstCaseListing = chat) => {
      const result = openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(listing) });
      return result.usdMicros;
    };
    const user = (...parts: unknown[]) => body({ messages: [{ role: 'user', content: parts }], max_tokens: 100 });
    const text = (b: Record<string, unknown>, payloadChars = 0) => size(b) - payloadChars + TEMPLATE_ALLOWANCE_TOKENS;

    it('counts a picture as IMAGE_INPUT_TOKENS at the input price, or at its per-image price when that is dearer', () => {
      const b = user({ type: 'image_url', image_url: { url: 'https://example.com/a.png' } });
      // 3 micro-dollars a token: 2,000 tokens are 6,000, above the 4,800 per-image line.
      expect(cost(b)).toBe(Math.ceil(text(b) * 3 + 100 * 15 + IMAGE_INPUT_TOKENS * 3));
      const dearImage: WorstCaseListing = { ...chat, price: tokenPrice(3_000_000, 15_000_000, [{ item: 'image', per: 'image', per_count: 1, cost_usd_micros: 9_000 }]) };
      expect(cost(b, dearImage)).toBe(Math.ceil(text(b) * 3 + 100 * 15 + 9_000));
      const two = user({ type: 'image_url', image_url: { url: 'https://example.com/a.png' } }, { type: 'image_url', image_url: { url: 'https://example.com/b.png' } });
      expect(cost(two)).toBe(Math.ceil(text(two) * 3 + 100 * 15 + 2 * IMAGE_INPUT_TOKENS * 3));
    });

    it('takes what a picture carries in its own bytes out of the text, so it is not counted twice', () => {
      const data = 'A'.repeat(40_000);
      const b = user({ type: 'image_url', image_url: { url: `data:image/png;base64,${data}` } });
      const payloadChars = `data:image/png;base64,${data}`.length;
      expect(cost(b)).toBe(Math.ceil(text(b, payloadChars) * 3 + 100 * 15 + IMAGE_INPUT_TOKENS * 3));
    });

    it('counts a PDF page as PDF_PAGE_INPUT_TOKENS and, on a model that does not read files, at the OCR price a page', () => {
      const pages = Buffer.from('%PDF-1.4\n1 0 obj << /Type /Pages /Count 3 >> endobj\n' + '<< /Type /Page >>\n'.repeat(3) + '%%EOF');
      const withPages = user({ type: 'file', file: { filename: 'a.pdf', file_data: `data:application/pdf;base64,${pages.toString('base64')}` } });
      const payload = pages.toString('base64').length + 'data:application/pdf;base64,'.length;
      expect(cost(withPages)).toBe(Math.ceil(text(withPages, payload) * 3 + 100 * 15 + 3 * PDF_PAGE_INPUT_TOKENS * 3 + 3 * PDF_OCR_USD_MICROS_PER_PAGE));
      const opaque = Buffer.concat([Buffer.from('%PDF-1.5\n'), Buffer.alloc(250_000, 1)]);
      const unread = user({ type: 'file', file: { filename: 'b.pdf', file_data: `data:application/pdf;base64,${opaque.toString('base64')}` } });
      const unreadPayload = opaque.toString('base64').length + 'data:application/pdf;base64,'.length;
      const fallbackPages = Math.ceil(Math.floor((opaque.toString('base64').length * 3) / 4) / PDF_FALLBACK_BYTES_PER_PAGE);
      expect(fallbackPages).toBe(3);
      expect(cost(unread)).toBe(Math.ceil(text(unread, unreadPayload) * 3 + 100 * 15 + fallbackPages * PDF_PAGE_INPUT_TOKENS * 3 + fallbackPages * PDF_OCR_USD_MICROS_PER_PAGE));
    });

    it('counts audio and video by the megabyte, or by the length the request states', () => {
      const audio = Buffer.alloc(2 * 1024 * 1024, 7).toString('base64');
      const heard = user({ type: 'input_audio', input_audio: { data: audio, format: 'mp3' } });
      expect(cost(heard)).toBe(Math.ceil(text(heard, audio.length) * 3 + 100 * 15 + 2 * AUDIO_INPUT_TOKENS_PER_MB * 3));
      const timed = user({ type: 'input_audio', input_audio: { data: audio, format: 'mp3', duration: 10 } });
      expect(cost(timed)).toBe(Math.ceil(text(timed, audio.length) * 3 + 100 * 15 + 10 * AUDIO_INPUT_TOKENS_PER_SECOND * 3));
      const film = Buffer.alloc(1024 * 1024, 9).toString('base64');
      const seen = user({ type: 'video_url', video_url: { url: `data:video/mp4;base64,${film}` } });
      const filmPayload = film.length + 'data:video/mp4;base64,'.length;
      expect(cost(seen)).toBe(Math.ceil(text(seen, filmPayload) * 3 + 100 * 15 + VIDEO_INPUT_TOKENS_PER_MB * 3));
    });

    it('counts a file named by its address, whose size the request does not say, as REFERENCED_MEDIA_ASSUMED_BYTES', () => {
      const linked = user({ type: 'video_url', video_url: { url: 'https://example.com/clip.mp4' } });
      const megabytes = REFERENCED_MEDIA_ASSUMED_BYTES / (1024 * 1024);
      expect(cost(linked)).toBe(Math.ceil(text(linked) * 3 + 100 * 15 + megabytes * VIDEO_INPUT_TOKENS_PER_MB * 3));
    });

    it('never holds more input than the model reads', () => {
      const small: WorstCaseListing = { ...chat, context_length: 3_000, max_completion_tokens: 100 };
      const pdf = user({ type: 'file', file: { filename: 'c.pdf', file_data: 'https://example.com/c.pdf' } });
      // The pages alone would be far above 3,000 tokens: the input is the context, the output its own limit. The pages of a file
      // named by address are counted from REFERENCED_MEDIA_ASSUMED_BYTES for the OCR price.
      const pages = Math.ceil(REFERENCED_MEDIA_ASSUMED_BYTES / PDF_FALLBACK_BYTES_PER_PAGE);
      expect(cost(pdf, small)).toBe(3_000 * 3 + 100 * 15 + pages * PDF_OCR_USD_MICROS_PER_PAGE);
    });
  });

  it('holds a call with no output limit at the smaller of the listed maximum and 8,192 tokens, times n', () => {
    expect(ASSUMED_OUTPUT_TOKENS).toBe(8_192);
    const big: WorstCaseListing = { ...plain, id: 'acme/big', context_length: 1_000_000, max_completion_tokens: 128_000 };
    const b = { model: 'acme/big', messages: [], n: 2 };
    expect(openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(big) }).usdMicros)
      .toBe(Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 1 + 8_192 * 2 * 2));
    // A listed maximum below 8,192 is the figure; a limit the request names is used as it is, above 8,192 too.
    const small: WorstCaseListing = { ...big, id: 'acme/small', max_completion_tokens: 1_000 };
    const s = { model: 'acme/small', messages: [] };
    expect(openRouterWorstCase({ body: s, bodyBytes: size(s), listings: catalogue(small) }).usdMicros)
      .toBe(Math.ceil((size(s) + TEMPLATE_ALLOWANCE_TOKENS) * 1 + 1_000 * 2));
    const named = { ...b, max_tokens: 50_000 };
    expect(openRouterWorstCase({ body: named, bodyBytes: size(named), listings: catalogue(big) }).usdMicros)
      .toBe(Math.ceil((size(named) + TEMPLATE_ALLOWANCE_TOKENS) * 1 + 50_000 * 2 * 2));
  });

  it('holds a model with a context length and no listed maximum at 8,192 tokens, not at its context length', () => {
    const noMax: WorstCaseListing = { ...plain, id: 'acme/no-max', context_length: 1_000_000, max_completion_tokens: undefined };
    const b = { model: 'acme/no-max', messages: [] };
    expect(openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(noMax) })).toMatchObject({
      usdMicros: Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 1 + 8_192 * 2), assumptions: ['output_tokens_assumed'],
    });
  });

  it('holds a call with no output limit on a model that lists neither a maximum nor a context length at ASSUMED_OUTPUT_TOKENS', () => {
    const bare: WorstCaseListing = { ...plain, id: 'acme/bare', context_length: undefined, max_completion_tokens: undefined };
    const b = { model: 'acme/bare', messages: [] };
    expect(openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(bare) })).toMatchObject({
      ok: true, usdMicros: Math.ceil((size(b) + TEMPLATE_ALLOWANCE_TOKENS) * 1 + ASSUMED_OUTPUT_TOKENS * 2), assumptions: ['output_tokens_assumed'],
    });
    const limited = { ...b, max_tokens: 50 };
    expect(openRouterWorstCase({ body: limited, bodyBytes: size(limited), listings: catalogue(bare) })).toMatchObject({ ok: true });
  });

  it('prices :online and the web plugin with the model\'s own search line, five results unless the request says, and counts what the results add to the input', () => {
    const online = { ...body({ max_tokens: 10 }), model: 'acme/chat-1:online' };
    const base = openRouterWorstCase({ body: body({ max_tokens: 10 }), bodyBytes: size(online), listings: catalogue(chat) });
    const withSearch = openRouterWorstCase({ body: online, bodyBytes: size(online), listings: catalogue(chat) });
    expect(base.ok && withSearch.ok && withSearch.usdMicros - base.usdMicros).toBe(5 * 10_000 + 5 * WEB_RESULT_INPUT_TOKENS * 3);
    const plugin = body({ max_tokens: 10, plugins: [{ id: 'web', max_results: 2 }] });
    const viaPlugin = openRouterWorstCase({ body: plugin, bodyBytes: size(online), listings: catalogue(chat) });
    expect(base.ok && viaPlugin.ok && viaPlugin.usdMicros - base.usdMicros).toBe(2 * 10_000 + 2 * WEB_RESULT_INPUT_TOKENS * 3);
  });

  it('estimates a native search on a model that lists no search price, a search tool with no limit, and a plugin with a charge of its own', () => {
    const native = body({ model: 'acme/plain-1', web_search_options: {} });
    expect(openRouterWorstCase({ body: native, bodyBytes: size(native), listings: catalogue(plain) })).toMatchObject({ ok: true, assumptions: ['web_engine_unknown'] });
    const tool = body({ tools: [{ type: 'web_search_20250305', name: 'web_search' }] });
    const bounded = body({ tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: WEB_TOOL_USES_ASSUMED }] });
    const unboundedHold = openRouterWorstCase({ body: tool, bodyBytes: size(bounded), listings: catalogue(chat) });
    expect(unboundedHold).toMatchObject({ ok: true, assumptions: ['web_uses_assumed'] });
    expect(unboundedHold.usdMicros).toBe(openRouterWorstCase({ body: bounded, bodyBytes: size(bounded), listings: catalogue(chat) }).usdMicros);
    const plugin = body({ plugins: [{ id: 'mystery' }] });
    const bare = body();
    expect(openRouterWorstCase({ body: plugin, bodyBytes: size(bare), listings: catalogue(chat) }).usdMicros
      - openRouterWorstCase({ body: bare, bodyBytes: size(bare), listings: catalogue(chat) }).usdMicros).toBe(PLUGIN_USE_ALLOWANCE_USD_MICROS);
  });

  it('holds a router model at the dearest text model it could pick, narrowed by an auto-router plugin', () => {
    const router: WorstCaseListing = { id: 'openrouter/auto', modalities: { input: ['text'], output: ['text'] }, price: { unit: 'varies', provider_cost: null } };
    const all = catalogue(router, chat, plain);
    const b = { model: 'openrouter/auto', messages: [], max_tokens: 100 };
    const dearest = openRouterWorstCase({ body: b, bodyBytes: size(b), listings: all });
    const chatOnly = openRouterWorstCase({ body: { ...b, model: 'acme/chat-1' }, bodyBytes: size(b), listings: all });
    expect(dearest).toMatchObject({ ok: true, usdMicros: expect.any(Number) });
    expect(dearest.ok && chatOnly.ok && dearest.usdMicros).toBe(chatOnly.ok ? chatOnly.usdMicros : -1);
    const narrowed = { ...b, plugins: [{ id: 'auto-router', allowed_models: ['acme/plain-*'] }] };
    const cheaper = openRouterWorstCase({ body: narrowed, bodyBytes: size(narrowed), listings: all });
    expect(cheaper.ok && dearest.ok && cheaper.usdMicros < dearest.usdMicros).toBe(true);
  });

  it('holds the dearest candidate of a router and of a fallback list at 8,192 output tokens when the request names no limit', () => {
    const router: WorstCaseListing = { id: 'openrouter/auto', modalities: { input: ['text'], output: ['text'] }, price: { unit: 'varies', provider_cost: null } };
    const dear: WorstCaseListing = { ...plain, id: 'acme/dear', context_length: 1_000_000, max_completion_tokens: 200_000, price: tokenPrice(1_000_000, 10_000_000) };
    const cheap: WorstCaseListing = { ...plain, id: 'acme/cheap', context_length: 1_000_000, max_completion_tokens: 200_000, price: tokenPrice(100_000, 100_000) };
    const routed = { model: 'openrouter/auto', messages: [] };
    expect(openRouterWorstCase({ body: routed, bodyBytes: size(routed), listings: catalogue(router, dear, cheap) }).usdMicros)
      .toBe(Math.ceil((size(routed) + TEMPLATE_ALLOWANCE_TOKENS) * 1 + 8_192 * 10));
    const fallback = { model: 'acme/cheap', models: ['acme/dear'], messages: [] };
    expect(openRouterWorstCase({ body: fallback, bodyBytes: size(fallback), listings: catalogue(dear, cheap) }).usdMicros)
      .toBe(Math.ceil((size(fallback) + TEMPLATE_ALLOWANCE_TOKENS) * 1 + 8_192 * 10));
  });

  it('prices a video by its duration at the dearest per-second line, and at VIDEO_ASSUMED_SECONDS when there is none', () => {
    const video: WorstCaseListing = {
      id: 'acme/video-1',
      modalities: { input: ['text'], output: ['video'] },
      price: {
        unit: 'lines',
        provider_cost: {
          lines: [
            { item: 'cents_per_video_output_second_480p', per: 'second', per_count: 1, cost_usd_micros: 5_000 },
            { item: 'cents_per_video_output_second_1080p', per: 'second', per_count: 1, cost_usd_micros: 25_000 },
            { item: 'minimum_cents_per_generation', per: 'generation', per_count: 1, cost_usd_micros: 50_000 },
          ],
        },
      },
    };
    const b = { model: 'acme/video-1', prompt: 'a cat', duration: 6 };
    expect(openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(video) })).toEqual({ ok: true, usdMicros: 6 * 25_000 + 50_000, cents: 20, assumptions: [] });
    const none = { model: 'acme/video-1', prompt: 'a cat' };
    expect(openRouterWorstCase({ body: none, bodyBytes: size(none), listings: catalogue(video) })).toMatchObject({
      ok: true, usdMicros: VIDEO_ASSUMED_SECONDS * 25_000 + 50_000, assumptions: ['video_estimated'],
    });
  });

  it('prices speech by the characters of its input, and a price per audio unit from the seconds of speech the input makes', () => {
    const speech: WorstCaseListing = {
      id: 'acme/tts', modalities: { input: ['text'], output: ['speech'] },
      price: { unit: 'lines', provider_cost: { lines: [{ item: 'prompt', per: 'character', per_count: 1, cost_usd_micros: 15 }] } },
    };
    const b = { model: 'acme/tts', input: 'héllo wörld', voice: 'x' };
    expect(openRouterWorstCase({ body: b, bodyBytes: size(b), listings: catalogue(speech) })).toMatchObject({ ok: true, usdMicros: 11 * 15 });
    const audio: WorstCaseListing = {
      ...speech, id: 'acme/tts-2',
      price: { unit: 'lines', provider_cost: { lines: [{ item: 'completion', per: 'audio_unit', per_count: 1, cost_usd_micros: 2_500 }] } },
    };
    // 2,500 micro-dollars a unit is a second; 60 characters are 5 seconds of speech.
    const c = { model: 'acme/tts-2', input: 'x'.repeat(60) };
    expect(openRouterWorstCase({ body: c, bodyBytes: size(c), listings: catalogue(audio) })).toMatchObject({ ok: true, usdMicros: 5 * 2_500, assumptions: ['audio_estimated'] });
  });

  it('holds one cent for a free model, strips a variant suffix the catalogue lacks, takes the dearest of fallback models, and holds an unknown model at the unpriced allowance', () => {
    const free: WorstCaseListing = { ...plain, id: 'acme/free-1:free', price: { unit: 'free', provider_cost: null } };
    const f = { model: 'acme/free-1:free', messages: [] };
    expect(openRouterWorstCase({ body: f, bodyBytes: size(f), listings: catalogue(free) })).toEqual({ ok: true, usdMicros: 0, cents: 1, assumptions: [] });
    const nitro = { model: 'acme/plain-1:nitro', messages: [], max_tokens: 10 };
    expect(openRouterWorstCase({ body: nitro, bodyBytes: size(nitro), listings: catalogue(plain) })).toMatchObject({ ok: true });
    const fallback = { model: 'acme/plain-1', models: ['acme/chat-1'], messages: [], max_tokens: 10 };
    const both = openRouterWorstCase({ body: fallback, bodyBytes: size(fallback), listings: catalogue(plain, chat) });
    const justChat = openRouterWorstCase({ body: { model: 'acme/chat-1', messages: [], max_tokens: 10 }, bodyBytes: size(fallback), listings: catalogue(plain, chat) });
    expect(both.ok && justChat.ok && both.usdMicros === justChat.usdMicros).toBe(true);
    const unknown = { model: 'acme/ghost', messages: [] };
    expect(openRouterWorstCase({ body: unknown, bodyBytes: size(unknown), listings: catalogue(plain) })).toMatchObject({ ok: true, usdMicros: UNPRICED_CALL_HOLD_USD_MICROS, assumptions: ['model_not_listed'] });
    expect(openRouterWorstCase({ body: {}, bodyBytes: 0, listings: catalogue(plain) })).toMatchObject({ ok: true, usdMicros: UNPRICED_CALL_HOLD_USD_MICROS, assumptions: ['model_not_listed'] });
  });
});

describe('tokenUsageUsdMicros: what tokens already used cost at the catalogue price', () => {
  it('prices prompt tokens at the input price and completion tokens at the output price', () => {
    // 5,000 x $3/M + 1,000 x $15/M = $0.015 + $0.015.
    expect(tokenUsageUsdMicros(plain, { prompt_tokens: 5_000, completion_tokens: 1_000 })).toBe(5_000 * 1 + 1_000 * 2);
    expect(tokenUsageUsdMicros(chat, { prompt_tokens: 5_000, completion_tokens: 1_000 })).toBe(5_000 * 3 + 1_000 * 15);
  });

  it('prices cached prompt tokens at the cache-read line when the model lists one, and at the input price when it lists none', () => {
    expect(tokenUsageUsdMicros(chat, { prompt_tokens: 10_000, completion_tokens: 0, cached_prompt_tokens: 8_000 })).toBeCloseTo(2_000 * 3 + 8_000 * 0.3, 6);
    expect(tokenUsageUsdMicros(plain, { prompt_tokens: 10_000, completion_tokens: 0, cached_prompt_tokens: 8_000 })).toBe(10_000);
  });

  it('uses a long-context tier once the prompt has passed its threshold', () => {
    const tiered: WorstCaseListing = {
      ...plain,
      price: {
        unit: 'token',
        provider_cost: {
          input_per_million_tokens_usd_micros: 1_000_000,
          output_per_million_tokens_usd_micros: 2_000_000,
          tiers: [{ above_prompt_tokens: 200_000, lines: [
            { item: 'prompt', per: 'token', per_count: 1_000_000, cost_usd_micros: 2_000_000 },
            { item: 'completion', per: 'token', per_count: 1_000_000, cost_usd_micros: 4_000_000 },
          ] }],
        },
      },
    };
    expect(tokenUsageUsdMicros(tiered, { prompt_tokens: 100_000, completion_tokens: 1_000 })).toBe(100_000 * 1 + 1_000 * 2);
    expect(tokenUsageUsdMicros(tiered, { prompt_tokens: 300_000, completion_tokens: 1_000 })).toBe(300_000 * 2 + 1_000 * 4);
  });

  it('is zero for a free model and null where there is no token price to read', () => {
    expect(tokenUsageUsdMicros({ ...plain, price: { unit: 'free', provider_cost: null } }, { prompt_tokens: 5, completion_tokens: 5 })).toBe(0);
    expect(tokenUsageUsdMicros(null, { prompt_tokens: 5, completion_tokens: 5 })).toBeNull();
    expect(tokenUsageUsdMicros({ ...plain, price: { unit: 'token', provider_cost: null } }, { prompt_tokens: 5, completion_tokens: 5 })).toBeNull();
    expect(tokenUsageUsdMicros({ ...plain, price: { unit: 'varies', provider_cost: null } }, { prompt_tokens: 5, completion_tokens: 5 })).toBeNull();
  });

  it('finds the model by id through the variant suffixes a hold strips, and prices nothing for an unlisted model or a router', () => {
    const usage = { prompt_tokens: 1_000, completion_tokens: 1_000 };
    expect(modelTokenUsageUsdMicros(catalogue(plain), 'acme/plain-1', usage)).toBe(3_000);
    expect(modelTokenUsageUsdMicros(catalogue(plain), 'acme/plain-1:nitro', usage)).toBe(3_000);
    expect(modelTokenUsageUsdMicros(catalogue(plain), 'acme/ghost', usage)).toBeNull();
    const router: WorstCaseListing = { id: 'acme/auto', modalities: { input: ['text'], output: ['text'] }, price: { unit: 'varies', provider_cost: null } };
    expect(modelTokenUsageUsdMicros(catalogue(plain, router), 'acme/auto', usage)).toBeNull();
  });
});
