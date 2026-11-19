import { describe, expect, it } from 'vitest';
import { ResponseTap, readUsage, usageFromText } from './tap.js';

const enc = (text: string) => new TextEncoder().encode(text);

function tapOf(contentType: string, chunks: Array<string | Uint8Array>, options: { header?: string | null; wantText?: boolean } = {}) {
  const tap = new ResponseTap({ contentType, generationIdHeader: options.header ?? null, wantText: options.wantText ?? false });
  for (const chunk of chunks) tap.push(typeof chunk === 'string' ? enc(chunk) : chunk);
  return tap.result();
}

describe('reading a usage object', () => {
  it('takes the cost as OpenRouter reports it, in a number or a numeric string', () => {
    expect(readUsage({ prompt_tokens: 3, completion_tokens: 4, total_tokens: 7, cost: 0.01 })).toEqual({
      prompt_tokens: 3, completion_tokens: 4, total_tokens: 7, provider_cost_usd: 0.01,
    });
    expect(readUsage({ cost: '0.5' })).toMatchObject({ provider_cost_usd: 0.5 });
    expect(readUsage({ input_tokens: 9, output_tokens: 1 })).toMatchObject({ prompt_tokens: 9, completion_tokens: 1, total_tokens: 10 });
    expect(readUsage({ cost: 0, prompt_tokens: 1, completion_tokens: 0, prompt_tokens_details: { cached_tokens: 1 } }))
      .toMatchObject({ provider_cost_usd: 0, cached_prompt_tokens: 1 });
  });

  it('reports no cost when OpenRouter reported none, and nothing for what is not usage', () => {
    expect(readUsage({ prompt_tokens: 3, completion_tokens: 1 })).not.toHaveProperty('provider_cost_usd');
    expect(readUsage({ cost: null })).toBeNull();
    expect(readUsage({ cost: -1 })).toBeNull();
    expect(readUsage('x')).toBeNull();
    expect(readUsage(null)).toBeNull();
  });

  it('finds the last usage object in a text, with the objects nested in it', () => {
    const text = '{"choices":[],"usage":{"cost":1,"cost_details":{"upstream_inference_cost":1}},"x":{"usage":{"cost":2,"prompt_tokens_details":{"cached_tokens":0}}}}';
    expect(usageFromText(text)).toMatchObject({ provider_cost_usd: 2 });
    expect(usageFromText('no usage here')).toBeNull();
  });
});

describe('a JSON answer', () => {
  it('reads the cost and the generation id from the body', () => {
    const result = tapOf('application/json', [JSON.stringify({ id: 'gen-1', choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, cost: 0.003 } })]);
    expect(result.generationId).toBe('gen-1');
    expect(result.usage).toMatchObject({ provider_cost_usd: 0.003 });
    expect(result.json).toMatchObject({ id: 'gen-1' });
  });

  it('prefers the generation id of the header, and has none for an answer that names none', () => {
    expect(tapOf('audio/mpeg', [new Uint8Array([1, 2, 3])], { header: 'gen-tts' }).generationId).toBe('gen-tts');
    expect(tapOf('audio/mpeg', [new Uint8Array([1, 2, 3])]).generationId).toBeNull();
    expect(tapOf('application/json', ['{"id":"chatcmpl-1"}']).generationId).toBeNull();
  });

  it('reads the cost across chunk boundaries', () => {
    const body = JSON.stringify({ id: 'gen-2', usage: { cost: 0.25 } });
    expect(tapOf('application/json', [body.slice(0, 7), body.slice(7, 20), body.slice(20)]).usage).toMatchObject({ provider_cost_usd: 0.25 });
  });

  it('reads the usage at the end of an answer too large to parse whole, and the cost a model\'s words cannot fake', () => {
    const big = `{"data":[{"b64_json":"${'A'.repeat(9 * 1024 * 1024)}"}],"revised":"\\"usage\\":{\\"cost\\":0}","usage":{"cost":0.04,"input_tokens":3}}`;
    const chunks: string[] = [];
    for (let at = 0; at < big.length; at += 1024 * 1024) chunks.push(big.slice(at, at + 1024 * 1024));
    const result = tapOf('application/json', chunks);
    expect(result.json).toBeNull();
    expect(result.usage).toMatchObject({ provider_cost_usd: 0.04 });
  });

  it('counts the bytes that passed and keeps a sample of the start for the audit record', () => {
    const result = tapOf('application/json', ['{"a":', '1}']);
    expect(result.bytes).toBe(7);
    expect(result.sample).toBe('{"a":1}');
  });

  it('reads no usage from a binary answer', () => {
    expect(tapOf('video/mp4', [enc('"usage":{"cost":5}')]).usage).toBeNull();
  });
});

describe('an event stream', () => {
  const chunkEvents = (events: string[], size: number) => {
    const text = events.join('');
    const out: string[] = [];
    for (let at = 0; at < text.length; at += size) out.push(text.slice(at, at + size));
    return out;
  };

  it('reads the cost in the last chat chunk however the bytes are cut, and the generation id', () => {
    const events = [
      'data: {"id":"gen-s","choices":[{"delta":{"content":"a"}}]}\n\n',
      ': OPENROUTER PROCESSING\n\n',
      'data: {"id":"gen-s","choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"cost":0.0004}}\r\n\r\n',
      'data: [DONE]\n\n',
    ];
    for (const size of [1, 5, 50, 10_000]) {
      const result = tapOf('text/event-stream; charset=utf-8', chunkEvents(events, size));
      expect(result.usage, `chunks of ${size}`).toMatchObject({ provider_cost_usd: 0.0004, prompt_tokens: 2 });
      expect(result.generationId).toBe('gen-s');
    }
  });

  it('reads the cost of a Responses answer and of an Anthropic-shaped one', () => {
    expect(tapOf('text/event-stream', ['data: {"type":"response.completed","response":{"usage":{"input_tokens":4,"output_tokens":2,"cost":0.01}}}\n\n']).usage)
      .toMatchObject({ provider_cost_usd: 0.01, prompt_tokens: 4 });
    expect(tapOf('text/event-stream', ['event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":5,"cost":0.02}}\n\n']).usage)
      .toMatchObject({ provider_cost_usd: 0.02 });
  });

  it('has no cost for a stream cut off before its last event', () => {
    const result = tapOf('text/event-stream', ['data: {"id":"gen-cut","choices":[{"delta":{"content":"a"}}]}\n\n']);
    expect(result.usage).toBeNull();
    expect(result.generationId).toBe('gen-cut');
  });

  it('collects the words of a stream when asked, up to a bound, and not otherwise', () => {
    const events = ['data: {"choices":[{"delta":{"content":"hel"}}]}\n\n', 'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n', 'data: {"type":"response.output_text.delta","delta":" world"}\n\n'];
    expect(tapOf('text/event-stream', events, { wantText: true }).text).toBe('hello world');
    expect(tapOf('text/event-stream', events).text).toBe('');
  });

  it('reads the cost of an event too large to parse, from the end of it', () => {
    const line = `data: {"image":"${'A'.repeat(300 * 1024)}","usage":{"cost":0.07}}\n\n`;
    expect(tapOf('text/event-stream', [line]).usage).toMatchObject({ provider_cost_usd: 0.07 });
  });
});
