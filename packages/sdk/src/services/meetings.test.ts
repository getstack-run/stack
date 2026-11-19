import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import type { AccountCallWebSocket, AccountCallWebSocketConstructor } from './accounts.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const parsed = new URL(url);
      calls.push({
        method: init.method ?? 'GET',
        path: parsed.pathname,
        search: parsed.search,
        body: init.body ? JSON.parse(init.body) : undefined,
        headers: init.headers ?? {},
      });
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_meetings_test', baseUrl: 'http://api.fixture' });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('meetings', () => {
  it('join, speak, write and leave on the meeting routes, the agent under its Passport', async () => {
    const calls = stubFetch();
    const { meetings } = stack();
    await meetings.join('acct_1', { event_id: 'cev_1', max_seconds: 1800, wait_seconds: 5 }, { passportToken: 'ppt' });
    await meetings.say('acct_1', 'mtg_1', { text: 'Hello.', wait_seconds: 10 });
    await meetings.chat('acct_1', 'mtg_1', 'Link.');
    await meetings.leave('acct_1', 'mtg_1');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /v1/accounts/acct_1/meetings',
      'POST /v1/accounts/acct_1/meetings/mtg_1/say',
      'POST /v1/accounts/acct_1/meetings/mtg_1/chat',
      'POST /v1/accounts/acct_1/meetings/mtg_1/leave',
    ]);
    expect(calls[0]!.body).toEqual({ event_id: 'cev_1', max_seconds: 1800, wait_seconds: 5 });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('ppt');
    expect(calls[1]!.headers['X-Passport-Token']).toBeUndefined();
    expect(calls[2]!.body).toEqual({ text: 'Link.' });
  });

  it("reads and sets the account's meeting voice, the agent under its Passport, a field left out not sent", async () => {
    const calls = stubFetch();
    const { meetings } = stack();
    await meetings.getVoice('acct_1', { passportToken: 'ppt' });
    await meetings.setVoice('acct_1', { voice: 'Claire', language: 'fr' });
    await meetings.setVoice('acct_1', {});
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'GET /v1/accounts/acct_1/meetings/voice',
      'PUT /v1/accounts/acct_1/meetings/voice',
      'PUT /v1/accounts/acct_1/meetings/voice',
    ]);
    expect(calls[0]!.headers['X-Passport-Token']).toBe('ppt');
    expect(calls[1]!.body).toEqual({ voice: 'Claire', language: 'fr' });
    expect(calls[2]!.body).toEqual({});
  });

  it('reads the list and one meeting, and keeps an id out of the path structure', async () => {
    const calls = stubFetch();
    const { meetings } = stack();
    await meetings.list('acct_1', { status: 'ended', limit: 5, cursor: 'c1' });
    await meetings.get('acct_1', '../x');
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      'GET /v1/accounts/acct_1/meetings?status=ended&limit=5&cursor=c1',
      'GET /v1/accounts/acct_1/meetings/..%2Fx',
    ]);
  });

  it('streams a meeting\'s events and sends words, chat and leave over its WebSocket', async () => {
    stubFetch();
    const listeners: Record<string, Array<(event: { data?: unknown }) => void>> = {};
    const sent: string[] = [];
    let url = '';
    let headers: Record<string, string> = {};
    class FakeSocket implements AccountCallWebSocket {
      readyState = 1;
      constructor(u: string, init: { headers: Record<string, string> }) {
        url = u;
        headers = init.headers;
        queueMicrotask(() => {
          listeners['open']?.forEach((l) => l({}));
          listeners['message']?.forEach((l) => l({ data: JSON.stringify({ seq: 1, at: 'now', type: 'heard', speaker: 'Olivia', text: 'Hi' }) }));
          listeners['message']?.forEach((l) => l({ data: JSON.stringify({ type: 'error', code: 'VALIDATION_ERROR', message: 'no' }) }));
          listeners['message']?.forEach((l) => l({ data: JSON.stringify({ seq: 2, at: 'now', type: 'ended', reason: 'agent_left' }) }));
          listeners['close']?.forEach((l) => l({}));
        });
      }
      send(data: string) {
        sent.push(data);
      }
      close() {}
      addEventListener(type: string, listener: (event: { data?: unknown }) => void) {
        (listeners[type] ??= []).push(listener);
      }
    }
    const stream = await stack().meetings.live('acct_1', 'mtg_1', { passportToken: 'ppt', webSocket: FakeSocket as unknown as AccountCallWebSocketConstructor });
    await stream.text('One more thing.', true);
    await stream.chat('Link.');
    await stream.leave();
    const seen: string[] = [];
    for await (const event of stream.events()) seen.push(event.type);
    expect(url).toBe('ws://api.fixture/v1/accounts/acct_1/meetings/mtg_1/live');
    expect(headers['X-Passport-Token']).toBe('ppt');
    expect(headers['Authorization']).toMatch(/^Bearer /);
    expect(sent.map((s) => JSON.parse(s))).toEqual([{ type: 'text', token: 'One more thing.', last: true }, { type: 'chat', text: 'Link.' }, { type: 'leave' }]);
    expect(seen).toEqual(['heard', 'ended']);
    expect(stream.errors).toEqual([{ code: 'VALIDATION_ERROR', message: 'no' }]);
  });
});
