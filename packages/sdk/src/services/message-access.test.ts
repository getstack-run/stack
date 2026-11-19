import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

const SETTING = {
  agent_id: null,
  read_teammates: null,
  messages_read_only: true,
  effective: { read_teammates: true, messages_read_only: true },
  source: { read_teammates: 'default', messages_read_only: 'account' },
};

function stubFetch(): Array<{ method: string; path: string; body: unknown }> {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string }) => {
      calls.push({ method: init.method ?? 'GET', path: new URL(url).pathname, body: init.body ? JSON.parse(init.body) : undefined });
      return new Response(JSON.stringify(SETTING), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const access = () => new Stack({ apiKey: 'sk_live_message_access_test', baseUrl: 'http://api.fixture' }).messageAccess;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('MessageAccessService', () => {
  it('reads and sets the account values and one agent values', async () => {
    const calls = stubFetch();
    await expect(access().get()).resolves.toEqual(SETTING);
    await access().set({ messages_read_only: true });
    await access().get('agt_one');
    await access().set({ read_teammates: false, messages_read_only: false }, 'agt_one');
    expect(calls).toEqual([
      { method: 'GET', path: '/v1/message-access', body: undefined },
      { method: 'PUT', path: '/v1/message-access', body: { messages_read_only: true } },
      { method: 'GET', path: '/v1/agents/agt_one/message-access', body: undefined },
      { method: 'PUT', path: '/v1/agents/agt_one/message-access', body: { read_teammates: false, messages_read_only: false } },
    ]);
  });

  it('removes only the named values of an agent by sending null', async () => {
    const calls = stubFetch();
    await access().clear('agt_one', ['read_teammates']);
    await access().clear('agt_one', ['read_teammates', 'messages_read_only']);
    expect(calls.map((c) => c.body)).toEqual([{ read_teammates: null }, { read_teammates: null, messages_read_only: null }]);
  });
});
