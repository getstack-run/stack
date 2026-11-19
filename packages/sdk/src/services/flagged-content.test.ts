import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

const SETTINGS = { warning: 'deliver', critical: 'withhold', controls: true };

function stubFetch(): Array<{ method: string; path: string; body: unknown }> {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string }) => {
      calls.push({ method: init.method ?? 'GET', path: new URL(url).pathname, body: init.body ? JSON.parse(init.body) : undefined });
      return new Response(JSON.stringify(SETTINGS), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const flagged = () => new Stack({ apiKey: 'sk_live_flagged_test', baseUrl: 'http://api.fixture' }).flaggedContent;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('FlaggedContentService', () => {
  it('reads and changes the setting per severity', async () => {
    const calls = stubFetch();
    await expect(flagged().get()).resolves.toEqual(SETTINGS);
    await expect(flagged().set({ warning: 'deliver' })).resolves.toEqual(SETTINGS);
    expect(calls).toEqual([
      { method: 'GET', path: '/v1/flagged-content/settings', body: undefined },
      { method: 'PUT', path: '/v1/flagged-content/settings', body: { warning: 'deliver' } },
    ]);
  });

  it('refuses a change that names no severity before any request', async () => {
    const calls = stubFetch();
    await expect(flagged().set({})).rejects.toThrow(/warning, critical or both/);
    expect(calls).toHaveLength(0);
  });
});
