import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from './index.js';
import { CONTROL_ACTION_TYPES } from './services/control-socket.js';

interface Sent {
  method: string;
  path: string;
  headers: Record<string, string>;
}

function stubFetch(): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; headers?: Record<string, string> }) => {
      calls.push({ method: init.method ?? 'GET', path: new URL(url).pathname, headers: init.headers ?? {} });
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const header = (call: Sent | undefined, name: string): string | undefined =>
  Object.entries(call?.headers ?? {}).find(([key]) => key.toLowerCase() === name)?.[1];

describe('retrying an action the owner approved', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('sends X-Control-Ref through stack.withControlRef(ref) and none otherwise', async () => {
    const calls = stubFetch();
    const stack = new Stack({ apiKey: 'sk_live_test', baseUrl: 'http://api.test' });

    await stack.accounts.sendEmail('acct_1', { to: 'ada@example.com', subject: 'Hi', body: 'Hello' }, { passportToken: 'ppt' });
    expect(header(calls[0], 'x-control-ref')).toBeUndefined();

    await stack.withControlRef('cref_approved').accounts.sendEmail('acct_1', { to: 'ada@example.com', subject: 'Hi', body: 'Hello' }, { passportToken: 'ppt' });
    expect(calls[1]?.path).toBe('/v1/accounts/acct_1/email/send');
    expect(header(calls[1], 'x-control-ref')).toBe('cref_approved');
    // The credential and the Passport go as before.
    expect(header(calls[1], 'authorization')).toBe('Bearer sk_live_test');
    expect(header(calls[1], 'x-passport-token')).toBe('ppt');

    // The original SDK is unchanged: the ref belongs to the scoped one only.
    await stack.accounts.sendEmail('acct_1', { to: 'ada@example.com', subject: 'Hi', body: 'Hello' }, { passportToken: 'ppt' });
    expect(header(calls[2], 'x-control-ref')).toBeUndefined();
  });

  it('refuses an empty ref', () => {
    const stack = new Stack({ apiKey: 'sk_live_test', baseUrl: 'http://api.test' });
    expect(() => stack.withControlRef('  ')).toThrow(TypeError);
  });
});

describe('the action kinds', () => {
  it('are the ones the API checks: the SDK list equals the shared list, in the same order', () => {
    // The SDK is published and cannot import the private shared package, so its list is a copy. This reads the source of
    // the original, so a kind added there and not here fails here.
    const source = readFileSync(fileURLToPath(new URL('../../shared/src/constants/control-socket.ts', import.meta.url)), 'utf8');
    const block = /export const CONTROL_ACTION_TYPES = \[([\s\S]*?)\] as const;/.exec(source)?.[1];
    expect(block, 'CONTROL_ACTION_TYPES in packages/shared/src/constants/control-socket.ts').toBeDefined();
    const shared = [...block!.matchAll(/'([a-z0-9_.]+)'/g)].map((match) => match[1]);
    expect(shared.length).toBeGreaterThan(30);
    expect([...CONTROL_ACTION_TYPES]).toEqual(shared);
  });
});
