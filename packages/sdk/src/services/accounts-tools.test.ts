import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as sdk from '../index.js';
import { Stack } from '../index.js';
import type { AccountToolRun, ToolRunFile } from '../index.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(status: number, body: unknown): Sent[] {
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
      return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_accounts_test', baseUrl: 'http://api.fixture' });
const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const options = { passportToken: 'pas.jwt.token' };

const FILE: ToolRunFile = {
  name: 'image.png',
  content_type: 'image/png',
  size_bytes: 1024,
  drive_file_id: 'dfl_1',
  source_url: null,
  data_base64: null,
};

const RUN_VIEW = {
  id: 'atr_12345678',
  account_id: ACCOUNT,
  provider: 'acme',
  endpoint: '/acme/web-search',
  state: 'settled',
  price_type: 'PER_RESULT',
  max_results: 5,
  reserved_cents: 10,
  charged_cents: 4,
  status: 'COMPLETED',
  provider_http_status: 200,
  result: { output: [{ title: 'Espresso' }] },
  withheld: null,
  flag: null,
  created_at: '2026-10-22T08:00:00.000Z',
  settled_at: '2026-10-22T08:00:05.000Z',
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('paid tool runs', () => {
  const runInput = { provider: 'acme', endpoint: '/acme/web-search', input: { queries: 'espresso' }, max_results: 5, max_cost_cents: 20 };

  it('carries untrusted and files on a run and on a run read again', async () => {
    const withFiles = { ...RUN_VIEW, untrusted: true, files: [FILE] };
    const calls = stubFetch(200, withFiles);
    const { tools } = stack().accounts;
    const run: AccountToolRun = await tools.run(ACCOUNT, runInput, options);
    const again: AccountToolRun = await tools.getRun(ACCOUNT, 'atr_12345678', options);
    expect(run.untrusted).toBe(true);
    expect(run.files).toEqual([FILE]);
    expect(again.untrusted).toBe(true);
    expect(again.files[0]!.content_type).toBe('image/png');
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['POST', `/v1/accounts/${ACCOUNT}/tools/run`, runInput],
      ['GET', `/v1/accounts/${ACCOUNT}/tools/runs/atr_12345678`, undefined],
    ]);
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual(['pas.jwt.token', 'pas.jwt.token']);
  });

  it('surfaces a run STACK cannot bound as TOOL_PRICE_REFUSED naming the endpoint and the reason', async () => {
    stubFetch(422, {
      error: {
        code: 'TOOL_PRICE_REFUSED',
        message: 'acme/acme/other cannot be run: it is priced per result and its input has no result limit.',
        details: { reason: 'result_bound_unavailable', provider: 'acme', endpoint: '/acme/other' },
      },
    });
    const error = await stack().accounts.tools.run(ACCOUNT, { provider: 'acme', endpoint: '/acme/other' }, options).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(sdk.ToolPriceRefusedError);
    expect(error).toMatchObject({ code: 'TOOL_PRICE_REFUSED', status: 422 });
    expect((error as sdk.StackError).details).toMatchObject({ error: { details: { reason: 'result_bound_unavailable', provider: 'acme', endpoint: '/acme/other' } } });
  });
});

describe('ready tools are gone', () => {
  it('has no ready-tool service on the tools service and no ready-tool path in the SDK', () => {
    const { tools } = stack().accounts;
    expect('ready' in tools).toBe(false);
    // The property is gone from the type too: this line fails to compile if it comes back.
    // @ts-expect-error `ready` is not a member of AccountToolsService
    expect(tools.ready).toBeUndefined();
    expect(Object.keys(sdk).filter((name) => /ready.?tool/i.test(name))).toEqual([]);
    const source = readFileSync(fileURLToPath(new URL('./accounts.ts', import.meta.url)), 'utf8');
    expect(source).not.toMatch(/ReadyTool|tools\/ready/);
  });
});
