import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import {
  StackError,
  WebsiteHostnameUnavailableError,
  WebsiteLimitExceededError,
  WebsitePublishRejectedError,
  WebsiteSuspendedError,
  siteFiles,
} from '../index.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }): Sent[] {
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
      if (reply.status === 204) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_website_test', baseUrl: 'http://api.fixture' });
const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const AGENT = { passportToken: 'agent.passport.jwt' };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('website reads', () => {
  it('reads the site, with the Passport only when the agent reads', async () => {
    const calls = stubFetch({ status: 200, body: { id: 'web_1', state: 'live' } });
    const operator = await stack().website.get(ACCOUNT);
    await stack().website.get(ACCOUNT, AGENT);
    expect(operator).toMatchObject({ id: 'web_1', state: 'live' });
    expect(calls[0]).toMatchObject({ method: 'GET', path: `/v1/accounts/${ACCOUNT}/website` });
    expect(calls[0]!.headers['X-Passport-Token']).toBeUndefined();
    expect(calls[0]!.headers['Authorization']).toBe('Bearer sk_live_website_test');
    expect(calls[1]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
  });

  it('escapes the account id in the path', async () => {
    const calls = stubFetch();
    await stack().website.get('acct/../x');
    expect(calls[0]!.path).toBe('/v1/accounts/acct%2F..%2Fx/website');
  });

  it('lists deploys with the limit in the query, and reads one', async () => {
    const calls = stubFetch({ status: 200, body: { deploys: [] } });
    await stack().website.listDeploys(ACCOUNT, { limit: 5 });
    await stack().website.listDeploys(ACCOUNT);
    await stack().website.getDeploy(ACCOUNT, 'wsd_12345678', AGENT);
    expect(calls[0]).toMatchObject({ method: 'GET', path: `/v1/accounts/${ACCOUNT}/website/deploys`, search: '?limit=5' });
    expect(calls[1]).toMatchObject({ path: `/v1/accounts/${ACCOUNT}/website/deploys`, search: '' });
    expect(calls[2]).toMatchObject({ path: `/v1/accounts/${ACCOUNT}/website/deploys/wsd_12345678` });
    expect(calls[2]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
  });

  it('lists hostnames and prices', async () => {
    const calls = stubFetch({ status: 200, body: { hostnames: [], prices: [] } });
    await stack().website.listHostnames(ACCOUNT);
    await stack().website.getPrices(ACCOUNT, AGENT);
    expect(calls[0]).toMatchObject({ method: 'GET', path: `/v1/accounts/${ACCOUNT}/website/hostnames` });
    expect(calls[1]).toMatchObject({ method: 'GET', path: `/v1/accounts/${ACCOUNT}/website/prices` });
    expect(calls[1]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
  });
});

describe('website publish', () => {
  const input = { files: [{ path: '/index.html', content: '<h1>Hi</h1>' }], server: { source: 'export default {}' } };

  it('posts the bundle under the agent Passport', async () => {
    const calls = stubFetch({ status: 201, body: { id: 'wsd_12345678', state: 'live' } });
    const deploy = await stack().website.publish(ACCOUNT, input, AGENT);
    expect(deploy).toMatchObject({ id: 'wsd_12345678', state: 'live' });
    expect(calls[0]).toMatchObject({ method: 'POST', path: `/v1/accounts/${ACCOUNT}/website/deploys`, body: input });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
  });

  it('refuses without a Passport before sending anything', async () => {
    const calls = stubFetch();
    await expect(stack().website.publish(ACCOUNT, input, {})).rejects.toThrow(/passportToken/);
    await expect(stack().website.publish(ACCOUNT, input, undefined as never)).rejects.toThrow(/passportToken/);
    expect(calls).toHaveLength(0);
  });

  it('throws WebsitePublishRejectedError carrying each finding', async () => {
    stubFetch({
      status: 422,
      body: {
        error: {
          code: 'WEBSITE_PUBLISH_REJECTED',
          message: 'The site was not published.',
          details: { findings: [{ code: 'brand_impersonation', path: '/login.html' }, { code: 'scanner_unavailable', path: null }] },
        },
      },
    });
    const error = await stack().website.publish(ACCOUNT, input, AGENT).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(WebsitePublishRejectedError);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({
      status: 422,
      code: 'WEBSITE_PUBLISH_REJECTED',
      findings: [{ code: 'brand_impersonation', path: '/login.html' }, { code: 'scanner_unavailable', path: null }],
    });
  });

  it('throws typed errors for the limit, the suspension and a taken address', async () => {
    stubFetch({
      status: 403,
      body: { error: { code: 'WEBSITE_LIMIT_EXCEEDED', message: 'At the limit.', details: { limit: 'max_total_bytes', max: 52428800 } } },
    });
    const limit = await stack().website.publish(ACCOUNT, input, AGENT).catch((e: unknown) => e);
    expect(limit).toBeInstanceOf(WebsiteLimitExceededError);
    expect(limit).toMatchObject({ limit: 'max_total_bytes', max: 52428800 });

    stubFetch({
      status: 403,
      body: { error: { code: 'WEBSITE_SUSPENDED', message: 'This site is suspended.', details: { state: 'suspended', by: 'owner' } } },
    });
    const suspended = await stack().website.publish(ACCOUNT, input, AGENT).catch((e: unknown) => e);
    expect(suspended).toBeInstanceOf(WebsiteSuspendedError);
    expect(suspended).toMatchObject({ state: 'suspended', by: 'owner' });

    stubFetch({
      status: 409,
      body: { error: { code: 'WEBSITE_HOSTNAME_UNAVAILABLE', message: 'Taken.', details: { reason: 'held_by_another_site' } } },
    });
    const taken = await stack().website.addHostname(ACCOUNT, { hostname: 'www.example.com' }, AGENT).catch((e: unknown) => e);
    expect(taken).toBeInstanceOf(WebsiteHostnameUnavailableError);
    expect(taken).toMatchObject({ reason: 'held_by_another_site', status: 409 });
  });

  it('leaves an unknown code as a plain StackError', async () => {
    stubFetch({ status: 501, body: { error: { code: 'NOT_CONFIGURED', message: 'Agent websites are not configured.' } } });
    const error = await stack().website.get(ACCOUNT).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({ code: 'NOT_CONFIGURED', status: 501 });
  });
});

describe('siteFiles', () => {
  it('sends text as content and bytes that are not text as base64', () => {
    const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff]);
    const html = new TextEncoder().encode('<p>Kaffe och kök</p>');
    expect(
      siteFiles([
        { path: '/a.txt', content: 'plain' },
        { path: '/index.html', content: html },
        { path: '/logo.png', content: png },
      ]),
    ).toEqual([
      { path: '/a.txt', content: 'plain' },
      { path: '/index.html', content: '<p>Kaffe och kök</p>' },
      { path: '/logo.png', content_base64: Buffer.from(png).toString('base64') },
    ]);
  });

  it('keeps a byte order mark, so the file arrives exactly as it was', () => {
    const withBom = new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69]);
    const [file] = siteFiles([{ path: '/bom.txt', content: withBom }]);
    expect(Buffer.from(file!.content!, 'utf8')).toEqual(Buffer.from(withBom));
  });

  it('sends bytes that are not valid UTF-8 as base64', () => {
    const [file] = siteFiles([{ path: '/latin.txt', content: new Uint8Array([0x63, 0x61, 0x66, 0xe9]) }]);
    expect(file).toEqual({ path: '/latin.txt', content_base64: 'Y2Fm6Q==' });
  });

  it('reads a Buffer view that does not start at the beginning of its memory', () => {
    const pool = Buffer.from('xxabcxx');
    const [file] = siteFiles([{ path: '/slice.txt', content: pool.subarray(2, 5) }]);
    expect(file).toEqual({ path: '/slice.txt', content: 'abc' });
  });

  it('refuses an empty bundle and a repeated path, and takes any number of files', () => {
    expect(() => siteFiles([])).toThrow(/at least one file/);
    const many = Array.from({ length: 501 }, (_, i) => ({ path: `/f${i}.txt`, content: 'x' }));
    expect(siteFiles(many)).toHaveLength(501);
    expect(() => siteFiles([{ path: '/a.txt', content: 'a' }, { path: '/a.txt', content: 'b' }])).toThrow(/twice/);
  });
});

describe('website hostnames', () => {
  it('adds a domain under the agent Passport and refuses without one', async () => {
    const calls = stubFetch({ status: 201, body: { id: 'whn_12345678', state: 'pending' } });
    await stack().website.addHostname(ACCOUNT, { hostname: 'www.example.com' }, AGENT);
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: `/v1/accounts/${ACCOUNT}/website/hostnames`,
      body: { hostname: 'www.example.com' },
    });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
    await expect(stack().website.addHostname(ACCOUNT, { hostname: 'a.example.com' }, {})).rejects.toThrow(/passportToken/);
    expect(calls).toHaveLength(1);
  });

  it('checks a domain as the owner or the agent', async () => {
    const calls = stubFetch({ status: 200, body: { state: 'active' } });
    await stack().website.checkHostname(ACCOUNT, 'whn_12345678');
    await stack().website.checkHostname(ACCOUNT, 'whn_12345678', AGENT);
    expect(calls[0]).toMatchObject({ method: 'POST', path: `/v1/accounts/${ACCOUNT}/website/hostnames/whn_12345678/check` });
    expect(calls[0]!.body).toBeUndefined();
    expect(calls[0]!.headers['X-Passport-Token']).toBeUndefined();
    expect(calls[1]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
  });

  it('removes a domain and returns nothing on 204', async () => {
    const calls = stubFetch({ status: 204 });
    await expect(stack().website.removeHostname(ACCOUNT, 'whn_12345678', AGENT)).resolves.toBeUndefined();
    expect(calls[0]).toMatchObject({ method: 'DELETE', path: `/v1/accounts/${ACCOUNT}/website/hostnames/whn_12345678` });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
    await expect(stack().website.removeHostname(ACCOUNT, 'whn_12345678', {})).rejects.toThrow(/passportToken/);
    expect(calls).toHaveLength(1);
  });
});

describe('website prices', () => {
  it('replaces the set with a PUT under the agent Passport', async () => {
    const calls = stubFetch({ status: 200, body: { prices: [] } });
    const input = { prices: [{ path: '/reports/*', price_usdc: '0.25', description: 'Reports' }] };
    await stack().website.setPrices(ACCOUNT, input, AGENT);
    expect(calls[0]).toMatchObject({ method: 'PUT', path: `/v1/accounts/${ACCOUNT}/website/prices`, body: input });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
    await expect(stack().website.setPrices(ACCOUNT, input, {})).rejects.toThrow(/passportToken/);
    expect(calls).toHaveLength(1);
  });
});

describe('suspending a site', () => {
  it('suspends and resumes as the owner, with no Passport', async () => {
    const calls = stubFetch({ status: 200, body: { state: 'suspended' } });
    await stack().website.suspend(ACCOUNT, 'Wrong contact address on the page');
    await stack().website.resume(ACCOUNT);
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: `/v1/accounts/${ACCOUNT}/website/suspension`,
      body: { reason: 'Wrong contact address on the page' },
    });
    expect(calls[1]).toMatchObject({ method: 'DELETE', path: `/v1/accounts/${ACCOUNT}/website/suspension` });
    expect(calls.every((call) => call.headers['X-Passport-Token'] === undefined)).toBe(true);
  });

  it('suspends every site of the account', async () => {
    const calls = stubFetch({ status: 200, body: { suspended: 3 } });
    await expect(stack().website.suspendAll('Pausing everything while we review')).resolves.toEqual({ suspended: 3 });
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/websites/suspend-all', body: { reason: 'Pausing everything while we review' } });
  });
});

describe('reporting a site', () => {
  it('posts the report without any credential', async () => {
    const calls = stubFetch({ status: 202, body: { accepted: true } });
    const reporter = new Stack({ baseUrl: 'http://api.fixture' });
    await expect(reporter.website.report('https://x.agent-sites.example/', 'phishing', 'It asks for a password.')).resolves.toEqual({ accepted: true });
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: '/v1/public/site-reports',
      body: { url: 'https://x.agent-sites.example/', category: 'phishing', description: 'It asks for a password.' },
    });
    expect(calls[0]!.headers['Authorization']).toBeUndefined();
    expect(calls[0]!.body).not.toHaveProperty('reporter_email');
  });

  it('sends the reporter address only when given, and still never an operator key', async () => {
    const calls = stubFetch({ status: 202, body: { accepted: true } });
    await stack().website.report('https://x.agent-sites.example/', 'spam', 'Unsolicited offers on this page.', 'me@example.test');
    expect(calls[0]!.body).toMatchObject({ reporter_email: 'me@example.test' });
    expect(calls[0]!.headers['Authorization']).toBeUndefined();
  });
});
