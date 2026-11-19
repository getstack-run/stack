import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { printJson } from './format.js';
import { readSecretFromStdin } from './secret-input.js';
import { cmdAccounts } from './accounts.js';
import { readBundleDirectory } from './account-site.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'passport-from-stdin') }));

const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const PASSPORT = { headers: { 'X-Passport-Token': 'passport-from-stdin' } };
const SITE = `/v1/accounts/${ACCOUNT}/website`;
const PAY = `/v1/accounts/${ACCOUNT}/payments`;

let directory: string;

beforeEach(() => {
  vi.clearAllMocks();
  directory = mkdtempSync(join(tmpdir(), 'stack-site-'));
});

afterEach(() => rmSync(directory, { recursive: true, force: true }));

describe('account website CLI wire contract', () => {
  it('reads the site as the operator, and as the agent only with --passport-stdin', async () => {
    await cmdAccounts(['website', ACCOUNT]);
    await cmdAccounts(['website', ACCOUNT, 'get', '--passport-stdin']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', SITE, {});
    expect(api).toHaveBeenNthCalledWith(2, 'GET', SITE, PASSPORT);
  });

  it('publishes a folder under the Passport: text as content, other bytes as base64, nested paths rooted', async () => {
    writeFileSync(join(directory, 'index.html'), '<h1>Hi</h1>');
    mkdirSync(join(directory, 'img'));
    writeFileSync(join(directory, 'img', 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
    mkdirSync(join(directory, 'node_modules'));
    writeFileSync(join(directory, 'node_modules', 'skipped.js'), 'never sent');
    writeFileSync(join(directory, 'server.js'), 'export default { fetch: (r, env) => env.ASSETS.fetch(r) };');
    await cmdAccounts(['website', ACCOUNT, 'publish', '--dir', directory, '--server-file', join(directory, 'server.js')]);
    expect(readSecretFromStdin).toHaveBeenCalledTimes(1);
    expect(api).toHaveBeenCalledWith('POST', `${SITE}/deploys`, {
      body: {
        files: [
          { path: '/img/logo.png', content_base64: 'iVBORwAB' },
          { path: '/index.html', content: '<h1>Hi</h1>' },
          { path: '/server.js', content: 'export default { fetch: (r, env) => env.ASSETS.fetch(r) };' },
        ],
        server: { source: 'export default { fetch: (r, env) => env.ASSETS.fetch(r) };' },
      },
      ...PASSPORT,
    });
  });

  it('checks the flags before it asks for the Passport', async () => {
    await expect(cmdAccounts(['website', ACCOUNT, 'publish'])).rejects.toThrow(/--dir is required/);
    await expect(cmdAccounts(['website', ACCOUNT, 'publish', '--dir', join(directory, 'missing')])).rejects.toThrow();
    expect(readSecretFromStdin).not.toHaveBeenCalled();
    expect(api).not.toHaveBeenCalled();
  });

  it('refuses an empty folder, and a Passport placed in argv', async () => {
    expect(() => readBundleDirectory(directory)).toThrow(/has no files/);
    await expect(cmdAccounts(['website', ACCOUNT, 'publish', '--dir', directory, '--passport-token', 'x'])).rejects.toThrow(/must not be placed in argv/);
    expect(api).not.toHaveBeenCalled();
  });

  it('lists and reads deploys', async () => {
    await cmdAccounts(['website', ACCOUNT, 'deploys', '--limit', '5']);
    await cmdAccounts(['website', ACCOUNT, 'deploys', 'dpl_1']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', `${SITE}/deploys`, { query: { limit: 5 } });
    expect(api).toHaveBeenNthCalledWith(2, 'GET', `${SITE}/deploys/dpl_1`, {});
  });

  it('manages the domain: add and remove always under the Passport, check and list only on request', async () => {
    await cmdAccounts(['website', ACCOUNT, 'hostname-add', '--hostname', 'www.example.com']);
    await cmdAccounts(['website', ACCOUNT, 'hostnames']);
    await cmdAccounts(['website', ACCOUNT, 'hostname-check', 'hst_1']);
    await cmdAccounts(['website', ACCOUNT, 'hostname-remove', 'hst_1']);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `${SITE}/hostnames`, { body: { hostname: 'www.example.com' }, ...PASSPORT });
    expect(api).toHaveBeenNthCalledWith(2, 'GET', `${SITE}/hostnames`, {});
    expect(api).toHaveBeenNthCalledWith(3, 'POST', `${SITE}/hostnames/hst_1/check`, {});
    expect(api).toHaveBeenNthCalledWith(4, 'DELETE', `${SITE}/hostnames/hst_1`, { expectEmpty: true, ...PASSPORT });
  });

  it('sets prices from a list or from an object with a prices list', async () => {
    const prices = [{ path: '/reports/*', price_usdc: '0.25' }];
    writeFileSync(join(directory, 'list.json'), JSON.stringify(prices));
    writeFileSync(join(directory, 'object.json'), JSON.stringify({ prices }));
    writeFileSync(join(directory, 'bad.json'), JSON.stringify({ nope: true }));
    await cmdAccounts(['website', ACCOUNT, 'prices-set', '--file', join(directory, 'list.json')]);
    await cmdAccounts(['website', ACCOUNT, 'prices-set', '--file', join(directory, 'object.json')]);
    expect(api).toHaveBeenNthCalledWith(1, 'PUT', `${SITE}/prices`, { body: { prices }, ...PASSPORT });
    expect(api).toHaveBeenNthCalledWith(2, 'PUT', `${SITE}/prices`, { body: { prices }, ...PASSPORT });
    await expect(cmdAccounts(['website', ACCOUNT, 'prices-set', '--file', join(directory, 'bad.json')])).rejects.toThrow(/list of prices/);
    await cmdAccounts(['website', ACCOUNT, 'prices']);
    expect(api).toHaveBeenLastCalledWith('GET', `${SITE}/prices`, {});
  });

  it('suspends and resumes as the owner with no Passport', async () => {
    await cmdAccounts(['website', ACCOUNT, 'suspend', '--reason', 'checking it']);
    await cmdAccounts(['website', ACCOUNT, 'resume']);
    await cmdAccounts(['websites-suspend-all', '--reason', 'checking them all']);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `${SITE}/suspension`, { body: { reason: 'checking it' } });
    expect(api).toHaveBeenNthCalledWith(2, 'DELETE', `${SITE}/suspension`);
    expect(api).toHaveBeenNthCalledWith(3, 'POST', '/v1/websites/suspend-all', { body: { reason: 'checking them all' } });
    expect(readSecretFromStdin).not.toHaveBeenCalled();
  });

  it('refuses an unknown action', async () => {
    await expect(cmdAccounts(['website', ACCOUNT, 'nope'])).rejects.toThrow(/website takes/);
  });
});

describe('the public report', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('posts without any credential and without signing in', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ accepted: true }), { status: 202 }));
    vi.stubGlobal('fetch', fetchMock);
    await cmdAccounts([
      'website-report', '--url', 'https://acme.sites.test/x', '--category', 'phishing',
      '--description', 'Asks visitors for a bank login.', '--email', 'r@example.com',
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/v1\/public\/site-reports$/);
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(JSON.parse(init.body as string)).toEqual({
      url: 'https://acme.sites.test/x', category: 'phishing', description: 'Asks visitors for a bank login.', reporter_email: 'r@example.com',
    });
    expect(api).not.toHaveBeenCalled();
    expect(printJson).toHaveBeenCalledWith({ accepted: true });
  });

  it('says why a report was refused', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"error":{"code":"VALIDATION_ERROR"}}', { status: 400 })));
    await expect(
      cmdAccounts(['website-report', '--url', 'x', '--category', 'spam', '--description', 'too short']),
    ).rejects.toThrow(/refused \(400\)/);
  });
});

describe('account payments CLI wire contract', () => {
  it('starts the Stripe connection as the owner by default, and as the agent on request', async () => {
    await cmdAccounts(['payments', ACCOUNT, 'stripe']);
    await cmdAccounts(['payments', ACCOUNT, 'stripe', '--passport-stdin']);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `${PAY}/stripe`, { body: {} });
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `${PAY}/stripe`, { body: {}, ...PASSPORT });
  });

  it('reads and disconnects the connection', async () => {
    await cmdAccounts(['payments', ACCOUNT, 'stripe-get']);
    await cmdAccounts(['payments', ACCOUNT, 'stripe-disconnect']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', `${PAY}/stripe`, {});
    expect(api).toHaveBeenNthCalledWith(2, 'DELETE', `${PAY}/stripe`, { expectEmpty: true });
    expect(printJson).toHaveBeenLastCalledWith({ disconnected: true });
  });

  it('creates a link and a checkout session under the Passport, with the optional fields only when given', async () => {
    await cmdAccounts(['payments', ACCOUNT, 'link-create', '--name', 'Report', '--amount-minor', '1200']);
    await cmdAccounts([
      'payments', ACCOUNT, 'link-create', '--name', 'Report', '--amount-minor', '1200',
      '--currency', 'eur', '--item', 'r-1', '--after-payment-url', 'https://acme.sites.test/ok',
    ]);
    await cmdAccounts([
      'payments', ACCOUNT, 'checkout-create', '--name', 'Report', '--amount-minor', '1200',
      '--success-url', 'https://acme.sites.test/ok', '--cancel-url', 'https://acme.sites.test/',
    ]);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `${PAY}/links`, { body: { name: 'Report', amount_minor: 1200 }, ...PASSPORT });
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `${PAY}/links`, {
      body: { name: 'Report', amount_minor: 1200, currency: 'eur', item: 'r-1', after_payment_url: 'https://acme.sites.test/ok' },
      ...PASSPORT,
    });
    expect(api).toHaveBeenNthCalledWith(3, 'POST', `${PAY}/checkout-sessions`, {
      body: { name: 'Report', amount_minor: 1200, success_url: 'https://acme.sites.test/ok', cancel_url: 'https://acme.sites.test/' },
      ...PASSPORT,
    });
  });

  it('checks the flags before it asks for the Passport', async () => {
    await expect(cmdAccounts(['payments', ACCOUNT, 'link-create', '--name', 'Report'])).rejects.toThrow(/--amount-minor is required/);
    await expect(cmdAccounts(['payments', ACCOUNT, 'link-create', '--name', 'R', '--amount-minor', '12.5'])).rejects.toThrow(/whole number/);
    await expect(cmdAccounts(['payments', ACCOUNT, 'checkout-create', '--name', 'R', '--amount-minor', '1'])).rejects.toThrow(/--success-url is required/);
    expect(readSecretFromStdin).not.toHaveBeenCalled();
    expect(api).not.toHaveBeenCalled();
  });

  it('lists links, deactivates one under the Passport, and lists and reads payments', async () => {
    await cmdAccounts(['payments', ACCOUNT, 'links', '--limit', '10']);
    await cmdAccounts(['payments', ACCOUNT, 'link-deactivate', 'pl_1']);
    await cmdAccounts(['payments', ACCOUNT]);
    await cmdAccounts(['payments', ACCOUNT, 'list', '--rail', 'x402', '--limit', '5', '--cursor', 'c1']);
    await cmdAccounts(['payments', ACCOUNT, 'get', 'pay_1']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', `${PAY}/links`, { query: { limit: 10 } });
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `${PAY}/links/pl_1/deactivate`, PASSPORT);
    expect(api).toHaveBeenNthCalledWith(3, 'GET', PAY, { query: {} });
    expect(api).toHaveBeenNthCalledWith(4, 'GET', PAY, { query: { rail: 'x402', limit: 5, cursor: 'c1' } });
    expect(api).toHaveBeenNthCalledWith(5, 'GET', `${PAY}/pay_1`, {});
  });

  it('refuses an unknown rail and an unknown action', async () => {
    await expect(cmdAccounts(['payments', ACCOUNT, 'list', '--rail', 'paypal'])).rejects.toThrow(/--rail must be/);
    await expect(cmdAccounts(['payments', ACCOUNT, 'nope'])).rejects.toThrow(/payments takes/);
  });
});
