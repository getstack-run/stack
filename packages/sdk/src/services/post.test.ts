import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { PostRefusedError, PostUnavailableError, PostalAddressNotActiveError } from '../errors.js';

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
      return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const post = () => new Stack({ apiKey: 'sk_live_post_test', baseUrl: 'http://api.fixture' }).post;

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('the customer\'s street address', () => {
  it('reads, starts, connects, refreshes, pauses, resumes and closes it', async () => {
    const calls = stubFetch();
    const p = post();
    await p.getAddress();
    await p.startAddress();
    await p.connectAddress({ api_key: 'sk_agent_key', webhook_secret: 'whsec_x' });
    await p.refreshAddress();
    await p.pauseAddress();
    await p.resumeAddress();
    await p.closeAddress();
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'GET /v1/post/address', 'POST /v1/post/address', 'POST /v1/post/address/connect', 'POST /v1/post/address/refresh',
      'POST /v1/post/address/pause', 'POST /v1/post/address/resume', 'DELETE /v1/post/address',
    ]);
    expect(calls[2]!.body).toEqual({ api_key: 'sk_agent_key', webhook_secret: 'whsec_x' });
  });

  it('lists every item for the owner and gives an unassigned one to an account', async () => {
    const calls = stubFetch();
    await post().listItems({ limit: 5, routing: 'unassigned' });
    await post().assignItem('pit_1', 'acct_1');
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/post/items', search: '?limit=5&routing=unassigned' });
    expect(calls[1]).toMatchObject({ method: 'POST', path: '/v1/post/items/pit_1/assign', body: { account_id: 'acct_1' } });
  });
});

describe('an account\'s post', () => {
  it('reads the agent\'s line, items and letters, sending the Passport when it has one', async () => {
    const calls = stubFetch();
    const p = post();
    await p.accountAddress('acct_1', { passportToken: 'pas.token' });
    await p.listAccountItems('acct_1', { limit: 10, cursor: 'c1' });
    await p.getAccountItem('acct_1', 'pit_1');
    await p.listLetters('acct_1', { limit: 3 });
    await p.getLetter('acct_1', 'plt_1');
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      'GET /v1/accounts/acct_1/post/address', 'GET /v1/accounts/acct_1/post/items?limit=10&cursor=c1', 'GET /v1/accounts/acct_1/post/items/pit_1',
      'GET /v1/accounts/acct_1/post/letters?limit=3', 'GET /v1/accounts/acct_1/post/letters/plt_1',
    ]);
    expect(calls[0]!.headers['X-Passport-Token']).toBe('pas.token');
  });

  it('asks for a scan, a forward and a shred under an idempotency key', async () => {
    const calls = stubFetch();
    const p = post();
    await p.scanItem('acct_1', 'pit_1', { capture: 'both' }, { idempotencyKey: 'scan-key-0001' });
    await p.forwardItem('acct_1', 'pit_1', { destination: { name: 'Pat', line1: '1 Main St', city: 'Reno', state: 'NV', postal_code: '89501' } });
    await p.shredItem('acct_1', 'pit_1');
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/accounts/acct_1/post/items/pit_1/scan', body: { capture: 'both' } });
    expect(calls[0]!.headers['Idempotency-Key']).toBe('scan-key-0001');
    expect(calls[1]).toMatchObject({ path: '/v1/accounts/acct_1/post/items/pit_1/forward' });
    expect(calls[2]).toMatchObject({ path: '/v1/accounts/acct_1/post/items/pit_1/shred', body: { confirm: true } });
  });

  it('sends a letter or a postcard and checks an address', async () => {
    const calls = stubFetch();
    const p = post();
    const to = { name: 'Pat', line1: '1 Main St', city: 'Reno', state: 'NV', postal_code: '89501' };
    await p.send('acct_1', { to, sender_name: 'Acme Dental', content: { text: 'Hello' }, use_type: 'operational' });
    await p.send('acct_1', { kind: 'postcard', to, sender_name: 'Acme Dental', front: { text: 'Hi' }, back: { text: 'There' }, use_type: 'marketing', size: '6x9' });
    await p.checkAddress('acct_1', to);
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /v1/accounts/acct_1/post/letters', 'POST /v1/accounts/acct_1/post/letters', 'POST /v1/accounts/acct_1/post/address-check',
    ]);
    expect(calls[2]!.body).toEqual({ address: to });
  });

  it('sends the optional return address as given', async () => {
    const calls = stubFetch();
    const to = { name: 'Pat', line1: '1 Main St', city: 'Reno', state: 'NV', postal_code: '89501' };
    const return_address = { name: 'Acme Dental', line1: '77 Sender Way', city: 'Carson City', state: 'NV', postal_code: '89701' };
    await post().send('acct_1', { to, sender_name: 'Acme Dental', return_address, content: { text: 'Hello' }, use_type: 'operational' });
    expect(calls[0]!.body).toMatchObject({ return_address });
  });
});

describe('errors', () => {
  it('names a refusal, an outage and an address that is not live', async () => {
    stubFetch({ status: 422, body: { error: { code: 'POST_REFUSED', message: 'no', details: { reason: 'provider_refused' } } } });
    const refused = await post().send('acct_1', { to: { name: 'X', line1: 'a', city: 'b', postal_code: '1' }, sender_name: 'Acme Dental', content: { text: 't' }, use_type: 'operational' }).catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(PostRefusedError);
    expect((refused as PostRefusedError).reason).toBe('provider_refused');
    stubFetch({ status: 503, body: { error: { code: 'POST_UNAVAILABLE', message: 'later', details: { reason: 'letters_not_configured' } } } });
    expect(await post().getLetter('acct_1', 'plt_1').catch((e: unknown) => e)).toBeInstanceOf(PostUnavailableError);
    stubFetch({ status: 409, body: { error: { code: 'POSTAL_ADDRESS_NOT_ACTIVE', message: 'wait', details: { status: 'pending_identity' } } } });
    const notActive = await post().accountAddress('acct_1').catch((e: unknown) => e);
    expect(notActive).toBeInstanceOf(PostalAddressNotActiveError);
    expect((notActive as PostalAddressNotActiveError).addressStatus).toBe('pending_identity');
  });
});
