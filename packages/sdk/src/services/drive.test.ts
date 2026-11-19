import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { StackError } from '../errors.js';

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

const stack = () => new Stack({ apiKey: 'sk_live_drive_test', baseUrl: 'http://api.fixture' });
const FILE = 'drv_0123456789abcdef';
const LINK = 'dsl_0123456789abcdef';
const TOKEN = 'jwt.passport.token';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('DriveService', () => {
  it('uploads text and base64 bodies as given', async () => {
    const calls = stubFetch({ status: 201, body: { id: FILE } });
    await stack().drive.upload({ name: 'a.txt', content_type: 'text/plain', content_text: 'hi', visibility: 'account', expires_in_seconds: 600 });
    await stack().drive.upload({ name: 'a.png', content_type: 'image/png', content_base64: 'iVBORw0K' });
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: '/v1/drive/files',
      body: { name: 'a.txt', content_type: 'text/plain', content_text: 'hi', visibility: 'account', expires_in_seconds: 600 },
    });
    expect(calls[1]!.body).toEqual({ name: 'a.png', content_type: 'image/png', content_base64: 'iVBORw0K' });
    expect(calls[0]!.headers['X-Passport-Token']).toBeUndefined();
  });

  it('sends the Passport as X-Passport-Token on every agent-side call', async () => {
    const calls = stubFetch({ status: 200, body: {} });
    const options = { passportToken: TOKEN };
    const drive = stack().drive;
    await drive.upload({ name: 'a.txt', content_type: 'text/plain', content_text: 'x' }, options);
    await drive.list({}, options);
    await drive.get(FILE, options);
    await drive.read(FILE, options);
    await drive.update(FILE, { visibility: 'account' }, options);
    await drive.delete(FILE, options);
    await drive.share(FILE, {}, options);
    await drive.links(FILE, options);
    await drive.revokeLink(FILE, LINK, options);
    await drive.copy(FILE, {}, options);
    expect(calls).toHaveLength(10);
    for (const call of calls) expect(call.headers['X-Passport-Token']).toBe(TOKEN);
  });

  it('lists with a limit and cursor as query parameters', async () => {
    const calls = stubFetch({ status: 200, body: { files: [], next_cursor: null, usage: {} } });
    await stack().drive.list({ limit: 25, cursor: 'c1' });
    await stack().drive.list();
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/drive/files' });
    expect(new URLSearchParams(calls[0]!.search).get('limit')).toBe('25');
    expect(new URLSearchParams(calls[0]!.search).get('cursor')).toBe('c1');
    expect(calls[1]!.search).toBe('');
  });

  it('gets one file and reads its content', async () => {
    const calls = stubFetch({ status: 200, body: { file: { id: FILE }, encoding: 'utf8', content: 'hi', withheld: false, flag: null } });
    const read = await stack().drive.read(FILE);
    await stack().drive.get(FILE);
    expect(read.content).toBe('hi');
    expect(calls[0]).toMatchObject({ method: 'GET', path: `/v1/drive/files/${FILE}/content` });
    expect(calls[1]).toMatchObject({ method: 'GET', path: `/v1/drive/files/${FILE}` });
  });

  it('updates visibility and removes an expiry with null', async () => {
    const calls = stubFetch({ status: 200, body: { id: FILE } });
    await stack().drive.update(FILE, { visibility: 'account', expires_in_seconds: null });
    expect(calls[0]).toMatchObject({
      method: 'PATCH',
      path: `/v1/drive/files/${FILE}`,
      body: { visibility: 'account', expires_in_seconds: null },
    });
  });

  it('deletes a file and revokes a link on 204', async () => {
    const calls = stubFetch({ status: 204 });
    await expect(stack().drive.delete(FILE)).resolves.toBeUndefined();
    await expect(stack().drive.revokeLink(FILE, LINK)).resolves.toBeUndefined();
    expect(calls[0]).toMatchObject({ method: 'DELETE', path: `/v1/drive/files/${FILE}` });
    expect(calls[1]).toMatchObject({ method: 'DELETE', path: `/v1/drive/files/${FILE}/links/${LINK}` });
  });

  it('makes a link and returns its URL', async () => {
    const calls = stubFetch({
      status: 201,
      body: { id: LINK, file_id: FILE, url: 'https://api.fixture/v1/drive/links/a.b.c', expires_at: '2030-01-01T00:00:00.000Z', max_downloads: 2 },
    });
    const share = await stack().drive.share(FILE, { ttl_seconds: 600, max_downloads: 2 });
    expect(share.url).toContain('/v1/drive/links/');
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: `/v1/drive/files/${FILE}/links`,
      body: { ttl_seconds: 600, max_downloads: 2 },
    });
  });

  it('copies a file into one of the caller\'s own, with the options as given', async () => {
    const calls = stubFetch({ status: 201, body: { id: FILE } });
    await stack().drive.copy(FILE, { name: 'kept.pdf', visibility: 'account', expires_in_seconds: 86_400 });
    await stack().drive.copy(FILE);
    expect(calls[0]).toMatchObject({ method: 'POST', path: `/v1/drive/files/${FILE}/copy`, body: { name: 'kept.pdf', visibility: 'account', expires_in_seconds: 86_400 } });
    expect(calls[1]!.body).toEqual({});
  });

  it('shares with an empty body when no options are given', async () => {
    const calls = stubFetch({ status: 201, body: {} });
    await stack().drive.share(FILE);
    expect(calls[0]!.body).toEqual({});
  });

  it("lists a file's links", async () => {
    const calls = stubFetch({ status: 200, body: { links: [] } });
    await stack().drive.links(FILE);
    expect(calls[0]).toMatchObject({ method: 'GET', path: `/v1/drive/files/${FILE}/links` });
  });

  it('encodes ids placed in a path', async () => {
    const calls = stubFetch({ status: 200, body: {} });
    await stack().drive.get('a b');
    expect(calls[0]!.path).toBe('/v1/drive/files/a%20b');
  });

  it('throws a StackError carrying the drive code', async () => {
    stubFetch({
      status: 413,
      body: { error: { code: 'DRIVE_INLINE_READ_TOO_LARGE', message: 'This file is larger than 262144 bytes, so it cannot be read inline. Share it with a link instead.' } },
    });
    const error = await stack().drive.read(FILE).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StackError);
    expect((error as StackError).code).toBe('DRIVE_INLINE_READ_TOO_LARGE');
    expect((error as StackError).status).toBe(413);
  });
});
