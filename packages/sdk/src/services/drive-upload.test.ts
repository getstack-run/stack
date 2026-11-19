import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Stack } from '../index.js';
import { StackError } from '../errors.js';
import type { DriveUploadProgress } from './drive.js';

// Uploads are one request carrying the whole file. These tests run the SDK's real fetch against a real local HTTP server, so what
// they check is what goes over the wire: the method, the query, the headers and every byte of the body.

const FILE = 'drv_0123456789abcdef';
const TOKEN = 'jwt.passport.token';

interface Seen {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

interface Reply {
  status: number;
  body?: unknown;
}

let server: Server;
let base = '';
let seen: Seen[] = [];
let reply: (request: Seen) => Reply = () => ({ status: 201, body: { id: FILE, trust: 'untrusted' } });

beforeEach(async () => {
  seen = [];
  reply = () => ({ status: 201, body: { id: FILE, trust: 'untrusted' } });
  server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const url = new URL(request.url ?? '/', 'http://local.fixture');
      const entry: Seen = {
        method: request.method ?? 'GET',
        path: url.pathname,
        query: url.searchParams,
        headers: request.headers,
        body: Buffer.concat(chunks),
      };
      seen.push(entry);
      const answer = reply(entry);
      response.writeHead(answer.status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(answer.body ?? {}));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
});

const stack = () => new Stack({ apiKey: 'sk_live_drive_test', baseUrl: base });
const hex = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const meta = { name: 'big file.zip', content_type: 'application/zip' as const };

function stream(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  let next = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const chunk = chunks[next];
      next += 1;
      if (chunk) controller.enqueue(chunk);
      else controller.close();
    },
  });
}

describe('DriveService upload: one request with the whole file', () => {
  it('PUTs bytes as the body with the facts in the query and the credential, and no hash or size', async () => {
    const content = randomBytes(300_000);
    const file = await stack().drive.upload({ ...meta, content, visibility: 'account', expires_in_seconds: 3600 });
    expect(file.id).toBe(FILE);
    expect(seen).toHaveLength(1);
    const request = seen[0]!;
    expect(request.method).toBe('PUT');
    expect(request.path).toBe('/v1/drive/files');
    expect(Object.fromEntries(request.query)).toEqual({
      name: 'big file.zip',
      content_type: 'application/zip',
      visibility: 'account',
      expires_in_seconds: '3600',
    });
    expect(request.headers['authorization']).toBe('Bearer sk_live_drive_test');
    expect(request.headers['content-type']).toBe('application/octet-stream');
    expect(request.headers['content-length']).toBe(String(content.byteLength));
    expect(request.headers['x-passport-token']).toBeUndefined();
    expect(hex(request.body)).toBe(hex(content));
  });

  it('sends only the name and type when nothing else is asked for', async () => {
    await stack().drive.upload({ ...meta, content: new Uint8Array([1, 2, 3]) });
    expect([...seen[0]!.query.keys()]).toEqual(['name', 'content_type']);
  });

  it('sends a Blob as it is, with its size as the length', async () => {
    const content = randomBytes(70_000);
    await stack().drive.upload({ ...meta, content: new Blob([content]) });
    expect(seen[0]!.headers['content-length']).toBe('70000');
    expect(hex(seen[0]!.body)).toBe(hex(content));
  });

  it('reads a stream as it goes: chunked without a size, with a Content-Length when the size is given', async () => {
    const parts = [randomBytes(40_000), randomBytes(25_000), randomBytes(1)];
    const whole = Buffer.concat(parts);
    await stack().drive.upload({ ...meta, content: stream(parts) });
    expect(seen[0]!.headers['transfer-encoding']).toBe('chunked');
    expect(seen[0]!.headers['content-length']).toBeUndefined();
    expect(hex(seen[0]!.body)).toBe(hex(whole));

    await stack().drive.upload({ ...meta, content: stream(parts), size_bytes: whole.byteLength });
    expect(seen[1]!.headers['content-length']).toBe(String(whole.byteLength));
    expect(hex(seen[1]!.body)).toBe(hex(whole));
  });

  it('streams a file from disk by its path, with its size as the length', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'drive-upload-'));
    try {
      const path = join(dir, 'video.mp4');
      const content = randomBytes(3 * 1024 * 1024 + 17);
      await writeFile(path, content);
      const file = await stack().drive.upload({ name: 'video.mp4', content_type: 'video/mp4', path }, { passportToken: TOKEN });
      expect(file.id).toBe(FILE);
      expect(seen[0]!.method).toBe('PUT');
      expect(seen[0]!.query.get('name')).toBe('video.mp4');
      expect(seen[0]!.headers['content-length']).toBe(String(content.byteLength));
      expect(seen[0]!.headers['x-passport-token']).toBe(TOKEN);
      expect(hex(seen[0]!.body)).toBe(hex(content));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('refuses a path that is not a file before it sends anything', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'drive-upload-'));
    try {
      const error = await stack().drive.upload({ ...meta, path: dir }).catch((e: unknown) => e);
      expect((error as StackError).code).toBe('DRIVE_UPLOAD_SOURCE_INVALID');
      expect(seen).toHaveLength(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reports progress as the bytes are sent, ending at the total', async () => {
    const content = randomBytes(2_500_000);
    const reports: DriveUploadProgress[] = [];
    await stack().drive.upload({ ...meta, content }, { onProgress: (progress) => reports.push(progress) });
    expect(reports[0]).toEqual({ uploaded_bytes: 0, total_bytes: 2_500_000 });
    expect(reports.at(-1)).toEqual({ uploaded_bytes: 2_500_000, total_bytes: 2_500_000 });
    expect(hex(seen[0]!.body)).toBe(hex(content));
  });

  it('sends a text or base64 body as JSON through POST /v1/drive/files', async () => {
    await stack().drive.upload({ name: 'a.txt', content_type: 'text/plain', content_text: 'hi' });
    expect(seen[0]!.method).toBe('POST');
    expect(seen[0]!.path).toBe('/v1/drive/files');
    expect(JSON.parse(seen[0]!.body.toString('utf8'))).toEqual({ name: 'a.txt', content_type: 'text/plain', content_text: 'hi' });
  });

  it('throws the API error with its code and never retries', async () => {
    const cases: Array<[number, string]> = [
      [429, 'DRIVE_TOO_MANY_UPLOADS'],
      [409, 'DRIVE_READ_ONLY'],
      [413, 'DRIVE_FILE_TOO_LARGE'],
      [400, 'DRIVE_FILE_EMPTY'],
      [402, 'INSUFFICIENT_BALANCE'],
    ];
    for (const [status, code] of cases) {
      seen = [];
      reply = () => ({ status, body: { error: { code, message: 'refused', details: { since: '2030-01-01T00:00:00.000Z' } } } });
      const error = await stack().drive.upload({ ...meta, content: new Uint8Array([1]) }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(StackError);
      expect((error as StackError).code).toBe(code);
      expect((error as StackError).status).toBe(status);
      expect(seen).toHaveLength(1);
    }
  });

  it('stops when the caller aborts', async () => {
    const controller = new AbortController();
    controller.abort();
    const error = await stack().drive.upload({ ...meta, content: new Uint8Array([1]) }, { signal: controller.signal }).catch((e: unknown) => e);
    expect((error as Error).name).toBe('AbortError');
    expect(seen).toHaveLength(0);
  });
});

describe('DriveService upload links', () => {
  const link = (url: string) => ({
    id: 'dul_0123456789abcdef',
    url,
    method: 'PUT' as const,
    name: 'big.zip',
    content_type: 'application/zip',
    max_bytes: 1_073_741_824,
    expires_at: '2030-01-01T00:00:00.000Z',
  });

  it('asks for a link with the facts it binds, as the action', async () => {
    reply = () => ({ status: 201, body: link('https://api.fixture/v1/drive/uploads/token') });
    const made = await stack().drive.createUploadLink({ ...meta, size_bytes: 5_000_000, visibility: 'agent', expires_in_seconds: 600 }, { passportToken: TOKEN });
    expect(made.method).toBe('PUT');
    expect(seen[0]!.method).toBe('POST');
    expect(seen[0]!.path).toBe('/v1/drive/uploads');
    expect(JSON.parse(seen[0]!.body.toString('utf8'))).toEqual({ ...meta, size_bytes: 5_000_000, visibility: 'agent', expires_in_seconds: 600 });
    expect(seen[0]!.headers['x-passport-token']).toBe(TOKEN);
    expect(seen[0]!.headers['authorization']).toBe('Bearer sk_live_drive_test');
  });

  it('PUTs to the link URL with no credential at all, and answers the file', async () => {
    const content = randomBytes(10_000);
    const url = `${base}/v1/drive/uploads/one-time-token`;
    const file = await stack().drive.uploadToLink(link(url), { content });
    expect(file.id).toBe(FILE);
    const request = seen[0]!;
    expect(request.method).toBe('PUT');
    expect(request.path).toBe('/v1/drive/uploads/one-time-token');
    expect(request.headers['authorization']).toBeUndefined();
    expect(request.headers['x-passport-token']).toBeUndefined();
    expect(request.headers['content-length']).toBe('10000');
    expect(hex(request.body)).toBe(hex(content));
  });

  it('takes the bare URL and a file path, and streams the file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'drive-upload-'));
    try {
      const path = join(dir, 'a.zip');
      const content = randomBytes(1_200_000);
      await writeFile(path, content);
      await stack().drive.uploadToLink(`${base}/v1/drive/uploads/tok`, { path });
      expect(seen[0]!.headers['authorization']).toBeUndefined();
      expect(hex(seen[0]!.body)).toBe(hex(content));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('answers a used, expired or foreign URL by its code, without the URL in the error', async () => {
    reply = () => ({ status: 404, body: { error: { code: 'DRIVE_UPLOAD_LINK_INVALID', message: 'This upload link is not valid. Ask for a new one.' } } });
    const url = `${base}/v1/drive/uploads/secret-token-value`;
    const error = (await stack().drive.uploadToLink(url, { content: new Uint8Array([1]) }).catch((e: unknown) => e)) as StackError;
    expect(error.code).toBe('DRIVE_UPLOAD_LINK_INVALID');
    expect(error.status).toBe(404);
    expect(JSON.stringify([error.message, error.details])).not.toContain('secret-token-value');
  });

  it('does not put the URL in the error when the connection fails', async () => {
    const url = 'http://127.0.0.1:1/v1/drive/uploads/secret-token-value';
    const error = (await stack().drive.uploadToLink(url, { content: new Uint8Array([1]) }).catch((e: unknown) => e)) as StackError;
    expect(error).toBeInstanceOf(StackError);
    expect(error.code).toBe('DRIVE_UPLOAD_FAILED');
    expect(`${error.message} ${JSON.stringify(error.details)} ${String((error as { cause?: unknown }).cause)}`).not.toContain('secret-token-value');
  });
});
