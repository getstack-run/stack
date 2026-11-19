import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { progressWriter } from './drive-upload.js';

// Each test loads the CLI's whole module graph afresh, which takes longer than the default five seconds on a loaded machine.
vi.setConfig({ testTimeout: 30_000 });

// `drive upload` against a real local server: the CLI's own sign-in, the SDK's real request, the file streamed from disk.

interface Seen {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

let dir: string;
let server: Server;
let seen: Seen[] = [];
let status = 201;
const saved = { url: process.env['STACK_API_URL'], key: process.env['STACK_API_KEY'] };

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'stack-drive-upload-'));
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

beforeEach(async () => {
  seen = [];
  status = 201;
  server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      seen.push({ method: request.method ?? '', url: request.url ?? '', headers: request.headers, body: Buffer.concat(chunks) });
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(status === 201 ? { id: 'drv_0123456789abcdef' } : { error: { code: 'DRIVE_READ_ONLY', message: 'This drive is read-only.' } }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  process.env['STACK_API_URL'] = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  process.env['STACK_API_KEY'] = 'sk_live_cli_test';
  vi.resetModules();
});

afterEach(async () => {
  for (const [name, value] of [['STACK_API_URL', saved.url], ['STACK_API_KEY', saved.key]] as const) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  await new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
  vi.restoreAllMocks();
});

describe('stack drive upload over the wire', () => {
  it('sends the file as the body of one PUT, with its name, type, size and the sign-in', async () => {
    const path = join(dir, 'archive.zip');
    const content = randomBytes(2 * 1024 * 1024 + 5);
    writeFileSync(path, content);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const printed: unknown[] = [];
    vi.doMock('./format.js', async (importOriginal) => ({ ...(await importOriginal<object>()), printJson: (value: unknown) => printed.push(value) }));
    const { cmdDrive } = await import('./drive.js');
    await cmdDrive(['upload', path, '--account', '--expires', '600']);
    expect(seen).toHaveLength(1);
    const request = seen[0]!;
    expect(request.method).toBe('PUT');
    const url = new URL(request.url, 'http://local.fixture');
    expect(url.pathname).toBe('/v1/drive/files');
    expect(Object.fromEntries(url.searchParams)).toEqual({ name: 'archive.zip', content_type: 'application/zip', visibility: 'account', expires_in_seconds: '600' });
    expect(request.headers['authorization']).toBe('Bearer sk_live_cli_test');
    expect(request.headers['content-length']).toBe(String(content.byteLength));
    expect(createHash('sha256').update(request.body).digest('hex')).toBe(createHash('sha256').update(content).digest('hex'));
    expect(printed).toEqual([{ id: 'drv_0123456789abcdef' }]);
  });

  it("fails with the API's message and code, and sends no second request", async () => {
    status = 409;
    const path = join(dir, 'notes.md');
    writeFileSync(path, '# notes');
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const { cmdDrive } = await import('./drive.js');
    await expect(cmdDrive(['upload', path])).rejects.toThrow(/read-only.*\(DRIVE_READ_ONLY\)/);
    expect(seen).toHaveLength(1);
  });
});

describe('the progress line', () => {
  it('writes a line per tenth when stderr is not a terminal, and nothing when the length is not known', () => {
    const lines: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => (lines.push(String(chunk)), true));
    const MIB = 1024 * 1024;
    const progress = progressWriter();
    progress({ uploaded_bytes: 0, total_bytes: 100 * MIB });
    progress({ uploaded_bytes: 3 * MIB, total_bytes: 100 * MIB });
    progress({ uploaded_bytes: 4 * MIB, total_bytes: 100 * MIB });
    progress({ uploaded_bytes: 100 * MIB, total_bytes: 100 * MIB });
    progress({ uploaded_bytes: 5, total_bytes: null });
    expect(lines).toEqual(['uploaded 0 of 100 MiB (0%)\n', 'uploaded 100 of 100 MiB (100%)\n']);
  });
});
