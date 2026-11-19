import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The BUILT self-managed server (`apps/api/dist/server.js`, the process the engine image runs), booted as a child
 * process with compose-equivalent settings: production mode, a key-encryption key file, a signing key file and an
 * S3-compatible archive in memory, nothing from STACK's cloud. It is what the conformance suites run against.
 *
 * Needs `pnpm --filter @stack/api build`, a dedicated test database (DATABASE_URL, migrated) and Redis (REDIS_URL).
 */

const API_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SERVER = join(API_ROOT, 'dist', 'server.js');
const CLI = join(API_ROOT, 'dist', 'cli', 'stack-engine.js');

/** The slice of S3 the archive store touches, in memory, path-style. */
function fakeS3(): Promise<{ endpoint: string; server: Server }> {
  const objects = new Map<string, Buffer>();
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const [, , ...rest] = url.pathname.split('/');
      const key = rest.join('/');
      if (!key) {
        if (req.method === 'GET' && url.searchParams.get('list-type') === '2') {
          const prefix = url.searchParams.get('prefix') ?? '';
          const keys = [...objects.keys()].filter((k) => k.startsWith(prefix));
          res.setHeader('content-type', 'application/xml');
          res.end(
            `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated>${keys
              .map((k) => `<Contents><Key>${k}</Key></Contents>`)
              .join('')}</ListBucketResult>`,
          );
          return;
        }
        res.statusCode = 200;
        res.end();
        return;
      }
      if (req.method === 'PUT') {
        objects.set(key, Buffer.concat(chunks));
        res.end();
      } else if (req.method === 'GET' || req.method === 'HEAD') {
        const body = objects.get(key);
        if (!body) {
          res.statusCode = 404;
          res.end(req.method === 'GET' ? '<Error><Code>NoSuchKey</Code></Error>' : undefined);
        } else {
          res.setHeader('content-length', String(body.length));
          res.end(req.method === 'GET' ? body : undefined);
        }
      } else if (req.method === 'DELETE') {
        objects.delete(key);
        res.statusCode = 204;
        res.end();
      } else {
        res.statusCode = 405;
        res.end();
      }
    });
  });
  return new Promise((done) => {
    server.listen(0, '127.0.0.1', () => {
      done({ endpoint: `http://127.0.0.1:${(server.address() as { port: number }).port}`, server });
    });
  });
}

function freePort(): Promise<number> {
  return new Promise((done) => {
    const s = createNetServer();
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => done(port));
    });
  });
}

export interface BuiltEngine {
  baseUrl: string;
  /** An operator API key of a freshly created operator. */
  apiKey: string;
  /** What the server wrote to its output so far. */
  log(): string;
  /** The person at the machine approves a governance approval, the way an install without a Console does it. */
  approve(approvalId: string): Promise<void>;
  stop(): Promise<void>;
}

export function builtEngineAvailable(): boolean {
  return existsSync(SERVER) && existsSync(CLI);
}

export async function bootBuiltEngine(databaseUrl: string, redisUrl: string): Promise<BuiltEngine> {
  for (const path of [SERVER, CLI]) {
    if (!existsSync(path)) throw new Error(`${path} is missing: run "pnpm --filter @stack/api build" first`);
  }
  const fake = await fakeS3();
  const secretsDir = mkdtempSync(join(tmpdir(), 'stack-engine-secrets-'));
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const env: NodeJS.ProcessEnv = {
    PATH: process.env['PATH'],
    ...(process.env['SystemRoot'] ? { SystemRoot: process.env['SystemRoot'] } : {}),
    NODE_ENV: 'production',
    STACK_DEPLOYMENT: 'self_managed',
    STACK_API_BASE_URL: baseUrl,
    DASHBOARD_URL: 'https://stack.corp.example',
    API_PORT: String(port),
    DATABASE_URL: databaseUrl,
    REDIS_URL: redisUrl,
    STACK_KEY_FILE: join(secretsDir, 'stack-kek'),
    SESSION_SIGNING_KEY_FILE: join(secretsDir, 'session-signing-key.pem'),
    API_KEY_PEPPER_FILE: join(secretsDir, 'api-key-pepper'),
    AUDIT_ARCHIVE_BUCKET: 'stack-audit',
    AUDIT_ARCHIVE_ENDPOINT: fake.endpoint,
    AUDIT_ARCHIVE_REGION: 'us-east-1',
    AWS_ACCESS_KEY_ID: 'conformance',
    AWS_SECRET_ACCESS_KEY: 'conformance-secret',
    OAUTH_ENABLED: 'true',
    OAUTH_SCOPE_ENFORCEMENT: 'true',
  };
  const keys = spawnSync(process.execPath, [CLI, 'keys', 'generate', '--dir', secretsDir], { env, encoding: 'utf8' });
  if (keys.status !== 0) throw new Error(`keys generate failed: ${keys.stderr}`);

  let log = '';
  const server: ChildProcess = spawn(process.execPath, [SERVER], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout?.on('data', (d: Buffer) => (log += d.toString()));
  server.stderr?.on('data', (d: Buffer) => (log += d.toString()));
  const deadline = Date.now() + 150_000;
  for (;;) {
    if (server.exitCode !== null) throw new Error(`the server exited (${server.exitCode}):\n${log}`);
    const res = await fetch(`${baseUrl}/health`).catch(() => undefined);
    if (res?.ok) break;
    if (Date.now() > deadline) throw new Error(`timed out waiting for /health\n${log}`);
    await new Promise((r) => setTimeout(r, 250));
  }

  const created = spawnSync(process.execPath, [CLI, 'operator', 'create', '--email', `owner-${Date.now()}@corp.example`], { env, encoding: 'utf8' });
  if (created.status !== 0) throw new Error(`operator create failed: ${created.stderr}`);
  const apiKey = /API key:\s+(sk_live_\S+)/.exec(created.stdout)?.[1] ?? '';
  if (!apiKey) throw new Error('operator create printed no API key');

  return {
    baseUrl,
    apiKey,
    log: () => log,
    approve: (approvalId: string) =>
      new Promise<void>((done, fail) => {
        const child = spawn(process.execPath, [CLI, 'approvals', 'approve', approvalId], { env, stdio: ['ignore', 'pipe', 'pipe'] });
        let output = '';
        child.stdout.on('data', (d: Buffer) => (output += d.toString()));
        child.stderr.on('data', (d: Buffer) => (output += d.toString()));
        child.on('exit', (status) => (status === 0 ? done() : fail(new Error(`approvals approve failed: ${output}`))));
      }),
    async stop() {
      if (server.exitCode === null) {
        const exited = new Promise((r) => server.once('exit', r));
        server.kill('SIGTERM');
        await Promise.race([exited, new Promise((r) => setTimeout(r, 5_000))]);
        if (server.exitCode === null) server.kill('SIGKILL');
      }
      await new Promise((r) => fake.server.close(() => r(undefined)));
      rmSync(secretsDir, { recursive: true, force: true });
    },
  };
}
