import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Boots the BUILT self-managed server (`apps/api/dist/server.js`, the process the engine image runs) as a child
 * process with compose-equivalent settings: production mode, key files, an S3-compatible archive, and nothing
 * from STACK's cloud. Tests that need the real HTTP surface of an install use it, and so does the identity
 * conformance run (`apps/api/src/identity-conformance.postgres.test.ts`).
 *
 * Needs `pnpm --filter @stack/api build`, a dedicated test database (`DATABASE_URL`, migrated) and Redis.
 */

const API_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SERVER = join(API_ROOT, 'dist', 'server.js');
const CLI = join(API_ROOT, 'dist', 'cli', 'stack-engine.js');

/** The slice of S3 the archive store touches, in memory, path-style. */
export function fakeS3(): Promise<{ endpoint: string; server: Server }> {
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
        res.statusCode = 200; // HeadBucket
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
  return new Promise((resolveListening) => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      resolveListening({ endpoint: `http://127.0.0.1:${port}`, server });
    });
  });
}

export function freePort(): Promise<number> {
  return new Promise((resolvePort) => {
    const s = createNetServer();
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolvePort(port));
    });
  });
}

export async function waitFor<T>(check: () => Promise<T | undefined>, ms: number, what: string, context = ''): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await check().catch(() => undefined);
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}\n${context}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

export interface EngineHandle {
  baseUrl: string;
  /** The first operator's API key. */
  apiKey: string;
  env: NodeJS.ProcessEnv;
  log(): string;
  /** Run `stack-engine <args>`. */
  cli(args: string[]): Promise<{ status: number | null; output: string }>;
  /** A person at the machine decides an approval, as the engine's CLI does. */
  approve(approvalId: string): Promise<void>;
  /** Create a further operator and return its API key. */
  createOperator(email: string): string;
  stop(): Promise<void>;
}

export async function startEngine(options: { databaseUrl: string; redisUrl: string; extraEnv?: Record<string, string> }): Promise<EngineHandle> {
  for (const path of [SERVER, CLI]) {
    if (!existsSync(path)) throw new Error(`${path} is missing: run "pnpm --filter @stack/api build" first`);
  }
  const s3 = await fakeS3();
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
    DATABASE_URL: options.databaseUrl,
    REDIS_URL: options.redisUrl,
    STACK_KEY_FILE: join(secretsDir, 'stack-kek'),
    SESSION_SIGNING_KEY_FILE: join(secretsDir, 'session-signing-key.pem'),
    API_KEY_PEPPER_FILE: join(secretsDir, 'api-key-pepper'),
    AUDIT_ARCHIVE_BUCKET: 'stack-audit',
    AUDIT_ARCHIVE_ENDPOINT: s3.endpoint,
    AUDIT_ARCHIVE_REGION: 'us-east-1',
    AWS_ACCESS_KEY_ID: 'conformance',
    AWS_SECRET_ACCESS_KEY: 'conformance-secret',
    OAUTH_ENABLED: 'true',
    OAUTH_SCOPE_ENFORCEMENT: 'true',
    ...options.extraEnv,
  };
  const keys = spawnSync(process.execPath, [CLI, 'keys', 'generate', '--dir', secretsDir], { env, encoding: 'utf8' });
  if (keys.status !== 0) throw new Error(`key generation failed: ${keys.stderr}`);

  let serverLog = '';
  const server: ChildProcess = spawn(process.execPath, [SERVER], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout?.on('data', (d: Buffer) => (serverLog += d.toString()));
  server.stderr?.on('data', (d: Buffer) => (serverLog += d.toString()));
  const stop = async () => {
    if (server.exitCode === null) {
      const exited = new Promise((r) => server.once('exit', r));
      server.kill('SIGTERM');
      await Promise.race([exited, new Promise((r) => setTimeout(r, 5_000))]);
      if (server.exitCode === null) server.kill('SIGKILL');
    }
    await new Promise((r) => s3.server.close(() => r(undefined)));
    rmSync(secretsDir, { recursive: true, force: true });
  };
  try {
    await waitFor(
      async () => {
        if (server.exitCode !== null) throw new Error(`the server exited (${server.exitCode}):\n${serverLog}`);
        const res = await fetch(`${baseUrl}/health`).catch(() => undefined);
        return res?.ok ? true : undefined;
      },
      150_000,
      'the server to answer /health',
      serverLog,
    );
  } catch (error) {
    await stop();
    throw error;
  }

  const createOperator = (email: string): string => {
    const created = spawnSync(process.execPath, [CLI, 'operator', 'create', '--email', email], { env, encoding: 'utf8' });
    if (created.status !== 0) throw new Error(`operator create failed: ${created.stderr}`);
    const key = /API key:\s+(sk_live_\S+)/.exec(created.stdout)?.[1];
    if (!key) throw new Error('operator create printed no API key');
    return key;
  };
  const cli = (args: string[]) =>
    new Promise<{ status: number | null; output: string }>((done) => {
      const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '';
      child.stdout.on('data', (d: Buffer) => (output += d.toString()));
      child.stderr.on('data', (d: Buffer) => (output += d.toString()));
      child.on('exit', (status) => done({ status, output }));
    });

  return {
    baseUrl,
    apiKey: createOperator(`owner-${Date.now()}@corp.example`),
    env,
    log: () => serverLog,
    cli,
    approve: async (approvalId) => {
      const decided = await cli(['approvals', 'approve', approvalId]);
      if (decided.status !== 0) throw new Error(`approving ${approvalId} failed: ${decided.output}`);
    },
    createOperator,
    stop,
  };
}
