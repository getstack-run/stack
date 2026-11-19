import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LICENCE_FEATURES } from '@stack/shared';
import { isDedicatedStackTestDatabase } from './test/dedicated-test-database.js';
import { createOwnDatabase, type OwnDatabase } from './test/own-database.js';

/**
 * Boots the BUILT self-managed server (`apps/api/dist/server.js`, the process
 * the engine image runs) as a child process with compose-equivalent settings:
 * production mode, a key-encryption key file, a signing key file, an
 * S3-compatible archive and nothing from STACK's cloud (no platform token, no AWS
 * KMS, no Resend). Then it drives the real HTTP surface: issue a passport,
 * read the record back and verify its chain, and check what the install does
 * and does not serve.
 *
 * The proxy half of the smoke test is in `self-managed.proxy.postgres.test.ts`:
 * a production process refuses to forward to a private address, so it needs a
 * transport the test controls.
 *
 * Needs `pnpm --filter @stack/api build`, a dedicated test database
 * (DATABASE_URL, migrated) and Redis (REDIS_URL). The install it boots runs on a
 * database of its own, created and dropped by this file: an install moves every
 * operator of its database to the contract plan and sweeps whatever expired
 * missions it finds, neither of which may reach rows other files own.
 */

const databaseUrl = process.env['DATABASE_URL'];
const redisUrl = process.env['REDIS_URL'] ?? process.env['STACK_TEST_REDIS_URL'];
const enabled = isDedicatedStackTestDatabase(databaseUrl) && Boolean(redisUrl);
const API_ROOT = resolve(__dirname, '..');
const SERVER = join(API_ROOT, 'dist', 'server.js');
const CLI = join(API_ROOT, 'dist', 'cli', 'stack-engine.js');
const WORKER = join(API_ROOT, '..', 'worker', 'dist', 'worker.js');
const MCP = join(API_ROOT, '..', 'mcp-server', 'dist', 'serve.js');

/** The slice of S3 the archive store touches, in memory, path-style. */
function fakeS3(): Promise<{ endpoint: string; server: Server }> {
  const objects = new Map<string, Buffer>();
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const [, bucket = '', ...rest] = url.pathname.split('/');
      const key = rest.join('/');
      void bucket;
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

function freePort(): Promise<number> {
  return new Promise((resolvePort) => {
    const s = createNetServer();
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolvePort(port));
    });
  });
}

let serverLog = '';

async function waitFor<T>(check: () => Promise<T | undefined>, ms: number, what: string): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await check().catch(() => undefined);
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}
${serverLog}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

describe.runIf(enabled)('self-managed engine: the built server, booted the way the image boots it', { timeout: 120_000 }, () => {
  let baseUrl = '';
  let server: ChildProcess | undefined;
  let s3: Server | undefined;
  let secretsDir = '';
  let apiKey = '';
  let env: NodeJS.ProcessEnv = {};
  let ownDatabase: OwnDatabase | undefined;
  // What the passport test leaves behind for the controls test to read.
  let missionId = '';
  let passportJti = '';
  const satellites: ChildProcess[] = [];

  const call = async (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: { 'content-type': 'application/json', ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    let json: unknown = text;
    try {
      json = JSON.parse(text);
    } catch {
      /* not JSON */
    }
    return { status: res.status, body: json as Record<string, any>, text };
  };
  const authed = () => ({ authorization: `Bearer ${apiKey}` });
  // Asynchronous on purpose: a command may reach the archive this test process serves.
  const runCli = (args: string[]) =>
    new Promise<{ status: number | null; output: string }>((done) => {
      const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '';
      child.stdout.on('data', (d: Buffer) => (output += d.toString()));
      child.stderr.on('data', (d: Buffer) => (output += d.toString()));
      child.on('exit', (status) => done({ status, output }));
    });

  beforeAll(async () => {
    for (const path of [SERVER, CLI, WORKER, MCP]) {
      if (!existsSync(path)) throw new Error(`${path} is missing: run "pnpm --filter @stack/api build" first`);
    }
    ownDatabase = await createOwnDatabase(databaseUrl, 'smoke');
    const fake = await fakeS3();
    s3 = fake.server;
    secretsDir = mkdtempSync(join(tmpdir(), 'stack-engine-secrets-'));
    const port = await freePort();
    baseUrl = `http://127.0.0.1:${port}`;

    // What an operator would put in the compose file, and nothing else: no platform token, no AWS KMS, no Resend.
    env = {
      PATH: process.env['PATH'],
      ...(process.env['SystemRoot'] ? { SystemRoot: process.env['SystemRoot'] } : {}),
      NODE_ENV: 'production',
      STACK_DEPLOYMENT: 'self_managed',
      STACK_API_BASE_URL: baseUrl,
      DASHBOARD_URL: 'https://stack.corp.example',
      API_PORT: String(port),
      DATABASE_URL: ownDatabase.url,
      REDIS_URL: redisUrl,
      STACK_KEY_FILE: join(secretsDir, 'stack-kek'),
      SESSION_SIGNING_KEY_FILE: join(secretsDir, 'session-signing-key.pem'),
      API_KEY_PEPPER_FILE: join(secretsDir, 'api-key-pepper'),
      AUDIT_ARCHIVE_BUCKET: 'stack-audit',
      AUDIT_ARCHIVE_ENDPOINT: fake.endpoint,
      AUDIT_ARCHIVE_REGION: 'us-east-1',
      AWS_ACCESS_KEY_ID: 'smoke',
      AWS_SECRET_ACCESS_KEY: 'smoke-secret',
      OAUTH_ENABLED: 'true',
      OAUTH_SCOPE_ENFORCEMENT: 'true',
    };

    const keys = spawnSync(process.execPath, [CLI, 'keys', 'generate', '--dir', secretsDir], { env, encoding: 'utf8' });
    expect(keys.status, keys.stderr).toBe(0);
    // The secrets are files; their content is never printed.
    expect(keys.stdout).not.toMatch(/[0-9a-f]{64}/);

    server = spawn(process.execPath, [SERVER], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    server.stdout?.on('data', (d: Buffer) => (serverLog += d.toString()));
    server.stderr?.on('data', (d: Buffer) => (serverLog += d.toString()));
    await waitFor(
      async () => {
        if (server!.exitCode !== null) throw new Error(`the server exited (${server!.exitCode}):\n${serverLog}`);
        const res = await fetch(`${baseUrl}/health`).catch(() => undefined);
        return res?.ok ? true : undefined;
      },
      150_000,
      'the server to answer /health',
    );

    const created = spawnSync(process.execPath, [CLI, 'operator', 'create', '--email', `owner-${Date.now()}@corp.example`], {
      env,
      encoding: 'utf8',
    });
    expect(created.status, created.stderr).toBe(0);
    apiKey = /API key:\s+(sk_live_\S+)/.exec(created.stdout)?.[1] ?? '';
    expect(apiKey).not.toBe('');
  }, 240_000);

  afterAll(async () => {
    for (const child of satellites) if (child.exitCode === null) child.kill('SIGKILL');
    if (server && server.exitCode === null) {
      const exited = new Promise((r) => server!.once('exit', r));
      server.kill('SIGTERM');
      await Promise.race([exited, new Promise((r) => setTimeout(r, 5_000))]);
      if (server.exitCode === null) server.kill('SIGKILL');
    }
    await new Promise((r) => (s3 ? s3.close(() => r(undefined)) : r(undefined)));
    if (secretsDir) rmSync(secretsDir, { recursive: true, force: true });
    await ownDatabase?.drop();
  });

  it('booted in production with no platform token, no AWS KMS and no Resend, and says it is self-managed', () => {
    expect(serverLog).toContain('STACK API running');
    expect(serverLog).toContain('[licence] No licence key');
    expect(serverLog).not.toMatch(/FLY_API_TOKEN|AWS_KMS_KEY_ID|Resend email service is required/);
  });

  it('names itself by its own address: tokens, OAuth discovery and the A2A card say nothing of getstack.run', async () => {
    const discovery = await call('GET', '/.well-known/oauth-authorization-server');
    expect(discovery.status).toBe(200);
    expect(discovery.body['issuer']).toBe(baseUrl);
    expect(discovery.text).not.toContain('getstack.run');
    const card = await call('GET', '/.well-known/agent.json');
    expect(card.text).not.toContain('getstack.run');
    expect(card.body['url']).toBe(`${baseUrl}/v1/a2a/jsonrpc`);
  });

  it('issues a passport signed under the install\'s own issuer, and reads the record back with its chain intact', async () => {
    // The owner's key registers an agent directly. Lifting a safety stop needs a person's approval, which a key
    // cannot give itself. An install has no browser Console, so the person at the machine decides with the CLI.
    const agent = await call('POST', '/v1/agents/register', { name: 'smoke-agent' }, authed());
    expect(agent.status, agent.text).toBe(201);
    const refused = await call('POST', `/v1/agents/${agent.body['id']}/unblock`, undefined, authed());
    expect(refused.status).toBe(403);
    const approvalId = refused.body['error']?.details?.approval_id as string;
    expect(approvalId).toMatch(/^gvr_/);
    const decided = await runCli(['approvals', 'approve', approvalId]);
    expect(decided.status, decided.output).toBe(0);
    const unblocked = await call('POST', `/v1/agents/${agent.body['id']}/unblock`, undefined, { ...authed(), 'x-governance-approval': approvalId });
    expect(unblocked.status, unblocked.text).toBe(200);
    const mission = await call(
      'POST',
      '/v1/missions',
      { intent_summary: 'Smoke test of a self-managed install', intent_services: [], agent_id: agent.body['id'] },
      authed(),
    );
    expect(mission.status, mission.text).toBe(201);
    const passport = await call(
      'POST',
      '/v1/passports/issue',
      { agent_id: agent.body['id'], mission_ids: [mission.body['mission_id']], intent: { summary: 'Smoke test', services: [] } },
      authed(),
    );
    expect(passport.status, passport.text).toBe(201);

    const [, payload] = String(passport.body['token']).split('.');
    const claims = JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8')) as { iss: string; jti: string };
    expect(claims.iss).toBe(new URL(baseUrl).host);
    missionId = String(mission.body['mission_id']);
    passportJti = claims.jti;

    const verified = await call('POST', '/v1/passports/verify', { token: passport.body['token'] });
    expect(verified.status, verified.text).toBe(200);

    const chain = await call('GET', '/v1/audit/verify-chain', undefined, authed());
    expect(chain.status, chain.text).toBe(200);
    expect(chain.body['valid']).toBe(true);
    expect(chain.body['total_checked']).toBeGreaterThan(0);

    const audit = await call('GET', '/v1/audit', undefined, authed());
    expect(audit.status).toBe(200);
    expect(JSON.stringify(audit.body)).toContain('passport.issue');
  });

  it('has no plan to refuse an operator and nothing to charge: a counted action is never a 402', async () => {
    const me = await call('GET', '/v1/operators/me', undefined, authed());
    expect(me.status, me.text).toBe(200);
    expect(me.body['plan']).toBe('contract');
    expect(me.body).not.toHaveProperty('tier');
  });

  it('serves the engine and not STACK\'s business', async () => {
    for (const path of ['/v1/billing/balance', '/v1/public/events', '/v1/admin/health', '/v1/accounts', '/v1/skills']) {
      const res = await call('GET', path, undefined, authed());
      expect(res.status, `${path} -> ${res.text}`).toBe(404);
    }
    for (const path of ['/v1/agents', '/v1/audit/chain-head', '/v1/security-events', '/v1/control-socket']) {
      const res = await call('GET', path, undefined, authed());
      expect(res.status, `${path} -> ${res.text}`).toBe(200);
    }
  });

  it('reports the licence, never the key, and turns every enterprise feature away with 402 until one is installed', async () => {
    const licence = await call('GET', '/v1/licence', undefined, authed());
    expect(licence.status, licence.text).toBe(200);
    expect(licence.body).toMatchObject({ mode: 'self_managed', licence: 'none', features: [] });

    const roles = await call('POST', '/v1/team/members', { email: 'a@corp.example', name: 'A', role: 'admin' }, authed());
    expect(roles.status).toBe(402);
    expect(roles.body['error']).toMatchObject({ code: 'LICENCE_REQUIRED', details: { feature: 'roles', licence: 'none' } });

    const evidence = await call(
      'POST',
      '/v1/evidence-packs',
      { scope: { kind: 'mission', ref: 'ms_none' } },
      authed(),
    );
    expect(evidence.status).toBe(402);
    expect(evidence.body['error']?.code).toBe('LICENCE_REQUIRED');

    // Partner routes answer before authentication, so nothing about them is discoverable.
    const partner = await call('GET', '/v1/partner/accounts', undefined, authed());
    expect(partner.status).toBe(402);

    const sso = await call('POST', '/v1/identity/sso-domains', { domain: 'corp.example' }, authed());
    expect(sso.status, sso.text).toBe(402);
    expect(sso.body['error']).toMatchObject({ code: 'LICENCE_REQUIRED', details: { feature: 'sso', licence: 'none' } });
  });

  it('with no licence key has every controls feature and none of the seven licensed ones', async () => {
    // None of the seven: the licence names no feature, and every licensed feature is off.
    const licence = await call('GET', '/v1/licence', undefined, authed());
    expect(LICENCE_FEATURES).toEqual(['sso', 'provisioning', 'roles', 'siem', 'evidence_exports', 'partners', 'lts']);
    expect(licence.body['features']).toEqual([]);

    // Every controls feature works with no subscription: no read answers CONTROLS_REQUIRED.
    expect(missionId).not.toBe('');
    expect(passportJti).not.toBe('');
    for (const path of [
      '/v1/audit',
      '/v1/audit/export',
      '/v1/audit/chain-head',
      '/v1/audit/verify-chain',
      '/v1/evidence-packs',
      `/v1/missions/${missionId}/replay`,
      `/v1/missions/${missionId}/dossiers`,
      `/v1/passports/${passportJti}/report`,
    ]) {
      const res = await call('GET', path, undefined, authed());
      expect(res.status, `${path} -> ${res.text}`).toBe(200);
    }

    // Detector settings: changed with no approval, and reset.
    const set = await call('PUT', '/v1/detectors/prompt_injection/config', { enabled: true }, authed());
    expect(set.status, set.text).toBe(200);
    const reset = await call('DELETE', '/v1/detectors/prompt_injection/config', {}, authed());
    expect(reset.status, reset.text).toBe(200);

    // Signed evidence exports are both: a controls feature, and on an install under the licence key.
    const evidence = await call('POST', '/v1/evidence-packs', { scope: { kind: 'mission', ref: missionId } }, authed());
    expect(evidence.status).toBe(402);
    expect(evidence.body['error']?.code).toBe('LICENCE_REQUIRED');
  });

  it('without email, hands the invitation back to the admin who issues it', async () => {
    const invite = await call('POST', '/v1/team/members', { email: 'b@corp.example', name: 'B' }, authed());
    expect(invite.status, invite.text).toBe(201);
    expect(invite.body['invite_token']).toMatch(/^inv_/);
    expect(invite.body['invite_url']).toContain('/team/invite');
  });

  it('keeps the signing key file out of the log and the process\'s secrets out of every response', () => {
    const pepper = readFileSync(join(secretsDir, 'api-key-pepper'), 'utf8').trim();
    const kek = readFileSync(join(secretsDir, 'stack-kek'), 'utf8').trim();
    expect(serverLog).not.toContain(pepper);
    expect(serverLog).not.toContain(kek);
    expect(serverLog).not.toContain('PRIVATE KEY');
  });

  it('the doctor passes on a healthy install', async () => {
    const doctor = await runCli(['doctor']);
    expect(doctor.status, doctor.output).toBe(0);
    expect(doctor.output).toMatch(/ok\s+key service\s+local/);
    expect(doctor.output).toMatch(/ok\s+database/);
  }, 60_000);

  it('boots the worker the same way, with nothing of STACK\'s business to run', async () => {
    const port = await freePort();
    const log = { text: '' };
    const worker = spawn(process.execPath, [WORKER], { env: { ...env, PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'] });
    satellites.push(worker);
    worker.stdout?.on('data', (d: Buffer) => (log.text += d.toString()));
    worker.stderr?.on('data', (d: Buffer) => (log.text += d.toString()));
    await waitFor(
      async () => {
        if (worker.exitCode !== null) throw new Error(`the worker exited (${worker.exitCode}):\n${log.text}`);
        return (await fetch(`http://127.0.0.1:${port}/health`).catch(() => undefined))?.ok ? true : undefined;
      },
      120_000,
      'the worker to answer /health',
    );
    // Let a few ticks run: they must not reach for a provider this install does not have.
    await new Promise((r) => setTimeout(r, 12_000));
    expect(worker.exitCode).toBeNull();
    expect(log.text).toContain('Worker ready');
    // The providers it does not have are named as off, never as failing, and nothing points at STACK.
    // "(0 failed)" is the expiry sweep reporting a clean pass.
    expect(log.text.replace(/\(0 failed\)/g, '')).not.toMatch(/getstack\.run|error|failed|unavailable:/i);
    // The daily external anchor publishes to STACK's public registry: it is STACK's own job, so an install runs none (and none is announced).
    expect(log.text).not.toContain('external anchor');
  }, 180_000);

  it('boots the MCP server against the API, naming itself by the install\'s own address', async () => {
    const port = await freePort();
    const mcpEnv = {
      PATH: env['PATH'],
      ...(env['SystemRoot'] ? { SystemRoot: env['SystemRoot'] } : {}),
      NODE_ENV: 'production',
      STACK_DEPLOYMENT: 'self_managed',
      STACK_API_BASE_URL: baseUrl,
      API_URL: baseUrl,
      OAUTH_ENABLED: 'true',
      PORT: String(port),
    };
    const mcp = spawn(process.execPath, [MCP], { env: mcpEnv, stdio: ['ignore', 'pipe', 'pipe'] });
    satellites.push(mcp);
    let log = '';
    mcp.stdout?.on('data', (d: Buffer) => (log += d.toString()));
    mcp.stderr?.on('data', (d: Buffer) => (log += d.toString()));
    await waitFor(
      async () => {
        if (mcp.exitCode !== null) throw new Error(`the MCP server exited (${mcp.exitCode}):\n${log}`);
        return (await fetch(`http://127.0.0.1:${port}/health`).catch(() => undefined))?.ok ? true : undefined;
      },
      60_000,
      'the MCP server to answer /health',
    );
    const metadata = await fetch(`http://127.0.0.1:${port}/.well-known/oauth-protected-resource/mcp`);
    const text = await metadata.text();
    expect(text).toContain(`${baseUrl}/mcp`);
    expect(text).not.toContain('getstack.run');
  }, 120_000);
});
