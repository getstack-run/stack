import { createServer, type Server } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { NO_SPEND_LEDGER } from '@stack/vault';
import { isDedicatedStackTestDatabase } from './test/dedicated-test-database.js';
import { createOwnDatabase, type OwnDatabase } from './test/own-database.js';

/**
 * The proxy half of the self-managed smoke test, on the real services built
 * the way a self-managed install builds them (a key-encryption key file, no
 * KMS, no platform, no email): an agent calls a service through the proxy and the
 * credential reaches the upstream without ever reaching the agent, and the
 * record of it verifies.
 *
 * Only the proxy's transport is substituted: a production process refuses to
 * send to a private address, so the call is forwarded to a local echo server
 * instead of the public address the connection names. Everything before the
 * socket (the passport, the Mission, the grant, the scope wall, the detectors,
 * the credential injection, the audit chain) is the real route.
 */

const databaseUrl = process.env['DATABASE_URL'];
const redisUrl = process.env['REDIS_URL'] ?? process.env['STACK_TEST_REDIS_URL'];
const enabled = isDedicatedStackTestDatabase(databaseUrl) && Boolean(redisUrl);

const UPSTREAM_HOST = '93.184.216.34';
const SECRET = `sk-echo-${randomBytes(8).toString('hex')}`;

describe.runIf(enabled)('self-managed engine: a call through the proxy to a local echo server', { timeout: 400_000 }, () => {
  let app: FastifyInstance;
  let echo: Server;
  let dir = '';
  const saved: Record<string, string | undefined> = {};
  const echoed: Array<{ method: string; path: string; headers: Record<string, string | string[] | undefined> }> = [];
  let apiKey = '';
  let agentId = '';
  let passportToken = '';
  let services: Awaited<ReturnType<typeof import('./config/services.js').createServices>>;
  let operatorId = '';
  let ownDatabase: OwnDatabase | undefined;

  beforeAll(async () => {
    ownDatabase = await createOwnDatabase(databaseUrl, 'proxy');
    saved['DATABASE_URL'] = process.env['DATABASE_URL'];
    process.env['DATABASE_URL'] = ownDatabase.url;
    dir = mkdtempSync(join(tmpdir(), 'stack-engine-proxy-'));
    writeFileSync(join(dir, 'kek'), `${randomBytes(32).toString('hex')}\n`);
    for (const name of ['STACK_DEPLOYMENT', 'STACK_API_BASE_URL', 'STACK_KEY_FILE', 'STACK_ALLOW_INSECURE_DEV_KMS', 'FLY_API_TOKEN', 'RESEND_API_KEY', 'AWS_KMS_KEY_ID']) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env['STACK_DEPLOYMENT'] = 'self_managed';
    process.env['STACK_API_BASE_URL'] = 'http://127.0.0.1:3999';
    process.env['STACK_KEY_FILE'] = join(dir, 'kek');

    echo = createServer((req, res) => {
      echoed.push({ method: req.method ?? '', path: req.url ?? '', headers: { ...req.headers } });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
    const echoPort = (echo.address() as { port: number }).port;

    const { createServices } = await import('./config/services.js');
    const { createSelfManagedOperator } = await import('./config/self-managed.js');
    const { createErrorHandler } = await import('./middleware/error-handler.js');
    const { registerProxyRoutes } = await import('./routes/proxy.js');
    const { registerPassportRoutes } = await import('./routes/passports.js');
    const { registerMissionsRoutes } = await import('./routes/missions.js');
    const { registerAuditRoutes } = await import('./routes/audit.js');
    const { RegisterAgentInput } = await import('@stack/shared');

    services = await createServices(null);
    expect(services.kms.providerKind).toBe('local');
    expect(services.features.snapshot().mode).toBe('self_managed');

    const created = await createSelfManagedOperator(services.db, { email: `proxy-${Date.now()}@corp.example` });
    apiKey = created.apiKey;
    operatorId = created.operatorId;

    // Setup through the services: registering an agent and widening a grant need a person's approval.
    const agent = await services.agent.register(operatorId, 'enterprise', RegisterAgentInput.parse({ name: 'echo-agent', accountability_mode: 'standard' }));
    agentId = agent.id;
    const connection = await services.serviceConnection.connectCustom(operatorId, 'enterprise', {
      name: 'echo',
      credential: SECRET,
      scopes: ['read'],
      allowed_hosts: [UPSTREAM_HOST],
    });
    await services.serviceConnection.grantAgentAccess(
      operatorId,
      { agent_id: agentId, service_connection_id: connection.id, scopes: ['read'] },
      { authorityExpansionApproved: true },
    );

    // The proxy's transport only: the connection names a public address; the bytes go to the echo server.
    (services.proxy as unknown as Record<string, unknown>)['forward'] = async (
      input: { method: string; headers?: Record<string, string> },
      authHeaders: Record<string, string>,
      resolvedUrl: string,
      allowedHosts: readonly string[],
    ) => {
      expect(allowedHosts).toContain(UPSTREAM_HOST);
      const target = new URL(resolvedUrl);
      const res = await fetch(`http://127.0.0.1:${echoPort}${target.pathname}${target.search}`, {
        method: input.method,
        headers: { ...(input.headers ?? {}), ...authHeaders },
      });
      return { status: res.status, headers: {}, body: await res.json() };
    };

    app = Fastify();
    app.setErrorHandler(createErrorHandler({ cmek: services.cmek }));
    registerPassportRoutes(app, services);
    registerMissionsRoutes(app, services);
    registerProxyRoutes(app, services);
    registerAuditRoutes(app, services);
    await app.ready();

    const key = { authorization: `Bearer ${apiKey}` };
    const mission = await app.inject({
      method: 'POST',
      url: '/v1/missions',
      headers: key,
      payload: { intent_summary: 'Read the echo service', intent_services: ['custom_echo'], agent_id: agentId },
    });
    expect(mission.statusCode, mission.body).toBe(201);
    const passport = await app.inject({
      method: 'POST',
      url: '/v1/passports/issue',
      headers: key,
      payload: {
        agent_id: agentId,
        mission_ids: [mission.json().mission_id],
        intent: { summary: 'Read the echo service', services: ['custom_echo'] },
        scopes: [{ service_connection_id: connection.id, scopes: ['read'] }],
      },
    });
    expect(passport.statusCode, passport.body).toBe(201);
    passportToken = passport.json().token;
  }, 400_000);

  afterAll(async () => {
    await app?.close();
    await new Promise((r) => (echo ? echo.close(() => r(undefined)) : r(undefined)));
    services?.redis.disconnect();
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    if (dir) rmSync(dir, { recursive: true, force: true });
    await ownDatabase?.drop();
  });

  it('forwards the call, injecting the credential the agent never held', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/proxy',
      headers: { authorization: `Bearer ${apiKey}`, 'x-passport-token': passportToken },
      payload: { service: 'custom_echo', url: `https://${UPSTREAM_HOST}/v1/things?limit=1`, method: 'GET' },
    });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({ status: 200, body: { ok: true } });
    // The credential reached the upstream, and is nowhere in what the agent received.
    expect(echoed).toHaveLength(1);
    expect(JSON.stringify(echoed[0]!.headers)).toContain(SECRET);
    expect(res.body).not.toContain(SECRET);
    expect(echoed[0]!.path).toBe('/v1/things?limit=1');
  });

  it('made that call with a spend ledger that refuses everything: a call on an install never reaches a wallet', () => {
    // The ledger is the install's own, not a stub of this test: any hold, capture or release it was asked for
    // would have failed the call above with NO_WALLET_ON_INSTALL.
    expect(services.spend).toBe(NO_SPEND_LEDGER);
  });

  it('records the call, and the record verifies', async () => {
    const chain = await app.inject({ method: 'GET', url: '/v1/audit/verify-chain', headers: { authorization: `Bearer ${apiKey}` } });
    expect(chain.statusCode, chain.body).toBe(200);
    expect(chain.json()).toMatchObject({ valid: true });
    expect(chain.json().total_checked).toBeGreaterThanOrEqual(3);
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=50', headers: { authorization: `Bearer ${apiKey}` } });
    expect(audit.body).toContain('proxy');
    expect(audit.body).not.toContain(SECRET);
  });
});
