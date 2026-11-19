import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { approvalScopeLines, governanceApprovals, hashMcpSessionId, signMcpElicitationAttestation } from '@stack/shared';
import { isDedicatedStackTestDatabase } from './test/dedicated-test-database.js';
import { createOwnDatabase, type OwnDatabase } from './test/own-database.js';

/**
 * A customer's setup, replayed: put rails on one grocery-ordering agent through an MCP client (an operator
 * credential, never the dashboard), then run twenty-five short test Missions with deliberate refusals.
 *
 * The owner is simulated by the rule "say yes to whatever is asked": every governance approval and every intent
 * approval the system asks for is one human decision, counted. Only the transport to the upstream is replaced.
 * It runs twice: once with the owner deciding each approval on its page, and once with the owner confirming each
 * in the chat (the MCP elicitation, attested by the MCP server), where the whole setup needs no browser at all.
 */

const databaseUrl = process.env['DATABASE_URL'];
const redisUrl = process.env['REDIS_URL'] ?? process.env['STACK_TEST_REDIS_URL'];
const enabled = isDedicatedStackTestDatabase(databaseUrl) && Boolean(redisUrl);

const UPSTREAM_HOST = '93.184.216.34';
const SECRET = `sk-grocer-${randomBytes(8).toString('hex')}`;
const MISSIONS = 25;
const ATTESTATION_KEY = `replay-${randomBytes(24).toString('hex')}`;

describe.runIf(enabled)('replay of the grocery-agent setup', { timeout: 900_000 }, () => {
  let app: FastifyInstance;
  let dir = '';
  const saved: Record<string, string | undefined> = {};
  let services: Awaited<ReturnType<typeof import('./config/services.js').createServices>>;
  let createOperator: (label: string) => Promise<{ apiKey: string; operatorId: string }>;
  let operatorId = '';
  let apiKey = '';
  let ownDatabase: OwnDatabase | undefined;

  /** What the owner was asked to decide. A dismissal is the owner's own housekeeping and is counted apart. */
  let decisions = { governance: 0, intent: 0, dismissals: 0, onThePage: 0, inTheChat: 0 };
  /** What the chat showed the owner for each confirmation: every line of what the approval covered. */
  let shown: string[][] = [];

  const key = () => ({ authorization: `Bearer ${apiKey}` });
  async function call(method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, payload?: unknown, headers: Record<string, string> = {}) {
    return app.inject({ method, url, headers: { ...key(), ...headers }, ...(payload === undefined ? {} : { payload: payload as object }) });
  }

  /** The owner confirms in the chat: the client shows the change in full, the MCP server attests the answer. */
  function attestation(approvalId: string, payloadHash: string, session: string, elicitationId: string, secret = ATTESTATION_KEY) {
    const issuedAt = Math.floor(Date.now() / 1000);
    return {
      decision: 'approve',
      payload_hash: payloadHash,
      mcp_session_hash: hashMcpSessionId(session),
      elicitation_id: elicitationId,
      issued_at: issuedAt,
      attestation: signMcpElicitationAttestation(secret, {
        approvalId,
        payloadHash,
        mcpSessionHash: hashMcpSessionId(session),
        principal: `operator:${operatorId}`,
        elicitationId,
        decision: 'approve',
        issuedAt,
      }),
    };
  }

  /** `counted` is false for the owner's own housekeeping (a dismissal), which is kept apart from the setup's decisions. */
  async function decideInChat(approvalId: string, counted = true) {
    const detail = (await call('GET', `/v1/governance/approvals/${approvalId}`)).json();
    // What the person reads in the chat before they say yes: the same lines the confirmation lists. A dismissal has no
    // parts to list: the confirmation shows its one-line summary.
    const lines = approvalScopeLines(detail.approval);
    if (counted) {
      expect(lines.length, `the chat shows what ${detail.approval.action} covers`).toBeGreaterThan(0);
      shown.push(lines);
    } else {
      expect(detail.approval.summary, `the chat shows what ${detail.approval.action} does`).toBeTruthy();
    }
    // A forged confirmation (signed with a key the MCP server does not hold) decides nothing.
    const forged = await call('POST', `/v1/governance/approvals/${approvalId}/chat-decision`, attestation(approvalId, detail.payload_hash, 'replay-session', randomUUID(), 'z'.repeat(40)));
    expect(forged.statusCode, forged.body).toBe(403);
    const real = attestation(approvalId, detail.payload_hash, 'replay-session', randomUUID());
    const decided = await call('POST', `/v1/governance/approvals/${approvalId}/chat-decision`, real);
    expect(decided.statusCode, decided.body).toBe(200);
    if (counted) decisions.inTheChat += 1;
    // A replay of the same confirmation decides nothing more.
    const replayed = await call('POST', `/v1/governance/approvals/${approvalId}/chat-decision`, real);
    expect(replayed.statusCode, replayed.body).toBe(403);
    return real;
  }

  /**
   * The owner says yes to the approval the call asked for, once, and the call is made again with it. A setup decision
   * (`counted`) is one of the three the owner is asked for; a dismissal is the owner's own housekeeping, counted apart.
   */
  async function withGovernance(mode: 'page' | 'chat', url: string, payload: unknown, counted = true) {
    const first = await call('POST', url, payload);
    if (first.statusCode !== 403 || first.json()?.error?.code !== 'GOVERNANCE_APPROVAL_REQUIRED') return first;
    const approvalId = first.json().error.details.approval_id as string;
    if (mode === 'chat') {
      await decideInChat(approvalId, counted);
    } else {
      await services.governanceApprovals.decide(approvalId, operatorId, 'approve');
      if (counted) decisions.onThePage += 1;
    }
    if (counted) decisions.governance += 1;
    return call('POST', url, payload, { 'x-governance-approval': approvalId });
  }

  beforeAll(async () => {
    ownDatabase = await createOwnDatabase(databaseUrl, 'replay');
    saved['DATABASE_URL'] = process.env['DATABASE_URL'];
    process.env['DATABASE_URL'] = ownDatabase.url;
    dir = mkdtempSync(join(tmpdir(), 'stack-replay-'));
    writeFileSync(join(dir, 'kek'), `${randomBytes(32).toString('hex')}\n`);
    for (const name of ['STACK_DEPLOYMENT', 'STACK_API_BASE_URL', 'STACK_KEY_FILE', 'STACK_ALLOW_INSECURE_DEV_KMS', 'RESEND_API_KEY', 'AWS_KMS_KEY_ID', 'MCP_ELICITATION_ATTESTATION_KEY']) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env['STACK_DEPLOYMENT'] = 'self_managed';
    process.env['STACK_API_BASE_URL'] = 'http://127.0.0.1:3999';
    process.env['STACK_KEY_FILE'] = join(dir, 'kek');
    process.env['MCP_ELICITATION_ATTESTATION_KEY'] = ATTESTATION_KEY;

    const { createServices } = await import('./config/services.js');
    const { createSelfManagedOperator } = await import('./config/self-managed.js');
    const { createErrorHandler } = await import('./middleware/error-handler.js');
    const { registerProxyRoutes } = await import('./routes/proxy.js');
    const { registerPassportRoutes } = await import('./routes/passports.js');
    const { registerMissionsRoutes } = await import('./routes/missions.js');
    const { registerAgentRoutes } = await import('./routes/agents.js');
    const { registerServiceRoutes } = await import('./routes/services.js');
    const { registerIntentsRoutes } = await import('./routes/intents.js');
    const { registerOperatorReviewRoutes } = await import('./routes/operator-reviews.js');
    const { registerGovernanceRoutes } = await import('./routes/governance.js');

    services = await createServices(null);
    createOperator = async (label) => createSelfManagedOperator(services.db, { email: `${label}-${Date.now()}@corp.example` });

    // The proxy's transport only: a production process refuses a private address, and nothing here may leave the machine.
    (services.proxy as unknown as Record<string, unknown>)['forwardPrepared'] = async () => ({
      kind: 'response',
      response: { status: 200, headers: {}, body: { ok: true } },
    });

    app = Fastify();
    app.setErrorHandler(createErrorHandler({ cmek: services.cmek }));
    // A person signed in to the chat client with OAuth is what the chat decision route asks for. This stands in for
    // that sign-in on the one route that reads it; the attestation the route verifies is the real one.
    app.addHook('onRequest', async (request) => {
      if (request.url.includes('/chat-decision')) {
        (request as unknown as Record<string, unknown>)['oauthScope'] = 'governance:decide';
        (request as unknown as Record<string, unknown>)['oauthClientId'] = 'client_replay';
      }
    });
    registerAgentRoutes(app, services);
    registerServiceRoutes(app, services);
    registerPassportRoutes(app, services);
    registerMissionsRoutes(app, services);
    registerProxyRoutes(app, services);
    registerIntentsRoutes(app, services);
    registerOperatorReviewRoutes(app, services);
    registerGovernanceRoutes(app, services);
    await app.ready();
  }, 400_000);

  afterAll(async () => {
    await app?.close();
    services?.redis.disconnect();
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    if (dir) rmSync(dir, { recursive: true, force: true });
    await ownDatabase?.drop();
  });

  async function replay(mode: 'page' | 'chat') {
    const created = await createOperator(`replay-${mode}`);
    apiKey = created.apiKey;
    operatorId = created.operatorId;
    decisions = { governance: 0, intent: 0, dismissals: 0, onThePage: 0, inTheChat: 0 };
    shown = [];

    // 1. The owner connects the custom service with its key and the host the key may go to: no approval.
    const connected = await call('POST', '/v1/services/custom', {
      name: 'grocer',
      credential: SECRET,
      scopes: ['read', 'write'],
      allowed_hosts: [UPSTREAM_HOST],
    });
    expect(connected.statusCode, connected.body).toBe(201);
    const connectionId = connected.json().id as string;
    const provider = connected.json().provider as string;

    // 2. Setup is ONE decision: the agent, its first grant (path constraints that turn out too narrow) and its host list.
    const pathPrefixes = (prefixes: string[]) => [{ path: 'url.pathname', op: 'matches', value: `^(${prefixes.join('|')})(/|$)` }];
    const setup = await withGovernance(mode, '/v1/agents/setup', {
      agent: { name: 'grocery-bot' },
      grants: [{ service_connection_id: connectionId, scopes: ['read', 'write'], constraints: pathPrefixes(['/v1/products']) }],
      allowed_hosts: [{ service_connection_id: connectionId, allowed_hosts: [UPSTREAM_HOST] }],
    });
    expect(setup.statusCode, setup.body).toBe(201);
    const agentId = setup.json().agent.id as string;
    // A new agent starts loose: recorded, never held for a call-by-call approval.
    expect(setup.json().agent.accountability_mode).toBe('logged');
    expect(decisions.governance).toBe(1);

    const widen = async (prefixes: string[]) => {
      const res = await withGovernance(mode, '/v1/services/grant', {
        agent_id: agentId,
        service_connection_id: connectionId,
        scopes: ['read', 'write'],
        constraints: pathPrefixes(prefixes),
      });
      expect(res.statusCode, res.body).toBe(201);
    };

    // 3. Twenty-five test Missions: one allowed call and one deliberate refusal each. The owner widens twice.
    let allowed = 0;
    let refused = 0;
    const widenAt = new Map<number, string[]>([
      [2, ['/v1/products', '/v1/cart']],
      [9, ['/v1/products', '/v1/cart', '/v1/orders']],
    ]);
    for (let i = 1; i <= MISSIONS; i += 1) {
      const wider = widenAt.get(i);
      if (wider) await widen(wider);
      const mission = await call('POST', '/v1/missions', { intent_summary: `Test order flow ${i}`, intent_services: [provider], agent_id: agentId });
      expect(mission.statusCode, mission.body).toBe(201);
      const passport = await call('POST', '/v1/passports/issue', {
        agent_id: agentId,
        mission_ids: [mission.json().mission_id],
        intent: { summary: `Test order flow ${i}`, services: [provider] },
        scopes: [{ service_connection_id: connectionId, scopes: ['read', 'write'] }],
      });
      expect(passport.statusCode, passport.body).toBe(201);
      const token = passport.json().token as string;

      const attempt = (path: string, body: Record<string, unknown>) =>
        call('POST', '/v1/proxy', { service: provider, url: `https://${UPSTREAM_HOST}${path}`, method: 'POST', body }, {
          'x-passport-token': token,
          'x-stack-authority-request-id': randomBytes(18).toString('base64url'),
        });

      // Before the first widening the cart is outside the grant; after it the call goes through.
      const good = await attempt(`/v1/cart/items/${1000 + i}`, { quantity: 1 });
      if (good.statusCode === 200) allowed += 1;
      else expect(i, good.body).toBe(1);
      const bad = await attempt(`/v1/admin/reset/${2000 + i}`, { confirm: true });
      expect(bad.statusCode, bad.body).toBe(403);
      refused += 1;
    }
    expect(allowed).toBe(MISSIONS - 1);
    expect(refused).toBe(MISSIONS);

    // At most three human decisions: the setup and the two widenings. No call-by-call approvals, no intent approvals.
    expect(decisions.governance).toBe(3);
    expect(decisions.intent).toBe(0);
    const total = decisions.governance + decisions.intent;
    expect(total).toBeLessThanOrEqual(3);

    // No duplicate approval rows: nothing was asked twice.
    const rows = await services.db.select().from(governanceApprovals).where(eq(governanceApprovals.operator_id, operatorId));
    const keys = rows.map((row) => `${row.action}|${row.resource_id}|${row.payload_hash}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(rows).toHaveLength(3);
    expect(rows.map((row) => row.action).sort()).toEqual(['agent_setup', 'service_grant_expand', 'service_grant_expand']);

    // Repeat refusals are one event with a count, not a card each; they are warnings, not criticals.
    const open = await services.securityEvent.getUnresolved(operatorId, { agentId, limit: 500 });
    const refusalEvents = open.filter((event) => event.signal_type === 'credential_outside_scope');
    expect(refusalEvents.length).toBeLessThanOrEqual(2);
    expect(refusalEvents.every((event) => event.severity === 'warning')).toBe(true);
    const probe = refusalEvents.find((event) => String((event.metadata as Record<string, unknown>)['request_path']).startsWith('/v1/admin/reset'));
    expect(probe, 'the repeated probe is one event').toBeDefined();
    expect((probe!.metadata as Record<string, unknown>)['repeat_count']).toBeGreaterThanOrEqual(MISSIONS - 1);
    expect(open.filter((event) => event.severity === 'critical')).toHaveLength(0);
    expect(open.length).toBeLessThan(10);

    // The connected host is never an undeclared counterparty, and a URL path never is.
    const undeclared = open.filter((event) => event.signal_type === 'undeclared_target');
    // (Before: one per Mission, 24 of them.) The calls carry no counterparty the owner did not connect.
    expect(undeclared).toHaveLength(0);

    // One dismissal clears the agent's warnings, and what it cleared does not come back. The owner's key dismisses them
    // directly: it asks for no approval.
    const dismissUrl = `/v1/agents/${agentId}/dismiss-warnings`;
    const dismissed = await call('POST', dismissUrl, {});
    expect(dismissed.statusCode, dismissed.body).toBe(200);
    decisions.dismissals += 1;
    expect(dismissed.json().dismissed).toBe(open.length);
    expect(await services.securityEvent.getUnresolved(operatorId, { agentId, limit: 500 })).toHaveLength(0);
    const again = await call('POST', '/v1/missions', { intent_summary: 'Another test', intent_services: [provider], agent_id: agentId });
    const passportAgain = await call('POST', '/v1/passports/issue', {
      agent_id: agentId,
      mission_ids: [again.json().mission_id],
      intent: { summary: 'Another test', services: [provider] },
      scopes: [{ service_connection_id: connectionId, scopes: ['read', 'write'] }],
    });
    const refusedAgain = await call('POST', '/v1/proxy', { service: provider, url: `https://${UPSTREAM_HOST}/v1/admin/reset/9`, method: 'POST', body: { confirm: true } }, {
      'x-passport-token': passportAgain.json().token as string,
      'x-stack-authority-request-id': randomBytes(18).toString('base64url'),
    });
    expect(refusedAgain.statusCode).toBe(403);
    expect(await services.securityEvent.getUnresolved(operatorId, { agentId, limit: 500 })).toHaveLength(0);
    expect(decisions.dismissals).toBe(1);
    return rows;
  }

  it('asks the owner for three decisions, folds the repeats, and one dismissal clears the agent', async () => {
    const rows = await replay('page');
    expect(decisions).toMatchObject({ onThePage: 3, inTheChat: 0 });
    expect(rows.every((row) => row.decided_via === 'dashboard' || row.decided_via === null)).toBe(true);
  });

  it('needs no browser visit at all when the owner confirms in the chat, and the chat shows every part', async () => {
    const rows = await replay('chat');
    // Three confirmations in the chat, none on a page, and each one recorded as such.
    expect(decisions).toMatchObject({ onThePage: 0, inTheChat: 3, governance: 3 });
    expect(rows.map((row) => row.decided_via)).toEqual(['chat_elicitation', 'chat_elicitation', 'chat_elicitation']);
    // What the person read before saying yes: the setup in full, then each widening in full.
    expect(shown).toHaveLength(3);
    const text = shown.map((lines) => lines.join('\n'));
    expect(text[0]).toContain('register agent grocery-bot');
    // The account holds one connection of the service, so the lines name the service alone.
    expect(text[0]).toContain('give it access to custom_grocer with scopes read, write');
    expect(text[0]).not.toContain('("default")');
    expect(text[0]).toContain('url.pathname must match "^(/v1/products)(/|$)"');
    expect(text[0]).toContain(`allow the custom_grocer credential to be sent to ${UPSTREAM_HOST}`);
    expect(text[1]).toContain('url.pathname must match "^(/v1/products|/v1/cart)(/|$)"');
    expect(text[2]).toContain('url.pathname must match "^(/v1/products|/v1/cart|/v1/orders)(/|$)"');
    for (const lines of text.slice(1)) expect(lines).toContain('with scopes read, write');
  });

  it('names the connection in the chat lines once the account holds a second connection of the service', async () => {
    const created = await createOperator('replay-two');
    apiKey = created.apiKey;
    operatorId = created.operatorId;
    decisions = { governance: 0, intent: 0, dismissals: 0, onThePage: 0, inTheChat: 0 };
    shown = [];
    const connect = async (connectionName: string) => {
      const res = await call('POST', '/v1/services/custom', {
        name: 'grocer', connection_name: connectionName, credential: SECRET, scopes: ['read', 'write'], allowed_hosts: [UPSTREAM_HOST],
      });
      expect(res.statusCode, res.body).toBe(201);
      return res.json().id as string;
    };
    await connect('default');
    const home = await connect('Home');
    const setup = await withGovernance('chat', '/v1/agents/setup', {
      agent: { name: 'grocery-two' },
      grants: [{ service_connection_id: home, scopes: ['read', 'write'] }],
      allowed_hosts: [{ service_connection_id: home, allowed_hosts: [UPSTREAM_HOST] }],
    });
    expect(setup.statusCode, setup.body).toBe(201);
    const text = shown[0]?.join(String.fromCharCode(10)) ?? '';
    expect(text).toContain('give it access to custom_grocer ("Home") with scopes read, write');
    expect(text).toContain(`allow the custom_grocer credential ("Home") to be sent to ${UPSTREAM_HOST}`);
  });
});
