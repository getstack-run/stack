// `stack proxy serve` — the localhost LLM-gateway shim.
//
// The universal integration problem: every tool (LangChain, an SDK, a
// custom bot) expects an LLM API key in an env var and talks to the
// provider's native endpoint. STACK's pitch is "no key on the box." Those
// collide for EVERY integration. The only bridge used to be "rewrite your
// tool to use our SDK."
//
// This command removes that. It runs a localhost HTTP endpoint that speaks
// the provider's NATIVE shape (Anthropic Messages / OpenAI chat-
// completions). Point any tool's baseURL at it, give it any dummy key, and
// the shim:
//   - ignores the dummy key the tool sends (that's the point — no real
//     provider key ever lives on the box)
//   - authenticates to STACK using the credential appropriate to the
//     agent's key mode: the signed-in operator session for stack_managed,
//     or a local Ed25519 agent key for customer_managed
//   - opens a Mission for the agent with its passport, refreshes the
//     passport, opens a fresh Mission before the current one expires, and
//     completes the Mission on Ctrl-C / SIGTERM
//   - forwards to /v1/llm/<provider>/*, where STACK injects the real key
//     from the vault, governs, logs, meters, and returns the provider's
//     native response (JSON or SSE) verbatim
//
// Integration drops from "7 steps + rewrite your tool" to "change one URL."
//
// Auth posture / threat model (surfaced in --help + docs). The provider
// key ALWAYS stays in the vault; the dummy key the tool sends is discarded.
// Which STACK credential is on the box depends on the agent's key_mode:
//   - stack_managed (default + the proxied-llm-bot preset): the agent has
//     no on-box keypair (STACK signs server-side). The shim authenticates
//     with the OPERATOR credential (STACK_API_KEY / the ~/.stack session)
//     and issues agent-scoped passports. The operator credential sits on
//     the box.
//   - customer_managed: the agent owns an Ed25519 key on the box
//     (~/.stack/agents/<id>.json, chmod 600), scoped to ONE agent and
//     rejected on the next STACK-verified call after revocation.
//     Agent-runtime mode signs each call with a 60s agent JWT; only the
//     scoped agent key is on the box, no operator-wide credential.
//     Strongest posture for an untrusted host.
//   - Binds 127.0.0.1 by default. --host is honored but a non-loopback
//     bind prints a loud warning — anyone who can reach the port can make
//     governed calls as this agent (still bounded by the agent's grants +
//     revocable, but no longer localhost-only).

import { env, stdout, stderr, argv } from 'node:process';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { Stack, StackError, type LlmProvider } from '@getstackrun/sdk';
import { findAgentByName } from './agent-lookup.js';
import { takeFlag } from './api.js';
import { invokeHint } from './auth.js';

const DEFAULT_PORT = 8788;
const DEFAULT_HOST = '127.0.0.1';
const ALL_PROVIDERS: LlmProvider[] = ['anthropic', 'openai', 'openrouter'];

// Map an incoming native-provider request path to the STACK gateway call.
// The provider slug is fixed per STACK route (not header-selectable), so
// we route by the path the tool hits. Anthropic SDKs POST /v1/messages;
// OpenAI-compatible SDKs POST /v1/chat/completions (or bare
// /chat/completions). openrouter shares OpenAI's shape, so a single shim
// can only serve ONE of openai|openrouter on the /chat/completions path —
// the operator picks via --provider (default anthropic + openai).
interface RouteMatch {
  provider: LlmProvider;
}

function matchRoute(pathname: string, providers: Set<LlmProvider>): RouteMatch | null {
  // Anthropic Messages — official SDK sends POST {baseURL}/v1/messages.
  if (
    providers.has('anthropic') &&
    (pathname === '/v1/messages' || pathname === '/messages')
  ) {
    return { provider: 'anthropic' };
  }
  // OpenAI / OpenRouter chat-completions — official SDKs send
  // POST {baseURL}/chat/completions (baseURL usually already ends /v1).
  if (pathname === '/v1/chat/completions' || pathname === '/chat/completions') {
    if (providers.has('openai')) return { provider: 'openai' };
    if (providers.has('openrouter')) return { provider: 'openrouter' };
  }
  return null;
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  return JSON.parse(raw) as Record<string, unknown>;
}

// Dispatch a parsed body to the right SDK gateway call. Returns either the
// parsed JSON response (non-streaming) or an async iterable of provider SSE
// events (streaming). The SDK attaches the agent JWT (Bearer) + passport
// (X-Passport-Token) automatically.
async function callGateway(
  stack: Stack,
  provider: LlmProvider,
  body: Record<string, unknown>,
  passportToken: string,
): Promise<unknown> {
  const opts = { passport: passportToken };
  if (provider === 'anthropic') {
    return stack.llm.anthropic.messages.create(body as never, opts);
  }
  if (provider === 'openai') {
    return stack.llm.openai.chat.completions.create(body as never, opts);
  }
  return stack.llm.openrouter.chat.completions.create(body as never, opts);
}

// ─── Mission lease ──────────────────────────────────────────────────
//
// Every passport belongs to exactly one live Mission, and the API clamps
// a passport's TTL to its Mission. The shim therefore holds a Mission
// lease: it opens a Mission + passport in one call (POST /v1/missions/start),
// refreshes the passport lazily on the call path ~60s before it expires
// (the same on-demand timing the SDK's PassportSession uses), and opens a
// fresh Mission + passport ~120s before the Mission itself expires. The
// rotation grace is wider than the refresh grace so a refresh never lands
// in the Mission's last minute and mints a near-dead token.
//
// Fail closed: a Mission the operator REVOKED is never replaced. Before
// rotating, the lease reads the Mission; if it was revoked the lease goes
// dead and every later call errors until the operator restarts the shim.

export const MISSION_ROTATE_GRACE_SECONDS = 120;
export const PASSPORT_REFRESH_GRACE_SECONDS = 60;
export const DEFAULT_MISSION_TTL_SECONDS = 3600;
export const MIN_MISSION_TTL_SECONDS = 300;

export interface MissionStartResult {
  mission_id: string;
  expires_at: string;
  passport: { token: string; jti: string; expires_at: string };
}

export interface MissionLeaseOps {
  /** POST /v1/missions/start (operator form) for this shim's agent. */
  start(): Promise<MissionStartResult>;
  /** POST /v1/passports/refresh. */
  refresh(token: string): Promise<{ token: string; expires_at: string }>;
  /** GET /v1/missions/:id, used only to detect an operator revocation. */
  get(missionId: string): Promise<{ revoked_at: string | null }>;
  /** POST /v1/missions/:id/complete. */
  complete(missionId: string): Promise<unknown>;
  /** Clock in ms; injectable for tests. */
  now?(): number;
  /** Non-fatal notices (rotation, completion failures). */
  log?(line: string): void;
}

/** Body for the operator form of POST /v1/missions/start used by the shim. */
export function proxyMissionStartBody(
  agentId: string,
  providers: LlmProvider[],
  missionTtlSeconds: number,
): Record<string, unknown> {
  return {
    agent_id: agentId,
    mission: {
      intent_summary: `proxy serve: governed LLM calls (${providers.join(', ')})`,
      intent_services: providers,
      expires_in_seconds: missionTtlSeconds,
    },
    // Passport intent defaults to the Mission's summary + services, which
    // logged/enforced agents need at issue time.
  };
}

export class MissionLease {
  private missionId: string;
  private missionExpMs: number;
  private token: string;
  private passportExpMs: number;
  private pending: Promise<void> | null = null;
  private dead: string | null = null;
  private closed = false;

  private constructor(private readonly ops: MissionLeaseOps, started: MissionStartResult) {
    this.missionId = started.mission_id;
    this.missionExpMs = Date.parse(started.expires_at);
    this.token = started.passport.token;
    this.passportExpMs = Date.parse(started.passport.expires_at);
  }

  static async open(ops: MissionLeaseOps): Promise<MissionLease> {
    return new MissionLease(ops, await ops.start());
  }

  get currentMissionId(): string { return this.missionId; }
  get missionExpiresAt(): Date { return new Date(this.missionExpMs); }
  get passportExpiresAt(): Date { return new Date(this.passportExpMs); }

  private now(): number {
    return this.ops.now ? this.ops.now() : Date.now();
  }

  /** A valid passport token, rotating the Mission or refreshing as needed. */
  async getToken(): Promise<string> {
    for (;;) {
      if (this.dead) throw new Error(this.dead);
      if (this.closed) throw new Error('proxy serve is shutting down; its Mission is complete.');
      if (this.pending) {
        await this.pending;
        continue;
      }
      const now = this.now();
      if (this.missionExpMs - now <= MISSION_ROTATE_GRACE_SECONDS * 1000) {
        this.pending = this.rotate().finally(() => { this.pending = null; });
        continue;
      }
      if (this.passportExpMs - now <= PASSPORT_REFRESH_GRACE_SECONDS * 1000) {
        this.pending = this.refresh().finally(() => { this.pending = null; });
        continue;
      }
      return this.token;
    }
  }

  private async refresh(): Promise<void> {
    const refreshed = await this.ops.refresh(this.token);
    this.token = refreshed.token;
    this.passportExpMs = Date.parse(refreshed.expires_at);
  }

  private async rotate(): Promise<void> {
    const previous = this.missionId;
    const mission = await this.ops.get(previous);
    if (mission.revoked_at) {
      this.dead =
        `Mission ${previous} was revoked; proxy serve will not open a replacement. ` +
        `Restart it once the agent should run again.`;
      throw new Error(this.dead);
    }
    const started = await this.ops.start();
    this.missionId = started.mission_id;
    this.missionExpMs = Date.parse(started.expires_at);
    this.token = started.passport.token;
    this.passportExpMs = Date.parse(started.passport.expires_at);
    this.ops.log?.(`  ↳ opened Mission ${started.mission_id} (replaces ${previous}, which was about to expire)\n`);
    // Close the old Mission now that nothing new uses it; completing it
    // revokes its passport instead of leaving it live until expiry.
    await this.completeQuietly(previous);
  }

  private async completeQuietly(missionId: string): Promise<void> {
    try {
      await this.ops.complete(missionId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.ops.log?.(`  ↳ could not complete Mission ${missionId} (${msg}); it expires on its own.\n`);
    }
  }

  /** Complete the current Mission (revokes its passport). Idempotent. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.pending) await this.pending.catch(() => undefined);
    if (this.dead) return;
    await this.completeQuietly(this.missionId);
  }
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const buf = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': String(buf.byteLength),
  });
  res.end(buf);
}

// Map a STACK gateway failure to the provider's native error envelope so
// the tool's own error handling stays legible, and print a targeted hint
// to the shim's stderr (the operator watching the terminal).
function sendGatewayError(res: ServerResponse, provider: LlmProvider, err: unknown): void {
  const status = err instanceof StackError ? err.status : 502;
  const message = err instanceof Error ? err.message : String(err);
  // Anthropic + OpenAI both use `{ error: { type, message } }`.
  sendJson(res, status, { error: { type: 'stack_gateway_error', message } });

  if (status === 403) {
    if (/not in passport scope/i.test(message)) {
      stderr.write(
        `  ↳ ${provider} is not in this agent's grants. Grant it: ` +
          `${invokeHint(`service grant <connection-id> --agent <agent>`)} ` +
          `(or connect ${provider} at https://getstack.run/services first).\n`,
      );
    } else if (/no .* connection|connect .* first/i.test(message)) {
      stderr.write(
        `  ↳ ${provider} is not connected on this operator. ` +
          `Connect it at https://getstack.run/services, then retry.\n`,
      );
    }
  }
}

export async function cmdProxy(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub !== 'serve') {
    stderr.write(
      `error: unknown proxy subcommand "${sub ?? ''}". Use: ${invokeHint('proxy serve --agent <name|id>')}\n`,
    );
    process.exit(2);
  }
  const rest = args.slice(1);

  const agentRef = takeFlag(rest, '--agent');
  if (typeof agentRef !== 'string' || !agentRef) {
    stderr.write(
      `usage: ${invokeHint('proxy serve --agent <name|id> [--port 8788] [--provider anthropic|openai|openrouter] [--host 127.0.0.1] [--mission-ttl 3600]')}\n\n` +
        `Runs a localhost endpoint speaking the provider's native API shape.\n` +
        `Point any tool's baseURL at it (dummy key is fine); STACK injects the\n` +
        `real key from the vault and governs + logs the call. No provider key on the box.\n`,
    );
    process.exit(2);
  }

  const portFlag = takeFlag(rest, '--port');
  const port = typeof portFlag === 'string' ? Number.parseInt(portFlag, 10) : DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    stderr.write(`error: --port must be an integer 1-65535 (got "${String(portFlag)}").\n`);
    process.exit(2);
  }

  const hostFlag = takeFlag(rest, '--host');
  const host = typeof hostFlag === 'string' ? hostFlag : DEFAULT_HOST;

  const missionTtlFlag = takeFlag(rest, '--mission-ttl');
  const missionTtl =
    typeof missionTtlFlag === 'string' ? Number(missionTtlFlag) : DEFAULT_MISSION_TTL_SECONDS;
  if (
    missionTtlFlag === true ||
    !Number.isInteger(missionTtl) ||
    missionTtl < MIN_MISSION_TTL_SECONDS
  ) {
    stderr.write(
      `error: --mission-ttl must be a whole number of seconds, at least ${MIN_MISSION_TTL_SECONDS} ` +
        `(got "${String(missionTtlFlag)}").\n`,
    );
    process.exit(2);
  }

  // --provider may be repeated or comma-separated; defaults to anthropic +
  // openai (openrouter shares openai's path, so it's opt-in to avoid an
  // ambiguous /chat/completions route).
  const providerFlags: string[] = [];
  for (;;) {
    const p = takeFlag(rest, '--provider');
    if (typeof p !== 'string') break;
    providerFlags.push(...p.split(',').map((s) => s.trim()).filter(Boolean));
  }
  let providers: Set<LlmProvider>;
  if (providerFlags.length === 0) {
    providers = new Set<LlmProvider>(['anthropic', 'openai']);
  } else {
    for (const p of providerFlags) {
      if (!ALL_PROVIDERS.includes(p as LlmProvider)) {
        stderr.write(`error: --provider must be one of: ${ALL_PROVIDERS.join(', ')} (got "${p}").\n`);
        process.exit(2);
      }
    }
    providers = new Set(providerFlags as LlmProvider[]);
    if (providers.has('openai') && providers.has('openrouter')) {
      stderr.write(
        `error: openai and openrouter both use the /chat/completions path and cannot be served together.\n` +
          `Run one shim per provider on different ports.\n`,
      );
      process.exit(2);
    }
  }

  const baseUrl = env['STACK_API_URL'] ?? 'https://api.getstack.run';

  // Resolve --agent to an agt_* id + its key_mode via the operator-auth
  // path (STACK_API_KEY or ~/.stack/credentials.json from `auth login`).
  const opStack = new Stack({ baseUrl });
  let agentId: string;
  let keyMode: string;
  try {
    if (agentRef.startsWith('agt_')) {
      const a = (await opStack.agents.get(agentRef)) as { id: string; key_mode?: string };
      agentId = a.id;
      keyMode = a.key_mode ?? 'stack_managed';
    } else {
      const list = (await opStack.agents.list()) as Array<{ id: string; name: string; status?: string; key_mode?: string }>;
      const match = findAgentByName(list, agentRef);
      if (!match) {
        stderr.write(
          `error: no agent named "${agentRef}" on this operator.\n` +
            `Register one for a bot that just runs:\n` +
            `  ${invokeHint(`agent register ${agentRef} --profile proxied-llm-bot`)}\n`,
        );
        process.exit(1);
      }
      agentId = match.id;
      keyMode = match.key_mode ?? 'stack_managed';
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    stderr.write(
      `error: could not resolve agent "${agentRef}" (${msg}).\n` +
        `Sign in first: ${invokeHint('auth login')}.\n`,
    );
    process.exit(1);
  }

  // Pick the auth model by the agent's signing model:
  //
  //   stack_managed (default + the proxied-llm-bot preset): the agent has
  //     NO on-box keypair — STACK signs its claims server-side. The shim
  //     authenticates as the OPERATOR (the same STACK_API_KEY / session
  //     that resolved the agent) and issues agent-scoped passports. The
  //     operator credential is what sits on the box. The PROVIDER key
  //     still never leaves the vault.
  //
  //   customer_managed: the agent owns an on-box Ed25519 keypair (via
  //     `agent enroll`). Agent-runtime mode signs each call with a fresh
  //     60s agent JWT; only the scoped agent key is on the box — no
  //     operator-wide credential. Strongest "no key on the box" posture.
  //
  // Both keep the provider key in the vault; they differ in WHICH STACK
  // credential is on the box.
  const stack =
    keyMode === 'customer_managed' ? new Stack({ agent_id: agentId, baseUrl }) : new Stack({ baseUrl });
  if (keyMode === 'customer_managed') {
    stdout.write(`  auth: on-box agent keypair (customer_managed) — only a scoped agent key on this box\n`);
  } else {
    stdout.write(
      `  auth: operator credential (stack_managed agent). For a box that holds only a\n` +
        `        scoped agent key instead, use a customer_managed agent (agent enroll).\n`,
    );
  }

  // One Mission lease for the shim's lifetime (see MissionLease above).
  // Passport scopes omitted → all of the agent's granted scopes; the agent
  // must be granted the provider(s) it will call, and those grants must
  // cover the Mission's intent_services. accountability comes from the
  // AGENT record (a proxied-llm-bot agent is `logged`, so the approval
  // gate is skipped and the first call just works). The passport intent
  // defaults to the Mission's summary + services. A customer_managed
  // agent opens the Mission for itself with its own agent JWT.
  const providerList = [...providers];
  const startBody = proxyMissionStartBody(agentId, providerList, missionTtl);
  let lease: MissionLease;
  try {
    lease = await MissionLease.open({
      start: async () =>
        (await stack.missions.start(startBody as never)) as unknown as MissionStartResult,
      refresh: (token) => stack.passports.refresh(token),
      get: async (missionId) => {
        const m = await stack.missions.get(missionId);
        return { revoked_at: m.revoked_at ?? null };
      },
      complete: (missionId) => stack.missions.complete(missionId),
      log: (line) => { stderr.write(line); },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const enrollmentHint =
      keyMode === 'customer_managed'
        ? ` If the local agent key is missing, run ${invokeHint(`agent enroll ${agentId}`)}.`
        : '';
    stderr.write(
      `error: could not open a Mission and issue its passport for ${agentId} (${msg}).\n` +
        `Check that you are signed in (${invokeHint('auth login')}) and that the agent is not blocked.` +
        `${enrollmentHint}\n`,
    );
    process.exit(1);
  }

  const server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', `http://${host}:${port}`);
      if (req.method === 'GET' && url.pathname === '/healthz') {
        sendJson(res, 200, {
          ok: true,
          agent_id: agentId,
          providers: [...providers],
          mission_id: lease.currentMissionId,
          mission_expires_at: lease.missionExpiresAt.toISOString(),
          passport_expires_at: lease.passportExpiresAt.toISOString(),
        });
        return;
      }
      if (req.method !== 'POST') {
        sendJson(res, 405, { error: { type: 'method_not_allowed', message: 'POST only' } });
        return;
      }
      const route = matchRoute(url.pathname, providers);
      if (!route) {
        sendJson(res, 404, {
          error: {
            type: 'not_found',
            message:
              `No gateway route for ${url.pathname}. Served: ` +
              [...providers]
                .map((p) => (p === 'anthropic' ? '/v1/messages' : '/v1/chat/completions'))
                .join(', '),
          },
        });
        return;
      }

      let body: Record<string, unknown>;
      try {
        body = await readJsonBody(req);
      } catch {
        sendJson(res, 400, { error: { type: 'invalid_request', message: 'body must be JSON' } });
        return;
      }

      const isStreaming = body['stream'] === true;
      try {
        const result = await callGateway(stack, route.provider, body, await lease.getToken());

        if (isStreaming) {
          // Re-serialize the SDK's parsed provider events as SSE frames.
          // Keeps the client stream byte-faithful to what the tool's SDK
          // expects; STACK's synthetic frames are NOT re-emitted — they go
          // to stderr so the operator sees them without polluting the
          // provider's native protocol.
          //
          // Two synthetic frames exist. `leak_detected` is a notice:
          // the stream completed. `leak_blocked` means STACK refused to
          // forward the next chunk and the stream ENDS THERE, so the tool sees
          // a truncated response with no error of its own — say so plainly, or
          // the operator debugs the wrong thing.
          res.writeHead(200, {
            'content-type': 'text/event-stream',
            'cache-control': 'no-cache',
            connection: 'keep-alive',
          });
          const iterable = result as AsyncIterable<Record<string, unknown>>;
          for await (const evt of iterable) {
            if (evt && evt['type'] === 'leak_detected') {
              stderr.write(`  ↳ STACK flagged a potential leak in a streamed response (agent ${agentId}).\n`);
              continue;
            }
            if (evt && evt['type'] === 'leak_blocked') {
              stderr.write(
                `  ↳ STACK BLOCKED a leak mid-stream (agent ${agentId}). The response stops here; ` +
                  'content delivered before this point was scanned and clean.\n',
              );
              continue;
            }
            res.write(`data: ${JSON.stringify(evt)}\n\n`);
          }
          res.end();
          return;
        }

        sendJson(res, 200, result);
      } catch (err) {
        if (res.headersSent) {
          // Mid-stream failure — best we can do is end the stream.
          res.end();
          return;
        }
        sendGatewayError(res, route.provider, err);
      }
    })();
  });

  if (host !== '127.0.0.1' && host !== 'localhost') {
    stderr.write(
      `\n  ⚠ WARNING: binding ${host} (not loopback). Anyone who can reach ${host}:${port}\n` +
        `    can make governed LLM calls as agent ${agentId}. This is still bounded by the\n` +
        `    agent's grants and rejected on its next STACK-verified call after revocation,\n` +
        `    but it is no longer localhost-only.\n`,
    );
  }

  server.listen(port, host, () => {
    const providerLines = [...providers]
      .map((p) =>
        p === 'anthropic'
          ? `    anthropic  →  http://${host}:${port}/v1/messages`
          : `    ${p}  →  http://${host}:${port}/v1/chat/completions`,
      )
      .join('\n');
    stdout.write(
      `\n  STACK proxy serve — governed LLM gateway on the box\n` +
        `  ───────────────────────────────────────────────────\n\n` +
        `  agent:     ${agentId}\n` +
        `  mission:   ${lease.currentMissionId} (a new one opens before it expires)\n` +
        `  listening: http://${host}:${port}\n` +
        `  providers:\n${providerLines}\n\n` +
        `  Point your tool at the base URL and use ANY dummy key — the real key\n` +
        `  stays in the STACK vault. Example (Anthropic SDK):\n\n` +
        (providers.has('anthropic')
          ? `    ANTHROPIC_BASE_URL=http://${host}:${port} ANTHROPIC_API_KEY=dummy your-tool\n\n`
          : `    OPENAI_BASE_URL=http://${host}:${port}/v1 OPENAI_API_KEY=dummy your-tool\n\n`) +
        `  health: curl http://${host}:${port}/healthz\n` +
        `  Ctrl-C to stop (completes the Mission). Revoking the agent or the Mission\n` +
        `  rejects its next STACK-verified call.\n\n`,
    );
  });

  server.on('error', (err) => {
    const e = err as NodeJS.ErrnoException;
    if (e.code === 'EADDRINUSE') {
      stderr.write(`error: port ${port} is already in use. Pass --port <n> to pick another.\n`);
    } else {
      stderr.write(`error: server failed: ${e.message}\n`);
    }
    void lease.close().finally(() => process.exit(1));
  });

  // Clean shutdown: stop accepting calls, then complete the Mission so its
  // passport is revoked now rather than staying live until expiry.
  const shutdown = (signal: string): void => {
    stdout.write(`\n  ${signal}: completing Mission ${lease.currentMissionId} and stopping.\n`);
    server.close();
    void lease.close().finally(() => process.exit(0));
  };
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
}

// Allow `proxy-serve.ts` to be a standalone entry if ever spawned directly,
// though the canonical path is the `proxy` verb in index.ts.
if (import.meta.url === `file://${argv[1]}`) {
  void cmdProxy(argv.slice(2));
}
