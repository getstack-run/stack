#!/usr/bin/env node

import { argv, env, stdout, stderr } from 'node:process';
import { cmdLogin, cmdLogout, cmdStatus, getAccessToken, invokeHint } from './auth.js';
import { renderHelp } from './help.js';
import { takeControlRefFlag } from './api.js';
import { cmdAgent } from './agent.js';
import { cmdPassport } from './passports.js';
import { cmdService } from './services.js';
import { cmdRentAHuman } from './rentahuman.js';
import { cmdPay } from './pay.js';
import { cmdDropoff } from './dropoffs.js';
import { cmdSkill } from './skills.js';
import { cmdIdentity } from './identity.js';
import { cmdAudit } from './audit.js';
import { cmdEvent } from './events.js';
import { cmdTeam } from './team.js';
import { cmdMe } from './me.js';
import { cmdNotifications } from './notifications.js';
import { cmdDetector } from './detectors.js';
import { cmdPii } from './pii.js';
import { cmdIntents } from './intents.js';
import { cmdMissions } from './missions.js';
import { cmdFleets } from './fleets.js';
import { cmdAccounts } from './accounts.js';
import { cmdCatalogue } from './catalogue.js';
import { cmdChat } from './chat-channels.js';
import { cmdDrive } from './drive.js';
import { cmdMemory } from './memory.js';
import { cmdBrain } from './brain.js';
import { cmdPost } from './post.js';
import { cmdControlSocket } from './control-socket.js';
import { cmdNetwork } from './network.js';
import { cmdAgentIdentity } from './agent-identity.js';
import { cmdPolicies, cmdReviews } from './control-policies.js';
import { cmdCalendar, cmdMeeting, cmdWake } from './wake.js';
import { cmdEvidencePack } from './evidence-packs.js';
import { cmdLlm } from './llm.js';
import { cmdInboundWebhook } from './inbound-webhooks.js';
import { cmdPartner } from './partner.js';
import { cmdProxy } from './proxy-serve.js';
import { cmdQuickstart } from './quickstart.js';
import { cmdScan } from './scan.js';
import { cmdUsage } from './usage.js';
import { cmdBilling } from './billing.js';
import { cmdFlaggedContent } from './flagged-content.js';
import { cmdMessageAccess } from './message-access.js';
import { cmdMessages } from './messages.js';
import { cmdTrust } from './trust.js';
import { cmdApproval } from './approvals.js';
import { cmdSetup } from './setup.js';
import { cmdAuthority } from './authority.js';

const DASHBOARD_URL = 'https://getstack.run';
const API_URL = env['STACK_API_URL'] ?? 'https://api.getstack.run';

// ── ANSI helpers ────────────────────────────────────────────────────

const isTTY = stdout.isTTY === true;
const useColor = isTTY && !env['NO_COLOR'];
function ansi(code: string): string {
  return useColor ? `\x1b[${code}m` : '';
}
const C = {
  reset:  ansi('0'),
  dim:    ansi('2'),
  bold:   ansi('1'),
  red:    ansi('31'),
  green:  ansi('32'),
  yellow: ansi('33'),
  cyan:   ansi('36'),
  white:  ansi('37'),
  gray:   ansi('90'),
};

// ── Audit-log row shape ─────────────────────────────────────────────
//
// One render path. Both --demo and --follow produce rows of this shape.
// Fields mirror audit_log columns 1:1 — no translation, no invented
// presentation tags. What you see is what's in the table.
//
// `level` is a render hint, not a stored field — derived from outcome
// and action so we can colour the moment without reshaping data.

// Layer is the displayed layer column. The DB audit_log enum still uses
// the older 4-layer taxonomy where `vault` covered passports + creds +
// proxy; the renderer maps action prefix → display layer (see
// `displayLayerForAction` below) so the CLI matches the new 5-layer
// marketing taxonomy.
type Layer = 'vault' | 'dropoff' | 'skills' | 'hire' | 'system' | 'billing' | 'detector'
  | 'passport' | 'proxy' | 'credential' | 'identity';
type Outcome = 'success' | 'failure' | 'pending' | 'blocked' | 'critical' | 'warning' | 'info';
type Level = 'normal' | 'alert' | 'resolved';

interface AuditRow {
  layer: Layer;
  action: string;
  outcome: Outcome;
  duration_ms: number | null;
  error_message: string | null;
  // Optional row timestamp (ms since epoch). When present, used for the
  // displayed time so a batch of rows shows their actual server-side
  // timestamps instead of all sharing the CLI process's wall-clock.
  timestamp_ms?: number | null;
}

function deriveLevel(row: AuditRow): Level {
  // A failure with an error message is the canonical "the system caught
  // something" moment — render red. Plain failures (no error message)
  // stay yellow. Revoke actions + detector fires also alert.
  if (row.layer === 'detector') return 'alert';
  if (row.outcome === 'blocked') return 'alert';
  if (row.outcome === 'critical') return 'alert';
  if (row.outcome === 'failure' && row.error_message) return 'alert';
  if (row.action.startsWith('passport.revoke')) return 'alert';
  if (row.action === 'passport.checkout') return 'resolved';
  return 'normal';
}

function formatRow(row: AuditRow, level: Level = deriveLevel(row)): string {
  const ts = row.timestamp_ms != null ? formatTs(new Date(row.timestamp_ms)) : formatTs();
  const marker =
    level === 'alert'    ? `${C.red}┃${C.reset}` :
    level === 'resolved' ? `${C.green}┃${C.reset}` :
                           ` `;
  const layerCol = `${C.cyan}${row.layer.padEnd(8)}${C.reset}`;
  const actionCol = `${C.white}${row.action.padEnd(28)}${C.reset}`;
  const outcomeColor =
    row.outcome === 'success' ? C.green :
    row.outcome === 'critical' ? C.red :
    row.outcome === 'warning' ? C.yellow :
    row.outcome === 'info' ? C.cyan :
    (row.outcome === 'failure' && row.error_message) ? C.red :
    row.outcome === 'blocked' ? C.red :
                                C.yellow;
  const outcomeCol = `${outcomeColor}${row.outcome.padEnd(7)}${C.reset}`;
  const durCol = row.duration_ms != null
    ? `${C.dim}${String(row.duration_ms).padStart(4)}ms${C.reset}`
    : `${C.dim}    -${C.reset}`;
  const detail = row.error_message
    ? ` ${C.red}· ${row.error_message}${C.reset}`
    : '';
  return `${marker} ${C.gray}${ts}${C.reset}  ${layerCol}  ${actionCol}  ${outcomeCol}  ${durCol}${detail}`;
}

function formatTs(t: Date = new Date()): string {
  const hh = String(t.getHours()).padStart(2, '0');
  const mm = String(t.getMinutes()).padStart(2, '0');
  const ss = String(t.getSeconds()).padStart(2, '0');
  const mmm = String(t.getMilliseconds()).padStart(3, '0');
  return `${hh}:${mm}:${ss}.${mmm}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

// ── Demo events ─────────────────────────────────────────────────────
//
// Every row uses the actual action names + layer values that audit_log
// stores in production. credential.proxy is the proxy action; passport.*
// is the vault. error_message on the denied row is the kind of string
// the proxy actually writes when it rejects a call.
//
// Note: today the API writes ONE passport.revoke audit entry even when
// the parent revoke cascades to children. Demo includes a second
// passport.revoke row to anticipate the cascade-audit fix that's the
// next commit. After that fix, --follow will produce the same shape.

interface DemoEvent extends AuditRow {
  delayMs: number;
  forceLevel?: Level;
}

// Layers below match what `displayLayerForAction` derives from the
// action prefix at runtime. Hardcoded here so the demo reads identically
// when piped through normalizeAuditEntry vs printed straight.
const DEMO: DemoEvent[] = [
  { layer: 'identity', action: 'identity.verify.complete', outcome: 'success', duration_ms: 142, error_message: null, delayMs: 600 },
  { layer: 'passport', action: 'passport.issue',           outcome: 'success', duration_ms: 47,  error_message: null, delayMs: 800 },
  { layer: 'passport', action: 'passport.delegate',        outcome: 'success', duration_ms: 38,  error_message: null, delayMs: 1100 },
  { layer: 'proxy',    action: 'credential.proxy',         outcome: 'success', duration_ms: 287, error_message: null, delayMs: 1100 },
  { layer: 'proxy',    action: 'credential.proxy',         outcome: 'success', duration_ms: 412, error_message: null, delayMs: 1100 },
  { layer: 'passport', action: 'passport.checkpoint',      outcome: 'success', duration_ms: 22,  error_message: null, delayMs: 1100 },
  { layer: 'proxy',    action: 'credential.proxy',         outcome: 'success', duration_ms: 311, error_message: null, delayMs: 1700 },
  { layer: 'proxy',    action: 'credential.proxy',         outcome: 'failure', duration_ms: 18,  error_message: 'stripe.charges.create · scope=slack,github · SCOPE_VIOLATION', delayMs: 250 },
  { layer: 'passport', action: 'passport.revoke',          outcome: 'success', duration_ms: 31,  error_message: null, delayMs: 700 },
  { layer: 'passport', action: 'passport.revoke_cascade',  outcome: 'success', duration_ms: 18,  error_message: null, delayMs: 220 },
  { layer: 'passport', action: 'passport.checkout',        outcome: 'success', duration_ms: 12,  error_message: null, delayMs: 1500 },
];

async function runDemo(loop: boolean): Promise<void> {
  do {
    stdout.write(`${C.gray}# ${invokeHint('monitor --demo')}${C.reset}\n`);
    stdout.write(`${C.gray}# replay of a real-shape STACK mission · same row format as --follow on your own audit_log${C.reset}\n\n`);
    for (const ev of DEMO) {
      await sleep(ev.delayMs);
      const level = ev.forceLevel ?? deriveLevel(ev);
      stdout.write(formatRow(ev, level) + '\n');
    }
    if (loop) {
      stdout.write(`\n${C.gray}# loop reset${C.reset}\n\n`);
      await sleep(1500);
    }
  } while (loop);
}

// ── Real follow mode ─────────────────────────────────────────────────
//
// Polls /v1/audit every second with the operator's API key. Same
// formatRow renderer as --demo, so the visual output is identical
// modulo the data being yours.

// Public sandbox events come in two shapes: 'audit' (ran) and
// 'security_event' (was flagged by a detector). Older deploys (and
// /v1/audit for non-sandbox callers) only return audit rows without
// the entry_type discriminator — treat absent entry_type as 'audit'.
interface AuditEntry {
  entry_id: string;
  trace_id?: string;
  timestamp: number;
  agent_id?: string;
  entry_type?: 'audit' | 'security_event';
  // Audit fields
  layer?: string;
  action?: string;
  outcome?: string;
  duration_ms?: number | null;
  error_code?: string | null;
  error_message?: string | null;
  // Security event fields
  signal_type?: string;
  severity?: string;
  message?: string;
}

async function authToken(): Promise<string> {
  // Three sources, in priority order:
  //   1. STACK_API_KEY env var (legacy sk_live_* path, preserved for CI)
  //   2. ~/.stack/credentials.json refresh_token → exchange for access
  //   3. Nothing — point user at `auth login`
  const token = await getAccessToken();
  if (token) return token;
  stderr.write(
    `${C.red}error:${C.reset} not signed in.\n` +
    `Run ${C.cyan}${invokeHint('auth login')}${C.reset}.\n`,
  );
  process.exit(2);
}

/**
 * Map an audit row (wire layer + action) to its display layer.
 * Mirrors the dashboard landing-page mapping so the CLI and the website
 * terminal show the same layer column for the same audit row.
 */
function displayLayerForAction(wireLayer: Layer, action: string | undefined): Layer {
  if (!action) return wireLayer;
  if (action.startsWith('passport.')) return 'passport';
  if (action === 'credential.proxy') return 'proxy';
  if (action.startsWith('credential.')) return 'credential';
  if (action.startsWith('dropoff.')) return 'dropoff';
  if (action.startsWith('skill.') || action.startsWith('invocation.')) return 'skills';
  if (action.startsWith('identity.')) return 'identity';
  if (action.startsWith('detector.')) return 'detector';
  if (action.startsWith('agent.') || action.startsWith('service.') || action.startsWith('member.') || action.startsWith('oauth_app.')) return 'system';
  if (action.startsWith('billing.') || action.startsWith('payout.')) return 'billing';
  return wireLayer;
}

function normalizeAuditEntry(e: AuditEntry): AuditRow {
  if (e.entry_type === 'security_event') {
    // Detector fire — synthesize an AuditRow with layer='detector' so
    // the existing renderer paints it red and distinct from audit rows.
    // signal_type takes the action column; severity takes the outcome
    // column; the message goes into error_message; duration is omitted.
    const sev = e.severity ?? 'critical';
    const outcome: Outcome = sev === 'critical' || sev === 'warning' || sev === 'info'
      ? sev
      : 'critical';
    return {
      layer: 'detector',
      action: e.signal_type ?? 'unknown',
      outcome,
      duration_ms: null,
      error_message: e.message ?? null,
      timestamp_ms: typeof e.timestamp === 'number' ? e.timestamp : null,
    };
  }
  const wireLayer = (['vault', 'dropoff', 'skills', 'hire', 'system', 'billing'] as Layer[]).includes(e.layer as Layer)
    ? (e.layer as Layer)
    : 'system';
  const layer = displayLayerForAction(wireLayer, e.action);
  const outcome: Outcome = e.outcome === 'success' ? 'success'
    : e.outcome === 'blocked' ? 'blocked'
    : e.outcome === 'pending' ? 'pending'
    : 'failure';
  return {
    layer,
    action: e.action ?? '',
    outcome,
    duration_ms: e.duration_ms ?? null,
    error_message: e.error_message ?? (e.error_code ? e.error_code : null),
    timestamp_ms: typeof e.timestamp === 'number' ? e.timestamp : null,
  };
}

async function runFollow(filters: {
  agentId?: string;
  jti?: string;
  sandbox?: boolean;
  challenge?: boolean;
}): Promise<void> {
  // --sandbox and --challenge tail public feeds at /v1/public/events. No API
  // key needed; same shape as /v1/audit. --sandbox is the demo tenant;
  // --challenge is the real email agent at agent@getstack.run - the same
  // stream the board on getstack.run/attack renders.
  const sandbox = filters.sandbox === true;
  const challenge = filters.challenge === true;
  const isPublic = sandbox || challenge;
  const key = isPublic ? null : await authToken();
  let watermark: number | null = null;
  let firstTick = true;

  const filterDesc = challenge ? ' · agent@getstack.run'
    : sandbox ? ' · public sandbox'
    : filters.agentId ? ` · agent=${filters.agentId}`
    : filters.jti     ? ` · jti=${filters.jti}`
    : '';
  const endpoint = isPublic ? '/v1/public/events' : '/v1/audit';
  const verb = challenge ? '--challenge' : sandbox ? '--sandbox' : '--follow';
  stdout.write(`${C.gray}# ${invokeHint(`monitor ${verb}`)}${filterDesc}${C.reset}\n`);
  stdout.write(`${C.gray}# tailing ${API_URL}${endpoint} · poll 1s · Ctrl-C to stop${C.reset}\n\n`);

  while (true) {
    try {
      const params = new URLSearchParams({ limit: '20' });
      if (watermark != null) params.set('since', String(watermark));
      if (challenge) params.set('feed', 'challenge');
      if (!isPublic && filters.agentId) params.set('agent_id', filters.agentId);
      if (!isPublic && filters.jti)     params.set('passport_jti', filters.jti);
      const headers: Record<string, string> = { Accept: 'application/json' };
      if (key) headers.Authorization = `Bearer ${key}`;
      const res = await fetch(`${API_URL}${endpoint}?${params.toString()}`, { headers });
      if (!res.ok) {
        if (firstTick) {
          stderr.write(`${C.red}error:${C.reset} audit endpoint returned ${res.status}\n`);
          process.exit(1);
        }
      } else {
        const data = (await res.json()) as { entries?: AuditEntry[] };
        const entries = data.entries ?? [];
        const fresh = entries
          .filter((e) => watermark == null ? true : Number(e.timestamp) > watermark)
          .sort((a, b) => Number(a.timestamp) - Number(b.timestamp));
        // Stagger output so a batch of N rows feels like a stream
        // rather than a stdout flush. 90ms per row keeps the CLI
        // responsive while making each row land visibly.
        for (const e of fresh) {
          stdout.write(formatRow(normalizeAuditEntry(e)) + '\n');
          if (watermark == null || Number(e.timestamp) > watermark) {
            watermark = Number(e.timestamp);
          }
          if (fresh.length > 1) await sleep(90);
        }
        firstTick = false;
      }
    } catch (err) {
      if (firstTick) {
        stderr.write(`${C.red}error:${C.reset} ${(err as Error).message}\n`);
        process.exit(1);
      }
    }
    await sleep(1000);
  }
}

// ── Help ────────────────────────────────────────────────────────────

function printHelp(): void {
  stdout.write(renderHelp(C, API_URL));
}

async function main(): Promise<void> {
  // The one global flag that changes what a command sends: the retry of an action the owner approved.
  takeControlRefFlag(argv);
  const command = argv[2];

  if (command === 'setup') {
    await cmdSetup(argv.slice(3));
    return;
  }

  if (command === 'auth') {
    const sub = argv[3];
    if (sub === 'login')   { await cmdLogin();  return; }
    if (sub === 'logout')  { await cmdLogout(); return; }
    if (sub === 'status')  { await cmdStatus(); return; }
    stderr.write(`error: unknown auth subcommand "${sub ?? ''}". Use login | logout | status.\n`);
    process.exit(2);
  }

  if (command === 'agent' || command === 'agents') {
    await cmdAgent(argv.slice(3));
    return;
  }
  if (command === 'passport' || command === 'passports') {
    await cmdPassport(argv.slice(3));
    return;
  }
  if (command === 'intent' || command === 'intents') {
    await cmdIntents(argv.slice(3));
    return;
  }
  if (command === 'mission' || command === 'missions') {
    await cmdMissions(argv.slice(3));
    return;
  }
  if (command === 'fleet' || command === 'fleets') {
    await cmdFleets(argv.slice(3));
    return;
  }
  if (command === 'account' || command === 'accounts') {
    await cmdAccounts(argv.slice(3));
    return;
  }
  if (command === 'catalogue') {
    await cmdCatalogue(argv.slice(3));
    return;
  }
  if (command === 'chat') {
    await cmdChat(argv.slice(3));
    return;
  }
  if (command === 'drive') {
    await cmdDrive(argv.slice(3));
    return;
  }
  if (command === 'memory') {
    await cmdMemory(argv.slice(3));
    return;
  }
  if (command === 'brain') {
    await cmdBrain(argv.slice(3));
    return;
  }
  if (command === 'post') {
    await cmdPost(argv.slice(3));
    return;
  }
  if (command === 'control-socket') {
    await cmdControlSocket(argv.slice(3));
    return;
  }
  if (command === 'network') {
    await cmdNetwork(argv.slice(3));
    return;
  }
  if (command === 'agent-identity') {
    await cmdAgentIdentity(argv.slice(3));
    return;
  }
  if (command === 'policies' || command === 'policy') {
    await cmdPolicies(argv.slice(3));
    return;
  }
  if (command === 'reviews' || command === 'review') {
    await cmdReviews(argv.slice(3));
    return;
  }
  if (command === 'wake' || command === 'wakes') {
    await cmdWake(argv.slice(3));
    return;
  }
  if (command === 'calendar' || command === 'cal') {
    await cmdCalendar(argv.slice(3));
    return;
  }
  if (command === 'meeting' || command === 'meetings') {
    await cmdMeeting(argv.slice(3));
    return;
  }
  if (command === 'authority') {
    await cmdAuthority(argv.slice(3));
    return;
  }
  if (command === 'evidence-pack' || command === 'evidence-packs') {
    await cmdEvidencePack(argv.slice(3));
    return;
  }
  if (command === 'llm') {
    await cmdLlm(argv.slice(3));
    return;
  }
  if (command === 'inbound-webhook' || command === 'inbound-webhooks') {
    await cmdInboundWebhook(argv.slice(3));
    return;
  }
  if (command === 'partner') {
    await cmdPartner(argv.slice(3));
    return;
  }
  if (command === 'proxy') {
    await cmdProxy(argv.slice(3));
    return;
  }
  if (command === 'quickstart' || command === 'init') {
    await cmdQuickstart(argv.slice(3));
    return;
  }
  if (command === 'pay') {
    await cmdPay(argv.slice(3));
    return;
  }
  if (command === 'rentahuman') {
    await cmdRentAHuman(argv.slice(3));
    return;
  }
  if (command === 'service' || command === 'services') {
    await cmdService(argv.slice(3));
    return;
  }
  if (command === 'dropoff' || command === 'dropoffs') {
    await cmdDropoff(argv.slice(3));
    return;
  }
  if (command === 'skill' || command === 'skills') {
    await cmdSkill(argv.slice(3));
    return;
  }
  if (command === 'identity') {
    await cmdIdentity(argv.slice(3));
    return;
  }
  if (command === 'audit') {
    await cmdAudit(argv.slice(3));
    return;
  }
  if (command === 'event' || command === 'events' || command === 'security-event' || command === 'security-events') {
    await cmdEvent(argv.slice(3));
    return;
  }
  if (command === 'team' || command === 'members' || command === 'member') {
    await cmdTeam(argv.slice(3));
    return;
  }
  if (command === 'me' || command === 'whoami') {
    await cmdMe(argv.slice(3));
    return;
  }
  if (command === 'notifications' || command === 'notification' || command === 'notify') {
    await cmdNotifications(argv.slice(3));
    return;
  }
  if (command === 'pii') {
    await cmdPii(argv.slice(3));
    return;
  }

  if (command === 'detector' || command === 'detectors') {
    await cmdDetector(argv.slice(3));
    return;
  }
  if (command === 'scan') {
    await cmdScan(argv.slice(3));
    return;
  }
  if (command === 'usage') {
    await cmdUsage(argv.slice(3));
    return;
  }
  if (command === 'billing') {
    await cmdBilling(argv.slice(3));
    return;
  }
  if (command === 'message-access') {
    await cmdMessageAccess(argv.slice(3));
    return;
  }
  if (command === 'messages') {
    await cmdMessages(argv.slice(3));
    return;
  }
  if (command === 'trust') {
    await cmdTrust(argv.slice(3));
    return;
  }
  if (command === 'flagged-content') {
    await cmdFlaggedContent(argv.slice(3));
    return;
  }
  if (command === 'approval' || command === 'approvals') {
    await cmdApproval(argv.slice(3));
    return;
  }

  if (command === 'register') {
    stdout.write(`
  STACK — Infrastructure for agents
  ─────────────────────────────────

  Get started at: ${DASHBOARD_URL}/get-started

  1. Start the 14-day trial at Stripe (card required), then sign in with the
     same email (magic link, no password)
  2. Add STACK to your installed MCP clients:
     ${C.cyan}${invokeHint('setup')}${C.reset}

`);
    return;
  }

  if (command === 'monitor') {
    const args = argv.slice(3);
    function valueFlag(name: string): string | undefined {
      const idx = args.indexOf(name);
      if (idx === -1 || idx === args.length - 1) return undefined;
      const next = args[idx + 1];
      if (!next || next.startsWith('--')) return undefined;
      return next;
    }
    const isDemo = args.includes('--demo');
    const isFollow = args.includes('--follow');
    const isLoop = args.includes('--loop');
    const isSandbox = args.includes('--sandbox');
    const isChallenge = args.includes('--challenge');
    const agentId = valueFlag('--agent');
    const jti = valueFlag('--jti');
    if (isDemo && isFollow) {
      stderr.write('error: --demo and --follow are mutually exclusive\n');
      process.exit(2);
    }
    if (isDemo && isSandbox) {
      stderr.write('error: --demo and --sandbox are mutually exclusive\n');
      process.exit(2);
    }
    if (agentId && jti) {
      stderr.write('error: --agent and --jti are mutually exclusive\n');
      process.exit(2);
    }
    if (isChallenge && isSandbox) {
      stderr.write('error: --challenge and --sandbox are mutually exclusive\n');
      process.exit(2);
    }
    if (isChallenge && isDemo) {
      stderr.write('error: --demo and --challenge are mutually exclusive\n');
      process.exit(2);
    }
    if (isChallenge && (agentId || jti)) {
      stderr.write('error: --challenge cannot be combined with --agent or --jti\n');
      process.exit(2);
    }
    if (isSandbox && (agentId || jti)) {
      stderr.write('error: --sandbox cannot be combined with --agent or --jti\n');
      process.exit(2);
    }
    // --sandbox implies a live tail: `monitor --sandbox` tails the public
    // sandbox feed on its own (no --follow needed). Without this, a bare
    // --sandbox fell through to runDemo() and silently showed the scripted
    // demo instead of the live feed the help text promises.
    if (isFollow || isSandbox || isChallenge) {
      await runFollow({ agentId, jti, sandbox: isSandbox, challenge: isChallenge });
      return;
    }
    await runDemo(isLoop);
    return;
  }

  printHelp();
  process.exit(command ? 1 : 0);
}

main().catch((err) => {
  stderr.write(`${C.red}error:${C.reset} ${(err as Error).message}\n`);
  process.exit(1);
});
