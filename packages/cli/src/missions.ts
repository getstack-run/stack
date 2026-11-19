// missions subcommands — thin wrappers over /v1/missions/*.
//
// stack missions open      --intent-summary "..." [--agent <name-or-id>] [--services svc1,svc2] [--coverage-cap-cents N] [--max-actions N] [--max-duration-seconds N] [--max-concurrent-intents N] [--expires-in N]
// stack missions start     --agent <name-or-id> --intent-summary "..." [--services svc1,svc2] [--expires-in N] [--ttl N]
//                          (opens the Mission and issues its Passport in one call; same Mission flags as open)
//                          open and start also take who the Mission may send to:
//                          [--recipients a@x.com,b@x.com] [--pin body.to=a@x.com] (repeatable; a comma list means "in") [--reply-to <message-id>]
// stack missions add-recipients <mission-id> [--recipients a,b] [--pin path=value] [--reply-to <message-id>]
//                          (the owner adds who a running Mission may send to; nothing pinned is taken away)
// stack missions start     --file <path>   (fleet form: body carries fleet_policy_id)
// stack missions complete  <mission-id> [--output-json <path>]
// stack missions revoke    <mission-id> --reason adversarial|operator_initiated_clean [--notes "..."]
// stack missions get       <mission-id>
// stack missions list      [--status active|completed|revoked|paused] [--page N] [--limit N]
// stack missions review    <mission-id> --decision raise|continue|close [--limit N]
// stack missions making-allowance <mission-id> --cents N | --none
//

import { readFileSync } from 'node:fs';
import { stderr, exit } from 'node:process';
import { api, takeFlag, resolveAgentId } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printRecord, printTable, fmtTs } from './format.js';
import { readFleetRequest } from './fleets.js';

interface MissionRecord {
  mission_id: string;
  operator_id: string;
  claim_id: string;
  intent_summary: string;
  intent_services: string[];
  expected_counterparties: string[];
  max_actions: number | null;
  max_dropoff_bytes: number | null;
  coverage_cap_cents: number | null;
  max_duration_seconds: number | null;
  max_concurrent_intents: number | null;
  max_actions_per_service: Record<string, number>;
  cap_behavior: Record<string, string>;
  baseline_profile: Record<string, unknown> | null;
  expected_output_shape: Record<string, unknown> | null;
  started_at: string;
  expires_at: string;
  completed_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
  terminal_state: string | null;
  recipient_pins?: RecipientPin[] | null;
}

interface RecipientPin {
  path: string;
  op: 'eq' | 'in';
  value: string | number | string[];
}

function parseCsv(value: string | boolean | undefined): string[] | undefined {
  if (typeof value !== 'string') return undefined;
  return value.split(',').map((s) => s.trim()).filter(Boolean);
}

function parseIntFlag(value: string | boolean | undefined, name: string): number | undefined {
  if (typeof value !== 'string') return undefined;
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) {
    stderr.write(`error: --${name} must be an integer (got "${value}")\n`);
    exit(2);
  }
  return n;
}

function usageError(message: string, usage: string): never {
  stderr.write(`error: ${message}\nusage: ${invokeHint(usage)}\n`);
  exit(2);
}

/** `--pin path=value` (repeatable): one value is `eq`, a comma list is `in`. One pin per path. */
export function parsePins(raw: string[]): RecipientPin[] {
  const pins: RecipientPin[] = [];
  for (const entry of raw) {
    const at = entry.indexOf('=');
    const path = at === -1 ? '' : entry.slice(0, at).trim();
    const values = at === -1 ? [] : entry.slice(at + 1).split(',').map((s) => s.trim()).filter(Boolean);
    if (!path || values.length === 0) throw new Error(`--pin needs path=value (for example body.to=ana@example.com), got "${entry}"`);
    if (pins.some((pin) => pin.path === path)) throw new Error(`--pin names ${path} twice; give one pin per field (a comma list means "in")`);
    pins.push(values.length === 1 ? { path, op: 'eq', value: values[0]! } : { path, op: 'in', value: values });
  }
  return pins;
}

/** The recipient flags of open and start, only those given. */
function takeRecipientFlags(args: string[], usage: string): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  const recipients = takeFlag(args, '--recipients');
  if (recipients !== undefined) {
    const list = parseCsv(recipients);
    if (!list || list.length === 0) usageError('--recipients needs a comma-separated list of addresses, numbers or ids.', usage);
    fields['recipients'] = list;
  }
  const raw: string[] = [];
  for (let pin = takeFlag(args, '--pin'); pin !== undefined; pin = takeFlag(args, '--pin')) {
    if (typeof pin !== 'string') usageError('--pin needs path=value (for example body.to=ana@example.com).', usage);
    raw.push(pin);
  }
  if (raw.length > 0) {
    try {
      fields['recipient_pins'] = parsePins(raw);
    } catch (err) {
      usageError((err as Error).message, usage);
    }
  }
  const replyTo = takeFlag(args, '--reply-to');
  if (replyTo !== undefined) {
    if (typeof replyTo !== 'string') usageError('--reply-to needs the id of a message the agent received.', usage);
    fields['reply_to_message'] = replyTo;
  }
  return fields;
}

function describePin(pin: RecipientPin): string {
  return `${pin.path} ${pin.op === 'in' ? 'in' : '='} ${Array.isArray(pin.value) ? pin.value.join(', ') : String(pin.value)}`;
}

function statusOf(m: MissionRecord): string {
  if (m.revoked_at) return 'revoked';
  if (m.completed_at) return m.terminal_state ?? 'completed';
  return 'active';
}

// ─── Subcommands ────────────────────────────────────────────────────

const OPEN_USAGE = 'missions open --intent-summary "..." [--agent <name-or-id>] [--services svc1,svc2] [--counterparties a,b] [--coverage-cap-cents N] [--max-actions N] [--max-duration-seconds N] [--max-concurrent-intents N] [--max-dropoff-bytes N] [--expires-in N] [--recipients a,b] [--pin path=value] [--reply-to <message-id>] [--json]';
const ADD_RECIPIENTS_USAGE = 'missions add-recipients <mission-id> [--recipients a,b] [--pin path=value] [--reply-to <message-id>] [--json]';
const START_USAGE = 'missions start --agent <name-or-id> --intent-summary "..." [--services svc1,svc2] [--expires-in N] [--ttl N] [--max-actions N] [--recipients a,b] [--pin path=value] [--reply-to <message-id>] [--json]';

/**
 * Build the POST /v1/missions spec (without agent_id) from flags. Returns
 * undefined when --intent-summary is missing so each caller prints its
 * own usage line.
 */
function buildMissionSpec(args: string[], usage: string): Record<string, unknown> | undefined {
  const intentSummary = takeFlag(args, '--intent-summary');
  const servicesFlag = takeFlag(args, '--services');
  const counterpartiesFlag = takeFlag(args, '--counterparties');
  const coverageCapCents = parseIntFlag(takeFlag(args, '--coverage-cap-cents'), 'coverage-cap-cents');
  const maxActions = parseIntFlag(takeFlag(args, '--max-actions'), 'max-actions');
  const maxDropoffBytes = parseIntFlag(takeFlag(args, '--max-dropoff-bytes'), 'max-dropoff-bytes');
  const maxDurationSeconds = parseIntFlag(takeFlag(args, '--max-duration-seconds'), 'max-duration-seconds');
  const maxConcurrentIntents = parseIntFlag(takeFlag(args, '--max-concurrent-intents'), 'max-concurrent-intents');
  const expiresInSeconds = parseIntFlag(takeFlag(args, '--expires-in'), 'expires-in');
  const recipientFields = takeRecipientFlags(args, usage);

  if (typeof intentSummary !== 'string') return undefined;

  const body: Record<string, unknown> = { intent_summary: intentSummary };
  const services = parseCsv(servicesFlag);
  if (services && services.length > 0) body['intent_services'] = services;
  const counterparties = parseCsv(counterpartiesFlag);
  if (counterparties && counterparties.length > 0) body['expected_counterparties'] = counterparties;
  if (coverageCapCents !== undefined) body['coverage_cap_cents'] = coverageCapCents;
  if (maxActions !== undefined) body['max_actions'] = maxActions;
  if (maxDropoffBytes !== undefined) body['max_dropoff_bytes'] = maxDropoffBytes;
  if (maxDurationSeconds !== undefined) body['max_duration_seconds'] = maxDurationSeconds;
  if (maxConcurrentIntents !== undefined) body['max_concurrent_intents'] = maxConcurrentIntents;
  if (expiresInSeconds !== undefined) body['expires_in_seconds'] = expiresInSeconds;
  Object.assign(body, recipientFields);
  return body;
}

/** --agent accepts a name or an agt_* id; returns undefined when absent. */
async function takeAgentId(args: string[], usage: string): Promise<string | undefined> {
  const agent = takeFlag(args, '--agent');
  if (agent === undefined) return undefined;
  if (typeof agent !== 'string') {
    stderr.write(`error: --agent needs an agent name or agt_* id.\nusage: ${invokeHint(usage)}\n`);
    exit(2);
  }
  return resolveAgentId(agent);
}

async function cmdOpen(args: string[], json: boolean): Promise<void> {
  if (args.includes('--file')) return printJson(await api('POST', '/v1/missions', { body: readFleetRequest(args) }));
  const agentId = await takeAgentId(args, OPEN_USAGE);
  const spec = buildMissionSpec(args, OPEN_USAGE);
  if (!spec) {
    stderr.write(`usage: ${invokeHint(OPEN_USAGE)}\n`);
    exit(2);
  }
  const body: Record<string, unknown> = { ...spec, ...(agentId ? { agent_id: agentId } : {}) };

  const result = await api<{ mission_id: string; claim_id: string; expires_at: string }>(
    'POST', '/v1/missions', { body },
  );
  if (json) return printJson(result);
  printRecord({
    mission_id: result.mission_id,
    claim_id: result.claim_id,
    expires_at: fmtTs(result.expires_at),
  });
}

/**
 * Operator form of POST /v1/missions/start: open a Mission for one agent
 * and issue its Passport in one call. The Passport's intent defaults to
 * the Mission's summary and services on the API side.
 */
async function cmdStartForAgent(args: string[], json: boolean): Promise<void> {
  if (args.includes('--file')) {
    stderr.write(`error: --file starts a fleet Mission and cannot be combined with --agent.\nusage: ${invokeHint(START_USAGE)}\n`);
    exit(2);
  }
  const agentId = await takeAgentId(args, START_USAGE);
  const ttl = parseIntFlag(takeFlag(args, '--ttl'), 'ttl');
  const mission = buildMissionSpec(args, START_USAGE);
  if (!agentId || !mission) {
    stderr.write(`usage: ${invokeHint(START_USAGE)}\n`);
    exit(2);
  }
  const body: Record<string, unknown> = { agent_id: agentId, mission };
  if (ttl !== undefined) body['passport'] = { ttl_seconds: ttl };
  const result = await api<{
    mission_id: string;
    claim_id: string;
    expires_at: string;
    passport: { token: string; jti: string; expires_at: string };
  }>('POST', '/v1/missions/start', { body });
  if (json) return printJson(result);
  printRecord({
    mission_id: result.mission_id,
    claim_id: result.claim_id,
    expires_at: fmtTs(result.expires_at),
    passport_jti: result.passport.jti,
    passport_expires_at: fmtTs(result.passport.expires_at),
    token: result.passport.token,
  });
}

async function cmdComplete(missionId: string, args: string[], json: boolean): Promise<void> {
  const outputPath = takeFlag(args, '--output-json');
  const body: Record<string, unknown> = {};
  if (typeof outputPath === 'string') {
    try {
      body['output'] = JSON.parse(readFileSync(outputPath, 'utf-8')) as Record<string, unknown>;
    } catch (err) {
      stderr.write(`failed to parse output JSON from ${outputPath}: ${(err as Error).message}\n`);
      exit(2);
    }
  }
  const result = await api<{
    mission_id: string;
    claim_id: string;
    terminal_state: string;
    completed_at: string;
    transitioned: boolean;
  }>('POST', `/v1/missions/${encodeURIComponent(missionId)}/complete`, { body });
  if (json) return printJson(result);
  printRecord({
    mission_id: result.mission_id,
    terminal_state: result.terminal_state,
    completed_at: fmtTs(result.completed_at),
    transitioned: result.transitioned,
    claim_id: result.claim_id,
  });
}

async function cmdRevoke(missionId: string, args: string[], json: boolean): Promise<void> {
  const reason = takeFlag(args, '--reason');
  const notes = takeFlag(args, '--notes');
  if (typeof reason !== 'string' || (reason !== 'adversarial' && reason !== 'operator_initiated_clean')) {
    stderr.write(
      `usage: ${invokeHint('missions revoke <mission-id> --reason adversarial|operator_initiated_clean [--notes "..."]')}\n`,
    );
    exit(2);
  }
  const body: Record<string, unknown> = { reason };
  if (typeof notes === 'string') body['notes'] = notes;
  const result = await api<{
    mission_id: string;
    claim_id: string;
    terminal_state: string;
    revoked_at: string;
    revoke_reason: string;
    transitioned: boolean;
  }>('POST', `/v1/missions/${encodeURIComponent(missionId)}/revoke`, { body });
  if (json) return printJson(result);
  printRecord({
    mission_id: result.mission_id,
    terminal_state: result.terminal_state,
    revoke_reason: result.revoke_reason,
    revoked_at: fmtTs(result.revoked_at),
    transitioned: result.transitioned,
    claim_id: result.claim_id,
  });
}

async function cmdGet(missionId: string, json: boolean): Promise<void> {
  const m = await api<MissionRecord>('GET', `/v1/missions/${encodeURIComponent(missionId)}`);
  if (json) return printJson(m);
  printRecord({
    mission_id: m.mission_id,
    intent_summary: m.intent_summary,
    status: statusOf(m),
    intent_services: m.intent_services.join(', ') || '(none)',
    counterparties: m.expected_counterparties.join(', ') || '(none)',
    coverage_cap_cents: m.coverage_cap_cents ?? '(none)',
    max_actions: m.max_actions ?? '(none)',
    max_duration_seconds: m.max_duration_seconds ?? '(none)',
    started_at: fmtTs(m.started_at),
    expires_at: fmtTs(m.expires_at),
    completed_at: m.completed_at ? fmtTs(m.completed_at) : '(active)',
    revoked_at: m.revoked_at ? fmtTs(m.revoked_at) : '(not revoked)',
    terminal_state: m.terminal_state ?? '(active)',
    recipients: m.recipient_pins?.length ? m.recipient_pins.map(describePin).join('; ') : '(none pinned)',
    claim_id: m.claim_id,
  });
}

async function cmdList(args: string[], json: boolean): Promise<void> {
  const status = takeFlag(args, '--status');
  const page = parseIntFlag(takeFlag(args, '--page'), 'page');
  const limit = parseIntFlag(takeFlag(args, '--limit'), 'limit');
  const params = new URLSearchParams();
  if (typeof status === 'string') params.set('status', status);
  if (page !== undefined) params.set('page', String(page));
  if (limit !== undefined) params.set('limit', String(limit));
  const suffix = params.toString();
  const { items } = await api<{ items: MissionRecord[] }>(
    'GET', `/v1/missions${suffix ? `?${suffix}` : ''}`,
  );
  if (json) return printJson(items);
  if (items.length === 0) {
    process.stdout.write('No missions.\n');
    return;
  }
  printTable(
    ['mission_id', 'status', 'intent', 'services', 'coverage_cents', 'started'],
    items.map((m) => [
      m.mission_id,
      statusOf(m),
      m.intent_summary.slice(0, 50),
      m.intent_services.slice(0, 3).join(',') + (m.intent_services.length > 3 ? '+' : ''),
      String(m.coverage_cap_cents ?? '-'),
      fmtTs(m.started_at),
    ]),
  );
}

// ─── replay + dossier subcommands ──────────────────────

async function cmdReplay(missionId: string, json: boolean): Promise<void> {
  const result = await api<Record<string, unknown>>(
    'GET',
    `/v1/missions/${encodeURIComponent(missionId)}/replay`,
  );
  if (json) {
    printJson(result);
    return;
  }
  printJson(result); // human-friendly replay rendering is dashboard territory; CLI emits JSON regardless.
}

async function cmdListDossiers(missionId: string, json: boolean): Promise<void> {
  const result = await api<{ items: Array<Record<string, unknown>> }>(
    'GET',
    `/v1/missions/${encodeURIComponent(missionId)}/dossiers`,
  );
  if (json) {
    printJson(result);
    return;
  }
  if (result.items.length === 0) {
    process.stdout.write('No dossiers for this mission.\n');
    return;
  }
  printJson(result);
}

async function cmdCreateDossier(missionId: string, args: string[], json: boolean): Promise<void> {
  const narrative = takeFlag(args, '--narrative');
  const lessons = takeFlag(args, '--lessons') ?? '';
  const classification = takeFlag(args, '--classification') ?? 'inconclusive';
  if (typeof narrative !== 'string' || narrative.length === 0) {
    stderr.write(
      `usage: ${invokeHint('missions dossier <mission-id> --narrative "..." [--lessons "..."] [--classification false_positive|true_positive_handled|true_positive_escalated|inconclusive]')}\n`,
    );
    exit(2);
  }
  const body = {
    narrative,
    lessons_learned: typeof lessons === 'string' ? lessons : '',
    incident_classification: typeof classification === 'string' ? classification : 'inconclusive',
  };
  const result = await api<Record<string, unknown>>(
    'POST',
    `/v1/missions/${encodeURIComponent(missionId)}/dossier`,
    { body },
  );
  if (json) {
    printJson(result);
    return;
  }
  printJson(result);
}

// ─── A paused Mission and the making allowance ──────────────────────

const REVIEW_USAGE = 'missions review <mission-id> --decision raise|continue|close [--limit N]';
const ALLOWANCE_USAGE = 'missions making-allowance <mission-id> --cents N | --none';

/** The owner's decision on a Mission a cap paused: raise its limit, let it go on as it is, or close it. */
async function cmdReview(missionId: string, args: string[], json: boolean): Promise<void> {
  const decision = takeFlag(args, '--decision');
  const limit = parseIntFlag(takeFlag(args, '--limit'), 'limit');
  if (decision !== 'raise' && decision !== 'continue' && decision !== 'close') {
    stderr.write(`usage: ${invokeHint(REVIEW_USAGE)}\n`);
    exit(2);
  }
  if ((decision === 'raise') !== (limit !== undefined)) {
    stderr.write(`error: raise needs --limit, and only raise takes one\nusage: ${invokeHint(REVIEW_USAGE)}\n`);
    exit(2);
  }
  const result = await api<{ mission_id: string; decision: string; result: string }>(
    'POST', `/v1/missions/${encodeURIComponent(missionId)}/review`,
    { body: { decision, ...(limit !== undefined ? { limit } : {}) } },
  );
  if (json) return printJson(result);
  printRecord({ mission_id: result.mission_id, decision: result.decision, agent_told: result.result });
}

/** What the owner pre-approves of a running Mission's print-on-demand orders, in cents across all of them. */
async function cmdMakingAllowance(missionId: string, args: string[], json: boolean): Promise<void> {
  const none = takeFlag(args, '--none') === true;
  const cents = parseIntFlag(takeFlag(args, '--cents'), 'cents');
  if (none === (cents !== undefined)) {
    stderr.write(`usage: ${invokeHint(ALLOWANCE_USAGE)}\n`);
    exit(2);
  }
  const result = await api<{ mission_id: string; making_orders_up_to_cents: number | null }>(
    'PUT', `/v1/missions/${encodeURIComponent(missionId)}/making-allowance`,
    { body: { making_orders_up_to_cents: none ? null : cents } },
  );
  if (json) return printJson(result);
  printRecord({ mission_id: result.mission_id, making_orders_up_to_cents: result.making_orders_up_to_cents ?? 'none' });
}

// ─── Dispatch ───────────────────────────────────────────────────────

export async function cmdMissions(argv: string[]): Promise<void> {
  const args = [...argv];
  const json = takeFlag(args, '--json') === true;
  const sub = args.shift();
  const arg1 = args[0];

  if (sub === 'start') {
    if (args.includes('--agent')) return cmdStartForAgent(args, json);
    return printJson(await api('POST', '/v1/missions/start', { body: readFleetRequest(args) }));
  }
  if (sub === 'renew') {
    if (!arg1) throw new Error('Invalid input');
    return printJson(await api('POST', `/v1/missions/${encodeURIComponent(arg1)}/renew`, { body: {} }));
  }

  if (sub === 'open') {
    return cmdOpen(args, json);
  }
  if (sub === 'add-recipients') {
    if (!arg1 || arg1.startsWith('--')) usageError('Name the Mission.', ADD_RECIPIENTS_USAGE);
    const rest = args.slice(1);
    const fields = takeRecipientFlags(rest, ADD_RECIPIENTS_USAGE);
    if (Object.keys(fields).length === 0) usageError('Name --recipients, --pin or --reply-to.', ADD_RECIPIENTS_USAGE);
    const out = await api('POST', `/v1/missions/${encodeURIComponent(arg1)}/recipients`, { body: fields });
    if (json) return printJson(out);
    return printRecord(out as Record<string, unknown>);
  }
  if (sub === 'complete') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('missions complete <mission-id> [--output-json <path>]')}\n`);
      exit(2);
    }
    return cmdComplete(arg1, args.slice(1), json);
  }
  if (sub === 'revoke') {
    if (!arg1) {
      stderr.write(
        `usage: ${invokeHint('missions revoke <mission-id> --reason adversarial|operator_initiated_clean [--notes "..."]')}\n`,
      );
      exit(2);
    }
    return cmdRevoke(arg1, args.slice(1), json);
  }
  if (sub === 'get' || sub === 'show') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('missions get <mission-id>')}\n`);
      exit(2);
    }
    return cmdGet(arg1, json);
  }
  if (sub === 'list') {
    return cmdList(args, json);
  }
  if (sub === 'replay') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('missions replay <mission-id>')}\n`);
      exit(2);
    }
    return cmdReplay(arg1, json);
  }
  if (sub === 'review') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint(REVIEW_USAGE)}\n`);
      exit(2);
    }
    return cmdReview(arg1, args.slice(1), json);
  }
  if (sub === 'making-allowance') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint(ALLOWANCE_USAGE)}\n`);
      exit(2);
    }
    return cmdMakingAllowance(arg1, args.slice(1), json);
  }
  if (sub === 'dossiers') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('missions dossiers <mission-id>')}\n`);
      exit(2);
    }
    return cmdListDossiers(arg1, json);
  }
  if (sub === 'dossier') {
    if (!arg1) {
      stderr.write(
        `usage: ${invokeHint('missions dossier <mission-id> --narrative "..." [--lessons "..."] [--classification ...]')}\n`,
      );
      exit(2);
    }
    return cmdCreateDossier(arg1, args.slice(1), json);
  }

  stderr.write(
    `error: unknown missions subcommand "${sub ?? ''}".\n` +
      `Use open | start | renew | add-recipients | complete | revoke | get | list | review | making-allowance | replay | dossiers | dossier
`,
  );
  exit(2);
}
