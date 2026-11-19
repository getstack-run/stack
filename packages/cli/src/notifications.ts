// notifications subcommands — delivery methods + routing rules.
//
// Endpoint shapes (see apps/api/src/routes/accountability.ts +
// packages/shared/src/schemas/passport.ts NotificationChannelInput etc):
//   - Delivery methods live under /v1/notifications/destinations
//     (not /delivery-methods — that path 404s).
//     POST body: { channel_type: 'email' | 'sms' | 'webhook', destination }
//   - Routing rules live under /v1/notifications/channels.
//     POST body: { destination_id | destination_ids, events: string[],
//                  min_severity?: 'info'|'warning'|'critical' }
//     PATCH body: { destination_ids?, events?, min_severity? }

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt, fmtTs } from './format.js';

interface DeliveryMethod {
  id: string;
  channel_type: string;
  destination: string;
  verified?: boolean;
  created_at?: string;
}

interface NotificationRule {
  id: string;
  destination_id?: string;
  destination_ids?: string[];
  channel_type?: string;
  destination?: string;
  events?: string[];
  min_severity?: string;
  active?: boolean;
  /** Active AND a verified delivery method it would send to: the API's one answer to whether the rule is On. */
  delivers?: boolean;
  delivery_methods?: DeliveryMethod[];
}

/**
 * How a rule is shown: on only when the API says it delivers. An answer without `delivers` (an API from before it) is read
 * as it always was, by `active`.
 */
export function ruleState(r: NotificationRule): string {
  if (typeof r.delivers === 'boolean') {
    if (r.delivers) return fmt.ok('on');
    if (r.active !== false && (r.delivery_methods ?? []).some((m) => m.verified !== true)) return fmt.warn('unverified');
    return fmt.dim('off');
  }
  return r.active === false ? fmt.dim('off') : fmt.ok('on');
}

// ── Delivery methods ──────────────────────────────────────────────

async function cmdMethodsList(json: boolean): Promise<void> {
  const out = await api<DeliveryMethod[] | { destinations?: DeliveryMethod[] }>(
    'GET', '/v1/notifications/destinations',
  );
  const list = Array.isArray(out) ? out : (out?.destinations ?? []);
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no delivery methods)\n');
    return;
  }
  const rows = list.map((m) => [
    m.id,
    m.channel_type,
    m.destination,
    m.verified ? fmt.ok('yes') : fmt.warn('no'),
    fmtTs(m.created_at ?? null),
  ]);
  printTable(['ID', 'KIND', 'DESTINATION', 'VERIFIED', 'CREATED'], rows);
}

async function cmdMethodsAdd(args: string[], json: boolean): Promise<void> {
  const kind = takeFlag(args, '--kind');
  const destination = takeFlag(args, '--destination');
  if (typeof kind !== 'string' || typeof destination !== 'string') {
    stderr.write(
      `usage: ${invokeHint('notifications methods add --kind email|sms|webhook --destination <addr>')}\n`,
    );
    exit(2);
  }
  // AddDeliveryMethodInput uses channel_type, not kind. Keep --kind as
  // the CLI flag (operator-friendly) but map to channel_type on the wire.
  const out = await api('POST', '/v1/notifications/destinations', {
    body: { channel_type: kind, destination },
  });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdMethodsTest(id: string, json: boolean): Promise<void> {
  const out = await api('POST', `/v1/notifications/destinations/${encodeURIComponent(id)}/test`);
  if (json) return printJson(out);
  stdout.write(`test sent to ${id}\n`);
}

async function cmdMethodsSendCode(id: string, json: boolean): Promise<void> {
  const out = await api('POST', `/v1/notifications/destinations/${encodeURIComponent(id)}/send-code`);
  if (json) return printJson(out);
  stdout.write(`verification code sent for ${id}\n`);
}

async function cmdMethodsVerify(args: string[], json: boolean): Promise<void> {
  const id = args[0];
  const code = takeFlag(args, '--code');
  if (!id || typeof code !== 'string') {
    stderr.write(`usage: ${invokeHint('notifications methods verify <id> --code <verification-code>')}\n`);
    exit(2);
  }
  const out = await api('POST', `/v1/notifications/destinations/${encodeURIComponent(id)}/verify`, {
    body: { code },
  });
  if (json) return printJson(out);
  stdout.write(`verified ${id}\n`);
}

async function cmdMethodsDelete(id: string, json: boolean): Promise<void> {
  const out = await api('DELETE', `/v1/notifications/destinations/${encodeURIComponent(id)}`);
  if (json) return printJson(out);
  stdout.write(`deleted ${id}\n`);
}

// ── Notification rules ───────────────────────────────────────────

async function cmdRulesList(json: boolean): Promise<void> {
  // The endpoint enriches each channel with a `delivery_methods` array;
  // top-level shape is plain array. Accept the legacy envelope shapes
  // defensively in case a future enrichment wraps it.
  const out = await api<NotificationRule[] | { rules?: NotificationRule[] } | { channels?: NotificationRule[] }>('GET', '/v1/notifications/channels');
  const list = Array.isArray(out) ? out : ((out as { rules?: NotificationRule[]; channels?: NotificationRule[] }).rules ?? (out as { channels?: NotificationRule[] }).channels ?? []);
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no notification rules)\n');
    return;
  }
  const rows = list.map((r) => {
    const dests = r.destination_ids?.length
      ? `${r.destination_ids.length} method${r.destination_ids.length === 1 ? '' : 's'}`
      : (r.destination_id ?? r.destination ?? '—');
    return [
      r.id,
      dests,
      (r.events ?? []).join(',') || 'all',
      r.min_severity ?? 'warning',
      ruleState(r),
    ];
  });
  printTable(['ID', 'METHOD(S)', 'EVENTS', 'MIN_SEVERITY', 'STATE'], rows);
}

async function cmdRulesCreate(args: string[], json: boolean): Promise<void> {
  // --method maps to destination_id (single delivery method id).
  // --methods (comma-separated) maps to destination_ids (multi).
  // --events is required (array). Common event names:
  //   passport.flagged, passport.blocked, agent.blocked,
  //   passport.missed_checkout
  // --min-severity defaults to 'warning' on the server side.
  const methodId = takeFlag(args, '--method');
  const methodsRaw = takeFlag(args, '--methods');
  const eventsRaw = takeFlag(args, '--events');
  const minSeverity = takeFlag(args, '--min-severity');
  const events = typeof eventsRaw === 'string'
    ? eventsRaw.split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;
  const haveMethod = typeof methodId === 'string' || typeof methodsRaw === 'string';
  if (!haveMethod || !events || events.length === 0) {
    stderr.write(
      `usage: ${invokeHint('notifications rules create (--method <id> | --methods <id1,id2>) --events <event1,event2> [--min-severity info|warning|critical]')}\n`
      + `events: passport.flagged | passport.blocked | agent.blocked | passport.missed_checkout\n`,
    );
    exit(2);
  }
  const body: Record<string, unknown> = { events };
  if (typeof methodsRaw === 'string') {
    body.destination_ids = methodsRaw.split(',').map((s) => s.trim()).filter(Boolean);
  } else if (typeof methodId === 'string') {
    body.destination_id = methodId;
  }
  if (typeof minSeverity === 'string') body.min_severity = minSeverity;
  const out = await api('POST', '/v1/notifications/channels', { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdRulesUpdate(id: string, args: string[], json: boolean): Promise<void> {
  const eventsRaw = takeFlag(args, '--events');
  const minSeverity = takeFlag(args, '--min-severity');
  const methodsRaw = takeFlag(args, '--methods');
  const body: Record<string, unknown> = {};
  if (typeof eventsRaw === 'string') {
    body.events = eventsRaw.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (typeof minSeverity === 'string') body.min_severity = minSeverity;
  if (typeof methodsRaw === 'string') {
    body.destination_ids = methodsRaw.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (Object.keys(body).length === 0) {
    stderr.write(
      `usage: ${invokeHint('notifications rules update <id> [--events e1,e2] [--min-severity info|warning|critical] [--methods id1,id2]')}\n`,
    );
    exit(2);
  }
  const out = await api('PATCH', `/v1/notifications/channels/${encodeURIComponent(id)}`, { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdRulesDelete(id: string, json: boolean): Promise<void> {
  const out = await api('DELETE', `/v1/notifications/channels/${encodeURIComponent(id)}`);
  if (json) return printJson(out);
  stdout.write(`deleted ${id}\n`);
}

// ── Dispatcher ───────────────────────────────────────────────────

export async function cmdNotifications(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const sub2 = args[1];
  const arg2 = args[2];

  if (sub === 'methods' || sub === 'method' || sub === 'delivery-methods') {
    if (sub2 === 'list' || sub2 === 'ls' || sub2 === undefined) return cmdMethodsList(json);
    if (sub2 === 'add' || sub2 === 'create') return cmdMethodsAdd(args.slice(2), json);
    if (sub2 === 'test') {
      if (!arg2) { stderr.write(`usage: ${invokeHint('notifications methods test <id>')}\n`); exit(2); }
      return cmdMethodsTest(arg2, json);
    }
    if (sub2 === 'send-code') {
      if (!arg2) { stderr.write(`usage: ${invokeHint('notifications methods send-code <id>')}\n`); exit(2); }
      return cmdMethodsSendCode(arg2, json);
    }
    if (sub2 === 'verify') return cmdMethodsVerify(args.slice(2), json);
    if (sub2 === 'delete' || sub2 === 'rm') {
      if (!arg2) { stderr.write(`usage: ${invokeHint('notifications methods delete <id>')}\n`); exit(2); }
      return cmdMethodsDelete(arg2, json);
    }
    stderr.write(`error: unknown notifications methods subcommand "${sub2 ?? ''}". Use list | add | test | send-code | verify | delete\n`);
    exit(2);
  }
  if (sub === 'rules' || sub === 'rule' || sub === 'channels') {
    if (sub2 === 'list' || sub2 === 'ls' || sub2 === undefined) return cmdRulesList(json);
    if (sub2 === 'create' || sub2 === 'add') return cmdRulesCreate(args.slice(2), json);
    if (sub2 === 'update') {
      if (!arg2) { stderr.write(`usage: ${invokeHint('notifications rules update <id> ...')}\n`); exit(2); }
      return cmdRulesUpdate(arg2, args.slice(3), json);
    }
    if (sub2 === 'delete' || sub2 === 'rm') {
      if (!arg2) { stderr.write(`usage: ${invokeHint('notifications rules delete <id>')}\n`); exit(2); }
      return cmdRulesDelete(arg2, json);
    }
    stderr.write(`error: unknown notifications rules subcommand "${sub2 ?? ''}". Use list | create | update | delete\n`);
    exit(2);
  }
  stderr.write(
    `error: unknown notifications subcommand "${sub ?? ''}".\nUse methods <list|add|test|send-code|verify|delete> | rules <list|create|update|delete>\n`,
  );
  exit(2);
}
