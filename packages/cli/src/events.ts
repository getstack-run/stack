// security-events subcommands.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag, resolveAgentId } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt, fmtTs } from './format.js';

interface SecurityEvent {
  id: string;
  agent_id?: string;
  signal_type: string;
  severity: string;
  message?: string;
  resolved?: boolean;
  resolved_at?: string | null;
  created_at?: string;
}

async function cmdList(args: string[], json: boolean): Promise<void> {
  const agentNameOrId = takeFlag(args, '--agent');
  const limit = takeFlag(args, '--limit');
  const agentId = typeof agentNameOrId === 'string' ? await resolveAgentId(agentNameOrId) : undefined;
  const out = await api<{ events?: SecurityEvent[] } | SecurityEvent[]>('GET', '/v1/security-events', {
    query: {
      agent_id: agentId,
      limit: typeof limit === 'string' ? limit : undefined,
    },
  });
  const list = Array.isArray(out) ? out : (out?.events ?? []);
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no security events)\n');
    return;
  }
  const rows = list.map((e) => [
    e.id,
    severityBadge(e.severity),
    e.signal_type,
    e.agent_id ?? '—',
    e.resolved ? fmt.ok('yes') : fmt.warn('no'),
    fmtTs(e.created_at ?? null),
    (e.message ?? '').slice(0, 60),
  ]);
  printTable(['ID', 'SEV', 'SIGNAL', 'AGENT', 'RESOLVED', 'CREATED', 'MESSAGE'], rows);
}

async function cmdShow(id: string, json: boolean): Promise<void> {
  const out = await api('GET', `/v1/security-events/${encodeURIComponent(id)}`);
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdResolve(id: string, json: boolean): Promise<void> {
  const out = await api('POST', `/v1/security-events/${encodeURIComponent(id)}/resolve`);
  if (json) return printJson(out);
  stdout.write(`resolved ${id}\n`);
}

function severityBadge(s: string): string {
  if (s === 'critical') return fmt.err(s);
  if (s === 'warning') return fmt.warn(s);
  if (s === 'info') return fmt.dim(s);
  return s;
}

export async function cmdEvent(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'list' || sub === 'ls') return cmdList(args.slice(1), json);
  if (sub === 'show' || sub === 'get') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('event show <id>')}\n`);
      exit(2);
    }
    return cmdShow(arg1, json);
  }
  if (sub === 'resolve') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('event resolve <id>')}\n`);
      exit(2);
    }
    return cmdResolve(arg1, json);
  }
  stderr.write(
    `error: unknown event subcommand "${sub ?? ''}".\nUse list | show | resolve\n`,
  );
  exit(2);
}
