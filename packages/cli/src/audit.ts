// audit subcommands (non-tail). Use `monitor --follow` for live tail.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag, resolveAgentId } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt, fmtTs } from './format.js';

interface AuditEntry {
  entry_id: string;
  timestamp: number;
  agent_id?: string;
  layer?: string;
  action?: string;
  outcome?: string;
  error_message?: string;
}

async function cmdList(args: string[], json: boolean): Promise<void> {
  const limit = takeFlag(args, '--limit');
  const agentNameOrId = takeFlag(args, '--agent');
  const agentId = typeof agentNameOrId === 'string' ? await resolveAgentId(agentNameOrId) : undefined;
  const out = await api<{ entries?: AuditEntry[] } | AuditEntry[]>('GET', '/v1/audit', {
    query: {
      limit: typeof limit === 'string' ? limit : '20',
      agent_id: agentId,
    },
  });
  const list = Array.isArray(out) ? out : (out?.entries ?? []);
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no audit entries)\n');
    return;
  }
  const rows = list.map((e) => [
    fmtTs(e.timestamp),
    e.layer ?? '—',
    e.action ?? '—',
    outcomeBadge(e.outcome),
    e.error_message ?? '',
  ]);
  printTable(['TIME', 'LAYER', 'ACTION', 'OUTCOME', 'ERROR'], rows);
}

async function cmdChainHead(json: boolean): Promise<void> {
  const out = await api('GET', '/v1/audit/chain-head');
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdVerifyChain(args: string[], json: boolean): Promise<void> {
  const limit = takeFlag(args, '--limit');
  const out = await api('GET', '/v1/audit/verify-chain', {
    query: { limit: typeof limit === 'string' ? limit : undefined },
  });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

function outcomeBadge(o?: string): string {
  if (o === 'success') return fmt.ok('success');
  if (o === 'failure' || o === 'blocked') return fmt.err(o);
  if (o === 'warning') return fmt.warn(o);
  return o ?? '—';
}

async function cmdExport(args: string[]): Promise<void> {
  const format = takeFlag(args, '--format');
  const from = takeFlag(args, '--from');
  const to = takeFlag(args, '--to');
  const limit = takeFlag(args, '--limit');
  const offset = takeFlag(args, '--offset');
  const out = takeFlag(args, '--out');
  const fmtStr = typeof format === 'string' ? format : 'json';
  if (!['json', 'ndjson', 'csv'].includes(fmtStr)) {
    stderr.write(`error: --format must be json | ndjson | csv (got "${fmtStr}").\n`);
    exit(2);
  }
  const body = await api<string>('GET', '/v1/audit/export', {
    query: {
      format: fmtStr,
      from: typeof from === 'string' ? from : undefined,
      to: typeof to === 'string' ? to : undefined,
      limit: typeof limit === 'string' ? limit : undefined,
      offset: typeof offset === 'string' ? offset : undefined,
    },
  });
  const text = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
  if (typeof out === 'string') {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(out, text, 'utf8');
    stdout.write(`exported ${fmtStr} audit log to ${out}\n`);
  } else {
    stdout.write(text.endsWith('\n') ? text : text + '\n');
  }
}

export async function cmdAudit(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];

  if (sub === 'list' || sub === 'ls' || sub === 'tail') return cmdList(args.slice(1), json);
  if (sub === 'chain-head' || sub === 'head') return cmdChainHead(json);
  if (sub === 'verify-chain' || sub === 'verify') return cmdVerifyChain(args.slice(1), json);
  if (sub === 'export') return cmdExport(args.slice(1));
  stderr.write(
    `error: unknown audit subcommand "${sub ?? ''}".\n` +
      `Use list | export | chain-head | verify-chain\n` +
      `For live tail, use \`${invokeHint('monitor --follow')}\`.\n`,
  );
  exit(2);
}
