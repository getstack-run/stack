// dropoffs subcommands.
//
// Drop-offs are point-to-point schema-validated handoffs between agents.
// Schema files passed via --schema must be a path to a JSON file; the
// CLI reads + parses it before POSTing.

import { stdout, stderr, exit } from 'node:process';
import { readFile } from 'node:fs/promises';
import { api, takeFlag, resolveAgentId } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt, fmtTs } from './format.js';

interface Dropoff {
  id: string;
  from_agent_id: string;
  to_agent_id: string;
  to_agent_ids?: string[];
  status: string;
  created_at: string;
  expires_at: string;
}

async function readJsonFile(path: string): Promise<unknown> {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw);
}

async function cmdList(json: boolean): Promise<void> {
  const list = await api<Dropoff[]>('GET', '/v1/dropoffs');
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no drop-offs)\n');
    return;
  }
  const rows = list.map((d) => [d.id, d.from_agent_id, (d.to_agent_ids ?? [d.to_agent_id]).join(','), statusBadge(d.status), fmtTs(d.created_at), fmtTs(d.expires_at)]);
  printTable(['ID', 'FROM', 'TO', 'STATUS', 'CREATED', 'EXPIRES'], rows);
}

async function cmdShow(id: string, json: boolean): Promise<void> {
  const out = await api('GET', `/v1/dropoffs/${encodeURIComponent(id)}`);
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdCreate(args: string[], json: boolean): Promise<void> {
  const fromArg = takeFlag(args, '--from');
  const toArg = takeFlag(args, '--to');
  const schemaPath = takeFlag(args, '--schema');
  const ttl = takeFlag(args, '--ttl');
  const onExpire = takeFlag(args, '--on-expire');
  if (typeof fromArg !== 'string' || typeof toArg !== 'string' || typeof schemaPath !== 'string') {
    stderr.write(
      `usage: ${invokeHint('dropoff create --from <name-or-id> --to <name-or-id>[,<name-or-id>...] --schema <file.json> [--ttl <seconds>] [--on-expire notify|retry|fail]')}\n` +
        'note: name two or more agents after --to, separated by commas, to hand work to a group: all are woken and the first to collect it takes it\n' +
        'note: all legacy --on-expire values now use the same expire-and-purge behavior\n',
    );
    exit(2);
  }
  // Resolve human names → agt_* ids before posting. Mirrors the pattern
  // every other --agent-style flag in the CLI uses.
  const from = await resolveAgentId(fromArg);
  const toNames = toArg.split(',').map((name) => name.trim()).filter(Boolean);
  if (toNames.length === 0) {
    stderr.write('error: --to needs at least one agent\n');
    exit(2);
  }
  const to = await Promise.all(toNames.map((name) => resolveAgentId(name)));
  const schema = await readJsonFile(schemaPath);
  // Field names match CreateDropoffInput in @stack/shared: from_agent /
  // to_agent or to_agents (NOT from_agent_id / to_agent_id — earlier CLI sent the
  // _id-suffixed names and got a ZodError).
  const body: Record<string, unknown> = {
    from_agent: from,
    ...(to.length === 1 ? { to_agent: to[0] } : { to_agents: to }),
    schema,
  };
  if (typeof ttl === 'string') body.ttl_seconds = parseInt(ttl, 10);
  if (typeof onExpire === 'string') body.on_expire = onExpire;
  const out = await api<Dropoff>('POST', '/v1/dropoffs', { body });
  if (json) return printJson(out);
  stdout.write(`created ${out.id}\n  from ${out.from_agent_id} → ${(out.to_agent_ids ?? [out.to_agent_id]).join(', ')}\n  expires ${fmtTs(out.expires_at)}\n`);
}

async function cmdDeposit(id: string, args: string[], json: boolean): Promise<void> {
  const agentArg = takeFlag(args, '--agent');
  const payloadPath = takeFlag(args, '--payload');
  const passportJti = takeFlag(args, '--passport-jti');
  const missionId = takeFlag(args, '--mission');
  const driveFiles = takeFlag(args, '--drive-files');
  if (typeof agentArg !== 'string' || typeof payloadPath !== 'string') {
    stderr.write(
      `usage: ${invokeHint('dropoff deposit <id> --agent <name-or-id> --payload <file.json> [--passport-jti <jti>] [--mission <id>] [--drive-files <id,id>]')}\n`,
    );
    exit(2);
  }
  const agentId = await resolveAgentId(agentArg);
  const payload = await readJsonFile(payloadPath);
  const out = await api('POST', `/v1/dropoffs/${encodeURIComponent(id)}/deposit`, {
    body: {
      agent_id: agentId,
      payload,
      ...(typeof passportJti === 'string' ? { passport_jti: passportJti } : {}),
      ...(typeof missionId === 'string' ? { mission_id: missionId } : {}),
      ...(typeof driveFiles === 'string' ? { drive_files: driveFiles.split(',').map((f) => f.trim()).filter(Boolean) } : {}),
    },
  });
  if (json) return printJson(out);
  stdout.write(`deposited to ${id}\n`);
}

async function cmdCollect(id: string, args: string[], json: boolean): Promise<void> {
  const agentArg = takeFlag(args, '--agent');
  if (typeof agentArg !== 'string') {
    stderr.write(`usage: ${invokeHint('dropoff collect <id> --agent <name-or-id>')}\n`);
    exit(2);
  }
  const agentId = await resolveAgentId(agentArg);
  const out = await api<{ payload: unknown; drive_files?: Array<{ id: string; name: string }> }>('POST', `/v1/dropoffs/${encodeURIComponent(id)}/collect`, {
    body: { agent_id: agentId },
  });
  if (json) return printJson(out);
  stdout.write(JSON.stringify(out.payload, null, 2) + '\n');
  // Drive files handed over with the payload are now readable by this agent; their content is untrusted.
  for (const file of out.drive_files ?? []) stdout.write(`drive file ${file.id}  ${file.name}\n`);
}

async function cmdExpire(id: string, json: boolean): Promise<void> {
  const out = await api('POST', `/v1/dropoffs/${encodeURIComponent(id)}/expire`);
  if (json) return printJson(out);
  stdout.write(`expired ${id}\n`);
}

function statusBadge(s: string): string {
  if (s === 'collected') return fmt.ok(s);
  if (s === 'expired') return fmt.dim(s);
  if (s === 'deposited') return fmt.warn(s);
  return s;
}

export async function cmdDropoff(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'list' || sub === 'ls') return cmdList(json);
  if (sub === 'show' || sub === 'status') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('dropoff show <id>')}\n`);
      exit(2);
    }
    return cmdShow(arg1, json);
  }
  if (sub === 'create') return cmdCreate(args.slice(1), json);
  if (sub === 'deposit') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('dropoff deposit <id> --agent <name-or-id> --payload <file.json> [--passport-jti <jti>] [--mission <id>] [--drive-files <id,id>]')}\n`);
      exit(2);
    }
    return cmdDeposit(arg1, args.slice(2), json);
  }
  if (sub === 'collect') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('dropoff collect <id> --agent <name-or-id>')}\n`);
      exit(2);
    }
    return cmdCollect(arg1, args.slice(2), json);
  }
  if (sub === 'expire') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('dropoff expire <id>')}\n`);
      exit(2);
    }
    return cmdExpire(arg1, json);
  }
  stderr.write(
    `error: unknown dropoff subcommand "${sub ?? ''}".\n` +
      `Use list | show | create | deposit | collect | expire\n`,
  );
  exit(2);
}
