// team / members subcommands.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt, fmtTs } from './format.js';
import { governedApi } from './governance.js';

interface Member {
  id: string;
  email: string;
  role: string;
  status: string;
  created_at?: string;
}

async function cmdList(json: boolean): Promise<void> {
  const list = await api<Member[]>('GET', '/v1/team/members');
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no team members)\n');
    return;
  }
  const rows = list.map((m) => [
    m.id,
    m.email,
    m.role,
    m.status === 'active' ? fmt.ok(m.status) : m.status === 'pending' ? fmt.warn(m.status) : fmt.dim(m.status),
    fmtTs(m.created_at ?? null),
  ]);
  printTable(['ID', 'EMAIL', 'ROLE', 'STATUS', 'JOINED'], rows);
}

async function cmdInvite(args: string[], json: boolean): Promise<void> {
  const email = args[0];
  const name = takeFlag(args, '--name');
  const role = takeFlag(args, '--role');
  const connectionsRaw = takeFlag(args, '--allowed-connections');
  // InviteMemberInput requires both email AND name (z.string().min(1).max(100)).
  // The earlier CLI sent only {email, role?} which 400'd with a ZodError.
  if (!email || typeof name !== 'string') {
    stderr.write(
      `usage: ${invokeHint('team invite <email> --name "<full name>" [--role admin|standard|readonly] [--allowed-connections id1,id2]')}\n`,
    );
    exit(2);
  }
  const body: Record<string, unknown> = { email, name };
  if (typeof role === 'string') body.role = role;
  if (typeof connectionsRaw === 'string') {
    body.allowed_connections = connectionsRaw.split(',').map((s) => s.trim()).filter(Boolean);
  }
  const out = await api<Member>('POST', '/v1/team/members', { body });
  if (json) return printJson(out);
  stdout.write(`invited ${out.email} (${out.id}) — role=${out.role}\n`);
}

async function cmdUpdate(id: string, args: string[], json: boolean): Promise<void> {
  // UpdateMemberInput accepts only {role?, allowed_connections?}. Earlier
  // CLI exposed --status which the schema rejects (no status field). The
  // member lifecycle (suspend/revoke) is done via DELETE, not PATCH.
  const role = takeFlag(args, '--role');
  const connectionsRaw = takeFlag(args, '--allowed-connections');
  const body: Record<string, unknown> = {};
  if (typeof role === 'string') body.role = role;
  if (typeof connectionsRaw === 'string') {
    body.allowed_connections = connectionsRaw.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (Object.keys(body).length === 0) {
    stderr.write(
      `usage: ${invokeHint('team update <id> [--role admin|standard|readonly] [--allowed-connections id1,id2]')}\n`
      + `(member lifecycle is via revoke; there is no status field on UpdateMemberInput)\n`,
    );
    exit(2);
  }
  const out = await api('PATCH', `/v1/team/members/${encodeURIComponent(id)}`, { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdRevoke(id: string, json: boolean): Promise<void> {
  const out = await api('DELETE', `/v1/team/members/${encodeURIComponent(id)}`);
  if (json) return printJson(out);
  stdout.write(`revoked ${id}\n`);
}

async function cmdSsoUnbind(args: string[], json: boolean): Promise<void> {
  const issuer = takeFlag(args, '--issuer');
  const id = args[0];
  const usage = `usage: ${invokeHint('team sso-unbind (<id> | --issuer <url>)')}\n`;
  // Exactly one target: a member id, or the issuer of the provider that was replaced.
  if (typeof issuer === 'string' ? issuer === '' || id !== undefined : id === undefined || id === '' || id.startsWith('--')) {
    stderr.write(usage);
    exit(2);
  }
  const body = typeof issuer === 'string' ? { issuer } : { member_id: id };
  const out = await governedApi<{ cleared: Array<{ id: string; email: string; sso_issuer: string }> }>(
    'POST',
    '/v1/team/sso-bindings/clear',
    { body },
  );
  if (json) return printJson(out);
  if (out.cleared.length === 0) {
    stdout.write('nobody had a single sign-on identity to forget\n');
    return;
  }
  for (const member of out.cleared) stdout.write(`cleared ${member.email} (${member.id}), bound to ${member.sso_issuer}\n`);
}

export async function cmdTeam(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'list' || sub === 'ls') return cmdList(json);
  if (sub === 'invite') return cmdInvite(args.slice(1), json);
  if (sub === 'update') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('team update <id> [--role ...] [--status ...]')}\n`);
      exit(2);
    }
    return cmdUpdate(arg1, args.slice(2), json);
  }
  if (sub === 'revoke' || sub === 'remove') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('team revoke <id>')}\n`);
      exit(2);
    }
    return cmdRevoke(arg1, json);
  }
  if (sub === 'sso-unbind') return cmdSsoUnbind(args.slice(1), json);
  stderr.write(
    `error: unknown team subcommand "${sub ?? ''}".\nUse list | invite | update | revoke | sso-unbind\n`,
  );
  exit(2);
}
