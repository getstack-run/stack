// passports subcommands — thin wrappers over /v1/passports/*.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag, resolveAgentId } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt, fmtTs } from './format.js';
import { readSecretFromStdin } from './secret-input.js';
import { delegationScopesFromToken } from '@getstackrun/sdk';

interface ActivePassport {
  jti: string;
  agent_id: string;
  session_id: string;
  delegation_depth: number;
  parent_passport_id: string | null;
  issued_at: string;
  expires_at: string;
}

async function cmdList(args: string[], json: boolean): Promise<void> {
  const agentNameOrId = takeFlag(args, '--agent');
  const sessionId = takeFlag(args, '--session');
  const agentId = typeof agentNameOrId === 'string' ? await resolveAgentId(agentNameOrId) : undefined;
  const list = await api<ActivePassport[]>('GET', '/v1/passports/active', {
    query: {
      agent_id: agentId,
      session_id: typeof sessionId === 'string' ? sessionId : undefined,
    },
  });
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no active passports)\n');
    return;
  }
  const rows = list.map((p) => [
    p.jti,
    p.agent_id,
    String(p.delegation_depth),
    fmtTs(p.issued_at),
    fmtTs(p.expires_at),
  ]);
  printTable(['JTI', 'AGENT', 'DEPTH', 'ISSUED', 'EXPIRES'], rows);
}

const MISSION_ID_RE = /^ms_[\w-]+$/;

/**
 * A Passport is issued for exactly one Mission. `--mission <ms_id>` is the
 * flag; `--missions` stays as an alias that must also name exactly one id.
 * Returns the id, or an error message for the caller to print.
 */
export function resolveSingleMissionId(
  mission: string | boolean | undefined,
  missions: string | boolean | undefined,
): { missionId: string } | { error: string } {
  if (mission !== undefined && missions !== undefined) {
    return { error: 'pass --mission once; --missions is an alias of --mission.' };
  }
  const raw = mission ?? missions;
  const flag = mission !== undefined ? '--mission' : '--missions';
  if (raw === undefined) {
    return { error: 'a Passport is issued for exactly one Mission: pass --mission <ms_id> (open one with `missions open` or `missions start`).' };
  }
  if (typeof raw !== 'string') return { error: `${flag} needs a Mission id (ms_*).` };
  const ids = raw.split(',').map((item) => item.trim()).filter(Boolean);
  if (ids.length !== 1) {
    return { error: `${flag} takes exactly one Mission id (got ${ids.length}).` };
  }
  if (!MISSION_ID_RE.test(ids[0]!)) return { error: `${flag} must be a Mission id (ms_*), got "${ids[0]}".` };
  return { missionId: ids[0]! };
}

const ISSUE_USAGE = () =>
  `usage: ${invokeHint('passport issue --agent <name-or-id> --mission <ms_id> --intent "<summary>" [--services slack,stripe] [--ttl <seconds>]')}\n` +
  `   or: ${invokeHint('passport issue --from-file issue.json [--mission <ms_id>]')}\n` +
  `--agent accepts either the agent's name (from \`agent list\`) or its agt_* id.\n` +
  `--mission is required: a Passport is issued for exactly one live Mission (\`missions open\` or \`missions start\`).\n` +
  `--services is optional; defaults to all services granted to the agent in the dashboard.\n`;

async function cmdIssue(args: string[], json: boolean): Promise<void> {
  const fromFile = takeFlag(args, '--from-file');
  const agentNameOrId = takeFlag(args, '--agent');
  const intentSummary = takeFlag(args, '--intent');
  const servicesRaw = takeFlag(args, '--services');
  const ttl = takeFlag(args, '--ttl');
  const missionFlag = takeFlag(args, '--mission');
  const missionsFlag = takeFlag(args, '--missions');
  if (typeof fromFile === 'string') {
    const { readFile } = await import('node:fs/promises');
    const parsed = JSON.parse(await readFile(fromFile, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      stderr.write('error: --from-file must contain one JSON object.\n');
      exit(2);
    }
    const body = { ...(parsed as Record<string, unknown>) };
    if (typeof body['agent_id'] !== 'string') {
      stderr.write('error: passport issue file requires agent_id.\n');
      exit(2);
    }
    body['agent_id'] = await resolveAgentId(body['agent_id']);
    // The flag, when given, binds the Mission; otherwise the file's own
    // mission_ids is sent as-is and the API enforces exactly one.
    if (missionFlag !== undefined || missionsFlag !== undefined) {
      const resolved = resolveSingleMissionId(missionFlag, missionsFlag);
      if ('error' in resolved) {
        stderr.write(`error: ${resolved.error}\n`);
        exit(2);
      }
      body['mission_ids'] = [resolved.missionId];
    }
    const issued = await api<{ token: string; jti: string; expires_at: string }>(
      'POST', '/v1/passports/issue', { body },
    );
    if (json) return printJson(issued);
    stdout.write(`issued ${issued.jti}\n  expires ${fmtTs(issued.expires_at)}\n  token: ${issued.token}\n`);
    return;
  }
  if (typeof agentNameOrId !== 'string' || typeof intentSummary !== 'string') {
    stderr.write(ISSUE_USAGE());
    exit(2);
  }
  const resolvedMission = resolveSingleMissionId(missionFlag, missionsFlag);
  if ('error' in resolvedMission) {
    stderr.write(`error: ${resolvedMission.error}\n${ISSUE_USAGE()}`);
    exit(2);
  }
  const missionId = resolvedMission.missionId;
  // Resolve human name → agt_* id before any agent-scoped API call.
  // /v1/agents/:id/permissions + POST /v1/passports/issue both want the
  // id. Passing the bare name 404s with "Agent not found".
  const agentId = await resolveAgentId(agentNameOrId);

  // The /v1/passports/issue body needs `scopes: [{service_connection_id,
  // scopes: [...]}]` — NOT a list of provider names. Fetch the agent's
  // grants and map each to that shape. If --services is supplied, filter
  // grants to those providers. The Mission does not change this: omitting
  // scopes would make the API bind EVERY active grant and silently drop
  // the --services narrowing, so the mapping always runs. The API then
  // checks the grants cover the Mission's intent_services.
  interface AgentGrant {
    grant_id: string;
    service_connection_id: string;
    provider: string;
    scopes: string[];
  }
  const grants = await api<AgentGrant[]>('GET', `/v1/agents/${encodeURIComponent(agentId)}/permissions`);
  let activeGrants: AgentGrant[] = Array.isArray(grants) ? grants : [];

  if (typeof servicesRaw === 'string') {
    const wanted = new Set(servicesRaw.split(',').map((s) => s.trim()).filter(Boolean));
    activeGrants = activeGrants.filter((g) => wanted.has(g.provider));
    if (activeGrants.length === 0) {
      stderr.write(
        `error: none of the providers in --services match grants on agent ${agentNameOrId}.\n` +
          `Available providers: ${(Array.isArray(grants) ? grants : []).map((g) => g.provider).join(', ') || '(none)'}\n`,
      );
      exit(1);
    }
  }

  if (activeGrants.length === 0) {
    stderr.write(
      `error: agent ${agentNameOrId} has no services granted, and --services was not specified.\n` +
        `Grant services in the dashboard at /agents → settings → service access, or pass --services explicitly.\n`,
    );
    exit(1);
  }

  const providerList = activeGrants.map((g) => g.provider);
  const body: Record<string, unknown> = {
    agent_id: agentId,
    mission_ids: [missionId],
    intent: { summary: intentSummary, services: providerList },
    scopes: activeGrants.map((g) => ({
      service_connection_id: g.service_connection_id,
      scopes: g.scopes,
    })),
  };
  if (typeof ttl === 'string') body.ttl_seconds = parseInt(ttl, 10);
  const checkpoint = takeFlag(args, '--checkpoint-interval');
  const estimatedDuration = takeFlag(args, '--estimated-duration');
  const identityClaims = takeFlag(args, '--identity-claims');
  const intentRefsFile = takeFlag(args, '--intent-refs-file');
  const scopesFile = takeFlag(args, '--scopes-file');
  if (typeof checkpoint === 'string') body['checkpoint_interval_seconds'] = Number.parseInt(checkpoint, 10);
  if (typeof identityClaims === 'string') {
    body['identity_claim_ids'] = identityClaims.split(',').map((item) => item.trim()).filter(Boolean);
  }
  const intent = body['intent'] as Record<string, unknown>;
  if (args.includes('--will-delegate')) intent['will_delegate'] = true;
  if (typeof estimatedDuration === 'string') {
    intent['estimated_duration_seconds'] = Number.parseInt(estimatedDuration, 10);
  }
  const { readFile } = await import('node:fs/promises');
  if (typeof intentRefsFile === 'string') {
    intent['refs'] = JSON.parse(await readFile(intentRefsFile, 'utf8'));
  }
  if (typeof scopesFile === 'string') {
    body['scopes'] = JSON.parse(await readFile(scopesFile, 'utf8'));
  }
  const issued = await api<{ token: string; jti: string; expires_at: string }>('POST', '/v1/passports/issue', { body });
  if (json) return printJson(issued);
  stdout.write(`issued ${issued.jti}\n  mission: ${missionId}\n  services: ${providerList.join(', ')}\n  expires ${fmtTs(issued.expires_at)}\n  token: ${issued.token}\n`);
}

async function cmdRefresh(jti: string, args: string[], json: boolean): Promise<void> {
  if (args.includes('--token')) {
    stderr.write('error: passport tokens must not be placed in argv. Pipe the token or use the hidden prompt.\n');
    exit(2);
  }
  const token = await readSecretFromStdin('Passport token: ');
  void jti; // accepted for symmetry but unused — token is the source
  const ttl = takeFlag(args, '--ttl');
  const body: Record<string, unknown> = { token };
  if (typeof ttl === 'string') body.ttl_seconds = parseInt(ttl, 10);
  const out = await api('POST', '/v1/passports/refresh', { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdVerify(json: boolean): Promise<void> {
  const token = await readSecretFromStdin('Passport token: ');
  const out = await api('POST', '/v1/passports/verify', { body: { token } });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdRevoke(jti: string, args: string[], json: boolean): Promise<void> {
  const reason = takeFlag(args, '--reason');
  const out = await api('POST', '/v1/passports/revoke', {
    body: { jti, reason: typeof reason === 'string' ? reason : undefined },
  });
  if (json) return printJson(out);
  stdout.write(`revoked ${jti}\n`);
}

async function cmdRevokeAgent(agentNameOrId: string, args: string[], json: boolean): Promise<void> {
  const reason = takeFlag(args, '--reason');
  const agentId = await resolveAgentId(agentNameOrId);
  const out = await api<{ revoked_count: number }>('POST', `/v1/passports/revoke-agent/${encodeURIComponent(agentId)}`, {
    body: { reason: typeof reason === 'string' ? reason : 'CLI revoke' },
  });
  if (json) return printJson(out);
  stdout.write(`revoked ${out.revoked_count} passport(s) for ${agentNameOrId}\n`);
}

async function cmdRevokeAll(args: string[], json: boolean): Promise<void> {
  const yes = !!takeFlag(args, '--yes');
  const reason = takeFlag(args, '--reason');
  if (!yes) {
    stderr.write(
      `error: passport revoke-all is destructive across all agents.\n` +
        `Pass --yes to confirm. Optional: --reason "<text>".\n`,
    );
    exit(2);
  }
  const out = await api<{ revoked_count: number }>('POST', '/v1/passports/revoke-all', {
    body: { confirm: true, reason: typeof reason === 'string' ? reason : 'CLI revoke-all' },
  });
  if (json) return printJson(out);
  stdout.write(`revoked ${out.revoked_count} passport(s)\n`);
}

async function cmdRevokeSession(sessionId: string, args: string[], json: boolean): Promise<void> {
  const reason = takeFlag(args, '--reason');
  const out = await api<{ revoked_count: number }>('POST', `/v1/passports/revoke-session/${encodeURIComponent(sessionId)}`, {
    body: { reason: typeof reason === 'string' ? reason : 'CLI revoke-session' },
  });
  if (json) return printJson(out);
  stdout.write(`revoked ${out.revoked_count} passport(s) on session ${sessionId}\n`);
}

async function cmdReport(jti: string, json: boolean): Promise<void> {
  const out = await api('GET', `/v1/passports/${encodeURIComponent(jti)}/report`);
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdDelegate(args: string[], json: boolean): Promise<void> {
  if (args.includes('--parent-token')) {
    stderr.write('error: passport tokens must not be placed in argv. Pipe the token or use the hidden prompt.\n');
    exit(2);
  }
  const childAgent = takeFlag(args, '--agent');
  const servicesRaw = takeFlag(args, '--services');
  const ttl = takeFlag(args, '--ttl');
  if (typeof childAgent !== 'string') {
    stderr.write(
      `usage: ${invokeHint('passport delegate --agent <child-name|id> [--services a,b] [--ttl 900]')}\n` +
        `The command reads the parent passport token from stdin or a hidden prompt.\n` +
        `Delegates a passport to a child agent. Scope narrows only (never widens); max 4 hops.\n`,
    );
    exit(2);
  }
  const parentToken = await readSecretFromStdin('Parent passport token: ');
  const childId = await resolveAgentId(childAgent);
  const body: Record<string, unknown> = {
    parent_passport_token: parentToken,
    child_agent_id: childId,
  };
  const scopesFile = takeFlag(args, '--scopes-file');
  body.scopes = typeof scopesFile === 'string'
    ? JSON.parse(await (await import('node:fs/promises')).readFile(scopesFile, 'utf8'))
    : delegationScopesFromToken(parentToken, typeof servicesRaw === 'string' ? servicesRaw.split(',').map(s => s.trim()).filter(Boolean) : undefined);
  if (typeof ttl === 'string') body.ttl_seconds = Number.parseInt(ttl, 10);
  const issued = await api('POST', '/v1/passports/delegate', { body });
  if (json) return printJson(issued);
  printRecord(issued as Record<string, unknown>);
}

export async function cmdPassport(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'list' || sub === 'ls' || sub === 'active') return cmdList(args.slice(1), json);
  if (sub === 'issue') return cmdIssue(args.slice(1), json);
  if (sub === 'refresh') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('passport refresh <jti> [--ttl 900]')}\n`);
      exit(2);
    }
    return cmdRefresh(arg1, args.slice(2), json);
  }
  if (sub === 'verify') {
    if (arg1) {
      stderr.write('error: passport tokens must not be placed in argv. Pipe the token or use the hidden prompt.\n');
      exit(2);
    }
    return cmdVerify(json);
  }
  if (sub === 'revoke') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('passport revoke <jti> [--reason "..."]')}\n`);
      exit(2);
    }
    return cmdRevoke(arg1, args.slice(2), json);
  }
  if (sub === 'revoke-agent') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('passport revoke-agent <agent-id> [--reason "..."]')}\n`);
      exit(2);
    }
    return cmdRevokeAgent(arg1, args.slice(2), json);
  }
  if (sub === 'revoke-all') return cmdRevokeAll(args.slice(1), json);
  if (sub === 'revoke-session') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('passport revoke-session <session-id> [--reason "..."]')}\n`);
      exit(2);
    }
    return cmdRevokeSession(arg1, args.slice(2), json);
  }
  if (sub === 'report') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('passport report <jti>')}\n`);
      exit(2);
    }
    return cmdReport(arg1, json);
  }
  if (sub === 'delegate') return cmdDelegate(args.slice(1), json);

  stderr.write(
    `error: unknown passport subcommand "${sub ?? ''}".\n` +
      `Use list | issue | delegate | refresh | verify | revoke | revoke-agent | revoke-session | revoke-all | report\n`,
  );
  exit(2);
}

// Silence the unused-imports warnings for the fields we re-export-like
// when building the table headers.
void fmt;
