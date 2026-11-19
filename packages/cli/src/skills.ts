// skills subcommands.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag, resolveAgentId } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt } from './format.js';

interface Skill {
  id: string;
  name: string;
  description?: string;
  status?: string;
  trust_required?: string;
  price_cents?: number;
}

async function cmdBrowse(args: string[], json: boolean): Promise<void> {
  const query = takeFlag(args, '--q');
  const list = await api<Skill[]>('GET', '/v1/skills', {
    query: { q: typeof query === 'string' ? query : undefined },
  });
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no skills match)\n');
    return;
  }
  const rows = list.map((s) => [
    s.id,
    s.name,
    s.trust_required ?? '—',
    s.price_cents != null ? `$${(s.price_cents / 100).toFixed(2)}` : fmt.dim('free'),
  ]);
  printTable(['ID', 'NAME', 'TRUST', 'PRICE'], rows);
}

async function cmdMine(json: boolean): Promise<void> {
  const list = await api<Skill[]>('GET', '/v1/skills/mine');
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(you have no published skills)\n');
    return;
  }
  const rows = list.map((s) => [s.id, s.name, s.status ?? '—']);
  printTable(['ID', 'NAME', 'STATUS'], rows);
}

async function cmdShow(id: string, json: boolean): Promise<void> {
  const out = await api('GET', `/v1/skills/${encodeURIComponent(id)}`);
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdSuspend(id: string, state: 'suspend' | 'activate', json: boolean): Promise<void> {
  const out = await api('POST', `/v1/skills/${encodeURIComponent(id)}/${state}`);
  if (json) return printJson(out);
  stdout.write(`${state}d ${id}\n`);
}

async function cmdFavorites(json: boolean): Promise<void> {
  const out = await api<Skill[]>('GET', '/v1/skills/favorites');
  if (json) return printJson(out);
  if (!Array.isArray(out) || out.length === 0) {
    stdout.write('(no favorites)\n');
    return;
  }
  const rows = out.map((s) => [s.id, s.name, s.trust_required ?? '—']);
  printTable(['ID', 'NAME', 'TRUST'], rows);
}

async function cmdInvocations(args: string[], json: boolean): Promise<void> {
  const out = await api<{ invocations?: unknown[] } | unknown[]>('GET', '/v1/skills/invocations/pending');
  const list = Array.isArray(out) ? out : ((out as { invocations?: unknown[] }).invocations ?? []);
  if (json) return printJson(list);
  printJson(list);
  void args;
}

async function cmdInvocationCheck(invocationId: string, json: boolean): Promise<void> {
  const out = await api('GET', `/v1/skills/invocations/${encodeURIComponent(invocationId)}`);
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdInvocationComplete(invocationId: string, args: string[], json: boolean): Promise<void> {
  // POST /v1/skills/invocations/:id/complete body shape (see the
  // skill invocation route of the API): { output: Record<string,unknown> }.
  // The earlier CLI sent {status, result} — both fields the route never
  // reads. `output` is required (the route destructures it). Read the
  // result body from --output-file (preferred) or --result-file (legacy
  // flag name kept for back-compat). No --status flag — the route has
  // no status param; status is derived server-side from sealed-execution
  // exit state.
  const outFile = takeFlag(args, '--output-file');
  const fromFile = typeof outFile === 'string' ? outFile : takeFlag(args, '--result-file');
  if (typeof fromFile !== 'string') {
    stderr.write(
      `usage: ${invokeHint('skill complete <invocation-id> --output-file <result.json>')}\n`
      + `the JSON file's contents become the invocation's output payload.\n`,
    );
    exit(2);
  }
  const { readFile } = await import('node:fs/promises');
  const output = JSON.parse(await readFile(fromFile, 'utf8'));
  const out = await api('POST', `/v1/skills/invocations/${encodeURIComponent(invocationId)}/complete`, {
    body: { output },
  });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdCheckTrust(skillId: string, json: boolean): Promise<void> {
  const out = await api('POST', `/v1/skills/${encodeURIComponent(skillId)}/check-trust`, { body: {} });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

// Skill discovery is request-id-scoped on the API side:
//   POST /v1/skill-requests        — declare what you need (description)
//   GET  /v1/skill-requests/:id/matches  — matching published skills
//   GET  /v1/skill-requests/:id/suggest  — composition suggestion
// The earlier CLI invented POST /v1/skills/find-matching +
// /v1/skills/suggest-composition that don't exist on the API. The two
// commands below match the actual API: pass an existing request-id, OR
// pass --description to auto-create a temporary skill-request then
// query its matches/suggest.
async function cmdMatches(args: string[], json: boolean): Promise<void> {
  const requestId = args[0];
  const desc = takeFlag(args, '--description');
  let id = requestId && !requestId.startsWith('--') ? requestId : undefined;
  if (!id && typeof desc === 'string') {
    const posted = await api<{ id: string }>('POST', '/v1/skill-requests', {
      body: { description: desc },
    });
    id = posted.id;
  }
  if (!id) {
    stderr.write(
      `usage: ${invokeHint('skill matches <request-id> | skill matches --description "<what you want to do>"')}\n`,
    );
    exit(2);
  }
  const out = await api('GET', `/v1/skill-requests/${encodeURIComponent(id)}/matches`);
  if (json) return printJson(out);
  printJson(out);
}

async function cmdSuggest(args: string[], json: boolean): Promise<void> {
  const requestId = args[0];
  const desc = takeFlag(args, '--description');
  let id = requestId && !requestId.startsWith('--') ? requestId : undefined;
  if (!id && typeof desc === 'string') {
    const posted = await api<{ id: string }>('POST', '/v1/skill-requests', {
      body: { description: desc },
    });
    id = posted.id;
  }
  if (!id) {
    stderr.write(
      `usage: ${invokeHint('skill suggest <request-id> | skill suggest --description "<what you want to do>"')}\n`,
    );
    exit(2);
  }
  const out = await api('GET', `/v1/skill-requests/${encodeURIComponent(id)}/suggest`);
  if (json) return printJson(out);
  printJson(out);
}

async function cmdAgentAllow(args: string[], allow: boolean, json: boolean): Promise<void> {
  const agentNameOrId = takeFlag(args, '--agent');
  const skillId = args[0];
  if (!skillId || typeof agentNameOrId !== 'string') {
    stderr.write(`usage: ${invokeHint(`skill ${allow ? 'allow' : 'disallow'} <skill-id> --agent <name-or-id>`)}\n`);
    exit(2);
  }
  const agentId = await resolveAgentId(agentNameOrId);
  // API shape:
  //   POST   /v1/agents/:id/allowed-skills           body { skill_id }
  //   DELETE /v1/agents/:id/allowed-skills/:skillId
  // The earlier CLI invented /add and /remove path-segments that 404.
  const out = allow
    ? await api(
        'POST',
        `/v1/agents/${encodeURIComponent(agentId)}/allowed-skills`,
        { body: { skill_id: skillId } },
      )
    : await api(
        'DELETE',
        `/v1/agents/${encodeURIComponent(agentId)}/allowed-skills/${encodeURIComponent(skillId)}`,
      );
  if (json) return printJson(out);
  stdout.write(`${allow ? 'allowed' : 'disallowed'} ${skillId} for ${agentNameOrId}\n`);
}

// Platform-staff (STACK staff) endpoints for marketplace approval.
// Mounted under /v1/admin/* via the encapsulation block — requires the
// caller to be on a platform-staff operator. The earlier CLI hit
// non-existent /v1/skills/reviews/* paths and a non-existent single
// `decide` endpoint with a decision flag. The real API splits approve
// and reject into separate routes.
async function cmdPendingReviews(json: boolean): Promise<void> {
  const out = await api<unknown[] | { reviews?: unknown[] }>('GET', '/v1/admin/skills/pending-reviews');
  const list = Array.isArray(out) ? out : ((out as { reviews?: unknown[] }).reviews ?? []);
  if (json) return printJson(list);
  printJson(list);
}

async function cmdApproveSkill(skillId: string, json: boolean): Promise<void> {
  const out = await api('POST', `/v1/admin/skills/${encodeURIComponent(skillId)}/approve`);
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdRejectSkill(skillId: string, args: string[], json: boolean): Promise<void> {
  const reason = takeFlag(args, '--reason');
  const body: Record<string, unknown> = {};
  if (typeof reason === 'string') body.reason = reason;
  const out = await api('POST', `/v1/admin/skills/${encodeURIComponent(skillId)}/reject`, { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdRequestsList(json: boolean): Promise<void> {
  const out = await api<{ requests: unknown[] } | unknown[]>('GET', '/v1/skill-requests');
  const list = Array.isArray(out) ? out : (out?.requests ?? []);
  if (json) return printJson(list);
  printJson(list);
}

async function cmdRequestPost(description: string, json: boolean): Promise<void> {
  const out = await api('POST', '/v1/skill-requests', { body: { description } });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdPublish(args: string[], json: boolean): Promise<void> {
  // The publish body is a large structured object (input/output schemas,
  // execution script or pipeline, credential config) — supplied via a JSON
  // file rather than a wall of flags.
  const file = takeFlag(args, '--file');
  if (typeof file !== 'string') {
    stderr.write(
      `usage: ${invokeHint('skill publish --file <skill.json>')}\n` +
        `  The file is a PublishSkillInput object (name, description, version,\n` +
        `  input_schema, output_schema, trust_level_required, execution_*, ...).\n`,
    );
    exit(2);
  }
  const { readFileSync } = await import('node:fs');
  let body: unknown;
  try {
    body = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    stderr.write(`error: could not read/parse --file ${file}: ${(err as Error).message}\n`);
    exit(1);
  }
  const out = await api('POST', '/v1/skills', { body });
  if (json) return printJson(out);
  const s = out as { id?: string; name?: string; version?: string };
  stdout.write(`published ${s.name ?? ''}@${s.version ?? ''} (${s.id ?? ''})\n`);
}

async function cmdInvoke(skillId: string, args: string[], json: boolean): Promise<void> {
  // Invoke input is a JSON payload matching the skill's input_schema —
  // supplied inline via --input '{...}' or from --input-file. --agent names
  // the agent invoking; optional --passport for an explicit passport id.
  const agentNameOrId = takeFlag(args, '--agent');
  const passportId = takeFlag(args, '--passport');
  const inputRaw = takeFlag(args, '--input');
  const inputFile = takeFlag(args, '--input-file');
  if (typeof agentNameOrId !== 'string') {
    stderr.write(`usage: ${invokeHint('skill invoke <skill-id> --agent <name|id> --input \'{"...": "..."}\'')}\n`);
    exit(2);
  }
  const agentId = await resolveAgentId(agentNameOrId);
  let input: Record<string, unknown> = {};
  if (typeof inputFile === 'string') {
    const { readFileSync } = await import('node:fs');
    try {
      input = JSON.parse(readFileSync(inputFile, 'utf8'));
    } catch (err) {
      stderr.write(`error: could not read/parse --input-file: ${(err as Error).message}\n`);
      exit(1);
    }
  } else if (typeof inputRaw === 'string') {
    try {
      input = JSON.parse(inputRaw);
    } catch {
      stderr.write(`error: --input must be valid JSON.\n`);
      exit(2);
    }
  }
  const body: Record<string, unknown> = { agent_id: agentId, input };
  if (typeof passportId === 'string') body.passport_id = passportId;
  const out = await api('POST', `/v1/skills/${encodeURIComponent(skillId)}/invoke`, { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

export async function cmdSkill(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'publish') return cmdPublish(args.slice(1), json);
  if (sub === 'invoke') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('skill invoke <skill-id> --input \'{"...": "..."}\' | --input-file <f.json>')}\n`);
      exit(2);
    }
    return cmdInvoke(arg1, args.slice(2), json);
  }
  if (sub === 'list' || sub === 'browse') return cmdBrowse(args.slice(1), json);
  if (sub === 'mine' || sub === 'published') return cmdMine(json);
  if (sub === 'show' || sub === 'get') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('skill show <id>')}\n`);
      exit(2);
    }
    return cmdShow(arg1, json);
  }
  if (sub === 'suspend' || sub === 'activate') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint(`skill ${sub} <id>`)}\n`);
      exit(2);
    }
    return cmdSuspend(arg1, sub, json);
  }
  if (sub === 'requests') return cmdRequestsList(json);
  if (sub === 'post-request') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('skill post-request "<description>"')}\n`);
      exit(2);
    }
    return cmdRequestPost(arg1, json);
  }
  if (sub === 'favorites') return cmdFavorites(json);
  if (sub === 'invocations') return cmdInvocations(args.slice(1), json);
  if (sub === 'check-invocation') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('skill check-invocation <invocation-id>')}\n`); exit(2); }
    return cmdInvocationCheck(arg1, json);
  }
  if (sub === 'complete') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('skill complete <invocation-id> --output-file <result.json>')}\n`); exit(2); }
    return cmdInvocationComplete(arg1, args.slice(2), json);
  }
  if (sub === 'check-trust') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('skill check-trust <skill-id>')}\n`); exit(2); }
    return cmdCheckTrust(arg1, json);
  }
  if (sub === 'matches' || sub === 'find') return cmdMatches(args.slice(1), json);
  if (sub === 'suggest' || sub === 'suggest-composition') return cmdSuggest(args.slice(1), json);
  if (sub === 'allow') return cmdAgentAllow(args.slice(1), true, json);
  if (sub === 'disallow') return cmdAgentAllow(args.slice(1), false, json);
  if (sub === 'pending-reviews') return cmdPendingReviews(json);
  if (sub === 'approve') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('skill approve <skill-id>')}\n`); exit(2); }
    return cmdApproveSkill(arg1, json);
  }
  if (sub === 'reject') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('skill reject <skill-id> [--reason "..."]')}\n`); exit(2); }
    return cmdRejectSkill(arg1, args.slice(2), json);
  }

  stderr.write(
    `error: unknown skill subcommand "${sub ?? ''}".\n` +
      `Use list | mine | show | suspend | activate | requests | post-request | favorites | invocations | check-invocation | complete | check-trust | matches | suggest | allow | disallow | pending-reviews | approve | reject\n`
      + `(approve/reject/pending-reviews are platform-staff only)\n`,
  );
  exit(2);
}
