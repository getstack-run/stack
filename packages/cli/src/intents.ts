// intents subcommands — thin wrappers over /v1/intents/*.
//
// stack intents simulate        --intent-json <path>
// stack intents submit          --intent-json <path> [--expires <seconds>] [--skip-simulation]
// stack intents submit-and-wait --intent-json <path> [--timeout <seconds>] [--interval <seconds>] [--expires <seconds>] [--skip-simulation]
// stack intents pending         [--page N] [--limit N]
// stack intents approve         <approval-id> [--notes "..."]
// stack intents reject          <approval-id> [--notes "..."] [--block-future]
// stack intents get             <approval-id>
//

import { readFileSync } from 'node:fs';
import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag } from './api.js';
import { governedApi } from './governance.js';
import { invokeHint } from './auth.js';
import { printJson, printRecord, printTable, fmtTs } from './format.js';
import { readSecretFromStdin } from './secret-input.js';

// ─── Helpers ────────────────────────────────────────────────────────

async function readIntentJson(path: string): Promise<Record<string, unknown>> {
  if (path === '-') {
    throw new Error('use an intent JSON file. stdin is reserved for the passport token.');
  }
  const raw = readFileSync(path, 'utf-8');
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== 'object' || parsed === null) {
      throw new Error('intent JSON must be an object');
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    throw new Error(`failed to parse intent JSON from ${path === '-' ? 'stdin' : path}: ${(err as Error).message}`, { cause: err });
  }
}

// ─── Subcommands ────────────────────────────────────────────────────

async function cmdSimulate(passportToken: string, args: string[], json: boolean): Promise<void> {
  const intentPath = takeFlag(args, '--intent-json');
  const claimRef = takeFlag(args, '--intent-claim-ref');
  const persist = !takeFlag(args, '--no-persist');
  if (typeof intentPath !== 'string') {
    stderr.write(
      `usage: ${invokeHint('intents simulate --intent-json <path> [--intent-claim-ref pc_...] [--no-persist] [--json]')}\n`,
    );
    exit(2);
  }
  const intent = await readIntentJson(intentPath);
  const body: Record<string, unknown> = { intent };
  if (typeof claimRef === 'string') body['intent_claim_ref'] = claimRef;
  if (!persist) body['persist'] = false;

  const result = await api<{
    allowed: boolean;
    denial_reasons: string[];
    simulated_cost: unknown;
    simulated_at: number;
    claim_id?: string;
    diagnostics: Record<string, unknown>;
  }>('POST', '/v1/intents/simulate', {
    body,
    headers: { 'X-Passport-Token': passportToken },
  });

  if (json) return printJson(result);
  printRecord({
    allowed: result.allowed,
    denial_reasons: result.denial_reasons.join(', ') || '(none)',
    claim_id: result.claim_id ?? '(persist=false)',
    simulated_at: new Date(result.simulated_at).toISOString(),
  });
  // Exit 1 on denial so shell pipelines can branch.
  if (!result.allowed) exit(1);
}

async function cmdSubmit(passportToken: string, args: string[], json: boolean): Promise<void> {
  const intentPath = takeFlag(args, '--intent-json');
  const expiresRaw = takeFlag(args, '--expires');
  const skipSim = !!takeFlag(args, '--skip-simulation');
  if (typeof intentPath !== 'string') {
    stderr.write(
      `usage: ${invokeHint('intents submit --intent-json <path> [--expires <seconds>] [--skip-simulation] [--json]')}\n`,
    );
    exit(2);
  }
  const intent = await readIntentJson(intentPath);
  const body: Record<string, unknown> = { intent };
  if (typeof expiresRaw === 'string') {
    const seconds = parseInt(expiresRaw, 10);
    if (!Number.isFinite(seconds) || seconds <= 0) {
      stderr.write('--expires must be a positive integer (seconds)\n');
      exit(2);
    }
    body['expires_in_seconds'] = seconds;
  }
  if (skipSim) body['skip_simulation'] = true;

  const result = await api<{
    approval_id: string;
    intent_claim_id: string;
    simulated_claim_id?: string;
    status: string;
    expires_at: string;
  }>('POST', '/v1/intents/submit', {
    body,
    headers: { 'X-Passport-Token': passportToken },
  });

  if (json) return printJson(result);
  printRecord({
    approval_id: result.approval_id,
    intent_claim_id: result.intent_claim_id,
    simulated_claim_id: result.simulated_claim_id ?? '(skipped)',
    status: result.status,
    expires_at: fmtTs(result.expires_at),
  });
}

async function cmdSubmitAndWait(
  passportToken: string,
  args: string[],
  json: boolean,
): Promise<void> {
  const intentPath = takeFlag(args, '--intent-json');
  const expiresRaw = takeFlag(args, '--expires');
  const timeoutRaw = takeFlag(args, '--timeout');
  const intervalRaw = takeFlag(args, '--interval');
  const skipSim = !!takeFlag(args, '--skip-simulation');
  if (typeof intentPath !== 'string') {
    stderr.write(
      `usage: ${invokeHint(
        'intents submit-and-wait --intent-json <path> [--timeout 60] [--interval 1] [--expires 900] [--skip-simulation] [--json]',
      )}\n`,
    );
    exit(2);
  }
  const timeoutSec = typeof timeoutRaw === 'string' ? parseInt(timeoutRaw, 10) : 60;
  const intervalSec = typeof intervalRaw === 'string' ? parseInt(intervalRaw, 10) : 1;
  if (!Number.isFinite(timeoutSec) || timeoutSec <= 0) {
    stderr.write('--timeout must be a positive integer (seconds)\n');
    exit(2);
  }
  if (!Number.isFinite(intervalSec) || intervalSec <= 0) {
    stderr.write('--interval must be a positive integer (seconds)\n');
    exit(2);
  }
  const intent = await readIntentJson(intentPath);
  const body: Record<string, unknown> = { intent };
  if (typeof expiresRaw === 'string') {
    const seconds = parseInt(expiresRaw, 10);
    if (!Number.isFinite(seconds) || seconds <= 0) {
      stderr.write('--expires must be a positive integer (seconds)\n');
      exit(2);
    }
    body['expires_in_seconds'] = seconds;
  }
  if (skipSim) body['skip_simulation'] = true;

  const initial = await api<{
    approval_id: string;
    intent_claim_id: string;
    simulated_claim_id?: string;
    status: string;
    expires_at: string;
  }>('POST', '/v1/intents/submit', { body, headers: { 'X-Passport-Token': passportToken } });

  const deadline = Date.now() + timeoutSec * 1000;
  let final: Record<string, unknown> | null = null;
  while (Date.now() < deadline) {
    const row = await api<Record<string, unknown>>(
      'GET',
      `/v1/intents/${encodeURIComponent(initial.approval_id)}`,
    );
    final = row;
    if (row['status'] !== 'pending') break;
    await new Promise((r) => setTimeout(r, intervalSec * 1000));
  }
  const timedOut = final === null || final['status'] === 'pending';
  const result = { initial, final, timed_out: timedOut };

  if (json) return printJson(result);
  printRecord({
    approval_id: initial.approval_id,
    status: (final?.['status'] as string) ?? 'pending',
    decided_at: final && final['decided_at'] ? fmtTs(final['decided_at'] as string) : '(none)',
    timed_out: timedOut ? 'true' : 'false',
  });
  // Exit 1 on non-approved terminal status so shell pipelines can branch.
  // (Approved → 0, rejected/expired/timed_out → 1.)
  if (final?.['status'] !== 'approved') exit(1);
}

async function cmdGet(approvalId: string, json: boolean): Promise<void> {
  const row = await api<Record<string, unknown>>('GET', `/v1/intents/${encodeURIComponent(approvalId)}`);
  if (json) return printJson(row);
  printRecord(row);
}

async function cmdPending(args: string[], json: boolean): Promise<void> {
  const page = takeFlag(args, '--page');
  const limit = takeFlag(args, '--limit');
  const result = await api<{
    items: Array<{
      id: string;
      agent_id: string;
      passport_jti: string;
      requested_at: string;
      expires_at: string;
    }>;
    total: number;
  }>('GET', '/v1/intents/pending', {
    query: {
      page: typeof page === 'string' ? page : undefined,
      limit: typeof limit === 'string' ? limit : undefined,
    },
  });

  if (json) return printJson(result);
  if (result.items.length === 0) {
    stdout.write('(no pending approvals)\n');
    return;
  }
  const rows = result.items.map((r) => [
    r.id,
    r.agent_id,
    r.passport_jti,
    fmtTs(r.requested_at),
    fmtTs(r.expires_at),
  ]);
  printTable(['APPROVAL', 'AGENT', 'PASSPORT', 'REQUESTED', 'EXPIRES'], rows);
}

async function cmdApprove(approvalId: string, args: string[], json: boolean): Promise<void> {
  const notes = takeFlag(args, '--notes');
  const body: Record<string, unknown> = {};
  if (typeof notes === 'string') body['notes'] = notes;
  // Approving releases what the agent was held on: a person confirms it, in the browser the link opens.
  const result = await governedApi<{ approval_id: string; status: string; decided_at: string }>(
    'POST',
    `/v1/intents/${encodeURIComponent(approvalId)}/approve`,
    { body },
  );
  if (json) return printJson(result);
  printRecord({ approval_id: result.approval_id, status: result.status, decided_at: fmtTs(result.decided_at) });
}

async function cmdReject(approvalId: string, args: string[], json: boolean): Promise<void> {
  const notes = takeFlag(args, '--notes');
  const blockFuture = !!takeFlag(args, '--block-future');
  const body: Record<string, unknown> = {};
  if (typeof notes === 'string') body['notes'] = notes;
  if (blockFuture) body['block_future'] = true;
  const result = await api<{ approval_id: string; status: string; decided_at: string }>(
    'POST',
    `/v1/intents/${encodeURIComponent(approvalId)}/reject`,
    { body },
  );
  if (json) return printJson(result);
  printRecord({ approval_id: result.approval_id, status: result.status, decided_at: fmtTs(result.decided_at) });
}

// ─── Router ─────────────────────────────────────────────────────────

export async function cmdIntents(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'simulate') {
    if (arg1 && !arg1.startsWith('--')) {
      stderr.write('error: passport tokens must not be placed in argv. Pipe the token or use the hidden prompt.\n');
      exit(2);
    }
    const passportToken = await readSecretFromStdin('Passport token: ');
    return cmdSimulate(passportToken, args.slice(1), json);
  }
  if (sub === 'submit') {
    if (arg1 && !arg1.startsWith('--')) {
      stderr.write('error: passport tokens must not be placed in argv. Pipe the token or use the hidden prompt.\n');
      exit(2);
    }
    const passportToken = await readSecretFromStdin('Passport token: ');
    return cmdSubmit(passportToken, args.slice(1), json);
  }
  if (sub === 'submit-and-wait') {
    if (arg1 && !arg1.startsWith('--')) {
      stderr.write('error: passport tokens must not be placed in argv. Pipe the token or use the hidden prompt.\n');
      exit(2);
    }
    const passportToken = await readSecretFromStdin('Passport token: ');
    return cmdSubmitAndWait(passportToken, args.slice(1), json);
  }
  if (sub === 'pending' || sub === 'list') {
    return cmdPending(args.slice(1), json);
  }
  if (sub === 'get' || sub === 'show') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('intents get <approval-id>')}\n`);
      exit(2);
    }
    return cmdGet(arg1, json);
  }
  if (sub === 'approve') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('intents approve <approval-id> [--notes "..."]')}\n`);
      exit(2);
    }
    return cmdApprove(arg1, args.slice(2), json);
  }
  if (sub === 'reject') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('intents reject <approval-id> [--notes "..."] [--block-future]')}\n`);
      exit(2);
    }
    return cmdReject(arg1, args.slice(2), json);
  }

  stderr.write(
    `error: unknown intents subcommand "${sub ?? ''}".\n` +
      `Use simulate | submit | pending | get | approve | reject\n`,
  );
  exit(2);
}
