// evidence-pack subcommands — thin wrappers over /v1/evidence-packs/*.
//
// stack evidence-pack export --scope mission:<id> [--supersedes pck_*] [--output pack.json] [--air-gap]
// stack evidence-pack export --scope period:2026-Q1 --output q1-pack.json
// stack evidence-pack list   [--scope mission:<id>]
// stack evidence-pack get    <pack-id>
//
// A controls feature: the API answers 402 CONTROLS_REQUIRED without controls.

import { writeFileSync } from 'node:fs';
import { stderr, stdout, exit } from 'node:process';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, fmtTs } from './format.js';

interface PackListItem {
  pack_id: string;
  claim_id: string;
  content_hash: string;
  scope: { kind: string; ref: string };
  time_bounds: { t0_ms: number; t1_ms: number };
  claim_count: number;
  supersedes: string | null;
  issued_at_ms: number | null;
}

export const EXPORT_SCOPE_KINDS = ['mission', 'session', 'incident', 'period'] as const;

/**
 * `--scope <kind>:<ref>` as the API takes it. A period's ref is the whole `period:<range>` (the service reads the
 * prefix), so `period:2026-Q3` is sent as kind `period`, ref `period:2026-Q3`; the doubled `period:period:2026-Q3`
 * that earlier versions needed means the same. Null for a kind STACK does not export.
 */
export function parseExportScope(arg: string): { kind: (typeof EXPORT_SCOPE_KINDS)[number]; ref: string } | null {
  const sep = arg.indexOf(':');
  if (sep < 0) return null;
  const kind = arg.slice(0, sep) as (typeof EXPORT_SCOPE_KINDS)[number];
  if (!EXPORT_SCOPE_KINDS.includes(kind)) return null;
  const ref = arg.slice(sep + 1);
  if (kind === 'period') return { kind, ref: ref.startsWith('period:') ? ref : `period:${ref}` };
  return { kind, ref };
}

async function cmdExport(args: string[], json: boolean): Promise<void> {
  const scopeArg = takeFlag(args, '--scope');
  if (typeof scopeArg !== 'string' || !scopeArg.includes(':')) {
    stderr.write(
      `usage: ${invokeHint("evidence-pack export --scope mission:<id> [--supersedes pck_*] [--output pack.json] [--air-gap]")}\n`,
    );
    exit(2);
  }
  const scope = parseExportScope(scopeArg);
  if (!scope) {
    stderr.write(
      `error: --scope must start with one of ${EXPORT_SCOPE_KINDS.join(' | ')} (got '${scopeArg.slice(0, scopeArg.indexOf(':'))}')\n`,
    );
    exit(2);
  }
  const { kind: scopeKindRaw, ref: scopeRef } = scope;

  const supersedes = takeFlag(args, '--supersedes');
  const outputPath = takeFlag(args, '--output');
  const airGap = takeFlag(args, '--air-gap') === true;

  const body: Record<string, unknown> = {
    scope: { kind: scopeKindRaw, ref: scopeRef },
  };
  if (typeof supersedes === 'string') body.supersedes = supersedes;
  if (airGap) body.air_gap = true;

  const result = await api<{
    pack_id: string;
    claim_id: string;
    pack_claim: Record<string, unknown>;
    manifest: Record<string, unknown>;
  }>('POST', '/v1/evidence-packs', { body });

  // Default output path: <pack_id>.json in cwd. --output overrides.
  const target = typeof outputPath === 'string' ? outputPath : `${result.pack_id}.json`;
  writeFileSync(target, JSON.stringify(result.manifest, null, 2), 'utf8');

  if (json) {
    printJson({ pack_id: result.pack_id, claim_id: result.claim_id, output: target });
    return;
  }
  stdout.write(`Exported ${result.pack_id} → ${target} (claim_id=${result.claim_id})\n`);
}

async function cmdList(args: string[], json: boolean): Promise<void> {
  const scope = takeFlag(args, '--scope');
  const params = new URLSearchParams();
  if (typeof scope === 'string') params.set('scope', scope);
  const suffix = params.toString();
  const result = await api<{ items: PackListItem[] }>(
    'GET',
    `/v1/evidence-packs${suffix ? `?${suffix}` : ''}`,
  );
  if (json) {
    printJson(result);
    return;
  }
  if (result.items.length === 0) {
    stdout.write('No evidence packs.\n');
    return;
  }
  printTable(
    ['pack_id', 'scope', 'claims', 'content_hash', 'exported'],
    result.items.map((p) => [
      p.pack_id,
      `${p.scope.kind}:${p.scope.ref}`,
      String(p.claim_count),
      p.content_hash.slice(0, 19) + '…',
      p.issued_at_ms ? fmtTs(new Date(p.issued_at_ms).toISOString()) : '-',
    ]),
  );
}

async function cmdGet(packId: string, json: boolean): Promise<void> {
  const result = await api<Record<string, unknown>>(
    'GET',
    `/v1/evidence-packs/${encodeURIComponent(packId)}`,
  );
  printJson(result);
  void json;
}

export async function cmdEvidencePack(argv: string[]): Promise<void> {
  const args = [...argv];
  const json = takeFlag(args, '--json') === true;
  const sub = args.shift();
  const arg1 = args[0];

  if (sub === 'export') {
    return cmdExport(args, json);
  }
  if (sub === 'list') {
    return cmdList(args, json);
  }
  if (sub === 'get' || sub === 'show') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('evidence-pack get <pack-id>')}\n`);
      exit(2);
    }
    return cmdGet(arg1, json);
  }

  stderr.write(
    `error: unknown evidence-pack subcommand "${sub ?? ''}".\n` +
      `Use export | list | get\n`,
  );
  exit(2);
}
