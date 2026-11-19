#!/usr/bin/env node
// stack-verify CLI — `npx @getstackrun/verify pack.json [flags]`.
//
// Reads a manifest JSON from disk (or stdin via `-`), runs the full
// verifier, prints a human-friendly or `--json` summary, and exits
// with 0 (valid) or 1 (invalid). Designed for grep-friendly output
// in CI pipelines + auditor scripts.

import { readFileSync } from 'node:fs';
import { argv, stdin, stdout, stderr, exit } from 'node:process';
import { verifyPack } from './verify.js';
import type { EvidencePackManifest, VerifyOptions, VerifyResult } from './types.js';

function printUsage(): void {
  stderr.write(
    [
      'stack-verify — offline STACK evidence-pack verifier',
      '',
      'usage:',
      '  stack-verify <pack.json> [flags]',
      '  stack-verify - < pack.json',
      '',
      'flags:',
      '  --air-gap          use embedded material only; unavailable external',
      '                     trust checks make the result incomplete.',
      '  --strict           fail on any claim_type without an inline schema.',
      '  --ignore-unknown   skip unknown claim_types with one warning. Mutually',
      '                     exclusive with --strict.',
      '  --fresh-jwks       re-fetch JWKS from URL even when inline copy exists',
      '                     (reserved for v2; v1 always uses inline).',
      '  --activity         reconstruct mission activity from signed claim envelopes.',
      '  --replay           compatibility alias for --activity.',
      '  --json             machine-readable output.',
      '  --help             this text.',
      '',
      'examples:',
      '  npx @getstackrun/verify pack.json --air-gap',
      '  npx @getstackrun/verify pack.json --strict --json | jq',
      '',
    ].join('\n'),
  );
}

async function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    stdin.setEncoding('utf8');
    stdin.on('data', (chunk: string) => {
      data += chunk;
    });
    stdin.on('end', () => resolve(data));
    stdin.on('error', reject);
  });
}

async function main(): Promise<void> {
  const args = argv.slice(2);
  if (args.includes('--help') || args.length === 0) {
    printUsage();
    exit(args.length === 0 ? 2 : 0);
  }

  const options: VerifyOptions = {
    airGap: args.includes('--air-gap'),
    strict: args.includes('--strict'),
    ignoreUnknown: args.includes('--ignore-unknown'),
    freshJwks: args.includes('--fresh-jwks'),
    activity: args.includes('--activity'),
    replay: args.includes('--replay'),
  };
  const jsonOut = args.includes('--json');

  // Positional: pack path or '-' for stdin.
  const positional = args.find((a) => !a.startsWith('--'));
  if (!positional) {
    stderr.write('error: pack path required (or pass `-` to read stdin)\n');
    exit(2);
  }

  let raw: string;
  try {
    raw = positional === '-' ? await readStdin() : readFileSync(positional, 'utf8');
  } catch (err) {
    stderr.write(`error: cannot read pack: ${(err as Error).message}\n`);
    exit(2);
  }

  let manifest: EvidencePackManifest;
  try {
    manifest = JSON.parse(raw) as EvidencePackManifest;
  } catch (err) {
    stderr.write(`error: pack is not valid JSON: ${(err as Error).message}\n`);
    exit(2);
  }

  let result: VerifyResult;
  try {
    result = await verifyPack(manifest, options);
  } catch (err) {
    stderr.write(`error: verifier threw: ${(err as Error).message}\n`);
    exit(1);
  }

  if (jsonOut) {
    stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    printHumanReport(result);
  }

  exit(result.valid ? 0 : 1);
}

function printHumanReport(result: VerifyResult): void {
  for (const check of result.checks) {
    const mark =
      check.outcome === 'pass'
        ? '✓'
        : check.outcome === 'fail'
          ? '✗'
          : check.outcome === 'warn'
            ? '⚠'
            : '•';
    stdout.write(`${mark} ${check.name}${check.detail ? ' — ' + check.detail : ''}\n`);
  }
  stdout.write('\n');
  stdout.write(`valid: ${result.valid}\n`);
  stdout.write(`complete: ${result.complete}\n`);
  stdout.write(`pack_id: ${result.pack_id ?? '-'}\n`);
  stdout.write(
    `scope: ${result.scope ? `${result.scope.kind}:${result.scope.ref}` : '-'}\n`,
  );
  stdout.write(`claim_count: ${result.claim_count}\n`);
  if (result.timespan) {
    stdout.write(
      `timespan: ${new Date(result.timespan[0]).toISOString()} → ${new Date(result.timespan[1]).toISOString()}\n`,
    );
  }
  stdout.write(`revoked_at_export: ${result.revoked_at_export}\n`);
  stdout.write(`unknown_claim_types: ${result.unknown_claim_types}\n`);
  stdout.write(`external_anchors_verified: ${result.external_anchors_verified}\n`);
  if (result.activity) {
    stdout.write('\nactivity:\n');
    stdout.write(JSON.stringify(result.activity, null, 2) + '\n');
  }
  if (result.errors.length > 0) {
    stdout.write('\nerrors:\n');
    for (const e of result.errors) {
      stdout.write(`  [${e.code}] ${e.message}\n`);
    }
  }
  if (result.warnings.length > 0) {
    stdout.write('\nwarnings:\n');
    for (const w of result.warnings) {
      stdout.write(`  [${w.code}] ${w.message}\n`);
    }
  }
}

main().catch((err) => {
  stderr.write(`unhandled: ${(err as Error).stack ?? (err as Error).message}\n`);
  exit(1);
});
