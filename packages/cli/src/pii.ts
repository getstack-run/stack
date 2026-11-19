// `stack pii` — per-operator PII redaction config.
//
// Wraps GET/PUT/DELETE /v1/pii/config. Two dials over the scored PII scanner
// in the LLM gateway:
//
//   threshold  how much confidence to demand before redacting (0-1).
//              HIGHER redacts LESS. Built-in default is 0.4.
//   countries  which countries' identifier schemes to run at all.
//              Unset means every country, which is safe and noisy.
//
// The pair is the point. Scope to the countries you actually work in, then
// lower the threshold: bare-format identifiers start redacting without every
// order number in your traffic getting eaten.
//
// Every change applies at once and asks no one, loosening included.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printRecord } from './format.js';

interface PiiConfig {
  configured: boolean;
  enabled: boolean;
  threshold: number;
  countries: string[] | null;
  direction?: string;
}

async function cmdShow(json: boolean): Promise<void> {
  const out = await api<PiiConfig>('GET', '/v1/pii/config');
  if (json) return printJson(out);
  printRecord({
    ...out,
    countries: out.countries === null ? '(every country)' : out.countries.join(', '),
    configured: out.configured ? 'yes' : 'no (running on built-in defaults)',
  } as unknown as Record<string, unknown>);
}

async function cmdSet(args: string[], json: boolean): Promise<void> {
  const threshold = takeFlag(args, '--threshold');
  const countries = takeFlag(args, '--countries');
  const enable = takeFlag(args, '--enable');
  const disable = takeFlag(args, '--disable');

  const body: Record<string, unknown> = {};
  if (typeof threshold === 'string') {
    const n = Number(threshold);
    if (!Number.isFinite(n) || n < 0 || n > 1) {
      stderr.write(`error: --threshold must be a number between 0 and 1 (got "${threshold}")\n`);
      exit(2);
    }
    body.threshold = n;
  }
  if (typeof countries === 'string') {
    // `--countries all` is how you widen back to every country: an empty
    // string would be ambiguous with "clear the flag".
    body.countries =
      countries.toLowerCase() === 'all'
        ? null
        : countries.split(',').map((c) => c.trim().toUpperCase()).filter(Boolean);
  }
  if (enable) body.enabled = true;
  if (disable) body.enabled = false;

  if (Object.keys(body).length === 0) {
    stderr.write(
      `usage: ${invokeHint('pii set [--threshold <0-1>] [--countries SE,NO,DK|all] [--enable|--disable]')}\n`
      + '\n'
      + '  --threshold  confidence needed to redact. HIGHER redacts LESS. Default 0.4.\n'
      + '  --countries  ISO 3166-1 alpha-2 codes, comma separated, or "all".\n'
      + '               Email, card, IBAN and IP always scan regardless.\n'
      + '\n'
      + `example: ${invokeHint('pii set --countries SE,NO,DK --threshold 0.2')}\n`
      + '  scopes to the Nordics and lowers the bar, so bare-format personal\n'
      + '  numbers redact without every order number being caught with them.\n',
    );
    exit(2);
  }

  const out = await api<PiiConfig>('PUT', '/v1/pii/config', { body });
  if (json) return printJson(out);
  printRecord(out as unknown as Record<string, unknown>);
}

async function cmdReset(json: boolean): Promise<void> {
  const out = await api('DELETE', '/v1/pii/config');
  if (json) return printJson(out);
  stdout.write('PII redaction config reset to built-in defaults\n');
}

export async function cmdPii(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];

  if (sub === 'show' || sub === 'get' || sub === undefined) return cmdShow(json);
  if (sub === 'set' || sub === 'configure') return cmdSet(args.slice(1), json);
  if (sub === 'reset') return cmdReset(json);

  stderr.write(
    `error: unknown pii subcommand "${sub}".\nUse show | set | reset\n`,
  );
  exit(2);
}
