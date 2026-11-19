// Output formatting helpers — table for terminal humans, JSON for
// pipes + scripts. Every command supports `--json` to switch from
// the table to a machine-readable dump.

import { stdout, env } from 'node:process';

const useColor = stdout.isTTY === true && !env['NO_COLOR'];
const color = (n: string) => (useColor ? `\x1b[${n}m` : '');
const C = {
  reset: color('0'),
  bold: color('1'),
  dim: color('2'),
  gray: color('90'),
  cyan: color('36'),
  green: color('32'),
  yellow: color('33'),
  red: color('31'),
};

/** Print rows as an aligned table. Headers are bold/dim. */
export function printTable(headers: string[], rows: string[][]): void {
  if (rows.length === 0) {
    stdout.write(`${C.gray}(no results)${C.reset}\n`);
    return;
  }
  const widths = headers.map((h, i) =>
    Math.max(
      h.length,
      ...rows.map((r) => stripAnsi(r[i] ?? '').length),
    ),
  );
  const headerLine = headers.map((h, i) => `${C.dim}${C.bold}${h.padEnd(widths[i] ?? 0)}${C.reset}`).join('  ');
  stdout.write(`${headerLine}\n`);
  for (const row of rows) {
    const line = row.map((cell, i) => {
      const visibleLen = stripAnsi(cell ?? '').length;
      const pad = ' '.repeat(Math.max(0, (widths[i] ?? 0) - visibleLen));
      return `${cell ?? ''}${pad}`;
    }).join('  ');
    stdout.write(`${line}\n`);
  }
}

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex -- strips ANSI color escape sequences from terminal output
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

export function printJson(data: unknown): void {
  stdout.write(JSON.stringify(data, null, 2) + '\n');
}

/** Render a single record as label/value lines. */
/** Fields whose VALUE is a secret, or a thin wrapper around one.
 *
 * `service_connections.credential_encrypted` comes back on a create response,
 * and in dev the KMS is a base64 mock — so printing it put the credential
 * straight into the operator's scrollback. That defeats the entire point of
 * reading it from stdin without echo. Masked everywhere rather than at the one
 * call site that noticed, because every other command prints records the same
 * way and the next one to return this field would leak it again.
 *
 * --json is deliberately NOT filtered: that output is for piping into a tool,
 * the caller asked for the raw shape, and it is not what lands in scrollback
 * by accident.
 */
const SECRET_KEYS = /credential|secret|api_key|token|password/i;

export function printRecord(record: Record<string, unknown>): void {
  const labelWidth = Math.max(...Object.keys(record).map((k) => k.length));
  for (const [k, v] of Object.entries(record)) {
    if (SECRET_KEYS.test(k) && v !== null && v !== undefined && v !== '') {
      stdout.write(`  ${C.gray}${k.padEnd(labelWidth)}${C.reset}  ${C.gray}[hidden]${C.reset}
`);
      continue;
    }
    const value = v === null || v === undefined
      ? `${C.gray}—${C.reset}`
      : typeof v === 'object'
        ? JSON.stringify(v)
        : String(v);
    stdout.write(`  ${C.gray}${k.padEnd(labelWidth)}${C.reset}  ${value}\n`);
  }
}

/** Tone helpers for table cells. */
export const fmt = {
  ok: (s: string) => `${C.green}${s}${C.reset}`,
  warn: (s: string) => `${C.yellow}${s}${C.reset}`,
  err: (s: string) => `${C.red}${s}${C.reset}`,
  dim: (s: string) => `${C.gray}${s}${C.reset}`,
  bold: (s: string) => `${C.bold}${s}${C.reset}`,
};

/** Render a timestamp (ISO string or unix-ms) as a compact short form. */
export function fmtTs(ts: string | number | null | undefined): string {
  if (ts === null || ts === undefined) return fmt.dim('—');
  const d = typeof ts === 'number' ? new Date(ts) : new Date(ts);
  if (Number.isNaN(d.getTime())) return fmt.dim('—');
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }
  return `${d.toLocaleDateString('en-CA')}`;
}

function pad(n: number): string {
  return String(n).padStart(2, '0');
}
