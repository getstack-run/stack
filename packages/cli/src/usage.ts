// `usage` — the one-screen usage + spend + earnings rollup. Wraps GET /v1/usage
// (server-computed) so the CLI, dashboard, and MCP all read one authoritative
// shape. Consumption on the left (what you used vs your plan), spend on the
// right (what it cost), then wallet + earnings.
//
// A window can be scoped with --period <preset> or --since/--until. Presets are
// resolved to a [since, until) window in LOCAL time here (so "today" means the
// user's day); the server only ever speaks raw since/until. When a window is
// set, the flow meters (spend, passports, dropoffs, skill invocations, proxy)
// count within it, and the inventory meters (agents, published skills) show
// "N now · +M new" — current active count plus created-in-window — because
// "how many agents existed last week" is not a real number.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag } from './api.js';
import { printJson, fmt } from './format.js';

interface UsageMeter {
  used: number;
  limit: number | null;
  created_in_window?: number;
}

interface UsageResponse {
  plan: 'platform' | 'internal' | 'contract' | 'none';
  /** @deprecated No longer sent; read `plan`. */
  tier?: string;
  period_start: string;
  period_end: string | null;
  period_label: string;
  consumption: {
    activity: {
      total: number;
      non_metered: number | null;
      total_coverage: 'complete' | 'lower_bound';
    };
    // One meter. The five per-domain keys below are deprecated and carry a
    // null limit — see packages/sdk/src/types.ts for the full note.
    actions: UsageMeter & {
      allowance_coverage: 'complete' | 'unavailable';
      allowance_plan: 'platform' | 'internal' | 'contract' | 'none' | null;
      by_kind?: Record<string, number>;
      detail_coverage: 'complete' | 'partial' | 'unavailable';
      // Present only for a white-label pool (a partner or one of its
      // tenants): `used` is then the whole pool, `own_used` this account's
      // share, and `tenants` how many tenant accounts share the pool.
      pooled?: true;
      own_used?: number;
      tenants?: number;
    };
    agents: UsageMeter;
    published_skills: UsageMeter;
    passports: UsageMeter;
    proxy_calls: UsageMeter;
    dropoffs: UsageMeter;
    skill_invocations: UsageMeter;
  };
  seats: { used: number; included: number | null; purchased: number; total: number | null };
  /** Null under a since/until window - the pass-through counters only
   * exist for the current month (Redis, ~35-day expiry), so a windowed
   * request gets honest absence rather than the wrong month's numbers. */
  passthrough: {
    l3_classifications: { used: number; included: number | null };
    sms: { used: number; included: number | null };
    email: { used: number; included: number | null };
  } | null;
  unlimited: {
    agents: number;
    service_connections: number;
    published_skills: number;
    inbound_webhook_endpoints: number;
  };
  retention: { days: number | null; negotiated: boolean };
  spend_cents: {
    skills: number;
    llm_compute: number;
    identity: number;
    overage: number;
    total: number;
  };
  wallet_cents: { balance: number };
  earnings_cents: { unpaid: number; lifetime: number };
}

const PRESETS = [
  'today',
  'yesterday',
  '7d',
  'week',
  '30d',
  'month',
  'last-month',
  'billing',
] as const;
export type Preset = (typeof PRESETS)[number];

export interface ResolvedPeriod {
  since?: Date; // omitted for 'billing' — server uses the operator's billing period
  until?: Date;
  label: string; // human label for the header ("last 7 days", "yesterday", ...)
}

/**
 * Resolve a period preset to a [since, until) window in LOCAL time. Pure —
 * `now` is injected so it's deterministic under test. 'billing' returns no
 * bounds (the server default). `week` is an alias for `7d`.
 */
export function resolvePeriod(preset: Preset, now: Date): ResolvedPeriod {
  const startOfDay = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const today0 = startOfDay(now);
  switch (preset) {
    case 'billing':
      return { label: 'billing period' };
    case 'today':
      return { since: today0, until: now, label: 'today' };
    case 'yesterday': {
      const y0 = new Date(today0);
      y0.setDate(y0.getDate() - 1);
      return { since: y0, until: today0, label: 'yesterday' };
    }
    case '7d':
    case 'week': {
      const s = new Date(now);
      s.setDate(s.getDate() - 7);
      return { since: s, until: now, label: 'last 7 days' };
    }
    case '30d': {
      const s = new Date(now);
      s.setDate(s.getDate() - 30);
      return { since: s, until: now, label: 'last 30 days' };
    }
    case 'month': {
      const s = new Date(now.getFullYear(), now.getMonth(), 1);
      return { since: s, until: now, label: 'this month' };
    }
    case 'last-month': {
      const s = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      const u = new Date(now.getFullYear(), now.getMonth(), 1);
      return { since: s, until: u, label: 'last month' };
    }
  }
}

/** 1234567 -> "1,234,567" */
function group(n: number): string {
  return n.toLocaleString('en-US');
}

/** cents -> "$12.40" */
function usd(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

/** "used / limit" with ∞ for an uncapped meter. */
function meter(m: UsageMeter): string {
  return `${group(m.used)} / ${m.limit === null ? '∞' : group(m.limit)}`;
}

/**
 * The actions meter. A white-label pool reads "Pool: 1,200 / 10,000 (your
 * share: 300, 4 tenants)", because the allowance gates the pool, not this
 * account alone. Exported for tests.
 */
export function actionsMeter(a: UsageResponse['consumption']['actions']): string {
  const base =
    a.allowance_coverage === 'complete'
      ? meter(a)
      : `${group(a.used)} / unknown historical limit`;
  if (!a.pooled) return base;
  const tenants = a.tenants ?? 0;
  return `Pool: ${base} (your share: ${group(a.own_used ?? 0)}, ${group(tenants)} ${tenants === 1 ? 'tenant' : 'tenants'})`;
}

/**
 * Inventory meter under a window: "16 now · +2 new" — current active count
 * plus created-in-window. Falls back to the plain meter when not windowed.
 */
function inventoryMeter(m: UsageMeter, windowed: boolean): string {
  if (!windowed || m.created_in_window === undefined) return meter(m);
  return `${group(m.used)} now · ${fmt.bold(`+${group(m.created_in_window)}`)} new`;
}

/** Short ISO date (YYYY-MM-DD) or "now". */
function day(iso: string | null): string {
  return iso ? iso.slice(0, 10) : 'now';
}

/** Parse --since/--until (ISO-8601 or unix-ms). Exits 2 on an unparseable value. */
function parseTime(v: string, flag: string): Date {
  const d = /^\d+$/.test(v) ? new Date(Number(v)) : new Date(v);
  if (Number.isNaN(d.getTime())) {
    stderr.write(`error: ${flag} "${v}" is not a valid ISO-8601 date or unix-ms timestamp\n`);
    exit(2);
  }
  return d;
}

export async function cmdUsage(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const periodArg = takeFlag(args, '--period');
  const sinceArg = takeFlag(args, '--since');
  const untilArg = takeFlag(args, '--until');

  if (periodArg && (sinceArg || untilArg)) {
    stderr.write('error: --period cannot be combined with --since/--until\n');
    exit(2);
  }

  const query: Record<string, string> = {};
  let windowLabel = 'billing period';

  if (typeof periodArg === 'string') {
    if (!(PRESETS as readonly string[]).includes(periodArg)) {
      stderr.write(`error: unknown --period "${periodArg}". One of: ${PRESETS.join(', ')}\n`);
      exit(2);
    }
    const win = resolvePeriod(periodArg as Preset, new Date());
    if (win.since) query.since = win.since.toISOString();
    if (win.until) query.until = win.until.toISOString();
    windowLabel = win.label;
  } else if (typeof sinceArg === 'string' || typeof untilArg === 'string') {
    if (typeof sinceArg === 'string') query.since = parseTime(sinceArg, '--since').toISOString();
    if (typeof untilArg === 'string') query.until = parseTime(untilArg, '--until').toISOString();
    windowLabel = 'custom range';
  }

  const u = await api<UsageResponse>('GET', '/v1/usage', { query });
  /** `used / included` for a pass-through allowance; `included` may be null. */
  function passthrough(p: { used: number; included: number | null }): string {
    return `${p.used} / ${p.included ?? '∞'}`;
  }
  if (json) return printJson(u);

  const windowed = u.period_label !== 'billing';
  const c = u.consumption;
  const s = u.spend_cents;

  // Two side-by-side blocks: consumption meters (left), spend lines (right).
  // A null row is a blank spacer; 'rule' is the separator before the total.
  // The meter first, because it is the only number that gates anything. The
  // Total activity and the metered subset are different clocks. Keep both
  // visible. Do not render a partial historical kind split as a set of zeros.
  const left: Array<[string, string] | null> = [
    [
      'Total actions',
      c.activity.total_coverage === 'complete'
        ? group(c.activity.total)
        : `${group(c.activity.total)}+`,
    ],
    ['Metered actions', actionsMeter(c.actions)],
    ['Not metered', c.activity.non_metered === null ? 'unknown' : group(c.activity.non_metered)],
    ...(c.actions.detail_coverage === 'complete'
      ? []
      : ([['Action detail', c.actions.detail_coverage]] as Array<[string, string]>)),
    ['Team members', String(u.seats.used)],
    null,
    // Absent under a window: the pass-through counters only exist for the
    // current month, and the server sends null rather than the wrong one.
    ...(u.passthrough
      ? ([
          ['L3 classify', passthrough(u.passthrough.l3_classifications)],
          ['SMS', passthrough(u.passthrough.sms)],
          ['Email', passthrough(u.passthrough.email)],
          null,
        ] as Array<[string, string] | null>)
      : []),
    ['Agents', inventoryMeter(c.agents, windowed)],
    ['Pub. skills', inventoryMeter(c.published_skills, windowed)],
  ];
  const right: Array<[string, string] | 'rule' | null> = [
    ['Skills', usd(s.skills)],
    ['LLM / compute', usd(s.llm_compute)],
    ['Identity', usd(s.identity)],
    ['Overage', usd(s.overage)],
    'rule',
    ['Total spent', usd(s.total)],
  ];

  // Visible width ignores ANSI color codes (inventoryMeter emits them).
  // eslint-disable-next-line no-control-regex -- strips ANSI color escape sequences from terminal output
  const vlen = (str: string) => str.replace(/\x1b\[[0-9;]*m/g, '').length;
  const lLabelW = Math.max(...left.map((r) => (r ? r[0].length : 0)));
  const lValW = Math.max(...left.map((r) => (r ? vlen(r[1]) : 0)));
  const rLabelW = Math.max(...right.map((r) => (Array.isArray(r) ? r[0].length : 0)));
  const leftBlockW = lLabelW + 2 + lValW;

  const leftCell = (i: number): string => {
    const row = left[i];
    if (!row) return ' '.repeat(leftBlockW);
    const pad = ' '.repeat(Math.max(0, lValW - vlen(row[1])));
    return `${fmt.dim(row[0].padEnd(lLabelW))}  ${pad}${row[1]}`;
  };
  const rightCell = (i: number): string => {
    const row = right[i];
    if (!row) return '';
    if (row === 'rule') return fmt.dim('─'.repeat(rLabelW + 2 + 8));
    const isTotal = row[0] === 'Total spent';
    const label = isTotal ? fmt.bold(row[0].padEnd(rLabelW)) : fmt.dim(row[0].padEnd(rLabelW));
    const value = isTotal ? fmt.bold(row[1]) : row[1];
    return `${label}  ${value}`;
  };

  const windowText = windowed
    ? `${windowLabel} (${day(u.period_start)} → ${day(u.period_end)})`
    : `billing period ${day(u.period_start)} → ${day(u.period_end)}`;
  stdout.write(
    `${fmt.dim('window')} ${windowText}\n\n`,
  );
  const gap = '     ';
  const spendHeader = windowed ? 'SPEND (window)' : 'SPEND (this period)';
  stdout.write(`${fmt.bold('CONSUMPTION'.padEnd(leftBlockW))}${gap}${fmt.bold(spendHeader)}\n`);
  const rowCount = Math.max(left.length, right.length);
  for (let i = 0; i < rowCount; i++) {
    stdout.write(`  ${leftCell(i)}${gap}${rightCell(i)}\n`);
  }

  stdout.write(
    `\n${fmt.bold('WALLET')}  balance ${usd(u.wallet_cents.balance)}` +
      `     ${fmt.bold('EARNINGS')}  unpaid ${usd(u.earnings_cents.unpaid)} · lifetime ${usd(u.earnings_cents.lifetime)}\n`,
  );
}
