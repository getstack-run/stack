const SAFE_ERROR_NAMES = new Set([
  'Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError',
  'URIError', 'AggregateError', 'AbortError', 'TimeoutError', 'ZodError',
  'PostgresError',
]);
const SAFE_ERROR_CODES = new Set([
  'ECONNABORTED', 'ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'EPIPE',
  'ETIMEDOUT', 'ENETUNREACH', 'ENOTFOUND', 'EAI_AGAIN',
  'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_SOCKET',
]);
// Fixed deployment labels. A `site` tag with any other value is dropped.
const SAFE_SITES = new Set(['api', 'worker', 'mcp', 'dashboard']);
const SQLSTATE = /^[0-9A-Z]{5}$/u;
const PG_IDENTIFIER = /^[a-z0-9_]{1,63}$/u;
// eslint-disable-next-line no-useless-escape -- this validator is pinned byte for byte by the telemetry security test and mirrored in the dashboard
const CONSOLE_LABEL = /^[A-Za-z \[\]:_\-.]{1,80}$/u;
const FRAME_BASENAME = /^[\w.-]+\.(?:js|ts|mjs)$/u;
const RELEASE_SHA = /^[0-9a-f]{40}$/u;
const ROUTE_TEMPLATE = /^\/[A-Za-z0-9_\-.:/*]{0,199}$/u;
const MAX_CAUSE_DEPTH = 5;
const MAX_ROUTE_TEMPLATES = 4096;
const INSTALLED = Symbol.for('stack.safe-console-installed');
const ROUTE_REGISTRY = Symbol.for('stack.safe-route-templates');

export interface SafeErrorSummary {
  name: string;
  code?: string;
  /** Postgres SQLSTATE from any level of the `.cause` chain. */
  pg_code?: string;
  /** Postgres table name (a schema identifier, never row data). */
  table?: string;
  /** Postgres constraint name (a schema identifier, never row data). */
  constraint?: string;
  /** A route TEMPLATE registered at startup, never a request URL. */
  route?: string;
}

function safeName(value: unknown): string {
  return typeof value === 'string' && SAFE_ERROR_NAMES.has(value) ? value : 'Error';
}

function safeCode(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  if (SAFE_ERROR_CODES.has(value) || /^FST_ERR_[A-Z0-9_]{1,64}$/u.test(value) || /^\d{5}$/u.test(value)) {
    return value;
  }
  return undefined;
}

function matching(pattern: RegExp, value: unknown): string | undefined {
  return typeof value === 'string' && pattern.test(value) ? value : undefined;
}

function routeRegistry(): Set<string> {
  // Shared through the global symbol registry so a second copy of this module
  // (bundled or dual-loaded) sees the templates the server registered.
  const holder = globalThis as typeof globalThis & { [ROUTE_REGISTRY]?: Set<string> };
  holder[ROUTE_REGISTRY] ??= new Set<string>();
  return holder[ROUTE_REGISTRY];
}

/**
 * Record a route template at registration time (Fastify `onRoute`). Only
 * registered templates are ever emitted as a `route` field or tag, so a raw
 * request path that happens to look like a template can never pass through.
 */
export function registerSafeRouteTemplate(template: unknown): void {
  if (typeof template !== 'string' || !ROUTE_TEMPLATE.test(template)) return;
  const registry = routeRegistry();
  if (registry.size < MAX_ROUTE_TEMPLATES) registry.add(template);
}

/** Return the value only when it is a registered route template. */
export function safeRouteTemplate(value: unknown): string | undefined {
  return typeof value === 'string' && routeRegistry().has(value) ? value : undefined;
}

/**
 * Sentry release identifier: `stack-<app>@<40-hex commit>` or undefined. The
 * commit comes from STACK_RELEASE_SHA, which the deploy workflow sets from
 * its already-validated candidate SHA. Anything else leaves release unset.
 */
export function safeSentryRelease(app: string, sha: unknown): string | undefined {
  if (!/^[a-z][a-z-]{0,31}$/u.test(app)) return undefined;
  const commit = matching(RELEASE_SHA, sha);
  return commit ? `stack-${app}@${commit}` : undefined;
}

function isPostgresShaped(record: Record<string, unknown>): boolean {
  return record['name'] === 'PostgresError' || typeof record['severity'] === 'string';
}

/**
 * Summarise an error to fixed, validated fields. Follows `.cause` up to five
 * levels, so a Drizzle query error keeps its Postgres SQLSTATE, table and
 * constraint. Messages, SQL, parameters, detail, hint and column values are
 * never read. Summarising a summary returns the same summary.
 */
export function safeErrorSummary(error: unknown): SafeErrorSummary {
  if (!error || typeof error !== 'object') return { name: 'Error' };
  try {
    const outer = error as Record<string, unknown>;
    const summary: SafeErrorSummary = { name: safeName(outer['name']) };
    const route = safeRouteTemplate(outer['route']);
    const seen = new Set<unknown>();
    let current: unknown = error;
    for (let depth = 0; depth <= MAX_CAUSE_DEPTH; depth += 1) {
      if (!current || typeof current !== 'object' || seen.has(current)) break;
      seen.add(current);
      try {
        const record = current as Record<string, unknown>;
        const code = record['code'];
        summary.code ??= safeCode(code);
        // A bare 5-character code could be EPIPE; only a Postgres-shaped
        // error (postgres.js PostgresError, or any error with a severity)
        // contributes its code as a SQLSTATE. A `pg_code` key is an earlier
        // summary being summarised again.
        const levelPgCode = matching(SQLSTATE, record['pg_code'])
          ?? (isPostgresShaped(record) && typeof code === 'string' && !SAFE_ERROR_CODES.has(code)
            ? matching(SQLSTATE, code)
            : undefined);
        if (levelPgCode !== undefined) {
          // Identifiers are read only from the level that carries the
          // SQLSTATE, so an unrelated object's `table` property (which could
          // hold a lowercase token) is never mistaken for a schema name.
          summary.pg_code ??= levelPgCode;
          summary.table ??= matching(PG_IDENTIFIER, record['table_name'])
            ?? matching(PG_IDENTIFIER, record['table']);
          summary.constraint ??= matching(PG_IDENTIFIER, record['constraint_name'])
            ?? matching(PG_IDENTIFIER, record['constraint']);
        }
        current = record['cause'];
      } catch {
        break;
      }
    }
    if (route !== undefined) summary.route = route;
    for (const key of ['code', 'pg_code', 'table', 'constraint'] as const) {
      if (summary[key] === undefined) delete summary[key];
    }
    return summary;
  } catch {
    // Proxies and hostile getter properties must not make the logging guard
    // throw while an application is already handling another failure.
    return { name: 'Error' };
  }
}

function safeScalar(value: unknown, max = 160): string | number | boolean | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'boolean') return value;
  if (typeof value !== 'string') return undefined;
  return value
    .replace(/[?#].*$/u, '')
    .replace(/\s+/gu, ' ')
    .slice(0, max);
}

function safeFrameBasename(item: Record<string, unknown>): string | undefined {
  // Only our own code. Third-party and unknown frames keep no file name.
  if (item['in_app'] !== true || typeof item['filename'] !== 'string') return undefined;
  const parts = item['filename'].split(/[\\/]/u);
  return matching(FRAME_BASENAME, parts[parts.length - 1]);
}

function safeStacktrace(value: unknown): unknown {
  if (!value || typeof value !== 'object') return undefined;
  const frames = (value as { frames?: unknown }).frames;
  if (!Array.isArray(frames)) return undefined;
  return {
    frames: frames.slice(-80).map((frame) => {
      if (!frame || typeof frame !== 'object') return {};
      const item = frame as Record<string, unknown>;
      // Raw filenames can be URLs (including query credentials) or local
      // paths containing user data. Only the validated basename of an in-app
      // frame is kept; directories, queries and vendor paths never are.
      const basename = safeFrameBasename(item);
      return {
        ...(basename !== undefined ? { filename: basename } : {}),
        function: safeScalar(item['function'], 160),
        lineno: safeScalar(item['lineno']),
        colno: safeScalar(item['colno']),
        in_app: safeScalar(item['in_app']),
      };
    }),
  };
}

/**
 * Build a deliberately small Sentry event. Error messages, request bodies,
 * headers, cookies, query strings, extras, breadcrumbs, user data, contexts,
 * causes and client configuration are never copied.
 */
export function sanitizeSentryEvent<T>(event: T, hint?: unknown): T {
  if (!event || typeof event !== 'object') return event;
  const input = event as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  for (const key of ['event_id', 'timestamp', 'platform', 'level', 'release', 'environment']) {
    const safe = safeScalar(input[key], 200);
    if (safe !== undefined) output[key] = safe;
  }

  const request = input['request'];
  if (request && typeof request === 'object') {
    const source = request as Record<string, unknown>;
    const method = safeScalar(source['method'], 16);
    if (method !== undefined) output['request'] = { method };
  }

  const exception = input['exception'];
  const values = exception && typeof exception === 'object'
    ? (exception as { values?: unknown }).values
    : undefined;
  if (Array.isArray(values)) {
    output['exception'] = {
      values: values.slice(0, 8).map((value) => {
        const item = value && typeof value === 'object'
          ? value as Record<string, unknown>
          : {};
        return {
          type: safeName(item['type']),
          value: 'Error details suppressed',
          stacktrace: safeStacktrace(item['stacktrace']),
        };
      }),
    };
  }

  const safeTags: Record<string, string | number | boolean> = {};
  const tags = input['tags'];
  if (tags && typeof tags === 'object') {
    // Routes and transaction names can contain raw URLs or path credentials.
    // Keep only values whose source is a fixed application label.
    const allowed = ['method', 'source', 'surface', 'kind'];
    const sourceTags = tags as Record<string, unknown>;
    for (const key of allowed) {
      const safe = safeScalar(sourceTags[key], 120);
      if (safe !== undefined) safeTags[key] = safe;
    }
    // Validated tags: a registered route template, a fixed site label and a
    // SQLSTATE. Any other value under these keys is dropped.
    const route = safeRouteTemplate(sourceTags['route']);
    if (route !== undefined) safeTags['route'] = route;
    const site = sourceTags['site'];
    if (typeof site === 'string' && SAFE_SITES.has(site)) safeTags['site'] = site;
    const pgCode = matching(SQLSTATE, sourceTags['pg_code']);
    if (pgCode !== undefined) safeTags['pg_code'] = pgCode;
  }
  if (safeTags['pg_code'] === undefined && hint && typeof hint === 'object') {
    try {
      const original = (hint as { originalException?: unknown }).originalException;
      const pgCode = safeErrorSummary(original).pg_code;
      if (pgCode !== undefined) safeTags['pg_code'] = pgCode;
    } catch {
      // A hostile hint must not break event delivery.
    }
  }
  if (Object.keys(safeTags).length > 0) output['tags'] = safeTags;

  return output as T;
}

/**
 * Last-resort process guard for runtime warnings/errors. It preserves the
 * caller's first argument only when it is a fixed label (letters, spaces and
 * `[]:_-.`; no digits, `@`, `/`, `=` or quotes, which excludes interpolated
 * data), plus non-sensitive error summaries. Callers should still prefer
 * structured logs with safeErrorSummary at the source.
 */
export function installSafeConsoleTelemetry(): void {
  const target = console as Console & { [INSTALLED]?: boolean };
  if (target[INSTALLED]) return;
  target[INSTALLED] = true;

  for (const level of ['error', 'warn'] as const) {
    const original = console[level].bind(console);
    console[level] = (...args: unknown[]) => {
      const label = matching(CONSOLE_LABEL, args[0]);
      const summaries = args.flatMap((arg) => {
        try {
          return arg instanceof Error
            || (arg !== null && typeof arg === 'object' && ('name' in arg || 'code' in arg))
            ? [safeErrorSummary(arg)]
            : [];
        } catch {
          return [];
        }
      });
      original(`Application ${level}`, ...(label !== undefined ? [label] : []), ...summaries);
    };
  }
}
