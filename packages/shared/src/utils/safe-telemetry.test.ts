import { describe, expect, it, vi } from 'vitest';
import {
  installSafeConsoleTelemetry,
  registerSafeRouteTemplate,
  safeErrorSummary,
  safeSentryRelease,
  sanitizeSentryEvent,
} from './safe-telemetry.js';

const CANARY = 'synthetic-canary-not-a-real-secret';

/** Each test spies on console first, so the guard must wrap the fresh spy. */
function installFreshConsoleGuard(): void {
  delete (console as unknown as Record<symbol, unknown>)[Symbol.for('stack.safe-console-installed')];
  installSafeConsoleTelemetry();
}

/**
 * The shape Drizzle 0.45 + postgres.js 3.4 produce on a failed query: an
 * outer `Error` (DrizzleQueryError) carrying the SQL and params, whose cause
 * is a `PostgresError` carrying message/detail/hint and schema identifiers.
 */
function wrappedPostgresError(): Error {
  const cause = Object.assign(new Error(`relation "${CANARY}" does not exist`), {
    name: 'PostgresError',
    severity: 'ERROR',
    severity_local: 'ERROR',
    code: '42P01',
    detail: `Key (email)=(${CANARY}@example.test) already exists.`,
    hint: `Perhaps ${CANARY}`,
    where: CANARY,
    internal_query: CANARY,
    schema_name: 'public',
    table_name: 'usage_rollups',
    column_name: 'operator_id',
    constraint_name: 'usage_rollups_operator_id_fkey',
  });
  return Object.assign(new Error(`Failed query: select '${CANARY}'\nparams: ${CANARY}`), {
    query: `select * from usage_rollups where token = '${CANARY}'`,
    params: [CANARY],
    cause,
  });
}

describe('safe telemetry', () => {
  it('keeps only error class and a bounded machine code', () => {
    const error = Object.assign(new Error(CANARY), {
      code: 'ECONNRESET',
      cause: { headers: { authorization: CANARY } },
      config: { url: `https://example.test/?token=${CANARY}` },
    });
    expect(safeErrorSummary(error)).toEqual({ name: 'Error', code: 'ECONNRESET' });
    expect(JSON.stringify(safeErrorSummary(error))).not.toContain(CANARY);
  });

  it('follows the cause chain to a Postgres SQLSTATE, table and constraint, and nothing else', () => {
    const summary = safeErrorSummary(wrappedPostgresError());
    expect(summary).toEqual({
      name: 'Error',
      pg_code: '42P01',
      table: 'usage_rollups',
      constraint: 'usage_rollups_operator_id_fkey',
    });
    expect(JSON.stringify(summary)).not.toContain(CANARY);
    // Summarising a summary keeps the same fields (callers pass summaries
    // through the console guard, which summarises again).
    expect(safeErrorSummary(summary)).toEqual(summary);
  });

  it('rejects hostile values in the diagnostic fields', () => {
    const hostile = Object.assign(new Error(CANARY), {
      name: 'PostgresError',
      severity: 'ERROR',
      code: `${CANARY}`,
      pg_code: `42P01 ${CANARY}`,
      table_name: `users; ${CANARY}`,
      constraint_name: CANARY.toUpperCase(),
      route: `/v1/agents/${CANARY}`,
    });
    const summary = safeErrorSummary(hostile);
    expect(summary).toEqual({ name: 'PostgresError' });
  });

  it('reads table and constraint names only from the level that carries a SQLSTATE', () => {
    const notPostgres = Object.assign(new Error('x'), {
      table: 'sk_live_lowercase_token',
      constraint: 'another_lowercase_token',
      cause: { name: 'Error', table_name: 'sk_live_lowercase_token' },
    });
    expect(safeErrorSummary(notPostgres)).toEqual({ name: 'Error' });
  });

  it('does not treat a 5-letter network code as a SQLSTATE', () => {
    expect(safeErrorSummary(Object.assign(new Error('x'), { code: 'EPIPE' }))).toEqual({ name: 'Error', code: 'EPIPE' });
  });

  it('stops after five cause levels and survives cycles', () => {
    let error: Record<string, unknown> = { name: 'PostgresError', severity: 'ERROR', code: '23505' };
    for (let i = 0; i < 6; i += 1) error = { name: 'Error', cause: error };
    expect(safeErrorSummary(error)).toEqual({ name: 'Error' });

    const loop: Record<string, unknown> = { name: 'Error' };
    loop['cause'] = loop;
    expect(safeErrorSummary(loop)).toEqual({ name: 'Error' });
  });

  it('keeps only registered route templates', () => {
    registerSafeRouteTemplate('/v1/agents/:id');
    registerSafeRouteTemplate(`/v1/x?token=${CANARY}`);
    expect(safeErrorSummary({ name: 'Error', route: '/v1/agents/:id' })).toEqual({ name: 'Error', route: '/v1/agents/:id' });
    expect(safeErrorSummary({ name: 'Error', route: '/v1/agents/agt_123' })).toEqual({ name: 'Error' });
    expect(safeErrorSummary({ name: 'Error', route: `/v1/x?token=${CANARY}` })).toEqual({ name: 'Error' });
  });

  it('drops nested secrets from Sentry events', () => {
    const event = sanitizeSentryEvent({
      event_id: 'evt_safe',
      message: CANARY,
      request: {
        method: 'POST',
        url: `https://api.test/v1/proxy?token=${CANARY}`,
        headers: { authorization: `Bearer ${CANARY}` },
        data: { credential: CANARY },
        cookies: CANARY,
      },
      exception: {
        values: [{
          type: 'ProviderError',
          value: CANARY,
          stacktrace: { frames: [{ filename: '/app/src/file.ts', function: 'run', lineno: 4 }] },
        }],
      },
      extra: { cause: CANARY, config: { apiKey: CANARY } },
      breadcrumbs: [{ message: CANARY, data: { body: CANARY } }],
      user: { email: CANARY },
      tags: { route: `/v1/proxy?token=${CANARY}`, unsafe: CANARY, site: CANARY, pg_code: CANARY },
    });

    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain(CANARY);
    expect(event).toMatchObject({
      event_id: 'evt_safe',
      request: { method: 'POST' },
    });
    expect(event).not.toHaveProperty('request.url');
    expect(event).not.toHaveProperty('tags');
    // A frame not marked in_app keeps no file name at all.
    expect(event).not.toHaveProperty('exception.values.0.stacktrace.frames.0.filename');
  });

  it('keeps route, site, pg_code and in-app file basenames in a Sentry event, and no canary', () => {
    registerSafeRouteTemplate('/v1/admin/usage/:operatorId');
    const error = wrappedPostgresError();
    const event = sanitizeSentryEvent({
      event_id: 'evt_pg',
      release: 'stack-api@0123456789abcdef0123456789abcdef01234567',
      message: error.message,
      request: { method: 'GET', url: `https://api.test/v1/admin/usage/${CANARY}` },
      exception: {
        values: [
          {
            type: 'PostgresError',
            value: (error.cause as Error).message,
            stacktrace: { frames: [
              { filename: `/app/node_modules/postgres/src/${CANARY}.js`, function: 'parse', lineno: 1, in_app: false },
            ] },
          },
          {
            type: 'Error',
            value: error.message,
            stacktrace: { frames: [
              { filename: `/app/${CANARY}/apps/worker/dist/usage-rollup.js?k=${CANARY}`, function: 'a', lineno: 2, in_app: true },
              { filename: `/app/${CANARY}/apps/worker/dist/usage-rollup.js`, function: 'rollup', lineno: 3, in_app: true },
              { filename: `C:\\Users\\${CANARY}\\worker.ts`, function: 'tick', lineno: 4, in_app: true },
            ] },
          },
        ],
      },
      tags: { route: '/v1/admin/usage/:operatorId', site: 'worker', source: 'worker.poll' },
    }, { originalException: error });

    expect(JSON.stringify(event)).not.toContain(CANARY);
    expect(event).toMatchObject({
      release: 'stack-api@0123456789abcdef0123456789abcdef01234567',
      tags: { route: '/v1/admin/usage/:operatorId', site: 'worker', source: 'worker.poll', pg_code: '42P01' },
    });
    const values = (event as { exception: { values: Array<{ type: string; value: string; stacktrace: { frames: Array<Record<string, unknown>> } }> } }).exception.values;
    expect(values.map((v) => v.type)).toEqual(['PostgresError', 'Error']);
    expect(values.every((v) => v.value === 'Error details suppressed')).toBe(true);
    expect(values[0]!.stacktrace.frames[0]).not.toHaveProperty('filename');
    expect(values[1]!.stacktrace.frames.map((f) => f['filename'])).toEqual([undefined, 'usage-rollup.js', 'worker.ts']);
  });

  it('builds a release only from a 40-character lowercase hex commit', () => {
    const sha = '0123456789abcdef0123456789abcdef01234567';
    expect(safeSentryRelease('api', sha)).toBe(`stack-api@${sha}`);
    expect(safeSentryRelease('api', 'registry.example.io/api:deployment-01ABC')).toBeUndefined();
    expect(safeSentryRelease('api', sha.toUpperCase())).toBeUndefined();
    expect(safeSentryRelease('api', `${sha}0`)).toBeUndefined();
    expect(safeSentryRelease('api', undefined)).toBeUndefined();
    expect(safeSentryRelease('api', '')).toBeUndefined();
    expect(safeSentryRelease('../evil', sha)).toBeUndefined();
  });

  it('suppresses raw console arguments process-wide and keeps fixed labels and Postgres diagnostics', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      installFreshConsoleGuard();
      console.error('provider failed', Object.assign(new Error(CANARY), { code: 'ECONNRESET' }));
      console.error('[USAGE-ROLLUP] Failed', wrappedPostgresError());
      console.error('Unhandled error', { ...safeErrorSummary(wrappedPostgresError()) });
      const serialized = JSON.stringify(errorSpy.mock.calls);
      expect(serialized).not.toContain(CANARY);
      expect(serialized).toContain('ECONNRESET');
      expect(errorSpy.mock.calls[0]).toEqual(['Application error', 'provider failed', { name: 'Error', code: 'ECONNRESET' }]);
      const pg = { name: 'Error', pg_code: '42P01', table: 'usage_rollups', constraint: 'usage_rollups_operator_id_fkey' };
      expect(errorSpy.mock.calls[1]).toEqual(['Application error', '[USAGE-ROLLUP] Failed', pg]);
      expect(errorSpy.mock.calls[2]).toEqual(['Application error', 'Unhandled error', pg]);
    } finally {
      errorSpy.mockRestore();
    }
  });

  it('drops labels that could carry data', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      installFreshConsoleGuard();
      const hostile = [
        `[AUTH] failed for ${CANARY}@example.test`,
        'Request to https://api.example.test/v1 failed',
        'token=sk_live_abc failed',
        'Retry 3 of 5',
        "Failed for 'someone'",
        'Bearer sk_live_51HxQ',
        `${'A'.repeat(81)}`,
        'line one\nline two',
        '',
      ];
      for (const label of hostile) console.warn(label);
      for (const call of warnSpy.mock.calls) expect(call).toEqual(['Application warn']);
      expect(JSON.stringify(warnSpy.mock.calls)).not.toContain(CANARY);
    } finally {
      warnSpy.mockRestore();
    }
  });
});
