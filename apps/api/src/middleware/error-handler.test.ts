import { describe, it, expect, vi } from 'vitest';
import {
  CmekRevokedError,
  ServiceUnavailableError,
  SpendRefusedError,
  SpendSettlementPendingError,
  StackError,
  installSafeConsoleTelemetry,
  registerSafeRouteTemplate,
  sanitizeSentryEvent,
} from '@stack/shared';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { createErrorHandler } from './error-handler.js';
import Fastify from 'fastify';
import { z } from 'zod';
import rateLimit from '@fastify/rate-limit';

const sentryCapture = vi.hoisted(() => ({
  tags: [] as Array<Record<string, string>>,
  errors: [] as unknown[],
}));
vi.mock('@sentry/node', () => ({
  withScope(callback: (scope: { setTag(key: string, value: string): void }) => void) {
    const tags: Record<string, string> = {};
    sentryCapture.tags.push(tags);
    callback({ setTag(key, value) { tags[key] = value; } });
  },
  captureException(error: unknown) { sentryCapture.errors.push(error); },
}));

function makeReply() {
  const sent: { status: number; body: unknown }[] = [];
  const state: { _s: number } = { _s: 0 };
  const reply = {
    status(s: number) {
      state._s = s;
      return this;
    },
    send(body: unknown) {
      sent.push({ status: state._s, body });
      return this;
    },
  } as unknown as FastifyReply & { _sent: typeof sent };
  (reply as unknown as { _sent: typeof sent })._sent = sent;
  return reply;
}

const fakeRequest = { url: '/test', method: 'GET' } as FastifyRequest;

describe('createErrorHandler — errors that mark themselves as STACK-side', () => {
  it('flags the request for the meter when the error says STACK could not serve it, whatever its code, and not otherwise', () => {
    const handler = createErrorHandler();
    const flagged = { url: '/test', method: 'GET' } as FastifyRequest & { stackSideUnavailable?: boolean };
    handler(new StackError('Not now.', 'SOME_NEW_UNAVAILABLE', 503, undefined, { stackSide: true }), flagged, makeReply());
    expect(flagged.stackSideUnavailable).toBe(true);

    const plain = { url: '/test', method: 'GET' } as FastifyRequest & { stackSideUnavailable?: boolean };
    handler(new StackError('Not now.', 'SOME_NEW_UNAVAILABLE', 503), plain, makeReply());
    expect(plain.stackSideUnavailable).toBeUndefined();
    // The code alone means nothing: the engine reads the marker, and keeps no list of codes.
    const named = { url: '/test', method: 'GET' } as FastifyRequest & { stackSideUnavailable?: boolean };
    handler(new StackError('Not now.', 'CAPACITY_UNAVAILABLE', 503), named, makeReply());
    expect(named.stackSideUnavailable).toBeUndefined();
  });
});

describe('createErrorHandler — spend refusals', () => {
  it('answers any refusal to spend by its engine base, from what the class fixed when it was raised', () => {
    const handler = createErrorHandler();
    const refusal = new SpendRefusedError('The wallet is frozen.', 'WALLET_FROZEN', { reason: 'dispute' });
    refusal.message = 'database password private-canary';
    Object.assign(refusal, { code: 'LEAKED', details: { credential: 'private-canary' } });
    const reply = makeReply();
    handler(refusal, fakeRequest, reply);
    expect(reply._sent).toEqual([{ status: 402, body: { error: {
      code: 'WALLET_FROZEN', message: 'The wallet is frozen.', details: { reason: 'dispute' },
    } } }]);
  });

  it('answers a spend whose settlement is pending as a retriable 503', () => {
    const handler = createErrorHandler();
    const reply = makeReply();
    handler(new SpendSettlementPendingError('Settlement is still pending.', 'SETTLEMENT_PENDING'), fakeRequest, reply);
    expect(reply._sent).toEqual([{ status: 503, body: { error: { code: 'SETTLEMENT_PENDING', message: 'Settlement is still pending.' } } }]);
  });

  it('does not trust a matching error name', () => {
    const handler = createErrorHandler();
    const spoof = Object.assign(new Error('private-canary'), { name: 'InsufficientBalanceError', statusCode: 402 });
    const second = makeReply();
    const silent = vi.spyOn(console, 'error').mockImplementation(() => {});
    try { handler(spoof, fakeRequest, second); } finally { silent.mockRestore(); }
    expect(second._sent).toEqual([{ status: 500, body: { error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } } }]);
  });
});

describe('createErrorHandler — CmekRevokedError wiring', () => {
  it('calls cmek.recordRevoked with the operator_id from the error details', () => {
    const recordRevoked = vi.fn().mockResolvedValue(undefined);
    const handler = createErrorHandler({ cmek: { recordRevoked } });

    handler(new CmekRevokedError('op_test_abc', 'arn:aws:kms:us-east-1:111:key/xxx'), fakeRequest, makeReply());

    expect(recordRevoked).toHaveBeenCalledTimes(1);
    expect(recordRevoked).toHaveBeenCalledWith('op_test_abc', 'arn:aws:kms:us-east-1:111:key/xxx');
  });

  it('calls recordRevoked without keyArn when the error has no key_arn detail', () => {
    const recordRevoked = vi.fn().mockResolvedValue(undefined);
    const handler = createErrorHandler({ cmek: { recordRevoked } });

    handler(new CmekRevokedError('op_no_key'), fakeRequest, makeReply());

    expect(recordRevoked).toHaveBeenCalledWith('op_no_key', undefined);
  });

  it('still surfaces the 503 to the client even when recordRevoked is wired', () => {
    const recordRevoked = vi.fn().mockResolvedValue(undefined);
    const handler = createErrorHandler({ cmek: { recordRevoked } });
    const reply = makeReply();

    handler(new CmekRevokedError('op_test'), fakeRequest, reply);

    const sent = (reply as unknown as { _sent: { status: number; body: { error: { code: string } } }[] })._sent;
    expect(sent).toHaveLength(1);
    expect(sent[0]!.status).toBe(503);
    expect(sent[0]!.body.error.code).toBe('CMEK_REVOKED');
  });

  it('does not throw or block the response when recordRevoked rejects', () => {
    const recordRevoked = vi.fn().mockRejectedValue(new Error('DB unreachable'));
    const handler = createErrorHandler({ cmek: { recordRevoked } });
    const reply = makeReply();

    // Must not throw synchronously.
    expect(() => handler(new CmekRevokedError('op_test'), fakeRequest, reply)).not.toThrow();

    // 503 still surfaced.
    const sent = (reply as unknown as { _sent: { status: number; body: unknown }[] })._sent;
    expect(sent).toHaveLength(1);
    expect(sent[0]!.status).toBe(503);
  });

  it('does not call recordRevoked for non-CmekRevokedError errors', () => {
    const recordRevoked = vi.fn().mockResolvedValue(undefined);
    const handler = createErrorHandler({ cmek: { recordRevoked } });

    handler(new StackError('Other thing', 'OTHER_CODE', 400), fakeRequest, makeReply());

    expect(recordRevoked).not.toHaveBeenCalled();
  });

  it('handles CmekRevokedError gracefully when cmek dep is absent', () => {
    const handler = createErrorHandler();
    const reply = makeReply();

    expect(() => handler(new CmekRevokedError('op_test'), fakeRequest, reply)).not.toThrow();

    const sent = (reply as unknown as { _sent: { status: number; body: { error: { code: string } } }[] })._sent;
    expect(sent[0]!.status).toBe(503);
    expect(sent[0]!.body.error.code).toBe('CMEK_REVOKED');
  });
});

describe('createErrorHandler — framework rate limits', () => {
  it('preserves a 429 response instead of masking it as an internal error', async () => {
    const app = Fastify({ logger: false });
    await app.register(rateLimit, { max: 1, timeWindow: '1 minute' });
    app.setErrorHandler(createErrorHandler());
    app.get('/limited', async () => ({ ok: true }));

    expect((await app.inject({ method: 'GET', url: '/limited' })).statusCode).toBe(200);
    const limited = await app.inject({ method: 'GET', url: '/limited' });

    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
      },
    });
    await app.close();
  });
});

describe('createErrorHandler — safe diagnostics', () => {
  const CANARY = 'synthetic-canary-not-a-real-secret';

  function drizzleWrappedPostgresError(): Error {
    const cause = Object.assign(new Error(`duplicate key ${CANARY}`), {
      name: 'PostgresError',
      severity: 'ERROR',
      code: '23505',
      detail: `Key (email)=(${CANARY}@example.test) already exists.`,
      hint: CANARY,
      table_name: 'operators',
      column_name: 'email',
      constraint_name: 'operators_email_unique',
    });
    return Object.assign(new Error(`Failed query: insert ${CANARY}
params: ${CANARY}`), {
      query: `insert into operators (email) values ('${CANARY}')`,
      params: [CANARY],
      cause,
    });
  }

  it('logs and reports SQLSTATE, table and route template, and never the canary', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    delete (console as unknown as Record<symbol, unknown>)[Symbol.for('stack.safe-console-installed')];
    installSafeConsoleTelemetry();
    const previousDsn = process.env['SENTRY_DSN'];
    process.env['SENTRY_DSN'] = 'https://public@example.invalid/1';
    sentryCapture.tags.length = 0;
    sentryCapture.errors.length = 0;
    const app = Fastify({ logger: false });
    app.addHook('onRoute', (routeOptions) => registerSafeRouteTemplate(routeOptions.url));
    app.setErrorHandler(createErrorHandler());
    app.get('/v1/operators/:id', async () => { throw drizzleWrappedPostgresError(); });
    try {
      const response = await app.inject({ method: 'GET', url: `/v1/operators/${CANARY}?token=${CANARY}` });
      expect(response.statusCode).toBe(500);
      expect(response.body).not.toContain(CANARY);

      const consoleOutput = JSON.stringify(errorSpy.mock.calls);
      expect(consoleOutput).not.toContain(CANARY);
      expect(errorSpy.mock.calls).toEqual([['Application error', 'Unhandled error', {
        name: 'Error',
        code: '23505',
        pg_code: '23505',
        table: 'operators',
        constraint: 'operators_email_unique',
        route: '/v1/operators/:id',
      }]]);

      expect(sentryCapture.tags).toEqual([{
        method: 'GET',
        source: 'api.error-handler',
        route: '/v1/operators/:id',
        pg_code: '23505',
      }]);
      // What Sentry would send: the scope tags plus the raw exception
      // values, sanitised by the same beforeSend the server installs.
      const captured = sentryCapture.errors[0] as Error;
      const event = sanitizeSentryEvent({
        message: captured.message,
        request: { method: 'GET', url: `https://api.test/v1/operators/${CANARY}?token=${CANARY}` },
        exception: { values: [
          { type: 'PostgresError', value: (captured.cause as Error).message },
          { type: 'Error', value: captured.message },
        ] },
        extra: { query: (captured as unknown as { query: string }).query },
        tags: sentryCapture.tags[0],
      }, { originalException: captured });
      expect(JSON.stringify(event)).not.toContain(CANARY);
      expect(event).toMatchObject({ tags: { route: '/v1/operators/:id', pg_code: '23505' } });
    } finally {
      await app.close();
      errorSpy.mockRestore();
      if (previousDsn === undefined) delete process.env['SENTRY_DSN'];
      else process.env['SENTRY_DSN'] = previousDsn;
    }
  });
});

describe('createErrorHandler — Zod validation errors', () => {
  async function respondTo(thrown: () => unknown) {
    const app = Fastify({ logger: false });
    app.setErrorHandler(createErrorHandler());
    app.get('/thrown', async () => thrown());
    try {
      return await app.inject({ method: 'GET', url: '/thrown' });
    } finally {
      await app.close();
    }
  }

  it('maps a ZodError to 400 VALIDATION_ERROR', async () => {
    const response = await respondTo(() => z.object({ n: z.number() }).parse({ n: 'x' }));
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
  });

  it('does not treat a plain error that only carries the name ZodError as validation', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const response = await respondTo(() => {
        throw Object.assign(new Error('spoofed'), { name: 'ZodError' });
      });
      expect(response.statusCode).toBe(500);
      expect(response.json().error.code).toBe('INTERNAL_ERROR');
    } finally {
      errorSpy.mockRestore();
    }
  });
});

describe('createErrorHandler - service unavailable', () => {
  async function send(thrown: () => Error) {
    const app = Fastify({ logger: false });
    app.setErrorHandler(createErrorHandler());
    app.get('/dependent', async () => { throw thrown(); });
    try { return await app.inject({ method: 'GET', url: '/dependent' }); } finally { await app.close(); }
  }

  it('answers a ServiceUnavailableError with 503, Retry-After and the wait in the body', async () => {
    const response = await send(() => new ServiceUnavailableError('Authentication backend temporarily unavailable, please retry', 7));
    expect(response.statusCode).toBe(503);
    expect(response.headers['retry-after']).toBe('7');
    expect(response.json()).toEqual({ error: {
      code: 'SERVICE_UNAVAILABLE',
      message: 'Authentication backend temporarily unavailable, please retry',
      details: { retry_after_seconds: 7 },
    } });
  });

  it('gives a plain SERVICE_UNAVAILABLE the default Retry-After', async () => {
    const response = await send(() => new StackError('Proxy operation read limit is unavailable', 'SERVICE_UNAVAILABLE', 503));
    expect(response.statusCode).toBe(503);
    expect(response.headers['retry-after']).toBe('5');
  });

  it('turns an ioredis outage on any route into a retriable 503, not a 500, and leaks nothing', async () => {
    const silent = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const response = await send(() => {
        const error = new Error('Reached the max retries per request limit (which is 2). redis://:secret-canary@10.0.0.4:6379');
        error.name = 'MaxRetriesPerRequestError';
        return error;
      });
      expect(response.statusCode).toBe(503);
      expect(response.headers['retry-after']).toBe('5');
      expect(response.json()).toEqual({ error: {
        code: 'SERVICE_UNAVAILABLE',
        message: 'Service temporarily unavailable, please retry',
        details: { retry_after_seconds: 5 },
      } });
      expect(response.body).not.toContain('secret-canary');
    } finally { silent.mockRestore(); }
  });

  it('does not add Retry-After to a revoked customer key', async () => {
    const response = await send(() => new CmekRevokedError('op_x'));
    expect(response.statusCode).toBe(503);
    expect(response.headers['retry-after']).toBeUndefined();
  });
});
