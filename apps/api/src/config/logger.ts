import { safeErrorSummary, safeRouteTemplate } from '@stack/shared';

/**
 * The API's logger configuration. A log line carries validated diagnostics
 * only: never a request URL, query, body, header or error message. A page link
 * that holds a one-time token (a connect link) therefore never reaches a log,
 * and neither does a credential a request body carries.
 * `logger-redaction.test.ts` drives the real connect-link routes through it.
 */
export function apiLoggerOptions(level: 'info' | 'warn') {
  return {
    level,
    serializers: {
      // Validated diagnostics only: code, SQLSTATE (pg_code), Postgres
      // table/constraint names and a registered route template.
      err(error: unknown) {
        const summary = safeErrorSummary(error);
        const { name, ...diagnostics } = summary;
        return { type: name, message: 'Error details suppressed', stack: '', ...diagnostics };
      },
      error(error: unknown) {
        const summary = safeErrorSummary(error);
        const { name, ...diagnostics } = summary;
        return { type: name, message: 'Error details suppressed', stack: '', ...diagnostics };
      },
      req(request: { id: string; method: string; routeOptions?: { url?: string } }) {
        // The route TEMPLATE (e.g. /v1/agents/:id), never request.url.
        const route = safeRouteTemplate(request.routeOptions?.url);
        return { id: request.id, method: request.method, ...(route ? { route } : {}) };
      },
      res(reply: { statusCode: number }) {
        return { statusCode: reply.statusCode };
      },
    },
    redact: {
      paths: [
        'headers', 'body', 'query', 'url', 'config', 'cause',
        '*.headers', '*.body', '*.query', '*.url', '*.config', '*.cause',
        'req.headers', 'req.body', 'req.query', 'req.url',
      ],
      censor: '[Suppressed]',
    },
  };
}
