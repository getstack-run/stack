import * as Sentry from '@sentry/node';
import { createServer } from 'node:http';
import { HTTP_MAX_HEADER_BYTES, STAGING_ROBOTS_TAG } from '@stack/shared';
import { sendInternalError } from './responses.js';
import { createHttpRequestHandler } from './request-handler.js';
import { createSessionRegistry } from './sessions.js';
import { resolveServerSettings } from './settings.js';
import type { McpServeExtension } from '../extension.js';
import type { StackMcpHttpServer, StackMcpHttpServerOptions } from './types.js';

/**
 * Wire the settings, the session registry and the request handler into one
 * `http.Server`: security headers on every response, the request and header
 * timeouts, and the idle-session sweep.
 */
export function createStackMcpHttpServer(
  options: StackMcpHttpServerOptions = {},
  extension: McpServeExtension | null = null,
): StackMcpHttpServer {
  const settings = resolveServerSettings(options);
  const { logger, requestTimeoutMs, sessionSweepIntervalMs } = settings;
  const registry = createSessionRegistry(settings);
  const { transports, closeEntries, pruneIdleSessions } = registry;
  const handleHttpRequest = createHttpRequestHandler(settings, registry, extension);

  // Request headers up to the size STACK's API reads, so nothing a client sends the API is refused here first.
  const httpServer = createServer({ maxHeaderSize: HTTP_MAX_HEADER_BYTES }, (req, res) => {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    // A staging deployment is never indexed, whatever the answer.
    if (settings.noindex) res.setHeader('X-Robots-Tag', STAGING_ROBOTS_TAG);
    void handleHttpRequest(req, res).catch(() => {
      logger.error('MCP request failed');
      Sentry.captureMessage('MCP request failed', 'error');
      sendInternalError(res);
    });
  });
  // Node's own limit on receiving a request is one number for every request, so it is off: the handler times each body
  // itself, `requestTimeoutMs` for any request and `bodyReceiveTimeoutMs` for a large body once its sender is checked, and
  // closes the connection of a request it answers before the body was read.
  httpServer.requestTimeout = 0;
  httpServer.headersTimeout = Math.min(requestTimeoutMs, 10_000);

  // What a deployment pushes to an agent's open sessions arrives over Redis when it is configured; the server never needs it.
  const redisUrl = options.redisUrl ?? process.env['REDIS_URL'];
  const extensionWork: Promise<(() => Promise<void>) | null> = extension?.onStart
    ? extension.onStart({ sessions: () => transports.values(), logger, redisUrl }).catch(() => {
      logger.error('MCP wake notifications are off: Redis is not reachable');
      return null;
    })
    : Promise.resolve(null);

  let sweepRunning = false;
  const sweepTimer = setInterval(() => {
    if (sweepRunning) return;
    sweepRunning = true;
    void pruneIdleSessions().finally(() => {
      sweepRunning = false;
    });
  }, sessionSweepIntervalMs);
  sweepTimer.unref();

  return {
    httpServer,
    listen(port, host) {
      return new Promise<void>((resolve, reject) => {
        const onError = (error: Error) => reject(error);
        httpServer.once('error', onError);
        httpServer.listen(port, host, () => {
          httpServer.off('error', onError);
          resolve();
        });
      });
    },
    async close() {
      clearInterval(sweepTimer);
      await (await extensionWork)?.();
      const entries = [...transports.values()];
      transports.clear();
      await closeEntries(entries);
      if (!httpServer.listening) return;
      await new Promise<void>((resolve, reject) => {
        httpServer.close((error) => error ? reject(error) : resolve());
      });
    },
    pruneIdleSessions,
    sessionCount: () => transports.size,
  };
}
