// Sentry init - must precede other imports.
import * as Sentry from '@sentry/node';
import './secret-files.js';
import { assertEngineEntryAllowed, installSafeConsoleTelemetry, safeSentryRelease, sanitizeSentryEvent } from '@stack/shared';

installSafeConsoleTelemetry();
const sentryDsn = process.env['SENTRY_DSN'];
if (sentryDsn) {
  Sentry.init({
    dsn: sentryDsn,
    environment: process.env['NODE_ENV'] ?? 'development',
    tracesSampleRate: 0,
    sendDefaultPii: false,
    // `stack-mcp@<40-hex>` from the deploy workflow, or unset.
    release: safeSentryRelease('mcp', process.env['STACK_RELEASE_SHA']),
    initialScope: { tags: { site: 'mcp' } },
    beforeSend: sanitizeSentryEvent,
  });
}

import { pathToFileURL } from 'node:url';
import { createStackMcpHttpServer } from './serve/server.js';
import type { McpServeExtension } from './extension.js';

// The server lives in ./serve/, one module per concern:
//   server.ts            assembles the http.Server: security headers, timeouts, idle sweep
//   settings.ts          options, environment and limit validation
//   request-handler.ts   the request pipeline, bearer validation and session handling
//   sessions.ts          the session table and its admission counters
//   resource-metadata.ts the endpoint table and RFC 9728 protected-resource metadata
//   auth-context.ts      bearer validation against the API
//   bearer-binding.ts    the session-to-bearer hash
//   origin.ts            Origin validation and CORS headers
//   body-limits.ts       bounded request body and response byte ceiling
//   responses.ts         the error responses and the 401 challenge
//   health.ts            /health and the OpenAI apps challenge
//   config.ts, types.ts
export { MCP_DIRECTORY_OAUTH_SCOPES, MCP_OAUTH_SCOPES } from './oauth-scopes.js';
export { isAllowedOrigin } from './serve/origin.js';
export { createStackMcpHttpServer } from './serve/server.js';
export type { StackMcpHttpServer, StackMcpHttpServerOptions } from './serve/types.js';
export type { McpServeContext, McpServeExtension } from './extension.js';

function isMainModule(): boolean {
  const entry = process.argv[1];
  return typeof entry === 'string' && import.meta.url === pathToFileURL(entry).href;
}

/**
 * Starts the server and returns once it is listening. With no extension it
 * serves the engine alone; a deployment that sells more passes its own.
 */
export async function startMcpServe(extension: McpServeExtension | null): Promise<void> {
  const port = parseInt(process.env['PORT'] ?? '3001', 10);
  const server = createStackMcpHttpServer({}, extension);

  await server.listen(port, '0.0.0.0');
  console.log(`STACK MCP server listening on port ${port}`);

  const shutdown = async () => {
    console.log('MCP server shutting down...');
    try {
      await server.close();
      process.exit(0);
    } catch {
      console.error('[mcp-server] shutdown failed: diagnostic details suppressed.');
      process.exit(1);
    }
  };

  process.once('SIGINT', () => void shutdown());
  process.once('SIGTERM', () => void shutdown());
}

// Run directly, this is the engine's entry point: it serves the engine alone, and in production only when the
// deployment is self-managed. STACK's own deployment starts from an entry point of its own instead.
if (isMainModule()) {
  try {
    assertEngineEntryAllowed();
    await startMcpServe(null);
  } catch {
    console.error('[mcp-server] failed to start: diagnostic details suppressed.');
    process.exit(1);
  }
}
