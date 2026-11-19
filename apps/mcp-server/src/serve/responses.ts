import type { ServerResponse } from 'node:http';
import { temporarilyUnavailableMessage } from '@stack/mcp-server';
import { CAPACITY_RETRY_AFTER_SECONDS } from './config.js';
import type { EndpointConfig } from './types.js';

function oauthChallenge(oauthEnabled: boolean, metadataUrl: string, scopes: readonly string[]): string {
  return oauthEnabled
    ? `Bearer realm="stack-mcp", resource_metadata="${metadataUrl}", scope="${scopes.join(' ')}", error="invalid_token"`
    : 'Bearer realm="stack-mcp", error="invalid_token"';
}

export function sendInvalidToken(
  res: import('node:http').ServerResponse,
  oauthEnabled: boolean,
  endpoint: Pick<EndpointConfig, 'metadataUrl' | 'scopes'>,
) {
  res.writeHead(401, {
    'Content-Type': 'application/json',
    'WWW-Authenticate': oauthChallenge(oauthEnabled, endpoint.metadataUrl, endpoint.scopes),
  });
  res.end(JSON.stringify({ error: 'invalid_token' }));
}

// 402, with the API's own body: the credential is valid and its account has no platform
// subscription, so no session is opened. A body that is not the API's error shape is replaced
// by the fixed one, never relayed.
export function sendSubscriptionRequired(res: import('node:http').ServerResponse, body: unknown) {
  const error = (body as { error?: { code?: unknown } } | undefined)?.error;
  const relay = error !== null && typeof error === 'object' && error.code === 'PLATFORM_SUBSCRIPTION_REQUIRED';
  res.writeHead(402, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(relay ? body : {
    error: {
      code: 'PLATFORM_SUBSCRIPTION_REQUIRED',
      message: 'This account needs a STACK platform subscription. Start one in the Console under billing.',
    },
  }));
}

export function sendSessionNotFound(res: import('node:http').ServerResponse) {
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Session not found' }));
}

// A 503, never a 401: STACK could not check the bearer, which says nothing
// about the bearer. The message is the same temporary-outage text a tool error
// carries, and Retry-After says when to retry.
export function sendAuthenticationUnavailable(res: import('node:http').ServerResponse, retryAfterSeconds: number) {
  res.writeHead(503, {
    'Content-Type': 'application/json',
    'Retry-After': String(retryAfterSeconds),
  });
  res.end(JSON.stringify({
    error: 'Authentication service unavailable',
    message: temporarilyUnavailableMessage(retryAfterSeconds),
  }));
}

export function sendCapacityUnavailable(res: import('node:http').ServerResponse) {
  res.writeHead(503, {
    'Content-Type': 'application/json',
    'Retry-After': String(CAPACITY_RETRY_AFTER_SECONDS),
  });
  res.end(JSON.stringify({ error: 'MCP session capacity reached' }));
}

export function sendBodyCapacityUnavailable(res: import('node:http').ServerResponse) {
  if (res.writableEnded) return;
  res.writeHead(503, {
    'Content-Type': 'application/json',
    'Retry-After': String(CAPACITY_RETRY_AFTER_SECONDS),
  });
  res.end(JSON.stringify({ error: 'Too many large requests are being read. Retry shortly.' }));
}

export function sendInternalError(res: import('node:http').ServerResponse) {
  if (res.headersSent) {
    if (!res.writableEnded) res.end();
    return;
  }
  res.writeHead(500, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Internal server error' }));
}

export function sendPayloadTooLarge(res: ServerResponse, kind: 'request' | 'response') {
  if (res.writableEnded) return;
  res.statusCode = 413;
  res.removeHeader('Content-Length');
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ error: `MCP ${kind} exceeds size limit` }));
}

export function sendTooManyRequests(res: ServerResponse) {
  if (res.writableEnded) return;
  res.writeHead(429, {
    'Content-Type': 'application/json',
    'Retry-After': String(CAPACITY_RETRY_AFTER_SECONDS),
  });
  res.end(JSON.stringify({ error: 'Too many concurrent MCP requests' }));
}

export function sendRequestTimeout(res: ServerResponse) {
  if (res.writableEnded) return;
  if (res.headersSent) {
    res.end();
    return;
  }
  res.writeHead(504, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'MCP request timed out' }));
}

/**
 * Ends one request that took longer than STACK waits for it, with a JSON-RPC error for each call in it (code -32001, the
 * MCP request timeout). Only this request ends: the session is still open and its other calls carry on.
 */
export function sendRequestDeadlineError(res: ServerResponse, requestIds: ReadonlyArray<string | number>) {
  if (res.writableEnded) return;
  const errors = requestIds.map((id) => ({
    jsonrpc: '2.0',
    id,
    error: { code: -32001, message: 'This call took longer than STACK waits for it. The session is still open; the call may have finished or may still be running.' },
  }));
  const body = JSON.stringify(errors.length === 1 ? errors[0] : errors);
  if (res.headersSent) {
    if (String(res.getHeader('content-type') ?? '').startsWith('text/event-stream')) res.end(`event: message\ndata: ${body}\n\n`);
    else res.end(body);
    return;
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(body);
}
