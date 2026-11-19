import assert from 'node:assert/strict';
import { type IncomingMessage, type ServerResponse } from 'node:http';
import { afterEach, describe, it, mock } from 'node:test';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createSessionRegistry } from './serve/sessions.js';
import type { SessionEntry } from './serve/types.js';
import { createStackMcpHttpServer, MCP_DIRECTORY_OAUTH_SCOPES, MCP_OAUTH_SCOPES } from './serve.js';
import { authContextResponse, closeServers, initialize, initializeBody, initializeSession, openChunkedPost, requestExistingSession, startServer, DIRECTORY_RESOURCE, DIRECTORY_METADATA, boundAuthContextResponse, resourceAwareFetch } from './serve.test-support.js';

it('applies security headers to discovery and unauthenticated errors', async () => {
  const { baseUrl } = await startServer({ oauthEnabled: true });
  for (const path of ['/.well-known/oauth-protected-resource', '/mcp', '/unknown']) {
    const response = await fetch(`${baseUrl}${path}`);
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    assert.match(response.headers.get('strict-transport-security') ?? '', /max-age=63072000/);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('x-robots-tag'), null);
    await response.text();
  }
});

it('marks every answer noindex on a staging deployment', async () => {
  const { baseUrl } = await startServer({ oauthEnabled: true, noindex: true });
  for (const path of ['/.well-known/oauth-protected-resource', '/mcp', '/unknown', '/health']) {
    const response = await fetch(`${baseUrl}${path}`);
    assert.equal(response.headers.get('x-robots-tag'), 'noindex, nofollow');
    await response.text();
  }
});

it('turns noindex on from STACK_STAGING and refuses a staging boot with no allow-list', async () => {
  const before = { staging: process.env['STACK_STAGING'], list: process.env['STAGING_SIGNIN_ALLOWLIST'] };
  try {
    process.env['STACK_STAGING'] = 'true';
    delete process.env['STAGING_SIGNIN_ALLOWLIST'];
    assert.throws(() => createStackMcpHttpServer({}), /STAGING_SIGNIN_ALLOWLIST/);
    process.env['STAGING_SIGNIN_ALLOWLIST'] = 'tester@example.com';
    const { baseUrl } = await startServer({ oauthEnabled: true });
    const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    assert.equal(response.headers.get('x-robots-tag'), 'noindex, nofollow');
    await response.text();
  } finally {
    for (const [name, value] of [['STACK_STAGING', before.staging], ['STAGING_SIGNIN_ALLOWLIST', before.list]] as const) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});


it('reads request headers up to 64 KB, so a long header the API takes is not refused here first', async () => {
  const { baseUrl } = await startServer({ oauthEnabled: true });
  const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`, { headers: { 'x-long': 'x'.repeat(40_000) } });
  assert.notEqual(response.status, 431);
  await response.text();
});


afterEach(async () => {
  mock.restoreAll();
  await closeServers();
});

describe('STACK MCP HTTP authentication', () => {
  it('advertises the reviewed routine tool scope without high-impact management grants', async () => {
    const { baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
    });
    const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    assert.equal(response.status, 200);
    const body = await response.json() as { scopes_supported: string[] };
    assert.deepEqual(body.scopes_supported, [...MCP_OAUTH_SCOPES]);
    for (const scope of [
      'passports:write',
      'services:connect',
      'proxy:write',
      'missions:write',
      'dropoffs:write',
      'skills:invoke',
      'audit:read',
      // Approval-gated writes requested by default (governance step-up).
      'notifications:write',
      'detectors:write',
      'pii:write',
      'reviews:write',
      'inbound-webhooks:write',
      // Deciding an approval in the chat: reject, or approve with this
      // server's attestation of the person's confirmation.
      'governance:decide',
      // The one tool that calls any OpenRouter endpoint (stack_call_openrouter): model calls are what /mcp serves.
      'llm:invoke',
      // The owner's own scopes, so running the account from a chat needs no second consent.
      'account:write',
      'billing:write',
      'governance:write',
      'security-events:write',
    ]) {
      assert.ok(body.scopes_supported.includes(scope as typeof MCP_OAUTH_SCOPES[number]));
    }
    for (const scope of [
      'team:write',
      'credentials:read',
      'oauth-apps:write',
      'cmek:write',
      'authority:write',
      'identity:write',
      'skills:publish',
      'accounts:manage',
      'partner:write',
      'admin',
    ]) {
      assert.ok(!body.scopes_supported.includes(scope as never));
    }
    assert.equal(new Set(body.scopes_supported).size, body.scopes_supported.length);
  });

  it('returns the OAuth challenge when the request has no bearer', async () => {
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => {
        throw new Error('validation must not run without a bearer');
      },
    });

    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify(initializeBody()),
    });

    assert.equal(response.status, 401);
    assert.match(
      response.headers.get('www-authenticate') ?? '',
      /resource_metadata="https:\/\/mcp\.test\/\.well-known\/oauth-protected-resource"/,
    );
    assert.equal(response.headers.get('mcp-session-id'), null);
    assert.equal(server.sessionCount(), 0);
  });

  it('rejects an invalid bearer before it creates a session', async () => {
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => new Response(JSON.stringify({ error: 'invalid' }), { status: 401 }),
    });

    const response = await initialize(baseUrl, 'invalid-bearer');

    assert.equal(response.status, 401);
    assert.match(
      response.headers.get('www-authenticate') ?? '',
      /resource_metadata="https:\/\/mcp\.test\/\.well-known\/oauth-protected-resource"/,
    );
    assert.equal(response.headers.get('mcp-session-id'), null);
    assert.equal(server.sessionCount(), 0);
  });

  it('returns 503 when bearer validation is unavailable', async () => {
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => new Response(JSON.stringify({ error: 'down' }), { status: 503 }),
    });

    const response = await initialize(baseUrl, 'valid-looking-bearer');

    assert.equal(response.status, 503);
    assert.equal(response.headers.get('mcp-session-id'), null);
    assert.equal(server.sessionCount(), 0);
  });

  it('turns a 503 from the auth context call into a temporary-unavailable answer, never an auth failure', async () => {
    const cases: Array<{ label: string; response: () => Response; seconds: number }> = [
      {
        label: 'Retry-After header',
        response: () => new Response(JSON.stringify({ error: { code: 'SERVICE_UNAVAILABLE', message: 'down', details: { retry_after_seconds: 99 } } }), { status: 503, headers: { 'Retry-After': '17' } }),
        seconds: 17,
      },
      {
        label: 'details only',
        response: () => new Response(JSON.stringify({ error: { code: 'SERVICE_UNAVAILABLE', message: 'down', details: { retry_after_seconds: 8 } } }), { status: 503 }),
        seconds: 8,
      },
      { label: 'bare 503', response: () => new Response(null, { status: 503 }), seconds: 5 },
      { label: 'clamped high', response: () => new Response(null, { status: 503, headers: { 'Retry-After': '9999' } }), seconds: 300 },
    ];
    for (const { label, response, seconds } of cases) {
      const { server, baseUrl } = await startServer({
        apiUrl: 'https://api.test',
        mcpResource: 'https://mcp.test/mcp',
        oauthEnabled: true,
        fetchImpl: async () => response(),
      });
      const answer = await initialize(baseUrl, 'valid-looking-bearer');
      assert.equal(answer.status, 503, label);
      assert.equal(answer.headers.get('retry-after'), String(seconds), label);
      assert.equal(answer.headers.get('www-authenticate'), null, label);
      assert.equal(answer.headers.get('mcp-session-id'), null, label);
      const body = await answer.json() as { error: string; message: string };
      assert.match(body.message, new RegExp(`^STACK is temporarily unavailable, retry in ${seconds} seconds`), label);
      assert.doesNotMatch(JSON.stringify(body), /invalid|credential|token|rotat|re-?authori/i, label);
      assert.equal(server.sessionCount(), 0, label);
    }
  });

  it('still answers a 401 from the auth context call with the invalid-token challenge', async () => {
    const { baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => new Response(JSON.stringify({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } }), { status: 401 }),
    });
    const answer = await initialize(baseUrl, 'expired-bearer');
    assert.equal(answer.status, 401);
    assert.match(answer.headers.get('www-authenticate') ?? '', /error="invalid_token"/);
    assert.equal(answer.headers.get('retry-after'), null);
    await answer.text();
  });

  it('answers the API\'s 402 to an account with no platform subscription and opens no session', async () => {
    const body = {
      error: {
        code: 'PLATFORM_SUBSCRIPTION_REQUIRED',
        message: 'Agents need an active STACK platform subscription to make calls.',
        details: { status: 'lapsed', subscribe: { api: 'POST /v1/billing/platform/subscribe' } },
      },
    };
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => new Response(JSON.stringify(body), { status: 402, headers: { 'Content-Type': 'application/json' } }),
    });

    const response = await initialize(baseUrl, 'valid-looking-bearer');

    assert.equal(response.status, 402);
    assert.equal(response.headers.get('mcp-session-id'), null);
    assert.equal(response.headers.get('www-authenticate'), null);
    assert.deepEqual(await response.json(), body);
    assert.equal(server.sessionCount(), 0);
  });

  it('never relays a 402 body that is not the API\'s own error', async () => {
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => new Response('<html>pay us</html>', { status: 402 }),
    });

    const response = await initialize(baseUrl, 'valid-looking-bearer');

    assert.equal(response.status, 402);
    const answer = await response.json() as { error: { code: string } };
    assert.equal(answer.error.code, 'PLATFORM_SUBSCRIPTION_REQUIRED');
    assert.equal(server.sessionCount(), 0);
  });

  it('returns 503 when bearer validation cannot reach the API', async () => {
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => {
        throw new Error('network unavailable');
      },
    });

    const response = await initialize(baseUrl, 'valid-looking-bearer');

    assert.equal(response.status, 503);
    assert.equal(response.headers.get('mcp-session-id'), null);
    assert.equal(server.sessionCount(), 0);
  });

  it('rebuilds after a bearer change and keeps the new session bound', async () => {
    const validationUrls: string[] = [];
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async (input, init) => {
        validationUrls.push(String(input));
        const authorization = new Headers(init?.headers).get('authorization');
        const id = authorization === 'Bearer other-principal-token' ? 'op_other' : 'op_test';
        return authContextResponse({ type: 'operator', id });
      },
    });
    const initialized = await initialize(baseUrl, 'access-token-a');
    assert.equal(initialized.status, 200);
    const sessionId = initialized.headers.get('mcp-session-id');
    assert.ok(sessionId);

    const sameBearerResponse = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer access-token-a',
        'Mcp-Session-Id': sessionId,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    });
    assert.equal(sameBearerResponse.status, 200);
    assert.equal(validationUrls.length, 2, 'the matching bearer must be revalidated');
    assert.ok(validationUrls.every((url) => url === 'https://api.test/v1/auth/context'));

    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer access-token-b',
        'Mcp-Session-Id': sessionId,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }),
    });

    assert.equal(response.status, 404);
    assert.deepEqual(await response.json(), { error: 'Session not found' });
    assert.equal(server.sessionCount(), 1, 'a mismatched bearer must not delete the old session');

    const reinitialized = await initialize(baseUrl, 'access-token-b');
    assert.equal(reinitialized.status, 200);
    const secondSessionId = reinitialized.headers.get('mcp-session-id');
    assert.ok(secondSessionId);
    assert.notEqual(secondSessionId, sessionId);

    const secondSessionResponse = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer access-token-b',
        'Mcp-Session-Id': secondSessionId,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/list', params: {} }),
    });
    assert.equal(secondSessionResponse.status, 200);

    const otherPrincipalResponse = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer other-principal-token',
        'Mcp-Session-Id': secondSessionId,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} }),
    });
    assert.equal(otherPrincipalResponse.status, 404);
    assert.equal(server.sessionCount(), 2, 'a mismatched principal must not delete either session');

    const stillActiveResponse = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer access-token-b',
        'Mcp-Session-Id': secondSessionId,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 6, method: 'tools/list', params: {} }),
    });
    assert.equal(stillActiveResponse.status, 200);
  });

  it('rejects a revoked matching bearer before local MCP methods run', async () => {
    let valid = true;
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => valid
        ? authContextResponse()
        : new Response(JSON.stringify({ error: 'revoked' }), { status: 401 }),
    });

    const initialized = await initialize(baseUrl, 'access-token-a');
    assert.equal(initialized.status, 200);
    const sessionId = initialized.headers.get('mcp-session-id');
    assert.ok(sessionId);

    valid = false;
    const revoked = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer access-token-a',
        'Mcp-Session-Id': sessionId,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    });

    assert.equal(revoked.status, 401);
    assert.match(revoked.headers.get('www-authenticate') ?? '', /error="invalid_token"/);
    assert.equal(server.sessionCount(), 1, 'revocation must not make the session id a deletion primitive');
  });

  const existingSessionRequests = [
    {
      name: 'tools/list',
      body: { jsonrpc: '2.0', id: 30, method: 'tools/list', params: {} },
    },
    {
      name: 'ping',
      body: { jsonrpc: '2.0', id: 31, method: 'ping', params: {} },
    },
    {
      name: 'tool call',
      body: {
        jsonrpc: '2.0',
        id: 32,
        method: 'tools/call',
        params: { name: 'stack_list_agents', arguments: {} },
      },
    },
  ] as const;

  for (const invalidState of ['expired', 'revoked'] as const) {
    for (const requestCase of existingSessionRequests) {
      it(`rejects ${invalidState} bearer credentials on ${requestCase.name} in an existing session`, async () => {
        let bearerIsValid = true;
        const { server, baseUrl } = await startServer({
          apiUrl: 'https://api.test',
          mcpResource: 'https://mcp.test/mcp',
          oauthEnabled: true,
          fetchImpl: async () => bearerIsValid
            ? authContextResponse()
            : new Response(JSON.stringify({ error: invalidState }), { status: 401 }),
        });
        const sessionId = await initializeSession(baseUrl, 'access-token-a');

        bearerIsValid = false;
        const response = await requestExistingSession(
          baseUrl,
          'access-token-a',
          sessionId,
          requestCase.body,
        );

        assert.equal(response.status, 401);
        assert.match(response.headers.get('www-authenticate') ?? '', /error="invalid_token"/);
        assert.deepEqual(await response.json(), { error: 'invalid_token' });
        assert.equal(server.sessionCount(), 1, 'invalid auth must not delete the bound session');
      });
    }
  }

  it('times out bearer validation after the configured deadline', async () => {
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      authValidationTimeoutMs: 5,
      fetchImpl: async (_input, init) => new Promise<Response>((resolve, reject) => {
        const timer = setTimeout(() => resolve(authContextResponse()), 100);
        init?.signal?.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(new Error('aborted'));
        }, { once: true });
      }),
    });

    const response = await initialize(baseUrl, 'access-token-a');
    assert.equal(response.status, 503);
    assert.equal(server.sessionCount(), 0);
  });

  it('closes a partial transport and returns a controlled initialization error', async () => {
    const handleRequest = mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async () => {
        throw new Error('initialization failed');
      },
    );
    const close = mock.method(StreamableHTTPServerTransport.prototype, 'close', async () => {});
    const errors: string[] = [];
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => authContextResponse(),
      logger: { error: (message) => errors.push(String(message)) },
    });

    const response = await initialize(baseUrl, 'access-token-a');
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: 'Internal server error' });
    assert.equal(handleRequest.mock.callCount(), 1);
    assert.equal(close.mock.callCount(), 1);
    assert.equal(server.sessionCount(), 0);
    assert.deepEqual(errors, ['MCP request failed']);
  });

});

describe('STACK MCP HTTP session capacity', () => {
  it('defaults to 256 sessions per bearer, and the 257th evicts the oldest instead of being refused', async () => {
    const close = mock.method(StreamableHTTPServerTransport.prototype, 'close', async () => {});
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => authContextResponse(),
    });

    for (let index = 0; index < 256; index += 1) {
      await initializeSession(baseUrl, 'access-token-a');
    }
    assert.equal(server.sessionCount(), 256);
    await initializeSession(baseUrl, 'access-token-a');

    assert.equal(server.sessionCount(), 256);
    assert.equal(close.mock.callCount(), 1);
  });

  it('admits a new bearer at the process cap by evicting a session of the largest holder', async () => {
    const close = mock.method(StreamableHTTPServerTransport.prototype, 'close', async () => {});
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      maxSessionsPerProcess: 3,
      fetchImpl: async () => authContextResponse(),
    });

    for (let index = 0; index < 3; index += 1) {
      await initializeSession(baseUrl, `access-token-${index}`);
    }
    await initializeSession(baseUrl, 'access-token-new');
    assert.equal(server.sessionCount(), 3);
    assert.equal(close.mock.callCount(), 1);
  });

  it('reserves initialization capacity across concurrent requests', async () => {
    let signalValidationStarted!: () => void;
    const validationStarted = new Promise<void>((resolve) => {
      signalValidationStarted = resolve;
    });
    let releaseValidation!: () => void;
    const validationHold = new Promise<void>((resolve) => {
      releaseValidation = resolve;
    });
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      maxSessionsPerBearer: 1,
      maxSessionsPerProcess: 1,
      fetchImpl: async () => {
        signalValidationStarted();
        await validationHold;
        return authContextResponse();
      },
    });

    const firstPending = initialize(baseUrl, 'access-token-a');
    await validationStarted;
    const full = await initialize(baseUrl, 'access-token-a');
    assert.equal(full.status, 503);
    assert.equal(full.headers.get('retry-after'), '5');
    releaseValidation();
    assert.equal((await firstPending).status, 200);
    assert.equal(server.sessionCount(), 1);
  });

  it('keeps the process within its limit across different bearers', async () => {
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      maxSessionsPerBearer: 2,
      maxSessionsPerProcess: 1,
      fetchImpl: async () => authContextResponse(),
    });

    assert.equal((await initialize(baseUrl, 'access-token-a')).status, 200);
    assert.equal((await initialize(baseUrl, 'access-token-b')).status, 200);
    assert.equal(server.sessionCount(), 1);
  });

  it('prunes idle sessions before it rejects a replacement', async () => {
    let now = 1_000;
    const close = mock.method(StreamableHTTPServerTransport.prototype, 'close', async () => {});
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      maxSessionsPerBearer: 1,
      maxSessionsPerProcess: 1,
      sessionIdleTtlMs: 100,
      now: () => now,
      fetchImpl: async () => authContextResponse(),
    });

    assert.equal((await initialize(baseUrl, 'access-token-a')).status, 200);
    now += 101;
    assert.equal((await initialize(baseUrl, 'access-token-a')).status, 200);
    assert.equal(close.mock.callCount(), 1);
    assert.equal(server.sessionCount(), 1);
  });

  it('pruning frees capacity without disrupting a non-idle session', async () => {
    let now = 1_000;
    const close = mock.method(StreamableHTTPServerTransport.prototype, 'close', async () => {});
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      maxSessionsPerBearer: 2,
      maxSessionsPerProcess: 2,
      sessionIdleTtlMs: 100,
      now: () => now,
      fetchImpl: async () => authContextResponse(),
    });

    const staleSessionId = await initializeSession(baseUrl, 'access-token-a');
    const activeSessionId = await initializeSession(baseUrl, 'access-token-a');
    assert.notEqual(activeSessionId, staleSessionId);

    now += 50;
    const refreshed = await requestExistingSession(
      baseUrl,
      'access-token-a',
      activeSessionId,
      { jsonrpc: '2.0', id: 40, method: 'ping', params: {} },
    );
    assert.equal(refreshed.status, 200);
    await refreshed.text();

    now += 51;
    const replacementSessionId = await initializeSession(baseUrl, 'access-token-a');
    assert.notEqual(replacementSessionId, staleSessionId);
    assert.equal(close.mock.callCount(), 1);
    assert.equal(server.sessionCount(), 2);

    const stillUsable = await requestExistingSession(
      baseUrl,
      'access-token-a',
      activeSessionId,
      { jsonrpc: '2.0', id: 41, method: 'tools/list', params: {} },
    );
    assert.equal(stillUsable.status, 200);
    await stillUsable.text();
    assert.equal(server.sessionCount(), 2);
  });
});

describe('STACK MCP session eviction at the cap', () => {
  function fakeRegistry(limits: { perBearer: number; perProcess: number }) {
    const errors: string[] = [];
    const warnings: string[] = [];
    const registry = createSessionRegistry({
      now: () => 0,
      logger: { error: (m: unknown) => errors.push(String(m)), warn: (m: unknown) => warnings.push(String(m)) },
      sessionIdleTtlMs: 1_000_000,
      maxSessionsPerBearer: limits.perBearer,
      maxSessionsPerProcess: limits.perProcess,
      maxInFlightRequests: 100,
      maxInFlightPerBearer: 100,
      maxInFlightPerSession: 100,
    });
    const closed: string[] = [];
    function add(id: string, bearer: string, lastSeenAt: number, closeImpl?: () => Promise<void>) {
      registry.transports.set(id, {
        bearerFingerprint: bearer,
        lastSeenAt,
        transport: { close: closeImpl ?? (async () => { closed.push(id); }) },
      } as unknown as SessionEntry);
    }
    return { registry, add, closed, errors, warnings };
  }

  it('admits one more for a bearer at its cap by evicting its least recently used idle session', async () => {
    const { registry, add, closed, warnings } = fakeRegistry({ perBearer: 3, perProcess: 50 });
    add('s-new', 'a', 300);
    add('s-old', 'a', 100);
    add('s-mid', 'a', 200);
    add('b-1', 'b', 1);

    const release = registry.reserveInitialization('a');
    assert.ok(release);
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual([...registry.transports.keys()].sort(), ['b-1', 's-mid', 's-new']);
    assert.deepEqual(closed, ['s-old']);
    assert.equal(warnings.length, 1);
    assert.doesNotMatch(warnings[0] ?? '', /s-old/);
    release();
  });

  it('keeps counting pending initializations: an eviction frees exactly one slot', () => {
    const { registry, add } = fakeRegistry({ perBearer: 2, perProcess: 50 });
    add('s-1', 'a', 1);
    add('s-2', 'a', 2);
    const first = registry.reserveInitialization('a');
    assert.ok(first);
    assert.equal(registry.transports.size, 1);
    const second = registry.reserveInitialization('a');
    assert.ok(second);
    assert.equal(registry.transports.size, 0);
    // Two pending now fill the cap and nothing active is left to evict.
    assert.equal(registry.reserveInitialization('a'), null);
  });

  it('refuses and evicts nothing when every session of the bearer has a request in flight', () => {
    const { registry, add, closed } = fakeRegistry({ perBearer: 2, perProcess: 50 });
    add('s-1', 'a', 1);
    add('s-2', 'a', 2);
    const busy1 = registry.reserveRequest('a', 's-1');
    const busy2 = registry.reserveRequest('a', 's-2');
    assert.ok(busy1 && busy2);

    assert.equal(registry.reserveInitialization('a'), null);
    assert.equal(registry.transports.size, 2);
    assert.deepEqual(closed, []);

    busy1();
    assert.ok(registry.reserveInitialization('a'));
    assert.deepEqual([...registry.transports.keys()], ['s-2']);
  });

  it('never evicts a session with a request in flight even when it is the least recently used', () => {
    const { registry, add } = fakeRegistry({ perBearer: 2, perProcess: 50 });
    add('s-old', 'a', 1);
    add('s-new', 'a', 2);
    assert.ok(registry.reserveRequest('a', 's-old'));
    assert.ok(registry.reserveInitialization('a'));
    assert.deepEqual([...registry.transports.keys()], ['s-old']);
  });

  it('at the process cap a caller with fewer sessions evicts the least recently used idle session of the largest holder', async () => {
    const { registry, add, closed } = fakeRegistry({ perBearer: 5, perProcess: 4 });
    add('b-3', 'b', 3);
    add('b-1', 'b', 1);
    add('b-2', 'b', 2);
    add('c-1', 'c', 0);

    assert.ok(registry.reserveInitialization('a'));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual([...registry.transports.keys()].sort(), ['b-2', 'b-3', 'c-1']);
    assert.deepEqual(closed, ['b-1']);
  });

  it('at the process cap refuses and evicts nothing when no bearer holds more than the caller', () => {
    const { registry, add, closed } = fakeRegistry({ perBearer: 5, perProcess: 3 });
    add('a-1', 'a', 1);
    add('b-1', 'b', 2);
    add('c-1', 'c', 3);
    // The caller's only session is busy, so it has nothing of its own to evict, and everyone holds one: a tie is not "more".
    assert.ok(registry.reserveRequest('a', 'a-1'));
    assert.equal(registry.reserveInitialization('a'), null);
    assert.deepEqual([...registry.transports.keys()].sort(), ['a-1', 'b-1', 'c-1']);
    assert.deepEqual(closed, []);
  });

  it('at the process cap refuses and evicts nothing when the largest holder has only sessions with a request in flight', () => {
    const { registry, add, closed } = fakeRegistry({ perBearer: 5, perProcess: 4 });
    add('b-1', 'b', 1);
    add('b-2', 'b', 2);
    add('b-3', 'b', 3);
    add('c-1', 'c', 0);
    assert.ok(registry.reserveRequest('b', 'b-1'));
    assert.ok(registry.reserveRequest('b', 'b-2'));
    assert.ok(registry.reserveRequest('b', 'b-3'));

    assert.equal(registry.reserveInitialization('a'), null);
    assert.equal(registry.transports.size, 4);
    assert.deepEqual(closed, []);
  });

  it('evicts the least recently used idle session of the caller when the process is full', () => {
    const { registry, add } = fakeRegistry({ perBearer: 5, perProcess: 3 });
    add('b-1', 'b', 1);
    add('a-1', 'a', 5);
    add('a-2', 'a', 6);
    assert.ok(registry.reserveInitialization('a'));
    assert.deepEqual([...registry.transports.keys()].sort(), ['a-2', 'b-1']);
  });

  it('admits the new session even if closing the evicted transport rejects', async () => {
    const { registry, add, errors } = fakeRegistry({ perBearer: 1, perProcess: 5 });
    add('s-1', 'a', 1, async () => { throw new Error('close failed'); });
    assert.ok(registry.reserveInitialization('a'));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(registry.transports.size, 0);
    assert.deepEqual(errors, ['MCP transport cleanup failed']);
  });

  it('answers a request for an evicted session id with the ordinary unknown-session answer', async () => {
    const close = mock.method(StreamableHTTPServerTransport.prototype, 'close', async () => {});
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      maxSessionsPerBearer: 2,
      fetchImpl: async () => authContextResponse(),
    });
    const first = await initializeSession(baseUrl, 'access-token-a');
    const second = await initializeSession(baseUrl, 'access-token-a');
    const third = await initializeSession(baseUrl, 'access-token-a');
    assert.equal(server.sessionCount(), 2);
    assert.equal(close.mock.callCount(), 1);

    const gone = await requestExistingSession(baseUrl, 'access-token-a', first, { jsonrpc: '2.0', id: 50, method: 'ping', params: {} });
    assert.equal(gone.status, 404);
    assert.deepEqual(await gone.json(), { error: 'Session not found' });
    for (const id of [second, third]) {
      const alive = await requestExistingSession(baseUrl, 'access-token-a', id, { jsonrpc: '2.0', id: 51, method: 'ping', params: {} });
      assert.equal(alive.status, 200);
      await alive.text();
    }
  });
});

describe('STACK MCP HTTP availability limits', () => {
  it('rejects an oversized declared body before authentication', async () => {
    let authenticationCalls = 0;
    const { baseUrl } = await startServer({
      maxRequestBodyBytes: 64,
      fetchImpl: async () => {
        authenticationCalls += 1;
        return authContextResponse();
      },
    });
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer synthetic-size-bearer',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ payload: 'x'.repeat(128) }),
    });
    assert.equal(response.status, 413);
    assert.deepEqual(await response.json(), { error: 'MCP request exceeds size limit' });
    assert.equal(authenticationCalls, 0);
  });

  it('counts the decoded bytes of a chunked body', async () => {
    const { baseUrl } = await startServer({
      maxRequestBodyBytes: 64,
      fetchImpl: async () => authContextResponse(),
    });
    const pending = openChunkedPost(baseUrl, {
      Authorization: 'Bearer synthetic-chunked-bearer',
    });
    pending.request.write('{"payload":"');
    pending.request.write('x'.repeat(80));
    pending.request.end('"}');
    const response = await pending.response;
    assert.equal(response.status, 413);
    assert.deepEqual(JSON.parse(response.body), { error: 'MCP request exceeds size limit' });
  });

  it('times out a slow body, tears down its session, and keeps health responsive', async () => {
    const { server, baseUrl } = await startServer({
      requestTimeoutMs: 100,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-slow-bearer');
    const pending = openChunkedPost(baseUrl, {
      Authorization: 'Bearer synthetic-slow-bearer',
      'Mcp-Session-Id': sessionId,
    });
    pending.request.write('{"jsonrpc":"2.0"');

    const health = await fetch(`${baseUrl}/health`);
    assert.equal(health.status, 200);
    const response = await pending.response;
    pending.request.destroy();
    assert.equal(response.status, 504);
    assert.deepEqual(JSON.parse(response.body), { error: 'MCP request timed out' });
    assert.equal(server.sessionCount(), 0);
  });

  it('rejects parallel work over the per-session ceiling without blocking health', async () => {
    const { baseUrl } = await startServer({
      maxInFlightPerSession: 1,
      requestTimeoutMs: 1_000,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-parallel-bearer');
    let signalStarted!: () => void;
    const started = new Promise<void>((resolve) => { signalStarted = resolve; });
    let release!: () => void;
    const hold = new Promise<void>((resolve) => { release = resolve; });
    mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async (_req: IncomingMessage, res: ServerResponse) => {
        signalStarted();
        await hold;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      },
    );

    const first = requestExistingSession(
      baseUrl,
      'synthetic-parallel-bearer',
      sessionId,
      { jsonrpc: '2.0', id: 80, method: 'ping', params: {} },
    );
    await started;
    const rejected = await requestExistingSession(
      baseUrl,
      'synthetic-parallel-bearer',
      sessionId,
      { jsonrpc: '2.0', id: 81, method: 'ping', params: {} },
    );
    assert.equal(rejected.status, 429);
    assert.equal(rejected.headers.get('retry-after'), '5');
    assert.equal((await fetch(`${baseUrl}/health`)).status, 200);
    release();
    assert.equal((await first).status, 200);
  });

  it('returns 413 for an oversized response and keeps the session', async () => {
    const { server, baseUrl } = await startServer({
      maxResponseBytes: 512,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-response-bearer');
    const handle = mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async (_req: IncomingMessage, res: ServerResponse) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ result: 'x'.repeat(1024) }));
      },
    );
    const response = await requestExistingSession(
      baseUrl,
      'synthetic-response-bearer',
      sessionId,
      { jsonrpc: '2.0', id: 82, method: 'tools/list', params: {} },
    );
    assert.equal(response.status, 413);
    assert.deepEqual(await response.json(), { error: 'MCP response exceeds size limit' });
    // The session is still there, and its next call is answered.
    assert.equal(server.sessionCount(), 1);
    handle.mock.restore();
    const next = await requestExistingSession(
      baseUrl,
      'synthetic-response-bearer',
      sessionId,
      { jsonrpc: '2.0', id: 83, method: 'ping', params: {} },
    );
    assert.equal(next.status, 200);
    await next.text();
  });

  it('takes the largest advertised input on a session its own bearer opened, and only a small one before that', async () => {
    const { server, baseUrl } = await startServer({
      maxRequestBodyBytes: 8 * 1024,
      maxNewSessionBodyBytes: 512,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-large-bearer');
    mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async (_req: IncomingMessage, res: ServerResponse, body?: unknown) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ received: JSON.stringify(body).length }));
      },
    );
    const big = { jsonrpc: '2.0', id: 90, method: 'tools/call', params: { name: 'stack_website_publish', arguments: { blob: 'y'.repeat(4000) } } };
    const own = await requestExistingSession(baseUrl, 'synthetic-large-bearer', sessionId, big);
    assert.equal(own.status, 200);
    assert.ok(((await own.json()) as { received: number }).received > 4000);
    // The same body with another bearer, with no session, or with a session id nobody holds never gets past the small limit.
    for (const [bearer, id] of [['synthetic-other-bearer', sessionId], ['synthetic-large-bearer', undefined], ['synthetic-large-bearer', 'no-such-session']] as const) {
      const refused = await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${bearer}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          ...(id ? { 'Mcp-Session-Id': id } : {}),
        },
        body: JSON.stringify(big),
      });
      assert.equal(refused.status, 413);
      await refused.text();
    }
    assert.equal(server.sessionCount(), 1);
  });

  it('reads large bodies only while the memory they take fits, tells another to retry, and never refuses a small one', async () => {
    const { server, baseUrl } = await startServer({
      maxRequestBodyBytes: 8 * 1024,
      maxNewSessionBodyBytes: 256,
      // One body of about 1,100 bytes takes its 1,100 bytes of the budget: one fits, a second does not.
      maxLargeBodyBytesInFlight: 1_500,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-gate-bearer');
    let release!: () => void;
    const hold = new Promise<void>((resolve) => { release = resolve; });
    let signalStarted!: () => void;
    const started = new Promise<void>((resolve) => { signalStarted = resolve; });
    mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async (_req: IncomingMessage, res: ServerResponse, body?: { id?: number }) => {
        if (body?.id === 100) {
          signalStarted();
          await hold;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      },
    );
    const large = (id: number) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'stack_drive_upload', arguments: { blob: 'z'.repeat(1000) } } });
    const first = requestExistingSession(baseUrl, 'synthetic-gate-bearer', sessionId, large(100));
    await started;
    const second = await requestExistingSession(baseUrl, 'synthetic-gate-bearer', sessionId, large(101));
    assert.equal(second.status, 503);
    assert.equal(second.headers.get('retry-after'), '5');
    await second.text();
    // A body of the size of an ordinary message is never refused for it.
    const small = await requestExistingSession(baseUrl, 'synthetic-gate-bearer', sessionId, { jsonrpc: '2.0', id: 102, method: 'ping', params: {} });
    assert.equal(small.status, 200);
    await small.text();
    release();
    assert.equal((await first).status, 200);
    // The memory is given back when the request ends.
    const third = await requestExistingSession(baseUrl, 'synthetic-gate-bearer', sessionId, large(103));
    assert.equal(third.status, 200);
    await third.text();
    assert.equal(server.sessionCount(), 1);
  });

  it('ends only a tool call that passed its tool\'s deadline, with an error for that call, and keeps the session', async () => {
    const { server, baseUrl } = await startServer({
      requestTimeoutMs: 60,
      toolBackstopMs: 40,
      toolDeadlineMs: (tool) => (tool === 'stack_workspace_run' ? 400 : 60),
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-deadline-bearer');
    let hold = true;
    const handle = mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async (_req: IncomingMessage, res: ServerResponse) => {
        if (hold) await new Promise((resolve) => setTimeout(resolve, 2_000));
        if (!res.writableEnded) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{}');
        }
      },
    );
    // A tool with a long deadline is not ended at the ordinary request time.
    const startedAt = Date.now();
    const slow = await requestExistingSession(baseUrl, 'synthetic-deadline-bearer', sessionId, {
      jsonrpc: '2.0', id: 91, method: 'tools/call', params: { name: 'stack_workspace_run', arguments: {} },
    });
    assert.equal(slow.status, 200);
    assert.deepEqual(await slow.json(), {
      jsonrpc: '2.0',
      id: 91,
      error: { code: -32001, message: 'This call took longer than STACK waits for it. The session is still open; the call may have finished or may still be running.' },
    });
    const waited = Date.now() - startedAt;
    assert.ok(waited >= 400, `waited ${waited} ms`);
    assert.ok(waited < 1_500, `waited ${waited} ms`);
    assert.equal(server.sessionCount(), 1);
    // The session answers its next call.
    hold = false;
    handle.mock.restore();
    const next = await requestExistingSession(baseUrl, 'synthetic-deadline-bearer', sessionId, { jsonrpc: '2.0', id: 92, method: 'ping', params: {} });
    assert.equal(next.status, 200);
    await next.text();
  });

  it('keeps a response that is still being made open with white space, and the answer that follows is whole JSON', async () => {
    const { baseUrl } = await startServer({
      jsonKeepaliveMs: 40,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-keepalive-bearer');
    mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async (_req: IncomingMessage, res: ServerResponse) => {
        await new Promise((resolve) => setTimeout(resolve, 250));
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '33' });
        res.end('{"jsonrpc":"2.0","id":93,"result":{}}');
      },
    );
    const response = await requestExistingSession(baseUrl, 'synthetic-keepalive-bearer', sessionId, {
      jsonrpc: '2.0', id: 93, method: 'tools/call', params: { name: 'stack_workspace_run', arguments: {} },
    });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /application\/json/);
    const text = await response.text();
    assert.match(text, /^ {2,}\{/u);
    assert.deepEqual(JSON.parse(text), { jsonrpc: '2.0', id: 93, result: {} });
  });

  it('answers a result past the ceiling after the keepalive as an error in the body already started, and keeps the session', async () => {
    const { server, baseUrl } = await startServer({
      jsonKeepaliveMs: 40,
      maxResponseBytes: 512,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-late-ceiling-bearer');
    const handle = mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async (_req: IncomingMessage, res: ServerResponse) => {
        await new Promise((resolve) => setTimeout(resolve, 250));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: 94, result: 'x'.repeat(2048) }));
      },
    );
    const response = await requestExistingSession(baseUrl, 'synthetic-late-ceiling-bearer', sessionId, {
      jsonrpc: '2.0', id: 94, method: 'tools/call', params: { name: 'stack_workspace_run', arguments: {} },
    });
    // The 200 went out with the keepalive; what follows is a JSON-RPC error, whole, never a body cut short.
    assert.equal(response.status, 200);
    const answer = JSON.parse(await response.text()) as { id: number; error: { code: number; message: string } };
    assert.equal(answer.id, 94);
    assert.equal(answer.error.code, -32000);
    assert.equal(answer.error.message, 'The answer to this call is larger than this connection can return. The session is still open.');
    assert.equal(server.sessionCount(), 1);
    handle.mock.restore();
    const next = await requestExistingSession(baseUrl, 'synthetic-late-ceiling-bearer', sessionId, { jsonrpc: '2.0', id: 95, method: 'ping', params: {} });
    assert.equal(next.status, 200);
    await next.text();
  });

  it('lets one bearer send several large bodies at once while the memory they take fits', async () => {
    const { baseUrl } = await startServer({
      maxRequestBodyBytes: 8 * 1024,
      maxNewSessionBodyBytes: 256,
      maxLargeBodyBytesInFlight: 100_000,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-share-bearer-a');
    let release!: () => void;
    const hold = new Promise<void>((resolve) => { release = resolve; });
    let started = 0;
    mock.method(
      StreamableHTTPServerTransport.prototype,
      'handleRequest',
      async (_req: IncomingMessage, res: ServerResponse, body?: { id?: number }) => {
        if ((body?.id ?? 0) >= 200) {
          started += 1;
          await hold;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      },
    );
    const large = (id: number) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'stack_drive_upload', arguments: { blob: 'z'.repeat(1000) } } });
    const a1 = requestExistingSession(baseUrl, 'synthetic-share-bearer-a', sessionId, large(200));
    const a2 = requestExistingSession(baseUrl, 'synthetic-share-bearer-a', sessionId, large(201));
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal(started, 2);
    release();
    assert.equal((await a1).status, 200);
    assert.equal((await a2).status, 200);
  });

  it('reads a large body on a session\'s own bearer with no check of its own: only the session\'s one check of the bearer', async () => {
    let checks = 0;
    const { baseUrl } = await startServer({
      maxRequestBodyBytes: 8 * 1024,
      maxNewSessionBodyBytes: 256,
      fetchImpl: async () => { checks += 1; return authContextResponse(); },
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-recheck-bearer');
    mock.method(StreamableHTTPServerTransport.prototype, 'handleRequest', async (_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
    const before = checks;
    const response = await requestExistingSession(baseUrl, 'synthetic-recheck-bearer', sessionId, {
      jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'stack_drive_upload', arguments: { blob: 'z'.repeat(1000) } },
    });
    assert.equal(response.status, 200);
    await response.text();
    assert.equal(checks, before + 1);
  });

  it('reads a large body that does not say how long it is, counting every byte it sent as it arrives', async () => {
    const { server, baseUrl } = await startServer({
      maxRequestBodyBytes: 8 * 1024,
      maxNewSessionBodyBytes: 256,
      maxLargeBodyBytesInFlight: 1_000,
      fetchImpl: async () => authContextResponse(),
    });
    const sessionId = await initializeSession(baseUrl, 'synthetic-chunked-large-bearer');
    mock.method(StreamableHTTPServerTransport.prototype, 'handleRequest', async (_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
    const send = async (extra: number) => {
      const pending = openChunkedPost(baseUrl, {
        Authorization: 'Bearer synthetic-chunked-large-bearer',
        'Mcp-Session-Id': sessionId,
      });
      pending.request.write('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"blob":"');
      pending.request.write('y'.repeat(extra));
      pending.request.end('"}}');
      return pending.response;
    };
    // 660 bytes in all, which fits.
    assert.equal((await send(600)).status, 200);
    // 1,060 bytes in all: only 804 of them are past the small size, but the whole body counts, so it is asked to come back.
    assert.equal((await send(1000)).status, 503);
    assert.equal(server.sessionCount(), 1);
  });

  it('closes the connection of a request it answers before its body was read, instead of holding it', async () => {
    const { baseUrl } = await startServer({ requestTimeoutMs: 400, fetchImpl: async () => authContextResponse() });
    // No bearer: refused at once, and the sender that goes on sending does not keep the connection.
    const pending = openChunkedPost(baseUrl, {});
    pending.request.write('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"blob":"');
    const closed = new Promise<void>((resolve) => pending.request.once('close', () => resolve()));
    const response = await pending.response;
    assert.equal(response.status, 401);
    const startedAt = Date.now();
    await closed;
    assert.ok(Date.now() - startedAt < 3_000, `closed after ${Date.now() - startedAt} ms`);
  });
});

describe('STACK MCP HTTP session expiry', () => {
  it('closes and removes an idle session', async () => {
    let now = 1_000;
    const close = mock.method(StreamableHTTPServerTransport.prototype, 'close', async () => {});
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => authContextResponse(),
      sessionIdleTtlMs: 100,
      now: () => now,
    });
    const initialized = await initialize(baseUrl, 'access-token-a');
    assert.equal(initialized.status, 200);
    const sessionId = initialized.headers.get('mcp-session-id');
    assert.ok(sessionId);
    assert.equal(server.sessionCount(), 1);

    now += 101;
    await server.pruneIdleSessions();

    assert.equal(server.sessionCount(), 0);
    assert.equal(close.mock.callCount(), 1);

    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer access-token-a',
        'Mcp-Session-Id': sessionId,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    });
    assert.equal(response.status, 404);
  });

  it('logs cleanup failures without the bearer or session id', async () => {
    let now = 1_000;
    const close = mock.method(StreamableHTTPServerTransport.prototype, 'close', async () => {
      throw new Error('close failed for access-token-secret');
    });
    const errors: string[] = [];
    const { server, baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => authContextResponse(),
      sessionIdleTtlMs: 100,
      now: () => now,
      logger: { error: (message) => errors.push(String(message)) },
    });
    const initialized = await initialize(baseUrl, 'access-token-secret');
    assert.equal(initialized.status, 200);
    const sessionId = initialized.headers.get('mcp-session-id');
    assert.ok(sessionId);

    now += 101;
    await server.pruneIdleSessions();

    assert.equal(close.mock.callCount(), 1);
    assert.deepEqual(errors, ['MCP transport cleanup failed']);
    const logged = JSON.stringify(errors);
    assert.doesNotMatch(logged, /access-token-secret/);
    assert.doesNotMatch(logged, new RegExp(sessionId));
  });
});

async function startDirectoryServer(extra: Parameters<typeof createStackMcpHttpServer>[0] = {}) {
  return startServer({
    apiUrl: 'https://api.test',
    mcpResource: 'https://mcp.test/mcp',
    oauthEnabled: true,
    fetchImpl: resourceAwareFetch(),
    ...extra,
  });
}

async function post(baseUrl: string, path: string, bearer: string | undefined, body: unknown, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

async function toolNamesAt(baseUrl: string, path: string, bearer: string, sessionId: string): Promise<string[]> {
  const response = await post(baseUrl, path, bearer, { jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} }, {
    'Mcp-Session-Id': sessionId,
  });
  assert.equal(response.status, 200);
  const payload = JSON.parse(await response.text()) as {
    result?: { tools?: Array<{ name: string; annotations?: Record<string, unknown> }> };
  };
  assert.ok(payload.result?.tools);
  for (const tool of payload.result.tools) {
    for (const hint of ['readOnlyHint', 'destructiveHint', 'openWorldHint']) {
      assert.equal(typeof tool.annotations?.[hint], 'boolean', `${tool.name} ${hint}`);
    }
  }
  return payload.result.tools.map((tool) => tool.name);
}

describe('Origin validation', () => {
  for (const origin of [
    'not a url',
    'null',
    'http://evil.example',
    'http://10.0.0.5:8080',
    'https://claude.ai/path',
    'ftp://files.example',
    'https://user:pass@claude.ai',
  ]) {
    it(`returns 403 for Origin ${JSON.stringify(origin)}`, async () => {
      const { server, baseUrl } = await startDirectoryServer();
      for (const path of ['/mcp', '/directory']) {
        const response = await post(baseUrl, path, 'mcp-token', initializeBody(), { Origin: origin });
        assert.equal(response.status, 403, `${path} ${origin}`);
        assert.deepEqual(await response.json(), { error: 'Origin not allowed' });
      }
      assert.equal(server.sessionCount(), 0);
    });
  }

  for (const origin of ['https://claude.ai', 'https://chatgpt.com', 'http://localhost:6274', 'http://127.0.0.1:3000']) {
    it(`accepts Origin ${origin}`, async () => {
      const { baseUrl } = await startDirectoryServer();
      const response = await post(baseUrl, '/mcp', 'mcp-token', initializeBody(), { Origin: origin });
      assert.equal(response.status, 200);
      await response.text();
    });
  }

  it('accepts a request without an Origin header', async () => {
    const { baseUrl } = await startDirectoryServer();
    const response = await post(baseUrl, '/mcp', 'mcp-token', initializeBody());
    assert.equal(response.status, 200);
    await response.text();
  });

  it('rejects a malformed Origin on a CORS preflight too', async () => {
    const { baseUrl } = await startDirectoryServer();
    const response = await fetch(`${baseUrl}/directory`, { method: 'OPTIONS', headers: { Origin: 'http://evil.example' } });
    assert.equal(response.status, 403);
    await response.text();
  });
});

describe('directory endpoint', () => {
  it('serves protected-resource metadata whose resource is exactly the directory URL', async () => {
    const { baseUrl } = await startDirectoryServer();
    const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/directory`);
    assert.equal(response.status, 200);
    const body = await response.json() as { resource: string; authorization_servers: string[]; scopes_supported: string[] };
    assert.equal(body.resource, DIRECTORY_RESOURCE);
    assert.deepEqual(body.authorization_servers, ['https://api.test']);
    assert.deepEqual(body.scopes_supported, [...MCP_DIRECTORY_OAUTH_SCOPES]);
    for (const scope of ['proxy:write', 'skills:invoke', 'services:connect', 'intents:write']) {
      assert.ok(!(body.scopes_supported as string[]).includes(scope), scope);
    }
    for (const scope of body.scopes_supported) {
      assert.ok((MCP_OAUTH_SCOPES as readonly string[]).includes(scope), scope);
    }

    const standard = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);
    assert.equal((await standard.json() as { resource: string }).resource, 'https://mcp.test/mcp');
  });

  it('names the default scope set of each endpoint in its 401 challenge', async () => {
    const { baseUrl } = await startDirectoryServer();
    for (const [path, scopes] of [['/directory', MCP_DIRECTORY_OAUTH_SCOPES], ['/mcp', MCP_OAUTH_SCOPES]] as const) {
      const response = await post(baseUrl, path, undefined, initializeBody());
      assert.equal(response.status, 401);
      const challenge = response.headers.get('www-authenticate') ?? '';
      assert.ok(challenge.includes(`scope="${scopes.join(' ')}"`), `${path}: ${challenge}`);
      await response.text();
    }
  });

  it('challenges an unauthenticated request with the directory metadata URL', async () => {
    const { baseUrl } = await startDirectoryServer();
    const response = await post(baseUrl, '/directory', undefined, initializeBody());
    assert.equal(response.status, 401);
    assert.match(response.headers.get('www-authenticate') ?? '', new RegExp(`resource_metadata="${DIRECTORY_METADATA.replace(/[./]/g, '\\$&')}"`));
    await response.text();
  });

  it('serves the directory tool set to a token granted for the directory resource', async () => {
    const { baseUrl } = await startDirectoryServer();
    const initialized = await post(baseUrl, '/directory', 'directory-token', initializeBody());
    assert.equal(initialized.status, 200);
    const sessionId = initialized.headers.get('mcp-session-id');
    assert.ok(sessionId);
    await initialized.text();
    const names = await toolNamesAt(baseUrl, '/directory', 'directory-token', sessionId);
    assert.ok(names.includes('stack_list_agents'));
    assert.ok(names.includes('stack_revoke_passport'));
    for (const excluded of ['stack_proxy_request', 'stack_invoke_skill', 'stack_connect_service', 'stack_issue_passport', 'stack_repo_state']) {
      assert.ok(!names.includes(excluded), excluded);
    }
  });

  it('refuses a /mcp token on /directory with the directory challenge', async () => {
    const { server, baseUrl } = await startDirectoryServer();
    for (const bearer of ['mcp-token', 'sk_live_operator_key']) {
      const response = await post(baseUrl, '/directory', bearer, initializeBody());
      assert.equal(response.status, 401, bearer);
      assert.match(response.headers.get('www-authenticate') ?? '', /oauth-protected-resource\/directory"/);
      await response.text();
    }
    assert.equal(server.sessionCount(), 0);
  });

  it('refuses a directory token on /mcp with the standard challenge', async () => {
    const { server, baseUrl } = await startDirectoryServer();
    const response = await post(baseUrl, '/mcp', 'directory-token', initializeBody());
    assert.equal(response.status, 401);
    assert.match(response.headers.get('www-authenticate') ?? '', /resource_metadata="https:\/\/mcp\.test\/\.well-known\/oauth-protected-resource"/);
    await response.text();
    assert.equal(server.sessionCount(), 0);
  });

  it('keeps serving /mcp to tokens without a resource claim and to /mcp tokens', async () => {
    const { baseUrl } = await startDirectoryServer();
    for (const bearer of ['mcp-token', 'legacy-token']) {
      const response = await post(baseUrl, '/mcp', bearer, initializeBody());
      assert.equal(response.status, 200, bearer);
      await response.text();
    }
  });

  it('never routes a session created on one path through the other', async () => {
    const { server, baseUrl } = await startDirectoryServer({
      // Report the directory resource for every bearer so only the session check can refuse.
      fetchImpl: async () => boundAuthContextResponse(DIRECTORY_RESOURCE),
    });
    const initialized = await post(baseUrl, '/directory', 'directory-token', initializeBody());
    assert.equal(initialized.status, 200);
    const sessionId = initialized.headers.get('mcp-session-id');
    assert.ok(sessionId);
    await initialized.text();

    const crossed = await post(baseUrl, '/mcp', 'directory-token', { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, {
      'Mcp-Session-Id': sessionId,
    });
    assert.equal(crossed.status, 404);
    assert.deepEqual(await crossed.json(), { error: 'Session not found' });
    assert.equal(server.sessionCount(), 1, 'the crossed request must not delete the session');
  });

  it('rejects a directory resource whose path is not /directory', () => {
    assert.throws(() => createStackMcpHttpServer({
      mcpResource: 'https://mcp.test/mcp',
      directoryResource: 'https://mcp.test/other',
    }), /must end in \/directory/);
  });
});

describe('OpenAI apps domain verification', () => {
  it('serves the configured token as text/plain', async () => {
    const { baseUrl } = await startDirectoryServer({ openaiAppsChallengeToken: 'oa-challenge-123' });
    const response = await fetch(`${baseUrl}/.well-known/openai-apps-challenge`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /^text\/plain/);
    assert.equal(await response.text(), 'oa-challenge-123');
  });

  it('returns 404 when no token is configured', async () => {
    const previous = process.env['OPENAI_APPS_CHALLENGE_TOKEN'];
    delete process.env['OPENAI_APPS_CHALLENGE_TOKEN'];
    try {
      const { baseUrl } = await startDirectoryServer();
      const response = await fetch(`${baseUrl}/.well-known/openai-apps-challenge`);
      assert.equal(response.status, 404);
      await response.text();
    } finally {
      if (previous !== undefined) process.env['OPENAI_APPS_CHALLENGE_TOKEN'] = previous;
    }
  });

  it('reads the token from OPENAI_APPS_CHALLENGE_TOKEN', async () => {
    const previous = process.env['OPENAI_APPS_CHALLENGE_TOKEN'];
    process.env['OPENAI_APPS_CHALLENGE_TOKEN'] = 'from-env-456';
    try {
      const { baseUrl } = await startDirectoryServer();
      const response = await fetch(`${baseUrl}/.well-known/openai-apps-challenge`);
      assert.equal(response.status, 200);
      assert.equal(await response.text(), 'from-env-456');
    } finally {
      if (previous === undefined) delete process.env['OPENAI_APPS_CHALLENGE_TOKEN'];
      else process.env['OPENAI_APPS_CHALLENGE_TOKEN'] = previous;
    }
  });
});

describe('session affinity across machines', () => {
  it('names its own machine in new session ids', async () => {
    const { baseUrl } = await startServer({ fetchImpl: async () => authContextResponse(), machineId: 'abcdef0123456789' });
    const sessionId = await initializeSession(baseUrl, 'bearer');
    assert.match(sessionId, /^abcdef0123456789\.[0-9a-f-]{36}$/);
  });

  it('replays a request for another machine\'s session there, once', async () => {
    const { baseUrl } = await startServer({ fetchImpl: async () => authContextResponse(), machineId: 'abcdef0123456789' });
    const foreign = '0123456789abcdef.0f4b8c55-2a6c-4c9e-9a51-6f1f2b3c4d5e';
    const replay = await requestExistingSession(baseUrl, 'bearer', foreign, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    assert.equal(replay.status, 409);
    assert.equal(replay.headers.get('fly-replay'), 'instance=0123456789abcdef');
    await replay.text();
    const replayed = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer bearer',
        'Mcp-Session-Id': foreign,
        'Fly-Replay-Src': 'instance=abcdef0123456789',
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }),
    });
    assert.equal(replayed.status, 404);
    assert.equal(replayed.headers.get('fly-replay'), null);
    await replayed.text();
  });

  it('never echoes a malformed machine id into a header', async () => {
    const { baseUrl } = await startServer({ fetchImpl: async () => authContextResponse(), machineId: 'abcdef0123456789' });
    const response = await requestExistingSession(baseUrl, 'bearer', 'ZZZ\r\nx.0f4b8c55-2a6c-4c9e-9a51-6f1f2b3c4d5e', {
      jsonrpc: '2.0', id: 2, method: 'tools/list', params: {},
    }).catch(() => null);
    if (response) {
      assert.equal(response.headers.get('fly-replay'), null);
      await response.text();
    }
  });
});

describe('the engine serves the engine alone', () => {
  async function connect(principal: { type: 'operator' | 'member' | 'agent'; id: string }) {
    const { baseUrl } = await startServer({
      apiUrl: 'https://api.test',
      mcpResource: 'https://mcp.test/mcp',
      oauthEnabled: true,
      fetchImpl: async () => authContextResponse(principal),
    });
    const client = new Client({ name: 'engine-only-test', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: 'Bearer engine-token' } },
    }));
    return client;
  }

  it('lists the engine tools and none of the hosted product\'s', async () => {
    const client = await connect({ type: 'operator', id: 'op_1' });
    try {
      const names = (await client.listTools()).tools.map((tool) => tool.name);
      assert.ok(names.includes('stack_list_agents'));
      assert.ok(names.includes('stack_issue_passport'));
      for (const hosted of ['stack_open_account', 'stack_list_wakes', 'stack_send_letter', 'stack_upload_design']) {
        assert.ok(!names.includes(hosted), `${hosted} is hosted and must not be served by the engine`);
      }
      // The catalogue is a resource of the hosted tool group, so the engine declares no resources at all.
      assert.ok(!('resources' in (client.getServerCapabilities() ?? {})));
    } finally {
      await client.close();
    }
  });

  it('declares no wake-up capability, even on an agent\'s own session', async () => {
    const client = await connect({ type: 'agent', id: 'agt_1' });
    try {
      assert.ok(!('logging' in (client.getServerCapabilities() ?? {})));
    } finally {
      await client.close();
    }
  });
});
