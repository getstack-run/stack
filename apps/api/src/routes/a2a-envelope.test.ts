import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';
import type { Services } from '../config/services.js';

/**
 * The A2A endpoint is JSON-RPC 2.0, so a malformed request keeps producing a
 * JSON-RPC error object (-32600) with HTTP 400, not the REST validation
 * envelope. The request id is echoed only when it is a valid JSON-RPC id.
 */

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    request['operatorId'] = 'op_owner';
  },
}));
vi.mock('../middleware/meter.js', () => ({ meterAction: vi.fn(async () => {}), enforceOverage: vi.fn(async () => {}) }));

const { registerA2aRpcRoute } = await import('./a2a.js');

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp() {
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerA2aRpcRoute(app, {} as unknown as Services);
  await app.ready();
  return app;
}

function rpc(app: ReturnType<typeof Fastify>, payload: unknown) {
  return app.inject({
    method: 'POST',
    url: '/v1/a2a/jsonrpc',
    headers: { authorization: 'Bearer operator', 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });
}

describe('POST /v1/a2a/jsonrpc envelope', () => {
  it.each([
    ['null', null, null],
    ['an array', [{ jsonrpc: '2.0', method: 'tasks/get' }], null],
    ['a string', 'tasks/get', null],
    ['a wrong version', { jsonrpc: '1.0', id: 7, method: 'tasks/get' }, 7],
    ['a missing version', { id: 'abc', method: 'tasks/get' }, 'abc'],
    ['a missing method', { jsonrpc: '2.0', id: 3 }, 3],
    ['a non-string method', { jsonrpc: '2.0', id: 3, method: 5 }, 3],
    ['an object id', { jsonrpc: '2.0', id: { a: 1 } }, null],
  ])('answers %s with a JSON-RPC invalid-request error', async (_label, payload, echoedId) => {
    const app = await makeApp();
    const res = await rpc(app, payload);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({
      jsonrpc: '2.0',
      id: echoedId,
      error: { code: -32600, message: 'Invalid JSON-RPC envelope' },
    });
  });

  it('answers an unknown method with method-not-found, echoing the id', async () => {
    const app = await makeApp();
    const res = await rpc(app, { jsonrpc: '2.0', id: 11, method: 'tasks/nope' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      jsonrpc: '2.0',
      id: 11,
      error: { code: -32601, message: 'Unknown method "tasks/nope"' },
    });
  });

  it('treats a non-object params like absent params', async () => {
    const app = await makeApp();
    for (const params of [undefined, null, 'x', [1, 2], 5]) {
      const res = await rpc(app, { jsonrpc: '2.0', id: 'r1', method: 'tasks/get', params });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({
        jsonrpc: '2.0',
        id: 'r1',
        error: { code: -32602, message: 'params.id is required' },
      });
    }
  });

  it('passes object params and the id through to the handler', async () => {
    const app = await makeApp();
    const res = await rpc(app, { jsonrpc: '2.0', id: null, method: 'tasks/send', params: { id: 't1' } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32602, message: 'params.message is required' },
    });
  });
});
