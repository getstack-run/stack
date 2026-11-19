import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { createErrorHandler } from './error-handler.js';
import { jsonBodyParser } from './json-body-parser.js';

// The body parser the server installs for application/json, behind the server's own error handler.

describe('the application/json body parser', () => {
  const apps: Array<{ close(): Promise<unknown> }> = [];
  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  async function app() {
    const server = Fastify({ logger: false });
    server.addContentTypeParser('application/json', { parseAs: 'string' }, jsonBodyParser);
    server.setErrorHandler(createErrorHandler());
    server.post('/echo', async (request) => ({ body: request.body, raw: (request as unknown as { rawBody?: string }).rawBody }));
    await server.ready();
    apps.push(server);
    return server;
  }

  const post = (server: Awaited<ReturnType<typeof app>>, payload: string) =>
    server.inject({ method: 'POST', url: '/echo', headers: { 'content-type': 'application/json' }, payload });

  it('keeps the exact text beside the parsed value', async () => {
    const text = '{ "a" : 1,\n  "b":"é" }';
    const response = await post(await app(), text);
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ body: { a: 1, b: 'é' }, raw: text });
  });

  it('reads an empty body as an empty object', async () => {
    const response = await post(await app(), '');
    expect(response.statusCode).toBe(200);
    expect(response.json().body).toEqual({});
  });

  it('answers 400 INVALID_JSON in the error envelope for a body that is not JSON, never a 500', async () => {
    for (const text of ['{', '{"a":', 'nope', '{"a":1}}']) {
      const response = await post(await app(), text);
      expect(response.statusCode, text).toBe(400);
      expect(response.json()).toEqual({ error: { code: 'INVALID_JSON', message: 'Request body is not valid JSON' } });
    }
  });
});
