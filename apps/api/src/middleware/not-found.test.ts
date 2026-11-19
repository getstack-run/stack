import { readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { apiLoggerOptions } from '../config/logger.js';
import { notFoundHandler, redactPathForLog } from './not-found.js';

// A request that matches no route can still carry a one-time token in its
// path (a connect link, a call relay) or a credential in its query. The
// default Fastify handler logs and echoes the whole URL; this one never does.

const TOKEN = ['Zk3', 'Tq9_LmN0pQrStUvWxYz1234567890AbCdEfGhIj'].join('-');
const SECRET = ['sk', 'live', 'super', 'secret', 'key', 'value', '0001'].join('-');

describe('redactPathForLog', () => {
  it.each([
    [`/v1/services/connect-links/${TOKEN}`, '/v1/services/connect-links/[redacted]'],
    ['/v1/services/connect-links/short', '/v1/services/connect-links/[redacted]'],
    [`/app/connect/link/${TOKEN}`, '/app/connect/link/[redacted]'],
    ['/v1/inbound/accounts/twilio/relay/abc', '/v1/inbound/accounts/twilio/relay/[redacted]'],
    [`/v1/unknown/${TOKEN}/more`, '/v1/unknown/[redacted]/more'],
    [`/v1/agents/agt_${'a'.repeat(30)}`, '/v1/agents/[redacted]'],
    ['/v1/agents/agt_short', '/v1/agents/agt_short'],
    ['/v1/missing', '/v1/missing'],
    ['/', '/'],
    ['', '/'],
  ])('%s -> %s', (raw, expected) => {
    expect(redactPathForLog(raw)).toBe(expected);
  });

  it('drops the query and the fragment whatever they hold', () => {
    expect(redactPathForLog(`/v1/missing?token=${TOKEN}&key=${SECRET}#${TOKEN}`)).toBe('/v1/missing');
  });
});

describe('the API not-found handler', () => {
  async function run(url: string) {
    let output = '';
    const stream = new Writable({ write(chunk, _encoding, done) { output += String(chunk); done(); } });
    const app = Fastify({ logger: { ...apiLoggerOptions('info'), stream } });
    app.setNotFoundHandler(notFoundHandler);
    app.get('/v1/known', async () => ({ ok: true }));
    await app.ready();
    const response = await app.inject({ method: 'GET', url });
    await app.close();
    return { output, response };
  }

  it('answers 404 and keeps the token path and the query out of the log and the answer', async () => {
    const { output, response } = await run(`/v1/services/connect-links/${TOKEN}?token=${TOKEN}&api_key=${SECRET}`);
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({
      error: { code: 'NOT_FOUND', message: 'Route GET:/v1/services/connect-links/[redacted] not found' },
    });
    expect(output).toContain('Route not found');
    expect(output).toContain('/v1/services/connect-links/[redacted]');
    expect(output).not.toContain(TOKEN);
    expect(output).not.toContain(SECRET);
    expect(response.body).not.toContain(TOKEN);
    expect(response.body).not.toContain(SECRET);
  });

  it('keeps an ordinary missing path readable and still serves known routes', async () => {
    const missing = await run('/v1/nothing-here?x=1');
    expect(missing.output).toContain('/v1/nothing-here');
    expect(missing.output).not.toContain('x=1');
    const known = await run('/v1/known');
    expect(known.response.statusCode).toBe(200);
  });

  it('is the handler the server installs', () => {
    const server = readFileSync(new URL('../start.ts', import.meta.url), 'utf8');
    expect(server).toContain('app.setNotFoundHandler(notFoundHandler);');
  });
});
