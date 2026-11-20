import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { FORWARDED_CLIENT_HEADER, forwardedClientMac } from './forwarded-client.js';
import { globalRateLimitOptions } from './global-rate-limit.js';

const SECRET = 'global-rate-limit-test-secret-0123456789abcdef';
const NOW = 1_700_000_000_000;
const DASHBOARD_ADDRESS = '10.20.30.40';
const BEARER = 'Bearer sk_live_synthetic';

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const SECOND_SECRET = 'second-forwarder-rate-limit-secret-0123456789abcdef';

async function build(secret: string | null | readonly string[] = SECRET): Promise<FastifyInstance> {
  const app = Fastify();
  apps.push(app);
  // The options start.ts registers: the real keys and caps.
  await app.register(rateLimit, globalRateLimitOptions(secret ?? undefined, () => NOW));
  app.get('/probe', async () => ({ ok: true }));
  await app.ready();
  return app;
}

function signed(clientIp: string, secret = SECRET): string {
  const seconds = String(NOW / 1000);
  return `${clientIp}.${seconds}.${forwardedClientMac(clientIp, seconds, secret)}`;
}

async function call(app: FastifyInstance, headers: Record<string, string>): Promise<number> {
  const response = await app.inject({ method: 'GET', url: '/probe', remoteAddress: DASHBOARD_ADDRESS, headers });
  return response.statusCode;
}

async function burst(app: FastifyInstance, count: number, headers: Record<string, string>): Promise<number[]> {
  const codes: number[] = [];
  for (let i = 0; i < count; i += 1) codes.push(await call(app, headers));
  return codes;
}

describe('the global rate limit behind the Console server', () => {
  it('counts one customer burst apart from another customer, each call carrying a valid header', async () => {
    const app = await build();
    const a = { authorization: BEARER, [FORWARDED_CLIENT_HEADER]: signed('198.51.100.1') };
    const b = { authorization: BEARER, [FORWARDED_CLIENT_HEADER]: signed('198.51.100.2') };
    const burstA = await burst(app, 501, a);
    expect(burstA.slice(0, 500).every((code) => code === 200)).toBe(true);
    expect(burstA[500]).toBe(429);
    expect(await call(app, b)).toBe(200);
  });

  it('still shares one bucket for calls without the header from one address, as before', async () => {
    const app = await build();
    const burstA = await burst(app, 501, { authorization: BEARER });
    expect(burstA[500]).toBe(429);
    // Another customer's call from the same address, with no header, is refused too.
    expect(await call(app, { authorization: BEARER })).toBe(429);
  });

  it('holds the 100 a minute cap for calls with no bearer', async () => {
    const app = await build();
    const codes = await burst(app, 101, { [FORWARDED_CLIENT_HEADER]: signed('198.51.100.3') });
    expect(codes[99]).toBe(200);
    expect(codes[100]).toBe(429);
  });

  it('gives a forged header no bucket of its own', async () => {
    const app = await build();
    const forged = (ip: string) => ({
      authorization: BEARER,
      [FORWARDED_CLIENT_HEADER]: signed(ip, 'not-the-dashboard-secret-0123456789abcdef'),
    });
    // 501 calls, each claiming a fresh address with a MAC from the wrong secret: all land on the source address.
    let last = 0;
    for (let i = 0; i < 501; i += 1) last = await call(app, forged(`198.51.100.${(i % 200) + 10}`));
    expect(last).toBe(429);
    expect(await call(app, { authorization: BEARER })).toBe(429);
  });

  it('counts the calls of a second trusted server per client too, the first still working', async () => {
    const app = await build([SECRET, SECOND_SECRET]);
    const viaSecond = (ip: string) => ({ authorization: BEARER, [FORWARDED_CLIENT_HEADER]: signed(ip, SECOND_SECRET) });
    const burstA = await burst(app, 501, viaSecond('198.51.100.1'));
    expect(burstA.slice(0, 500).every((code) => code === 200)).toBe(true);
    expect(burstA[500]).toBe(429);
    expect(await call(app, viaSecond('198.51.100.2'))).toBe(200);
    expect(await call(app, { authorization: BEARER, [FORWARDED_CLIENT_HEADER]: signed('198.51.100.3') })).toBe(200);
  });

  it('gives a header made under a key that is not handed in, a stale one and a malformed one no bucket of their own', async () => {
    const app = await build([SECRET]);
    // The second server's key is not handed in here: its headers are forged.
    let last = 0;
    for (let i = 0; i < 501; i += 1) {
      last = await call(app, { authorization: BEARER, [FORWARDED_CLIENT_HEADER]: signed(`198.51.100.${(i % 200) + 10}`, SECOND_SECRET) });
    }
    expect(last).toBe(429);
    const stale = `198.51.100.9.${NOW / 1000 - 3600}.${forwardedClientMac('198.51.100.9', String(NOW / 1000 - 3600), SECOND_SECRET)}`;
    for (const value of [stale, 'not a header', '']) {
      const both = await build([SECRET, SECOND_SECRET]);
      let code = 0;
      for (let i = 0; i < 501; i += 1) code = await call(both, { authorization: BEARER, [FORWARDED_CLIENT_HEADER]: value });
      expect(code, value).toBe(429);
    }
  });

  it('ignores the header on a deployment with no Console secret', async () => {
    const app = await build(null);
    let last = 0;
    for (let i = 0; i < 501; i += 1) {
      last = await call(app, { authorization: BEARER, [FORWARDED_CLIENT_HEADER]: signed(`198.51.100.${(i % 200) + 10}`) });
    }
    expect(last).toBe(429);
  });
});
