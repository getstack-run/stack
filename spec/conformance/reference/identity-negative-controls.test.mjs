// A kit that passes everything proves nothing. These tests run the identity suites against implementations with ONE
// deliberate defect each and require the suite to name the checks that defect should break.

import { createServer } from 'node:http';
import { afterAll, describe, expect, it } from 'vitest';
import {
  presenterFromFunction,
  runAgentJwtMinterSuite,
  runAgentJwtVerifierSuite,
  runOAuthSuite,
  runWorkloadExchangeSuite,
} from '../src/index.mjs';
import { createAgentJwtVerifier, mintAgentJwt } from './agent-jwt-reference.mjs';
import { listen } from './support.mjs';

const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

describe('agent JWT verifier suite', () => {
  const run = (verify) => runAgentJwtVerifierSuite(presenterFromFunction(verify));

  it('fails a verifier that forgets the tokens it has accepted', async () => {
    // A new verifier for every token: no single-use record survives.
    const forgetful = (token, context) => createAgentJwtVerifier()(token, context);
    const ids = mustFailedIds(await run(forgetful));
    expect(ids).toEqual(expect.arrayContaining(['AJV30', 'AJV31', 'AJV33']));
  });

  it('fails a verifier that accepts alg none, or any lifetime, or a token issued in the future', async () => {
    const lax = async (token, { agentId, publicJwk }) => {
      const [h, p] = token.split('.');
      const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
      if (header.alg === 'none' && payload.sub === agentId) return payload;
      return createAgentJwtVerifier()(token, { agentId, publicJwk });
    };
    expect(mustFailedIds(await run(lax))).toContain('AJV16');
    const longLived = (() => {
      const inner = createAgentJwtVerifier();
      return async (token, context) => {
        const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
        // Pretend the lifetime limit is not checked by shortening what the reference sees.
        if (payload.exp - payload.iat > 120 && payload.iat <= Math.floor(Date.now() / 1000)) return payload;
        return inner(token, context);
      };
    })();
    expect(mustFailedIds(await run(longLived))).toContain('AJV12');
  });

  it('fails a verifier that records a token before it has checked it', async () => {
    const seen = new Set();
    const inner = createAgentJwtVerifier();
    const early = async (token, context) => {
      const jti = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8') || '{}').jti;
      const repeated = jti !== undefined && seen.has(jti);
      if (jti !== undefined) seen.add(jti);
      if (repeated) {
        const error = new Error('replayed');
        error.code = 'AGENT_JWT_REPLAYED';
        throw error;
      }
      return inner(token, context);
    };
    expect(mustFailedIds(await run(early))).toContain('AJV32');
  });

  it('fails a verifier that accepts everything, and one that accepts nothing', async () => {
    expect((await run(async () => ({ sub: 'x' }))).conforms).toBe(false);
    expect((await run(async () => { throw new Error('no'); })).conforms).toBe(false);
  });
});

describe('agent JWT minter suite', () => {
  it('fails a minter whose tokens live too long, repeat a jti, or say another audience', async () => {
    const tamper = (change) => async (input) => {
      const token = await mintAgentJwt(input);
      const [h, p] = token.split('.');
      const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
      return `${h}.${Buffer.from(JSON.stringify(change(payload))).toString('base64url')}.${token.split('.')[2]}`;
    };
    expect(mustFailedIds(await runAgentJwtMinterSuite({ mint: tamper((p) => ({ ...p, exp: p.iat + 600 })), tokens: 3 }))).toContain('AJM03');
    expect(mustFailedIds(await runAgentJwtMinterSuite({ mint: tamper((p) => ({ ...p, jti: 'aj_same' })), tokens: 3 }))).toContain('AJM07');
    expect(mustFailedIds(await runAgentJwtMinterSuite({ mint: tamper((p) => ({ ...p, aud: 'stack:passport' })), tokens: 3 }))).toContain('AJM02');
  });
});

describe('suites that need a server', () => {
  const servers = [];
  afterAll(() => Promise.all(servers.map((s) => s.close())));
  const serve = async (handler) => {
    const s = await listen(createServer(handler));
    servers.push(s);
    return s.url;
  };

  it('fails an OAuth server that advertises a client secret method, and one that serves nothing', async () => {
    const document = {
      issuer: 'http://x', authorization_endpoint: 'http://x/oauth/authorize', token_endpoint: 'http://x/oauth/token',
      response_types_supported: ['code'], code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    };
    const url = await serve((req, res) => {
      if (req.url === '/.well-known/oauth-authorization-server') return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(document));
      return res.writeHead(404).end();
    });
    const report = await runOAuthSuite({ baseUrl: url, rateLimits: false });
    expect(report.conforms).toBe(false);
    const failure = report.results.find((r) => r.id === 'OA01');
    expect(failure?.status).toBe('fail');
    const none = await runOAuthSuite({ baseUrl: await serve((_req, res) => res.writeHead(404).end()), rateLimits: false });
    expect(mustFailedIds(none).length).toBeGreaterThan(10);
  });

  it('fails a workload exchange that answers 200 to everything, and one that answers a server error', async () => {
    const accepting = await serve((_req, res) => res.writeHead(200, { 'content-type': 'application/json' }).end('{}'));
    const report = await runWorkloadExchangeSuite({ baseUrl: accepting, rateLimits: false });
    expect(mustFailedIds(report)).toEqual(expect.arrayContaining(['WX01', 'WX02', 'WX03', 'WX06']));
    const broken = await serve((_req, res) => res.writeHead(500, { 'content-type': 'application/json' }).end('{"error":{"code":"INTERNAL_ERROR","message":"x"}}'));
    expect((await runWorkloadExchangeSuite({ baseUrl: broken, rateLimits: false })).conforms).toBe(false);
  });
});
