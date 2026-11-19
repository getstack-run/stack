// Conformance suite for the EXCHANGE of a workload identity token for a Passport on a running server
// (spec/workload-identity/SPEC.md, sections 6 and 8): POST /v1/workload/passport (SPIFFE) and POST
// /v1/workload/wit (WIMSE). The kit sends requests that need no trust configuration on the server, so the
// refusals are all it can see: the shape of each refusal, its code and its status, and the order the server
// applies its checks in. A refusal that carries the right code proves the server got that far.
//
//   { baseUrl }   the address of a test instance. The calls need no credential.
//
// The server limits these calls to ten a second per source address, so the suite paces itself under that, and its
// last check deliberately goes over the limit.

import { assert, runChecks, skip } from './harness.mjs';
import { b64url, callJson, errorCode, newEd25519, randomToken, signEdDsa, unixNow } from './identity-support.mjs';

const MISSION = { mission_id: 'ms_conformance' };
const PACE_MS = 150;

/** @param {{ baseUrl: string, rateLimits?: boolean }} options  `rateLimits: false` leaves out the check that goes over the limit. */
export async function runWorkloadExchangeSuite(options) {
  const { baseUrl, rateLimits = true } = options;
  const key = newEd25519();
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const post = async (path, { bearer, body = MISSION } = {}) => {
    await sleep(PACE_MS);
    return callJson(baseUrl, path, {
      method: 'POST',
      headers: bearer === undefined ? {} : { authorization: `Bearer ${bearer}` },
      body,
    });
  };
  const now = unixNow();
  const spiffe = (over = {}) => signEdDsa({ alg: 'EdDSA', kid: 'conf-1' }, { sub: `spiffe://${randomToken(6).toLowerCase().replace(/[^a-z0-9]/g, 'x')}.invalid/ns/x`, aud: ['conformance'], iat: now, exp: now + 300, ...over }, key.privateKey);
  const wit = (over = {}) => signEdDsa({ alg: 'EdDSA', kid: 'conf-1' }, { iss: `https://${randomToken(6).toLowerCase().replace(/[^a-z0-9]/g, 'x')}.invalid`, sub: 'https://workloads.invalid/x', aud: 'conformance', iat: now, exp: now + 300, ...over }, key.privateKey);
  const withoutClaim = (token, name) => {
    const [h, p] = token.split('.');
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    delete payload[name];
    return signEdDsa(JSON.parse(Buffer.from(h, 'base64url').toString('utf8')), payload, key.privateKey);
  };
  const endpoints = [['/v1/workload/passport', spiffe], ['/v1/workload/wit', wit]];
  const expectError = (r, status, code, why) => {
    assert(r.status === status && errorCode(r) === code, `${why}: answered ${r.status} ${errorCode(r) ?? JSON.stringify(r.body)}, not ${status} ${code}`);
  };

  return runChecks('workload exchange', [
    {
      id: 'WX01', level: 'MUST', title: 'refuses a request with no bearer token (401 UNAUTHORIZED), before it looks at the body',
      async run() {
        for (const [path] of endpoints) {
          expectError(await post(path, {}), 401, 'UNAUTHORIZED', `${path} with no bearer`);
          expectError(await post(path, { body: {} }), 401, 'UNAUTHORIZED', `${path} with no bearer and no mission`);
        }
      },
    },
    {
      id: 'WX02', level: 'MUST', title: 'refuses a body that is not exactly {mission_id: ms_...} (400 MISSION_REQUIRED), before it looks at the token',
      async run() {
        for (const [path] of endpoints) {
          for (const [why, body] of [
            ['no mission id', {}],
            ['a mission id that is not ms_...', { mission_id: 'mission-1' }],
            ['an extra member', { ...MISSION, agent_id: 'agt_x' }],
          ]) {
            expectError(await post(path, { bearer: 'not-even-a-token', body }), 400, 'MISSION_REQUIRED', `${path} with ${why}`);
          }
        }
      },
    },
    {
      id: 'WX03', level: 'MUST', title: 'refuses a bearer that is not a JWT (400 WORKLOAD_TOKEN_MALFORMED)',
      async run() {
        for (const [path] of endpoints) {
          expectError(await post(path, { bearer: 'not-a-jwt' }), 400, 'WORKLOAD_TOKEN_MALFORMED', `${path} with text`);
          expectError(await post(path, { bearer: `${b64url({ alg: 'none' })}.${b64url('payload')}.` }), 400, 'WORKLOAD_TOKEN_MALFORMED', `${path} with a payload that is not JSON`);
        }
      },
    },
    {
      id: 'WX04', level: 'MUST', title: 'refuses a SPIFFE token whose sub is absent or is not a SPIFFE id (400 WORKLOAD_SPIFFE_ID_INVALID)',
      async run() {
        expectError(await post('/v1/workload/passport', { bearer: spiffe({ sub: 'https://not-spiffe.invalid/x' }) }), 400, 'WORKLOAD_SPIFFE_ID_INVALID', 'a sub that is a URL');
        expectError(await post('/v1/workload/passport', { bearer: withoutClaim(spiffe(), 'sub') }), 400, 'WORKLOAD_SPIFFE_ID_INVALID', 'a token with no sub');
        expectError(await post('/v1/workload/passport', { bearer: spiffe({ sub: 'spiffe:///no-host' }) }), 400, 'WORKLOAD_SPIFFE_ID_INVALID', 'an id with no trust domain');
      },
    },
    {
      id: 'WX05', level: 'MUST', title: 'refuses a WIT with no iss (400 WORKLOAD_ISSUER_MISSING) or no sub (400 WORKLOAD_SUBJECT_MISSING)',
      async run() {
        expectError(await post('/v1/workload/wit', { bearer: withoutClaim(wit(), 'iss') }), 400, 'WORKLOAD_ISSUER_MISSING', 'a WIT with no iss');
        expectError(await post('/v1/workload/wit', { bearer: withoutClaim(wit(), 'sub') }), 400, 'WORKLOAD_SUBJECT_MISSING', 'a WIT with no sub');
      },
    },
    {
      id: 'WX06', level: 'MUST', title: 'refuses a well-formed token of an issuer nobody configured (401 WORKLOAD_ISSUER_NOT_CONFIGURED), without verifying it',
      async run() {
        expectError(await post('/v1/workload/passport', { bearer: spiffe() }), 401, 'WORKLOAD_ISSUER_NOT_CONFIGURED', 'a SVID of an unknown trust domain');
        expectError(await post('/v1/workload/wit', { bearer: wit() }), 401, 'WORKLOAD_ISSUER_NOT_CONFIGURED', 'a WIT of an unknown issuer');
      },
    },
    {
      id: 'WX07', level: 'MUST', title: 'answers every refusal in the API error envelope, with a code and a message, and no token or key in it',
      async run() {
        const bearer = spiffe();
        const r = await post('/v1/workload/passport', { bearer });
        assert(r.body?.error && typeof r.body.error.code === 'string' && typeof r.body.error.message === 'string', 'the refusal is not { error: { code, message } }');
        assert(!r.text.includes(bearer) && !r.text.includes(bearer.split('.')[2]), 'the refusal repeats the token');
        assert(r.body.error_description === undefined, 'the refusal uses the flat OAuth shape');
      },
    },
    {
      id: 'WX10', level: 'MUST', title: 'limits calls to ten a second per source address (429 RATE_LIMITED, details.scope ip)',
      async run() {
        if (!rateLimits) return skip('rate limit checks are off');
        const results = await Promise.all(Array.from({ length: 30 }, () => callJson(baseUrl, '/v1/workload/passport', {
          method: 'POST', headers: { authorization: `Bearer ${spiffe()}` }, body: MISSION, waitOnRateLimit: false,
        })));
        const limited = results.filter((r) => r.status === 429);
        assert(limited.length > 0, 'thirty calls in one burst were all answered');
        assert(limited.every((r) => errorCode(r) === 'RATE_LIMITED'), 'a 429 did not carry the RATE_LIMITED code');
        assert(limited.some((r) => r.body?.error?.details?.scope === 'ip'), 'no 429 named the ip window');
        await sleep(1500);
      },
    },
  ]);
}
