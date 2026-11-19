// Conformance suites for the AGENT JWT of spec/agent-auth/SPEC.md (sections 3 and 4).
//
// Two sides:
//
//   runAgentJwtMinterSuite({ mint })       an agent-side implementation (an SDK). The kit gives it a private key and
//                                          an agent id and checks the tokens it signs.
//   runAgentJwtVerifierSuite({ present })  a server. The kit signs tokens with the key of an enrolled agent, some of
//                                          them deliberately wrong, and checks which ones the server accepts.
//
// A minter is `mint({ agentId, privateJwk }) -> token` (async allowed). A server is reached through a presenter,
// `present(token) -> { accepted, replay?, unavailable?, detail? }`, which either calls your verifier function
// (`presenterFromFunction`) or sends the token to a running server (`presenterFromServer`).

import { assert, runChecks, skip } from './harness.mjs';
import {
  b64url,
  callJson,
  decodeCompact,
  ed25519FromJwk,
  errorCode,
  newEd25519,
  randomToken,
  signEdDsa,
  signHs256,
  unixNow,
} from './identity-support.mjs';

const ISSUER = 'stack-sdk';
const AUDIENCE = 'stack:agent';
const TOLERANCE = 30;

/**
 * @param {{ mint: (input: { agentId: string, privateJwk: object }) => string | Promise<string>, tokens?: number }} options
 */
export async function runAgentJwtMinterSuite(options) {
  const { mint, tokens = 60 } = options;
  const agentId = `agt_${randomToken(9)}`;
  const key = newEd25519();
  const minted = async () => {
    const before = unixNow();
    const token = await mint({ agentId, privateJwk: key.privateJwk });
    return { token, ...decodeCompact(token), before, after: unixNow() };
  };
  const batch = [];
  const all = async () => {
    while (batch.length < tokens) batch.push(await minted());
    return batch;
  };

  return runChecks('agent JWT minter', [
    {
      id: 'AJM01', level: 'MUST', title: 'signs with EdDSA and a signature that verifies with the agent\'s public key',
      async run() {
        const t = (await all())[0];
        assert(t.header.alg === 'EdDSA', `the header alg is ${JSON.stringify(t.header.alg)}`);
        const [h, p, s] = t.token.split('.');
        const { verify } = await import('node:crypto');
        assert(verify(null, Buffer.from(`${h}.${p}`), key.publicKey, Buffer.from(s, 'base64url')), 'the signature does not verify with the public key');
      },
    },
    {
      id: 'AJM02', level: 'MUST', title: 'carries iss stack-sdk, aud stack:agent and sub equal to the agent id',
      async run() {
        for (const t of await all()) {
          assert(t.payload.iss === ISSUER, `iss is ${JSON.stringify(t.payload.iss)}`);
          assert(t.payload.aud === AUDIENCE, `aud is ${JSON.stringify(t.payload.aud)}`);
          assert(t.payload.sub === agentId, `sub is ${JSON.stringify(t.payload.sub)}`);
        }
      },
    },
    {
      id: 'AJM03', level: 'MUST', title: 'sets integer iat and exp, with a lifetime of at most 120 seconds, and iat at the time of signing',
      async run() {
        for (const t of await all()) {
          const { iat, exp } = t.payload;
          assert(Number.isInteger(iat) && Number.isInteger(exp), 'iat and exp must be integers');
          assert(exp > iat, 'exp is not after iat');
          assert(exp - iat <= 120, `the lifetime is ${exp - iat} seconds, over the 120 a server accepts`);
          assert(iat >= t.before - TOLERANCE && iat <= t.after + TOLERANCE, 'iat is not the time of signing');
        }
      },
    },
    {
      id: 'AJM04', level: 'SHOULD', title: 'uses a lifetime of 60 seconds or less',
      async run() {
        for (const t of await all()) assert(t.payload.exp - t.payload.iat <= 60, `the lifetime is ${t.payload.exp - t.payload.iat} seconds`);
      },
    },
    {
      id: 'AJM05', level: 'MUST', title: 'applies nbf, when it sends one, no later than the time it signs',
      async run() {
        for (const t of await all()) {
          if (t.payload.nbf === undefined) continue;
          assert(Number.isInteger(t.payload.nbf) && t.payload.nbf <= t.after + TOLERANCE, 'nbf is in the future');
        }
      },
    },
    {
      id: 'AJM06', level: 'MUST', title: 'gives every token a jti of 1 to 200 characters from A-Z a-z 0-9 _ -',
      async run() {
        for (const t of await all()) assert(/^[A-Za-z0-9_-]{1,200}$/.test(String(t.payload.jti)), `the jti ${JSON.stringify(t.payload.jti)} is not valid`);
      },
    },
    {
      id: 'AJM07', level: 'MUST', title: 'never repeats a jti: every token is new, retries included',
      async run() {
        const ids = (await all()).map((t) => t.payload.jti);
        assert(new Set(ids).size === ids.length, `${ids.length - new Set(ids).size} of ${ids.length} tokens repeated a jti`);
        const tokensSeen = (await all()).map((t) => t.token);
        assert(new Set(tokensSeen).size === tokensSeen.length, 'two requests were given the same token');
      },
    },
    {
      id: 'AJM08', level: 'SHOULD', title: 'draws the jti from a secure random source with at least 128 bits',
      async run() {
        const ids = (await all()).map((t) => String(t.payload.jti));
        // A prefix such as aj_ is allowed; 128 bits is 22 base64url characters, 32 hexadecimal ones.
        for (const id of ids) {
          const body = id.replace(/^[a-z]{1,4}_/, '');
          const random = body.replace(/^\d{9,11}_/, '');
          assert(random.length >= 22, `the jti ${JSON.stringify(id)} carries fewer than 128 bits of randomness`);
        }
      },
    },
    {
      id: 'AJM09', level: 'MUST', title: 'sends no other critical header and no kid that would select another key',
      async run() {
        for (const t of await all()) {
          assert(t.header.crit === undefined, 'a crit header was sent');
          assert(t.header.jku === undefined && t.header.jwk === undefined && t.header.x5u === undefined, 'a header names a key location');
        }
      },
    },
  ]);
}

/** A presenter for a verifier function `(token, { agentId, publicJwk }) => claims`, which keeps its own replay memory. */
export function presenterFromFunction(verify) {
  const agent = newEd25519();
  const agentId = `agt_${randomToken(9)}`;
  const present = async (token, as = { agentId, publicJwk: agent.publicJwk }) => {
    try {
      const claims = await verify(token, { agentId: as.agentId, publicJwk: as.publicJwk });
      return { accepted: claims !== undefined && claims !== null && claims !== false };
    } catch (error) {
      return { accepted: false, replay: error?.code === 'AGENT_JWT_REPLAYED', unavailable: error?.code === 'SERVICE_UNAVAILABLE', detail: error instanceof Error ? error.message : String(error) };
    }
  };
  return { present, agentId, privateKey: agent.privateKey, publicKey: agent.publicKey, unenrolled: (id) => ({ agentId: id, publicJwk: null }) };
}

/**
 * A presenter for a running server: the token is sent as the bearer of GET /v1/auth/context, which answers 200 to
 * any credential the server accepts. `agent` is an agent already enrolled there, with its private key as a JWK.
 */
export function presenterFromServer({ baseUrl, agentId, privateJwk }) {
  const key = ed25519FromJwk(privateJwk);
  const present = async (token) => {
    const r = await callJson(baseUrl, '/v1/auth/context', { headers: { authorization: `Bearer ${token}` } });
    return {
      accepted: r.status === 200,
      replay: errorCode(r) === 'AGENT_JWT_REPLAYED',
      unavailable: r.status === 503,
      status: r.status,
      detail: `${r.status} ${errorCode(r) ?? ''}`.trim(),
    };
  };
  return { present, agentId, privateKey: key.privateKey, publicKey: key.publicKey, unenrolled: (id) => ({ agentId: id }) };
}

/**
 * @param {{
 *   present: (token: string, as?: object) => Promise<{ accepted: boolean, replay?: boolean, unavailable?: boolean, detail?: string }>,
 *   agentId: string,
 *   privateKey: import('node:crypto').KeyObject,
 *   publicKey: import('node:crypto').KeyObject,
 *   unenrolled?: (agentId: string) => object,
 *   unenrolledAgentId?: string,
 * }} options
 */
export async function runAgentJwtVerifierSuite(options) {
  const { present, agentId, privateKey, publicKey } = options;
  const other = newEd25519();
  const header = { alg: 'EdDSA' };
  const claims = (over = {}) => {
    const now = unixNow();
    return { iss: ISSUER, sub: agentId, aud: AUDIENCE, iat: now, nbf: now, exp: now + 60, jti: `aj_${randomToken()}`, ...over };
  };
  const without = (obj, name) => Object.fromEntries(Object.entries(obj).filter(([k]) => k !== name));
  const sign = (over = {}, hdr = header, key = privateKey) => signEdDsa(hdr, claims(over), key);
  const signRaw = (payload, key = privateKey) => signEdDsa(header, payload, key);

  const accepts = async (token, why, as) => {
    const r = await present(token, as);
    assert(r.accepted, `${why} was refused${r.detail ? ` (${r.detail})` : ''}`);
    return r;
  };
  const refuses = async (token, why, as) => {
    const r = await present(token, as);
    assert(!r.accepted, `${why} was accepted`);
    assert(!r.unavailable, `${why} was answered as an outage, not as a refusal`);
    return r;
  };

  return runChecks('agent JWT verifier', [
    {
      id: 'AJV01', level: 'MUST', title: 'accepts a valid token',
      async run() {
        await accepts(sign(), 'a valid token');
      },
    },
    {
      id: 'AJV02', level: 'MUST', title: 'accepts a token without nbf',
      async run() {
        await accepts(signRaw(without(claims(), 'nbf')), 'a token without nbf');
      },
    },
    {
      id: 'AJV03', level: 'MUST', title: 'accepts a token whose lifetime is 120 seconds',
      async run() {
        const now = unixNow();
        await accepts(sign({ iat: now, nbf: now, exp: now + 120 }), 'a 120 second token');
      },
    },
    {
      id: 'AJV04', level: 'MUST', title: 'allows 30 seconds of clock tolerance on exp and nbf',
      async run() {
        const now = unixNow();
        await accepts(sign({ iat: now - 70, nbf: now - 70, exp: now - 10 }), 'a token that expired 10 seconds ago');
        await accepts(sign({ iat: now + 10, nbf: now + 10, exp: now + 70 }), 'a token that becomes valid in 10 seconds');
      },
    },
    {
      id: 'AJV10', level: 'MUST', title: 'refuses an expired token, beyond the tolerance',
      async run() {
        const now = unixNow();
        await refuses(sign({ iat: now - 200, nbf: now - 200, exp: now - 100 }), 'a token that expired 100 seconds ago');
      },
    },
    {
      id: 'AJV11', level: 'MUST', title: 'refuses a token that is not valid yet, beyond the tolerance',
      async run() {
        const now = unixNow();
        await refuses(sign({ nbf: now + 120, exp: now + 180 }), 'a token with nbf 120 seconds ahead');
      },
    },
    {
      id: 'AJV12', level: 'MUST', title: 'refuses a token whose lifetime is over 120 seconds',
      async run() {
        const now = unixNow();
        await refuses(sign({ iat: now, nbf: now, exp: now + 300 }), 'a 300 second token');
        await refuses(sign({ iat: now, nbf: now, exp: now + 121 }), 'a 121 second token');
      },
    },
    {
      id: 'AJV13', level: 'MUST', title: 'refuses a token with no iat, no exp or no jti',
      async run() {
        for (const name of ['iat', 'exp', 'jti']) await refuses(signRaw(without(claims(), name)), `a token with no ${name}`);
      },
    },
    {
      id: 'AJV14', level: 'MUST', title: 'refuses a token issued in the future, beyond the tolerance',
      async run() {
        const now = unixNow();
        await refuses(signRaw(without({ ...claims(), iat: now + 120, exp: now + 180 }, 'nbf')), 'a token with iat 120 seconds ahead');
      },
    },
    {
      id: 'AJV15', level: 'MUST', title: 'refuses another issuer, another audience and no audience',
      async run() {
        // A token with another issuer is not an agent JWT: a server may route it to another check and refuse it there.
        await refuses(sign({ iss: 'attacker.example' }), 'a token with another issuer');
        await refuses(sign({ aud: 'stack:passport' }), 'a token for another audience');
        await refuses(signRaw(without(claims(), 'aud')), 'a token with no audience');
      },
    },
    {
      id: 'AJV16', level: 'MUST', title: 'refuses alg none and an HMAC token keyed with the public key',
      async run() {
        const unsigned = `${b64url({ alg: 'none' })}.${b64url(claims())}.`;
        await refuses(unsigned, 'an unsigned token');
        const secret = publicKey.export({ format: 'jwk' }).x;
        await refuses(signHs256({ alg: 'HS256' }, claims(), Buffer.from(secret, 'base64url')), 'an HS256 token keyed with the public key');
        await refuses(signHs256({ alg: 'HS256' }, claims(), Buffer.from(secret)), 'an HS256 token keyed with the public key text');
      },
    },
    {
      id: 'AJV17', level: 'MUST', title: 'refuses a token signed by another key, and one whose payload was changed',
      async run() {
        await refuses(sign({}, header, other.privateKey), 'a token signed by another key');
        const [h, , s] = sign().split('.');
        await refuses(`${h}.${b64url(claims({ jti: 'aj_tampered' }))}.${s}`, 'a token with a changed payload');
      },
    },
    {
      id: 'AJV18', level: 'MUST', title: 'refuses an agent that has no enrolled key',
      async run() {
        if (!options.unenrolled && !options.unenrolledAgentId) return skip('give the suite an agent id that is not enrolled');
        const id = options.unenrolledAgentId ?? `agt_${randomToken(9)}`;
        const as = options.unenrolled ? options.unenrolled(id) : undefined;
        await refuses(signRaw({ ...claims(), sub: id }, other.privateKey), 'a token for an agent with no key', as);
      },
    },
    {
      id: 'AJV19', level: 'MUST', title: 'refuses a sub or jti that is not well formed, and a token over 4096 bytes',
      async run() {
        await refuses(sign({ jti: 'has a space' }), 'a jti with a space');
        await refuses(sign({ jti: 'x'.repeat(201) }), 'a jti of 201 characters');
        await refuses(sign({ sub: `${agentId}!` }), 'a sub with a character that is not allowed');
        await refuses(sign({ pad: 'x'.repeat(5000) }), 'a token of over 4096 bytes');
      },
    },
    {
      id: 'AJV30', level: 'MUST', title: 'refuses a token presented a second time',
      async run() {
        const token = sign();
        await accepts(token, 'the first presentation');
        await refuses(token, 'the second presentation of the same token');
      },
    },
    {
      id: 'AJV31', level: 'MUST', title: 'still refuses a replay in the last seconds of a 120 second token (inside the tolerance)',
      async run() {
        const now = unixNow();
        const token = sign({ iat: now - 125, nbf: now - 125, exp: now - 5 });
        await accepts(token, 'the first presentation of a token with 5 seconds past its exp');
        await refuses(token, 'the second presentation of that token');
      },
    },
    {
      id: 'AJV32', level: 'MUST', title: 'does not let a token that failed verification use up a jti',
      async run() {
        const jti = `aj_${randomToken()}`;
        await refuses(sign({ jti }, header, other.privateKey), 'a forged token with a jti');
        await accepts(sign({ jti }), 'the genuine token with the same jti');
      },
    },
    {
      id: 'AJV33', level: 'MUST', title: 'accepts exactly one of several concurrent presentations of one token',
      async run() {
        const token = sign();
        const results = await Promise.all(Array.from({ length: 8 }, () => present(token)));
        const accepted = results.filter((r) => r.accepted).length;
        assert(accepted === 1, `${accepted} of 8 concurrent presentations were accepted`);
      },
    },
    {
      id: 'AJV34', level: 'SHOULD', title: 'tells a repeated token from other refusals (AGENT_JWT_REPLAYED)',
      async run() {
        const token = sign();
        await accepts(token, 'the first presentation');
        const second = await present(token);
        assert(!second.accepted && second.replay === true, 'the repeat was not reported as a replay');
      },
    },
  ]);
}
