// A small reference implementation of the agent JWT (spec/agent-auth/SPEC.md, sections 3 and 4), written from the
// specification with nothing but node:crypto. It is both halves: `mintAgentJwt` is what an agent does, and
// `createAgentJwtVerifier` is what a server does, including the single-use record of each jti. The conformance kit
// runs against it in CI, as a worked example you can start an implementation of your own from.

import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';

const ISSUER = 'stack-sdk';
const AUDIENCE = 'stack:agent';
const MAX_TTL = 120;
const TOLERANCE = 30;
const MAX_BEARER = 4096;
const SUB = /^[A-Za-z0-9_-]{1,128}$/;
const JTI = /^[A-Za-z0-9_-]{1,200}$/;

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** What an agent does: a fresh token for one request, signed with its private key (a JWK with `d`). */
export function mintAgentJwt({ agentId, privateJwk }) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: ISSUER, sub: agentId, aud: AUDIENCE, iat: now, nbf: now, exp: now + 60, jti: `aj_${randomBytes(16).toString('base64url')}` };
  const input = `${b64({ alg: 'EdDSA' })}.${b64(payload)}`;
  const signature = sign(null, Buffer.from(input), createPrivateKey({ key: privateJwk, format: 'jwk' }));
  return `${input}.${signature.toString('base64url')}`;
}

class Refused extends Error {
  constructor(message, code = 'INVALID_API_KEY') {
    super(message);
    this.code = code;
  }
}

/**
 * What a server does. The returned `verify(token, { agentId, publicJwk })` resolves with the claims or throws
 * (`AGENT_JWT_REPLAYED` for a token used before). `publicJwk` is the agent's enrolled key, or null for an agent
 * with no key. It keeps the record of used jtis in memory; a server keeps it in a store shared by its machines.
 */
export function createAgentJwtVerifier({ now = () => Math.floor(Date.now() / 1000) } = {}) {
  /** `agentId:jti` -> the time after which the token can no longer verify. */
  const used = new Map();
  const sweep = (t) => {
    for (const [key, until] of used) if (until <= t) used.delete(key);
  };

  return async function verifyAgentJwt(token, { agentId, publicJwk }) {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_BEARER) throw new Refused('token size');
    const parts = token.split('.');
    if (parts.length !== 3) throw new Refused('not a compact JWS');
    let header;
    let payload;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      throw new Refused('not JSON');
    }
    // 1. Shapes.
    if (typeof payload.sub !== 'string' || !SUB.test(payload.sub)) throw new Refused('sub');
    if (typeof payload.jti !== 'string' || !JTI.test(payload.jti)) throw new Refused('jti');
    if (!Number.isInteger(payload.exp)) throw new Refused('exp');
    // 2. The agent has an enrolled key (a server also checks it is active and not blocked).
    if (payload.sub !== agentId || !publicJwk) throw new Refused('unknown agent or no key');
    // 3. Signature, with EdDSA only.
    if (header.alg !== 'EdDSA') throw new Refused('alg');
    let ok;
    try {
      ok = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key: publicJwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'));
    } catch {
      ok = false;
    }
    if (!ok) throw new Refused('signature');
    // 4 to 6. Issuer, audience, times and lifetime.
    const t = now();
    if (payload.iss !== ISSUER || payload.aud !== AUDIENCE) throw new Refused('iss or aud');
    if (payload.exp + TOLERANCE <= t) throw new Refused('expired');
    if (payload.nbf !== undefined && (!Number.isInteger(payload.nbf) || payload.nbf > t + TOLERANCE)) throw new Refused('nbf');
    if (!Number.isInteger(payload.iat) || payload.exp - payload.iat > MAX_TTL || payload.iat > t + TOLERANCE) throw new Refused('iat or lifetime');
    // 8. Single use, for as long as the token can still verify. The check and the record are one step.
    sweep(t);
    const key = createHash('sha256').update(`${payload.sub}:${payload.jti}`).digest('hex');
    if (used.has(key)) throw new Refused('replayed', 'AGENT_JWT_REPLAYED');
    used.set(key, payload.exp + TOLERANCE + 1);
    return payload;
  };
}
