// Conformance suite for a PASSPORT VERIFIER (offline verification, section 9.1
// of spec/passport/SPEC.md). The kit mints tokens with a key of its own, hands
// your verifier the matching JWKS, and checks that it accepts what it must and
// rejects what it must, including the classic attacks on JWT verification.
//
// A verifier is an async function
//
//   verify(token, { jwks, issuer, audience }) -> claims
//
// that resolves with the verified claims object (the JWT payload, with `jti`
// and `stk`) and rejects (throws) for any token it does not accept. A verifier
// in another language is wrapped with `commandVerifier`: a program that reads
// one JSON object `{ token, jwks, issuer, audience }` on stdin and writes
// `{ "valid": true, "claims": {...} }` or `{ "valid": false }` to stdout.

import { createPrivateKey, createPublicKey, createHmac, sign } from 'node:crypto';
import { spawn } from 'node:child_process';
import { assert, fail, runChecks } from './harness.mjs';

const ISSUER = 'getstack.run';
const AUDIENCE = 'stack:passport';
const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

/** An Ed25519 key pair from a one-byte seed, so runs are reproducible. */
export function keyFromSeed(seedByte, kid) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seedByte)]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const publicJwk = { ...createPublicKey(privateKey).export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig' };
  return { kid, privateKey, publicJwk };
}

/** Sign a JWT. `header` and `payload` are objects; `key` is a keyFromSeed result. */
export function signJwt(header, payload, key) {
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const signature = sign(null, Buffer.from(signingInput), key.privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

function baseStk() {
  return {
    operator_id: 'op_conformance',
    agent_id: 'agt_conformance',
    agent_name: 'conformance-agent',
    services: [{ service_id: 'svc_conformance', service_name: 'github', scopes: ['read'], credential_ref: 'cred_conformance', connection_id: 'scon_conformance' }],
    identity_claims: [],
    delegation_depth: 0,
    session_id: 'ses_conformance',
    accountability: 'standard',
    mission_ids: ['ms_conformance'],
  };
}

function authorityRef(n) {
  return {
    binding_id: `abn_c${n}`, binding_version: 1, binding_claim_id: `pc_c${n}`, binding_digest: `sha256:${'a'.repeat(64)}`,
    receiver_id: `rcv_c${n}`, receiver_profile_version_id: `apv_c${n}`, expires_at: 1_900_000_000,
  };
}

/**
 * @param {{ verify: (token: string, ctx: { jwks: { keys: object[] }, issuer: string, audience: string }) => Promise<any>, now?: number }} options
 */
export async function runPassportVerifierSuite(options) {
  const { verify } = options;
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const key = keyFromSeed(0x11, 'conf-1');
  const decoy = keyFromSeed(0x22, 'conf-decoy');
  const other = keyFromSeed(0x33, 'conf-1'); // same kid, different key
  const jwks = { keys: [decoy.publicJwk, key.publicJwk] };
  const ctx = { jwks, issuer: ISSUER, audience: AUDIENCE };

  const payload = (over = {}, stkOver = {}) => ({
    iss: ISSUER, aud: AUDIENCE, sub: 'agt_conformance', iat: now - 10, exp: now + 600, jti: 'pas_conformance',
    stk: { ...baseStk(), ...stkOver }, ...over,
  });
  const token = (over, stkOver, header = { alg: 'EdDSA', kid: key.kid }, signer = key) => signJwt(header, payload(over, stkOver), signer);

  const accepts = async (t, why) => {
    let claims;
    try {
      claims = await verify(t, ctx);
    } catch (error) {
      fail(`${why} was rejected: ${error instanceof Error ? error.message : String(error)}`);
    }
    return claims;
  };
  const rejects = async (t, why) => {
    let claims;
    try {
      claims = await verify(t, ctx);
    } catch {
      return;
    }
    fail(`${why} was accepted${claims ? ` (claims for ${claims.sub ?? claims.jti ?? 'unknown'})` : ''}`);
  };
  const omit = (obj, field) => Object.fromEntries(Object.entries(obj).filter(([k]) => k !== field));
  const tamperedPayload = () => {
    const [h, , s] = token().split('.');
    return `${h}.${b64(payload({}, { agent_name: 'someone-else' }))}.${s}`;
  };

  return runChecks('passport verifier (offline)', [
    {
      id: 'P01', level: 'MUST', title: 'accepts a valid token and returns its claims',
      async run() {
        const claims = await accepts(token(), 'a valid token');
        assert(claims && claims.jti === 'pas_conformance', 'the returned claims lack the jti');
        assert(claims.stk && claims.stk.agent_id === 'agt_conformance', 'the returned claims lack stk.agent_id');
      },
    },
    {
      id: 'P02', level: 'MUST', title: 'selects the key by kid from a JWKS with several keys',
      async run() {
        await accepts(token(), 'a token signed by the second key of the JWKS');
      },
    },
    {
      id: 'P03', level: 'MUST', title: 'accepts a token that expires shortly in the future',
      async run() {
        await accepts(token({ exp: now + 45 }), 'a token with 45 seconds left');
      },
    },
    {
      id: 'P04', level: 'MUST', title: 'accepts unknown extra claims at the top level and inside stk',
      async run() {
        await accepts(token({ future_claim: 'x' }, { future_stk_claim: { a: 1 } }), 'a token with extra claims');
      },
    },
    {
      id: 'P05', level: 'MUST', title: 'accepts a token whose header carries typ JWT',
      async run() {
        await accepts(token({}, {}, { alg: 'EdDSA', kid: key.kid, typ: 'JWT' }), 'a token with typ JWT');
      },
    },
    {
      id: 'P10', level: 'MUST', title: 'rejects an expired token',
      async run() {
        await rejects(token({ iat: now - 7200, exp: now - 3600 }), 'a token that expired an hour ago');
      },
    },
    {
      id: 'P11', level: 'MUST', title: 'rejects a token for another audience',
      async run() {
        await rejects(token({ aud: 'stack:dashboard' }), 'a token with audience stack:dashboard');
        await rejects(token({ aud: undefined }), 'a token with no audience');
      },
    },
    {
      id: 'P12', level: 'MUST', title: 'rejects a token from another issuer',
      async run() {
        await rejects(token({ iss: 'attacker.example' }), 'a token from another issuer');
        await rejects(token({ iss: undefined }), 'a token with no issuer');
      },
    },
    {
      id: 'P13', level: 'MUST', title: 'rejects alg none',
      async run() {
        const unsigned = `${b64({ alg: 'none', kid: key.kid })}.${b64(payload())}.`;
        await rejects(unsigned, 'an unsigned token (alg none)');
        await rejects(`${b64({ alg: 'none', kid: key.kid })}.${b64(payload())}.${b64('x')}`, 'an alg none token with a signature');
      },
    },
    {
      id: 'P14', level: 'MUST', title: 'rejects an HMAC token keyed with the public key (algorithm confusion)',
      async run() {
        const header = { alg: 'HS256', kid: key.kid };
        const signingInput = `${b64(header)}.${b64(payload())}`;
        const secrets = [Buffer.from(key.publicJwk.x, 'base64url'), Buffer.from(JSON.stringify(key.publicJwk))];
        for (const secret of secrets) {
          const mac = createHmac('sha256', secret).update(signingInput).digest('base64url');
          await rejects(`${signingInput}.${mac}`, 'an HS256 token keyed with the public key');
        }
      },
    },
    {
      id: 'P15', level: 'MUST', title: 'rejects a token whose payload was changed after signing',
      async run() {
        await rejects(tamperedPayload(), 'a tampered token');
      },
    },
    {
      id: 'P16', level: 'MUST', title: 'rejects a token signed by a different key that uses a known kid',
      async run() {
        await rejects(token({}, {}, { alg: 'EdDSA', kid: key.kid }, other), 'a token signed by an unknown key');
      },
    },
    {
      id: 'P17', level: 'MUST', title: 'rejects a token with a kid that is not in the JWKS',
      async run() {
        await rejects(token({}, {}, { alg: 'EdDSA', kid: 'not-in-the-set' }), 'a token with an unknown kid');
      },
    },
    {
      id: 'P18', level: 'MUST', title: 'rejects a token that is not a well-formed compact JWS',
      async run() {
        const good = token();
        for (const [why, value] of [
          ['an empty string', ''],
          ['a token with two parts', good.split('.').slice(0, 2).join('.')],
          ['a token with four parts', `${good}.x`],
          ['a token with a truncated signature', good.slice(0, -12)],
          ['a token with a garbage signature', `${good.split('.').slice(0, 2).join('.')}.${b64('not a signature')}`],
          ['text that is not a token', 'hello world'],
        ]) {
          await rejects(value, why);
        }
      },
    },
    {
      id: 'P20', level: 'MUST', title: 'rejects a token missing jti',
      async run() {
        await rejects(signJwt({ alg: 'EdDSA', kid: key.kid }, omit(payload(), 'jti'), key), 'a token with no jti');
      },
    },
    {
      id: 'P21', level: 'MUST', title: 'rejects a token missing sub, or whose sub differs from stk.agent_id',
      async run() {
        await rejects(signJwt({ alg: 'EdDSA', kid: key.kid }, omit(payload(), 'sub'), key), 'a token with no sub');
        await rejects(token({ sub: 'agt_someone_else' }), 'a token whose sub is not stk.agent_id');
      },
    },
    {
      id: 'P22', level: 'MUST', title: 'rejects a token missing exp or iat',
      async run() {
        await rejects(signJwt({ alg: 'EdDSA', kid: key.kid }, omit(payload(), 'exp'), key), 'a token with no exp');
        await rejects(signJwt({ alg: 'EdDSA', kid: key.kid }, omit(payload(), 'iat'), key), 'a token with no iat');
      },
    },
    {
      id: 'P23', level: 'MUST', title: 'rejects a token with no stk claims, or with malformed ones',
      async run() {
        await rejects(signJwt({ alg: 'EdDSA', kid: key.kid }, omit(payload(), 'stk'), key), 'a token with no stk');
        await rejects(token({ stk: 'not an object' }), 'a token whose stk is a string');
        await rejects(token({}, { operator_id: undefined }), 'a token with no stk.operator_id');
        await rejects(token({}, { agent_id: undefined }), 'a token with no stk.agent_id');
        await rejects(token({}, { services: 'github' }), 'a token whose stk.services is not an array');
        await rejects(token({}, { identity_claims: {} }), 'a token whose stk.identity_claims is not an array');
      },
    },
    {
      id: 'P24', level: 'MUST', title: 'rejects malformed authority_refs, and more than eight of them',
      async run() {
        await accepts(token({}, { authority_refs: [authorityRef(1), authorityRef(2)] }), 'a token with two well-formed authority_refs');
        await rejects(token({}, { authority_refs: Array.from({ length: 9 }, (_, i) => authorityRef(i)) }), 'a token with nine authority_refs');
        await rejects(token({}, { authority_refs: [{ ...authorityRef(1), binding_digest: 'md5:zzz' }] }), 'a token with a malformed binding_digest');
        await rejects(token({}, { authority_refs: 'abn_1' }), 'a token whose authority_refs is not an array');
      },
    },
  ]);
}

/**
 * Wrap a program as a verifier: it reads `{ token, jwks, issuer, audience }`
 * as JSON on stdin and writes `{ "valid": boolean, "claims"?: object }`.
 */
export function commandVerifier(command, args = []) {
  return (token, ctx) =>
    new Promise((resolve, reject) => {
      const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], shell: false });
      let out = '';
      let err = '';
      child.stdout.on('data', (chunk) => { out += chunk; });
      child.stderr.on('data', (chunk) => { err += chunk; });
      child.on('error', reject);
      child.on('close', () => {
        try {
          const answer = JSON.parse(out);
          if (answer.valid === true) resolve(answer.claims ?? {});
          else reject(new Error('rejected'));
        } catch {
          reject(new Error(`the verifier program printed no JSON answer${err ? `: ${err.trim().slice(0, 200)}` : ''}`));
        }
      });
      child.stdin.end(JSON.stringify({ token, ...ctx }));
    });
}
