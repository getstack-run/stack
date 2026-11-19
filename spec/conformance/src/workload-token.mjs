// Conformance suite for ACCEPTING a workload identity token (spec/workload-identity/SPEC.md, section 4): a SPIFFE
// JWT-SVID or a WIMSE Workload Identity Token. The kit mints tokens with keys of its own, hands your function the
// matching key set and the configuration of an issuer, and checks what it accepts and what it refuses.
//
// An acceptor is
//
//   accept({ kind, token, config, jwks }) -> { subject, issuer, audience?, not_after }
//
// that resolves for a token it accepts and rejects (throws) for any other. `kind` is 'spiffe' or 'wimse'. `config`
// is { trust_domain, audience } for SPIFFE and { issuer_uri, audience } for WIMSE; `audience` is a string, or null
// for "accept any". `jwks` is the issuer's key set, `{ keys: [...] }`. A thrown error carries the failure `reason`
// of section 8 as `error.code` or `error.reason` (`signature_invalid`, `expired`, ...); the kit checks it as a
// SHOULD. The function covers steps 1, 2, 4 and 5 of section 4: the choice of configuration by mapping and the
// check of the remaining life belong to the exchange, which `workload-exchange` tests on a running server.

import {
  constants,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
} from 'node:crypto';
import { assert, runChecks } from './harness.mjs';
import { b64url, newEd25519, signEdDsa, signHs256, unixNow } from './identity-support.mjs';

const TRUST_DOMAIN = 'conformance.example';
const ISSUER = 'https://issuer.conformance.example';
const AUDIENCE = 'stack-conformance';
const reasonOf = (error) => error?.code ?? error?.reason;

function esKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, publicJwk: publicKey.export({ format: 'jwk' }) };
}

/** An ES256 JWS (the JOSE signature is the raw r||s form). */
function signEs256(header, payload, privateKey) {
  const input = `${b64url(header)}.${b64url(payload)}`;
  const signature = cryptoSign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${signature.toString('base64url')}`;
}

/** An RSA JWS: RS256 (PKCS 1.5) or PS256 (PSS). */
function signRsa(header, payload, privateKey, pss) {
  const input = `${b64url(header)}.${b64url(payload)}`;
  const options = pss ? { key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 } : { key: privateKey };
  return `${input}.${cryptoSign('sha256', Buffer.from(input), options).toString('base64url')}`;
}

/**
 * @param {{ accept: (input: { kind: 'spiffe' | 'wimse', token: string, config: object, jwks: { keys: object[] } }) => Promise<{ subject: string, issuer?: string, audience?: string, not_after: number }> }} options
 */
export async function runWorkloadTokenSuite(options) {
  const { accept } = options;
  const ed = newEd25519();
  const edOther = newEd25519();
  const es = esKey();
  const rsa = (() => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    return { privateKey, publicJwk: publicKey.export({ format: 'jwk' }) };
  })();
  const kid = 'wl-1';
  const edJwk = (over = {}) => ({ ...ed.publicJwk, kid, ...over });
  const jwks = { keys: [{ ...newEd25519().publicJwk, kid: 'decoy' }, edJwk()] };

  const spiffeId = `spiffe://${TRUST_DOMAIN}/ns/payments/sa/orders`;
  const claims = (kind, over = {}) => {
    const now = unixNow();
    return kind === 'spiffe'
      ? { sub: spiffeId, aud: [AUDIENCE], iat: now, exp: now + 300, ...over }
      : { iss: ISSUER, sub: 'https://workloads.conformance.example/orders', aud: AUDIENCE, iat: now, exp: now + 300, ...over };
  };
  const configOf = (kind, audience = AUDIENCE) => (kind === 'spiffe' ? { trust_domain: TRUST_DOMAIN, audience } : { issuer_uri: ISSUER, audience });
  const token = (kind, over = {}, header = { alg: 'EdDSA', kid, typ: kind === 'spiffe' ? 'JWT' : 'wit+jwt' }, key = ed.privateKey) => signEdDsa(header, claims(kind, over), key);

  const run = async (kind, tok, why, { config = configOf(kind), keys = jwks } = {}) => {
    try {
      return { accepted: true, result: await accept({ kind, token: tok, config, jwks: keys }) };
    } catch (error) {
      return { accepted: false, reason: reasonOf(error), error };
    }
  };
  const accepts = async (kind, tok, why, extra) => {
    const r = await run(kind, tok, why, extra);
    assert(r.accepted, `${kind}: ${why} was refused${r.error ? ` (${r.error.message ?? r.reason})` : ''}`);
    return r.result;
  };
  const refuses = async (kind, tok, why, extra) => {
    const r = await run(kind, tok, why, extra);
    assert(!r.accepted, `${kind}: ${why} was accepted`);
    return r;
  };
  const kinds = ['spiffe', 'wimse'];
  const eachKind = async (fn) => {
    for (const kind of kinds) await fn(kind);
  };

  return runChecks('workload token acceptance', [
    {
      id: 'WT01', level: 'MUST', title: 'accepts a valid token, picks the key by kid, and returns the subject, issuer, audience and expiry',
      async run() {
        await eachKind(async (kind) => {
          const now = unixNow();
          const result = await accepts(kind, token(kind, { exp: now + 300 }), 'a valid token');
          const claim = claims(kind);
          assert(result.subject === claim.sub, `${kind}: the subject is ${JSON.stringify(result.subject)}`);
          assert(Math.abs(result.not_after - (now + 300)) <= 5, `${kind}: not_after is ${result.not_after}`);
          if (kind === 'wimse') assert(result.issuer === ISSUER, `the issuer is ${JSON.stringify(result.issuer)}`);
        });
      },
    },
    {
      id: 'WT02', level: 'MUST', title: 'accepts an ES256 key whose JWK has no alg (the bundle SPIRE publishes), and a key that names its alg',
      async run() {
        await eachKind(async (kind) => {
          const keys = { keys: [{ ...es.publicJwk, kid }] };
          await accepts(kind, signEs256({ alg: 'ES256', kid }, claims(kind), es.privateKey), 'an ES256 token', { keys });
          await accepts(kind, token(kind), 'an EdDSA token with the alg in the JWK', { keys: { keys: [edJwk({ alg: 'EdDSA' })] } });
        });
      },
    },
    {
      id: 'WT03', level: 'MUST', title: 'accepts an audience listed among several, and any audience when the configuration pins none',
      async run() {
        await eachKind(async (kind) => {
          await accepts(kind, token(kind, { aud: ['other', AUDIENCE] }), 'a token whose aud lists the audience');
          await accepts(kind, token(kind, { aud: 'anything-at-all' }), 'a token with another audience, to a configuration that pins none', { config: configOf(kind, null) });
        });
      },
    },
    {
      id: 'WT04', level: 'MUST', title: 'accepts a WIT that carries a cnf key, and an unknown claim',
      async run() {
        await accepts('wimse', token('wimse', { cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: edOther.publicJwk.x } }, future_claim: 1 }), 'a WIT with cnf');
      },
    },
    {
      id: 'WT10', level: 'MUST', title: 'refuses a token that is not a compact JWS with a JSON payload',
      async run() {
        await eachKind(async (kind) => {
          const good = token(kind);
          for (const [why, value] of [
            ['an empty string', ''],
            ['text', 'hello'],
            ['two parts', good.split('.').slice(0, 2).join('.')],
            ['a payload that is not JSON', `${b64url({ alg: 'EdDSA', kid })}.${b64url('nope')}.${good.split('.')[2]}`],
          ]) {
            const r = await refuses(kind, value, why);
            if (why === 'text') assert(r.reason === undefined || r.reason === 'malformed_jwt', `${kind}: the reason is ${r.reason}`);
          }
        });
      },
    },
    {
      id: 'WT11', level: 'MUST', title: 'refuses a SPIFFE id that is not under the configured trust domain, and a WIT from another issuer or without a subject',
      async run() {
        await refuses('spiffe', token('spiffe', { sub: 'not-a-spiffe-id' }), 'a sub that is not a SPIFFE id');
        await refuses('spiffe', token('spiffe', { sub: undefined }), 'a token with no sub');
        await refuses('spiffe', token('spiffe', { sub: 'spiffe://other.example/ns/x' }), 'an id of another trust domain');
        await refuses('wimse', token('wimse', { iss: 'https://attacker.example' }), 'a WIT from another issuer');
        await refuses('wimse', token('wimse', { iss: undefined }), 'a WIT with no issuer');
        await refuses('wimse', token('wimse', { sub: undefined }), 'a WIT with no subject');
      },
    },
    {
      id: 'WT12', level: 'MUST', title: 'refuses a token with no kid, and one whose kid is not in the key set',
      async run() {
        await eachKind(async (kind) => {
          await refuses(kind, token(kind, {}, { alg: 'EdDSA' }), 'a token with no kid');
          await refuses(kind, token(kind, {}, { alg: 'EdDSA', kid: 'not-there' }), 'a token with an unknown kid');
        });
      },
    },
    {
      id: 'WT13', level: 'MUST', title: 'refuses a signature by another key under the same kid, and a payload changed after signing',
      async run() {
        await eachKind(async (kind) => {
          await refuses(kind, token(kind, {}, undefined, edOther.privateKey), 'a token signed by another key');
          const [h, , s] = token(kind).split('.');
          await refuses(kind, `${h}.${b64url(claims(kind, { sub: kind === 'spiffe' ? `${spiffeId}/x` : 'https://workloads.conformance.example/other' }))}.${s}`, 'a token with a changed payload');
        });
      },
    },
    {
      id: 'WT14', level: 'MUST', title: 'refuses an expired token, a token with no exp, and one that is not yet valid',
      async run() {
        await eachKind(async (kind) => {
          const now = unixNow();
          await refuses(kind, token(kind, { iat: now - 900, exp: now - 600 }), 'an expired token');
          await refuses(kind, token(kind, { exp: undefined }), 'a token with no exp');
          await refuses(kind, token(kind, { nbf: now + 600 }), 'a token with nbf ten minutes ahead');
        });
      },
    },
    {
      id: 'WT15', level: 'MUST', title: 'refuses another audience when the configuration pins one, and a token with no audience',
      async run() {
        await eachKind(async (kind) => {
          await refuses(kind, token(kind, { aud: 'someone-else' }), 'a token for another audience');
          await refuses(kind, token(kind, { aud: ['a', 'b'] }), 'a token whose audiences do not include it');
          await refuses(kind, token(kind, { aud: undefined }), 'a token with no audience');
        });
      },
    },
    {
      id: 'WT16', level: 'MUST', title: 'refuses alg none, and an HMAC token keyed with the public key or with a published secret',
      async run() {
        await eachKind(async (kind) => {
          await refuses(kind, `${b64url({ alg: 'none', kid })}.${b64url(claims(kind))}.`, 'an unsigned token');
          await refuses(kind, signHs256({ alg: 'HS256', kid }, claims(kind), Buffer.from(ed.publicJwk.x, 'base64url')), 'an HS256 token keyed with the public key');
          const secret = randomBytes(32);
          const octKeys = { keys: [{ kty: 'oct', k: secret.toString('base64url'), kid, alg: 'HS256' }] };
          await refuses(kind, signHs256({ alg: 'HS256', kid }, claims(kind), secret), 'an HS256 token under a symmetric key in the key set', { keys: octKeys });
          const octNoAlg = { keys: [{ kty: 'oct', k: secret.toString('base64url'), kid }] };
          await refuses(kind, signHs256({ alg: 'HS256', kid }, claims(kind), secret), 'an HS256 token under a symmetric key with no alg', { keys: octNoAlg });
        });
      },
    },
    {
      id: 'WT17', level: 'MUST', title: 'verifies only with the algorithm the key gives: an RSA key is RS256, and a PS256 token is refused',
      async run() {
        await eachKind(async (kind) => {
          const keys = { keys: [{ ...rsa.publicJwk, kid }] };
          await accepts(kind, signRsa({ alg: 'RS256', kid }, claims(kind), rsa.privateKey, false), 'an RS256 token under an RSA key', { keys });
          await refuses(kind, signRsa({ alg: 'PS256', kid }, claims(kind), rsa.privateKey, true), 'a PS256 token under an RSA key with no alg', { keys });
          await refuses(kind, signRsa({ alg: 'PS256', kid }, claims(kind), rsa.privateKey, true), 'a PS256 token under an RSA key that says RS256', { keys: { keys: [{ ...rsa.publicJwk, kid, alg: 'RS256' }] } });
        });
      },
    },
    {
      id: 'WT18', level: 'SHOULD', title: 'reports the reason of the specification (signature_invalid, expired, audience_mismatch, unknown_kid, missing_kid, malformed_jwt)',
      async run() {
        const now = unixNow();
        const cases = [
          ['signature_invalid', token('spiffe', {}, undefined, edOther.privateKey)],
          ['expired', token('spiffe', { iat: now - 900, exp: now - 600 })],
          ['audience_mismatch', token('spiffe', { aud: 'x' })],
          ['unknown_kid', token('spiffe', {}, { alg: 'EdDSA', kid: 'nope' })],
          ['missing_kid', token('spiffe', {}, { alg: 'EdDSA' })],
          ['malformed_jwt', 'hello'],
        ];
        for (const [reason, tok] of cases) {
          const r = await run('spiffe', tok, reason);
          assert(!r.accepted, `${reason}: the token was accepted`);
          assert(r.reason === reason, `${reason}: the failure reason is ${JSON.stringify(r.reason)}`);
        }
      },
    },
  ]);
}
