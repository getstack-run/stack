// Conformance suites for the claims an agent's own key signs (spec/agent-keys/SPEC.md, sections 5 and 6).
//
//   runAgentClaimSignerSuite({ sign })      the signing helper of an SDK or your own: it gets an envelope, a
//                                           private key and an agent id and must return the COSE_Sign1 message.
//   runAgentClaimVerifierSuite({ verify })  a verifier: it gets a message, the agent's key set and the agent id
//                                           the claim is checked for.
//
// `sign({ envelope, privateJwk, agentId, alg? }) -> base64url COSE_Sign1` (async allowed). `alg` is given only to
// check that a signer refuses what it does not implement.
// `verify(message, { jwks, agentId }) -> { valid: boolean }`; throwing counts as "not valid".
//
// The key set of a running server is checked by the `agent-enrollment` suite, which enrolls a key and reads it
// back from the endpoint.

import { sign as edSign, verify as edVerify } from 'node:crypto';
import { Float64, Tagged, decode, encode, untag } from './cbor.mjs';
import { assert, runChecks } from './harness.mjs';
import { newEd25519, randomToken } from './identity-support.mjs';

const COSE_ALG = 1;
const COSE_KID = 4;
const COSE_TYP = 16;
const EDDSA = -8;
const TYP = 'stack/claim+cose';

export const agentKid = (agentId) => `agent:${agentId}:v1`;

/** A claim envelope (spec/record section 4.1) that is valid enough to carry. */
export function sampleEnvelope(agentId) {
  return {
    envelope_version: 1,
    issuer: 'op_conformance',
    subject: `stack:agent:${agentId}`,
    issued_at: 1_790_000_000_000,
    claim_type: 'intent_claim',
    claim_version: 1,
    payload: { type: 'intent_claim', note: 'conformance' },
    receipt: null,
    co_signatures: [],
  };
}

/**
 * Build a COSE_Sign1 message by hand, so that the suite can make it right and wrong in exactly one way.
 * Options: `kid`, `alg`, `key` (private KeyObject), `tagProtected` (default true), `kidAsText`, `payloadBytes`,
 * `protectedMap` (a Map that replaces the whole protected header), `tamper`.
 */
export function buildCose(envelope, key, options = {}) {
  const kid = options.kid;
  const protectedMap =
    options.protectedMap ??
    new Map([
      [COSE_ALG, options.alg ?? EDDSA],
      ...(kid === undefined ? [] : [[COSE_KID, options.kidAsText ? kid : Buffer.from(kid, 'utf8')]]),
      [COSE_TYP, TYP],
    ]);
  const protectedBytes = encode(options.tagProtected === false ? protectedMap : new Tagged(259, protectedMap));
  const payloadBytes = options.payloadBytes ?? encode(envelope);
  const toBeSigned = encode(['Signature1', protectedBytes, Buffer.alloc(0), payloadBytes]);
  const signature = edSign(null, toBeSigned, key);
  const parts = [protectedBytes, new Map(), payloadBytes, signature];
  if (options.tamper) options.tamper(parts);
  return encode(parts).toString('base64url');
}

function decodeMessage(message) {
  const outer = decode(Buffer.from(message, 'base64url'));
  assert(Array.isArray(outer) && outer.length === 4, 'the message is not a four-element array');
  const [protectedBytes, unprotected, payloadBytes, signature] = outer;
  assert(Buffer.isBuffer(protectedBytes) && Buffer.isBuffer(payloadBytes) && Buffer.isBuffer(signature), 'the protected header, payload and signature must be byte strings');
  return { protectedBytes, unprotected: untag(unprotected), payloadBytes, signature, protectedMap: untag(decode(protectedBytes)) };
}

const plain = (value) => {
  const v = untag(value);
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, plain(x)]));
  if (Array.isArray(v)) return v.map(plain);
  if (Buffer.isBuffer(v)) return v.toString('base64url');
  return v;
};

/** @param {{ sign: (input: { envelope: object, privateJwk: object, agentId: string }) => string | Promise<string> }} options */
export async function runAgentClaimSignerSuite(options) {
  const agentId = `agt_${randomToken(9)}`;
  const key = newEd25519();
  const envelope = sampleEnvelope(agentId);
  let cached;
  const message = async () => (cached ??= await options.sign({ envelope, privateJwk: key.privateJwk, agentId }));

  return runChecks('agent claim signer', [
    {
      id: 'CS01', level: 'MUST', title: 'produces a base64url COSE_Sign1: an untagged array of protected bytes, an empty unprotected map, payload bytes and a 64-byte signature',
      async run() {
        const text = await message();
        assert(typeof text === 'string' && /^[A-Za-z0-9_-]+$/.test(text), 'the message is not base64url');
        const outer = decode(Buffer.from(text, 'base64url'));
        assert(Array.isArray(outer), 'the message is tagged or is not an array');
        const parts = decodeMessage(text);
        assert(parts.unprotected instanceof Map && parts.unprotected.size === 0, 'the unprotected header is not an empty map');
        assert(parts.signature.length === 64, `the signature is ${parts.signature.length} bytes`);
      },
    },
    {
      id: 'CS02', level: 'MUST', title: 'sets alg -8, the key id agent:{id}:v1 as a byte string and typ stack/claim+cose in the protected header, and nothing else',
      async run() {
        const { protectedMap } = decodeMessage(await message());
        assert(protectedMap instanceof Map, 'the protected header is not a map');
        assert(protectedMap.get(COSE_ALG) === EDDSA, `alg is ${protectedMap.get(COSE_ALG)}`);
        const kid = protectedMap.get(COSE_KID);
        assert(Buffer.isBuffer(kid), 'the kid is not a byte string');
        assert(kid.toString('utf8') === agentKid(agentId), `the kid is ${kid.toString('utf8')}`);
        assert(protectedMap.get(COSE_TYP) === TYP, `typ is ${JSON.stringify(protectedMap.get(COSE_TYP))}`);
        assert(protectedMap.size === 3, `the protected header has ${protectedMap.size} entries, not 3`);
      },
    },
    {
      id: 'CS03', level: 'MUST', title: 'carries the envelope, unchanged, as the CBOR payload',
      async run() {
        const { payloadBytes } = decodeMessage(await message());
        assert(canonical(plain(decode(payloadBytes))) === canonical(envelope), 'the payload is not the envelope that was given');
      },
    },
    {
      id: 'CS04', level: 'MUST', title: 'signs RFC 9052\'s Sig_structure1 (Signature1, the protected bytes, empty external data, the payload bytes) with Ed25519',
      async run() {
        const { protectedBytes, payloadBytes, signature } = decodeMessage(await message());
        const toBeSigned = encode(['Signature1', protectedBytes, Buffer.alloc(0), payloadBytes]);
        assert(edVerify(null, toBeSigned, key.publicKey, signature), 'the signature does not verify with the agent\'s public key');
      },
    },
    {
      id: 'CS05', level: 'MUST', title: 'names the agent it was asked to sign for, whatever the key',
      async run() {
        const other = `agt_${randomToken(9)}`;
        const text = await options.sign({ envelope: sampleEnvelope(other), privateJwk: key.privateJwk, agentId: other });
        const kid = decodeMessage(text).protectedMap.get(COSE_KID).toString('utf8');
        assert(kid === agentKid(other), `the kid is ${kid}`);
      },
    },
    {
      id: 'CS06', level: 'MUST', title: 'refuses to sign with an algorithm it does not implement (alg given as ML-DSA-65), and does not fall back to EdDSA',
      async run() {
        let refused = false;
        try {
          await options.sign({ envelope, privateJwk: key.privateJwk, agentId, alg: 'ML-DSA-65' });
        } catch {
          refused = true;
        }
        assert(refused, 'a request for an algorithm the signer does not implement produced a message');
      },
    },
  ]);
}

const canonical = (value) => {
  if (value instanceof Map) return canonical(Object.fromEntries(value));
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
};

/** @param {{ verify: (message: string, context: { jwks: { keys: object[] }, agentId: string }) => { valid: boolean } | Promise<{ valid: boolean }> }} options */
export async function runAgentClaimVerifierSuite(options) {
  const agentId = `agt_${randomToken(9)}`;
  const key = newEd25519();
  const other = newEd25519();
  const kid = agentKid(agentId);
  const envelope = sampleEnvelope(agentId);
  const jwk = (k, over = {}) => ({ kty: 'OKP', crv: 'Ed25519', x: k.publicJwk.x, kid, alg: 'EdDSA', use: 'sig', not_before: 1, not_after: null, ...over });
  const jwks = { keys: [jwk(key)] };
  const check = async (message, keys = jwks, id = agentId) => {
    try {
      const result = await options.verify(message, { jwks: keys, agentId: id });
      return result?.valid === true;
    } catch {
      return false;
    }
  };
  const good = (over = {}) => buildCose(envelope, key.privateKey, { kid, ...over });
  const accepts = async (message, why, keys) => assert(await check(message, keys), `${why} was refused`);
  const refuses = async (message, why, keys, id) => assert(!(await check(message, keys, id)), `${why} was accepted`);

  return runChecks('agent claim verifier', [
    {
      id: 'CV01', level: 'MUST', title: 'accepts a valid message, with the protected header in the tag 259 form of the reference producer',
      async run() {
        await accepts(good(), 'a valid message');
      },
    },
    {
      id: 'CV02', level: 'SHOULD', title: 'accepts the same message with the protected header untagged, and the kid as a text string',
      async run() {
        await accepts(good({ tagProtected: false }), 'a message with an untagged protected header');
        await accepts(good({ kidAsText: true }), 'a message with a text kid');
      },
    },
    {
      id: 'CV03', level: 'MUST', title: 'verifies the bytes on the wire: a payload with a longer length prefix, and a timestamp written as a double',
      async run() {
        const entries = [['envelope_version', 1], ['issuer', 'op_conformance'], ['subject', `stack:agent:${agentId}`], ['issued_at', new Float64(1_790_000_000_000)], ['claim_type', 'intent_claim'], ['claim_version', 1], ['payload', new Map([['type', 'intent_claim']])], ['receipt', null], ['co_signatures', []]];
        const longPrefix = Buffer.concat([Buffer.from([0xb9, 0x00, entries.length]), ...entries.flatMap(([k, v]) => [encode(k), encode(v)])]);
        await accepts(good({ payloadBytes: longPrefix }), 'a payload with a two-byte map length and a double timestamp');
      },
    },
    {
      id: 'CV04', level: 'MUST', title: 'refuses a message whose payload, protected header or signature was changed after signing',
      async run() {
        const flip = (b) => { const c = Buffer.from(b); c[c.length - 1] ^= 1; return c; };
        await refuses(good({ tamper: (p) => { p[2] = flip(p[2]); } }), 'a message with a changed payload');
        await refuses(good({ tamper: (p) => { p[3] = flip(p[3]); } }), 'a message with a changed signature');
        await refuses(good({ tamper: (p) => { p[0] = encode(new Tagged(259, new Map([[COSE_ALG, EDDSA], [COSE_KID, Buffer.from(kid)], [COSE_TYP, 'stack/other']]))); } }), 'a message with a changed protected header');
      },
    },
    {
      id: 'CV05', level: 'MUST', title: 'refuses an algorithm other than EdDSA (-8)',
      async run() {
        await refuses(good({ alg: -7 }), 'a message that says ES256');
        await refuses(good({ alg: 'EdDSA' }), 'a message whose alg is a text');
      },
    },
    {
      id: 'CV06', level: 'MUST', title: 'refuses a key id that is not the agent\'s own, even if the key set holds a key under it that verifies',
      async run() {
        const otherAgent = `agt_${randomToken(9)}`;
        const message = buildCose(envelope, other.privateKey, { kid: agentKid(otherAgent) });
        await refuses(message, 'a message for another agent', { keys: [jwk(key), jwk(other, { kid: agentKid(otherAgent) })] });
        const operatorKid = 'op_conformance:claim:v1';
        await refuses(buildCose(envelope, other.privateKey, { kid: operatorKid }), 'a message under an operator key id', { keys: [jwk(key), jwk(other, { kid: operatorKid })] });
      },
    },
    {
      id: 'CV07', level: 'MUST', title: 'refuses a message with no key id, an empty one, or a protected header that is not a map',
      async run() {
        await refuses(good({ kid: undefined }), 'a message with no kid');
        await refuses(buildCose(envelope, key.privateKey, { kid: '' }), 'a message with an empty kid');
        await refuses(buildCose(envelope, key.privateKey, { protectedMap: [EDDSA] }), 'a message whose protected header is an array');
      },
    },
    {
      id: 'CV08', level: 'MUST', title: 'refuses a message that is not a four-element COSE_Sign1',
      async run() {
        await refuses(encode(['a', 'b', 'c']).toString('base64url'), 'a three-element array');
        await refuses(encode('text').toString('base64url'), 'a CBOR text');
        await refuses('not base64 at all !!!', 'text that is not base64url');
        await refuses('', 'an empty message');
      },
    },
    {
      id: 'CV09', level: 'MUST', title: 'refuses a signature that verifies with another key than the one under the key id',
      async run() {
        await refuses(buildCose(envelope, other.privateKey, { kid }), 'a message signed by another key');
        await refuses(good(), 'a valid message against a key set whose key is another', { keys: [jwk(other)] });
      },
    },
    {
      id: 'CV10', level: 'MUST', title: 'refuses a key set with no key under the key id, and a key that carries private material or the wrong use',
      async run() {
        await refuses(good(), 'a message against an empty key set', { keys: [] });
        await refuses(good(), 'a message against a key set with only another kid', { keys: [jwk(key, { kid: agentKid(`agt_${randomToken(6)}`) })] });
        await refuses(good(), 'a key that carries the private member', { keys: [jwk(key, { d: key.privateJwk.d })] });
        await refuses(good(), 'a key whose alg is RS256', { keys: [jwk(key, { alg: 'RS256' })] });
        await refuses(good(), 'a key whose use is enc', { keys: [jwk(key, { use: 'enc' })] });
      },
    },
    {
      id: 'CV11', level: 'MUST', title: 'accepts the same key listed twice under the key id',
      async run() {
        await accepts(good(), 'a key listed twice', { keys: [jwk(key), jwk(key)] });
      },
    },
    {
      id: 'CV12', level: 'MUST', title: 'picks the key by key id from a set with several keys',
      async run() {
        await accepts(good(), 'a message against a set with two keys', { keys: [jwk(other, { kid: agentKid(`agt_${randomToken(6)}`) }), jwk(key)] });
      },
    },
  ]);
}
