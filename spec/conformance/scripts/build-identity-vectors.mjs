#!/usr/bin/env node
// Builds fixtures/identity/vectors.json: test vectors for the identity specifications, for an implementer in
// another language who cannot run the kit's suites as a JavaScript module. Each vector is a message or token with
// the verdict a conforming implementation must give it, written from the specifications alone (spec/agent-auth,
// spec/agent-keys, spec/workload-identity, spec/oauth-profile) and built by this script, which is public and uses
// nothing but node:crypto and the kit's own helpers. Deterministic: every key comes from a seed, every time is
// fixed, and Ed25519 signatures are deterministic, so running it twice writes the same bytes.
// `--check` fails if the file on disk differs from a fresh build. The keys in it are for these vectors only.

import { createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Float64, Tagged, encode } from '../src/cbor.mjs';
import { b64url } from '../src/identity-support.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'identity');
const NOW = 1_790_000_000;

function keyFromSeed(seedByte) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seedByte)]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return { privateKey, publicJwk: createPublicKey(privateKey).export({ format: 'jwk' }) };
}

const jws = (header, payload, key) => {
  const input = `${b64url(header)}.${b64url(payload)}`;
  return `${input}.${sign(null, Buffer.from(input), key.privateKey).toString('base64url')}`;
};
// A token is written as its three parts, so that no line of the file looks like a bearer token to a secret scanner.
const partsOf = (token) => token.split('.');
const without = (obj, name) => Object.fromEntries(Object.entries(obj).filter(([k]) => k !== name));

// ─── The agent JWT (spec/agent-auth sections 3 and 4) ───────────────────────────────────────────────────────────

const AGENT = keyFromSeed(0x31);
const OTHER = keyFromSeed(0x32);
const AGENT_ID = 'agt_vectors';
const agentClaims = (over = {}) => ({ iss: 'stack-sdk', sub: AGENT_ID, aud: 'stack:agent', iat: NOW, nbf: NOW, exp: NOW + 60, jti: 'aj_vector_0000000000000001', ...over });
let jtiCounter = 1;
const agentCase = (name, valid, claims, { header = { alg: 'EdDSA' }, key = AGENT, token } = {}) => {
  jtiCounter += 1;
  const payload = claims === undefined ? agentClaims({ jti: `aj_vector_${String(jtiCounter).padStart(16, '0')}` }) : claims;
  return { name, valid, token_parts: partsOf(token ?? jws(header, payload, key)) };
};
const firstToken = jws({ alg: 'EdDSA' }, agentClaims(), AGENT);
const agentCases = [
  { name: 'a valid token', valid: true, token_parts: partsOf(firstToken) },
  agentCase('a valid token without nbf', true, without(agentClaims({ jti: 'aj_vector_0000000000000100' }), 'nbf')),
  agentCase('a token that lives 120 seconds', true, agentClaims({ jti: 'aj_vector_0000000000000101', exp: NOW + 120 })),
  agentCase('a token that expired 10 seconds ago (inside the tolerance of 30)', true, agentClaims({ jti: 'aj_vector_0000000000000102', iat: NOW - 70, nbf: NOW - 70, exp: NOW - 10 })),
  agentCase('a token that is valid in 10 seconds (inside the tolerance)', true, agentClaims({ jti: 'aj_vector_0000000000000103', iat: NOW + 10, nbf: NOW + 10, exp: NOW + 70 })),
  agentCase('a token that expired 100 seconds ago', false, agentClaims({ jti: 'aj_vector_0000000000000104', iat: NOW - 200, nbf: NOW - 200, exp: NOW - 100 })),
  agentCase('a token with nbf 120 seconds ahead', false, agentClaims({ jti: 'aj_vector_0000000000000105', nbf: NOW + 120, exp: NOW + 180 })),
  agentCase('a token that lives 121 seconds', false, agentClaims({ jti: 'aj_vector_0000000000000106', exp: NOW + 121 })),
  agentCase('a token with no iat', false, without(agentClaims({ jti: 'aj_vector_0000000000000107' }), 'iat')),
  agentCase('a token with no exp', false, without(agentClaims({ jti: 'aj_vector_0000000000000108' }), 'exp')),
  agentCase('a token with no jti', false, without(agentClaims(), 'jti')),
  agentCase('a token issued 120 seconds in the future', false, without(agentClaims({ jti: 'aj_vector_0000000000000109', iat: NOW + 120, exp: NOW + 180 }), 'nbf')),
  agentCase('a token for another audience', false, agentClaims({ jti: 'aj_vector_0000000000000110', aud: 'stack:passport' })),
  agentCase('a token with no audience', false, without(agentClaims({ jti: 'aj_vector_0000000000000111' }), 'aud')),
  agentCase('a token from another issuer', false, agentClaims({ jti: 'aj_vector_0000000000000112', iss: 'attacker.example' })),
  agentCase('a token signed by another key', false, agentClaims({ jti: 'aj_vector_0000000000000113' }), { key: OTHER }),
  agentCase('a token with alg none', false, undefined, { token: `${b64url({ alg: 'none' })}.${b64url(agentClaims({ jti: 'aj_vector_0000000000000114' }))}.` }),
  agentCase('an HS256 token keyed with the public key', false, undefined, {
    token: (() => {
      const input = `${b64url({ alg: 'HS256' })}.${b64url(agentClaims({ jti: 'aj_vector_0000000000000115' }))}`;
      return `${input}.${createHmac('sha256', Buffer.from(AGENT.publicJwk.x, 'base64url')).update(input).digest('base64url')}`;
    })(),
  }),
  agentCase('a token whose payload was changed after signing', false, undefined, {
    token: (() => {
      const [h, , s] = firstToken.split('.');
      return `${h}.${b64url(agentClaims({ jti: 'aj_vector_0000000000000116' }))}.${s}`;
    })(),
  }),
  agentCase('a jti with a space in it', false, agentClaims({ jti: 'has a space' })),
  agentCase('a sub with a character that is not allowed', false, agentClaims({ jti: 'aj_vector_0000000000000117', sub: `${AGENT_ID}!` })),
  { name: 'the first token again: a token is used once', valid: false, token_parts: partsOf(firstToken) },
];

// ─── A claim signed with an agent's key (spec/agent-keys sections 5 and 6) ─────────────────────────────────────

const KID = `agent:${AGENT_ID}:v1`;
const envelope = {
  envelope_version: 1, issuer: 'op_vectors', subject: `stack:agent:${AGENT_ID}`, issued_at: 1_790_000_000_000,
  claim_type: 'intent_claim', claim_version: 1, payload: { type: 'intent_claim', note: 'vector' }, receipt: null, co_signatures: [],
};
const jwk = (key, over = {}) => ({ kty: 'OKP', crv: 'Ed25519', x: key.publicJwk.x, kid: KID, alg: 'EdDSA', use: 'sig', not_before: 1, not_after: null, ...over });

function cose(key, { kid = KID, alg = -8, tagProtected = true, kidAsText = false, payloadBytes, tamper } = {}) {
  const header = new Map([[1, alg], ...(kid === null ? [] : [[4, kidAsText ? kid : Buffer.from(kid, 'utf8')]]), [16, 'stack/claim+cose']]);
  const protectedBytes = encode(tagProtected ? new Tagged(259, header) : header);
  const payload = payloadBytes ?? encode(envelope);
  const signature = sign(null, encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]), key.privateKey);
  const parts = [protectedBytes, new Map(), payload, signature];
  if (tamper) tamper(parts);
  return encode(parts).toString('base64url');
}
const flip = (bytes) => {
  const c = Buffer.from(bytes);
  c[c.length - 1] ^= 1;
  return c;
};
const entries = [['envelope_version', 1], ['issuer', 'op_vectors'], ['subject', `stack:agent:${AGENT_ID}`], ['issued_at', new Float64(1_790_000_000_000)], ['claim_type', 'intent_claim'], ['claim_version', 1], ['payload', new Map([['type', 'intent_claim']])], ['receipt', null], ['co_signatures', []]];
const longPrefixPayload = Buffer.concat([Buffer.from([0xb9, 0x00, entries.length]), ...entries.flatMap(([k, v]) => [encode(k), encode(v)])]);
const claimKeys = { keys: [jwk(AGENT)] };
const claimCases = [
  { name: 'a valid message, protected header under tag 259', valid: true, message: cose(AGENT) },
  { name: 'the same with the protected header untagged (a verifier SHOULD accept it)', valid: true, level: 'SHOULD', message: cose(AGENT, { tagProtected: false }) },
  { name: 'the same with the key id as a text string (a verifier SHOULD accept it)', valid: true, level: 'SHOULD', message: cose(AGENT, { kidAsText: true }) },
  { name: 'a payload with a two-byte map length and a timestamp written as a double', valid: true, message: cose(AGENT, { payloadBytes: longPrefixPayload }) },
  { name: 'a changed payload', valid: false, message: cose(AGENT, { tamper: (p) => { p[2] = flip(p[2]); } }) },
  { name: 'a changed signature', valid: false, message: cose(AGENT, { tamper: (p) => { p[3] = flip(p[3]); } }) },
  { name: 'alg ES256 (-7)', valid: false, message: cose(AGENT, { alg: -7 }) },
  { name: 'a key id of another agent, signed by a key the key set lists under it', valid: false, message: cose(OTHER, { kid: 'agent:agt_other:v1' }), jwks: { keys: [jwk(AGENT), jwk(OTHER, { kid: 'agent:agt_other:v1' })] } },
  { name: 'a key id of an operator claim key', valid: false, message: cose(OTHER, { kid: 'op_vectors:claim:v1' }), jwks: { keys: [jwk(AGENT), jwk(OTHER, { kid: 'op_vectors:claim:v1' })] } },
  { name: 'no key id', valid: false, message: cose(AGENT, { kid: null }) },
  { name: 'a signature by another key under the agent key id', valid: false, message: cose(OTHER) },
  { name: 'an empty key set', valid: false, message: cose(AGENT), jwks: { keys: [] } },
  { name: 'a key that carries its private member', valid: false, message: cose(AGENT), jwks: { keys: [jwk(AGENT, { d: 'not-a-real-private-key' })] } },
  { name: 'a key whose alg is RS256', valid: false, message: cose(AGENT), jwks: { keys: [jwk(AGENT, { alg: 'RS256' })] } },
  { name: 'the same key listed twice', valid: true, message: cose(AGENT), jwks: { keys: [jwk(AGENT), jwk(AGENT)] } },
];

// ─── A workload token (spec/workload-identity section 4) ────────────────────────────────────────────────────────

const WL = keyFromSeed(0x41);
const WL_OTHER = keyFromSeed(0x42);
const wlJwks = { keys: [{ ...keyFromSeed(0x43).publicJwk, kid: 'decoy' }, { ...WL.publicJwk, kid: 'wl-1' }] };
const SPIFFE_ID = 'spiffe://vectors.example/ns/payments/sa/orders';
const spiffeClaims = (over = {}) => ({ sub: SPIFFE_ID, aud: ['stack-vectors'], iat: NOW, exp: NOW + 300, ...over });
const witClaims = (over = {}) => ({ iss: 'https://issuer.vectors.example', sub: 'https://workloads.vectors.example/orders', aud: 'stack-vectors', iat: NOW, exp: NOW + 300, ...over });
const spiffeConfig = { trust_domain: 'vectors.example', audience: 'stack-vectors' };
const witConfig = { issuer_uri: 'https://issuer.vectors.example', audience: 'stack-vectors' };
const wl = (kind, name, valid, claims, { header = { alg: 'EdDSA', kid: 'wl-1' }, key = WL, config, jwks, reason, token } = {}) => ({
  kind, name, valid, ...(reason ? { reason } : {}), config: config ?? (kind === 'spiffe' ? spiffeConfig : witConfig), jwks: jwks ?? wlJwks, token_parts: partsOf(token ?? jws(header, claims, key)),
});
const hmacSecret = Buffer.alloc(32, 0x44);
const workloadCases = [
  wl('spiffe', 'a valid JWT-SVID, with the audience in an array', true, spiffeClaims()),
  wl('wimse', 'a valid WIT', true, witClaims()),
  wl('wimse', 'a valid WIT with a cnf key', true, witClaims({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: WL_OTHER.publicJwk.x } } })),
  wl('spiffe', 'any audience, when the configuration pins none', true, spiffeClaims({ aud: ['anything'] }), { config: { trust_domain: 'vectors.example', audience: null } }),
  wl('spiffe', 'an expired token', false, spiffeClaims({ iat: NOW - 900, exp: NOW - 600 }), { reason: 'expired' }),
  wl('spiffe', 'a token with no exp', false, without(spiffeClaims(), 'exp')),
  wl('spiffe', 'a token that is not valid yet', false, spiffeClaims({ nbf: NOW + 600 })),
  wl('spiffe', 'another audience', false, spiffeClaims({ aud: ['someone-else'] }), { reason: 'audience_mismatch' }),
  wl('spiffe', 'a sub that is not a SPIFFE id', false, spiffeClaims({ sub: 'not-a-spiffe-id' }), { reason: 'invalid_spiffe_id' }),
  wl('spiffe', 'an id of another trust domain', false, spiffeClaims({ sub: 'spiffe://other.example/ns/x' }), { reason: 'trust_domain_mismatch' }),
  wl('wimse', 'a WIT from another issuer', false, witClaims({ iss: 'https://attacker.example' }), { reason: 'issuer_mismatch' }),
  wl('wimse', 'a WIT with no sub', false, without(witClaims(), 'sub'), { reason: 'missing_sub' }),
  wl('spiffe', 'a token with no kid', false, spiffeClaims(), { header: { alg: 'EdDSA' }, reason: 'missing_kid' }),
  wl('spiffe', 'a kid that is not in the key set', false, spiffeClaims(), { header: { alg: 'EdDSA', kid: 'nope' }, reason: 'unknown_kid' }),
  wl('spiffe', 'a signature by another key under the same kid', false, spiffeClaims(), { key: WL_OTHER, reason: 'signature_invalid' }),
  wl('wimse', 'a payload changed after signing', false, undefined, {
    token: (() => {
      const [h, , s] = jws({ alg: 'EdDSA', kid: 'wl-1' }, witClaims(), WL).split('.');
      return `${h}.${b64url(witClaims({ sub: 'https://workloads.vectors.example/other' }))}.${s}`;
    })(),
  }),
  wl('spiffe', 'alg none', false, undefined, { token: `${b64url({ alg: 'none', kid: 'wl-1' })}.${b64url(spiffeClaims())}.` }),
  wl('spiffe', 'an HS256 token keyed with a published symmetric key', false, undefined, {
    jwks: { keys: [{ kty: 'oct', k: hmacSecret.toString('base64url'), kid: 'wl-1', alg: 'HS256' }] },
    token: (() => {
      const input = `${b64url({ alg: 'HS256', kid: 'wl-1' })}.${b64url(spiffeClaims())}`;
      return `${input}.${createHmac('sha256', hmacSecret).update(input).digest('base64url')}`;
    })(),
  }),
];

// ─── A client metadata document (spec/oauth-profile section 4.1 and 4.3) ────────────────────────────────────────

const CLIENT_ID = 'https://client.example/oauth/client.json';
const doc = (over = {}) => ({ client_id: CLIENT_ID, client_name: 'Vector Client', redirect_uris: ['https://client.example/callback'], ...over });
const clientCases = [
  { name: 'a minimal document', valid: true, client_id: CLIENT_ID, document: doc() },
  { name: 'https, loopback and private-use redirects', valid: true, client_id: CLIENT_ID, document: doc({ redirect_uris: ['https://client.example/cb', 'http://127.0.0.1:8123/cb', 'http://[::1]/cb', 'cursor://anysphere.cursor-mcp/oauth/callback'] }) },
  { name: 'a client that prefers private_key_jwt but lists none', valid: true, client_id: CLIENT_ID, document: doc({ token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_methods_supported: ['private_key_jwt', 'none'] }) },
  { name: 'a client that lists jwt-bearer among its grants (kept grants: authorization_code, refresh_token)', valid: true, client_id: CLIENT_ID, document: doc({ grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'] }) },
  { name: 'a client_id that is not the URL', valid: false, client_id: CLIENT_ID, document: doc({ client_id: 'https://client.example/other.json' }) },
  { name: 'a document with a client secret', valid: false, client_id: CLIENT_ID, document: doc({ client_secret: 'shh' }) },
  { name: 'a client that wants client_secret_post', valid: false, client_id: CLIENT_ID, document: doc({ token_endpoint_auth_method: 'client_secret_post' }) },
  { name: 'an http redirect on a public host', valid: false, client_id: CLIENT_ID, document: doc({ redirect_uris: ['http://client.example/cb'] }) },
  { name: 'a redirect with a fragment', valid: false, client_id: CLIENT_ID, document: doc({ redirect_uris: ['https://client.example/cb#x'] }) },
  { name: 'a javascript: redirect', valid: false, client_id: CLIENT_ID, document: doc({ redirect_uris: ['javascript:alert(1)'] }) },
  { name: 'no redirect URIs', valid: false, client_id: CLIENT_ID, document: doc({ redirect_uris: [] }) },
  { name: 'twenty-one redirect URIs', valid: false, client_id: CLIENT_ID, document: doc({ redirect_uris: Array.from({ length: 21 }, (_, i) => `https://client.example/cb${i}`) }) },
  { name: 'grants without authorization_code', valid: false, client_id: CLIENT_ID, document: doc({ grant_types: ['refresh_token'] }) },
  { name: 'response_types ["token"]', valid: false, client_id: CLIENT_ID, document: doc({ response_types: ['token'] }) },
  { name: 'a blank client name', valid: false, client_id: CLIENT_ID, document: doc({ client_name: '   ' }) },
];
const clientIdCases = [
  ['https://client.example/oauth/client.json', true], ['https://client.example:8443/a', true],
  ['https://client.example/', false], ['https://client.example', false], ['http://client.example/client.json', false],
  ['https://client.example/a?x=1', false], ['https://client.example/a#x', false], ['https://user:pw@client.example/a', false],
  ['https://client.example/a/../b', false], ['https://client.example/./a', false], ['oc_0123456789', false],
].map(([client_id, metadata_document_url]) => ({ client_id, metadata_document_url }));

const vectors = {
  version: 1,
  note: 'Test vectors for the identity specifications. Built by scripts/build-identity-vectors.mjs; the keys are for these vectors only.',
  agent_jwt: {
    spec: 'spec/agent-auth/SPEC.md sections 3 and 4',
    now: NOW,
    agent_id: AGENT_ID,
    public_jwk: AGENT.publicJwk,
    token_parts_are: 'The three parts of the compact token (header, payload, signature); join them with a full stop. The last part is empty for alg none.',
    cases_are_presented_in_order: 'A verifier that keeps its record of used tokens sees the cases one after the other; the last one repeats the first.',
    cases: agentCases,
  },
  agent_claim: {
    spec: 'spec/agent-keys/SPEC.md sections 5 and 6',
    agent_id: AGENT_ID,
    key_id: KID,
    jwks: claimKeys,
    envelope,
    cases: claimCases,
  },
  workload_token: {
    spec: 'spec/workload-identity/SPEC.md section 4 (steps 1, 2, 4 and 5)',
    now: NOW,
    cases: workloadCases,
  },
  client_metadata: {
    spec: 'spec/oauth-profile/SPEC.md sections 4.1 and 4.3',
    cases: clientCases,
    client_ids: clientIdCases,
  },
};

const text = `${JSON.stringify(vectors, null, 2)}\n`;
const file = join(OUT, 'vectors.json');
if (process.argv.includes('--check')) {
  const current = existsSync(file) ? readFileSync(file, 'utf8').replaceAll('\r\n', '\n') : '';
  if (current !== text) {
    console.error('fixtures/identity/vectors.json is out of date: run `node scripts/build-identity-vectors.mjs`');
    process.exit(1);
  }
  console.log('identity vectors are current');
} else {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(file, text, 'utf8');
  console.log(`wrote ${file}`);
}
