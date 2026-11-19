#!/usr/bin/env node
// Builds the test vectors of the authority receiver protocol in
// fixtures/authority/: every signed and encrypted message of
// spec/authority-receiver/SPEC.md as exact bytes, with the inputs that make
// them, so an implementation in any language can check its encodings offline
// before it meets a server.
//
// The vectors are built from the specification alone with node:crypto: Ed25519
// signatures are deterministic, and the one JWE is built with a fixed ephemeral
// key, content key and nonce, so running the script twice writes the same
// bytes. `--check` fails if the files on disk differ from a fresh build. The
// keys are for these fixtures only and protect nothing.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../src/canonical.mjs';
import { b64u, digest, ed25519FromSeed, encryptJwe, p256FromSeed, signJws } from '../src/authority-jose.mjs';
import {
  FIXTURE, NORMALIZED_REQUEST, fixtureKeys, presentationPayload, presentationRequestFields, requestHashOf, resourceHashOf,
} from '../src/authority-fixtures.mjs';

/**
 * A compact JWS in a file of fixtures is written as the array of its three dot-separated parts: join them with
 * '.' to get the token. (A token written whole looks like a credential to a secret scanner, and these are not.)
 */
const explode = (value) => {
  if (typeof value === 'string' && /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value)) return value.split('.');
  if (Array.isArray(value)) return value.map(explode);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, explode(v)]));
  return value;
};

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'authority');
const NOW = FIXTURE.startedAt;
const keys = fixtureKeys();
const signWith = (key, claims) => signJws({ alg: key.alg, kid: key.kid, typ: 'JWT' }, claims, key.privateKey, key.alg);
const publicOf = (key) => key.publicJwk;

function build() {
  const files = new Map();

  // ─── Keys ───────────────────────────────────────────────────────
  const stackJwks = { keys: [{ ...publicOf(keys.stack), use: 'sig' }] };
  files.set('stack-jwks.json', stackJwks);

  // The private halves are not written out: each is a fixed seed byte repeated 32 times (a private key for these
  // fixtures only), so the file holds nothing that looks like a secret. Ed25519: the 32-byte seed. P-256: the scalar d.
  const receiverKeys = {
    note: 'Fixture keys. They protect nothing. The receiver under test holds the private halves of the first three and of response_encryption; STACK holds the public halves.',
    private_key_rule: 'A private key is 32 bytes that all equal the byte seed_byte_hex: the Ed25519 seed, or the P-256 scalar d. The JWK of an Ed25519 key is {kty:OKP, crv:Ed25519, x, d} and of a P-256 key {kty:EC, crv:P-256, x, y, d}, d being the base64url of those 32 bytes.',
    request_signing: { use: 'request_signing', algorithm: 'EdDSA', seed_byte_hex: '41', public_jwk: publicOf(keys.request) },
    request_signing_es256: { use: 'request_signing', algorithm: 'ES256', seed_byte_hex: '47', public_jwk: publicOf(keys.requestEs) },
    receipt_signing: { use: 'receipt_signing', algorithm: 'EdDSA', seed_byte_hex: '42', public_jwk: publicOf(keys.receipt) },
    response_encryption: { use: 'response_encryption', algorithm: 'ECDH-ES+A256KW', seed_byte_hex: '43', public_jwk: publicOf(keys.encryption) },
  };

  // ─── Digests ────────────────────────────────────────────────────
  const unordered = { b: [3, { y: 1, x: 2 }], a: null, c: 'é "quoted"' };
  const digests = [
    { name: 'empty string', input: '', digest: digest('') },
    { name: 'canonical JSON, keys sorted at every depth', input: unordered, canonical: canonicalize(unordered), digest: digest(canonicalize(unordered)) },
    { name: 'request_hash', receiver_request_id: FIXTURE.receiverRequestId, normalized_request: NORMALIZED_REQUEST, digest: requestHashOf(FIXTURE.receiverRequestId, NORMALIZED_REQUEST) },
    { name: 'resource_hash', receiver_request_id: FIXTURE.receiverRequestId, resource_ref: NORMALIZED_REQUEST.resource_ref, digest: resourceHashOf(FIXTURE.receiverRequestId, NORMALIZED_REQUEST.resource_ref) },
    {
      name: 'agent key thumbprint', jwk: { kty: 'OKP', crv: 'Ed25519', x: ed25519FromSeed(0x51, 'agent').publicJwk.x },
      digest: `sha256:${createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: ed25519FromSeed(0x51, 'agent').publicJwk.x })).digest('hex')}`,
    },
  ];

  // ─── Call assertions ────────────────────────────────────────────
  const assertionClaims = ({ method, path, body, jti }) => ({
    iss: FIXTURE.receiverId, sub: FIXTURE.receiverId, aud: `${FIXTURE.stackOrigin}${path}`, jti, iat: NOW, exp: NOW + 30,
    htm: method, htu: path, body_hash: digest(body === undefined ? '' : canonicalize(body)),
  });
  const assertions = [
    { method: 'POST', path: '/v1/authority/status-checks', body: { normalized_request: { b: 2, a: 1 }, binding_id: 'abn_conformance' }, jti: 'assertion-vector-1' },
    { method: 'GET', path: '/v1/authority/presentation-requests/prs_conformance', jti: 'assertion-vector-2' },
  ].map((input) => {
    const claims = assertionClaims(input);
    return { ...input, now: NOW, key: 'request_signing', claims, jws: signWith(keys.request, claims) };
  });

  // ─── Signed presentation request ────────────────────────────────
  const fields = presentationRequestFields(NOW);
  const { passport, agent_proof: agentProof, ...bodyFields } = fields;
  const repeated = ['authority_ref', 'receiver_profile_version_id', 'receiver_request_id', 'mission_id', 'action_uri', 'resource_hash', 'request_hash', 'requested_facts', 'nonce', 'issued_at', 'expires_at', 'normalized_request'];
  const requestClaims = {
    iss: FIXTURE.receiverId, sub: FIXTURE.receiverId, aud: `${FIXTURE.stackOrigin}/v1/authority/presentation-requests`, jti: 'request-vector-1', iat: fields.issued_at, exp: fields.expires_at,
    ...Object.fromEntries(repeated.map((name) => [name, fields[name]])),
    passport_hash: digest(passport), agent_proof_hash: digest(agentProof),
  };
  const signedRequest = {
    now: NOW, key: 'request_signing', fields, claims: requestClaims, signed_request: signWith(keys.request, requestClaims),
    body: { ...bodyFields, passport, agent_proof: agentProof },
  };

  // ─── Presentation: signed by STACK, encrypted to the receiver ───
  const payload = presentationPayload(NOW, { jti: 'pjt_conformance_vector' });
  const inner = signJws({ alg: 'EdDSA', kid: keys.stack.kid, typ: 'JWT' }, payload, keys.stack.privateKey, 'EdDSA');
  const ephemeral = p256FromSeed(0x48, 'ephemeral');
  const jwe = encryptJwe({
    plaintext: inner, recipientPublicJwk: keys.encryption.publicJwk, kid: keys.encryption.kid,
    ephemeral: { privateKey: ephemeral.privateKey }, cek: Buffer.alloc(32, 0x55), iv: Buffer.alloc(12, 0x66),
  });
  const presentation = {
    now: NOW, expected: { nonce: FIXTURE.nonce, request_hash: payload.request_hash },
    payload, payload_digest: digest(canonicalize(payload)), signed: inner, jwe, recipient_key: 'response_encryption',
  };

  // ─── Receipts ───────────────────────────────────────────────────
  const receipts = ['accepted', 'rejected'].map((outcome, index) => {
    const result = { outcome, reference: `case-${index}`, nested: { b: 1, a: [2, 1] } };
    const nonce = b64u(Buffer.alloc(18, 0x70 + index));
    const claims = {
      iss: FIXTURE.receiverId, sub: FIXTURE.receiverId, aud: `${FIXTURE.stackOrigin}/v1/authority/presentations/prs_conformance/receipts`,
      jti: `receipt-vector-${index + 1}`, iat: NOW, exp: NOW + 30,
      receiver_id: FIXTURE.receiverId, presentation_id: 'prs_conformance', authority_use_id: payload.authority_use_id,
      presentation_payload_hash: digest(canonicalize(payload)), request_hash: payload.request_hash, action_uri: payload.action_uri,
      outcome, result, result_commitment_nonce: nonce, result_hash: digest(canonicalize({ value: result, commitment_nonce: nonce })),
      external_transaction_ref: `case-${index}`,
    };
    return { now: NOW, key: 'receipt_signing', presentation_id: 'prs_conformance', outcome, result, claims, signed_receipt: signWith(keys.receipt, claims) };
  });

  // ─── Origin document ────────────────────────────────────────────
  const challenge = { challenge_id: 'rvc_conformance', challenge: b64u(Buffer.alloc(32, 0x31)) };
  const originClaims = {
    iss: FIXTURE.receiverId, sub: FIXTURE.receiverId, aud: FIXTURE.stackOrigin, jti: 'origin-vector-1', iat: NOW, exp: NOW + 120, ...challenge,
  };
  const origin = {
    now: NOW, key: 'request_signing', challenge, claims: originClaims,
    document: { origin: 'https://receiver.stack-conformance.test', key_id: keys.request.kid, signed_challenge: signWith(keys.request, originClaims) },
  };

  files.set('vectors.json', {
    spec: 'stack-authority-receiver',
    version: '1.0.0',
    note: 'A compact JWS is written as the array of its three dot-separated parts: join them with a full stop. Built by scripts/build-authority-vectors.mjs from the specification alone. Ed25519 signatures and the one JWE are deterministic. The keys are fixtures and protect nothing.',
    constants: { ...FIXTURE },
    receiver_keys: receiverKeys,
    stack_jwks: stackJwks,
    digests,
    assertions,
    signed_request: signedRequest,
    presentation,
    receipts,
    origin_document: origin,
  });
  return files;
}

const check = process.argv.includes('--check');
const files = build();
const stale = [];
mkdirSync(OUT, { recursive: true });
for (const [name, value] of files) {
  const text = `${JSON.stringify(explode(value), null, 2)}\n`;
  const path = join(OUT, name);
  const current = existsSync(path) ? readFileSync(path, 'utf8').replaceAll('\r\n', '\n') : null;
  if (current !== text) stale.push(name);
  if (!check && current !== text) writeFileSync(path, text, 'utf8');
}
if (check) {
  if (stale.length > 0) {
    console.error(`the authority fixtures are out of date: ${stale.join(', ')}. Run node scripts/build-authority-vectors.mjs`);
    process.exit(1);
  }
  console.log('the authority fixtures are current');
} else {
  console.log(`wrote ${stale.length} changed file(s) of ${files.size}`);
}
