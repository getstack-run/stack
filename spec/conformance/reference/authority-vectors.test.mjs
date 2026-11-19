// The test vectors in fixtures/authority/ are the exact bytes of every signed
// and encrypted message of the authority receiver protocol. This test proves
// they are what the script builds, that the kit reads each as STACK does, and
// that the reference receiver opens the one encrypted presentation.

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { canonicalize } from '../src/canonical.mjs';
import { decodeJws, digest, verifyJwsSignature } from '../src/authority-jose.mjs';
import { readReceiverJws } from '../src/authority-receiver.mjs';
import { createReceiver } from './authority-receiver.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const vectors = JSON.parse(readFileSync(join(root, 'fixtures', 'authority', 'vectors.json'), 'utf8'));
const { constants } = vectors;
/** The private JWK of a fixture key: its public JWK and d, 32 bytes that all equal the seed byte. */
const privateJwk = (name) => ({ ...vectors.receiver_keys[name].public_jwk, d: Buffer.alloc(32, Number.parseInt(vectors.receiver_keys[name].seed_byte_hex, 16)).toString('base64url') });
const key = (name) => ({ kid: vectors.receiver_keys[name].public_jwk.kid, alg: vectors.receiver_keys[name].algorithm, publicJwk: vectors.receiver_keys[name].public_jwk });

describe('authority test vectors', () => {
  it('are what the script builds', () => {
    const run = spawnSync(process.execPath, [join(root, 'scripts', 'build-authority-vectors.mjs'), '--check'], { encoding: 'utf8' });
    expect(run.status, run.stderr).toBe(0);
  });

  it('every digest is the digest of its input', () => {
    for (const entry of vectors.digests) {
      if (entry.canonical !== undefined) expect(canonicalize(entry.input), entry.name).toBe(entry.canonical);
      if (entry.name === 'empty string') expect(digest(entry.input)).toBe(entry.digest);
      if (entry.canonical !== undefined) expect(digest(entry.canonical), entry.name).toBe(entry.digest);
    }
    expect(vectors.digests.map((d) => d.digest).every((d) => /^sha256:[0-9a-f]{64}$/.test(d))).toBe(true);
  });

  it('each call assertion verifies and binds its request', () => {
    for (const vector of vectors.assertions) {
      const token = vector.jws.join('.');
      const read = readReceiverJws(token, { key: key(vector.key), receiverId: constants.receiverId, audience: `${constants.stackOrigin}${vector.path}`, now: vector.now, maxLifetime: 60 });
      expect(read.problems).toEqual([]);
      expect(read.payload.body_hash).toBe(digest(vector.body === undefined ? '' : canonicalize(vector.body)));
    }
  });

  it('the signed request verifies and repeats the body', () => {
    const v = vectors.signed_request;
    const read = readReceiverJws(v.signed_request.join('.'), { key: key(v.key), receiverId: constants.receiverId, audience: `${constants.stackOrigin}/v1/authority/presentation-requests`, now: v.now, maxLifetime: 120 });
    expect(read.problems).toEqual([]);
    for (const name of ['authority_ref', 'receiver_request_id', 'request_hash', 'nonce', 'normalized_request', 'requested_facts']) {
      expect(canonicalize(read.payload[name]), name).toBe(canonicalize(v.body[name]));
    }
    expect(read.payload.passport_hash).toBe(digest(v.body.passport.join('.')));
    expect(read.payload.agent_proof_hash).toBe(digest(v.body.agent_proof.join('.')));
  });

  it('each receipt verifies and commits its result', () => {
    for (const v of vectors.receipts) {
      const audience = `${constants.stackOrigin}/v1/authority/presentations/${v.presentation_id}/receipts`;
      const read = readReceiverJws(v.signed_receipt.join('.'), { key: key(v.key), receiverId: constants.receiverId, audience, now: v.now, maxLifetime: 60 });
      expect(read.problems).toEqual([]);
      expect(read.payload.presentation_payload_hash).toBe(vectors.presentation.payload_digest);
      expect(read.payload.result_hash).toBe(digest(canonicalize({ value: read.payload.result, commitment_nonce: read.payload.result_commitment_nonce })));
    }
  });

  it('the origin document verifies', () => {
    const v = vectors.origin_document;
    const decoded = decodeJws(v.document.signed_challenge.join('.'));
    expect(verifyJwsSignature(decoded, key(v.key).publicJwk, key(v.key).alg)).toBe(true);
    expect(decoded.payload).toMatchObject({ aud: constants.stackOrigin, challenge_id: v.challenge.challenge_id, challenge: v.challenge.challenge });
  });

  it('the reference receiver opens the encrypted presentation and the signed one is STACK\'s', () => {
    const v = vectors.presentation;
    const stack = vectors.stack_jwks.keys[0];
    expect(verifyJwsSignature(decodeJws(v.signed.join('.')), stack, 'EdDSA')).toBe(true);
    const receiver = createReceiver({
      receiverId: constants.receiverId, receiverProfileVersionId: constants.receiverProfileVersionId, stackOrigin: constants.stackOrigin,
      presentationIssuer: constants.presentationIssuer, audience: constants.audience,
      requestKey: { kid: key('request_signing').kid, alg: 'EdDSA', privateJwk: privateJwk('request_signing') },
      receiptKey: { kid: key('receipt_signing').kid, alg: 'EdDSA', privateJwk: privateJwk('receipt_signing') },
      encryptionKey: { kid: key('response_encryption').kid, privateJwk: privateJwk('response_encryption') },
      stackKeys: vectors.stack_jwks,
    });
    const claims = receiver.openPresentation(v.jwe, { now: v.now, expected: { nonce: v.expected.nonce, requestHash: v.expected.request_hash } });
    expect(claims).toEqual(v.payload);
  });
});
