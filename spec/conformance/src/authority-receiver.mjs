// Conformance suite for an AUTHORITY RECEIVER: the server or library that an
// authority, a bank or any service runs to ask the owner of an agent for
// information and to get only what it asked for (spec/authority-receiver/SPEC.md).
// The kit plays STACK. It reads what your receiver produces the way STACK
// reads it, and it hands your receiver what STACK sends, the correct message
// and the ones that have one thing wrong, and checks that your receiver
// accepts the first and refuses the others.
//
// Two ways to point it at a receiver, together or alone:
//
//   { create }        a function that takes a configuration (the receiver's
//                     identifier and keys, the STACK origin and keys it trusts)
//                     and returns an object with the five functions of
//                     section 15.1 of the specification. A receiver in
//                     another language is wrapped with `commandReceiver`.
//   { deliveryUrl, deliveryKey }  the receiver's delivery endpoint, as a test
//                     instance configured as section 15.2 says, and the public
//                     JWK of its response-encryption key.
//
// The messages are synthetic and nothing is done on anyone's behalf.

import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { assert, post, runChecks, skip } from './harness.mjs';
import { canonicalize } from './canonical.mjs';
import {
  b64u, decodeJws, digest, fromB64u, verifyJwsSignature,
} from './authority-jose.mjs';
import {
  FIXTURE, NORMALIZED_REQUEST, encryptPresentation, fixtureKeys, presentationPayload, presentationRequestFields,
  randomId, requestHashOf, signPresentation,
} from './authority-fixtures.mjs';

const BASE64URL_22 = /^[A-Za-z0-9_-]{22,}$/;
const FORBIDDEN_HEADER_MEMBERS = ['jku', 'x5u', 'jwk', 'crit'];

/** The configuration a receiver under test is created with. */
export function receiverConfig(keys = fixtureKeys(), requestAlg = 'EdDSA') {
  const request = requestAlg === 'ES256' ? keys.requestEs : keys.request;
  return {
    receiverId: FIXTURE.receiverId,
    receiverProfileVersionId: FIXTURE.receiverProfileVersionId,
    stackOrigin: FIXTURE.stackOrigin,
    presentationIssuer: FIXTURE.presentationIssuer,
    audience: FIXTURE.audience,
    requestKey: { kid: request.kid, alg: request.alg, privateJwk: request.privateJwk },
    receiptKey: { kid: keys.receipt.kid, alg: keys.receipt.alg, privateJwk: keys.receipt.privateJwk },
    encryptionKey: { kid: keys.encryption.kid, privateJwk: keys.encryption.privateJwk },
    stackKeys: { keys: [keys.stack.publicJwk] },
  };
}

/**
 * A receiver written in another language: a program that reads one JSON
 * object `{ op, config, input }` on stdin and writes one JSON object on stdout:
 * `{ "result": ... }`, or `{ "error": "..." }` when it refuses. `op` is one of
 * `authorization`, `signPresentationRequest`, `signReceipt`, `openPresentation`
 * and `verificationDocument`.
 */
export function commandReceiver(command, args = []) {
  const call = (op, config, input) => new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'] });
    let out = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.on('error', reject);
    child.on('close', () => {
      try {
        const answer = JSON.parse(out);
        if (answer.error !== undefined) reject(new Error(String(answer.error)));
        else resolve(answer.result);
      } catch {
        reject(new Error('the program did not answer with one JSON object'));
      }
    });
    child.stdin.end(JSON.stringify({ op, config, input }));
  });
  return (config) => ({
    authorization: (input) => call('authorization', config, input),
    signPresentationRequest: (fields, options) => call('signPresentationRequest', config, { fields, ...options }),
    signReceipt: (input) => call('signReceipt', config, input),
    openPresentation: (jwe, options) => call('openPresentation', config, { jwe, ...options }),
    verificationDocument: (input) => call('verificationDocument', config, input),
  });
}

// ─── How STACK reads what a receiver sends ──────────────────────────

/**
 * Judge a receiver-signed compact JWS the way STACK does. Returns the problems
 * found (an empty list is a pass) and what was read.
 */
export function readReceiverJws(compact, { key, receiverId, audience, now, maxLifetime }) {
  const problems = [];
  const decoded = decodeJws(compact);
  if (!decoded) return { problems: ['not a compact JWS'] };
  const { header, payload } = decoded;
  if (header.alg !== key.alg) problems.push(`alg is ${JSON.stringify(header.alg)}, expected ${key.alg}`);
  if (header.kid !== key.kid) problems.push(`kid is ${JSON.stringify(header.kid)}, expected ${key.kid}`);
  for (const member of FORBIDDEN_HEADER_MEMBERS) if (member in header) problems.push(`header carries ${member}`);
  if (!verifyJwsSignature(decoded, key.publicJwk, key.alg)) problems.push('the signature does not verify with the registered key');
  if (payload.iss !== receiverId) problems.push(`iss is ${JSON.stringify(payload.iss)}, expected ${receiverId}`);
  if (payload.sub !== receiverId) problems.push(`sub is ${JSON.stringify(payload.sub)}, expected ${receiverId}`);
  if (payload.aud !== audience) problems.push(`aud is ${JSON.stringify(payload.aud)}, expected ${audience}`);
  if (typeof payload.jti !== 'string' || payload.jti === '') problems.push('jti is missing');
  const { iat, exp } = payload;
  if (!Number.isInteger(iat) || !Number.isInteger(exp)) problems.push('iat and exp must be integers');
  else {
    if (iat > now + 5) problems.push('iat is in the future');
    if (iat < now - maxLifetime) problems.push('iat is older than the lifetime allows');
    if (exp <= now) problems.push('exp has passed');
    if (exp <= iat || exp - iat > maxLifetime) problems.push(`the lifetime is not between 1 and ${maxLifetime} seconds`);
  }
  return { problems, header, payload };
}

const bodyDigest = (body) => digest(body === undefined ? '' : canonicalize(body));
const stripQuery = (path) => path.split('?', 1)[0];

/**
 * @param {{
 *   create?: (config: object) => object | Promise<object>,
 *   deliveryUrl?: string,
 *   deliveryKey?: { kid: string, publicJwk: object },
 *   now?: number,
 *   requestAlg?: 'EdDSA' | 'ES256',
 *   timeoutMs?: number,
 *   fetchImpl?: typeof fetch,
 * }} options
 */
export async function runAuthorityReceiverSuite(options) {
  const { create, deliveryUrl, timeoutMs = 10_000, fetchImpl } = options;
  if (!create && !deliveryUrl) throw new Error('give the authority suite a create function, a deliveryUrl, or both');
  if (deliveryUrl && !options.deliveryKey) throw new Error('a deliveryUrl needs the receiver\'s deliveryKey ({ kid, publicJwk })');
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const keys = fixtureKeys();
  const requestAlg = options.requestAlg ?? 'EdDSA';
  const config = receiverConfig(keys, requestAlg);
  const receiverKey = (k) => ({ kid: k.kid, alg: k.alg, publicJwk: k.publicJwk });
  const requestKey = receiverKey(requestAlg === 'ES256' ? keys.requestEs : keys.request);
  const receiptKey = receiverKey(keys.receipt);
  const receiver = create ? await create(config) : null;
  const originAndPath = (path) => `${FIXTURE.stackOrigin}${stripQuery(path)}`;

  const checks = [];
  const need = (what) => (receiver ? undefined : skip(`needs a create function: ${what}`));

  // ─── Authenticating a call (section 5) ────────────────────────────
  const call = async (method, path, body) => {
    const header = await receiver.authorization({ method, path, body, now });
    return header;
  };
  const readAssertion = (header, path) => {
    assert(typeof header === 'string' && header.startsWith('STACK-Receiver '), 'the Authorization value must begin with "STACK-Receiver "');
    const token = header.slice('STACK-Receiver '.length);
    assert(token !== '' && !/\s/.test(token), 'the credential must be one compact JWS with no spaces');
    return readReceiverJws(token, { key: requestKey, receiverId: FIXTURE.receiverId, audience: originAndPath(path), now, maxLifetime: 60 });
  };
  const STATUS_BODY = { binding_id: 'abn_conformance', action_uri: FIXTURE.actionUri, normalized_request: { b: 2, a: { z: 1, y: [3, 2, 1] } } };

  checks.push(
    {
      id: 'A01', level: 'MUST', title: 'a call carries "STACK-Receiver " and one compact JWS',
      async run() {
        const early = need('request authentication');
        if (early) return early;
        const header = await call('POST', '/v1/authority/status-checks', STATUS_BODY);
        assert(typeof header === 'string' && header.startsWith('STACK-Receiver '), 'the Authorization value must begin with "STACK-Receiver "');
        const token = header.slice('STACK-Receiver '.length);
        assert(decodeJws(token) !== null, 'the credential is not a compact JWS');
        assert(!/\s/.test(token), 'the credential has whitespace in it');
      },
    },
    {
      id: 'A02', level: 'MUST', title: 'the assertion names the registered key and algorithm, carries no key discovery member and verifies',
      async run() {
        const early = need('request authentication');
        if (early) return early;
        const read = readAssertion(await call('POST', '/v1/authority/status-checks', STATUS_BODY), '/v1/authority/status-checks');
        const wanted = read.problems.filter((p) => /alg|kid|header|signature/.test(p));
        assert(wanted.length === 0, wanted.join('; '));
      },
    },
    {
      id: 'A03', level: 'MUST', title: 'iss and sub are the receiver identifier and aud is the STACK origin plus the exact path',
      async run() {
        const early = need('request authentication');
        if (early) return early;
        for (const [method, path, body] of [
          ['POST', '/v1/authority/status-checks', STATUS_BODY],
          ['GET', '/v1/authority/presentation-requests/prs_conformance', undefined],
          ['POST', '/v1/authority/presentation-requests', presentationRequestFields(now)],
        ]) {
          const read = readAssertion(await call(method, path, body), path);
          const wanted = read.problems.filter((p) => /^(iss|sub|aud)/.test(p));
          assert(wanted.length === 0, `${method} ${path}: ${wanted.join('; ')}`);
        }
      },
    },
    {
      id: 'A04', level: 'MUST', title: 'htm is the upper-case method, htu the path without its query, body_hash the digest of the canonical body',
      async run() {
        const early = need('request authentication');
        if (early) return early;
        const path = '/v1/authority/status-checks';
        const read = readAssertion(await call('POST', path, STATUS_BODY), path);
        assert(read.payload.htm === 'POST', `htm is ${JSON.stringify(read.payload.htm)}`);
        assert(read.payload.htu === path, `htu is ${JSON.stringify(read.payload.htu)}`);
        assert(read.payload.body_hash === bodyDigest(STATUS_BODY), `body_hash is ${JSON.stringify(read.payload.body_hash)}, expected ${bodyDigest(STATUS_BODY)} (the sha256 of the canonical JSON: keys sorted at every depth, no whitespace)`);
        const queried = readAssertion(await call('GET', '/v1/authority/presentation-requests/prs_conformance?x=1', undefined), '/v1/authority/presentation-requests/prs_conformance');
        assert(queried.payload.htu === '/v1/authority/presentation-requests/prs_conformance', `htu kept the query: ${JSON.stringify(queried.payload.htu)}`);
        assert(queried.payload.htm === 'GET', `htm is ${JSON.stringify(queried.payload.htm)}`);
      },
    },
    {
      id: 'A05', level: 'MUST', title: 'a call without a body signs the digest of the empty string',
      async run() {
        const early = need('request authentication');
        if (early) return early;
        const path = '/v1/authority/presentation-requests/prs_conformance';
        const read = readAssertion(await call('GET', path, undefined), path);
        assert(read.payload.body_hash === digest(''), `body_hash is ${JSON.stringify(read.payload.body_hash)}, expected ${digest('')}`);
      },
    },
    {
      id: 'A06', level: 'MUST', title: 'iat is now (within 5 s) and exp is at most 60 seconds after it',
      async run() {
        const early = need('request authentication');
        if (early) return early;
        const path = '/v1/authority/status-checks';
        const read = readAssertion(await call('POST', path, STATUS_BODY), path);
        const wanted = read.problems.filter((p) => /iat|exp|lifetime/.test(p));
        assert(wanted.length === 0, wanted.join('; '));
        assert(Math.abs(read.payload.iat - now) <= 5, `iat ${read.payload.iat} is not the clock the kit gave (${now})`);
      },
    },
    {
      id: 'A07', level: 'MUST', title: 'every call has its own jti',
      async run() {
        const early = need('request authentication');
        if (early) return early;
        const path = '/v1/authority/status-checks';
        const seen = new Set();
        for (let i = 0; i < 4; i += 1) {
          const read = readAssertion(await call('POST', path, STATUS_BODY), path);
          assert(!seen.has(read.payload.jti), 'a jti was used twice: STACK refuses a repeated one');
          seen.add(read.payload.jti);
        }
      },
    },
    {
      id: 'A08', level: 'MUST', title: 'the body digest does not depend on the order of keys in the body',
      async run() {
        const early = need('request authentication');
        if (early) return early;
        const path = '/v1/authority/status-checks';
        const reordered = { normalized_request: { a: { y: [3, 2, 1], z: 1 }, b: 2 }, action_uri: FIXTURE.actionUri, binding_id: 'abn_conformance' };
        const read = readAssertion(await call('POST', path, reordered), path);
        assert(read.payload.body_hash === bodyDigest(STATUS_BODY), 'the same body with its keys in another order gave a different digest');
      },
    },
  );

  // ─── The signed presentation request (section 6) ──────────────────
  const signedRequest = async (fields = presentationRequestFields(now)) => receiver.signPresentationRequest(fields, { now });
  const REPEATED = ['authority_ref', 'receiver_profile_version_id', 'receiver_request_id', 'mission_id', 'action_uri', 'resource_hash', 'request_hash', 'requested_facts', 'nonce', 'issued_at', 'expires_at', 'normalized_request'];

  checks.push(
    {
      id: 'A10', level: 'MUST', title: 'the signed request names the registered key, is for the presentation-requests path and verifies',
      async run() {
        const early = need('the signed request');
        if (early) return early;
        const read = readReceiverJws(await signedRequest(), { key: requestKey, receiverId: FIXTURE.receiverId, audience: originAndPath('/v1/authority/presentation-requests'), now, maxLifetime: 120 });
        const wanted = read.problems.filter((p) => !/iat|exp|lifetime/.test(p));
        assert(wanted.length === 0, wanted.join('; '));
      },
    },
    {
      id: 'A11', level: 'MUST', title: 'the signed request repeats every field of the body exactly, and the digests of the Passport and the agent proof',
      async run() {
        const early = need('the signed request');
        if (early) return early;
        const fields = presentationRequestFields(now);
        const { payload } = decodeJws(await signedRequest(fields));
        for (const name of REPEATED) {
          assert(canonicalize(payload[name]) === canonicalize(fields[name]), `${name} differs from the body: ${canonicalize(payload[name])}`);
        }
        assert(payload.passport_hash === digest(fields.passport), `passport_hash is ${JSON.stringify(payload.passport_hash)}, expected the digest of the Passport string`);
        assert(payload.agent_proof_hash === digest(fields.agent_proof), `agent_proof_hash is ${JSON.stringify(payload.agent_proof_hash)}, expected the digest of the agent proof string`);
      },
    },
    {
      id: 'A12', level: 'MUST', title: 'iat equals issued_at, exp equals expires_at, the lifetime is at most 120 seconds',
      async run() {
        const early = need('the signed request');
        if (early) return early;
        const fields = presentationRequestFields(now);
        const { payload } = decodeJws(await signedRequest(fields));
        assert(payload.iat === fields.issued_at, `iat ${payload.iat} is not issued_at ${fields.issued_at}`);
        assert(payload.exp === fields.expires_at, `exp ${payload.exp} is not expires_at ${fields.expires_at}`);
        assert(payload.exp - payload.iat <= 120, 'the lifetime is more than 120 seconds');
      },
    },
    {
      id: 'A13', level: 'MUST', title: 'the signed request has a jti of its own, never the one of the call that carries it',
      async run() {
        const early = need('the signed request');
        if (early) return early;
        const fields = presentationRequestFields(now);
        const path = '/v1/authority/presentation-requests';
        const assertion = readAssertion(await call('POST', path, fields), path).payload.jti;
        const signed = decodeJws(await signedRequest(fields)).payload.jti;
        assert(typeof signed === 'string' && signed !== '', 'the signed request has no jti');
        assert(signed !== assertion, 'the signed request and the call share a jti: STACK burns both in one namespace, so the second is refused as a replay');
        const again = decodeJws(await signedRequest(fields)).payload.jti;
        assert(again !== signed, 'two signed requests share a jti');
      },
    },
  );

  // ─── The receipt (section 9) ───────────────────────────────────────
  const presentation = presentationPayload(now);
  const receiptInput = (over = {}) => ({
    presentationId: 'prs_conformance', presentation, outcome: 'accepted', result: { filed: true, reference: 'file-0001' }, now, ...over,
  });
  const readReceipt = (compact) => readReceiverJws(compact, {
    key: receiptKey, receiverId: FIXTURE.receiverId, audience: originAndPath('/v1/authority/presentations/prs_conformance/receipts'), now, maxLifetime: 60,
  });

  checks.push(
    {
      id: 'A20', level: 'MUST', title: 'the receipt is signed with the registered receipt key and is for the receipts path of this presentation',
      async run() {
        const early = need('the receipt');
        if (early) return early;
        const read = readReceipt(await receiver.signReceipt(receiptInput()));
        assert(read.problems.length === 0, read.problems.join('; '));
      },
    },
    {
      id: 'A21', level: 'MUST', title: 'the receipt binds the receiver, the presentation, the use, the digest of the presentation payload, the request and the action',
      async run() {
        const early = need('the receipt');
        if (early) return early;
        const { payload } = decodeJws(await receiver.signReceipt(receiptInput()));
        const wanted = {
          receiver_id: FIXTURE.receiverId,
          presentation_id: 'prs_conformance',
          authority_use_id: presentation.authority_use_id,
          presentation_payload_hash: digest(canonicalize(presentation)),
          request_hash: presentation.request_hash,
          action_uri: presentation.action_uri,
        };
        for (const [name, value] of Object.entries(wanted)) assert(payload[name] === value, `${name} is ${JSON.stringify(payload[name])}, expected ${JSON.stringify(value)}`);
      },
    },
    {
      id: 'A22', level: 'MUST', title: 'outcome is accepted, rejected or failed, and each is a well-formed receipt',
      async run() {
        const early = need('the receipt');
        if (early) return early;
        for (const outcome of ['accepted', 'rejected', 'failed']) {
          const compact = await receiver.signReceipt(receiptInput({ outcome, result: { outcome } }));
          const read = readReceipt(compact);
          assert(read.problems.length === 0, `${outcome}: ${read.problems.join('; ')}`);
          assert(read.payload.outcome === outcome, `outcome is ${JSON.stringify(read.payload.outcome)}, expected ${outcome}`);
        }
      },
    },
    {
      id: 'A23', level: 'MUST', title: 'the result is committed: a nonce of 22 or more base64url characters and result_hash over the canonical { value, commitment_nonce }',
      async run() {
        const early = need('the receipt');
        if (early) return early;
        for (const result of [{ filed: true, nested: { b: 1, a: [2, { d: 4, c: 3 }] } }, 'accepted', null, 42, []]) {
          const { payload } = decodeJws(await receiver.signReceipt(receiptInput({ result })));
          assert(canonicalize(payload.result) === canonicalize(result), `result differs: ${canonicalize(payload.result)}`);
          assert(typeof payload.result_commitment_nonce === 'string' && BASE64URL_22.test(payload.result_commitment_nonce), 'result_commitment_nonce must be at least 22 base64url characters');
          const expected = digest(canonicalize({ value: result, commitment_nonce: payload.result_commitment_nonce }));
          assert(payload.result_hash === expected, `result_hash is ${JSON.stringify(payload.result_hash)}, expected ${expected}`);
        }
      },
    },
    {
      id: 'A24', level: 'MUST', title: 'the commitment nonce is new for every receipt and the jti of every receipt is new',
      async run() {
        const early = need('the receipt');
        if (early) return early;
        const a = decodeJws(await receiver.signReceipt(receiptInput())).payload;
        const b = decodeJws(await receiver.signReceipt(receiptInput())).payload;
        assert(a.jti !== b.jti, 'two receipts share a jti');
        assert(a.result_commitment_nonce !== b.result_commitment_nonce, 'two receipts share a commitment nonce: the hash of a guessable result would be guessable');
      },
    },
    {
      id: 'A25', level: 'SHOULD', title: 'an external transaction reference is carried as external_transaction_ref',
      async run() {
        const early = need('the receipt');
        if (early) return early;
        const { payload } = decodeJws(await receiver.signReceipt(receiptInput({ externalTransactionRef: 'case-2026-0001' })));
        assert(payload.external_transaction_ref === 'case-2026-0001', `external_transaction_ref is ${JSON.stringify(payload.external_transaction_ref)}`);
      },
    },
  );

  // ─── Opening a presentation (section 7), through the function and through the endpoint ──
  const expected = { nonce: FIXTURE.nonce, requestHash: presentationPayload(now).request_hash };
  /** Sign as STACK does (`signer`, `headerOver`) and encrypt to `to` (`jwe` overrides the JWE header values). */
  const seal = (payload, to, { signer = keys.stack, headerOver } = {}, jwe = {}) => encryptPresentation(signPresentation(payload, signer, headerOver), to, jwe);
  const hs256Forgery = (payload) => {
    // The "algorithm confusion" token: HMAC-signed with the bytes of the STACK public key.
    const header = { alg: 'HS256', kid: FIXTURE.stackKid, typ: 'JWT' };
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
    return `${input}.${b64u(createHmac('sha256', fromB64u(keys.stack.publicJwk.x)).update(input).digest())}`;
  };
  const unsecured = (payload) => `${b64u(JSON.stringify({ alg: 'none', kid: FIXTURE.stackKid, typ: 'JWT' }))}.${b64u(JSON.stringify(payload))}.`;
  const tamperedJwe = (compact, part) => {
    const pieces = compact.split('.');
    const bytes = fromB64u(pieces[part]);
    bytes[0] ^= 0x01;
    pieces[part] = b64u(bytes);
    return pieces.join('.');
  };
  const swapHeader = (compact, change) => {
    const pieces = compact.split('.');
    const header = JSON.parse(fromB64u(pieces[0]).toString('utf8'));
    pieces[0] = b64u(JSON.stringify({ ...header, ...change }));
    return pieces.join('.');
  };

  /**
   * The presentations the kit hands a receiver: [id suffix, level, title, build the compact JWE for a recipient key, must it be accepted].
   * One is right and each other has exactly one thing wrong.
   */
  const variants = [
    ['30', 'MUST', 'opens a presentation with every field right and returns its claims', (to) => seal(presentationPayload(now), to), true],
    ['31', 'MUST', 'refuses a JWE whose ciphertext was changed', (to) => tamperedJwe(seal(presentationPayload(now), to), 3), false],
    ['32', 'MUST', 'refuses a JWE whose protected header was changed after encryption (the header is authenticated)', (to) => swapHeader(seal(presentationPayload(now), to), { cty: 'JSON' }), false],
    ['33', 'MUST', 'refuses a JWE encrypted to a key that is not the receiver\'s', () => seal(presentationPayload(now), keys.otherRecipient), false],
    ['34', 'MUST', 'refuses key agreement other than ECDH-ES+A256KW (ECDH-ES direct)', (to) => seal(presentationPayload(now), to, {}, { alg: 'ECDH-ES' }), false],
    ['35', 'MUST', 'refuses content encryption other than A256GCM (A128GCM)', (to) => seal(presentationPayload(now), to, {}, { enc: 'A128GCM' }), false],
    ['36', 'MUST', 'refuses a presentation signed with another key under the STACK key\'s kid', (to) => seal(presentationPayload(now), to, { signer: keys.impostor }), false],
    ['37', 'MUST', 'refuses a presentation whose kid is not a STACK key the receiver trusts', (to) => seal(presentationPayload(now), to, { headerOver: { kid: 'stack-unknown-key' } }), false],
    ['38', 'MUST', 'refuses an unsecured presentation (alg none)', (to) => encryptPresentation(unsecured(presentationPayload(now)), to), false],
    ['39', 'MUST', 'refuses a presentation MACed with the public key as secret (alg HS256)', (to) => encryptPresentation(hs256Forgery(presentationPayload(now)), to), false],
    ['40', 'MUST', 'refuses a presentation from another issuer (iss)', (to) => seal(presentationPayload(now, { iss: 'https://not-stack.example' }), to), false],
    ['41', 'MUST', 'refuses a presentation for another audience (aud)', (to) => seal(presentationPayload(now, { aud: 'urn:someone:else' }), to), false],
    ['42', 'MUST', 'refuses a presentation that has expired', (to) => seal(presentationPayload(now, { iat: now - 200, exp: now - 100 }), to), false],
    ['43', 'MUST', 'refuses a presentation issued in the future', (to) => seal(presentationPayload(now, { iat: now + 300, exp: now + 360 }), to), false],
    ['44', 'MUST', 'refuses a presentation that lives more than 120 seconds', (to) => seal(presentationPayload(now, { iat: now, exp: now + 600 }), to), false],
    ['45', 'MUST', 'refuses a presentation for another receiver (receiver_id)', (to) => seal(presentationPayload(now, { receiver_id: 'rcv_someone_else' }), to), false],
    ['46', 'MUST', 'refuses a presentation that answers another nonce', (to) => seal(presentationPayload(now, { nonce: 'a-nonce-the-receiver-never-sent-0001' }), to), false],
    ['47', 'MUST', 'refuses a presentation for another transaction (request_hash)', (to) => seal(presentationPayload(now, { request_hash: requestHashOf('another-request-id-000000001', NORMALIZED_REQUEST) }), to), false],
  ];

  /** Hand one presentation to the receiver; a function that is not async is read the same. */
  const open = (message) => Promise.resolve().then(() => receiver.openPresentation(message, { now, expected }));

  if (receiver) {
    for (const [suffix, level, title, build, accepts] of variants) {
      checks.push({
        id: `A${suffix}`, level, title,
        async run() {
          const message = build(keys.encryption);
          let outcome;
          try {
            outcome = await open(message);
          } catch {
            outcome = null;
          }
          const opened = outcome !== null && outcome !== undefined && outcome !== false;
          assert(opened === accepts, accepts ? 'a correct presentation was refused' : 'a presentation with one thing wrong was accepted');
          if (accepts) {
            const claims = outcome.payload ?? outcome;
            assert(claims && claims.jti && claims.nonce === FIXTURE.nonce, 'the opened claims are not the presentation\'s');
          }
        },
      });
    }
    checks.push({
      id: 'A48', level: 'SHOULD', title: 'refuses the same presentation a second time (its jti was already seen)',
      async run() {
        const message = seal(presentationPayload(now), keys.encryption);
        const first = await open(message).catch(() => null);
        assert(first, 'a correct presentation was refused');
        const second = await open(message).catch(() => null);
        assert(!second, 'the same presentation was accepted twice');
      },
    });
  }

  // ─── The origin verification document (section 3.3) ───────────────
  checks.push({
    id: 'A50', level: 'MUST', title: 'the origin document names the origin, the key, and a signed challenge for the STACK origin',
    async run() {
      const early = need('the origin document');
      if (early) return early;
      const challenge = { challengeId: 'rvc_conformance', challenge: b64u('conformance challenge value 0123456789') };
      const doc = await receiver.verificationDocument({ ...challenge, now });
      assert(doc && typeof doc === 'object', 'the document is not an object');
      assert(typeof doc.origin === 'string' && doc.origin.startsWith('https://'), 'origin must be an HTTPS origin');
      assert(doc.key_id === requestKey.kid, `key_id is ${JSON.stringify(doc.key_id)}, expected ${requestKey.kid}`);
      const decoded = decodeJws(doc.signed_challenge);
      assert(decoded, 'signed_challenge is not a compact JWS');
      assert(decoded.header.kid === doc.key_id, 'the kid of signed_challenge is not key_id');
      assert(decoded.header.alg === requestKey.alg && verifyJwsSignature(decoded, requestKey.publicJwk, requestKey.alg), 'signed_challenge does not verify with the request key');
      assert(decoded.payload.iss === FIXTURE.receiverId && decoded.payload.sub === FIXTURE.receiverId, 'iss and sub must be the receiver identifier');
      assert(decoded.payload.aud === FIXTURE.stackOrigin, `aud is ${JSON.stringify(decoded.payload.aud)}, expected the STACK origin ${FIXTURE.stackOrigin} with no path`);
      assert(decoded.payload.challenge_id === challenge.challengeId && decoded.payload.challenge === challenge.challenge, 'the challenge was not echoed exactly');
      assert(Number.isInteger(decoded.payload.exp) && decoded.payload.exp > now, 'exp is missing or past');
    },
  });

  // ─── The delivery endpoint (section 7.1) ──────────────────────────
  if (deliveryUrl) {
    const recipient = { kid: options.deliveryKey.kid, publicJwk: options.deliveryKey.publicJwk };
    const accepted = async (compact, { form = true, field = 'response' } = {}) => {
      const body = form ? new URLSearchParams({ [field]: compact }).toString() : JSON.stringify({ [field]: compact });
      const r = await post(deliveryUrl, {
        headers: { accept: 'application/json', 'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json', 'idempotency-key': randomId('prs') },
        body, timeoutMs, fetchImpl,
      });
      return r.status >= 200 && r.status < 300;
    };
    for (const [suffix, level, title, build, accepts] of variants) {
      checks.push({
        id: `U${suffix}`, level, title: `endpoint: ${title}`,
        async run() {
          const ok = await accepted(build(recipient));
          assert(ok === accepts, accepts ? 'the endpoint refused a correct presentation (is it configured as section 15.2 says?)' : 'the endpoint answered 2xx to a presentation with one thing wrong');
        },
      });
    }
    checks.push(
      {
        id: 'U60', level: 'MUST', title: 'endpoint: refuses a request with no response field',
        async run() {
          const r = await post(deliveryUrl, { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'other=1', timeoutMs, fetchImpl });
          assert(r.status < 200 || r.status >= 300, 'a request with no response field was accepted');
        },
      },
      {
        id: 'U61', level: 'MUST', title: 'endpoint: refuses a response that is not a compact JWE',
        async run() {
          assert(!(await accepted('not.a.jwe')), 'garbage was accepted');
          assert(!(await accepted(signPresentation(presentationPayload(now)))), 'an unencrypted (signed only) presentation was accepted');
        },
      },
    );
  }

  return runChecks('authority receiver', checks);
}
