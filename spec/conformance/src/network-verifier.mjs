// Conformance suite for a VERIFIER of the STACK network's signed objects and for
// an INSTALL CLIENT's signer (spec/network/SPEC.md, sections 4, 5.3, 6, 8, 9, 10
// and 12). The kit mints objects with keys of its own (the public test keys of
// the specification's vectors), hands your verifier the matching JWKS and a clock,
// and checks that it accepts what it must and refuses what it must, including
// every kind of object presented as another and the classic attacks on JWS
// verification.
//
// A verifier is an async function
//
//   verify(kind, token, { jwks, now, passport?, heldRevision? }) -> anything
//
// that resolves when it accepts the token and rejects (throws) when it does not.
// `kind` is `countersignature`, `revocation_list`, `verified` or `detection_rules`;
// `now` is the clock in unix seconds the verifier must use in place of its own;
// for a countersignature `passport` is the passport it covers (check the digest
// and the passport's own signature with the key the countersignature carries);
// for a rule set `heldRevision` is the highest revision the caller already runs.
//
// A verifier that also reads revocation lists is asked, optionally, to match one to a
// countersigned passport it holds (section 10.4: on the subject AND the install):
//
//   revoked(listToken, { install, keyId, passportDigest, agent }, { jwks, now }) -> boolean
//
// It verifies the signed list and answers whether it covers that countersignature. It may
// resolve false or reject for a list it does not accept; it must never resolve true for an
// entry of another install, or for an entry that names no install.
//
// An install client's signer is optional:
//
//   signer.keyProof({ installId, nonce, privateKeyPem, now }) -> compact JWS
//   signer.proof({ installId, claims, privateKeyPem, now })   -> compact JWS   (claims carry `act` and its fields)
//
// A program in another language is wrapped with `commandNetworkImplementation`:
// it reads one JSON object on stdin and writes one on stdout (see the README).

import { createHmac, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { spawn } from 'node:child_process';
import { assert, fail, runChecks } from './harness.mjs';
import { signJwt } from './passport-verifier.mjs';
import {
  buildNetworkVectors,
  countersignatureBody,
  detectionRulesBody,
  installKeyThumbprint,
  NETWORK_AUDIENCE,
  NETWORK_INSTALL_POP_TYP,
  NETWORK_INSTALL_PROOF_TYP,
  NETWORK_KINDS,
  passportDigest,
  revocationListBody,
  signNetworkObject,
  signPassport,
  VECTOR_INSTALL_ID,
  VECTOR_NOW,
  vectorKeys,
  verifiedBody,
} from './network-vectors.mjs';

const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const KINDS = Object.keys(NETWORK_KINDS);

/** @param {{ verify: (kind: string, token: string, ctx: object) => Promise<unknown>, revoked?: (token: string, held: object, ctx: object) => Promise<boolean> | boolean, signer?: { keyProof: Function, proof: Function } }} options */
export async function runNetworkVerifierSuite(options) {
  const { verify, signer, revoked } = options;
  const keys = vectorKeys();
  const now = VECTOR_NOW + 10;
  const passport = signPassport();
  const digest = passportDigest(passport);
  const decoy = { ...keys.other.publicJwk, kid: 'decoy-key', x: keys.stranger.publicJwk.x };
  const jwks = { keys: [decoy, keys.stack.publicJwk] };

  /** What each kind is minted with, so any of them can be altered one way at a time. */
  const bodies = {
    countersignature: (over) => countersignatureBody(digest, over),
    revocation_list: (over) => revocationListBody(over),
    verified: (over) => verifiedBody(digest, over),
    detection_rules: (over) => detectionRulesBody(over),
  };
  const lifetimes = { countersignature: 900, revocation_list: 300, verified: 300, detection_rules: 72 * 3600 };
  const subjects = {
    countersignature: { subject: VECTOR_INSTALL_ID, jti: 'csg_vector000000000000' },
    verified: { subject: `passport:${digest}` },
  };
  /** A token of `kind` as STACK signs it, with the given alterations. `inner` changes the claim object (cs, rl, vs, rs); `outer` the claims beside it. */
  const mint = (kind, { inner = {}, outer = {}, ...signOptions } = {}) =>
    signNetworkObject(kind, { ...bodies[kind](inner), ...outer }, { ttl: lifetimes[kind], ...subjects[kind], ...signOptions });
  const ctxFor = (kind, over = {}) => ({ jwks, now, ...(kind === 'countersignature' ? { passport } : {}), ...over });

  const accepts = async (kind, token, why, over = {}) => {
    try {
      await verify(kind, token, ctxFor(kind, over));
    } catch (error) {
      fail(`${why} was rejected: ${error instanceof Error ? error.message : String(error)}`);
    }
  };
  const rejects = async (kind, token, why, over = {}) => {
    try {
      await verify(kind, token, ctxFor(kind, over));
    } catch {
      return;
    }
    fail(`${why} was accepted`);
  };
  const eachKind = async (body) => {
    for (const kind of KINDS) await body(kind);
  };
  const payloadOf = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  const headerOf = (token) => JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
  const resign = (kind, token, edit, header) => {
    const payload = payloadOf(token);
    edit(payload);
    return signJwt(header ?? headerOf(token), payload, keys.stack);
  };
  const vectors = buildNetworkVectors();
  const joined = (parts) => parts.join('.');
  const byName = { countersignature: vectors.countersignature, verified: vectors.verified_statement, revocation_list: vectors.revocation_list, detection_rules: vectors.detection_rules };

  const checks = [
    {
      id: 'N01', level: 'MUST', title: 'accepts a countersigned passport',
      async run() {
        await accepts('countersignature', mint('countersignature'), 'a valid countersignature with its passport');
      },
    },
    {
      id: 'N02', level: 'MUST', title: 'accepts each of the other three kinds of object STACK signs',
      async run() {
        await accepts('revocation_list', mint('revocation_list'), 'a valid revocation list');
        await accepts('verified', mint('verified'), 'a valid statement');
        await accepts('detection_rules', mint('detection_rules'), 'a valid rule set');
      },
    },
    {
      id: 'N03', level: 'MUST', title: 'selects the key by kid from a JWKS with several keys',
      async run() {
        await accepts('countersignature', mint('countersignature'), 'a token signed by the second key of the JWKS', { jwks: { keys: [decoy, keys.stack.publicJwk] } });
        await accepts('revocation_list', mint('revocation_list'), 'a list signed by the first key of the JWKS', { jwks: { keys: [keys.stack.publicJwk, decoy] } });
      },
    },
    {
      id: 'N04', level: 'MUST', title: 'ignores claims it does not know, at the top level and inside the claim set',
      async run() {
        await eachKind(async (kind) => {
          const inner = { future_member: { a: 1 } };
          await accepts(kind, mint(kind, { inner, outer: { future_claim: 'x' } }), `a ${kind} with extra claims`);
        });
      },
    },
    {
      id: 'N05', level: 'MUST', title: 'accepts a list with no entries, and a rule set at the revision it already holds',
      async run() {
        await accepts('revocation_list', mint('revocation_list', { inner: { entries: [], head: 0, next: null } }), 'an empty revocation list');
        await accepts('detection_rules', mint('detection_rules'), 'a rule set at the held revision', { heldRevision: 1 });
        await accepts('detection_rules', mint('detection_rules', { inner: { revision: 3, version: 'r3-vector000000' } }), 'a rule set newer than the held revision', { heldRevision: 2 });
      },
    },
    {
      id: 'N06', level: 'MUST', title: 'accepts every positive vector of spec/network/test-vectors.json',
      async run() {
        const ctx = { jwks: vectors.stack.jwks, now: vectors.now + 10 };
        for (const kind of KINDS) await accepts(kind, joined(byName[kind]), `the ${kind} vector`, { ...ctx, ...(kind === 'countersignature' ? { passport: joined(vectors.passport.parts) } : {}) });
      },
    },
    {
      id: 'N10', level: 'MUST', title: 'rejects every kind of object presented as another kind',
      async run() {
        for (const { token_of: held, presented_as: wanted } of vectors.negative.cross_kind) {
          await rejects(wanted, joined(byName[held === 'verified_statement' ? 'verified' : held]), `a ${held} presented as a ${wanted}`);
        }
      },
    },
    {
      id: 'N11', level: 'MUST', title: 'rejects a token with the typ of another kind, or with no typ',
      async run() {
        await eachKind(async (kind) => {
          const other = KINDS.find((k) => k !== kind);
          await rejects(kind, mint(kind, { typ: NETWORK_KINDS[other].typ }), `a ${kind} under the typ of a ${other}`);
          await rejects(kind, mint(kind, { header: { alg: 'EdDSA', kid: keys.stack.kid } }), `a ${kind} with no typ`);
        });
      },
    },
    {
      id: 'N12', level: 'MUST', title: 'rejects a token for another audience, and a passport (audience stack:passport)',
      async run() {
        await eachKind(async (kind) => {
          await rejects(kind, mint(kind, { aud: 'stack:passport' }), `a ${kind} with the audience of a passport`);
          await rejects(kind, mint(kind, { aud: 'stack:network' }), `a ${kind} with the audience of an install proof`);
          await rejects(kind, resign(kind, mint(kind), (p) => delete p.aud), `a ${kind} with no audience`);
        });
      },
    },
    {
      id: 'N13', level: 'MUST', title: 'rejects a token from another issuer, or with none',
      async run() {
        await eachKind(async (kind) => {
          await rejects(kind, resign(kind, mint(kind), (p) => { p.iss = 'attacker.example'; }), `a ${kind} from another issuer`);
          await rejects(kind, resign(kind, mint(kind), (p) => delete p.iss), `a ${kind} with no issuer`);
        });
      },
    },
    {
      id: 'N14', level: 'MUST', title: 'rejects alg none',
      async run() {
        await eachKind(async (kind) => {
          const token = mint(kind);
          const header = { ...headerOf(token), alg: 'none' };
          await rejects(kind, `${b64(header)}.${token.split('.')[1]}.`, `an unsigned ${kind} (alg none)`);
          await rejects(kind, `${b64(header)}.${token.split('.')[1]}.${b64('x')}`, `an alg none ${kind} with a signature`);
        });
      },
    },
    {
      id: 'N15', level: 'MUST', title: 'rejects an HMAC token keyed with the public key (algorithm confusion)',
      async run() {
        await eachKind(async (kind) => {
          const token = mint(kind);
          const signingInput = `${b64({ ...headerOf(token), alg: 'HS256' })}.${token.split('.')[1]}`;
          for (const secret of [Buffer.from(keys.stack.publicJwk.x, 'base64url'), Buffer.from(JSON.stringify(keys.stack.publicJwk))]) {
            await rejects(kind, `${signingInput}.${createHmac('sha256', secret).update(signingInput).digest('base64url')}`, `an HS256 ${kind} keyed with the public key`);
          }
        });
      },
    },
    {
      id: 'N16', level: 'MUST', title: 'rejects a token whose payload was changed after signing',
      async run() {
        await eachKind(async (kind) => {
          const [h, p, s] = mint(kind).split('.');
          const changed = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
          changed.exp += 3600;
          await rejects(kind, `${h}.${b64(changed)}.${s}`, `a ${kind} with a longer life written into it`);
        });
      },
    },
    {
      id: 'N17', level: 'MUST', title: 'rejects a token signed by another key under a known kid, and one with an unknown kid or none',
      async run() {
        await eachKind(async (kind) => {
          await rejects(kind, mint(kind, { key: keys.other }), `a ${kind} signed by a key that is not in the JWKS, under the kid that is`);
          await rejects(kind, mint(kind, { header: { alg: 'EdDSA', kid: 'not-in-the-set', typ: NETWORK_KINDS[kind].typ } }), `a ${kind} with an unknown kid`);
          await rejects(kind, mint(kind, { header: { alg: 'EdDSA', typ: NETWORK_KINDS[kind].typ } }), `a ${kind} naming no key`);
        });
      },
    },
    {
      id: 'N18', level: 'MUST', title: 'rejects an expired token',
      async run() {
        await eachKind(async (kind) => {
          await rejects(kind, mint(kind), `a ${kind} an hour after it expired`, { now: VECTOR_NOW + lifetimes[kind] + 3600 });
        });
      },
    },
    {
      id: 'N19', level: 'MUST', title: 'rejects a token that is not a well-formed compact JWS',
      async run() {
        const good = mint('revocation_list');
        for (const [why, value] of [
          ['an empty string', ''],
          ['a token with two parts', good.split('.').slice(0, 2).join('.')],
          ['a token with four parts', `${good}.x`],
          ['a token with a truncated signature', good.slice(0, -12)],
          ['a token with a garbage signature', `${good.split('.').slice(0, 2).join('.')}.${b64('not a signature')}`],
          ['text that is not a token', 'hello world'],
        ]) {
          await rejects('revocation_list', value, why);
        }
      },
    },
    {
      id: 'N20', level: 'MUST', title: 'rejects a claim set whose version it does not know',
      async run() {
        await eachKind(async (kind) => {
          await rejects(kind, mint(kind, { inner: { v: 2 } }), `a ${kind} whose claim set is version 2`);
        });
      },
    },
    {
      id: 'N30', level: 'MUST', title: 'rejects a countersignature for a passport that does not hash to its digest',
      async run() {
        await rejects('countersignature', mint('countersignature'), 'a countersignature with another passport', { passport: signPassport({ jti: 'pas_vector00000000000002' }) });
      },
    },
    {
      id: 'N31', level: 'MUST', title: 'rejects a passport the countersigned install key did not sign',
      async run() {
        const stranger = signPassport({ key: keys.stranger, jti: 'pas_vector00000000000001' });
        const token = mint('countersignature', { inner: { passport: { alg: 'sha256', digest: passportDigest(stranger), jti: 'pas_vector00000000000001', agent: 'support-bot' } } });
        await rejects('countersignature', token, 'a passport signed by another key', { passport: stranger });
      },
    },
    {
      id: 'N32', level: 'MUST', title: 'rejects an expired passport while its countersignature is still good',
      async run() {
        const short = signPassport({ ttl: 100, jti: 'pas_vector00000000000003' });
        const token = mint('countersignature', { inner: { passport: { alg: 'sha256', digest: passportDigest(short), jti: 'pas_vector00000000000003', agent: 'support-bot' } } });
        await accepts('countersignature', token, 'the short-lived passport while it is live', { passport: short, now: VECTOR_NOW + 50 });
        await rejects('countersignature', token, 'the short-lived passport after it expired', { passport: short, now: VECTOR_NOW + 200 });
      },
    },
    {
      id: 'N33', level: 'MUST', title: 'rejects a countersignature whose key id is not the thumbprint of its key',
      async run() {
        await rejects('countersignature', mint('countersignature', { inner: { key: { kid: 'A'.repeat(43), jwk: keys.install.public_jwk } } }), 'a countersignature naming the wrong key id');
        await rejects('countersignature', mint('countersignature', { inner: { key: { kid: installKeyThumbprint(keys.stranger.publicJwk), jwk: { kty: 'OKP', crv: 'Ed25519', x: keys.stranger.publicJwk.x } } } }), 'a countersignature whose key is not the one that signed the passport');
      },
    },
    {
      id: 'N34', level: 'MUST', title: 'rejects a countersignature with a digest algorithm other than sha256, or a key that is not Ed25519',
      async run() {
        await rejects('countersignature', mint('countersignature', { inner: { passport: { alg: 'md5', digest, jti: 'pas_vector00000000000000', agent: 'support-bot' } } }), 'a countersignature with digest algorithm md5');
        await rejects('countersignature', mint('countersignature', { inner: { key: { kid: keys.install.kid, jwk: { kty: 'OKP', crv: 'Ed448', x: keys.install.public_jwk.x } } } }), 'a countersignature with an Ed448 key');
      },
    },
    {
      id: 'N36', level: 'MUST', title: 'rejects a rule set older than the revision already held',
      async run() {
        await rejects('detection_rules', mint('detection_rules'), 'revision 1 when revision 2 is held', { heldRevision: 2 });
      },
    },
    {
      id: 'N40', level: 'MUST', title: 'refuses every negative vector of spec/network/test-vectors.json that is a STACK-signed object',
      async run() {
        const ctx = { jwks: vectors.stack.jwks, now: vectors.now + 10 };
        for (const c of vectors.negative.cases) {
          if (c.kind === 'install_proof') continue;
          const token = c.token ? joined(c.token) : joined(c.token_of === 'countersignature' ? vectors.countersignature : byName[c.kind]);
          const over = { ...ctx, ...(c.at ? { now: c.at } : {}), ...(c.held_revision ? { heldRevision: c.held_revision } : {}) };
          if (c.kind === 'countersignature') over.passport = c.passport ? joined(c.passport) : joined(vectors.passport.parts);
          await rejects(c.kind, token, `the vector "${c.id}" (${c.description})`, over);
        }
      },
    },
  ];

  // ─── matching a revocation list to a countersigned passport (section 10.4) ───
  const RIVAL = 'ins_vector_rival0000000';
  const at = new Date(VECTOR_NOW * 1000).toISOString();
  const entry = (n, kind, subject, install, reason = 'owner_request') => ({ seq: n, id: `rev_vector000000000000${n}${n}`, kind, subject, install, reason, by: 'owner', at });
  const heldOf = (install = VECTOR_INSTALL_ID) => ({ install, keyId: keys.install.kid, passportDigest: digest, agent: 'support-bot' });
  const listWith = (...entries) => mint('revocation_list', { inner: { entries, head: entries.length, next: null } });
  /** True when the implementation says this list covers the held countersignature. A refusal of the list counts as "does not cover". */
  const covers = async (list, held, over = {}) => {
    try {
      return (await revoked(list, held, { jwks, now, ...over })) === true;
    } catch {
      return false;
    }
  };
  const skipNoMatcher = () => (revoked ? undefined : { skip: 'no revoked function was given' });
  checks.push(
    {
      id: 'N60', level: 'MUST', title: 'matches a revocation entry to a countersigned passport on the subject and the install',
      async run() {
        const skipped = skipNoMatcher();
        if (skipped) return skipped;
        const held = heldOf();
        for (const [why, e] of [
          ['passport', entry(1, 'passport', digest, VECTOR_INSTALL_ID)],
          ['agent', entry(2, 'agent', 'support-bot', VECTOR_INSTALL_ID)],
          ['key', entry(3, 'key', keys.install.kid, VECTOR_INSTALL_ID)],
          ['install', entry(4, 'install', VECTOR_INSTALL_ID, VECTOR_INSTALL_ID)],
        ]) {
          assert(await covers(listWith(e), held), `a ${why} entry of the countersignature's own install did not cover it`);
        }
        assert(!(await covers(listWith(entry(1, 'agent', 'someone-else', VECTOR_INSTALL_ID)), held)), 'an entry for another agent of the same install covered the countersignature');
      },
    },
    {
      id: 'N61', level: 'MUST', title: 'ignores an entry of another install, however well the subject matches',
      async run() {
        const skipped = skipNoMatcher();
        if (skipped) return skipped;
        const held = heldOf();
        for (const [why, e] of [
          ['passport digest', entry(1, 'passport', digest, RIVAL)],
          ['agent name', entry(2, 'agent', 'support-bot', RIVAL)],
          ['key id', entry(3, 'key', keys.install.kid, RIVAL)],
        ]) {
          assert(!(await covers(listWith(e), held)), `an entry of another install with the same ${why} covered the countersignature: a verifier that matches on the subject alone lets one company have another's agent refused`);
        }
        assert(!(await covers(listWith(entry(1, 'install', RIVAL, RIVAL)), held)), 'a revocation of another install covered the countersignature');
        assert(await covers(listWith(entry(1, 'passport', digest, RIVAL), entry(2, 'passport', digest, VECTOR_INSTALL_ID)), held), 'the matching entry was not found behind an entry of another install');
        assert(!(await covers(listWith(entry(1, 'agent', 'support-bot', VECTOR_INSTALL_ID)), heldOf(RIVAL))), 'an entry covered a countersignature of another install');
      },
    },
    {
      id: 'N62', level: 'MUST', title: 'ignores an entry that names no install',
      async run() {
        const skipped = skipNoMatcher();
        if (skipped) return skipped;
        const held = heldOf();
        for (const e of [entry(1, 'passport', digest, null), entry(2, 'agent', 'support-bot', null), entry(3, 'key', keys.install.kid, null)]) {
          assert(!(await covers(listWith(e), held)), `an entry of kind ${e.kind} with no install covered the countersignature`);
        }
      },
    },
    {
      id: 'N63', level: 'MUST', title: 'matches the kind of an entry as well as its subject',
      async run() {
        const skipped = skipNoMatcher();
        if (skipped) return skipped;
        assert(!(await covers(listWith(entry(1, 'agent', digest, VECTOR_INSTALL_ID)), heldOf())), 'an agent entry whose subject is the passport digest covered the countersignature');
        assert(!(await covers(listWith(entry(1, 'passport', 'support-bot', VECTOR_INSTALL_ID)), heldOf())), 'a passport entry whose subject is the agent name covered the countersignature');
      },
    },
    {
      id: 'N64', level: 'MUST', title: 'does not act on a list that has expired or is not signed by STACK',
      async run() {
        const skipped = skipNoMatcher();
        if (skipped) return skipped;
        const list = listWith(entry(1, 'passport', digest, VECTOR_INSTALL_ID));
        assert(!(await covers(list, heldOf(), { now: VECTOR_NOW + 300 + 3600 })), 'an expired list was acted on');
        const forged = mint('revocation_list', { key: keys.other, inner: { entries: [entry(1, 'passport', digest, VECTOR_INSTALL_ID)], head: 1, next: null } });
        assert(!(await covers(forged, heldOf())), 'a list signed by another key was acted on');
      },
    },
  );

  if (!signer) {
    checks.push({ id: 'N50', level: 'MUST', title: 'signs a key proof and an install proof as sections 5.3 and 6.2 say', async run() { return { skip: 'no signer was given' }; } });
  } else {
    const pem = keys.install.key.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicKey = createPublicKey({ key: keys.install.public_jwk, format: 'jwk' });
    const parse = (token) => {
      const [h, p, s] = token.split('.');
      assert(h && p && s && token.split('.').length === 3, 'a signed request is three dot-separated parts');
      return { header: JSON.parse(Buffer.from(h, 'base64url').toString('utf8')), payload: JSON.parse(Buffer.from(p, 'base64url').toString('utf8')), valid: cryptoVerify(null, Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, 'base64url')) };
    };
    const actions = {
      rules: { act: 'rules' },
      classify: { act: 'classify' },
      countersign: { act: 'countersign', pd: digest, pjti: 'pas_vector00000000000000', agent: 'support-bot', ttl: 900 },
      revoke: { act: 'revoke', kind: 'agent', subject: 'support-bot', reason: 'agent_decommissioned' },
    };
    const proofFor = (claims) => signer.proof({ installId: VECTOR_INSTALL_ID, claims, privateKeyPem: pem, now: new Date(VECTOR_NOW * 1000) });
    checks.push(
      {
        id: 'N50', level: 'MUST', title: 'signs a key proof of possession as section 5.3 says',
        async run() {
          const nonce = 'k'.repeat(32);
          const token = await signer.keyProof({ installId: VECTOR_INSTALL_ID, nonce, privateKeyPem: pem, now: new Date(VECTOR_NOW * 1000) });
          const { header, payload, valid } = parse(token);
          assert(valid, 'the key proof does not verify with the public key');
          assert(header.alg === 'EdDSA' && header.typ === NETWORK_INSTALL_POP_TYP, `the key proof header is ${JSON.stringify(header)}`);
          assert(header.kid === keys.install.kid && payload.iss === keys.install.kid, 'the key proof must name the key by its thumbprint, in the header kid and in iss');
          assert(payload.aud === NETWORK_AUDIENCE && payload.install === VECTOR_INSTALL_ID && payload.nonce === nonce, 'the key proof must carry aud stack:network, the install id and the nonce');
          assert(Number.isInteger(payload.iat) && payload.exp - payload.iat > 0 && payload.exp - payload.iat <= 300, 'the key proof must expire within 300 seconds of iat');
          assert(Object.keys(payload).sort().join() === 'aud,exp,iat,install,iss,nonce', `the key proof must carry no other claim: ${Object.keys(payload).join(', ')}`);
        },
      },
      {
        id: 'N51', level: 'MUST', title: 'signs an install proof for each action as section 6.2 says',
        async run() {
          for (const [name, claims] of Object.entries(actions)) {
            const { header, payload, valid } = parse(await proofFor(claims));
            assert(valid, `the ${name} proof does not verify with the public key`);
            assert(header.alg === 'EdDSA' && header.typ === NETWORK_INSTALL_PROOF_TYP && header.kid === keys.install.kid, `the ${name} proof header is ${JSON.stringify(header)}`);
            assert(payload.iss === VECTOR_INSTALL_ID && payload.sub === VECTOR_INSTALL_ID && payload.aud === NETWORK_AUDIENCE, `the ${name} proof must carry iss and sub (the install id) and aud stack:network`);
            assert(Number.isInteger(payload.iat) && Number.isInteger(payload.exp) && payload.exp > payload.iat && payload.exp - payload.iat <= 120, `the ${name} proof must expire within 120 seconds of iat`);
            assert(typeof payload.jti === 'string' && /^[A-Za-z0-9_-]{16,64}$/.test(payload.jti), `the ${name} proof jti must be 16 to 64 characters of [A-Za-z0-9_-]`);
            for (const [k, v] of Object.entries(claims)) assert(JSON.stringify(payload[k]) === JSON.stringify(v), `the ${name} proof lost the claim ${k}`);
            const allowed = new Set(['iss', 'sub', 'aud', 'iat', 'exp', 'jti', ...Object.keys(claims)]);
            const extra = Object.keys(payload).filter((k) => !allowed.has(k));
            assert(extra.length === 0, `the ${name} proof carries claims it must not: ${extra.join(', ')}`);
          }
        },
      },
      {
        id: 'N52', level: 'MUST', title: 'gives every install proof a fresh jti',
        async run() {
          const seen = new Set();
          for (let i = 0; i < 5; i += 1) seen.add(parse(await proofFor(actions.rules)).payload.jti);
          assert(seen.size === 5, 'five proofs for the same request shared a jti: a proof is good for exactly one request');
        },
      },
    );
  }

  return runChecks('network verifier (offline) and install signer', checks);
}

/**
 * Wrap a program as a network implementation. For each call it reads one JSON
 * object on stdin and writes one on stdout:
 *   { "op": "verify", "kind", "token", "jwks", "now", "passport"?, "held_revision"? } -> { "valid": boolean }
 *   { "op": "revoked", "token", "held": { "install", "key_id", "passport_digest", "agent" }, "jwks", "now" } -> { "revoked": boolean }
 *   { "op": "key_proof", "install_id", "nonce", "private_key_pem", "now" }             -> { "token": "<compact JWS>" }
 *   { "op": "proof", "install_id", "claims", "private_key_pem", "now" }                -> { "token": "<compact JWS>" }
 * `now` is unix seconds. A program that cannot sign answers `{ "unsupported": true }` to the last two and the signer checks are skipped.
 */
export function commandNetworkImplementation(command, args = [], { signs = true, matches = true } = {}) {
  const call = (message) =>
    new Promise((resolve, reject) => {
      const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], shell: false });
      let out = '';
      let err = '';
      child.stdout.on('data', (chunk) => { out += chunk; });
      child.stderr.on('data', (chunk) => { err += chunk; });
      child.on('error', reject);
      child.on('close', () => {
        try {
          resolve(JSON.parse(out));
        } catch {
          reject(new Error(`the program printed no JSON answer${err ? `: ${err.trim().slice(0, 200)}` : ''}`));
        }
      });
      child.stdin.end(JSON.stringify(message));
    });
  return {
    verify: async (kind, token, ctx) => {
      const answer = await call({ op: 'verify', kind, token, jwks: ctx.jwks, now: ctx.now, ...(ctx.passport ? { passport: ctx.passport } : {}), ...(ctx.heldRevision !== undefined ? { held_revision: ctx.heldRevision } : {}) });
      if (answer.valid !== true) throw new Error('rejected');
      return answer;
    },
    ...(matches
      ? {
          revoked: async (token, held, ctx) => {
            const answer = await call({ op: 'revoked', token, jwks: ctx.jwks, now: ctx.now, held: { install: held.install, key_id: held.keyId, passport_digest: held.passportDigest, agent: held.agent } });
            if (typeof answer.revoked !== 'boolean') throw new Error('rejected');
            return answer.revoked;
          },
        }
      : {}),
    ...(signs
      ? {
          signer: {
            keyProof: async ({ installId, nonce, privateKeyPem, now }) => (await call({ op: 'key_proof', install_id: installId, nonce, private_key_pem: privateKeyPem, now: Math.floor(now.getTime() / 1000) })).token,
            proof: async ({ installId, claims, privateKeyPem, now }) => (await call({ op: 'proof', install_id: installId, claims, private_key_pem: privateKeyPem, now: Math.floor(now.getTime() / 1000) })).token,
          },
        }
      : {}),
  };
}

