// The test vectors of the STACK network specification (spec/network/SPEC.md,
// section 14), produced from the specification alone: Node's crypto and nothing
// else, fixed public test keys and a fixed clock. Ed25519 signatures are
// deterministic, so running this twice (on any machine) gives the same bytes.
//
//   node spec/conformance/scripts/build-network-vectors.mjs           write spec/network/test-vectors.json
//   node spec/conformance/scripts/build-network-vectors.mjs --check   fail when the file differs
//
// The keys are public and are for these vectors only: the STACK key is the
// Ed25519 key whose 32-byte seed is 0x01 repeated; the install key's seed is 0x02
// repeated (`private_seed_hex` in the file); the "other key" of the negative
// vectors is 0x03 repeated and the passport signer of the wrong-key vector is 0x04.
// Nothing here is, or has ever been, a key of a real deployment.

import { createHash } from 'node:crypto';
import { keyFromSeed, signJwt } from './passport-verifier.mjs';

export const VECTOR_NOW = 1_790_000_000;
export const VECTOR_INSTALL_ID = 'ins_vector0000000000000';
export const VECTOR_STACK_KID = 'stack-passport-v1';
const OWNER = 'op_vector000000000000';

/** typ and aud of every signed object of the network, by kind (section 4 of the specification). */
export const NETWORK_KINDS = {
  countersignature: { typ: 'stack-countersignature+jwt', aud: 'stack:countersignature' },
  revocation_list: { typ: 'stack-revocation-list+jwt', aud: 'stack:revocation-list' },
  verified: { typ: 'stack-verified+jwt', aud: 'stack:verified' },
  detection_rules: { typ: 'stack-detection-rules+jwt', aud: 'stack:detection-rules' },
};
export const NETWORK_INSTALL_PROOF_TYP = 'stack-install+jwt';
export const NETWORK_INSTALL_POP_TYP = 'stack-install-pop+jwt';
export const NETWORK_AUDIENCE = 'stack:network';
export const ISSUER = 'getstack.run';

/** RFC 7638 thumbprint of an Ed25519 public JWK. */
export function installKeyThumbprint(jwk) {
  return createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`).digest('base64url');
}

/** base64url SHA-256 of a passport's compact serialisation, as issued. */
export function passportDigest(passport) {
  return createHash('sha256').update(passport, 'utf8').digest('base64url');
}

/** The key material of the vectors, by role. */
export function vectorKeys() {
  const stack = keyFromSeed(1, VECTOR_STACK_KID);
  const installKey = keyFromSeed(2);
  const installPublic = { kty: 'OKP', crv: 'Ed25519', x: installKey.publicJwk.x };
  const kid = installKeyThumbprint(installPublic);
  const other = keyFromSeed(3, VECTOR_STACK_KID);
  const stranger = keyFromSeed(4);
  return { stack, install: { key: installKey, public_jwk: installPublic, kid }, other, stranger };
}

const iso = (seconds) => new Date(seconds * 1000).toISOString();

/**
 * A signed object of the network as STACK signs it. `claims` is the object under
 * the kind's claim (`cs`, `rl`, `vs`, `rs`); `over` replaces registered members.
 */
export function signNetworkObject(kind, body, { key, now = VECTOR_NOW, ttl, subject, jti, header, aud, typ } = {}) {
  const k = NETWORK_KINDS[kind];
  const signer = key ?? vectorKeys().stack;
  const payload = {
    ...body,
    iss: ISSUER,
    aud: aud ?? k.aud,
    iat: now,
    exp: now + ttl,
    ...(subject !== undefined ? { sub: subject } : {}),
    ...(jti !== undefined ? { jti } : {}),
  };
  return signJwt(header ?? { alg: 'EdDSA', kid: signer.kid, typ: typ ?? k.typ }, payload, signer);
}

/** A request an install signs: `claims` carries `act` and what the action needs. */
export function signInstallProof(claims, { key, kid, installId = VECTOR_INSTALL_ID, now = VECTOR_NOW, lifetime = 60, jti, typ = NETWORK_INSTALL_PROOF_TYP, aud = NETWORK_AUDIENCE } = {}) {
  const k = vectorKeys();
  const signer = key ?? k.install.key;
  const payload = { ...claims, iss: installId, sub: installId, aud, iat: now, exp: now + lifetime, jti };
  return signJwt({ alg: 'EdDSA', typ, kid: kid ?? k.install.kid }, payload, signer);
}

/** The proof of possession that registers a key. */
export function signKeyProof(installId, nonce, { key, kid, now = VECTOR_NOW, lifetime = 120 } = {}) {
  const k = vectorKeys();
  const signer = key ?? k.install.key;
  const thumb = kid ?? k.install.kid;
  return signJwt(
    { alg: 'EdDSA', typ: NETWORK_INSTALL_POP_TYP, kid: thumb },
    { install: installId, nonce, iss: thumb, aud: NETWORK_AUDIENCE, iat: now, exp: now + lifetime },
    signer,
  );
}

/** A passport as an install issues it: any EdDSA JWT the install signs; the digest is of this exact string. */
export function signPassport({ key, kid, now = VECTOR_NOW, ttl = 900, jti = 'pas_vector00000000000000' } = {}) {
  const k = vectorKeys();
  const signer = key ?? k.install.key;
  return signJwt(
    { alg: 'EdDSA', kid: kid ?? k.install.kid },
    { stk: { agent_id: 'support-bot', session_id: 'ses_vector' }, iss: ISSUER, aud: 'stack:passport', sub: 'support-bot', iat: now, exp: now + ttl, jti },
    signer,
  );
}

/** The countersignature body of the vectors over a passport digest. */
export function countersignatureBody(digest, over = {}) {
  const k = vectorKeys();
  return {
    cs: {
      v: 1,
      install: VECTOR_INSTALL_ID,
      owner: OWNER,
      owner_verified: true,
      key: { kid: k.install.kid, jwk: k.install.public_jwk },
      passport: { alg: 'sha256', digest, jti: 'pas_vector00000000000000', agent: 'support-bot' },
      ...over,
    },
  };
}

export function revocationListBody(over = {}) {
  const k = vectorKeys();
  const at = iso(VECTOR_NOW);
  return {
    rl: {
      v: 1,
      after: 0,
      head: 2,
      next: null,
      entries: [
        { seq: 1, id: 'rev_vector00000000000001', kind: 'agent', subject: 'support-bot', install: VECTOR_INSTALL_ID, reason: 'agent_decommissioned', by: 'install', at },
        { seq: 2, id: 'rev_vector00000000000002', kind: 'key', subject: k.install.kid, install: VECTOR_INSTALL_ID, reason: 'key_compromise', by: 'owner', at },
      ],
      ...over,
    },
  };
}

export function verifiedBody(digest, over = {}) {
  return {
    vs: {
      v: 1,
      mark: 'STACK-verified',
      status: 'live',
      install: VECTOR_INSTALL_ID,
      countersignature: 'csg_vector000000000000',
      valid_until: iso(VECTOR_NOW + 900),
      passport_digest: digest,
      ...over,
    },
  };
}

export function detectionRulesBody(over = {}) {
  return {
    rs: {
      v: 1,
      version: 'r1-vector000000',
      revision: 1,
      sha256: 'a'.repeat(64),
      packs: [{ id: 'prompt_injection', direction: 'input', rules: [{ id: 'override_ignore_previous', severity: 'critical', pattern: '\\bignore\\s+all\\s+previous\\s+instructions\\b', flags: 'i' }] }],
      ...over,
    },
  };
}

/** A token as its three dot-separated parts, so no file holds a token-shaped string. */
const parts = (token) => token.split('.');

/** The ten ways a token can be presented as the wrong kind of object (section 4.3): `token_of` presented as `presented_as`. */
function crossKind() {
  const kinds = ['countersignature', 'verified_statement', 'revocation_list', 'detection_rules'];
  const asKind = { countersignature: 'countersignature', verified_statement: 'verified', revocation_list: 'revocation_list', detection_rules: 'detection_rules' };
  const out = [];
  for (const held of kinds) for (const wanted of kinds) if (held !== wanted) out.push({ token_of: held, presented_as: asKind[wanted] });
  return out;
}

/** The vectors, as the object that is written to spec/network/test-vectors.json. */
export function buildNetworkVectors() {
  const k = vectorKeys();
  const passport = signPassport();
  const digest = passportDigest(passport);

  const countersignature = signNetworkObject('countersignature', countersignatureBody(digest), { ttl: 900, subject: VECTOR_INSTALL_ID, jti: 'csg_vector000000000000' });
  const verified = signNetworkObject('verified', verifiedBody(digest), { ttl: 300, subject: `passport:${digest}` });
  const revocations = signNetworkObject('revocation_list', revocationListBody(), { ttl: 300 });
  const rules = signNetworkObject('detection_rules', detectionRulesBody(), { ttl: 72 * 3600 });

  const proofs = {
    rules: signInstallProof({ act: 'rules' }, { jti: 'jtiVectorRules0000' }),
    countersign: signInstallProof({ act: 'countersign', pd: digest, pjti: 'pas_vector00000000000000', agent: 'support-bot', ttl: 900 }, { jti: 'jtiVectorCounter00' }),
    revoke: signInstallProof({ act: 'revoke', kind: 'agent', subject: 'support-bot', reason: 'agent_decommissioned' }, { jti: 'jtiVectorRevoke000' }),
  };
  const pop = signKeyProof(VECTOR_INSTALL_ID, 'n'.repeat(32));

  // ─── tokens that every conforming implementation must refuse ───
  const countersigned = (over, options = {}) =>
    parts(signNetworkObject('countersignature', countersignatureBody(digest, over), { ttl: 900, subject: VECTOR_INSTALL_ID, jti: 'csg_vector000000000000', ...options }));
  const [h, p, s] = parts(countersignature);
  const flipped = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  flipped.cs.owner_verified = false;
  const strangerPassport = signPassport({ key: k.stranger, jti: 'pas_vector00000000000001' });
  const shortPassport = signPassport({ ttl: 100, jti: 'pas_vector00000000000003' });
  const none = (payload) => `${Buffer.from(JSON.stringify({ alg: 'none', kid: VECTOR_STACK_KID, typ: NETWORK_KINDS.countersignature.typ })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.`;
  const decoded = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  const negative = [
    { id: 'countersignature_wrong_typ', kind: 'countersignature', description: 'a countersignature body under the typ of a verified statement', token: countersigned({}, { typ: NETWORK_KINDS.verified.typ }), expect: 'reject' },
    { id: 'countersignature_wrong_audience', kind: 'countersignature', description: 'the right typ with the audience of a passport', token: countersigned({}, { aud: 'stack:passport' }), expect: 'reject' },
    { id: 'countersignature_other_key', kind: 'countersignature', description: 'signed by a key that is not in the JWKS, under the kid that is', token: parts(signNetworkObject('countersignature', countersignatureBody(digest), { key: k.other, ttl: 900, subject: VECTOR_INSTALL_ID, jti: 'csg_vector000000000000' })), expect: 'reject' },
    { id: 'countersignature_tampered', kind: 'countersignature', description: 'the payload changed after signing (owner_verified false), the signature kept', token: [h, Buffer.from(JSON.stringify(flipped)).toString('base64url'), s], expect: 'reject' },
    { id: 'countersignature_alg_none', kind: 'countersignature', description: 'an unsigned token (alg none)', token: [...none(decoded).split('.')], expect: 'reject' },
    { id: 'countersignature_expired', kind: 'countersignature', description: 'the countersignature of the vectors, checked after it expired', token_of: 'countersignature', at: VECTOR_NOW + 900 + 3600, expect: 'reject', reason: 'expired' },
    { id: 'countersignature_wrong_issuer', kind: 'countersignature', description: 'issuer other than getstack.run', token: parts(signJwt({ alg: 'EdDSA', kid: VECTOR_STACK_KID, typ: NETWORK_KINDS.countersignature.typ }, { ...decoded, iss: 'attacker.example' }, k.stack)), expect: 'reject' },
    { id: 'countersignature_digest_mismatch', kind: 'countersignature', description: 'the countersignature of the vectors presented with a different passport', token_of: 'countersignature', passport: parts(signPassport({ jti: 'pas_vector00000000000002' })), expect: 'reject', reason: 'digest_mismatch' },
    {
      id: 'countersignature_passport_wrong_key', kind: 'countersignature',
      description: 'a countersignature over the digest of a passport that the install key did not sign',
      token: countersigned({ passport: { alg: 'sha256', digest: passportDigest(strangerPassport), jti: 'pas_vector00000000000001', agent: 'support-bot' } }),
      passport: parts(strangerPassport), expect: 'reject', reason: 'passport_invalid',
    },
    {
      id: 'countersignature_passport_expired', kind: 'countersignature',
      description: 'a passport that expired (after 100 seconds) while the countersignature over it (900 seconds) is still good',
      token: countersigned({ passport: { alg: 'sha256', digest: passportDigest(shortPassport), jti: 'pas_vector00000000000003', agent: 'support-bot' } }),
      passport: parts(shortPassport), at: VECTOR_NOW + 200, expect: 'reject', reason: 'passport_expired',
    },
    {
      id: 'countersignature_key_id_not_key', kind: 'countersignature',
      description: 'cs.key.kid is not the thumbprint of cs.key.jwk',
      token: countersigned({ key: { kid: 'A'.repeat(43), jwk: k.install.public_jwk } }), passport: parts(passport), expect: 'reject',
    },
    { id: 'revocation_list_unknown_version', kind: 'revocation_list', description: 'a list whose rl.v is 2', token: parts(signNetworkObject('revocation_list', revocationListBody({ v: 2 }), { ttl: 300 })), expect: 'reject' },
    { id: 'verified_statement_expired', kind: 'verified', description: 'the statement of the vectors checked after its five minutes', token_of: 'verified_statement', at: VECTOR_NOW + 300 + 10, expect: 'reject', reason: 'expired' },
    { id: 'detection_rules_older_than_held', kind: 'detection_rules', description: 'revision 1 presented to a verifier that already runs revision 2', token_of: 'detection_rules', held_revision: 2, expect: 'reject', reason: 'revision_too_old' },
    { id: 'install_proof_wrong_typ', kind: 'install_proof', description: 'an install proof under the typ of a key proof of possession', token: parts(signInstallProof({ act: 'rules' }, { jti: 'jtiVectorWrongTyp00', typ: NETWORK_INSTALL_POP_TYP })), expect: 'reject' },
    { id: 'install_proof_wrong_audience', kind: 'install_proof', description: 'an install proof addressed to the passport audience', token: parts(signInstallProof({ act: 'rules' }, { jti: 'jtiVectorWrongAud00', aud: 'stack:passport' })), expect: 'reject' },
    { id: 'install_proof_other_key', kind: 'install_proof', description: 'a proof naming the install key, signed by another key', token: parts(signInstallProof({ act: 'rules' }, { jti: 'jtiVectorOtherKey00', key: k.stranger })), expect: 'reject' },
    { id: 'install_proof_too_long_lived', kind: 'install_proof', description: 'a proof valid for 121 seconds', token: parts(signInstallProof({ act: 'rules' }, { jti: 'jtiVectorTooLong000', lifetime: 121 })), expect: 'reject' },
    { id: 'install_proof_expired', kind: 'install_proof', description: 'the rules proof of the vectors checked two minutes after it was issued', token_of: 'install_proofs.rules', at: VECTOR_NOW + 61 + 60, expect: 'reject', reason: 'expired' },
  ];

  return {
    description: 'Deterministic vectors for the STACK network formats (spec/network/SPEC.md, section 14). Every token is its three dot-separated parts as an array: join with a dot. Produced by the public generator named in `generator`, from the public test keys described there; regenerate with `node spec/conformance/scripts/build-network-vectors.mjs`.',
    generator: 'spec/conformance/scripts/build-network-vectors.mjs',
    now: VECTOR_NOW,
    stack: { jwks: { keys: [k.stack.publicJwk] }, kid: VECTOR_STACK_KID },
    install: { id: VECTOR_INSTALL_ID, kid: k.install.kid, public_jwk: k.install.public_jwk, private_seed_hex: '02'.repeat(32) },
    typ: { countersignature: NETWORK_KINDS.countersignature.typ },
    passport: { parts: parts(passport), digest },
    countersignature: parts(countersignature),
    verified_statement: parts(verified),
    revocation_list: parts(revocations),
    detection_rules: parts(rules),
    install_proofs: { rules: parts(proofs.rules), countersign: parts(proofs.countersign), revoke: parts(proofs.revoke) },
    key_proof_of_possession: { nonce: 'n'.repeat(32), proof: parts(pop) },
    negative: { cross_kind: crossKind(), cases: negative },
  };
}
