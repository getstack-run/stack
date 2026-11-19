#!/usr/bin/env node
// Builds the agent identity test vectors in fixtures/agent-identity/vectors.json, from the
// specification alone (spec/agent-identity/SPEC.md sections 5 and 12): a statement that verifies,
// in each of the forms a lookup can take, and the statements a verifier must refuse, each with one
// defect. Ed25519 is deterministic, so with a fixed clock the file is the same bytes every time.
// The keys are TEST keys made from fixed seeds (src/agent-identity.mjs); they are for these
// vectors only. `--check` fails if the file on disk differs from a fresh build.

import { createHmac } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PASSPORT_AUDIENCE,
  STATEMENT_TYP,
  TEST_ISSUER_KEY,
  TEST_RETIRED_KEY,
  TEST_STRANGER_KEY,
  signStatement,
  statementClaims,
} from '../src/agent-identity.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'agent-identity');
const IAT = 1_790_000_000;
/** The clock the vectors are checked at: 100 seconds into a 300 second statement. */
const NOW = IAT + 100;
const AGENT = 'agt_Q2x5b3Vkc0FyZUp1c3RlA';
const OTHER_AGENT = 'agt_T3RoZXJBZ2VudElkMTIzNA';
const KEY_ID = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';
const OTHER_KEY_ID = 'A'.repeat(43);
const SITE = 'acme.sites.example';

const facts = (lookup, over = {}) => ({
  agent: { id: AGENT, status: 'active', ...(over.agent ?? {}) },
  owner: { identity_verified: true, good_standing: true, ...(over.owner ?? {}) },
  lookup,
});
const claimsOf = (lookup, over = {}) => statementClaims({ facts: facts(lookup, over), iat: IAT });
const valid = (lookup, over) => signStatement({ claims: claimsOf(lookup, over) });

const cases = [];
// A statement is stored as its parts, to be joined with `.`: a compact token written out whole is shaped like a credential, and these are not.
const add = (id, group, title, statement, expect, agentId = AGENT) => cases.push({ id, group, title, agent_id: agentId, verdict: group === 'valid' ? 'accept' : 'reject', expect, statement_parts: statement.split('.') });
// The groups are the checks of the suite: valid (AV01), time (AV02), header (AV03), claims (AV04), signature (AV05), lookup (AV06) and lifetime (AV07, a SHOULD).

// ─── Statements that verify ──────────────────────────────────────
add('valid-by-key', 'valid', 'a statement for a lookup by key id', valid({ key_id: KEY_ID }), { key_id: KEY_ID });
add('valid-by-site', 'valid', 'a statement for a lookup by site, with the agent\'s name shown', valid({ site: SITE }, { agent: { name: 'Acme Helper' } }), { site: SITE });
add('valid-by-agent-id', 'valid', 'a statement for a closed agent, asked for by its id, with the owner not in good standing', valid({ agent_id: AGENT }, { agent: { status: 'closed' }, owner: { good_standing: false } }), { agent_id: AGENT });
add('valid-retired-key', 'valid', 'a statement signed by a retired key the key set still holds', signStatement({ key: TEST_RETIRED_KEY, claims: claimsOf({ key_id: KEY_ID }) }), { key_id: KEY_ID });

// ─── The clock ───────────────────────────────────────────────────
add('expired', 'time', 'a statement that expired a minute before the clock', signStatement({ claims: statementClaims({ facts: facts({ key_id: KEY_ID }), iat: NOW - 360, ttl: 300 }) }), { key_id: KEY_ID });
add('made-in-the-future', 'time', 'a statement made ten minutes after the clock', signStatement({ claims: statementClaims({ facts: facts({ key_id: KEY_ID }), iat: NOW + 600, ttl: 300 }) }), { key_id: KEY_ID });
add('good-for-an-hour', 'lifetime', 'a statement that is good for 3600 seconds', signStatement({ claims: statementClaims({ facts: facts({ key_id: KEY_ID }), iat: IAT, ttl: 3600 }) }), { key_id: KEY_ID });

// ─── The header ──────────────────────────────────────────────────
const claims = claimsOf({ key_id: KEY_ID });
add('wrong-type', 'header', 'the protected type is JWT', signStatement({ header: { alg: 'EdDSA', kid: TEST_ISSUER_KEY.kid, typ: 'JWT' }, claims }), { key_id: KEY_ID });
add('no-type', 'header', 'the protected header has no type, as a Passport has none', signStatement({ header: { alg: 'EdDSA', kid: TEST_ISSUER_KEY.kid }, claims }), { key_id: KEY_ID });
add('alg-none', 'header', 'the algorithm is none and the signature is empty', signStatement({ header: { alg: 'none', kid: TEST_ISSUER_KEY.kid, typ: STATEMENT_TYP }, claims, signature: null }), { key_id: KEY_ID });
{
  // The classic confusion: a MAC made with the public key as the secret.
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', kid: TEST_ISSUER_KEY.kid, typ: STATEMENT_TYP })).toString('base64url');
  const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const mac = createHmac('sha256', Buffer.from(TEST_ISSUER_KEY.publicJwk.x, 'base64url')).update(`${header}.${body}`).digest('base64url');
  add('alg-hs256', 'header', 'the algorithm is HS256 and the MAC is made with the public key', `${header}.${body}.${mac}`, { key_id: KEY_ID });
}
add('not-compact', 'header', 'a string that is not a compact JWS', 'not-a-statement', { key_id: KEY_ID });

// ─── The claims ──────────────────────────────────────────────────
add('passport-audience', 'claims', 'correctly signed, with the audience of a Passport', signStatement({ claims: { ...claims, aud: PASSPORT_AUDIENCE } }), { key_id: KEY_ID });
add('other-issuer', 'claims', 'correctly signed, with another issuer', signStatement({ claims: { ...claims, iss: 'issuer.example' } }), { key_id: KEY_ID });
add('subject-is-not-the-agent', 'claims', 'correctly signed, with a subject that is not the agent it is about', signStatement({ claims: { ...claims, sub: OTHER_AGENT } }), { key_id: KEY_ID });
add('another-version', 'claims', 'correctly signed, with identity.v 2', signStatement({ claims: { ...claims, identity: { ...claims.identity, v: 2 } } }), { key_id: KEY_ID });
add('no-identity', 'claims', 'correctly signed, with no identity claim', signStatement({ claims: { iss: claims.iss, aud: claims.aud, sub: claims.sub, iat: claims.iat, exp: claims.exp } }), { key_id: KEY_ID });

// ─── The signature ───────────────────────────────────────────────
{
  const suspended = valid({ key_id: KEY_ID }, { owner: { good_standing: false } });
  const [head, , signature] = suspended.split('.');
  const altered = Buffer.from(JSON.stringify(claimsOf({ key_id: KEY_ID }))).toString('base64url');
  add('altered-payload', 'signature', 'the owner\'s standing changed after signing: not in good standing made good', `${head}.${altered}.${signature}`, { key_id: KEY_ID });
}
add('unknown-key', 'signature', 'signed by a key under a key id the key set does not hold', signStatement({ key: { ...TEST_STRANGER_KEY, kid: 'stack-passport-v9' }, claims }), { key_id: KEY_ID });
add('stranger-under-known-kid', 'signature', 'signed by another key under a key id the key set does hold', signStatement({ key: TEST_STRANGER_KEY, claims }), { key_id: KEY_ID });

// ─── What was asked ──────────────────────────────────────────────
add('about-another-key', 'lookup', 'valid, about one key id, offered as the answer for another', valid({ key_id: KEY_ID }), { key_id: OTHER_KEY_ID });
add('about-a-site-asked-by-id', 'lookup', 'valid, about a site, offered as the answer to a lookup by agent id', valid({ site: SITE }), { agent_id: AGENT });

const vectors = {
  spec: 'agent-identity',
  version: '1.0.0',
  note: 'Built by scripts/build-agent-identity-vectors.mjs. The keys are TEST keys from fixed seeds: never use them for anything but these vectors.',
  issuer: 'getstack.run',
  now: NOW,
  jwks: { keys: [TEST_ISSUER_KEY.publicJwk, TEST_RETIRED_KEY.publicJwk] },
  cases,
};

const content = `${JSON.stringify(vectors, null, 2)}\n`;
const path = join(OUT, 'vectors.json');
const check = process.argv.includes('--check');
const current = existsSync(path) ? readFileSync(path, 'utf8').replaceAll('\r\n', '\n') : null;
if (check) {
  if (current !== content) {
    console.error('the agent identity vectors are out of date; run `node scripts/build-agent-identity-vectors.mjs`');
    process.exit(1);
  }
  console.log('agent-identity vectors are current');
} else if (current !== content) {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(path, content, 'utf8');
  console.log('wrote the agent identity vectors');
} else console.log('agent-identity vectors unchanged');
