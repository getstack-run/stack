// Conformance suite for the agent identity endpoint as STACK specifies it (spec/agent-identity/SPEC.md).
// Two things can be judged, each by handing the kit one handle:
//
//   server    the origin of a server and the handles of a test agent: its key id, the host name of
//             its site and its id (all three find the same agent), and optionally a closed agent
//             and one whose owner switched the answer off. The kit makes the lookups, reads the
//             answer and the signed statement, and asks for the agent's machine files.
//   verifier  a function that checks a statement: `verify(statement, { jwks, now, issuer, expect })`
//             returns the claims, or throws (or returns false or `{ ok: false }`) to refuse. The
//             kit hands it the vectors of fixtures/agent-identity/vectors.json, one defect at a time.
//
// A check that needs a handle you did not provide is reported as skipped, never as passed. The
// kit asks a server only to read: it creates nothing. Use a test instance and a test agent.

import { createPrivateKey, createPublicKey, randomBytes, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { assert, runChecks, skip } from './harness.mjs';
import { runA2aSuite } from './a2a.mjs';
import { ed25519Thumbprint } from './http-signature.mjs';
import { runWebBotAuthSuite } from './web-bot-auth.mjs';

export const STATEMENT_TYP = 'stack-agent-identity+jwt';
export const STATEMENT_AUDIENCE = 'stack:agent-identity';
export const PASSPORT_AUDIENCE = 'stack:passport';
export const CLAIM_VERSION = 1;
/** The longest a statement may be good for, in seconds. */
export const STATEMENT_MAX_SECONDS = 900;
/** How far off its clock a verifier tolerates a statement, in seconds. */
export const CLOCK_SKEW_SECONDS = 5;
export const AGENT_STATUSES = ['active', 'suspended', 'closed'];
export const NOT_FOUND_BODY = { error: { code: 'AGENT_IDENTITY_NOT_FOUND', message: 'No agent answers to this lookup.' } };
export const ANONYMOUS_DESCRIPTION = 'An AI agent operated through STACK.';
export const FILE_NAMES = { agent_card: 'agent-card.json', mcp_server_card: 'mcp-server-card.json', key_directory: 'http-message-signatures-directory' };
export const JWKS_PATH = '/v1/.well-known/jwks.json';
const MCP_SIGNATURE_KEY = 'run.getstack/signature';

const b64url = (data) => Buffer.from(data).toString('base64url');
const fromB64url = (text) => Buffer.from(text, 'base64url');

// ─── The statement, as the kit reads and writes it ───────────────

/** A test key from a fixed seed: an Ed25519 key pair, its public JWK (with `kid`, `alg` and `use`) and its private key object. */
export function testKey(seedByte, kid) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seedByte)]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const jwk = privateKey.export({ format: 'jwk' });
  return { kid, privateKey, publicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid, alg: 'EdDSA', use: 'sig' } };
}

/** The key of the vectors and of the reference server: a TEST key, for these checks only. */
export const TEST_ISSUER_KEY = testKey(0x53, 'stack-passport-v1');
/** A retired key the vectors' key set still trusts. */
export const TEST_RETIRED_KEY = testKey(0x54, 'stack-passport-v0');
/** A key that is nowhere in the key set. */
export const TEST_STRANGER_KEY = testKey(0x55, 'stack-passport-v1');

/**
 * A compact JWS, with every part overridable so that a vector damages exactly one thing.
 * @param {{ key?: ReturnType<typeof testKey>, header?: object, claims: object, alg?: string, signature?: string | null }} input
 */
export function signStatement({ key = TEST_ISSUER_KEY, header, claims, signature }) {
  const protectedHeader = header ?? { alg: 'EdDSA', kid: key.kid, typ: STATEMENT_TYP };
  const signingInput = `${b64url(JSON.stringify(protectedHeader))}.${b64url(JSON.stringify(claims))}`;
  const sig = signature === undefined ? cryptoSign(null, Buffer.from(signingInput), key.privateKey).toString('base64url') : signature;
  return `${signingInput}.${sig ?? ''}`;
}

/** The claims of a statement for facts, as a server writes them. */
export function statementClaims({ facts, iat, ttl = 300, issuer = 'getstack.run', audience = STATEMENT_AUDIENCE, subject }) {
  return { iss: issuer, aud: audience, sub: subject ?? facts.agent.id, iat, exp: iat + ttl, identity: { v: CLAIM_VERSION, ...facts } };
}

function decodeJws(token) {
  assert(typeof token === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token), 'the statement is not a compact JWS');
  const [head, body, signature] = token.split('.');
  let header;
  let payload;
  try {
    header = JSON.parse(fromB64url(head).toString('utf8'));
    payload = JSON.parse(fromB64url(body).toString('utf8'));
  } catch {
    throw new Error('the statement does not decode to JSON');
  }
  return { header, payload, signingInput: `${head}.${body}`, signature: fromB64url(signature) };
}

function verifySignature(decoded, jwks) {
  const keys = Array.isArray(jwks) ? jwks : jwks?.keys;
  assert(Array.isArray(keys) && keys.length > 0, 'the issuer publishes no keys');
  const key = keys.find((k) => k.kid === decoded.header.kid);
  assert(key, `the statement names the key ${JSON.stringify(decoded.header.kid)}, which the issuer's keys do not hold`);
  assert(key.kty === 'OKP' && key.crv === 'Ed25519', 'the named key is not an Ed25519 key');
  const ok = cryptoVerify(null, Buffer.from(decoded.signingInput), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' }), decoded.signature);
  assert(ok, 'the signature does not verify');
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const sameKeys = (value, expected, where) => {
  assert(isObject(value), `${where} is not an object`);
  const actual = Object.keys(value).sort();
  assert(JSON.stringify(actual) === JSON.stringify([...expected].sort()), `${where} has the members ${JSON.stringify(actual)}, expected ${JSON.stringify([...expected].sort())}`);
};

/** The facts of section 4, checked member by member. Returns them. */
function checkFacts({ agent, owner, lookup }, where) {
  assert(isObject(agent), `${where}: agent is not an object`);
  const agentMembers = Object.keys(agent).sort();
  assert(agentMembers.every((m) => ['id', 'name', 'status'].includes(m)) && agentMembers.includes('id') && agentMembers.includes('status'), `${where}: agent has the members ${JSON.stringify(agentMembers)}`);
  assert(/^agt_[A-Za-z0-9_-]{21}$/.test(agent.id), `${where}: agent.id ${JSON.stringify(agent.id)} is not an agent id`);
  assert(AGENT_STATUSES.includes(agent.status), `${where}: agent.status ${JSON.stringify(agent.status)} is not one of ${AGENT_STATUSES.join(', ')}`);
  if ('name' in agent) assert(typeof agent.name === 'string' && agent.name.length >= 1 && agent.name.length <= 120, `${where}: agent.name is not a string of 1 to 120 characters`);
  sameKeys(owner, ['identity_verified', 'good_standing'], `${where}: owner`);
  for (const fact of ['identity_verified', 'good_standing']) assert(typeof owner[fact] === 'boolean', `${where}: owner.${fact} is not a boolean`);
  assert(isObject(lookup) && Object.keys(lookup).length === 1, `${where}: lookup is not an object with one member`);
  const [by] = Object.keys(lookup);
  assert(['key_id', 'site', 'agent_id'].includes(by) && typeof lookup[by] === 'string', `${where}: lookup names ${JSON.stringify(by)}`);
  return { agent, owner, lookup };
}

/**
 * Judge a statement the way section 12 says a verifier does, and return its claims. Throws a
 * message that says what is wrong.
 */
export function judgeStatement(token, { jwks, now, issuer = 'getstack.run', expect } = {}) {
  const decoded = decodeJws(token);
  sameKeys(decoded.header, ['alg', 'kid', 'typ'], 'the protected header');
  assert(decoded.header.alg === 'EdDSA', `alg is ${JSON.stringify(decoded.header.alg)}`);
  assert(decoded.header.typ === STATEMENT_TYP, `typ is ${JSON.stringify(decoded.header.typ)}`);
  verifySignature(decoded, jwks);
  const claims = decoded.payload;
  sameKeys(claims, ['iss', 'aud', 'sub', 'iat', 'exp', 'identity'], 'the payload');
  assert(claims.iss === issuer, `iss is ${JSON.stringify(claims.iss)}`);
  assert(claims.aud === STATEMENT_AUDIENCE, `aud is ${JSON.stringify(claims.aud)}`);
  assert(Number.isInteger(claims.iat) && Number.isInteger(claims.exp), 'iat and exp are not integers');
  assert(claims.exp > claims.iat && claims.exp - claims.iat <= STATEMENT_MAX_SECONDS, `the statement is good for ${claims.exp - claims.iat} seconds`);
  assert(isObject(claims.identity), 'identity is not an object');
  sameKeys(claims.identity, ['v', 'agent', 'owner', 'lookup'], 'identity');
  assert(claims.identity.v === CLAIM_VERSION, `identity.v is ${JSON.stringify(claims.identity.v)}`);
  const facts = checkFacts(claims.identity, 'identity');
  assert(claims.sub === facts.agent.id, 'sub is not the agent id');
  if (now !== undefined) {
    const at = Math.floor(now.getTime() / 1000);
    assert(at < claims.exp + CLOCK_SKEW_SECONDS, 'the statement has expired');
    assert(claims.iat <= at + CLOCK_SKEW_SECONDS, 'the statement was made in the future');
  }
  if (expect) {
    const [by] = Object.keys(expect);
    assert(JSON.stringify(facts.lookup) === JSON.stringify({ [by]: expect[by] }), `the statement is about ${JSON.stringify(facts.lookup)}, not ${JSON.stringify(expect)}`);
  }
  return claims;
}

// ─── The suite ───────────────────────────────────────────────────

/**
 * @param {{
 *   url?: string,                                   // the origin of the server
 *   known?: { key_id: string, site: string, agent_id: string, showName?: boolean, name?: string },  // an active agent, by all three
 *   closed?: { agent_id: string, key_id?: string, site?: string },   // a closed agent
 *   hidden?: { key_id: string, site: string, agent_id: string },     // an agent whose owner switched the answer off
 *   jwks?: { keys: object[] },                      // the issuer's keys; default: read from the server
 *   verifier?: (statement: string, options: { jwks: object, now: Date, issuer: string, expect?: object }) => unknown,
 *   vectors?: object,                               // fixtures/agent-identity/vectors.json, for the verifier checks
 *   probeRateLimit?: boolean,                       // send enough lookups to meet the limit (the kit sends up to `rateLimitProbe`)
 *   rateLimitProbe?: number,
 *   headers?: Record<string, string>, timeoutMs?: number, fetchImpl?: typeof fetch,
 * }} options
 */
export async function runAgentIdentitySuite(options) {
  const { url, known, closed, hidden, verifier, vectors, headers = {}, timeoutMs = 10_000, fetchImpl = fetch } = options;
  if (!url && !verifier) throw new Error('give the agent-identity suite a server url or a verifier');
  const origin = url ? new URL(url).origin : '';
  const probeCount = options.rateLimitProbe ?? 200;

  async function http(path, init = {}) {
    const response = await fetchImpl(`${origin}${path}`, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), ...init, headers: { accept: 'application/json', ...headers, ...(init.headers ?? {}) } });
    const text = await response.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: response.status, headers: response.headers, text, json };
  }
  const lookupPath = (params) => `/v1/agent-identity?${new URLSearchParams(params).toString()}`;
  const memo = new Map();
  /** A lookup, made once per suite run: the server limits a source, and the checks share what they read. */
  const lookup = async (params) => {
    const path = lookupPath(params);
    if (!memo.has(path)) memo.set(path, http(path));
    return memo.get(path);
  };
  const filePath = (agentId, name) => `/v1/agent-identity/agents/${agentId}/${name}`;

  let issuerKeys = options.jwks;
  const keys = async () => {
    if (issuerKeys) return issuerKeys;
    const r = await http(JWKS_PATH);
    assert(r.status === 200 && Array.isArray(r.json?.keys), `the issuer's keys at ${JWKS_PATH} answered ${r.status}`);
    issuerKeys = r.json;
    return issuerKeys;
  };

  const needsKnown = known ? null : skip('needs known: a test agent, by its key id, its site and its id');
  const needsServer = url ? null : skip('needs url: the origin of a server');

  /** The 404 an unknown agent gets, as a comparable line. */
  const refusalOf = (r) => `${r.status} ${r.headers.get('content-type') ?? ''} ${r.headers.get('cache-control') ?? ''} ${r.text}`;
  const randomId = () => `agt_${randomBytes(16).toString('base64url').slice(0, 21)}`;
  const randomKeyId = () => randomBytes(32).toString('base64url');
  const randomSite = () => `nobody-${randomBytes(6).toString('hex')}.sites.example`;

  let notFoundCache;
  const unknownRefusals = async () => {
    notFoundCache ??= await Promise.all([
      lookup({ key_id: randomKeyId() }),
      lookup({ site: randomSite() }),
      lookup({ agent_id: randomId() }),
    ]);
    return notFoundCache;
  };

  const checks = [
    // ─── lookups ───
    {
      id: 'AI01', level: 'MUST', title: 'answers a lookup by key id with 200, a JSON object and Cache-Control: no-store',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        const r = await lookup({ key_id: known.key_id });
        assert(r.status === 200, `answered ${r.status}: ${r.text.slice(0, 160)}`);
        assert(/^application\/json/i.test(r.headers.get('content-type') ?? ''), `content-type is ${JSON.stringify(r.headers.get('content-type'))}`);
        assert(/no-store/i.test(r.headers.get('cache-control') ?? ''), `cache-control is ${JSON.stringify(r.headers.get('cache-control'))}`);
        assert(isObject(r.json), 'the body is not a JSON object');
      },
    },
    {
      id: 'AI02', level: 'MUST', title: 'finds the same agent by the host name of its site, in any case, and answers the host in lower case',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        const byKey = await lookup({ key_id: known.key_id });
        const lower = await lookup({ site: known.site.toLowerCase() });
        const upper = await lookup({ site: known.site.toUpperCase() });
        for (const r of [lower, upper]) {
          assert(r.status === 200, `answered ${r.status}: ${r.text.slice(0, 160)}`);
          assert(r.json?.agent?.id === byKey.json?.agent?.id, 'a different agent was found by the site');
          assert(r.json?.lookup?.site === known.site.toLowerCase(), `the lookup echoes ${JSON.stringify(r.json?.lookup)}`);
        }
      },
    },
    {
      id: 'AI03', level: 'MUST', title: 'finds the same agent by its id, and echoes what was asked',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        const byKey = await lookup({ key_id: known.key_id });
        const r = await lookup({ agent_id: known.agent_id });
        assert(r.status === 200, `answered ${r.status}: ${r.text.slice(0, 160)}`);
        assert(r.json?.agent?.id === known.agent_id && byKey.json?.agent?.id === known.agent_id, 'the agent found is not the agent given');
        assert(r.json?.lookup?.agent_id === known.agent_id && byKey.json?.lookup?.key_id === known.key_id, 'the lookup does not echo what was asked');
      },
    },
    {
      id: 'AI04', level: 'MUST', title: 'answers exactly the members of section 4, with the types it gives: the facts of the agent and of the owner, and nothing else',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        for (const params of [{ key_id: known.key_id }, { site: known.site }, { agent_id: known.agent_id }]) {
          const r = await lookup(params);
          assert(r.status === 200, `answered ${r.status}`);
          sameKeys(r.json, ['statement', 'agent', 'owner', 'lookup', 'issued_at', 'expires_at'], 'the body');
          checkFacts(r.json, 'the body');
          assert(Number.isInteger(r.json.issued_at) && Number.isInteger(r.json.expires_at), 'issued_at and expires_at are not integers');
          assert(r.json.expires_at > r.json.issued_at && r.json.expires_at - r.json.issued_at <= STATEMENT_MAX_SECONDS, `the statement is good for ${r.json.expires_at - r.json.issued_at} seconds`);
          assert(r.json.agent.id === known.agent_id, 'the agent is not the one given');
          assert(r.json.agent.status === 'active', `a test agent that is in use has the status ${JSON.stringify(r.json.agent.status)}`);
        }
      },
    },
    {
      id: 'AI05', level: 'MUST', title: 'signs the statement as section 5 writes it: EdDSA under the issuer\'s keys, the typ and audience of an identity statement, the claims equal to the plain JSON',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        const jwks = await keys();
        for (const params of [{ key_id: known.key_id }, { site: known.site }, { agent_id: known.agent_id }]) {
          const r = await lookup(params);
          assert(r.status === 200, `answered ${r.status}`);
          const claims = judgeStatement(r.json.statement, { jwks, now: new Date() });
          assert(JSON.stringify(claims.identity.agent) === JSON.stringify(r.json.agent), 'the agent in the statement is not the agent in the JSON');
          assert(JSON.stringify(claims.identity.owner) === JSON.stringify(r.json.owner), 'the owner in the statement is not the owner in the JSON');
          assert(JSON.stringify(claims.identity.lookup) === JSON.stringify(r.json.lookup), 'the lookup in the statement is not the lookup in the JSON');
          assert(claims.iat === r.json.issued_at && claims.exp === r.json.expires_at, 'iat and exp are not issued_at and expires_at');
        }
      },
    },
    {
      id: 'AI06', level: 'MUST', title: 'never makes a statement that could be taken for a Passport, or carries anything of one',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        const r = await lookup({ agent_id: known.agent_id });
        assert(r.status === 200, `answered ${r.status}`);
        const decoded = decodeJws(r.json.statement);
        assert(decoded.payload.aud !== PASSPORT_AUDIENCE && decoded.payload.aud === STATEMENT_AUDIENCE, `aud is ${JSON.stringify(decoded.payload.aud)}`);
        assert(decoded.header.typ === STATEMENT_TYP, `typ is ${JSON.stringify(decoded.header.typ)}`);
        assert(!('stk' in decoded.payload) && !('jti' in decoded.payload), 'the payload carries a claim of a Passport');
        assert(!/@|mailto:|tel:/i.test(JSON.stringify(r.json)), 'the answer carries an address or a number');
      },
    },
    {
      id: 'AI07', level: 'MUST', title: 'refuses a lookup that names none, two, an undefined parameter or a value of no possible form: 400 AGENT_IDENTITY_LOOKUP_INVALID, repeating nothing',
      async run() {
        if (needsServer) return needsServer;
        const good = { key_id: 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U', agent: 'agt_abcdefghijklmnopqrstu', site: 'acme.sites.example' };
        const bad = [
          ['no parameter', {}],
          ['two selectors', { key_id: good.key_id, agent_id: good.agent }],
          ['an undefined parameter', { key_id: good.key_id, extra: 'zzz-marker-1' }],
          ['a key id that is too short', { key_id: 'poqkLGiymh' }],
          ['a key id with a character outside base64url', { key_id: `${good.key_id.slice(0, 42)}+` }],
          ['an agent id with another prefix', { agent_id: 'age_abcdefghijklmnopqrstu' }],
          ['an agent id that is too long', { agent_id: 'agt_abcdefghijklmnopqrstuvw' }],
          ['a site with a port', { site: 'acme.sites.example:8443' }],
          ['a site with a scheme', { site: 'https://acme.sites.example' }],
          ['a site with a path', { site: 'acme.sites.example/path' }],
          ['a site of one label', { site: 'localhost' }],
          ['an empty value', { site: '' }],
        ];
        for (const [what, params] of bad) {
          const r = await http(lookupPath(params));
          assert(r.status === 400, `${what}: answered ${r.status}`);
          assert(r.json?.error?.code === 'AGENT_IDENTITY_LOOKUP_INVALID', `${what}: the code is ${JSON.stringify(r.json?.error?.code)}`);
          for (const value of Object.values(params)) {
            if (value.length >= 5) assert(!r.text.includes(value), `${what}: the refusal repeats ${JSON.stringify(value)}`);
          }
        }
      },
    },

    // ─── an agent that is not found ───
    {
      id: 'AI08', level: 'MUST', title: 'answers an agent that does not exist with the 404 of section 7, for each way of asking, and repeats nothing that was asked',
      async run() {
        if (needsServer) return needsServer;
        const asked = [];
        for (const [what, params] of [['key id', { key_id: randomKeyId() }], ['site', { site: randomSite() }], ['agent id', { agent_id: randomId() }]]) {
          const r = await http(lookupPath(params));
          assert(r.status === 404, `${what}: answered ${r.status}`);
          assert(JSON.stringify(r.json) === JSON.stringify(NOT_FOUND_BODY), `${what}: the body is ${r.text.slice(0, 200)}`);
          asked.push(Object.values(params)[0]);
          for (const value of asked) assert(!r.text.includes(value), `${what}: the refusal repeats what was asked`);
        }
      },
    },
    {
      id: 'AI09', level: 'MUST', title: 'gives the same answer, word for word, whether an agent is unknown, closed and asked for by a guessable thing, or switched off by its owner',
      async run() {
        if (needsServer) return needsServer;
        const refusals = (await unknownRefusals()).map(refusalOf);
        const compared = ['an unknown key id', 'an unknown site', 'an unknown agent id'];
        if (closed?.site) {
          refusals.push(refusalOf(await lookup({ site: closed.site })));
          compared.push('a closed agent asked for by its site');
        }
        if (closed?.key_id) {
          refusals.push(refusalOf(await lookup({ key_id: closed.key_id })));
          compared.push('a closed agent asked for by its key id');
        }
        if (hidden) {
          for (const params of [{ key_id: hidden.key_id }, { site: hidden.site }, { agent_id: hidden.agent_id }]) {
            refusals.push(refusalOf(await lookup(params)));
            compared.push(`a switched-off agent asked for by ${Object.keys(params)[0]}`);
          }
        }
        refusals.forEach((line, i) => assert(line === refusals[0], `${compared[i]} is answered differently from ${compared[0]}:\n${line}\n${refusals[0]}`));
        assert(refusals[0].startsWith('404 '), `the answer is ${refusals[0].slice(0, 60)}`);
      },
    },
    {
      id: 'AI10', level: 'MUST', title: 'names a closed agent to someone who holds its id, as closed',
      async run() {
        if (needsServer) return needsServer;
        if (!closed) return skip('needs closed: a closed agent');
        const r = await lookup({ agent_id: closed.agent_id });
        assert(r.status === 200, `a closed agent asked for by its id was answered ${r.status}`);
        assert(r.json?.agent?.status === 'closed', `its status is ${JSON.stringify(r.json?.agent?.status)}`);
        judgeStatement(r.json.statement, { jwks: await keys(), now: new Date(), expect: { agent_id: closed.agent_id } });
      },
    },
    {
      id: 'AI11', level: 'MUST', title: 'shows the name only when its owner chose to: absent from the answer and the statement otherwise, and the name itself when shown',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        if (known.showName === undefined) return skip('needs known.showName: whether the test agent\'s owner shows its name');
        const r = await lookup({ agent_id: known.agent_id });
        const claims = decodeJws(r.json.statement).payload.identity;
        if (known.showName) {
          assert(known.name && r.json.agent.name === known.name && claims.agent.name === known.name, `the name is ${JSON.stringify(r.json.agent.name)}, expected ${JSON.stringify(known.name)}`);
        } else {
          assert(!('name' in r.json.agent) && !('name' in claims.agent), 'a name is in the answer although its owner does not show it');
        }
      },
    },
    {
      id: 'AI12', level: 'SHOULD', title: 'limits one source: a run of lookups is answered 429 RATE_LIMITED before long',
      async run() {
        if (needsServer) return needsServer;
        if (!options.probeRateLimit) return skip('not asked for: it sends up to rateLimitProbe lookups from one source');
        let limited;
        for (let i = 0; i < probeCount && !limited; i += 1) {
          const r = await http(lookupPath({ key_id: randomKeyId() }));
          if (r.status === 429) limited = r;
        }
        assert(limited, `${probeCount} lookups from one source were never limited`);
        assert(limited.json?.error?.code === 'RATE_LIMITED', `the limited answer is ${limited.text.slice(0, 100)}`);
      },
    },

    // ─── the machine files ───
    {
      id: 'AF01', level: 'MUST', title: 'serves the signed A2A card of an agent: JSON, open to any origin, a JWS the key directory it names verifies, naming the agent only as its owner shows it',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        const cardUrl = `${origin}${filePath(known.agent_id, FILE_NAMES.agent_card)}`;
        const r = await http(filePath(known.agent_id, FILE_NAMES.agent_card));
        assert(r.status === 200, `answered ${r.status}: ${r.text.slice(0, 160)}`);
        assert(/^application\/json/i.test(r.headers.get('content-type') ?? ''), `content-type is ${JSON.stringify(r.headers.get('content-type'))}`);
        assert(r.headers.get('access-control-allow-origin') === '*', 'the card is not open to any origin');
        assert(/public/i.test(r.headers.get('cache-control') ?? '') && /max-age=\d+/.test(r.headers.get('cache-control') ?? ''), `cache-control is ${JSON.stringify(r.headers.get('cache-control'))}`);
        const card = r.json;
        assert(isObject(card) && Array.isArray(card.signatures) && card.signatures.length === 1, 'the card is not signed once');
        const header = JSON.parse(fromB64url(card.signatures[0].protected).toString('utf8'));
        assert(header.jku === `${origin}${filePath(known.agent_id, FILE_NAMES.key_directory)}`, `jku is ${JSON.stringify(header.jku)}, not the agent's key directory on the server`);
        const report = await runA2aSuite({ url: cardUrl, groups: ['card'], timeoutMs, fetchImpl });
        const failed = report.results.filter((x) => x.status === 'fail' && x.level === 'MUST');
        assert(failed.length === 0, `the a2a card checks failed: ${failed.map((x) => `${x.id} ${x.detail ?? ''}`).join('; ')}`);
        assert(report.results.find((x) => x.id === 'A07')?.status === 'pass', 'the card signature was not checked against its key directory');
        const shown = known.showName ?? (await lookup({ agent_id: known.agent_id })).json?.agent?.name !== undefined;
        if (shown) {
          assert(card.name === (known.name ?? card.name) && card.name !== known.agent_id, `the card is named ${JSON.stringify(card.name)}`);
        } else {
          assert(card.name === known.agent_id, `the card is named ${JSON.stringify(card.name)}, not by the agent id`);
          assert(card.description === ANONYMOUS_DESCRIPTION, `the description is ${JSON.stringify(card.description)}`);
        }
        assert(!/@|\/_stack\/|contact/i.test(JSON.stringify(card.skills) + String(card.documentationUrl)) && !JSON.stringify(card).includes(known.site), 'the card names an inbox, a contact form or a site');
      },
    },
    {
      id: 'AF02', level: 'MUST', title: 'serves the MCP server card of an agent, signed by the same key and open to any origin',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        const r = await http(filePath(known.agent_id, FILE_NAMES.mcp_server_card));
        assert(r.status === 200, `answered ${r.status}: ${r.text.slice(0, 160)}`);
        assert(r.headers.get('access-control-allow-origin') === '*', 'the card is not open to any origin');
        const { _meta, ...unsigned } = r.json ?? {};
        const signature = _meta?.[MCP_SIGNATURE_KEY];
        assert(signature && typeof signature.protected === 'string' && typeof signature.signature === 'string', `_meta carries no ${MCP_SIGNATURE_KEY}`);
        assert(Array.isArray(unsigned.remotes) && unsigned.remotes.length > 0 && /^https:|^http:\/\/(127\.0\.0\.1|localhost)/.test(unsigned.remotes[0].url), 'the card names no MCP endpoint');
        const header = JSON.parse(fromB64url(signature.protected).toString('utf8'));
        const directory = await http(filePath(known.agent_id, FILE_NAMES.key_directory));
        const key = directory.json?.keys?.find((k) => k.x && ed25519Thumbprint(k.x) === header.kid);
        assert(key, 'the key that signed the card is not in the agent\'s key directory');
        const input = `${signature.protected}.${b64url(canonicalJson(unsigned))}`;
        assert(cryptoVerify(null, Buffer.from(input), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' }), fromB64url(signature.signature)), 'the signature does not verify over the protected header and the canonical card');
      },
    },
    {
      id: 'AF03', level: 'MUST', title: 'serves the Web Bot Auth key directory of an agent: it passes the directory checks of the web-bot-auth suite',
      async run() {
        if (needsServer ?? needsKnown) return needsServer ?? needsKnown;
        const host = new URL(origin).host;
        const report = await runWebBotAuthSuite({
          directoryHost: host,
          directory: async () => {
            const response = await fetchImpl(`${origin}${filePath(known.agent_id, FILE_NAMES.key_directory)}`, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
            return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() };
          },
        });
        const failed = report.results.filter((x) => x.status === 'fail' && x.level === 'MUST');
        assert(failed.length === 0, `the directory checks failed: ${failed.map((x) => `${x.id} ${x.detail ?? ''}`).join('; ')}`);
      },
    },
    {
      id: 'AF04', level: 'MUST', title: 'serves no file for an agent that does not exist or has an id of no form: the 404 of section 7, the same for each, and nothing repeated',
      async run() {
        if (needsServer) return needsServer;
        let expected;
        for (const name of Object.values(FILE_NAMES)) {
          for (const id of [randomId(), 'agt_short', 'not-an-id']) {
            const r = await http(filePath(id, name));
            assert(r.status === 404 && JSON.stringify(r.json) === JSON.stringify(NOT_FOUND_BODY), `${name} for ${id} answered ${r.status}: ${r.text.slice(0, 160)}`);
            expected ??= refusalOf(r);
            assert(refusalOf(r) === expected, `${name} for ${id} answered differently from the first refusal:\n${refusalOf(r)}\n${expected}`);
            assert(!r.text.includes(id), `the answer for ${name} repeats ${id}`);
          }
        }
      },
    },
    {
      id: 'AF05', level: 'MUST', title: 'serves no file for a closed agent or one its owner switched off: the same 404 as for an agent that does not exist',
      async run() {
        if (needsServer) return needsServer;
        if (!closed && !hidden) return skip('needs closed or hidden: an agent that is closed or switched off');
        const expected = refusalOf(await http(filePath(randomId(), FILE_NAMES.agent_card)));
        for (const agentId of [closed?.agent_id, hidden?.agent_id].filter(Boolean)) {
          for (const name of Object.values(FILE_NAMES)) {
            const r = await http(filePath(agentId, name));
            assert(refusalOf(r) === expected, `${name} of an agent that is closed or switched off answered differently from an unknown agent:\n${refusalOf(r)}`);
          }
        }
      },
    },
  ];

  // ─── the verifier ───
  const verifierChecks = verifierCases(vectors);
  async function judge(testCase) {
    const options = { jwks: vectors.jwks, now: new Date(vectors.now * 1000), issuer: vectors.issuer, ...(testCase.expect ? { expect: testCase.expect } : {}) };
    try {
      const out = await verifier(testCase.statement_parts.join('.'), options);
      if (out === false || out === null || out === undefined || (isObject(out) && out.ok === false)) return { accepted: false };
      return { accepted: true, claims: isObject(out) && 'claims' in out ? out.claims : out };
    } catch (error) {
      return { accepted: false, error };
    }
  }
  const verifierNeeds = !verifier ? skip('needs verifier: a function that checks a statement') : !vectors ? skip('needs vectors: fixtures/agent-identity/vectors.json') : null;
  for (const { id, level, title, cases, accepts } of verifierChecks) {
    checks.push({
      id, level, title,
      async run() {
        if (verifierNeeds) return verifierNeeds;
        for (const caseId of cases) {
          const testCase = vectors.cases.find((c) => c.id === caseId);
          assert(testCase, `the vectors have no case ${caseId}`);
          const result = await judge(testCase);
          if (accepts) {
            assert(result.accepted, `refused ${testCase.id} (${testCase.title})${result.error ? `: ${result.error.message}` : ''}`);
            const agent = result.claims?.identity?.agent ?? result.claims?.agent;
            assert(agent?.id === testCase.agent_id, `accepted ${testCase.id} but returned the agent ${JSON.stringify(agent?.id)}, expected ${testCase.agent_id}`);
          } else {
            assert(!result.accepted, `accepted ${testCase.id}: ${testCase.title}`);
          }
        }
      },
    });
  }

  return runChecks('agent identity', checks);
}

/** The verifier checks: which vector cases each judges. */
function verifierCases(vectors) {
  const ids = (predicate) => (vectors?.cases ?? []).filter(predicate).map((c) => c.id);
  const group = (name) => ids((c) => c.group === name);
  return [
    { id: 'AV01', level: 'MUST', title: 'accepts a statement that is right, found by key id, by site or by agent id, and a statement signed by a retired key the key set still holds, and returns the agent', accepts: true, cases: group('valid') },
    { id: 'AV02', level: 'MUST', title: 'refuses a statement that has expired, and one made in the future', cases: group('time') },
    { id: 'AV03', level: 'MUST', title: 'refuses a token whose type is not an identity statement\'s, whose alg is not EdDSA (none, a MAC under the public key) or that is not a compact JWS', cases: group('header') },
    { id: 'AV04', level: 'MUST', title: 'refuses a token with a Passport\'s audience, another issuer, a subject that is not the agent, another version, or no identity', cases: group('claims') },
    { id: 'AV05', level: 'MUST', title: 'refuses an altered payload, a key the key set does not hold, and a signature made by another key under a key id it does hold', cases: group('signature') },
    { id: 'AV06', level: 'MUST', title: 'refuses a statement that is valid but about something other than what was asked', cases: group('lookup') },
    { id: 'AV07', level: 'SHOULD', title: 'refuses a statement that is good for longer than 900 seconds', cases: group('lifetime') },
  ];
}

/** Canonical JSON, as the specifications define it (RFC 8785 for what a card holds): keys sorted at every depth, no whitespace. */
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
