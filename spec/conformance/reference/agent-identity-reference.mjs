// A reference server and a reference verifier of the agent identity specification
// (spec/agent-identity/SPEC.md), written from the specification with node:crypto and nothing else,
// in the way a small deployment would write them. They share no code with the kit's own judge
// (`src/agent-identity.mjs`), so a pass means two independent readings agree. Each can be made to
// break one rule on purpose (`defect`), and the suite must fail exactly the checks that rule is
// judged by.

import { createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { referenceDirectoryResponse } from './web-bot-auth-reference.mjs';

const TYP = 'stack-agent-identity+jwt';
const AUDIENCE = 'stack:agent-identity';
const ISSUER = 'getstack.run';
const TTL = 300;
const MAX_TTL = 900;
const SKEW = 5;
const LOOKUPS_PER_MINUTE = 60;
const FILES_PER_MINUTE = 120;
const ANONYMOUS = 'An AI agent operated through STACK.';

const b64 = (data) => Buffer.from(data).toString('base64url');
const thumbprint = (x) => createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
const canonical = (v) => (Array.isArray(v) ? `[${v.map(canonical).join(',')}]` : v && typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}` : JSON.stringify(v));

/** A test agent: its own Ed25519 key (the key of its signed requests and its cards), a site and the facts about it. */
export function makeAgent(over = {}) {
  const pair = generateKeyPairSync('ed25519');
  const jwk = pair.privateKey.export({ format: 'jwk' });
  const id = over.id ?? `agt_${randomBytes(16).toString('base64url').slice(0, 21)}`;
  return {
    id,
    site: `${id.slice(4, 12).toLowerCase().replace(/[^a-z0-9]/g, 'x')}.sites.example`,
    status: 'active',
    enabled: true,
    showName: false,
    name: 'Acme Helper',
    owner: { identity_verified: true, good_standing: true },
    key: { x: jwk.x, d: jwk.d },
    keyId: thumbprint(jwk.x),
    ...over,
  };
}

/** The deployment's issuer key (a TEST key) and its JWKS. */
function makeIssuerKey() {
  const pair = generateKeyPairSync('ed25519');
  const jwk = pair.privateKey.export({ format: 'jwk' });
  return { privateKey: pair.privateKey, jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid: 'ref-v1', alg: 'EdDSA', use: 'sig' } };
}

const NOT_FOUND = { error: { code: 'AGENT_IDENTITY_NOT_FOUND', message: 'No agent answers to this lookup.' } };
const INVALID = { error: { code: 'AGENT_IDENTITY_LOOKUP_INVALID', message: 'A lookup names exactly one of key_id, site and agent_id, each in its own form.' } };

const FORMS = {
  key_id: /^[A-Za-z0-9_-]{43}$/,
  agent_id: /^agt_[A-Za-z0-9_-]{21}$/,
  site: /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/,
};

/** What an account's status says about the agent, or null while it is still opening. */
const statusOf = (account) => ({ active: 'active', suspended: 'suspended', closed: 'closed' })[account.status] ?? null;

/**
 * @param {{ agents: ReturnType<typeof makeAgent>[], defect?: string, now?: () => Date }} options
 *   `defect` breaks one rule: echo-in-404, closed-by-site, closed-differs, hidden-differs, aud-passport,
 *   no-typ, ttl-1h, name-leaks, extra-member, json-differs, cacheable, two-selectors, unsigned-card,
 *   card-names-site, no-limit, invalid-repeats.
 */
export function createReferenceIdentityServer({ agents, defect, now = () => new Date() }) {
  const issuer = makeIssuerKey();
  const hits = new Map();
  let origin = '';

  const sendJson = (res, status, body, extra = {}) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra });
    res.end(JSON.stringify(body));
  };
  const limited = (source, bucket, allowed) => {
    if (defect === 'no-limit') return false;
    const minute = Math.floor(now().getTime() / 60_000);
    const key = `${bucket}:${source}:${minute}`;
    hits.set(key, (hits.get(key) ?? 0) + 1);
    return hits.get(key) > allowed;
  };
  const refuse = (res, asked) => {
    if (defect === 'echo-in-404') return sendJson(res, 404, { error: { ...NOT_FOUND.error, message: `No agent answers to ${asked}.` } });
    return sendJson(res, 404, NOT_FOUND);
  };

  /** The agent a lookup finds, or null for every reason there is none. */
  function find(selector, value) {
    let agent;
    let guessable = false;
    if (selector === 'key_id') agent = agents.find((a) => a.keyId === value && a.status !== 'closed');
    else if (selector === 'site') {
      agent = agents.find((a) => a.site === value.toLowerCase());
      guessable = true;
    } else agent = agents.find((a) => a.id === value);
    if (!agent || !agent.enabled) return null;
    const status = statusOf(agent);
    if (!status) return null;
    if (status === 'closed' && guessable && defect !== 'closed-by-site') return null;
    return { agent, status };
  }

  function statement(agent, status, lookup) {
    const shownName = defect === 'name-leaks' || agent.showName;
    const facts = {
      v: 1,
      agent: { id: agent.id, ...(shownName ? { name: agent.name } : {}), status },
      owner: { ...agent.owner, ...(defect === 'extra-member' ? { email: 'owner@example.test' } : {}) },
      lookup,
    };
    const iat = Math.floor(now().getTime() / 1000);
    const exp = iat + (defect === 'ttl-1h' ? 3600 : TTL);
    const header = defect === 'no-typ' ? { alg: 'EdDSA', kid: issuer.jwk.kid } : { alg: 'EdDSA', kid: issuer.jwk.kid, typ: TYP };
    const claims = { iss: ISSUER, aud: defect === 'aud-passport' ? 'stack:passport' : AUDIENCE, sub: agent.id, iat, exp, identity: facts };
    const input = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(claims))}`;
    const token = `${input}.${sign(null, Buffer.from(input), issuer.privateKey).toString('base64url')}`;
    const plain = defect === 'json-differs' ? { ...facts, owner: { ...facts.owner, good_standing: true } } : facts;
    return { statement: token, agent: plain.agent, owner: plain.owner, lookup, issued_at: iat, expires_at: exp };
  }

  function card(agent) {
    const shown = agent.showName;
    const body = {
      name: shown ? agent.name : agent.id,
      description: shown ? `${agent.name} is an AI agent operated through the reference server.` : ANONYMOUS,
      url: `${origin}/v1/a2a/jsonrpc`,
      version: '1.0.0',
      protocolVersion: '0.3.0',
      supportedInterfaces: [{ url: `${origin}/v1/a2a/jsonrpc`, protocolBinding: 'JSONRPC', protocolVersion: '0.3' }],
      provider: { organization: 'reference', url: 'https://example.com' },
      documentationUrl: defect === 'card-names-site' ? `https://${agent.site}` : `${origin}/v1/agent-identity?agent_id=${agent.id}`,
      capabilities: { streaming: false, pushNotifications: false },
      defaultInputModes: ['text/plain'],
      defaultOutputModes: ['text/plain'],
      skills: [{ id: 'identity', name: 'Identity', description: `Who this agent is: ${origin}/v1/agent-identity?agent_id=${agent.id}`, tags: ['identity'] }],
    };
    if (defect === 'unsigned-card') return body;
    const protectedHeader = b64(JSON.stringify({ alg: 'EdDSA', kid: agent.keyId, typ: 'JOSE', jku: `${origin}/v1/agent-identity/agents/${agent.id}/http-message-signatures-directory` }));
    const input = `${protectedHeader}.${b64(canonical(body))}`;
    const key = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: agent.key.d, x: agent.key.x }, format: 'jwk' });
    return { ...body, signatures: [{ protected: protectedHeader, signature: sign(null, Buffer.from(input), key).toString('base64url') }] };
  }

  function mcpCard(agent) {
    const body = {
      $schema: 'https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json',
      name: `run.getstack/agent-${agent.id}`,
      title: agent.showName ? agent.name : agent.id,
      version: '1.0.0',
      description: agent.showName ? `${agent.name} is an AI agent operated through the reference server.` : ANONYMOUS,
      websiteUrl: `${origin}/v1/agent-identity?agent_id=${agent.id}`,
      remotes: [{ type: 'streamable-http', url: `${origin}/mcp`, supportedProtocolVersions: ['2025-06-18'] }],
    };
    const protectedHeader = b64(JSON.stringify({ alg: 'EdDSA', kid: agent.keyId, typ: 'JOSE', jku: `${origin}/v1/agent-identity/agents/${agent.id}/http-message-signatures-directory` }));
    const input = `${protectedHeader}.${b64(canonical(body))}`;
    const key = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: agent.key.d, x: agent.key.x }, format: 'jwk' });
    return { ...body, _meta: { 'run.getstack/signature': { protected: protectedHeader, signature: sign(null, Buffer.from(input), key).toString('base64url') } } };
  }

  const handler = (req, res) => {
    const url = new URL(req.url, 'http://reference.invalid');
    const source = req.socket.remoteAddress ?? 'unknown';
    if (req.method !== 'GET') return sendJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } });

    if (url.pathname === '/v1/.well-known/jwks.json') return sendJson(res, 200, { keys: [issuer.jwk] }, { 'cache-control': 'public, max-age=300' });

    const tooMany = () => sendJson(res, 429, { error: { code: 'RATE_LIMITED', message: 'Too many requests' } }, { 'retry-after': '60' });

    if (url.pathname === '/v1/agent-identity') {
      if (limited(source, 'lookup', LOOKUPS_PER_MINUTE)) return tooMany();
      const names = [...url.searchParams.keys()];
      const allowed = names.filter((n) => n in FORMS);
      const asked = allowed.filter((n) => FORMS[n].test(url.searchParams.get(n) ?? ''));
      const wellFormed = names.length === allowed.length && allowed.length === asked.length;
      const exactlyOne = defect === 'two-selectors' ? allowed.length >= 1 : allowed.length === 1;
      if (!wellFormed || !exactlyOne) {
        const repeated = defect === 'invalid-repeats' ? { error: { ...INVALID.error, message: `Bad lookup: ${url.search}` } } : INVALID;
        return sendJson(res, 400, repeated);
      }
      const selector = asked[0];
      const value = url.searchParams.get(selector);
      const found = find(selector, value);
      if (!found) {
        // A closed agent asked for by something guessable is told apart, and so is one that is switched off.
        const known = agents.find((a) => (selector === 'key_id' ? a.keyId === value : selector === 'site' ? a.site === value.toLowerCase() : a.id === value));
        if (known && defect === 'closed-differs' && known.status === 'closed') return sendJson(res, 410, { error: { code: 'AGENT_CLOSED', message: 'This agent is closed.' } });
        if (known && defect === 'hidden-differs' && !known.enabled) return sendJson(res, 403, { error: { code: 'AGENT_HIDDEN', message: 'Hidden.' } });
        return refuse(res, value);
      }
      const lookup = { [selector]: selector === 'site' ? value.toLowerCase() : value };
      return sendJson(res, 200, statement(found.agent, found.status, lookup), defect === 'cacheable' ? { 'cache-control': 'public, max-age=300' } : {});
    }

    const file = /^\/v1\/agent-identity\/agents\/([^/]+)\/(agent-card\.json|mcp-server-card\.json|http-message-signatures-directory)$/.exec(url.pathname);
    if (file) {
      if (limited(source, 'file', FILES_PER_MINUTE)) return tooMany();
      const agent = FORMS.agent_id.test(file[1]) ? agents.find((a) => a.id === file[1]) : undefined;
      const status = agent ? statusOf(agent) : null;
      if (!agent || !agent.enabled || (status !== 'active' && status !== 'suspended')) return refuse(res, file[1]);
      if (file[2] === 'agent-card.json') return sendJson(res, 200, card(agent), { 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=60' });
      if (file[2] === 'mcp-server-card.json') return sendJson(res, 200, mcpCard(agent), { 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=60' });
      const directory = referenceDirectoryResponse({ authority: req.headers.host, keys: [{ x: agent.key.x, nbf: Math.floor(now().getTime() / 1000) - 3600 }], signingKey: agent.key, now: now() });
      res.writeHead(directory.status, { ...directory.headers, 'access-control-allow-origin': '*' });
      return res.end(directory.body);
    }
    return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'not found' } });
  };

  return {
    handler,
    jwks: { keys: [issuer.jwk] },
    /** Start on an ephemeral loopback port. */
    async listen() {
      const server = createServer(handler);
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      origin = `http://127.0.0.1:${server.address().port}`;
      return { url: origin, close: () => new Promise((resolve) => server.close(resolve)) };
    },
  };
}

// ─── The verifier ────────────────────────────────────────────────

const fromB64 = (text) => Buffer.from(text, 'base64url');

/**
 * Check a statement as section 12 says. Returns the claims, or throws. A `defect` skips one check:
 * any-type, passport-audience, expired, alg-none, ignore-lookup, ignore-version, ignore-subject,
 * long-lived, hs256, any-issuer.
 */
export function createReferenceVerifier({ defect } = {}) {
  return function verifyStatement(token, { jwks, now, issuer = ISSUER, expect }) {
    const parts = typeof token === 'string' ? token.split('.') : [];
    if (parts.length !== 3) throw new Error('not a compact JWS');
    const header = JSON.parse(fromB64(parts[0]).toString('utf8'));
    const claims = JSON.parse(fromB64(parts[1]).toString('utf8'));
    if (defect !== 'alg-none' && defect !== 'hs256' && header.alg !== 'EdDSA') throw new Error('alg');
    if (defect === 'alg-none' && header.alg === 'none') {
      // Defective: trusts an unsigned token.
    } else if (defect === 'hs256' && header.alg === 'HS256') {
      // Defective: checks a MAC made with the public key.
      const key = (jwks.keys ?? jwks).find((k) => k.kid === header.kid);
      if (!key) throw new Error('unknown key');
      const expected = createHmac('sha256', fromB64(key.x)).update(`${parts[0]}.${parts[1]}`).digest('base64url');
      if (expected !== parts[2]) throw new Error('mac');
    } else {
      if (defect !== 'any-type' && header.typ !== TYP) throw new Error('typ');
      const key = (jwks.keys ?? jwks).find((k) => k.kid === header.kid);
      if (!key) throw new Error('unknown key');
      const ok = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' }), fromB64(parts[2]));
      if (!ok) throw new Error('signature');
    }
    if (defect !== 'any-issuer' && claims.iss !== issuer) throw new Error('iss');
    if (defect !== 'passport-audience' && claims.aud !== AUDIENCE) throw new Error('aud');
    const at = Math.floor(now.getTime() / 1000);
    if (defect !== 'expired' && at >= claims.exp + SKEW) throw new Error('expired');
    if (at + SKEW < claims.iat) throw new Error('made in the future');
    if (defect !== 'long-lived' && claims.exp - claims.iat > MAX_TTL) throw new Error('too long');
    if (!claims.identity) throw new Error('no identity');
    if (defect !== 'ignore-version' && claims.identity.v !== 1) throw new Error('version');
    if (defect !== 'ignore-subject' && claims.sub !== claims.identity.agent?.id) throw new Error('sub');
    if (defect !== 'ignore-lookup' && expect) {
      const [by] = Object.keys(expect);
      if (claims.identity.lookup?.[by] !== expect[by] || Object.keys(claims.identity.lookup).length !== 1) throw new Error('lookup');
    }
    return claims;
  };
}
