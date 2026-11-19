// A reference SERVICE of the STACK network (spec/network/SPEC.md): an in-memory
// implementation of the calls the specification defines, written from the
// specification alone with Node's crypto and http. It is the implementation the
// `network-service` suite is tested against in this repository (STACK's own hosted
// service passes the same suite in STACK's private continuous integration), and a
// starting point for a service of your own. It keeps everything in memory and has
// no accounts: an install is registered by calling `service.registerInstall`.
//
// `quirk` builds a service with ONE deliberate defect, for the kit's own tests:
//   'no-replay'          accepts the same install proof twice
//   'any-action'         does not check that the proof asks for the call it is sent to
//   'extra-claims'       accepts install proofs with claims the action does not have
//   'long-proofs'        accepts install proofs that live longer than 120 seconds
//   'cached-list'        serves the revocation list with a cacheable header
//   'forged-is-error'    answers a forged countersignature with an HTTP error, not a verdict
//   'countersign-revoked' countersigns an agent that is revoked
//   'no-agent-revoke'    does not let a revoked agent show in the online check or the statement
//   'wrong-typ'          signs the revocation list under the typ of a statement
//   'cursor-skips'       gives `next` one too high on a full page
//   'open-countersign'   takes any bearer as an install proof
//   'ownerless-entry'    lists a revocation that names no install

import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from 'node:crypto';
import { createServer } from 'node:http';
import { keyFromSeed } from '../src/passport-verifier.mjs';
import { canonicalize } from '../src/canonical.mjs';
import {
  installKeyThumbprint,
  NETWORK_AUDIENCE,
  NETWORK_INSTALL_PROOF_TYP,
  NETWORK_KINDS,
  passportDigest,
  signNetworkObject,
} from '../src/network-vectors.mjs';
import { listen } from './support.mjs';

const KID_RE = /^[A-Za-z0-9_-]{43}$/;
const JTI_RE = /^[A-Za-z0-9_-]{16,64}$/;
const DIGEST_RE = /^[A-Za-z0-9_-]{43}$/;
const COMPACT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const INSTALL_RE = /^ins_[A-Za-z0-9_-]{16,40}$/;
const REVOCATION_KINDS = ['passport', 'agent', 'key', 'install'];
const REASONS = ['unspecified', 'key_compromise', 'agent_decommissioned', 'superseded', 'policy_violation', 'owner_request'];

class Refusal extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}
const proofRefusal = (reason) => new Refusal(401, 'INSTALL_PROOF_INVALID', 'The install proof was refused', { reason });

const RULE_PACKS = [
  { id: 'prompt_injection', direction: 'input', rules: [{ id: 'override_ignore_previous', severity: 'critical', pattern: '\\bignore\\s+all\\s+previous\\s+instructions\\b', flags: 'i' }] },
  { id: 'output_injection', direction: 'output', rules: [{ id: 'exfil_marker', severity: 'warning', pattern: 'BEGIN EXFILTRATION', flags: '' }] },
];

export async function startReferenceNetworkService({ quirk = 'none', now = () => Math.floor(Date.now() / 1000) } = {}) {
  const stack = keyFromSeed(0x51, 'reference-network-1');
  const jwks = { keys: [stack.publicJwk] };
  const installs = new Map(); // id -> { id, owner, status }
  const keys = new Map(); // kid -> { install, jwk, status, validUntil }
  const countersignatures = []; // { id, install, kid, owner, digest, jti, agent, exp }
  const revocations = []; // entries, in seq order
  const seen = new Set(); // install:jti
  let seq = 0;

  const sign = (kind, body, options) => signNetworkObject(kind, body, { key: stack, now: now(), ...options });

  const service = {
    jwks,
    /** Register an install and its key (the owner's side of the specification, which this reference does not model). */
    registerInstall(id, publicJwk, owner = 'op_reference') {
      installs.set(id, { id, owner, status: 'active' });
      keys.set(installKeyThumbprint(publicJwk), { install: id, jwk: publicJwk, status: 'active', validUntil: null });
    },
    revokeKey(kid) { keys.get(kid).status = 'revoked'; },
    revocations,
    countersignatures,
  };

  function covering(cs) {
    return revocations.find((r) =>
      (r.kind === 'passport' && r.subject === cs.digest)
      || (r.kind === 'key' && r.subject === cs.kid)
      || (r.kind === 'install' && r.subject === cs.install)
      || (r.kind === 'agent' && cs.agent && r.subject === cs.agent && r.install === cs.install));
  }

  /** Section 6.3: the install proof, checked. */
  function authenticate(req, act) {
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
    if (token.length === 0 || token.length > 4096) throw new Refusal(401, 'INVALID_API_KEY', 'Invalid API key');
    let head;
    try {
      head = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
    } catch {
      head = null;
    }
    if (!head || head.typ !== NETWORK_INSTALL_PROOF_TYP) throw new Refusal(401, 'INSTALL_PROOF_REQUIRED', 'This call must be signed with an install key');
    if (head.alg !== 'EdDSA' || typeof head.kid !== 'string' || !KID_RE.test(head.kid)) throw proofRefusal('malformed');
    const entry = keys.get(head.kid);
    if (!entry) throw proofRefusal('unknown_key');
    const [h, p, s] = token.split('.');
    if (!s || !cryptoVerify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: entry.jwk, format: 'jwk' }), Buffer.from(s, 'base64url'))) throw proofRefusal('bad_signature');
    let claims;
    try {
      claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    } catch {
      throw proofRefusal('malformed');
    }
    if (claims.aud !== NETWORK_AUDIENCE) throw proofRefusal('bad_signature');
    const t = now();
    if (!Number.isInteger(claims.exp) || !Number.isInteger(claims.iat)) throw proofRefusal('malformed');
    if (claims.exp <= t - 60) throw proofRefusal('expired');
    const allowed = new Set(['iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'act']);
    const more = { countersign: ['pd', 'pjti', 'agent', 'ttl'], revoke: ['kind', 'subject', 'reason'] }[claims.act] ?? [];
    for (const m of more) allowed.add(m);
    if (quirk !== 'extra-claims' && Object.keys(claims).some((k) => !allowed.has(k))) throw proofRefusal('malformed');
    if (!['rules', 'classify', 'countersign', 'revoke'].includes(claims.act) || typeof claims.jti !== 'string' || !JTI_RE.test(claims.jti)) throw proofRefusal('malformed');
    if (claims.act === 'countersign' && (typeof claims.pd !== 'string' || !DIGEST_RE.test(claims.pd))) throw proofRefusal('malformed');
    if (claims.act === 'revoke' && (!REVOCATION_KINDS.includes(claims.kind) || typeof claims.subject !== 'string' || claims.subject.length === 0)) throw proofRefusal('malformed');
    if (quirk !== 'long-proofs' && claims.exp - claims.iat > 120) throw proofRefusal('malformed');
    if (claims.iat > t + 60) throw proofRefusal('malformed');
    if (claims.iss !== entry.install || claims.sub !== entry.install) throw proofRefusal('malformed');
    if (quirk !== 'any-action' && claims.act !== act) throw proofRefusal('wrong_action');
    if (installs.get(entry.install).status !== 'active') throw proofRefusal('install_revoked');
    if (entry.status !== 'active') throw proofRefusal('key_revoked');
    if (entry.validUntil !== null && entry.validUntil <= t) throw proofRefusal('key_expired');
    const mark = `${entry.install}:${claims.jti}`;
    if (quirk !== 'no-replay' && seen.has(mark)) throw new Refusal(401, 'INSTALL_PROOF_REPLAYED', 'This install proof was already used. Sign a new one for every request.');
    seen.add(mark);
    return { install: installs.get(entry.install), kid: head.kid, claims };
  }

  const strict = (value, allowed) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Refusal(400, 'VALIDATION_ERROR', 'The request is not an object');
    for (const k of Object.keys(value)) if (!allowed.includes(k)) throw new Refusal(400, 'VALIDATION_ERROR', `Unrecognized key ${k}`);
  };
  const parseJson = (text) => {
    if (text.length === 0) return undefined;
    try {
      return JSON.parse(text);
    } catch {
      throw new Refusal(400, 'INVALID_JSON', 'Request body is not valid JSON');
    }
  };
  const emptyBody = (body) => {
    if (body === undefined || body === null) return;
    strict(body, []);
  };

  const listEntries = (query) => {
    const params = new URLSearchParams(query);
    for (const k of params.keys()) if (!['after', 'limit', 'install'].includes(k)) throw new Refusal(400, 'VALIDATION_ERROR', `Unrecognized key ${k}`);
    const int = (name, min, max, fallback) => {
      if (!params.has(name)) return fallback;
      const v = params.get(name);
      if (!/^\d+$/.test(v) || Number(v) < min || Number(v) > max) throw new Refusal(400, 'VALIDATION_ERROR', `${name} is out of range`);
      return Number(v);
    };
    const after = int('after', 0, Number.MAX_SAFE_INTEGER, 0);
    const limit = int('limit', 1, 500, 200);
    const install = params.get('install');
    if (install !== null && !INSTALL_RE.test(install)) throw new Refusal(400, 'VALIDATION_ERROR', 'install is not an install id');
    const head = seq;
    const entries = revocations.filter((r) => r.seq > after && (install === null || r.install === install)).slice(0, limit);
    if (quirk === 'ownerless-entry' && install === null && after === 0 && entries.length < limit) {
      entries.push({ seq: seq + 1, id: 'rev_ownerless0000000000', kind: 'passport', subject: 'Z'.repeat(43), install: null, reason: 'owner_request', by: 'owner', at: new Date(now() * 1000).toISOString() });
    }
    let next = entries.length >= limit ? entries[entries.length - 1].seq : null;
    if (quirk === 'cursor-skips' && next !== null) next += 1;
    return { after, head, next, entries };
  };

  const decode = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  const readStack = (kind, token) => {
    const { typ, aud } = NETWORK_KINDS[kind];
    const [h, p, s] = token.split('.');
    const head = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    if (head.alg !== 'EdDSA' || head.typ !== typ || head.kid !== stack.kid) throw new Error('not signed by this service');
    if (!cryptoVerify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: stack.publicJwk, format: 'jwk' }), Buffer.from(s, 'base64url'))) throw new Error('bad signature');
    const payload = decode(token);
    if (payload.iss !== 'getstack.run' || payload.aud !== aud) throw new Error('wrong issuer or audience');
    return payload;
  };

  async function handle(req, res, bodyText) {
    const url = new URL(req.url, 'http://x');
    const path = url.pathname;
    const send = (status, body, headers = {}) => res.writeHead(status, { 'content-type': 'application/json', ...headers }).end(JSON.stringify(body));

    if (req.method === 'GET' && path === '/v1/network/jwks.json') return send(200, jwks, { 'cache-control': 'public, max-age=300' });

    if (req.method === 'GET' && path === '/v1/network/revocations') {
      const page = listEntries(url.search.slice(1));
      const list = sign('revocation_list', { rl: { v: 1, ...page } }, { ttl: 300, ...(quirk === 'wrong-typ' ? { typ: NETWORK_KINDS.verified.typ } : {}) });
      return send(200, { list }, { 'cache-control': quirk === 'cached-list' ? 'public, max-age=60' : 'no-store' });
    }

    if (req.method === 'POST' && path === '/v1/network/verify') {
      const body = parseJson(bodyText);
      strict(body, ['countersignature', 'passport']);
      for (const field of ['countersignature', 'passport']) {
        if (body[field] !== undefined && (typeof body[field] !== 'string' || body[field].length < 20 || body[field].length > 24_000 || !COMPACT_RE.test(body[field]))) throw new Refusal(400, 'VALIDATION_ERROR', `${field} is not a compact JWS`);
      }
      if (body.countersignature === undefined) throw new Refusal(400, 'VALIDATION_ERROR', 'countersignature is required');
      const verdict = { valid: false, reasons: [], checked_at: new Date(now() * 1000).toISOString(), install: null, owner: null, passport_digest: null, countersignature_expires_at: null, revoked: null };
      let claims;
      try {
        claims = readStack('countersignature', body.countersignature);
      } catch {
        if (quirk === 'forged-is-error') throw new Refusal(400, 'INVALID_REQUEST', 'not a countersignature of this service');
        verdict.reasons.push('countersignature_invalid');
        return send(200, verdict, { 'cache-control': 'no-store' });
      }
      if (claims.exp <= now() - 5) verdict.reasons.push('countersignature_expired');
      const cs = claims.cs;
      verdict.install = cs.install;
      verdict.owner = cs.owner;
      verdict.passport_digest = cs.passport.digest;
      verdict.countersignature_expires_at = new Date(claims.exp * 1000).toISOString();
      const row = countersignatures.find((c) => c.id === claims.jti);
      if (!row || row.install !== cs.install || row.digest !== cs.passport.digest) {
        verdict.reasons.push('countersignature_unknown');
        return send(200, verdict, { 'cache-control': 'no-store' });
      }
      const state = keys.get(row.kid);
      if (installs.get(row.install).status !== 'active') verdict.reasons.push('install_revoked');
      else if (state.status !== 'active') verdict.reasons.push('key_revoked');
      const hit = quirk === 'no-agent-revoke' ? undefined : covering(row);
      if (hit) {
        verdict.revoked = { kind: hit.kind, at: hit.at, reason: hit.reason };
        if (!verdict.reasons.includes('install_revoked') && !verdict.reasons.includes('key_revoked')) verdict.reasons.push('revoked');
      }
      if (body.passport !== undefined) {
        if (passportDigest(body.passport) !== cs.passport.digest) verdict.reasons.push('passport_digest_mismatch');
        else {
          try {
            const [h, p, s] = body.passport.split('.');
            const ok = cryptoVerify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: cs.key.jwk, format: 'jwk' }), Buffer.from(s, 'base64url'));
            if (!ok) verdict.reasons.push('passport_signature_invalid');
            else if (decode(body.passport).exp <= now() - 5) verdict.reasons.push('passport_expired');
          } catch {
            verdict.reasons.push('passport_signature_invalid');
          }
        }
      }
      verdict.valid = verdict.reasons.length === 0;
      return send(200, verdict, { 'cache-control': 'no-store' });
    }

    if (req.method === 'GET' && path === '/v1/network/verified') {
      const q = Object.fromEntries(url.searchParams);
      strict(q, ['passport_digest', 'install', 'agent']);
      const byDigest = q.passport_digest !== undefined;
      if (byDigest === (q.install !== undefined && q.agent !== undefined) || (q.install === undefined) !== (q.agent === undefined)) throw new Refusal(400, 'VALIDATION_ERROR', 'Give either passport_digest, or install and agent together');
      if (byDigest && !DIGEST_RE.test(q.passport_digest)) throw new Refusal(400, 'VALIDATION_ERROR', 'passport_digest is not a digest');
      if (!byDigest && !INSTALL_RE.test(q.install)) throw new Refusal(400, 'VALIDATION_ERROR', 'install is not an install id');
      const matching = countersignatures.filter((c) => (byDigest ? c.digest === q.passport_digest : c.install === q.install && c.agent === q.agent));
      const row = matching.sort((a, b) => b.exp - a.exp)[0];
      if (!row) throw new Refusal(404, 'NOT_FOUND', 'Countersignature not found');
      let status = 'live';
      if ((quirk !== 'no-agent-revoke' && covering(row)) || installs.get(row.install).status !== 'active' || keys.get(row.kid).status !== 'active') status = 'revoked';
      else if (row.exp <= now()) status = 'expired';
      const statement = sign('verified', {
        vs: { v: 1, mark: 'STACK-verified', status, install: row.install, countersignature: row.id, valid_until: new Date(row.exp * 1000).toISOString(), passport_digest: row.digest },
      }, { ttl: 300, subject: byDigest ? `passport:${row.digest}` : `agent:${row.install}:${row.agent}` });
      return send(200, { status, statement }, { 'cache-control': 'no-store' });
    }

    if (req.method === 'POST' && path === '/v1/network/countersignatures') {
      const auth = quirk === 'open-countersign'
        ? { install: [...installs.values()][0], kid: [...keys.keys()][0], claims: { pd: passportDigest('open'), agent: 'open' } }
        : authenticate(req, 'countersign');
      emptyBody(parseJson(bodyText));
      const { claims } = auth;
      const ttl = claims.ttl ?? 900;
      if (!Number.isInteger(ttl) || ttl < 60 || ttl > 3600) throw proofRefusal('malformed');
      const row = { id: `csg_${randomBytes(15).toString('base64url')}`, install: auth.install.id, kid: auth.kid, owner: auth.install.owner, digest: claims.pd, jti: claims.pjti, agent: claims.agent, exp: now() + ttl };
      if (quirk !== 'countersign-revoked' && covering(row)) throw new Refusal(409, 'CONFLICT', 'This passport or agent is revoked and cannot be countersigned');
      const entry = keys.get(auth.kid);
      const token = sign('countersignature', {
        cs: {
          v: 1, install: row.install, owner: row.owner, owner_verified: false, key: { kid: auth.kid, jwk: entry.jwk },
          passport: { alg: 'sha256', digest: row.digest, ...(row.jti ? { jti: row.jti } : {}), ...(row.agent ? { agent: row.agent } : {}) },
        },
      }, { ttl, subject: row.install, jti: row.id });
      countersignatures.push(row);
      return send(201, { id: row.id, countersignature: token, expires_at: new Date(row.exp * 1000).toISOString(), install: row.install, passport_digest: row.digest });
    }

    if (req.method === 'POST' && path === '/v1/network/revocations') {
      const auth = authenticate(req, 'revoke');
      const { claims } = auth;
      if (claims.kind === 'install' && claims.subject !== auth.install.id) throw new Refusal(404, 'NOT_FOUND', 'Install not found');
      if (claims.kind === 'key' && keys.get(claims.subject)?.install !== auth.install.id) throw new Refusal(404, 'NOT_FOUND', 'Install key not found');
      const reason = claims.reason ?? 'unspecified';
      if (!REASONS.includes(reason)) throw proofRefusal('malformed');
      let entry = revocations.find((r) => r.kind === claims.kind && r.subject === claims.subject && r.install === auth.install.id);
      if (!entry) {
        seq += 1;
        entry = { seq, id: `rev_${randomBytes(15).toString('base64url')}`, kind: claims.kind, subject: claims.subject, install: auth.install.id, reason, by: 'install', at: new Date(now() * 1000).toISOString() };
        revocations.push(entry);
      }
      return send(201, entry);
    }

    if (req.method === 'POST' && path === '/v1/network/detection/rules') {
      authenticate(req, 'rules');
      emptyBody(parseJson(bodyText));
      const sha256 = createHash('sha256').update(canonicalize(RULE_PACKS)).digest('hex');
      const version = `r1-${sha256.slice(0, 12)}`;
      const statement = sign('detection_rules', { rs: { v: 1, version, revision: 1, sha256, packs: RULE_PACKS } }, { ttl: 72 * 3600 });
      return send(200, { version, revision: 1, expires_at: new Date((now() + 72 * 3600) * 1000).toISOString(), statement });
    }

    if (req.method === 'POST' && path === '/v1/network/detection/classify') {
      authenticate(req, 'classify');
      const body = parseJson(bodyText);
      strict(body, ['content', 'context']);
      const { content } = body;
      const text = typeof content === 'string' ? content : JSON.stringify(content);
      if (content === undefined || text.length === 0 || text.length > 200_000) throw new Refusal(400, 'INVALID_REQUEST', 'content is not 1 to 200,000 characters');
      let match = null;
      for (const rule of RULE_PACKS[0].rules) {
        const m = new RegExp(rule.pattern, rule.flags).exec(text);
        if (m) { match = { pattern_id: rule.id, severity: rule.severity, field_path: 'content', matched_excerpt: m[0] }; break; }
      }
      return send(200, { verdict: match ? 'critical' : 'clean', request_id: `ses_${randomBytes(9).toString('base64url')}`, duration_ms: 1, rules_version: 'r1', match, llm: null, l3_degraded: null });
    }

    throw new Refusal(404, 'NOT_FOUND', 'No such route');
  }

  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      handle(req, res, Buffer.concat(chunks).toString('utf8')).catch((error) => {
        const refusal = error instanceof Refusal ? error : new Refusal(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
        res.writeHead(refusal.status, { 'content-type': 'application/json' }).end(JSON.stringify({ error: { code: refusal.code, message: refusal.message, details: refusal.details } }));
      });
    });
  });
  const listening = await listen(server);
  return { ...service, url: listening.url, close: listening.close };
}

