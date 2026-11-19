// A small server of the wire contract of agent key enrollment, fleet enrollment and the online half of a Passport
// (spec/agent-auth/SPEC.md sections 3 to 6, spec/agent-keys/SPEC.md section 4, spec/passport/SPEC.md sections 7 to 11),
// written from the specifications with nothing but node:crypto and node:http. It keeps everything in memory. It is the
// public reference the `agent-enrollment`, `fleet-enrollment` and `passport-online` suites run against in continuous
// integration, and the starting point for a server of your own.
//
// What it is not: a deployment. It has one operator, one credential, no persistence and no rate limits, and its
// "person" is a function (`approve`) the test calls. The wire contract is the whole of what it implements.
//
// `quirk` turns on ONE deliberate defect, for the tests of the suites themselves (identity-reference.test.mjs): a
// conformance kit that cannot fail a broken server would certify anything.

import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { createAgentJwtVerifier } from './agent-jwt-reference.mjs';

export const IDENTITY_QUIRKS = [
  'none',
  // Key enrollment (agent-auth section 5)
  'challenge-ttl', // a challenge lives 600 seconds, not 300
  'challenge-repeat', // every challenge of an agent is the same text
  'no-pop', // the signature over the challenge is not checked
  'any-challenge', // a challenge issued for another agent is accepted
  'no-approval', // a credential enrolls a key without a person's approval
  'approval-unbound', // an approval is good for any key
  'challenge-reuse', // a challenge can be used again
  'overwrite-key', // a second enrollment without force replaces the key
  'managed-enroll', // a key is enrolled for an agent whose key STACK holds
  'jwks-private', // the key set carries the private member
  'jwks-kid', // the key set names the key with another identifier
  'ticket-reuse', // an enrollment ticket can be used again
  'ticket-any-agent', // a ticket works for any agent
  'garbage-bearer', // any bearer is taken for a credential on the enrollment calls
  'rotate-keeps-old', // after a rotation the old key still signs in
  // Fleet enrollment (agent-auth section 6)
  'fleet-any-caller', // the operator's own key is given a fleet challenge
  'fleet-no-proof', // the worker's proof is not checked
  'fleet-challenge-reuse', // a fleet challenge can be used again
  'fleet-duplicate', // a repeat of an enrollment makes a second agent
  'fleet-name-ignored', // the same idempotency key with another name is accepted
  'fleet-open-rotation', // a worker's key is replaced without a proof by the previous key
  'fleet-extra-members', // a member the schema does not name is accepted
  'fleet-worker-enrolls', // an enrolled worker can enroll others
  'fleet-long-lease', // the lease is longer than the policy's
  // Passports (passport sections 7 to 11)
  'verify-valid-false', // a Passport that is not accepted is a 200 with valid false
  'verify-no-signature', // the signature is not checked
  'verify-alg-none', // alg none is accepted
  'verify-500', // a token that is not a Passport is a server error
  'revocation-ignored', // online verification does not read revocation
  'no-cascade', // revoking a Passport leaves its descendants
  'mission-keeps', // a Mission that ends leaves its Passports
  'revoke-agent-all', // revoking one agent revokes every agent's Passports
  'depth-unlimited', // delegation has no depth limit
  'child-outlives', // a child may live longer than its parent
  'accountability-down', // a child may be less accountable than its parent
  'scope-escalation', // a child may hold a scope its parent lacks
  'drops-constraints', // a child does not keep the parent's constraints
  'long-lived', // a Passport lives an hour by default
  'channel-silent', // nothing is published on the revocation channel
  'revoked-parent-delegates', // a revoked Passport can be delegated from
];

const ISSUER = 'reference.example';
const OPERATOR = 'op_reference';
const MAX_DEPTH = 4;
const RANK = { standard: 0, logged: 1, enforced: 2 };

const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const rand = (bytes = 15) => randomBytes(bytes).toString('base64url');
const id = (prefix) => `${prefix}_${rand()}`;
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const thumbprint = (x) => createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');

/** An Ed25519 public key from the `x` of a JWK, or null when it cannot be read. */
function publicKeyOf(x) {
  try {
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
  } catch {
    return null;
  }
}

function verifyText(x, text, signature) {
  const key = publicKeyOf(x);
  if (!key || typeof signature !== 'string') return false;
  try {
    return verify(null, Buffer.from(text, 'utf8'), key, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

const ED25519_X = /^[A-Za-z0-9_-]{43}$/;
/** The key of an enroll body as the schema reads it: Ed25519, 43 characters. Other members are ignored. */
function readKey(value) {
  if (!isObject(value) || value.kty !== 'OKP' || value.crv !== 'Ed25519' || typeof value.x !== 'string' || !ED25519_X.test(value.x)) return null;
  return value.x;
}

/** The string a worker signs with its previous key to replace it (agent-auth section 6.2). */
function rotationMessage({ challenge, challenge_id, idempotency_key, policy_id, x }) {
  return JSON.stringify({ challenge, challenge_id, domain: 'stack:fleet-key-rotation:v1', idempotency_key, policy_id, public_key_thumbprint: thumbprint(x) });
}

/**
 * @param {{ quirk?: string, apiKey?: string }} [options]
 */
export async function startIdentityReference({ quirk = 'none', apiKey = `sk_live_${rand(18)}` } = {}) {
  if (!IDENTITY_QUIRKS.includes(quirk)) throw new Error(`unknown quirk ${quirk}`);
  const q = (name) => quirk === name;

  // The issuer's own key: it signs Passports and enrollment tickets.
  const serverKey = generateKeyPairSync('ed25519');
  const serverJwk = { ...serverKey.publicKey.export({ format: 'jwk' }), kid: 'reference-1', alg: 'EdDSA', use: 'sig' };

  const approvals = new Map();
  const agents = new Map(); // id -> agent
  const challenges = new Map(); // key-enrollment challenges
  const tickets = new Map();
  const missions = new Map();
  const passports = new Map();
  const policies = new Map();
  const fleetChallenges = new Map();
  const members = new Map(); // `${policy}:${principal}:${idempotency_key}` -> membership
  const enrollmentLog = []; // enrollment times of fleet workers, for the hourly quota
  const subscribers = new Set();
  const verifyAgentJwt = createAgentJwtVerifier();
  let baseUrl = '';

  // A connection of the operator with two scopes, for the checks of scope and constraint narrowing.
  const connection = { id: 'scon_reference', scopes: ['read', 'write'], granted: new Set() };

  const publish = (event) => {
    if (q('channel-silent')) return;
    const message = { operator_id: OPERATOR, at: Date.now(), ...event };
    for (const handler of subscribers) handler(message);
  };

  const fail = (status, code, message, details) => ({ status, body: { error: { code, message, ...(details ? { details } : {}) } } });
  const invalid = () => fail(401, 'PASSPORT_INVALID', 'Passport is not valid');

  // ─── Credentials ────────────────────────────────────────────────────────────

  /**
   * Who is calling. `operator` is the operator's credential; `agent` an agent that signed in with its key; `ticket` an
   * enrollment ticket. Anything else is null (401). A verification failure of an agent JWT is one answer whatever its
   * cause (section 4), except a repeat.
   */
  async function principal(request) {
    const header = request.headers.authorization ?? '';
    const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!bearer) return { refusal: fail(401, 'INVALID_API_KEY', 'Invalid API key') };
    if (bearer === apiKey) return { kind: 'operator' };
    const parts = bearer.split('.');
    if (parts.length === 3 && bearer.length <= 4096) {
      let payload;
      let head;
      try {
        head = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      } catch {
        payload = null;
      }
      if (payload && payload.iss === 'stack-sdk' && typeof payload.sub === 'string') {
        const agent = agents.get(payload.sub);
        const publicJwk = agent?.active && agent.publicJwk && (!agent.leaseUntil || agent.leaseUntil > Date.now()) ? agent.publicJwk : null;
        try {
          await verifyAgentJwt(bearer, { agentId: payload.sub, publicJwk });
          return { kind: 'agent', agent };
        } catch (error) {
          if (error.code === 'AGENT_JWT_REPLAYED') return { refusal: fail(401, 'AGENT_JWT_REPLAYED', 'Agent JWT already used - mint a fresh JWT for every request') };
          // An old key that a defective server still honours.
          if (q('rotate-keeps-old') && agent?.oldKeys?.length) {
            for (const old of agent.oldKeys) {
              try {
                await verifyAgentJwt(bearer, { agentId: payload.sub, publicJwk: old });
                return { kind: 'agent', agent };
              } catch {
                /* try the next */
              }
            }
          }
          return { refusal: fail(401, 'INVALID_API_KEY', 'Invalid API key') };
        }
      }
      if (payload && payload.aud === 'stack:enrollment-ticket' && head?.alg === 'EdDSA') {
        const ok = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), serverKey.publicKey, Buffer.from(parts[2], 'base64url'));
        const ticket = tickets.get(payload.jti);
        if (ok && ticket && payload.exp > now()) {
          if (ticket.used && !q('ticket-reuse')) return { refusal: fail(401, 'INVALID_API_KEY', 'Invalid API key') };
          return { kind: 'ticket', ticket };
        }
      }
    }
    // Not a credential this server knows. On the enrollment calls a defective server takes any bearer for one.
    return { refusal: fail(401, 'INVALID_API_KEY', 'Invalid API key'), garbage: true };
  }

  // ─── Governance step-up ─────────────────────────────────────────────────────

  /**
   * A person's approval of one exact change. Returns null when the change may go ahead, or the refusal. A credential
   * that is not a person must have the approval decided; the approval names the action, the resource and the change.
   */
  function stepUp(request, { action, resource, change }) {
    const hash = sha256(JSON.stringify(change));
    const wanted = request.headers['x-governance-approval'];
    if (!wanted) {
      const approval = { id: id('gvr'), action, resource, hash, status: 'pending' };
      approvals.set(approval.id, approval);
      return fail(403, 'GOVERNANCE_APPROVAL_REQUIRED', `Approval ${approval.id} is needed: ask a person to decide it, then repeat the call with X-Governance-Approval: ${approval.id}`, { approval_id: approval.id, approval_url: `${baseUrl}/app/approve/${approval.id}` });
    }
    const approval = approvals.get(String(wanted));
    if (!approval) return fail(404, 'NOT_FOUND', `governance approval not found: ${wanted}`);
    if (approval.status === 'pending') return fail(403, 'GOVERNANCE_APPROVAL_PENDING', 'governance approval is still pending: a person must decide it first', { approval_id: approval.id, status: 'pending' });
    if (approval.status === 'rejected' || approval.status === 'expired') {
      return fail(403, `GOVERNANCE_APPROVAL_${approval.status.toUpperCase()}`, `governance approval is ${approval.status}: request a new one`, { approval_id: approval.id, status: approval.status });
    }
    if (approval.status !== 'approved') return fail(403, 'FORBIDDEN', `governance approval is ${approval.status}`);
    if (approval.action !== action || approval.resource !== resource) return fail(403, 'FORBIDDEN', 'governance approval does not match this action');
    if (!(q('approval-unbound') && action === 'agent_enroll') && approval.hash !== hash) return fail(403, 'FORBIDDEN', 'governance approval does not match this exact change');
    approval.status = 'consumed';
    return null;
  }

  // ─── Passports ──────────────────────────────────────────────────────────────

  function signPassport(payload) {
    const input = `${b64({ alg: 'EdDSA', kid: serverJwk.kid })}.${b64(payload)}`;
    return `${input}.${sign(null, Buffer.from(input), serverKey.privateKey).toString('base64url')}`;
  }

  /** Revoke a Passport and, unless a defect says otherwise, its descendants; the jtis revoked besides it. */
  function revokeTree(jti) {
    const root = passports.get(jti);
    if (!root || root.revoked) return [];
    root.revoked = true;
    const cascaded = [];
    if (!q('no-cascade')) {
      const walk = (parent) => {
        for (const p of passports.values()) {
          if (p.parent === parent && !p.revoked) {
            p.revoked = true;
            cascaded.push(p.jti);
            walk(p.jti);
          }
        }
      };
      walk(jti);
    }
    return cascaded;
  }

  /** Online verification (passport section 9.2). Returns `{ record, payload }` or `{ refusal }`. */
  function checkPassport(token) {
    if (typeof token !== 'string') return { refusal: fail(400, 'VALIDATION_ERROR', 'token is required') };
    const parts = token.split('.');
    if (parts.length !== 3) return q('verify-500') ? { refusal: fail(500, 'INTERNAL_ERROR', 'An unexpected error occurred') } : { refusal: invalid() };
    let header;
    let payload;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      return q('verify-500') ? { refusal: fail(500, 'INTERNAL_ERROR', 'An unexpected error occurred') } : { refusal: invalid() };
    }
    if (!isObject(header) || !isObject(payload)) return { refusal: invalid() };
    const unaccepted = (why) => (q('verify-valid-false') ? { refusal: { status: 200, body: { valid: false, reason: why } } } : { refusal: invalid() });
    if (header.alg === 'none' && q('verify-alg-none')) {
      // accepted without a signature
    } else {
      if (header.alg !== 'EdDSA' || header.kid !== serverJwk.kid) return unaccepted('alg');
      if (!q('verify-no-signature')) {
        let ok;
        try {
          ok = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), serverKey.publicKey, Buffer.from(parts[2], 'base64url'));
        } catch {
          ok = false;
        }
        if (!ok) return unaccepted('signature');
      }
    }
    if (payload.iss !== ISSUER || payload.aud !== 'stack:passport') return unaccepted('iss or aud');
    if (!Number.isInteger(payload.exp) || payload.exp <= now()) return { refusal: fail(401, 'PASSPORT_EXPIRED', 'Passport has expired') };
    const record = passports.get(payload.jti);
    if (!record) return { refusal: fail(401, 'PASSPORT_REVOKED', 'Passport has been revoked') };
    if (!q('revocation-ignored')) {
      const dead = (p) => p.revoked || !agents.get(p.agentId)?.active;
      if (dead(record)) return { refusal: fail(401, 'PASSPORT_REVOKED', 'Passport has been revoked') };
      for (let parent = record.parent && passports.get(record.parent); parent; parent = parent.parent && passports.get(parent.parent)) {
        if (dead(parent) || parent.exp <= now()) return { refusal: fail(401, 'PASSPORT_REVOKED', 'Passport has been revoked') };
      }
    }
    return { record, payload };
  }

  const missionLive = (m) => m && m.status === 'live';

  function issue(body) {
    if (!isObject(body) || typeof body.agent_id !== 'string' || !Array.isArray(body.mission_ids)) return fail(400, 'VALIDATION_ERROR', 'agent_id and mission_ids are required');
    const agent = agents.get(body.agent_id);
    if (!agent) return fail(404, 'NOT_FOUND', 'Agent not found');
    if (!agent.active) return fail(403, 'FORBIDDEN', 'Agent is not active');
    if (body.mission_ids.length !== 1) return fail(400, 'VALIDATION_ERROR', 'exactly one Mission is required');
    const mission = missions.get(body.mission_ids[0]);
    if (!mission || mission.agentId !== agent.id) return fail(404, 'NOT_FOUND', 'Mission not found');
    if (!missionLive(mission)) return fail(409, 'CONFLICT', 'The Mission has ended');
    const services = [];
    for (const scope of Array.isArray(body.scopes) ? body.scopes : []) {
      if (!isObject(scope) || scope.service_connection_id !== connection.id || !connection.granted.has(agent.id)) return fail(400, 'SCOPE_ESCALATION', 'The agent has no grant for that connection');
      const requested = Array.isArray(scope.scopes) ? scope.scopes : [];
      if (requested.some((s) => !connection.scopes.includes(s))) return fail(400, 'SCOPE_ESCALATION', 'The agent has no grant for that scope');
      services.push({ service_id: 'svc_reference', service_name: 'reference', scopes: requested, credential_ref: 'cred_reference', connection_id: connection.id, constraints: Array.isArray(scope.constraints) ? scope.constraints : [] });
    }
    const ttl = Math.min(Number.isInteger(body.ttl_seconds) ? body.ttl_seconds : q('long-lived') ? 3600 : 900, 3600);
    const iat = now();
    const jti = id('pas');
    const stk = {
      operator_id: OPERATOR,
      agent_id: agent.id,
      agent_name: agent.name,
      services,
      identity_claims: [],
      delegation_depth: 0,
      session_id: id('ses'),
      accountability: agent.accountability,
      mission_ids: [mission.id],
      intent_summary: body.intent?.summary ?? '',
      will_delegate: body.intent?.will_delegate === true,
    };
    const payload = { iss: ISSUER, aud: 'stack:passport', sub: agent.id, iat, exp: iat + ttl, jti, stk };
    const token = signPassport(payload);
    passports.set(jti, { jti, agentId: agent.id, missionId: mission.id, sessionId: stk.session_id, parent: null, depth: 0, exp: payload.exp, revoked: false, stk });
    return { status: 201, body: { token, jti, expires_at: new Date(payload.exp * 1000).toISOString() } };
  }

  function delegate(body) {
    if (!isObject(body) || typeof body.parent_passport_token !== 'string' || typeof body.child_agent_id !== 'string') return fail(400, 'VALIDATION_ERROR', 'parent_passport_token and child_agent_id are required');
    const checked = checkPassport(body.parent_passport_token);
    let parent;
    if (checked.refusal) {
      if (!q('revoked-parent-delegates') || checked.refusal.body?.error?.code !== 'PASSPORT_REVOKED') return checked.refusal;
      parent = passports.get(JSON.parse(Buffer.from(body.parent_passport_token.split('.')[1], 'base64url').toString('utf8')).jti);
    } else {
      parent = checked.record;
    }
    const child = agents.get(body.child_agent_id);
    if (!child) return fail(404, 'NOT_FOUND', 'Agent not found');
    if (!child.active) return fail(403, 'FORBIDDEN', 'Agent is not active');
    if (parent.depth + 1 > MAX_DEPTH && !q('depth-unlimited')) return fail(400, 'DELEGATION_DEPTH_EXCEEDED', 'Maximum delegation depth exceeded');
    const parentAccountability = parent.stk.accountability;
    if (RANK[child.accountability] < RANK[parentAccountability] && !q('accountability-down')) {
      return fail(400, 'DELEGATION_ACCOUNTABILITY_VIOLATION', 'Cannot delegate to a less accountable agent. Delegation cannot reduce accountability.');
    }
    if (parentAccountability === 'enforced' && !parent.stk.will_delegate) return fail(403, 'FORBIDDEN', 'The parent did not declare that it would delegate');
    const services = [];
    for (const scope of Array.isArray(body.scopes) ? body.scopes : []) {
      const held = parent.stk.services.find((s) => s.connection_id === scope?.service_connection_id);
      const requested = Array.isArray(scope?.scopes) ? scope.scopes : [];
      if (!q('scope-escalation') && (!held || requested.some((s) => !held.scopes.includes(s)))) return fail(400, 'SCOPE_ESCALATION', 'Child scope cannot exceed parent scope');
      const own = Array.isArray(scope?.constraints) ? scope.constraints : [];
      const inherited = q('drops-constraints') ? [] : held?.constraints ?? [];
      services.push({ service_id: held?.service_id ?? 'svc_reference', service_name: held?.service_name ?? 'reference', scopes: requested, credential_ref: held?.credential_ref ?? 'cred_reference', connection_id: scope?.service_connection_id, constraints: [...inherited, ...own] });
    }
    const left = parent.exp - now();
    const asked = Number.isInteger(body.ttl_seconds) ? body.ttl_seconds : left;
    const ttl = q('child-outlives') ? asked : Math.min(asked, left);
    const iat = now();
    const jti = id('pas');
    const stk = {
      operator_id: OPERATOR,
      agent_id: child.id,
      agent_name: child.name,
      services,
      identity_claims: [],
      delegation_depth: parent.depth + 1,
      parent_passport_id: parent.jti,
      session_id: parent.sessionId,
      accountability: child.accountability,
      mission_ids: parent.stk.mission_ids,
      will_delegate: true,
    };
    const payload = { iss: ISSUER, aud: 'stack:passport', sub: child.id, iat, exp: iat + ttl, jti, stk };
    passports.set(jti, { jti, agentId: child.id, missionId: parent.missionId, sessionId: parent.sessionId, parent: parent.jti, depth: parent.depth + 1, exp: payload.exp, revoked: false, stk });
    return { status: 201, body: { token: signPassport(payload), jti, expires_at: new Date(payload.exp * 1000).toISOString() } };
  }

  /** Revoke every Passport an agent holds, with a notice; used by a rotation, a revocation and an ended Mission. */
  function revokeAgentPassports(agentId, reason) {
    let revoked = 0;
    const cascaded = 0;
    for (const p of [...passports.values()]) {
      if (p.agentId !== agentId && !q('revoke-agent-all')) continue;
      if (p.revoked) continue;
      p.revoked = true;
      revoked += 1;
    }
    publish({ type: 'bulk_agent', agent_id: agentId, revoked_count: revoked, cascaded_count: cascaded, reason: reason ?? null });
    return { revoked, cascaded };
  }

  // ─── Enrollment ─────────────────────────────────────────────────────────────

  const keySetOf = (agent) => {
    const key = {
      kty: 'OKP', crv: 'Ed25519', x: agent.publicJwk.x,
      kid: q('jwks-kid') ? `agent:${agent.id}:v2` : `agent:${agent.id}:v1`,
      alg: 'EdDSA', use: 'sig', not_before: agent.enrolledAt, not_after: null,
    };
    if (q('jwks-private')) key.d = rand(32);
    return { keys: [key] };
  };

  async function handleEnrollmentCall(request, url, body, agentId, who) {
    const agent = agents.get(agentId);
    // A ticket names one agent; it is no credential for another.
    if (who.kind === 'ticket' && who.ticket.agentId !== agentId && !q('ticket-any-agent')) return fail(403, 'FORBIDDEN', 'This ticket is for another agent');
    if (!agent) return fail(404, 'NOT_FOUND', 'Agent not found');
    const last = url.pathname.split('/').pop();
    if (last === 'enrollment-challenge') {
      const text = q('challenge-repeat') && agent.fixedChallenge ? agent.fixedChallenge : `chl_${rand(24)}`;
      agent.fixedChallenge = text;
      const record = { id: id('enr'), agentId, challenge: text, expiresAt: Date.now() + (q('challenge-ttl') ? 600 : 300) * 1000, used: false, ticketJti: who.kind === 'ticket' ? who.ticket.jti : null };
      challenges.set(record.id, record);
      return { status: 200, body: { challenge_id: record.id, challenge: record.challenge, expires_in: q('challenge-ttl') ? 600 : 300 } };
    }
    // enroll
    const x = readKey(body?.public_key);
    if (!isObject(body) || !x || typeof body.challenge_id !== 'string' || typeof body.signed_challenge !== 'string') return fail(400, 'VALIDATION_ERROR', 'public_key, challenge_id and signed_challenge are required');
    const force = url.searchParams.get('force') === 'true';
    if (agent.key_mode !== 'customer_managed' && !q('managed-enroll')) return fail(409, 'ENROLL_NOT_APPLICABLE', 'The key of this agent is held by STACK');
    if (agent.publicJwk && !force && !q('overwrite-key')) return fail(409, 'CONFLICT', 'The agent already has a key');
    if (force && who.kind === 'agent') return fail(403, 'FORBIDDEN', 'An agent never rotates a key');
    const refused = fail(400, 'INVALID_ENROLLMENT', 'The enrollment cannot be completed');
    const challenge = challenges.get(body.challenge_id);
    if (!challenge || challenge.expiresAt <= Date.now() || (challenge.used && !q('challenge-reuse'))) return refused;
    if (challenge.agentId !== agentId && !q('any-challenge')) return refused;
    if (challenge.ticketJti !== (who.kind === 'ticket' ? who.ticket.jti : null)) return refused;
    if (!q('no-pop') && !verifyText(x, challenge.challenge, body.signed_challenge)) return refused;
    if (who.kind === 'operator' && !q('no-approval')) {
      const stopped = stepUp(request, { action: 'agent_enroll', resource: agentId, change: { agent_id: agentId, x, rotation: force } });
      if (stopped) return stopped;
    }
    // One step: the challenge and the ticket are used, the key is stored.
    challenge.used = true;
    if (who.kind === 'ticket') who.ticket.used = true;
    if (agent.publicJwk) {
      agent.oldKeys = [...(agent.oldKeys ?? []), agent.publicJwk];
      revokeAgentPassports(agentId, 'key rotated');
    }
    agent.publicJwk = { kty: 'OKP', crv: 'Ed25519', x };
    agent.enrolledAt = Date.now();
    return { status: 200, body: { agent_id: agentId, enrolled_at: new Date(agent.enrolledAt).toISOString() } };
  }

  async function handleTicketMint(request, who, agentId, body) {
    const agent = agents.get(agentId);
    if (!agent) return fail(404, 'NOT_FOUND', 'Agent not found');
    if (who.kind !== 'operator') return fail(403, 'FORBIDDEN', 'A ticket is a person\'s decision');
    const stopped = stepUp(request, { action: 'agent_enrollment_ticket', resource: agentId, change: { agent_id: agentId, machine_label: body?.machine_label ?? null } });
    if (stopped) return stopped;
    const jti = id('tkt');
    const iat = now();
    const payload = { iss: ISSUER, aud: 'stack:enrollment-ticket', sub: agentId, op: OPERATOR, jti, iat, exp: iat + 300 };
    const input = `${b64({ alg: 'EdDSA', kid: serverJwk.kid })}.${b64(payload)}`;
    const ticket = `${input}.${sign(null, Buffer.from(input), serverKey.privateKey).toString('base64url')}`;
    tickets.set(jti, { jti, agentId, used: false });
    return { status: 200, body: { ticket, jti, expires_at: new Date((iat + 300) * 1000).toISOString(), expires_in: 300 } };
  }

  // ─── Fleets ─────────────────────────────────────────────────────────────────

  const FLEET_KEYS = new Set(['idempotency_key', 'name', 'public_key', 'challenge_id', 'proof', 'previous_key_proof']);

  function fleetRefusal() {
    return fail(403, 'FORBIDDEN', 'Forbidden');
  }

  function fleetPrincipal(who, policy) {
    if (who.kind === 'agent' && policy.provisioner_agent_ids.includes(who.agent.id)) return who.agent.id;
    if (q('fleet-any-caller') && who.kind === 'operator') return 'operator';
    if (q('fleet-worker-enrolls') && who.kind === 'agent' && who.agent.worker) return who.agent.id;
    return null;
  }

  async function handleFleetCall(url, body, policyId, who) {
    const policy = policies.get(policyId);
    if (!policy || policy.revoked || policy.expires_at <= Date.now()) return fleetRefusal();
    const principalId = fleetPrincipal(who, policy);
    if (!principalId) return fleetRefusal();
    const last = url.pathname.split('/').pop();
    if (last === 'enrollment-challenges') {
      const record = { id: id('fec'), policy: policyId, principal: principalId, challenge: `fch_${rand(24)}`, expiresAt: Date.now() + 120_000, used: false };
      fleetChallenges.set(record.id, record);
      enrollmentLog.push(Date.now());
      return { status: 200, body: { challenge_id: record.id, challenge: record.challenge, expires_in: 120 } };
    }
    // enroll: the body first, then everything that must hold before anything is created or changed.
    if (!isObject(body)) return fail(400, 'VALIDATION_ERROR', 'The body is not an object');
    const extra = q('fleet-extra-members') ? [] : Object.keys(body).filter((k) => !FLEET_KEYS.has(k));
    const x = readKey(body.public_key);
    const keyOk = typeof body.idempotency_key === 'string' && body.idempotency_key.length >= 8 && body.idempotency_key.length <= 128
      && typeof body.name === 'string' && body.name.length >= 1 && body.name.length <= 128
      && x && typeof body.challenge_id === 'string' && typeof body.proof === 'string'
      && (body.previous_key_proof === undefined || typeof body.previous_key_proof === 'string');
    if (extra.length > 0 || !keyOk) return fail(400, 'VALIDATION_ERROR', 'The body does not match the schema');
    const challenge = fleetChallenges.get(body.challenge_id);
    if (!challenge || challenge.policy !== policyId || challenge.principal !== principalId || challenge.expiresAt <= Date.now()) return fleetRefusal();
    if (challenge.used && !q('fleet-challenge-reuse')) return fleetRefusal();
    challenge.used = true;
    if (!q('fleet-no-proof') && !verifyText(x, challenge.challenge, body.proof)) return fleetRefusal();
    const key = `${policyId}:${principalId}:${body.idempotency_key}`;
    const existing = members.get(key);
    const lease = (policy.identity_lease_seconds + (q('fleet-long-lease') ? 7200 : 0)) * 1000;
    const leaseUntil = Math.min(Date.now() + lease, q('fleet-long-lease') ? Infinity : policy.expires_at);
    if (existing && !q('fleet-duplicate')) {
      if (existing.name !== body.name && !q('fleet-name-ignored')) return fail(409, 'CONFLICT', 'That idempotency key names another worker');
      const agent = agents.get(existing.agentId);
      if (agent.publicJwk.x !== x) {
        const previous = body.previous_key_proof;
        const message = rotationMessage({ challenge: challenge.challenge, challenge_id: challenge.id, idempotency_key: body.idempotency_key, policy_id: policyId, x });
        if (!q('fleet-open-rotation') && (typeof previous !== 'string' || !verifyText(agent.publicJwk.x, message, previous))) return fleetRefusal();
        agent.oldKeys = [...(agent.oldKeys ?? []), agent.publicJwk];
        agent.publicJwk = { kty: 'OKP', crv: 'Ed25519', x };
        revokeAgentPassports(agent.id, 'key rotated');
      } else if (typeof body.previous_key_proof === 'string') {
        return fleetRefusal();
      }
      agent.leaseUntil = leaseUntil;
      return { status: 201, body: { agent_id: agent.id, membership_id: existing.membershipId, identity_expires_at: new Date(leaseUntil).toISOString() } };
    }
    if (body.previous_key_proof !== undefined && !q('fleet-open-rotation')) return fleetRefusal();
    if ([...members.values()].filter((m) => m.policy === policyId).length >= policy.max_members) return fleetRefusal();
    if (enrollmentLog.filter((t) => t > Date.now() - 3_600_000).length > policy.max_enrollments_per_hour) return fleetRefusal();
    const agent = { id: id('agt'), name: body.name, key_mode: 'customer_managed', accountability: 'enforced', active: true, publicJwk: { kty: 'OKP', crv: 'Ed25519', x }, enrolledAt: Date.now(), worker: true, leaseUntil };
    agents.set(agent.id, agent);
    const membership = { policy: policyId, agentId: agent.id, membershipId: id('flm'), name: body.name };
    members.set(q('fleet-duplicate') ? `${key}:${agent.id}` : key, membership);
    return { status: 201, body: { agent_id: agent.id, membership_id: membership.membershipId, identity_expires_at: new Date(leaseUntil).toISOString() } };
  }

  // ─── The server ─────────────────────────────────────────────────────────────

  async function route(request, url, body) {
    const method = request.method;
    const path = url.pathname;
    let m;

    if (method === 'GET' && path === '/health') return { status: 200, body: { status: 'ok' } };
    if (method === 'GET' && path === '/v1/.well-known/jwks.json') return { status: 200, body: { keys: [serverJwk] } };
    if (method === 'POST' && path === '/v1/passports/verify') {
      const checked = checkPassport(isObject(body) ? body.token : undefined);
      if (checked.refusal) return checked.refusal;
      const { record, payload } = checked;
      return { status: 200, body: { valid: true, jti: record.jti, agent_id: record.agentId, expires_at: new Date(payload.exp * 1000).toISOString(), claims: record.stk } };
    }
    if ((m = /^\/v1\/agents\/([^/]+)\/\.well-known\/jwks\.json$/.exec(path)) && method === 'GET') {
      const agent = agents.get(m[1]);
      if (!agent?.publicJwk) return fail(404, 'SIGNING_KEY_UNAVAILABLE', 'No signing key is available for this agent');
      return { status: 200, body: keySetOf(agent) };
    }

    const who = await principal(request);
    const isTicketRoute = /^\/v1\/agents\/[^/]+\/(enrollment-challenge|enroll)$/.test(path);
    if (who.refusal && !(who.garbage && q('garbage-bearer') && isTicketRoute)) return who.refusal;
    const caller = who.refusal ? { kind: 'operator' } : who;

    if (method === 'GET' && path === '/v1/auth/context') return { status: 200, body: { operator_id: OPERATOR, agent_id: caller.agent?.id ?? null } };

    // Fleets and the calls only the operator makes.
    if (method === 'POST' && path === '/v1/agents/register') {
      if (caller.kind !== 'operator') return fail(403, 'FORBIDDEN', 'Forbidden');
      if (!isObject(body) || typeof body.name !== 'string' || body.name.length === 0) return fail(400, 'VALIDATION_ERROR', 'name is required');
      const stopped = stepUp(request, { action: 'agent_register', resource: body.name, change: body });
      if (stopped) return stopped;
      const agent = {
        id: id('agt'), name: body.name, key_mode: body.key_mode ?? 'customer_managed', accountability: body.accountability_mode ?? 'standard',
        active: true, publicJwk: null, enrolledAt: null,
      };
      agents.set(agent.id, agent);
      return { status: 201, body: { id: agent.id, name: agent.name, key_mode: agent.key_mode, accountability_mode: agent.accountability } };
    }
    if ((m = /^\/v1\/agents\/([^/]+)\/(enrollment-challenge|enroll)$/.exec(path)) && method === 'POST') {
      if (caller.kind === 'agent') return fail(403, 'FORBIDDEN', 'Forbidden');
      return handleEnrollmentCall(request, url, body, m[1], caller);
    }
    if ((m = /^\/v1\/agents\/([^/]+)\/enrollment-tickets$/.exec(path)) && method === 'POST') return handleTicketMint(request, caller, m[1], body);

    if (method === 'POST' && path === '/v1/fleets') {
      if (caller.kind !== 'operator') return fail(403, 'FORBIDDEN', 'Forbidden');
      if (!isObject(body) || !Array.isArray(body.provisioner_agent_ids)) return fail(400, 'VALIDATION_ERROR', 'provisioner_agent_ids is required');
      const stopped = stepUp(request, { action: 'fleet_create', resource: String(body.name), change: body });
      if (stopped) return stopped;
      const policy = {
        id: id('flp'), provisioner_agent_ids: body.provisioner_agent_ids, max_members: body.max_members ?? 100,
        max_enrollments_per_hour: body.max_enrollments_per_hour ?? 100, identity_lease_seconds: body.identity_lease_seconds ?? 600,
        expires_at: Date.parse(body.expires_at) || Date.now() + 3_600_000, revoked: false,
      };
      policies.set(policy.id, policy);
      return { status: 200, body: { id: policy.id, name: body.name } };
    }
    if ((m = /^\/v1\/fleets\/(flp_[A-Za-z0-9_-]+)\/(enrollment-challenges|enroll)$/.exec(path)) && method === 'POST') return handleFleetCall(url, body, m[1], caller);

    // Missions and Passports: the operator's.
    if (caller.kind !== 'operator') return fail(403, 'FORBIDDEN', 'Forbidden');
    if (method === 'POST' && path === '/v1/missions') {
      if (!isObject(body) || typeof body.agent_id !== 'string' || !agents.has(body.agent_id)) return fail(404, 'NOT_FOUND', 'Agent not found');
      const mission = { id: id('ms'), agentId: body.agent_id, status: 'live' };
      missions.set(mission.id, mission);
      return { status: 201, body: { mission_id: mission.id } };
    }
    if ((m = /^\/v1\/missions\/([^/]+)\/complete$/.exec(path)) && method === 'POST') {
      const mission = missions.get(m[1]);
      if (!mission) return fail(404, 'NOT_FOUND', 'Mission not found');
      mission.status = 'completed';
      const jtis = [];
      if (!q('mission-keeps')) {
        for (const p of passports.values()) {
          if (p.missionId === mission.id && !p.revoked) {
            p.revoked = true;
            jtis.push(p.jti);
          }
        }
      }
      publish({ type: 'bulk_mission', mission_id: mission.id, revoke_reason: 'completed', cascaded_passport_jtis: jtis });
      return { status: 200, body: { mission_id: mission.id, status: 'completed' } };
    }
    if (method === 'POST' && path === '/v1/passports/issue') return issue(body);
    if (method === 'POST' && path === '/v1/passports/delegate') return delegate(body);
    if (method === 'POST' && path === '/v1/passports/revoke') {
      if (!isObject(body) || typeof body.jti !== 'string') return fail(400, 'VALIDATION_ERROR', 'jti is required');
      const record = passports.get(body.jti);
      if (!record) return fail(404, 'NOT_FOUND', 'Passport not found');
      const cascaded = revokeTree(body.jti);
      if (cascaded.length > 0 || !record.noticed) {
        record.noticed = true;
        publish({ type: 'single', jti: body.jti, cascaded, reason: body.reason ?? null });
      }
      return { status: 200, body: { success: true, jti: body.jti, cascaded_count: cascaded.length, revoked_claims_count: 0 } };
    }
    if ((m = /^\/v1\/passports\/revoke-agent\/([^/]+)$/.exec(path)) && method === 'POST') {
      const { revoked, cascaded } = revokeAgentPassports(m[1], body?.reason);
      return { status: 200, body: { success: true, revoked_count: revoked, cascaded_count: cascaded } };
    }
    if ((m = /^\/v1\/passports\/revoke-session\/([^/]+)$/.exec(path)) && method === 'POST') {
      let revoked = 0;
      for (const p of passports.values()) if (p.sessionId === m[1] && !p.revoked) { p.revoked = true; revoked += 1; }
      publish({ type: 'bulk_session', session_id: m[1], revoked_count: revoked, reason: body?.reason ?? null });
      return { status: 200, body: { success: true, revoked_count: revoked } };
    }
    return fail(404, 'NOT_FOUND', `Route ${method}:${path} not found`);
  }

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://x');
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    let body;
    if (request.method === 'POST') {
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        response.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify(fail(400, 'INVALID_JSON', 'Request body is not valid JSON').body));
        return;
      }
    }
    let result;
    try {
      result = await route(request, url, body);
    } catch (error) {
      result = fail(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
      process.stderr.write(`identity reference: ${error?.stack ?? error}\n`);
    }
    response.writeHead(result.status, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify(result.body));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  return {
    baseUrl,
    apiKey,
    headers: { authorization: `Bearer ${apiKey}` },
    /** A person decides an approval. */
    approve: async (approvalId) => {
      const approval = approvals.get(approvalId);
      if (!approval) throw new Error(`no approval ${approvalId}`);
      approval.status = 'approved';
    },
    /** A subscription to the revocation channel: `subscribe(onEvent)` resolves with the function that ends it. */
    revocations: {
      subscribe: async (onEvent) => {
        subscribers.add(onEvent);
        return async () => void subscribers.delete(onEvent);
      },
    },
    /** A connection of the operator with two scopes, and the grant of all of them to an agent. */
    connection: { id: connection.id, scopes: [...connection.scopes], grantTo: async (agentId) => void connection.granted.add(agentId) },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
