// Conformance suite for a SERVER's online verification of a Passport, its revocation (including the
// `stack:revoked` channel) and the narrowing rules of delegation (spec/passport/SPEC.md, sections 8 to 11). The
// offline suite (`passport`) tests a verifier; this one tests the issuer, on a test instance.
//
//   {
//     baseUrl, headers, approve,        as the `agent-enrollment` suite: the credential of a test operator, and a
//                                       person's decision for the approval that registering an agent needs
//     revocations?: { subscribe(onEvent): Promise<() => Promise<void>> }
//                                       optional: a subscription to the issuer's `stack:revoked` channel
//     connection?: { id, scopes: string[], grantTo(agentId): Promise<void> }
//                                       optional: a connection of the operator, with at least two scopes, and a
//                                       function that grants an agent all of them (as the operator would), for the
//                                       checks of scope and constraint narrowing
//   }
//
// The kit registers agents named conf-*, opens Missions and issues Passports on the instance. It never removes them.
// The server limits issue and verify to twenty calls a minute, and the kit waits for the window when it is told to.

import { verify as edVerify, createPublicKey } from 'node:crypto';
import { assert, runChecks, skip } from './harness.mjs';
import { enrollmentClient, registerAgent } from './agent-enrollment.mjs';
import { b64url, callJson, decodeCompact, errorCode, newEd25519, signEdDsa, signHs256 } from './identity-support.mjs';

const REVOCATION_TYPES = {
  single: ['jti', 'cascaded', 'reason'],
  bulk_agent: ['agent_id', 'revoked_count', 'cascaded_count', 'reason'],
  bulk_session: ['session_id', 'revoked_count', 'reason'],
  bulk_operator: ['revoked_count', 'reason'],
  bulk_claim: ['claim_id', 'revoked_count', 'reason'],
  bulk_mission: ['mission_id', 'revoke_reason', 'cascaded_passport_jtis'],
};

/** Whether a message of the revocation channel has the shape of RevocationEvent. */
export function revocationEventProblem(event) {
  if (!event || typeof event !== 'object') return 'not an object';
  const fields = REVOCATION_TYPES[event.type];
  if (!fields) return `unknown type ${JSON.stringify(event.type)}`;
  for (const name of ['operator_id', 'at', ...fields]) if (event[name] === undefined) return `${event.type} has no ${name}`;
  if (typeof event.operator_id !== 'string' || !Number.isInteger(event.at)) return 'operator_id or at has the wrong type';
  if (event.at < 1_000_000_000_000) return 'at is not in milliseconds';
  return undefined;
}

/** @param {{ baseUrl: string, headers: Record<string, string>, approve: (id: string) => Promise<void>, revocations?: { subscribe: (onEvent: (event: object) => void) => Promise<() => Promise<void>> }, connection?: { id: string, scopes: string[], grantTo: (agentId: string) => Promise<void> } }} options */
export async function runPassportOnlineSuite(options) {
  const client = enrollmentClient(options);
  const state = {};
  const call = (path, init) => client.call(path, init);
  const post = (path, body, extra = {}) => call(path, { method: 'POST', body, ...extra });
  const agent = async (accountability = 'standard') => registerAgent(client, 'customer_managed', { accountability_mode: accountability });

  const mission = async (agentId) => {
    const r = await post('/v1/missions', { intent_summary: 'conformance', intent_services: [], agent_id: agentId });
    assert(r.status === 201 && typeof r.body?.mission_id === 'string', `opening a Mission answered ${r.status} ${errorCode(r) ?? ''}`.trim());
    return r.body.mission_id;
  };
  const issue = async (agentId, missionId, over = {}) => {
    const r = await post('/v1/passports/issue', { agent_id: agentId, mission_ids: [missionId], intent: { summary: 'conformance', services: [], will_delegate: true }, ...over });
    assert(r.status === 201 && typeof r.body?.token === 'string', `issuing answered ${r.status} ${errorCode(r) ?? ''}`.trim());
    return r.body;
  };
  const verify = (token) => callJson(client.baseUrl, '/v1/passports/verify', { method: 'POST', body: { token } });
  const delegate = (parent, child, extra = {}) => post('/v1/passports/delegate', { parent_passport_token: parent, child_agent_id: child, scopes: [], ...extra });
  const claimsOf = (token) => decodeCompact(token).payload;
  // Registering an agent takes a person's approval, which is slow, so agents are kept and used again: a root
  // Passport is a new Mission and Passport of a kept agent, unless a check needs an agent of its own (it revokes
  // everything the agent has).
  const kept = {};
  /** A fresh root Passport, on a new Mission. */
  const fresh = async (accountability = 'standard', { own = false } = {}) => {
    const agentId = own ? await agent(accountability) : (kept[accountability] ??= await agent(accountability));
    const missionId = await mission(agentId);
    return { agentId, missionId, ...(await issue(agentId, missionId)) };
  };
  /** One root Passport shared by the delegation checks that only read it (the last of them revokes it). */
  const sharedRoot = async () => (state.root ??= await fresh());
  const setup = async () => {
    if (state.ready) return state;
    state.child1 = await agent();
    state.child2 = await agent();
    state.ready = true;
    return state;
  };
  const dead = (r, why) => {
    assert(r.status === 401, `${why} answered ${r.status} ${errorCode(r) ?? ''}, not 401`.trim());
    assert(['PASSPORT_REVOKED', 'PASSPORT_EXPIRED'].includes(errorCode(r)), `${why} answered the code ${errorCode(r)}`);
  };

  /** A token that is not a Passport of the issuer: 401 PASSPORT_INVALID, never a revocation and never a server error. */
  const invalid = (r, why) => {
    assert(r.status === 401, `${why} answered ${r.status} ${errorCode(r) ?? ''}, not 401`.trim());
    assert(errorCode(r) === 'PASSPORT_INVALID', `${why} answered the code ${errorCode(r)}, not PASSPORT_INVALID`);
  };

  let subscription;
  const events = [];
  const startEvents = async () => {
    if (!options.revocations) return false;
    if (!subscription) subscription = await options.revocations.subscribe((event) => events.push(event));
    return true;
  };
  const waitForEvent = async (match, ms = 5000) => {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      const found = events.find(match);
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return undefined;
  };

  const report = await runChecks('passport online verification, revocation and delegation', [
    {
      id: 'PO01', level: 'MUST', title: 'issues a Passport signed with a key of the published key set (kid, EdDSA), with the claims of section 3',
      async run() {
        const { token, jti, agentId, missionId } = (state.live = await fresh());
        const { header, payload } = decodeCompact(token);
        assert(header.alg === 'EdDSA' && typeof header.kid === 'string', `the header is ${JSON.stringify(header)}`);
        assert(payload.aud === 'stack:passport' && payload.jti === jti && payload.sub === agentId && payload.stk?.agent_id === agentId, 'the registered claims are not as specified');
        assert(typeof payload.iss === 'string' && payload.iss.length > 0, 'there is no issuer');
        assert(payload.exp - payload.iat <= 900, `the lifetime is ${payload.exp - payload.iat} seconds, not the 900 default`);
        assert(JSON.stringify(payload.stk.mission_ids) === JSON.stringify([missionId]), 'the Passport is not bound to the Mission it was issued for');
        const set = await callJson(client.baseUrl, '/v1/.well-known/jwks.json');
        assert(set.status === 200 && Array.isArray(set.body?.keys), 'the key set is not served at /v1/.well-known/jwks.json');
        const key = set.body.keys.find((k) => k.kid === header.kid);
        assert(key && key.kty === 'OKP' && key.crv === 'Ed25519' && key.alg === 'EdDSA' && key.use === 'sig' && !('d' in key), 'the key of the Passport is not an Ed25519 signing key in the key set');
        const [h, p, s] = token.split('.');
        assert(edVerify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key, format: 'jwk' }), Buffer.from(s, 'base64url')), 'the signature does not verify with the published key');
      },
    },
    {
      id: 'PO02', level: 'MUST', title: 'answers 200 {valid: true, jti, agent_id, expires_at, claims} to a live Passport, with no credential',
      async run() {
        const { token, jti, agentId } = state.live ?? (state.live = await fresh());
        const r = await verify(token);
        assert(r.status === 200, `answered ${r.status} ${errorCode(r) ?? ''}`.trim());
        assert(r.body.valid === true && r.body.jti === jti && r.body.agent_id === agentId, 'the answer does not name the Passport');
        assert(typeof r.body.expires_at === 'string' && !Number.isNaN(Date.parse(r.body.expires_at)), 'expires_at is not a time');
        assert(r.body.claims && r.body.claims.agent_id === agentId && typeof r.body.claims.operator_id === 'string', 'the claims are not the stk claims');
      },
    },
    {
      id: 'PO03', level: 'MUST', title: 'never answers 200 for a Passport it does not accept: a changed token, a foreign signature, alg none, HMAC and text are 401 PASSPORT_INVALID, and a missing token is 400',
      async run() {
        const { token } = state.live ?? (state.live = await fresh());
        const [h, p, s] = token.split('.');
        const { payload, header } = decodeCompact(token);
        const foreign = newEd25519();
        const hmacSecret = Buffer.from(foreign.publicJwk.x, 'base64url');
        const cases = [
          // The first character of a signature carries six whole bits, so a different first character is always a different signature.
          ['a changed signature', `${h}.${p}.${s[0] === 'A' ? 'B' : 'A'}${s.slice(1)}`],
          ['a changed payload', `${h}.${b64url({ ...payload, jti: 'pas_forged' })}.${s}`],
          ['a signature by another key', signEdDsa(header, payload, foreign.privateKey)],
          ['alg none', `${b64url({ alg: 'none', kid: header.kid })}.${p}.`],
          ['an HMAC token', signHs256({ alg: 'HS256', kid: header.kid }, payload, hmacSecret)],
          ['text', 'not.a.token'],
          ['an empty string', ''],
        ];
        for (const [why, bad] of cases) invalid(await verify(bad), why);
        const missing = await callJson(client.baseUrl, '/v1/passports/verify', { method: 'POST', body: {} });
        assert(missing.status === 400 && errorCode(missing) === 'VALIDATION_ERROR', `a request with no token answered ${missing.status} ${errorCode(missing) ?? ''}`.trim());
      },
    },
    {
      id: 'PO04', level: 'MUST', title: 'refuses a revoked Passport on the very next verification (401 PASSPORT_REVOKED), and says the same of every Passport that was made and then ended',
      async run() {
        const { token, jti } = await fresh();
        assert((await verify(token)).status === 200, 'the Passport was not live before the revocation');
        const revoked = await post('/v1/passports/revoke', { jti, reason: 'conformance' });
        assert(revoked.status === 200 && revoked.body?.success === true && revoked.body.jti === jti, `revoking answered ${revoked.status} ${errorCode(revoked) ?? ''}`.trim());
        assert(Number.isInteger(revoked.body.cascaded_count) && Number.isInteger(revoked.body.revoked_claims_count), 'the revoke answer lacks its counts');
        const after = await verify(token);
        assert(after.status === 401 && errorCode(after) === 'PASSPORT_REVOKED', `the next verification answered ${after.status} ${errorCode(after) ?? ''}`.trim());
        const again = await post('/v1/passports/revoke', { jti });
        assert(again.status === 200, `revoking twice answered ${again.status}`);
      },
    },
    {
      id: 'PO05', level: 'MUST', title: 'revokes a Passport\'s descendants with it',
      async run() {
        const { child1 } = await setup();
        const root = await fresh();
        const child = await delegate(root.token, child1);
        assert(child.status === 201, `delegating answered ${child.status} ${errorCode(child) ?? ''}`.trim());
        const grandchild = await delegate(child.body.token, state.child2);
        assert(grandchild.status === 201, `delegating again answered ${grandchild.status}`);
        assert((await verify(grandchild.body.token)).status === 200, 'the grandchild was not live');
        const revoked = await post('/v1/passports/revoke', { jti: root.jti });
        assert(revoked.body?.cascaded_count === 2, `${revoked.body?.cascaded_count} descendants were reported revoked, not 2`);
        dead(await verify(child.body.token), 'the child');
        dead(await verify(grandchild.body.token), 'the grandchild');
      },
    },
    {
      id: 'PO06', level: 'MUST', title: 'revokes every Passport of a Mission when the Mission ends',
      async run() {
        const root = await fresh();
        const child = await delegate(root.token, (await setup()).child1);
        const done = await post(`/v1/missions/${root.missionId}/complete`, {});
        assert(done.status === 200, `completing the Mission answered ${done.status} ${errorCode(done) ?? ''}`.trim());
        dead(await verify(root.token), 'the Passport of a completed Mission');
        dead(await verify(child.body.token), 'a delegated Passport of a completed Mission');
        const again = await post('/v1/passports/issue', { agent_id: root.agentId, mission_ids: [root.missionId], intent: { summary: 'x', services: [] } });
        assert(again.status >= 400 && again.status < 500, `issuing for an ended Mission answered ${again.status}`);
      },
    },
    {
      id: 'PO07', level: 'MUST', title: 'revokes every Passport of an agent, and every Passport of a session, on request',
      async run() {
        const a = await fresh('standard', { own: true });
        const sessionId = claimsOf(a.token).stk.session_id;
        const b = await fresh();
        const byAgent = await post(`/v1/passports/revoke-agent/${a.agentId}`, {});
        assert(byAgent.status === 200 && byAgent.body?.revoked_count >= 1, `revoking an agent answered ${byAgent.status}`);
        dead(await verify(a.token), 'a Passport of a revoked agent');
        assert((await verify(b.token)).status === 200, 'revoking one agent revoked another agent\'s Passport');
        const c = await issue(b.agentId, b.missionId);
        const bySession = await post(`/v1/passports/revoke-session/${claimsOf(c.token).stk.session_id}`, {});
        assert(bySession.status === 200 && bySession.body?.revoked_count >= 1, `revoking a session answered ${bySession.status}`);
        dead(await verify(c.token), 'a Passport of a revoked session');
        assert(typeof sessionId === 'string', 'the Passport has no session id');
      },
    },
    {
      id: 'PD01', level: 'MUST', title: 'delegates a Passport that carries the parent\'s Mission and session, one level deeper, and names its parent',
      async run() {
        const { child1 } = await setup();
        const root = await sharedRoot();
        const r = await delegate(root.token, child1);
        assert(r.status === 201 && typeof r.body?.token === 'string' && typeof r.body.jti === 'string' && r.body.expires_at, `delegating answered ${r.status} ${errorCode(r) ?? ''}`.trim());
        const parent = claimsOf(root.token).stk;
        const stk = claimsOf(r.body.token).stk;
        assert(stk.agent_id === child1 && claimsOf(r.body.token).sub === child1, 'the child Passport is not the child agent\'s');
        assert(stk.delegation_depth === 1 && stk.parent_passport_id === root.jti, 'the depth or the parent is wrong');
        assert(JSON.stringify(stk.mission_ids) === JSON.stringify(parent.mission_ids), 'the child does not carry the parent\'s Mission');
        assert(stk.session_id === parent.session_id, 'the child does not inherit the session');
        const verified = await verify(r.body.token);
        assert(verified.status === 200 && verified.body.claims.delegation_depth === 1, 'the child Passport does not verify online');
      },
    },
    {
      id: 'PD02', level: 'MUST', title: 'never gives a child more life than its parent has left',
      async run() {
        const { child1 } = await setup();
        const root = await sharedRoot();
        const r = await delegate(root.token, child1, { ttl_seconds: 3600 });
        assert(r.status === 201, `delegating answered ${r.status}`);
        const parentExp = claimsOf(root.token).exp;
        const childExp = claimsOf(r.body.token).exp;
        assert(childExp <= parentExp + 1, `the child lives ${childExp - parentExp} seconds beyond its parent`);
      },
    },
    {
      id: 'PD03', level: 'MUST', title: 'stops delegation at depth 4 (400 DELEGATION_DEPTH_EXCEEDED)',
      async run() {
        const { child1, child2 } = await setup();
        let token = (await sharedRoot()).token;
        for (let depth = 1; depth <= 4; depth++) {
          const r = await delegate(token, depth % 2 ? child1 : child2);
          assert(r.status === 201, `delegation to depth ${depth} answered ${r.status} ${errorCode(r) ?? ''}`.trim());
          token = r.body.token;
        }
        const fifth = await delegate(token, child1);
        assert(fifth.status === 400 && errorCode(fifth) === 'DELEGATION_DEPTH_EXCEEDED', `a fifth delegation answered ${fifth.status} ${errorCode(fifth) ?? ''}`.trim());
      },
    },
    {
      id: 'PD04', level: 'MUST', title: 'never delegates to a less accountable agent (400 DELEGATION_ACCOUNTABILITY_VIOLATION)',
      async run() {
        const { child1 } = await setup();
        const enforced = await fresh('enforced');
        const r = await delegate(enforced.token, child1);
        assert(r.status === 400 && errorCode(r) === 'DELEGATION_ACCOUNTABILITY_VIOLATION', `answered ${r.status} ${errorCode(r) ?? ''}`.trim());
        const up = await agent('enforced');
        const fromStandard = await delegate((await fresh('standard')).token, up);
        assert(fromStandard.status === 201, `delegating to a more accountable agent answered ${fromStandard.status} ${errorCode(fromStandard) ?? ''}`.trim());
      },
    },
    {
      id: 'PD05', level: 'MUST', title: 'refuses a scope the parent does not have (400 SCOPE_ESCALATION)',
      async run() {
        const { child1 } = await setup();
        const root = await sharedRoot();
        const r = await delegate(root.token, child1, { scopes: [{ service_connection_id: 'scon_conformance_unknown', scopes: ['read'] }] });
        assert(r.status === 400 && errorCode(r) === 'SCOPE_ESCALATION', `answered ${r.status} ${errorCode(r) ?? ''}`.trim());
      },
    },
    {
      id: 'PD06', level: 'MUST', title: 'refuses to delegate to an agent that does not exist (404) and to delegate from a revoked Passport (401)',
      async run() {
        const { child1 } = await setup();
        const root = await sharedRoot();
        const missing = await delegate(root.token, 'agt_conformance_missing');
        assert(missing.status === 404, `an unknown child answered ${missing.status}`);
        await post('/v1/passports/revoke', { jti: root.jti });
        const revoked = await delegate(root.token, child1);
        assert(revoked.status === 401 && errorCode(revoked) === 'PASSPORT_REVOKED', `a revoked parent answered ${revoked.status} ${errorCode(revoked) ?? ''}`.trim());
      },
    },
    {
      id: 'PD07', level: 'MUST', title: 'narrows scopes and keeps the parent\'s constraints when a child asks for part of a connection',
      async run() {
        const connection = options.connection;
        if (!connection || connection.scopes.length < 2 || typeof connection.grantTo !== 'function') return skip('give the suite a connection with at least two scopes and a way to grant it');
        const { child1 } = await setup();
        const agentId = await agent();
        await connection.grantTo(agentId);
        const missionId = await mission(agentId);
        const parentConstraint = { path: 'method', op: 'eq', value: 'GET' };
        const parent = await issue(agentId, missionId, {
          intent: { summary: 'conformance', services: [], will_delegate: true },
          scopes: [{ service_connection_id: connection.id, scopes: connection.scopes, constraints: [parentConstraint] }],
        });
        const [kept, other] = connection.scopes;
        const narrowed = await delegate(parent.token, child1, { scopes: [{ service_connection_id: connection.id, scopes: [kept], constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1' }] }] });
        assert(narrowed.status === 201, `narrowing answered ${narrowed.status} ${errorCode(narrowed) ?? ''}`.trim());
        const service = claimsOf(narrowed.body.token).stk.services[0];
        assert(JSON.stringify(service.scopes) === JSON.stringify([kept]), `the child has the scopes ${JSON.stringify(service.scopes)}`);
        assert(service.constraints.some((c) => c.path === 'method' && c.op === 'eq' && c.value === 'GET'), 'the child dropped the parent\'s constraint');
        assert(service.constraints.length === 2, 'the child\'s own constraint is missing');
        const escalated = await delegate(narrowed.body.token, state.child2, { scopes: [{ service_connection_id: connection.id, scopes: [kept, other] }] });
        assert(escalated.status === 400 && errorCode(escalated) === 'SCOPE_ESCALATION', `a grandchild asking for a scope its parent lacks answered ${escalated.status}`);
      },
    },
    {
      id: 'PC01', level: 'MUST', title: 'publishes a single event on stack:revoked for a revoked Passport, naming its descendants',
      async run() {
        if (!(await startEvents())) return skip('give the suite a subscription to the revocation channel');
        const root = await fresh();
        const child = await delegate(root.token, (await setup()).child1);
        await post('/v1/passports/revoke', { jti: root.jti, reason: 'conformance' });
        const event = await waitForEvent((e) => e.type === 'single' && e.jti === root.jti);
        assert(event, 'no single event was published');
        assert(!revocationEventProblem(event), `the event is malformed: ${revocationEventProblem(event)}`);
        assert(Array.isArray(event.cascaded) && event.cascaded.includes(claimsOf(child.body.token).jti), 'the event does not list the revoked child');
        assert(Math.abs(event.at - Date.now()) < 120_000, 'at is not a recent time in milliseconds');
      },
    },
    {
      id: 'PC02', level: 'MUST', title: 'publishes bulk_agent for a revoked agent, bulk_session for a session and bulk_mission when a Mission ends',
      async run() {
        if (!(await startEvents())) return skip('give the suite a subscription to the revocation channel');
        const a = await fresh('standard', { own: true });
        await post(`/v1/passports/revoke-agent/${a.agentId}`, {});
        const byAgent = await waitForEvent((e) => e.type === 'bulk_agent' && e.agent_id === a.agentId);
        assert(byAgent && !revocationEventProblem(byAgent), `bulk_agent: ${byAgent ? revocationEventProblem(byAgent) : 'no event'}`);
        const b = await fresh();
        const sessionId = claimsOf(b.token).stk.session_id;
        await post(`/v1/passports/revoke-session/${sessionId}`, {});
        const bySession = await waitForEvent((e) => e.type === 'bulk_session' && e.session_id === sessionId);
        assert(bySession && !revocationEventProblem(bySession), `bulk_session: ${bySession ? revocationEventProblem(bySession) : 'no event'}`);
        const c = await fresh();
        await post(`/v1/missions/${c.missionId}/complete`, {});
        const byMission = await waitForEvent((e) => e.type === 'bulk_mission' && e.mission_id === c.missionId);
        assert(byMission && !revocationEventProblem(byMission), `bulk_mission: ${byMission ? revocationEventProblem(byMission) : 'no event'}`);
        assert(byMission.cascaded_passport_jtis.includes(c.jti), 'bulk_mission does not list the Passport of the Mission');
      },
    },
  ]);
  if (subscription) await subscription().catch(() => undefined);
  return report;
}
