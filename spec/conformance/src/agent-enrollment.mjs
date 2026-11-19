// Conformance suite for a SERVER's agent key enrollment (spec/agent-auth/SPEC.md, sections 4 and 5), including
// the key set it publishes for the agent (spec/agent-keys/SPEC.md, section 4). The kit plays the agent: it
// registers agents on a TEST instance, requests challenges, signs them (rightly and wrongly), enrolls keys, and
// then signs in with them.
//
// You give it the base address of a test instance and the credential of a test operator:
//
//   { baseUrl, headers, approve }
//
// `headers` carries the operator credential (`{ authorization: 'Bearer sk_live_...' }`). `approve(approvalId)` is
// a person's decision: registering an agent and enrolling a key are acts a credential cannot approve for itself,
// so the server answers 403 GOVERNANCE_APPROVAL_REQUIRED with the id of a pending approval, and your `approve`
// decides it (in the Console, or with your install's command line). The kit then repeats the request with the
// approval. Use a test instance: the kit registers agents named conf-* and never removes them.

import { randomUUID } from 'node:crypto';
import { sign } from 'node:crypto';
import { assert, runChecks } from './harness.mjs';
import { callJson, errorCode, newEd25519, randomToken, signEdDsa, unixNow } from './identity-support.mjs';

const APPROVAL_REQUIRED = 'GOVERNANCE_APPROVAL_REQUIRED';

/** Make a client for one instance: calls with the operator credential, and the approval round trip. */
export function enrollmentClient({ baseUrl, headers, approve }) {
  const call = (path, init = {}) => callJson(baseUrl, path, { ...init, headers: { ...headers, ...init.headers } });
  /** Send a request; when the server asks for a person's approval, have it decided and send it again. */
  async function approved(path, init) {
    const first = await call(path, init);
    if (first.status !== 403 || errorCode(first) !== APPROVAL_REQUIRED) return first;
    const approvalId = first.body?.error?.details?.approval_id;
    assert(typeof approvalId === 'string', 'the approval answer names no approval id');
    await approve(approvalId);
    return call(path, { ...init, headers: { ...init.headers, 'x-governance-approval': approvalId } });
  }
  return { baseUrl, call, approved };
}

/** Register an agent whose key the customer holds (or STACK holds, with `keyMode`). */
export async function registerAgent(client, keyMode = 'customer_managed', extra = {}) {
  const name = `conf-${randomToken(6).toLowerCase().replace(/[^a-z0-9]/g, 'x')}`;
  const r = await client.approved('/v1/agents/register', { method: 'POST', body: { name, key_mode: keyMode, ...extra } });
  assert(r.status === 201 && typeof r.body?.id === 'string', `registering an agent answered ${r.status} ${errorCode(r) ?? ''}`.trim());
  return r.body.id;
}

/** Ask for a challenge as the operator. */
export async function requestChallenge(client, agentId, init = {}) {
  return client.call(`/v1/agents/${agentId}/enrollment-challenge`, { method: 'POST', ...init });
}

/** The body of an enroll call: the key, and the challenge signed by `signer`. */
export function enrollBody({ challenge, publicJwk, signer }) {
  return {
    public_key: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x },
    challenge_id: challenge.challenge_id,
    signed_challenge: sign(null, Buffer.from(challenge.challenge, 'utf8'), signer).toString('base64url'),
  };
}

/** Challenge, enroll (with a person's approval) and return the key pair the agent now holds. */
export async function enrollAgent(client, agentId, { force = false } = {}) {
  const key = newEd25519();
  const challenge = await requestChallenge(client, agentId);
  assert(challenge.status === 200, `the challenge call answered ${challenge.status}`);
  const r = await client.approved(`/v1/agents/${agentId}/enroll${force ? '?force=true' : ''}`, {
    method: 'POST',
    body: enrollBody({ challenge: challenge.body, publicJwk: key.publicJwk, signer: key.privateKey }),
  });
  assert(r.status === 200, `enrolling answered ${r.status} ${errorCode(r) ?? ''}`.trim());
  return { ...key, response: r };
}

/** An agent JWT signed with `privateKey`. */
export function agentJwt(agentId, privateKey, over = {}) {
  const now = unixNow();
  return signEdDsa({ alg: 'EdDSA' }, { iss: 'stack-sdk', sub: agentId, aud: 'stack:agent', iat: now, nbf: now, exp: now + 60, jti: `aj_${randomUUID()}`, ...over }, privateKey);
}

/** Whether the server takes the token as a credential: GET /v1/auth/context answers 200 to any it accepts. */
export async function signsIn(client, token) {
  const r = await callJson(client.baseUrl, '/v1/auth/context', { headers: { authorization: `Bearer ${token}` } });
  return { ok: r.status === 200, status: r.status, code: errorCode(r) };
}

/**
 * @param {{ baseUrl: string, headers: Record<string, string>, approve: (approvalId: string) => Promise<void> }} options
 */
export async function runAgentEnrollmentSuite(options) {
  const client = enrollmentClient(options);
  const state = {};
  const setup = async () => {
    if (state.ready) return state;
    state.a = await registerAgent(client);
    state.b = await registerAgent(client);
    state.c = await registerAgent(client);
    state.managed = await registerAgent(client, 'stack_managed');
    state.ready = true;
    return state;
  };
  const stranger = newEd25519();
  const sig = (text, key) => sign(null, Buffer.from(text, 'utf8'), key).toString('base64url');

  return runChecks('agent enrollment', [
    {
      id: 'AE01', level: 'MUST', title: 'answers a challenge: an id, random text, and 300 seconds to use them',
      async run() {
        const { a } = await setup();
        const first = await requestChallenge(client, a);
        const second = await requestChallenge(client, a);
        assert(first.status === 200, `the challenge call answered ${first.status}`);
        for (const field of ['challenge_id', 'challenge']) assert(typeof first.body?.[field] === 'string' && first.body[field].length > 0, `the answer has no ${field}`);
        assert(first.body.expires_in === 300, `expires_in is ${first.body.expires_in}, not 300`);
        assert(first.body.challenge !== second.body.challenge && first.body.challenge_id !== second.body.challenge_id, 'two challenges were the same');
      },
    },
    {
      id: 'AE02', level: 'MUST', title: 'answers 404 for an agent that does not exist, on both calls',
      async run() {
        await setup();
        const missing = `agt_${randomToken(9)}`;
        assert((await requestChallenge(client, missing)).status === 404, 'the challenge call for an unknown agent was not a 404');
        const key = newEd25519();
        const r = await client.call(`/v1/agents/${missing}/enroll`, { method: 'POST', body: enrollBody({ challenge: { challenge_id: 'x', challenge: 'y' }, publicJwk: key.publicJwk, signer: key.privateKey }) });
        assert(r.status === 404, `the enroll call for an unknown agent answered ${r.status}`);
      },
    },
    {
      id: 'AE03', level: 'MUST', title: 'refuses a body that is not an Ed25519 key, a challenge id and a signature (400 VALIDATION_ERROR)',
      async run() {
        const { a } = await setup();
        const key = newEd25519();
        const challenge = (await requestChallenge(client, a)).body;
        const good = enrollBody({ challenge, publicJwk: key.publicJwk, signer: key.privateKey });
        const bodies = [
          ['no signature', { ...good, signed_challenge: undefined }],
          ['no challenge id', { ...good, challenge_id: undefined }],
          ['an RSA-shaped key', { ...good, public_key: { kty: 'RSA', n: 'abc', e: 'AQAB' } }],
          ['a key of the wrong length', { ...good, public_key: { ...good.public_key, x: 'AAAA' } }],
        ];
        for (const [why, body] of bodies) {
          const r = await client.call(`/v1/agents/${a}/enroll`, { method: 'POST', body });
          assert(r.status === 400 && errorCode(r) === 'VALIDATION_ERROR', `${why}: ${r.status} ${errorCode(r) ?? ''}`.trim());
        }
      },
    },
    {
      id: 'AE04', level: 'MUST', title: 'refuses a key whose holder cannot sign the challenge (400 INVALID_ENROLLMENT), before any approval is asked',
      async run() {
        const { a } = await setup();
        const key = newEd25519();
        const challenge = (await requestChallenge(client, a)).body;
        const good = enrollBody({ challenge, publicJwk: key.publicJwk, signer: key.privateKey });
        for (const [why, body] of [
          ['a signature by another key', { ...good, signed_challenge: sig(challenge.challenge, stranger.privateKey) }],
          ['a signature over other text', { ...good, signed_challenge: sig(`${challenge.challenge}x`, key.privateKey) }],
        ]) {
          const r = await client.call(`/v1/agents/${a}/enroll`, { method: 'POST', body });
          assert(r.status === 400 && errorCode(r) === 'INVALID_ENROLLMENT', `${why}: ${r.status} ${errorCode(r) ?? ''}`.trim());
        }
      },
    },
    {
      id: 'AE05', level: 'MUST', title: 'refuses a challenge id the server did not issue, and one issued for another agent',
      async run() {
        const { a, c } = await setup();
        const key = newEd25519();
        const unknown = { challenge_id: `enr_${randomToken(12)}`, challenge: 'chl_made_up' };
        let r = await client.call(`/v1/agents/${a}/enroll`, { method: 'POST', body: enrollBody({ challenge: unknown, publicJwk: key.publicJwk, signer: key.privateKey }) });
        assert(r.status === 400 && errorCode(r) === 'INVALID_ENROLLMENT', `a made-up challenge: ${r.status} ${errorCode(r) ?? ''}`.trim());
        const forC = (await requestChallenge(client, c)).body;
        r = await client.call(`/v1/agents/${a}/enroll`, { method: 'POST', body: enrollBody({ challenge: forC, publicJwk: key.publicJwk, signer: key.privateKey }) });
        assert(r.status === 400 && errorCode(r) === 'INVALID_ENROLLMENT', `a challenge issued for another agent: ${r.status} ${errorCode(r) ?? ''}`.trim());
      },
    },
    {
      id: 'AE06', level: 'MUST', title: 'asks for a person\'s approval of the exact enrollment when the caller is a credential (403 GOVERNANCE_APPROVAL_REQUIRED)',
      async run() {
        const { a } = await setup();
        const key = newEd25519();
        const challenge = (await requestChallenge(client, a)).body;
        const r = await client.call(`/v1/agents/${a}/enroll`, { method: 'POST', body: enrollBody({ challenge, publicJwk: key.publicJwk, signer: key.privateKey }) });
        assert(r.status === 403 && errorCode(r) === APPROVAL_REQUIRED, `answered ${r.status} ${errorCode(r) ?? ''}`.trim());
        assert(typeof r.body?.error?.details?.approval_id === 'string', 'the answer names no approval');
        // The approval is of this key: another key needs its own.
        await options.approve(r.body.error.details.approval_id);
        const other = newEd25519();
        const forOther = await client.call(`/v1/agents/${a}/enroll`, {
          method: 'POST', headers: { 'x-governance-approval': r.body.error.details.approval_id },
          body: enrollBody({ challenge, publicJwk: other.publicJwk, signer: other.privateKey }),
        });
        assert(forOther.status === 403, `an approval for one key was used for another: ${forOther.status}`);
      },
    },
    {
      id: 'AE10', level: 'MUST', title: 'enrolls the key, answers the agent id and the time, and lets the agent sign in with it',
      async run() {
        const { a } = await setup();
        const enrolled = await enrollAgent(client, a);
        const body = enrolled.response.body;
        assert(body?.agent_id === a, 'the answer names another agent');
        assert(typeof body.enrolled_at === 'string' && !Number.isNaN(Date.parse(body.enrolled_at)), 'enrolled_at is not a time');
        state.aKey = enrolled;
        const result = await signsIn(client, agentJwt(a, enrolled.privateKey));
        assert(result.ok, `the enrolled agent could not sign in (${result.status} ${result.code ?? ''})`.trim());
      },
    },
    {
      id: 'AE11', level: 'MUST', title: 'uses a challenge once',
      async run() {
        const { b } = await setup();
        const key = newEd25519();
        const challenge = (await requestChallenge(client, b)).body;
        const body = enrollBody({ challenge, publicJwk: key.publicJwk, signer: key.privateKey });
        const first = await client.approved(`/v1/agents/${b}/enroll`, { method: 'POST', body });
        assert(first.status === 200, `the first enroll answered ${first.status}`);
        const again = await client.approved(`/v1/agents/${b}/enroll?force=true`, { method: 'POST', body });
        assert(again.status === 400 && errorCode(again) === 'INVALID_ENROLLMENT', `the used challenge answered ${again.status} ${errorCode(again) ?? ''}`.trim());
        state.bKey = key;
      },
    },
    {
      id: 'AE12', level: 'MUST', title: 'refuses a second enrollment of an agent that has a key, without force (409 CONFLICT)',
      async run() {
        const { a } = await setup();
        if (!state.aKey) await enrollAgent(client, a).then((k) => { state.aKey = k; });
        const key = newEd25519();
        const challenge = (await requestChallenge(client, a)).body;
        const r = await client.approved(`/v1/agents/${a}/enroll`, { method: 'POST', body: enrollBody({ challenge, publicJwk: key.publicJwk, signer: key.privateKey }) });
        assert(r.status === 409 && errorCode(r) === 'CONFLICT', `answered ${r.status} ${errorCode(r) ?? ''}`.trim());
      },
    },
    {
      id: 'AE13', level: 'MUST', title: 'refuses to enroll a key for an agent whose key STACK holds (409 ENROLL_NOT_APPLICABLE)',
      async run() {
        const { managed } = await setup();
        const key = newEd25519();
        const challenge = (await requestChallenge(client, managed)).body;
        const r = await client.approved(`/v1/agents/${managed}/enroll`, { method: 'POST', body: enrollBody({ challenge, publicJwk: key.publicJwk, signer: key.privateKey }) });
        assert(r.status === 409 && errorCode(r) === 'ENROLL_NOT_APPLICABLE', `answered ${r.status} ${errorCode(r) ?? ''}`.trim());
      },
    },
    {
      id: 'AE14', level: 'MUST', title: 'publishes the enrolled key at the agent\'s key set, under the key id agent:{id}:v1, and 404 before there is one',
      async run() {
        const { a, c } = await setup();
        const before = await callJson(client.baseUrl, `/v1/agents/${c}/.well-known/jwks.json`);
        assert(before.status === 404 && errorCode(before) === 'SIGNING_KEY_UNAVAILABLE', `an agent with no key answered ${before.status} ${errorCode(before) ?? ''}`.trim());
        if (!state.aKey) state.aKey = await enrollAgent(client, a);
        const after = await callJson(client.baseUrl, `/v1/agents/${a}/.well-known/jwks.json`);
        assert(after.status === 200, `the key set answered ${after.status}`);
        const keys = after.body?.keys;
        assert(Array.isArray(keys) && keys.length === 1, 'the key set does not hold exactly one key');
        const k = keys[0];
        assert(k.kty === 'OKP' && k.crv === 'Ed25519' && k.alg === 'EdDSA' && k.use === 'sig', 'the key is not an Ed25519 signing key');
        assert(k.kid === `agent:${a}:v1`, `the kid is ${k.kid}`);
        assert(k.x === state.aKey.publicJwk.x, 'the published key is not the enrolled one');
        assert(!('d' in k), 'the key set carries a private member');
        assert(k.not_after === null && Number.isInteger(k.not_before), 'not_before and not_after are not as specified');
      },
    },
    {
      id: 'AE20', level: 'MUST', title: 'accepts an enrollment ticket for the one agent it names, without a further approval, and only once',
      async run() {
        const { c } = await setup();
        const minted = await client.approved(`/v1/agents/${c}/enrollment-tickets`, { method: 'POST', body: {} });
        assert(minted.status === 200 && typeof minted.body?.ticket === 'string', `minting a ticket answered ${minted.status} ${errorCode(minted) ?? ''}`.trim());
        assert(minted.body.expires_in === 300, `the ticket's expires_in is ${minted.body.expires_in}`);
        const ticket = { authorization: `Bearer ${minted.body.ticket}` };
        // Bound to the agent: another agent's challenge is refused.
        const other = await callJson(client.baseUrl, `/v1/agents/${state.managed}/enrollment-challenge`, { method: 'POST', headers: ticket });
        assert(other.status === 403, `a ticket for another agent answered ${other.status}`);
        const key = newEd25519();
        const challenge = await callJson(client.baseUrl, `/v1/agents/${c}/enrollment-challenge`, { method: 'POST', headers: ticket });
        assert(challenge.status === 200, `a challenge with the ticket answered ${challenge.status}`);
        const body = enrollBody({ challenge: challenge.body, publicJwk: key.publicJwk, signer: key.privateKey });
        const enrolled = await callJson(client.baseUrl, `/v1/agents/${c}/enroll`, { method: 'POST', headers: ticket, body });
        assert(enrolled.status === 200, `enrolling with the ticket answered ${enrolled.status} ${errorCode(enrolled) ?? ''}`.trim());
        assert((await signsIn(client, agentJwt(c, key.privateKey))).ok, 'the agent enrolled with a ticket could not sign in');
        const again = await callJson(client.baseUrl, `/v1/agents/${c}/enrollment-challenge`, { method: 'POST', headers: ticket });
        assert(again.status === 401, `a used ticket answered ${again.status}`);
        state.cKey = key;
      },
    },
    {
      id: 'AE21', level: 'MUST', title: 'treats a bearer that is not a valid ticket as an ordinary credential, and refuses garbage (401)',
      async run() {
        const { a } = await setup();
        const r = await callJson(client.baseUrl, `/v1/agents/${a}/enrollment-challenge`, { method: 'POST', headers: { authorization: 'Bearer not.a.ticket' } });
        assert(r.status === 401, `answered ${r.status}`);
        const none = await callJson(client.baseUrl, `/v1/agents/${a}/enrollment-challenge`, { method: 'POST' });
        assert(none.status === 401, `no credential answered ${none.status}`);
      },
    },
    {
      id: 'AE30', level: 'MUST', title: 'rotates a key only on request (force=true) and then stops accepting the old key',
      async run() {
        const { a } = await setup();
        if (!state.aKey) state.aKey = await enrollAgent(client, a);
        const old = state.aKey;
        const rotated = await enrollAgent(client, a, { force: true });
        assert(rotated.response.body?.agent_id === a, 'the rotation answered another agent');
        const oldResult = await signsIn(client, agentJwt(a, old.privateKey));
        assert(!oldResult.ok && oldResult.status === 401, `the old key still signs in (${oldResult.status})`);
        assert((await signsIn(client, agentJwt(a, rotated.privateKey))).ok, 'the new key does not sign in');
        const set = await callJson(client.baseUrl, `/v1/agents/${a}/.well-known/jwks.json`);
        assert(set.body?.keys?.length === 1 && set.body.keys[0].x === rotated.publicJwk.x, 'the key set was not replaced');
        assert(set.body.keys[0].kid === `agent:${a}:v1`, 'the key id changed with the key');
        state.aKey = rotated;
      },
    },
  ]);
}
