// Conformance suite for FLEET ENROLLMENT through a provisioner agent (spec/agent-auth/SPEC.md, section 6): the
// challenge and enroll calls at /v1/fleets/{policy}/enrollment-challenges and /v1/fleets/{policy}/enroll. The kit
// sets up a test fleet (an enrolled provisioner agent and a policy that names it), then plays a worker: it
// requests challenges as the provisioner, signs them with keys of its own, and enrolls them, rightly and wrongly.
//
// The workload principal (a SPIFFE or WIMSE token) needs an issuer the server can fetch keys from, which a kit
// cannot give a test instance; its rules are tested in the `workload-token` suite and in the engine's own tests.
//
//   { baseUrl, headers, approve }   as the `agent-enrollment` suite: a test operator's credential and a person's
//                                   decision for the approvals that registering an agent and a policy need.

import { createHash, sign } from 'node:crypto';
import { agentJwt, enrollAgent, enrollmentClient, registerAgent, signsIn } from './agent-enrollment.mjs';
import { assert, runChecks } from './harness.mjs';
import { callJson, errorCode, newEd25519, randomToken } from './identity-support.mjs';

const thumbprintOf = (jwk) => createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`).digest('base64url');
const sig = (text, key) => sign(null, Buffer.from(text, 'utf8'), key).toString('base64url');

/** The string a worker signs with its previous key to replace it (spec/agent-auth section 6.2). */
export function rotationMessage({ challenge, challenge_id, idempotency_key, policy_id, public_key_thumbprint }) {
  return JSON.stringify({ challenge, challenge_id, domain: 'stack:fleet-key-rotation:v1', idempotency_key, policy_id, public_key_thumbprint });
}

/** @param {{ baseUrl: string, headers: Record<string, string>, approve: (id: string) => Promise<void> }} options */
export async function runFleetEnrollmentSuite(options) {
  const client = enrollmentClient(options);
  const state = {};
  const setup = async () => {
    if (state.ready) return state;
    state.provisionerId = await registerAgent(client);
    state.provisioner = await enrollAgent(client, state.provisionerId);
    const created = await client.approved('/v1/fleets', {
      method: 'POST',
      headers: { 'idempotency-key': `conf-fleet-${randomToken(8)}` },
      body: {
        name: 'conformance fleet',
        rules: [],
        operation_rules: [{ id: 'drop', effect: 'allow', access: { producer: 'dropoff', target_id: 'conformance', action: 'create' } }],
        limits: { max_actions: 10, max_concurrent_actions: 2, max_duration_seconds: 600 },
        window_seconds: 3600,
        max_members: 20,
        max_enrollments_per_hour: 200,
        identity_lease_seconds: 600,
        provisioner_agent_ids: [state.provisionerId],
        workload_trust: [],
        allow_delegation: false,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      },
    });
    assert(created.status === 200 && /^flp_/.test(created.body?.id ?? ''), `creating the policy answered ${created.status} ${errorCode(created) ?? ''}`.trim());
    state.policy = created.body.id;
    state.ready = true;
    return state;
  };
  const asProvisioner = () => ({ authorization: `Bearer ${agentJwt(state.provisionerId, state.provisioner.privateKey)}` });
  const challenge = async (headers) => callJson(client.baseUrl, `/v1/fleets/${state.policy}/enrollment-challenges`, { method: 'POST', headers, body: {} });
  const enroll = (headers, body) => callJson(client.baseUrl, `/v1/fleets/${state.policy}/enroll`, { method: 'POST', headers, body });
  const worker = () => {
    const key = newEd25519();
    return { key, idempotency_key: `conf-${randomToken(10)}`, name: `worker-${randomToken(4)}` };
  };
  const body = (w, ch, over = {}) => ({
    idempotency_key: w.idempotency_key,
    name: w.name,
    public_key: { kty: 'OKP', crv: 'Ed25519', x: w.key.publicJwk.x },
    challenge_id: ch.challenge_id,
    proof: sig(ch.challenge, w.key.privateKey),
    ...over,
  });
  /** Enroll a worker as the provisioner. */
  const enrolled = async (w) => {
    const ch = await challenge(asProvisioner());
    assert(ch.status === 200, `a challenge answered ${ch.status} ${errorCode(ch) ?? ''}`.trim());
    return enroll(asProvisioner(), body(w, ch.body));
  };

  return runChecks('fleet enrollment', [
    {
      id: 'FE01', level: 'MUST', title: 'answers a provisioner\'s challenge call: an id, random text, and 120 seconds',
      async run() {
        await setup();
        const r = await challenge(asProvisioner());
        assert(r.status === 200, `answered ${r.status} ${errorCode(r) ?? ''}`.trim());
        assert(typeof r.body.challenge_id === 'string' && typeof r.body.challenge === 'string' && r.body.challenge.length > 0, 'the answer has no challenge');
        assert(r.body.expires_in === 120, `expires_in is ${r.body.expires_in}, not 120`);
      },
    },
    {
      id: 'FE02', level: 'MUST', title: 'answers 403 to a caller that is not the policy\'s provisioner (the operator\'s key, an agent the policy does not name), and 401 to no credential',
      async run() {
        await setup();
        assert((await challenge({ authorization: options.headers.authorization })).status === 403, 'the operator\'s own key was given a challenge');
        const strangerId = await registerAgent(client);
        const enrolledStranger = await enrollAgent(client, strangerId);
        const asStranger = await challenge({ authorization: `Bearer ${agentJwt(strangerId, enrolledStranger.privateKey)}` });
        assert(asStranger.status === 403 && errorCode(asStranger) === 'FORBIDDEN', `an agent the policy does not name answered ${asStranger.status} ${errorCode(asStranger) ?? ''}`.trim());
        assert((await challenge({})).status === 401, 'a call with no credential was not 401');
      },
    },
    {
      id: 'FE03', level: 'MUST', title: 'enrolls a worker: 201 with its agent id, membership id and the end of its lease; the worker signs in with its key',
      async run() {
        await setup();
        const w = worker();
        const r = await enrolled(w);
        assert(r.status === 201, `enrolling answered ${r.status} ${errorCode(r) ?? ''}`.trim());
        assert(/^agt_/.test(r.body.agent_id) && typeof r.body.membership_id === 'string', 'the answer does not name the agent and the membership');
        const until = Date.parse(r.body.identity_expires_at);
        assert(until > Date.now() && until <= Date.now() + 601_000, 'the lease does not end within the policy\'s 600 seconds');
        assert((await signsIn(client, agentJwt(r.body.agent_id, w.key.privateKey))).ok, 'the worker could not sign in');
        state.worker = { ...w, agentId: r.body.agent_id, membershipId: r.body.membership_id };
      },
    },
    {
      id: 'FE04', level: 'MUST', title: 'answers the same agent and membership to a repeat of the same enrollment, with a new challenge and proof',
      async run() {
        await setup();
        if (!state.worker) {
          const w = worker();
          const r = await enrolled(w);
          state.worker = { ...w, agentId: r.body.agent_id, membershipId: r.body.membership_id };
        }
        const again = await enrolled(state.worker);
        assert(again.status === 201, `the repeat answered ${again.status} ${errorCode(again) ?? ''}`.trim());
        assert(again.body.agent_id === state.worker.agentId && again.body.membership_id === state.worker.membershipId, 'the repeat made a second agent or membership');
      },
    },
    {
      id: 'FE05', level: 'MUST', title: 'refuses the same idempotency key with another name (409 CONFLICT)',
      async run() {
        await setup();
        const w = state.worker ?? worker();
        if (!state.worker) await enrolled(w);
        const ch = (await challenge(asProvisioner())).body;
        const r = await enroll(asProvisioner(), body(w, ch, { name: `${w.name}-other` }));
        assert(r.status === 409 && errorCode(r) === 'CONFLICT', `answered ${r.status} ${errorCode(r) ?? ''}`.trim());
      },
    },
    {
      id: 'FE06', level: 'MUST', title: 'refuses a proof by another key, a proof over other text, a challenge that was used and one that was never issued (403 FORBIDDEN)',
      async run() {
        await setup();
        const w = worker();
        const other = newEd25519();
        let ch = (await challenge(asProvisioner())).body;
        for (const [why, bad] of [
          ['a proof by another key', body(w, ch, { proof: sig(ch.challenge, other.privateKey) })],
          ['a proof over other text', body(w, ch, { proof: sig(`${ch.challenge}x`, w.key.privateKey) })],
          ['a challenge that was never issued', body(w, { challenge_id: `fec_${randomToken(12)}`, challenge: 'made-up' })],
        ]) {
          const r = await enroll(asProvisioner(), bad);
          assert(r.status === 403 && errorCode(r) === 'FORBIDDEN', `${why}: ${r.status} ${errorCode(r) ?? ''}`.trim());
        }
        ch = (await challenge(asProvisioner())).body;
        const good = body(w, ch);
        assert((await enroll(asProvisioner(), good)).status === 201, 'the first use of a challenge failed');
        const reused = await enroll(asProvisioner(), good);
        assert(reused.status === 403, `a challenge used twice answered ${reused.status}`);
      },
    },
    {
      id: 'FE07', level: 'MUST', title: 'refuses a body with a member the schema does not name, a short idempotency key or a key that is not Ed25519 (400 VALIDATION_ERROR)',
      async run() {
        await setup();
        const w = worker();
        const ch = (await challenge(asProvisioner())).body;
        for (const [why, bad] of [
          ['an extra member', body(w, ch, { agent_id: 'agt_x' })],
          ['an idempotency key of 3 characters', body(w, ch, { idempotency_key: 'abc' })],
          ['a P-256 key', body(w, ch, { public_key: { kty: 'EC', crv: 'P-256', x: w.key.publicJwk.x } })],
        ]) {
          const r = await enroll(asProvisioner(), bad);
          assert(r.status === 400 && errorCode(r) === 'VALIDATION_ERROR', `${why}: ${r.status} ${errorCode(r) ?? ''}`.trim());
        }
      },
    },
    {
      id: 'FE08', level: 'MUST', title: 'replaces a worker\'s key only with a proof by the previous key over the rotation message (403 without one, 201 with)',
      async run() {
        await setup();
        const w = worker();
        const first = await enrolled(w);
        assert(first.status === 201, 'the first enrollment failed');
        const next = newEd25519();
        const asNext = { ...w, key: next };
        let ch = (await challenge(asProvisioner())).body;
        const without = await enroll(asProvisioner(), body(asNext, ch));
        assert(without.status === 403, `a new key with no previous proof answered ${without.status}`);
        ch = (await challenge(asProvisioner())).body;
        const message = (c) => rotationMessage({ challenge: c.challenge, challenge_id: c.challenge_id, idempotency_key: w.idempotency_key, policy_id: state.policy, public_key_thumbprint: thumbprintOf(next.publicJwk) });
        const wrongKey = await enroll(asProvisioner(), body(asNext, ch, { previous_key_proof: sig(message(ch), newEd25519().privateKey) }));
        assert(wrongKey.status === 403, `a previous proof by another key answered ${wrongKey.status}`);
        ch = (await challenge(asProvisioner())).body;
        const wrongText = await enroll(asProvisioner(), body(asNext, ch, { previous_key_proof: sig(ch.challenge, w.key.privateKey) }));
        assert(wrongText.status === 403, `a previous proof over the bare challenge answered ${wrongText.status}`);
        ch = (await challenge(asProvisioner())).body;
        const rotated = await enroll(asProvisioner(), body(asNext, ch, { previous_key_proof: sig(message(ch), w.key.privateKey) }));
        assert(rotated.status === 201 && rotated.body.agent_id === first.body.agent_id, `the rotation answered ${rotated.status} ${errorCode(rotated) ?? ''}`.trim());
        const old = await signsIn(client, agentJwt(first.body.agent_id, w.key.privateKey));
        assert(!old.ok && old.status === 401, `the old key still signs in (${old.status})`);
        assert((await signsIn(client, agentJwt(first.body.agent_id, next.privateKey))).ok, 'the new key does not sign in');
      },
    },
    {
      id: 'FE09', level: 'MUST', title: 'refuses a previous-key proof on a first enrollment (403)',
      async run() {
        await setup();
        const w = worker();
        const ch = (await challenge(asProvisioner())).body;
        const r = await enroll(asProvisioner(), body(w, ch, { previous_key_proof: sig('anything', w.key.privateKey) }));
        assert(r.status === 403, `answered ${r.status}`);
      },
    },
    {
      id: 'FE10', level: 'MUST', title: 'does not let an enrolled worker enroll others (403): only the provisioner may',
      async run() {
        await setup();
        if (!state.worker) return;
        const asWorker = { authorization: `Bearer ${agentJwt(state.worker.agentId, state.worker.key.privateKey)}` };
        const r = await challenge(asWorker);
        assert(r.status === 403, `a worker's challenge call answered ${r.status}`);
      },
    },
  ]);
}
