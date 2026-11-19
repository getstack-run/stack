// Conformance suite for a SERVER of the STACK REST API: the engine, or anything that serves the same routes. The kit
// plays the client. It checks what spec/rest-api/SPEC.md says every route has in common: the error envelope and the status
// classes, how a request is read, how a credential is refused, the governance step-up, and (with probes you supply) the
// `402` answers, the refusals of a customer's controls and the model cost cap.
//
// Point it at a base URL:
//
//   { url }                           what needs no credential: the envelope, the reading of a request, the refusal of a
//                                     credential that is absent or bad
//   { url, apiKey }                   also the step-up: a gated change refused, read, retried, and refused again once used
//   { url, apiKey, approve }          also the retry of an approved change. `approve(approvalId)` is the person at the
//                                     machine: it decides the approval the way your deployment lets a person decide
//   { probes: { payment, controls, costCap } }
//                                     requests that make your server answer a `402`, a refusal of a control, a cost cap
//
// Use a TEST instance and a TEST credential: the suite changes things (it asks to register an agent, and with `approve` it
// does). A check that needs something it was not given is reported as skipped, never as passed.

import { randomBytes } from 'node:crypto';
import { assert, assertEqual, runChecks, skip } from './harness.mjs';

const CODE = /^[A-Z][A-Z0-9_]*$/;
const APPROVAL_ID = /^gvr_[A-Za-z0-9_-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const JSON_TYPE = /^application\/json\b/i;

/**
 * @typedef {{ method: string, path: string, body?: unknown, headers?: Record<string, string> }} ProbeRequest
 * @typedef {{
 *   url: string,
 *   apiKey?: string,
 *   approve?: (approvalId: string) => Promise<void> | void,
 *   protectedPath?: string,
 *   jsonPath?: string,
 *   stepUp?: (variant: 'asked' | 'other', nonce: string) => ProbeRequest,
 *   probes?: {
 *     stepUp?: { asked: ProbeRequest, other: ProbeRequest },
 *     payment?: ProbeRequest & { code?: string },
 *     controls?: Array<ProbeRequest & { code: 'CONTROL_DENIED' | 'CONTROL_LIMIT_EXCEEDED' | 'CONTROL_SOCKET_UNAVAILABLE' | 'CONTROL_UNAVAILABLE' }>,
 *     costCap?: ProbeRequest & { mode: 'own_key' | 'deployment_key' },
 *     perJob?: { unbounded: ProbeRequest, policy: ProbeRequest, unpinned: ProbeRequest, stranger: ProbeRequest, pinned: ProbeRequest, recipients?: string[] },
 *   },
 *   only?: string[],
 *   timeoutMs?: number,
 *   fetchImpl?: typeof fetch,
 * }} RestApiOptions
 */

/**
 * The gated change the suite asks for when the server gates registering an agent: registering one. `nonce` is new in every
 * run, so a run never meets the agent of the one before. The suite's own default is the change a server that does not
 * gate registration still gates (unblocking an agent, see `runRestApiSuite`); a server names another with
 * `probes.stepUp` (two requests, the one asked for and a different one) or, from code, with the `stepUp` option.
 */
export function defaultStepUp(variant, nonce) {
  return { method: 'POST', path: '/v1/agents/register', body: { name: `conformance-${variant === 'other' ? 'other-' : ''}${nonce}` } };
}

/** What is wrong with an error answer as section 5.1 of the specification describes it, or null. */
export function envelopeProblem(response) {
  if (response.status < 400) return `the status ${response.status} is not an error`;
  if (!JSON_TYPE.test(response.headers.get('content-type') ?? '')) return `the content type is ${JSON.stringify(response.headers.get('content-type'))}, not application/json`;
  const { json } = response;
  if (json === null || typeof json !== 'object' || Array.isArray(json)) return 'the body is not a JSON object';
  const keys = Object.keys(json);
  if (keys.length !== 1 || keys[0] !== 'error') return `the body has the properties ${JSON.stringify(keys)}, not only "error"`;
  const { error } = json;
  if (error === null || typeof error !== 'object' || Array.isArray(error)) return '"error" is not an object';
  if (typeof error.code !== 'string' || !CODE.test(error.code)) return `"error.code" is ${JSON.stringify(error.code)}, not a code in upper case with underscores`;
  if (typeof error.message !== 'string' || error.message.length === 0) return '"error.message" is not a non-empty string';
  if ('details' in error && (error.details === null || typeof error.details !== 'object' || Array.isArray(error.details))) return '"error.details" is present and not an object';
  const extra = Object.keys(error).filter((key) => !['code', 'message', 'details'].includes(key));
  if (extra.length > 0) return `"error" has the extra properties ${JSON.stringify(extra)}`;
  return null;
}

/**
 * @param {RestApiOptions} options
 */
export async function runRestApiSuite(options) {
  const { url, apiKey, approve, probes = {}, timeoutMs = 15_000, fetchImpl = fetch } = options;
  const protectedPath = options.protectedPath ?? '/v1/operators/me';
  const jsonPath = options.jsonPath ?? '/v1/passports/verify';
  const nonce = randomBytes(5).toString('hex');
  // The agents this run made, removed when it ends (best effort): a run must not leave its test agents on the server.
  const created = [];
  let unblockPlan;
  /**
   * The default gated change. Register two agents (the one change asked for and a different one) and ask to unblock
   * them: unblocking releases a block, so a server gates it whether or not it gates registration. A server that answers
   * the registration with a request for a person's approval gates registering instead, and the suite asks for that.
   */
  function defaultUnblockPlan() {
    unblockPlan ??= (async () => {
      const made = [];
      for (const variant of ['asked', 'other']) {
        const response = await send('POST', '/v1/agents/register', { headers: bearer, body: { name: `conformance-${variant}-${nonce}` } });
        if (response.status < 200 || response.status >= 300 || typeof response.json?.id !== 'string') break;
        made.push(response.json.id);
        created.push(response.json.id);
      }
      if (made.length < 2) return null;
      return {
        asked: { method: 'POST', path: `/v1/agents/${made[0]}/unblock` },
        other: { method: 'POST', path: `/v1/agents/${made[1]}/unblock` },
      };
    })();
    return unblockPlan;
  }
  async function stepUp(variant) {
    if (options.stepUp) return options.stepUp(variant, nonce);
    if (probes.stepUp) return probes.stepUp[variant === 'other' ? 'other' : 'asked'];
    const plan = apiKey ? await defaultUnblockPlan() : null;
    return plan ? plan[variant === 'other' ? 'other' : 'asked'] : defaultStepUp(variant, nonce);
  }
  async function removeCreatedAgents() {
    for (const agentId of created) {
      try {
        await send('DELETE', `/v1/agents/${encodeURIComponent(agentId)}`, { headers: bearer });
      } catch {
        /* the run is over; a server that cannot delete is told by its own state */
      }
    }
  }
  const base = url.replace(/\/+$/, '');
  const bearer = apiKey ? { authorization: `Bearer ${apiKey}` } : {};

  /** One request; never throws on a status. */
  async function send(method, path, { headers = {}, body, raw } = {}) {
    const hasBody = raw !== undefined || body !== undefined;
    const response = await fetchImpl(`${base}${path}`, {
      method,
      headers: { ...(hasBody && raw === undefined ? { 'content-type': 'application/json' } : {}), ...headers },
      ...(hasBody ? { body: raw ?? JSON.stringify(body) } : {}),
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await response.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: response.status, headers: response.headers, text, json };
  }
  const sendProbe = (probe, extraHeaders = {}) => send(probe.method, probe.path, { headers: { ...bearer, ...(probe.headers ?? {}), ...extraHeaders }, ...(probe.body !== undefined ? { body: probe.body } : {}) });

  function assertEnvelope(response, status, code, what) {
    assertEqual(response.status, status, `${what}: the status`);
    const problem = envelopeProblem(response);
    assert(problem === null, `${what}: ${problem}`);
    assertEqual(response.json.error.code, code, `${what}: error.code`);
  }

  const needKey = () => (apiKey ? null : skip('needs apiKey'));

  // The step-up checks share one approval; they run in order and the first one that creates it keeps it for the others.
  const approval = { id: null, hash: null, created: null };
  async function asked() {
    if (approval.created) return approval.created;
    approval.created = (async () => {
      const request = await stepUp('asked');
      const refused = await sendProbe(request);
      return { request, refused };
    })();
    return approval.created;
  }

  const checks = [
    // ─── The reading of a request, and the envelope ───
    {
      id: 'R01', level: 'MUST', title: 'a request that reaches no route is 404 NOT_FOUND in the error envelope',
      async run() {
        assertEnvelope(await send('GET', '/v1/conformance/no-such-route'), 404, 'NOT_FOUND', 'an unknown path');
      },
    },
    {
      id: 'R02', level: 'MUST', title: 'a method a path does not serve is a 404 as well: there is no 405',
      async run() {
        const response = await send('DELETE', '/health');
        assertEnvelope(response, 404, 'NOT_FOUND', 'DELETE on a path that serves GET');
      },
    },
    {
      id: 'R03', level: 'MUST', title: 'the 404 does not echo a query string or a token-shaped path segment',
      async run() {
        const token = ['Zk3Tq9LmN0pQr', 'StUvWxYz1234567890', 'AbCdEfGhIj'].join('');
        const secret = ['sk', 'live', 'conformance', 'marker', '0001'].join('_');
        const response = await send('GET', `/v1/conformance/${token}/more?api_key=${secret}`);
        assertEnvelope(response, 404, 'NOT_FOUND', 'an unknown path with a token');
        assert(!response.text.includes(token), 'the token-shaped path segment was echoed');
        assert(!response.text.includes(secret), 'the query string was echoed');
      },
    },
    {
      id: 'R04', level: 'MUST', title: 'HEAD is answered for a GET route, with no body',
      async run() {
        const response = await send('HEAD', '/health');
        assertEqual(response.status, 200, 'HEAD /health');
        assertEqual(response.text, '', 'the body of a HEAD answer');
      },
    },
    {
      id: 'R10', level: 'MUST', title: 'a body that is not JSON is 400 INVALID_JSON, never a 500',
      async run() {
        for (const raw of ['{', '{"a":', 'not json', '{"a":1}}']) {
          assertEnvelope(await send('POST', jsonPath, { headers: { 'content-type': 'application/json' }, raw }), 400, 'INVALID_JSON', `the body ${JSON.stringify(raw)}`);
        }
      },
    },
    {
      id: 'R11', level: 'MUST', title: 'a body that fails the route\'s schema is 400 VALIDATION_ERROR',
      async run() {
        assertEnvelope(await send('POST', jsonPath, { body: { token: 5 } }), 400, 'VALIDATION_ERROR', 'a body of the wrong shape');
        assertEnvelope(await send('POST', jsonPath, { body: {} }), 400, 'VALIDATION_ERROR', 'a body with a missing field');
      },
    },
    {
      id: 'R15', level: 'SHOULD', title: 'the message of a validation error names fields and what was expected, not the text of the values that were sent',
      async run() {
        const marker = 'conformance_marker_value_7f3a';
        const response = await send('POST', jsonPath, { body: { token: 5, unexpected: marker } });
        assertEnvelope(response, 400, 'VALIDATION_ERROR', 'a body of the wrong shape');
        assert(!response.text.includes(marker), 'a value from the request was echoed');
      },
    },
    {
      id: 'R12', level: 'MUST', title: 'a content type the server has no parser for is 415 UNSUPPORTED_MEDIA_TYPE',
      async run() {
        assertEnvelope(await send('POST', jsonPath, { headers: { 'content-type': 'application/xml' }, raw: '<a/>' }), 415, 'UNSUPPORTED_MEDIA_TYPE', 'an XML body');
      },
    },
    {
      id: 'R13', level: 'SHOULD', title: 'a JSON value that is not an object is 400 VALIDATION_ERROR',
      async run() {
        assertEnvelope(await send('POST', jsonPath, { body: [] }), 400, 'VALIDATION_ERROR', 'an array body');
      },
    },
    {
      id: 'R14', level: 'MUST', title: 'a token that is not a Passport is 401 PASSPORT_INVALID (never PASSPORT_REVOKED, never a 5xx)',
      async run() {
        for (const token of ['not.a.jwt', 'abc', 'a.b.c']) {
          assertEnvelope(await send('POST', jsonPath, { body: { token } }), 401, 'PASSPORT_INVALID', `the token ${JSON.stringify(token)}`);
        }
      },
    },

    // ─── Credentials ───
    {
      id: 'A01', level: 'MUST', title: 'a protected route without a credential is 401 INVALID_API_KEY',
      async run() {
        assertEnvelope(await send('GET', protectedPath), 401, 'INVALID_API_KEY', 'no credential');
      },
    },
    {
      id: 'A02', level: 'MUST', title: 'every credential that is not accepted is refused alike: the same code and the same message',
      async run() {
        const none = await send('GET', protectedPath);
        assertEnvelope(none, 401, 'INVALID_API_KEY', 'no credential');
        const refused = [
          ['an unknown key', { authorization: `Bearer ${['sk', 'live', 'conformance', 'not', 'a', 'real', 'key', '0000000000'].join('_')}` }],
          ['a token that is not a key', { authorization: 'Bearer garbage' }],
          ['another scheme', { authorization: 'Basic Y29uZm9ybWFuY2U6bm9wZQ==' }],
          ['an empty bearer', { authorization: 'Bearer ' }],
          ['a JWT-shaped token nobody signed', { authorization: `Bearer ${['eyJhbGciOiJFZERTQSJ9', 'eyJzdWIiOiJvcF94In0', 'AAAA'].join('.')}` }],
        ];
        for (const [what, headers] of refused) {
          const response = await send('GET', protectedPath, { headers });
          assertEnvelope(response, 401, 'INVALID_API_KEY', what);
          assertEqual(response.json.error.message, none.json.error.message, `the message for ${what} differs from the one for no credential: a refusal says which`);
        }
      },
    },
    {
      id: 'A03', level: 'MUST', title: 'a valid credential is accepted on the protected route',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        const response = await send('GET', protectedPath, { headers: bearer });
        assertEqual(response.status, 200, 'the protected route with a valid key');
        assert(JSON_TYPE.test(response.headers.get('content-type') ?? ''), 'the answer is not application/json');
      },
    },
    {
      id: 'A04', level: 'SHOULD', title: 'an answer to a limited route carries X-RateLimit-Limit, X-RateLimit-Remaining and X-RateLimit-Reset as whole numbers',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        const response = await send('GET', protectedPath, { headers: bearer });
        for (const name of ['x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset']) {
          assert(/^\d+$/.test(response.headers.get(name) ?? ''), `${name} is ${JSON.stringify(response.headers.get(name))}`);
        }
      },
    },

    // ─── The governance step-up ───
    {
      id: 'S01', level: 'MUST', title: 'a gated change from a bearer credential is refused 403 GOVERNANCE_APPROVAL_REQUIRED with the approval id and its page',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        const { refused } = await asked();
        assertEnvelope(refused, 403, 'GOVERNANCE_APPROVAL_REQUIRED', 'the gated change');
        const { details } = refused.json.error;
        assert(details && typeof details === 'object', '"error.details" is missing');
        assert(typeof details.approval_id === 'string' && APPROVAL_ID.test(details.approval_id), `details.approval_id is ${JSON.stringify(details.approval_id)}`);
        assert(typeof details.approval_url === 'string' && /^https?:\/\//.test(details.approval_url), `details.approval_url is ${JSON.stringify(details.approval_url)}`);
        assert(details.approval_url.includes(details.approval_id), 'details.approval_url is not the page of this approval');
        approval.id = details.approval_id;
      },
    },
    {
      id: 'S02', level: 'SHOULD', title: 'the message of the refusal names the header to retry with',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        const { refused } = await asked();
        assert(/x-governance-approval/i.test(refused.json?.error?.message ?? ''), 'the message does not name X-Governance-Approval');
      },
    },
    {
      id: 'S03', level: 'MUST', title: 'the approval can be read: pending, with the hash of the change and its expiry',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        await asked();
        assert(approval.id, 'there is no approval: S01 failed');
        const response = await send('GET', `/v1/governance/approvals/${approval.id}`, { headers: bearer });
        assertEqual(response.status, 200, 'reading the approval');
        const { json } = response;
        assertEqual(json.approval?.id, approval.id, 'approval.id');
        assertEqual(json.approval?.status, 'pending', 'approval.status');
        assert(typeof json.approval?.action === 'string' && json.approval.action.length > 0, 'approval.action is missing');
        assert(typeof json.payload_hash === 'string' && HEX64.test(json.payload_hash), `payload_hash is ${JSON.stringify(json.payload_hash)}`);
        assert(typeof json.approval_url === 'string' && json.approval_url.includes(approval.id), 'approval_url is not the approval\'s page');
        const expires = Date.parse(json.approval?.expires_at ?? '');
        assert(Number.isFinite(expires) && expires > Date.now() && expires - Date.now() <= 25 * 3600 * 1000, `approval.expires_at is ${JSON.stringify(json.approval?.expires_at)}`);
        approval.hash = json.payload_hash;
      },
    },
    {
      id: 'S04', level: 'MUST', title: 'the approvals of the account are listed',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        await asked();
        const response = await send('GET', '/v1/governance/approvals', { headers: bearer });
        assertEqual(response.status, 200, 'listing the approvals');
        assert(Array.isArray(response.json?.approvals), '"approvals" is not an array');
        assert(response.json.approvals.some((entry) => entry.id === approval.id), 'the approval is not in the list');
      },
    },
    {
      id: 'S05', level: 'MUST', title: 'a retry that cites an approval nobody has decided is 403 GOVERNANCE_APPROVAL_PENDING and does nothing',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        await asked();
        const response = await sendProbe(await stepUp('asked'), { 'x-governance-approval': approval.id });
        assertEnvelope(response, 403, 'GOVERNANCE_APPROVAL_PENDING', 'a retry while the approval is pending');
      },
    },
    {
      id: 'S06', level: 'MUST', title: 'a retry that cites an approval that does not exist is 404 NOT_FOUND',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        const response = await sendProbe(await stepUp('asked'), { 'x-governance-approval': 'gvr_conformance_does_not_exist' });
        assertEnvelope(response, 404, 'NOT_FOUND', 'a retry citing an unknown approval');
      },
    },
    {
      id: 'S07', level: 'MUST', title: 'a bearer credential cannot decide an approval, and the approval stays pending',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        await asked();
        for (const decision of ['approve', 'reject']) {
          const response = await send('POST', `/v1/governance/approvals/${approval.id}/decide`, { headers: bearer, body: { decision } });
          assert(response.status === 401 || response.status === 403, `a bearer credential's ${decision} was answered ${response.status}`);
          assertEqual(envelopeProblem(response), null, 'the refusal');
        }
        const after = await send('GET', `/v1/governance/approvals/${approval.id}`, { headers: bearer });
        assertEqual(after.json?.approval?.status, 'pending', 'the approval after a bearer credential tried to decide it');
      },
    },
    {
      id: 'S10', level: 'MUST', title: 'an approved change runs when the same request is repeated with the approval, and a different change is refused',
      async run() {
        const skipped = needKey();
        if (skipped) return skipped;
        if (!approve) return skip('needs approve: the person who decides the approval');
        // A fresh approval, decided by the person.
        const request = await stepUp('asked');
        const refused = await sendProbe(request);
        const id = refused.json?.error?.details?.approval_id;
        assert(typeof id === 'string' && APPROVAL_ID.test(id), `no approval to decide: ${refused.status} ${refused.json?.error?.code}`);
        await approve(id);
        const different = await sendProbe(await stepUp('other'), { 'x-governance-approval': id });
        assertEnvelope(different, 403, 'FORBIDDEN', 'a different change under the approval');
        const done = await sendProbe(request, { 'x-governance-approval': id });
        if (request.path === '/v1/agents/register' && typeof done.json?.id === 'string') created.push(done.json.id);
        assert(done.status >= 200 && done.status < 300, `the approved change was answered ${done.status} ${done.json?.error?.code ?? ''}`);
        const reused = await sendProbe(request, { 'x-governance-approval': id });
        assertEnvelope(reused, 403, 'FORBIDDEN', 'the approval used twice');
        const detail = await send('GET', `/v1/governance/approvals/${id}`, { headers: bearer });
        assertEqual(detail.json?.approval?.status, 'consumed', 'the state of the approval after it was used');
      },
    },

    // ─── 402 ───
    {
      id: 'P01', level: 'MUST', title: 'a 402 is the error envelope with a code, and a LICENCE_REQUIRED carries the feature and the state of the licence',
      async run() {
        if (!probes.payment) return skip('needs probes.payment: a request your server answers with 402');
        const response = await sendProbe(probes.payment);
        assertEqual(response.status, 402, 'the payment probe');
        assertEqual(envelopeProblem(response), null, 'the 402');
        if (probes.payment.code) assertEqual(response.json.error.code, probes.payment.code, 'error.code');
        if (response.json.error.code === 'LICENCE_REQUIRED') {
          const { details } = response.json.error;
          assert(details && typeof details.feature === 'string' && details.feature.length > 0, 'details.feature is missing');
          assert(['none', 'invalid', 'expired', 'valid'].includes(details.licence), `details.licence is ${JSON.stringify(details.licence)}`);
          assert(!/[A-Za-z0-9+/_-]{40,}/.test(JSON.stringify(details)), 'details carries something that looks like a key');
        }
      },
    },

    // ─── Refusals by the customer's controls ───
    {
      id: 'C01', level: 'MUST', title: 'each refusal of a control has the status, the code and the details the specification gives it',
      async run() {
        if (!probes.controls || probes.controls.length === 0) return skip('needs probes.controls: requests your server refuses by a control');
        const expected = { CONTROL_DENIED: 403, CONTROL_LIMIT_EXCEEDED: 403, CONTROL_SOCKET_UNAVAILABLE: 403, CONTROL_UNAVAILABLE: 503 };
        for (const probe of probes.controls) {
          const response = await sendProbe(probe);
          assertEnvelope(response, expected[probe.code], probe.code, `the ${probe.code} probe`);
          const details = response.json.error.details;
          assert(details && typeof details === 'object', `${probe.code}: "error.details" is missing`);
          if (probe.code === 'CONTROL_DENIED') {
            assert(typeof details.decision_id === 'string', 'CONTROL_DENIED: details.decision_id is not a string');
            assert(details.reason_code === null || typeof details.reason_code === 'string', 'CONTROL_DENIED: details.reason_code is not a string or null');
            if ('retry' in details) {
              assert(typeof details.retry?.ref === 'string', 'CONTROL_DENIED: details.retry.ref is not a string');
              assert(!('after_seconds' in details.retry) || Number.isInteger(details.retry.after_seconds), 'CONTROL_DENIED: details.retry.after_seconds is not an integer');
            }
            if ('rule' in details) {
              for (const field of ['policy_id', 'section', 'rule', 'code']) assert(typeof details.rule?.[field] === 'string', `CONTROL_DENIED: details.rule.${field} is not a string`);
              assert(Number.isInteger(details.rule.policy_revision), 'CONTROL_DENIED: details.rule.policy_revision is not an integer');
            }
          } else if (probe.code === 'CONTROL_LIMIT_EXCEEDED') {
            assert(['day', 'month', 'mission', 'action'].includes(details.limit?.window), `CONTROL_LIMIT_EXCEEDED: details.limit.window is ${JSON.stringify(details.limit?.window)}`);
            assert(['cents', 'actions'].includes(details.limit?.unit), `CONTROL_LIMIT_EXCEEDED: details.limit.unit is ${JSON.stringify(details.limit?.unit)}`);
            assert(Number.isInteger(details.remaining), 'CONTROL_LIMIT_EXCEEDED: details.remaining is not an integer');
            if (details.limit.window === 'action') assert(Number.isInteger(details.max_per_action_cents), 'CONTROL_LIMIT_EXCEEDED: details.max_per_action_cents is not an integer for a per-action limit');
          } else if (probe.code === 'CONTROL_SOCKET_UNAVAILABLE') {
            assert(typeof details.decision_id === 'string', 'CONTROL_SOCKET_UNAVAILABLE: details.decision_id is not a string');
            assert(typeof details.cause === 'string' && details.cause.length > 0, 'CONTROL_SOCKET_UNAVAILABLE: details.cause is not a string');
          } else {
            assert(typeof details.decision_id === 'string', 'CONTROL_UNAVAILABLE: details.decision_id is not a string');
          }
        }
      },
    },

    {
      id: 'C02', level: 'MUST', title: 'a policy rule that leaves its recipients to each Mission is accepted where the same rule without it is refused as unbounded, and what a Mission pinned decides who a send reaches',
      async run() {
        const job = probes.perJob;
        if (!job) return skip('needs probes.perJob: a policy write with and without per_mission recipients, and sends inside a Mission that pins no one, a Mission that pins someone else, and a Mission that pins the recipient');
        const unbounded = await sendProbe(job.unbounded);
        assertEnvelope(unbounded, 400, 'UNBOUNDED_SEND_RULE', 'the policy that allows a send without naming who receives it');
        assert(Array.isArray(unbounded.json.error.details?.rules) && unbounded.json.error.details.rules.length > 0, 'UNBOUNDED_SEND_RULE: details.rules does not list the rule');
        const accepted = await sendProbe(job.policy);
        assert(accepted.status >= 200 && accepted.status < 300, `the policy that leaves its recipients to each Mission was answered ${accepted.status} ${accepted.json?.error?.code ?? ''}`);
        for (const [name, code] of [['unpinned', 'recipients_not_pinned'], ['stranger', 'recipient_not_allowed']]) {
          const refused = await sendProbe(job[name]);
          assertEnvelope(refused, 403, 'CONTROL_DENIED', `the ${name} send`);
          assertEqual(refused.json.error.details?.rule?.code, code, `the ${name} send: details.rule.code`);
          for (const value of job.recipients ?? []) assert(!JSON.stringify(refused.json).includes(value), `the ${name} send: the refusal names a recipient`);
        }
        const pinned = await sendProbe(job.pinned);
        const refusedForPins = pinned.status === 403 && pinned.json?.error?.code === 'CONTROL_DENIED' && ['recipients_not_pinned', 'recipient_not_allowed'].includes(pinned.json.error.details?.rule?.code);
        assert(!refusedForPins, 'the send to the recipient the Mission pinned was refused for its recipients');
      },
    },

    // ─── The cost cap ───
    {
      id: 'M01', level: 'MUST', title: 'a cost cap that is not a whole number of cents, 1 or more, is 400 VALIDATION_ERROR, never read as no cap',
      async run() {
        if (!probes.costCap) return skip('needs probes.costCap: a model call your server admits');
        if (probes.costCap.mode === 'own_key_ignored') return skip('a server that ignores the cap on the customer\'s own key does not read it there');
        for (const cap of ['abc', '0', '1.5', '', '-3']) {
          assertEnvelope(await sendProbe(probes.costCap, { 'x-max-cost-cents': cap }), 400, 'VALIDATION_ERROR', `the cap ${JSON.stringify(cap)}`);
        }
      },
    },
    {
      id: 'M02', level: 'MUST', title: 'a cap below the worst case is refused 422 MODEL_COST_CAP with the reason, or, on a key of the deployment\'s own, held instead; on the customer\'s own key it is refused as unavailable or, where the server says so, ignored',
      async run() {
        if (!probes.costCap) return skip('needs probes.costCap: a model call your server admits');
        const response = await sendProbe(probes.costCap, { 'x-max-cost-cents': '1' });
        if (probes.costCap.mode === 'own_key_ignored') {
          assert(response.status >= 200 && response.status < 300, `a cap of one cent on the customer's own key was answered ${response.status}, not let through`);
          return;
        }
        // On a key of the deployment's own a server may hold the cap instead of refusing (REST API 2.1.0).
        if (probes.costCap.mode === 'deployment_key' && response.status >= 200 && response.status < 300) return;
        assertEnvelope(response, 422, 'MODEL_COST_CAP', 'a cap of one cent');
        const { details } = response.json.error;
        if (probes.costCap.mode === 'own_key') {
          assertEqual(details?.reason, 'cost_cap_unavailable', 'details.reason on a call on the customer\'s own key');
        } else {
          assertEqual(details?.reason, 'cost_cap_exceeded', 'details.reason on a call whose worst case is above the cap');
          assert(Number.isInteger(details.worst_case_cents) && details.worst_case_cents > 1, `details.worst_case_cents is ${JSON.stringify(details.worst_case_cents)}`);
          assertEqual(details.max_cost_cents, 1, 'details.max_cost_cents');
        }
      },
    },
  ];

  // `only` runs the checks it names (a test of one part of a server that has no other routes).
  try {
    return await runChecks('REST API server', options.only ? checks.filter((check) => options.only.includes(check.id)) : checks);
  } finally {
    await removeCreatedAgents();
  }
}
