// Conformance suite for a control socket DECISION SERVER: the customer's server
// that STACK asks before an action runs. The kit plays the gateway: it signs
// requests with the secret you give it, posts them to your URL and checks what
// comes back against spec/control-socket/SPEC.md.
//
// Point it at a test instance with a test secret, never at a production
// secret. The requests are synthetic and nothing is done on anyone's behalf.

import { randomBytes } from 'node:crypto';
import { canonicalize, sha256Hex } from './canonical.mjs';
import { assert, assertEqual, fail, post, runChecks } from './harness.mjs';
import { WRONG_SECRET, signMessage, verifyMessage } from './webhook.mjs';

/** The action kinds of control socket 1.0 with a representative target each. */
export const ACTION_TARGETS = {
  'model.call': { provider: 'anthropic', model: 'a-model', stream: false, max_output_tokens: 1024 },
  'proxy.call': { service: 'github', connection_id: 'scon_1', method: 'GET', host: 'api.github.com', path: '/user' },
  'tool.run': { provider: 'acme', endpoint: 'search' },
  'email.send': { recipients: [{ address: 'ana@example.com', domain: 'example.com' }], recipient_count: 1 },
  'sms.send': { recipients: [{ number: '+14155550123' }], recipient_count: 1 },
  'call.start': { recipients: [{ number: '+14155550123' }], recipient_count: 1, max_seconds: 120 },
  'browser.session.start': {},
  'browser.navigate': { origin: 'https://shop.example', path: '/cart' },
  'card.checkout': { merchant_origin: 'https://shop.example', amount_minor: 1200, currency: 'USD' },
  'wallet.payment': { chain_id: '8453', token: '0x0000000000000000000000000000000000000001', payee: '0x0000000000000000000000000000000000000002', amount: '10000', valid_before: '1790000000' },
  'workspace.exec': { new_workspace: false, timeout_seconds: 30, stack_access: false, command_bytes: 12 },
  'account.open': { name: 'scout', skipped_pieces: [] },
  'dropoff.create': { to_agent: 'agt_2' },
  'dropoff.deposit': { to_agent: 'agt_2', payload_bytes: 2048 },
  'a2a.send': { to_agent: 'agt_2', message_bytes: 512 },
  'skill.invoke': { skill_id: 'skl_1' },
  'passport.delegate': { binding_id: 'abn_1' },
};

const REASON_CODE = /^[a-z0-9_]{1,64}$/;
const ANSWER_MAX_BYTES = 16 * 1024;

/** Build a request the way the gateway does: the digest covers every other field. */
export function buildDecisionRequest({ action = 'test', target, test = action === 'test', amount = null, retryRef = null, purpose = null, now = new Date(), deadlineMs = 1500 } = {}) {
  const decisionId = `dec_${randomBytes(12).toString('base64url')}`;
  const unsigned = {
    type: 'stack.decision.request',
    version: '1',
    decision_id: decisionId,
    created_at: now.toISOString(),
    deadline_at: new Date(now.getTime() + deadlineMs).toISOString(),
    test,
    operator_id: 'op_conformance',
    socket_id: 'csk_conformance',
    account: test ? null : { id: 'acct_conformance' },
    agent: test ? null : { id: 'agt_conformance', passport_jti: 'pas_conformance', mission_id: 'ms_conformance' },
    actor: { kind: test ? 'owner' : 'agent' },
    action: { type: action },
    target: target ?? (action === 'test' ? {} : (ACTION_TARGETS[action] ?? {})),
    amount,
    purpose: { agent_stated: purpose },
    retry_ref: retryRef,
  };
  const request = { ...unsigned, request_digest: `sha256:${sha256Hex(canonicalize(unsigned))}` };
  return { request, body: JSON.stringify(request) };
}

/**
 * Judge a response as the gateway would. Returns { ok: true, answer } for a
 * usable answer, or { ok: false, why } naming the first reason it is not one.
 */
export function readAnswer(response, request, secrets) {
  if (response.status !== 200) return { ok: false, why: `status ${response.status}, not 200` };
  if (Buffer.byteLength(response.text) > ANSWER_MAX_BYTES) return { ok: false, why: 'body larger than 16 KiB' };
  const verified = verifyMessage({ headers: response.headers, body: response.text, secrets });
  if (!verified.ok) return { ok: false, why: `signature: ${verified.reason}` };
  if (verified.id !== request.decision_id) return { ok: false, why: `webhook-id ${verified.id} is not the decision id ${request.decision_id}` };
  let answer;
  try {
    answer = JSON.parse(response.text);
  } catch {
    return { ok: false, why: 'body is not JSON' };
  }
  if (!answer || typeof answer !== 'object') return { ok: false, why: 'body is not an object' };
  if (answer.decision_id !== request.decision_id) return { ok: false, why: 'decision_id not echoed' };
  if (answer.request_digest !== request.request_digest) return { ok: false, why: 'request_digest not echoed' };
  if (answer.verdict !== 'allow' && answer.verdict !== 'deny') return { ok: false, why: `verdict ${JSON.stringify(answer.verdict)} is neither allow nor deny` };
  if (answer.reason !== undefined) {
    if (!answer.reason || typeof answer.reason.code !== 'string' || !REASON_CODE.test(answer.reason.code)) return { ok: false, why: 'reason.code is not [a-z0-9_]{1,64}' };
    if (answer.reason.message !== undefined && (typeof answer.reason.message !== 'string' || answer.reason.message.length > 200)) return { ok: false, why: 'reason.message is not a string of at most 200 characters' };
  }
  if (answer.retry !== undefined) {
    const retry = answer.retry;
    if (!retry || typeof retry.ref !== 'string' || retry.ref.length < 1 || retry.ref.length > 200) return { ok: false, why: 'retry.ref is not a string of 1 to 200 characters' };
    if (retry.after_seconds !== undefined && !(Number.isInteger(retry.after_seconds) && retry.after_seconds >= 0 && retry.after_seconds <= 86_400)) return { ok: false, why: 'retry.after_seconds is not an integer from 0 to 86400' };
  }
  if (answer.policy_ref !== undefined && (typeof answer.policy_ref !== 'string' || answer.policy_ref.length > 200)) return { ok: false, why: 'policy_ref is not a string of at most 200 characters' };
  return { ok: true, answer };
}

/**
 * @param {{ url: string, secret: string, timeoutMs?: number, fetchImpl?: typeof fetch }} options
 */
export async function runDecisionServerSuite(options) {
  const { url, secret, timeoutMs = 5000, fetchImpl } = options;
  const send = (request, body, headers) => post(url, { headers: { 'content-type': 'application/json', ...headers }, body, timeoutMs, fetchImpl });
  const signed = (body, id, extra = {}) => signMessage({ id, body, secrets: [secret], ...extra });

  /** Send a correctly signed request and require a usable answer. */
  async function exchange(input) {
    const { request, body } = buildDecisionRequest(input);
    const response = await send(request, body, signed(body, request.decision_id));
    const read = readAnswer(response, request, [secret]);
    if (!read.ok) fail(`no usable answer: ${read.why}`);
    return { request, response, answer: read.answer };
  }

  /** Send something that must NOT be allowed and require that no signed allow comes back. */
  async function refused(request, body, headers) {
    let response;
    try {
      response = await send(request, body, headers);
    } catch {
      return { response: null };
    }
    const read = readAnswer(response, request, [secret]);
    if (read.ok && read.answer.verdict === 'allow') fail('answered with a signed allow');
    return { response };
  }

  return runChecks('control socket decision server', [
    {
      id: 'D01', level: 'MUST', title: 'answers a signed test request with a signed allow',
      async run() {
        const { answer } = await exchange({ action: 'test' });
        assertEqual(answer.verdict, 'allow', 'verdict to a test request');
      },
    },
    {
      id: 'D02', level: 'MUST', title: 'answers within the maximum deadline of 2 seconds',
      async run() {
        const { response } = await exchange({ action: 'test' });
        assert(response.ms <= 2000, `took ${response.ms} ms`);
      },
    },
    {
      id: 'D03', level: 'SHOULD', title: 'answers within the default deadline of 1.5 seconds',
      async run() {
        const { response } = await exchange({ action: 'test' });
        assert(response.ms <= 1500, `took ${response.ms} ms`);
      },
    },
    ...Object.keys(ACTION_TARGETS).map((kind, index) => ({
      id: `D${String(10 + index)}`, level: 'MUST', title: `answers a ${kind} request with a well-formed signed answer`,
      async run() {
        const amount = kind === 'card.checkout' ? { max_cents: 1200, currency: 'USD' } : null;
        await exchange({ action: kind, amount, purpose: 'conformance check' });
      },
    })),
    {
      id: 'D30', level: 'MUST', title: 'answers an action kind it does not know with a well-formed signed answer, not an error',
      async run() {
        await exchange({ action: 'future.kind', target: { anything: 'goes' } });
      },
    },
    {
      id: 'D31', level: 'MUST', title: 'accepts a request carrying two signatures when one matches (secret rotation)',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'test' });
        const headers = signMessage({ id: request.decision_id, body, secrets: [WRONG_SECRET, secret] });
        const response = await send(request, body, headers);
        const read = readAnswer(response, request, [secret]);
        if (!read.ok) fail(`no usable answer: ${read.why}`);
      },
    },
    {
      id: 'D40', level: 'MUST', title: 'does not allow a request signed with the wrong secret',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'test' });
        await refused(request, body, signMessage({ id: request.decision_id, body, secrets: [WRONG_SECRET] }));
      },
    },
    {
      id: 'D41', level: 'MUST', title: 'does not allow a request without signature headers',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'test' });
        await refused(request, body, {});
      },
    },
    {
      id: 'D42', level: 'MUST', title: 'does not allow a correctly signed request whose timestamp is ten minutes old',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'test' });
        await refused(request, body, signMessage({ id: request.decision_id, body, secrets: [secret], timestamp: Math.floor(Date.now() / 1000) - 600 }));
      },
    },
    {
      id: 'D43', level: 'MUST', title: 'does not allow a correctly signed request whose timestamp is ten minutes in the future',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'test' });
        await refused(request, body, signMessage({ id: request.decision_id, body, secrets: [secret], timestamp: Math.floor(Date.now() / 1000) + 600 }));
      },
    },
    {
      id: 'D44', level: 'MUST', title: 'does not allow a body that was changed after it was signed',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'email.send' });
        const headers = signMessage({ id: request.decision_id, body, secrets: [secret] });
        const changed = body.replace('ana@example.com', 'eve@example.org');
        assert(changed !== body, 'the kit could not alter the body');
        await refused(request, changed, headers);
      },
    },
    {
      id: 'D45', level: 'SHOULD', title: 'does not allow a request whose webhook-id is not its decision_id',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'test' });
        await refused(request, body, signMessage({ id: `dec_${randomBytes(12).toString('base64url')}`, body, secrets: [secret] }));
      },
    },
    {
      id: 'D46', level: 'SHOULD', title: 'refuses an unauthenticated request with a 4xx status',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'test' });
        const { response } = await refused(request, body, signMessage({ id: request.decision_id, body, secrets: [WRONG_SECRET] }));
        assert(response !== null && response.status >= 400 && response.status < 500, `status was ${response?.status ?? 'none'}`);
      },
    },
    {
      id: 'D47', level: 'SHOULD', title: 'does not allow a request whose request_digest does not match its content',
      async run() {
        const { request } = buildDecisionRequest({ action: 'email.send' });
        const forged = { ...request, request_digest: `sha256:${'0'.repeat(64)}` };
        const body = JSON.stringify(forged);
        await refused(forged, body, signMessage({ id: forged.decision_id, body, secrets: [secret] }));
      },
    },
    {
      id: 'D50', level: 'SHOULD', title: 'gives the same verdict when the same request is sent twice',
      async run() {
        const { request, body } = buildDecisionRequest({ action: 'email.send' });
        const verdicts = [];
        for (let i = 0; i < 2; i += 1) {
          const response = await send(request, body, signed(body, request.decision_id));
          const read = readAnswer(response, request, [secret]);
          if (!read.ok) fail(`no usable answer: ${read.why}`);
          verdicts.push(read.answer.verdict);
        }
        assertEqual(verdicts[1], verdicts[0], 'second verdict');
      },
    },
  ]);
}
