// Conformance suite for an A2A endpoint as STACK profiles it (spec/a2a/SPEC.md): the agent card
// at /.well-known/agent.json and the JSON-RPC 2.0 endpoint with tasks/send, tasks/get and
// tasks/cancel. You give it the origin of your server and the headers that authenticate a test
// caller; give it two agents of that caller (`fromAgent`, `toAgent`) to also run the task flow.
// A check that needs a handle you did not provide is reported as skipped, never as passed.
//
// The card is read without credentials. Every request to the endpoint carries `headers`. The
// tasks the flow creates are cancelled at the end. Use a test instance and a test credential.

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { assert, runChecks, skip } from './harness.mjs';
import { canonicalize } from './canonical.mjs';
import { ed25519Thumbprint } from './http-signature.mjs';

const TASK_STATES = ['submitted', 'working', 'completed', 'canceled', 'failed'];
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/**
 * @param {{
 *   url: string,                       // the origin of the server (or the card's URL)
 *   headers?: Record<string, string>,  // authenticates a test caller at the JSON-RPC endpoint
 *   fromAgent?: string, toAgent?: string,
 *   otherHeaders?: Record<string, string>,  // a second caller, for the isolation check
 *   groups?: ('card' | 'rpc' | 'flow')[],     // judge the card only (an agent site's signed card has no endpoint of its own), or only the endpoint; default all
 *   timeoutMs?: number, fetchImpl?: typeof fetch,
 * }} options
 */
export async function runA2aSuite(options) {
  const { url, headers = {}, fromAgent, toAgent, otherHeaders, timeoutMs = 10_000, fetchImpl = fetch } = options;
  const groups = options.groups ?? ['card', 'rpc', 'flow'];
  const origin = new URL(url).origin;
  const CARD_URL = new URL(url).pathname.endsWith('.json') ? new URL(url).href : `${origin}/.well-known/agent.json`;

  async function http(target, init = {}) {
    const response = await fetchImpl(target, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), ...init });
    const text = await response.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: response.status, headers: response.headers, text, json };
  }

  let card;
  const readCard = async () => {
    if (card) return card;
    const r = await http(CARD_URL, { headers: { accept: 'application/json' } });
    assert(r.status === 200, `GET ${CARD_URL} answered ${r.status}`);
    assert(r.json && typeof r.json === 'object' && !Array.isArray(r.json), 'the agent card is not a JSON object');
    card = r.json;
    return card;
  };
  const endpoint = async () => (await readCard()).url;

  /** One JSON-RPC call (or a raw body) to the endpoint, with the test caller's headers. */
  async function rpc(body, { auth = true, raw = false, extraHeaders = {} } = {}) {
    return http(await endpoint(), {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(auth ? headers : {}), ...extraHeaders },
      body: raw ? body : JSON.stringify(body),
    });
  }
  const call = (method, params, id = 1) => rpc({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
  const errorOf = (r) => {
    assert(r.json && r.json.jsonrpc === '2.0', `the answer is not JSON-RPC 2.0 (${r.status}: ${r.text.slice(0, 120)})`);
    assert(r.json.error && typeof r.json.error.code === 'number' && typeof r.json.error.message === 'string', 'the answer has no error object');
    assert(!('result' in r.json), 'the answer has both an error and a result');
    return r.json.error;
  };
  const resultOf = (r) => {
    assert(r.status === 200, `the endpoint answered ${r.status}: ${r.text.slice(0, 160)}`);
    assert(r.json && r.json.jsonrpc === '2.0' && 'result' in r.json && !('error' in r.json), `the answer is not a JSON-RPC result: ${r.text.slice(0, 160)}`);
    return r.json.result;
  };

  const needsAgents = !fromAgent || !toAgent ? skip('needs fromAgent and toAgent: two agents of the test caller') : null;
  const sendParams = (extra = {}) => ({
    message: { role: 'user', parts: [{ type: 'text', text: 'Conformance check: nothing to do.' }] },
    metadata: { stack_from_agent: fromAgent, stack_to_agent: toAgent, ...extra },
  });
  const created = [];
  async function send(extra) {
    const result = resultOf(await call('tasks/send', sendParams(extra)));
    created.push(result.id);
    return result;
  }

  const checks = [
    // ─── the card ───
    {
      id: 'A01', level: 'MUST', title: 'serves the agent card at /.well-known/agent.json without credentials, as a JSON object',
      async run() {
        const r = await http(CARD_URL, { headers: { accept: 'application/json' } });
        assert(r.status === 200, `answered ${r.status}`);
        assert(/json/i.test(r.headers.get('content-type') ?? ''), `content-type is ${JSON.stringify(r.headers.get('content-type'))}`);
        assert(r.json && typeof r.json === 'object' && !Array.isArray(r.json), 'the body is not a JSON object');
      },
    },
    {
      id: 'A02', level: 'MUST', title: 'the card names the server (name, description, version) and its provider (organization, url)',
      async run() {
        const c = await readCard();
        for (const field of ['name', 'description', 'version']) assert(typeof c[field] === 'string' && c[field].length > 0, `${field} is missing`);
        assert(c.provider && typeof c.provider.organization === 'string' && typeof c.provider.url === 'string', 'provider.organization and provider.url are missing');
        assert(/^\d+\.\d+\.\d+$/.test(c.version), `version ${JSON.stringify(c.version)} is not an A2A protocol version`);
      },
    },
    {
      id: 'A03', level: 'MUST', title: 'the card\'s url is the absolute address of the JSON-RPC endpoint',
      async run() {
        const c = await readCard();
        assert(typeof c.url === 'string', 'url is missing');
        let parsed;
        try {
          parsed = new URL(c.url);
        } catch {
          throw new Error(`url ${JSON.stringify(c.url)} is not absolute`);
        }
        assert(parsed.protocol === 'https:' || ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname), 'url is not https');
      },
    },
    {
      id: 'A04', level: 'SHOULD', title: 'the endpoint is at /v1/a2a/jsonrpc',
      async run() {
        assert(new URL((await readCard()).url).pathname === '/v1/a2a/jsonrpc', `the endpoint is at ${new URL((await readCard()).url).pathname}`);
      },
    },
    {
      id: 'A05', level: 'MUST', title: 'the card lists input and output modes, capabilities as booleans, the authentication schemes and the skills',
      async run() {
        const c = await readCard();
        for (const field of ['defaultInputModes', 'defaultOutputModes']) {
          assert(Array.isArray(c[field]) && c[field].length > 0 && c[field].every((m) => typeof m === 'string'), `${field} is not a list of strings`);
        }
        const flags = c.supportedInterfaces ? ['streaming', 'pushNotifications'] : ['streaming', 'pushNotifications', 'stateTransitionHistory'];
        for (const flag of flags) {
          assert(typeof c.capabilities?.[flag] === 'boolean', `capabilities.${flag} is not a boolean`);
        }
        if (c.supportedInterfaces) {
          // An agent site's card, of A2A 0.3: the interfaces are named, the protocol version is its own field.
          assert(typeof c.protocolVersion === 'string' && Array.isArray(c.supportedInterfaces) && c.supportedInterfaces.length > 0, 'protocolVersion or supportedInterfaces is missing');
          for (const i of c.supportedInterfaces) assert(typeof i.url === 'string' && typeof i.protocolBinding === 'string' && typeof i.protocolVersion === 'string', 'an interface lacks url, protocolBinding or protocolVersion');
        } else {
          assert(Array.isArray(c.authentication?.schemes) && c.authentication.schemes.length > 0, 'authentication.schemes is empty');
        }
        assert(Array.isArray(c.skills) && c.skills.length > 0, 'skills is empty');
        for (const skillEntry of c.skills) {
          assert(typeof skillEntry.id === 'string' && typeof skillEntry.name === 'string' && typeof skillEntry.description === 'string' && Array.isArray(skillEntry.tags), 'a skill lacks id, name, description or tags');
        }
      },
    },
    {
      id: 'A07', level: 'MUST', title: 'a signed card carries a JWS over its canonical form that verifies against the key directory its protected header names',
      async run() {
        const c = await readCard();
        if (!Array.isArray(c.signatures)) return skip('the card is not signed');
        assert(c.signatures.length >= 1, 'signatures is empty');
        const { signatures, ...unsigned } = c;
        const { protected: protectedHeader, signature } = signatures[0];
        assert(typeof protectedHeader === 'string' && typeof signature === 'string', 'a signature has no protected header or signature');
        const header = JSON.parse(Buffer.from(protectedHeader, 'base64url').toString('utf8'));
        assert(header.alg === 'EdDSA' && header.typ === 'JOSE', `the protected header is ${JSON.stringify(header)}`);
        assert(typeof header.kid === 'string' && typeof header.jku === 'string', 'the protected header has no kid or jku');
        const directoryResponse = await http(header.jku, { headers: { accept: 'application/http-message-signatures-directory+json' } });
        assert(directoryResponse.status === 200 && Array.isArray(directoryResponse.json?.keys), `the key directory at ${header.jku} answered ${directoryResponse.status}`);
        const key = directoryResponse.json.keys.find((k) => k.x && ed25519Thumbprint(k.x) === header.kid);
        assert(key, 'the key named by kid is not in the directory');
        const input = `${protectedHeader}.${Buffer.from(canonicalize(unsigned), 'utf8').toString('base64url')}`;
        const ok = cryptoVerify(null, Buffer.from(input, 'utf8'), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' }), Buffer.from(signature, 'base64url'));
        assert(ok, 'the signature does not verify over the protected header and the canonical card');
      },
    },
    {
      id: 'A06', level: 'MUST', title: 'does not advertise a capability the endpoint lacks: with streaming off, tasks/sendSubscribe is method-not-found',
      async run() {
        const c = await readCard();
        if (c.capabilities.streaming === true) return skip('streaming is on: its behaviour is not part of this profile');
        const e = errorOf(await call('tasks/sendSubscribe', sendParams(), 'stream'));
        assert(e.code === -32601, `tasks/sendSubscribe answered code ${e.code}`);
      },
    },

    // ─── the endpoint ───
    {
      id: 'A10', level: 'MUST', title: 'refuses a call with no credentials: it is not a JSON-RPC result',
      async run() {
        const r = await rpc({ jsonrpc: '2.0', id: 1, method: 'tasks/get', params: { id: 'x' } }, { auth: false });
        assert(r.status === 401 || r.status === 403, `an unauthenticated call answered ${r.status}`);
        assert(!(r.json && 'result' in r.json), 'an unauthenticated call got a result');
      },
    },
    {
      id: 'A11', level: 'MUST', title: 'answers a malformed envelope with HTTP 400 and a -32600 error, echoing the id only when it is a string, a number or null',
      async run() {
        const cases = [
          ['null', 'null', null],
          ['an array', JSON.stringify([{ jsonrpc: '2.0', method: 'tasks/get' }]), null],
          ['a string', '"tasks/get"', null],
          ['a wrong version', JSON.stringify({ jsonrpc: '1.0', id: 7, method: 'tasks/get' }), 7],
          ['no version', JSON.stringify({ id: 'abc', method: 'tasks/get' }), 'abc'],
          ['no method', JSON.stringify({ jsonrpc: '2.0', id: 3 }), 3],
          ['a method that is not a string', JSON.stringify({ jsonrpc: '2.0', id: 3, method: 5 }), 3],
          ['an object id and no method', JSON.stringify({ jsonrpc: '2.0', id: { a: 1 } }), null],
        ];
        for (const [label, body, echoed] of cases) {
          const r = await rpc(body, { raw: true });
          assert(r.status === 400, `${label}: answered ${r.status}`);
          const e = errorOf(r);
          assert(e.code === -32600, `${label}: code ${e.code}`);
          assert(r.json.id === echoed, `${label}: id is ${JSON.stringify(r.json.id)}, expected ${JSON.stringify(echoed)}`);
        }
      },
    },
    {
      id: 'A12', level: 'MUST', title: 'answers an unknown method with -32601, echoing the id when it is a string, a number or null, and null for any other id or none',
      async run() {
        for (const [sent, echoed] of [['abc', 'abc'], [11, 11], [null, null], [{ a: 1 }, null], [[1], null]]) {
          const r = await call('tasks/nope', {}, sent);
          assert(r.status === 200, `id ${JSON.stringify(sent)}: answered ${r.status}`);
          assert(errorOf(r).code === -32601, 'the code is not -32601');
          assert(r.json.id === echoed, `id ${JSON.stringify(sent)}: answered with ${JSON.stringify(r.json.id)}, expected ${JSON.stringify(echoed)}`);
        }
        // No id at all is answered with a null id, as an id that cannot be echoed is.
        const none = await rpc({ jsonrpc: '2.0', method: 'tasks/nope' });
        assert(errorOf(none).code === -32601 && none.json.id === null, 'a request with no id was not answered with a null id');
      },
    },
    {
      id: 'A13', level: 'MUST', title: 'reads params that are not an object as no params: tasks/get and tasks/cancel without an id answer -32602',
      async run() {
        for (const method of ['tasks/get', 'tasks/cancel']) {
          for (const params of [undefined, null, 'x', [1, 2], 5, {}]) {
            const r = await call(method, params);
            assert(errorOf(r).code === -32602, `${method} with params ${JSON.stringify(params)} answered code ${r.json?.error?.code}`);
          }
        }
      },
    },
    {
      id: 'A14', level: 'MUST', title: 'tasks/send answers -32602 when the message or the sender and recipient are missing',
      async run() {
        const noMessage = await call('tasks/send', { id: 't1', metadata: { stack_from_agent: 'a', stack_to_agent: 'b' } });
        assert(errorOf(noMessage).code === -32602, 'a send with no message did not answer -32602');
        const noAgents = await call('tasks/send', { message: { role: 'user', parts: [] } });
        assert(errorOf(noAgents).code === -32602, 'a send with no stack_from_agent and stack_to_agent did not answer -32602');
        const onlyOne = await call('tasks/send', { message: { role: 'user', parts: [] }, metadata: { stack_from_agent: 'a' } });
        assert(errorOf(onlyOne).code === -32602, 'a send with no stack_to_agent did not answer -32602');
      },
    },
    {
      id: 'A15', level: 'MUST', title: 'an unknown task is -32001 "Task not found", for get and cancel, and the answer does not repeat the id or carry data',
      async run() {
        const id = 'dof_00000000000000000000000000000000';
        for (const method of ['tasks/get', 'tasks/cancel']) {
          const e = errorOf(await call(method, { id }));
          assert(e.code === -32001, `${method} answered code ${e.code}`);
          assert(e.message === 'Task not found', `${method} answered ${JSON.stringify(e.message)}`);
          assert(!JSON.stringify(e).includes(id) && !('data' in e), `${method} repeated the id or added data`);
        }
      },
    },
    {
      id: 'A16', level: 'MUST', title: 'a send from or to an agent that is not the caller\'s is an error, creates no task and names no agent',
      async run() {
        const e = errorOf(await call('tasks/send', {
          message: { role: 'user', parts: [{ type: 'text', text: 'x' }] },
          metadata: { stack_from_agent: 'agt_00000000000000000000000000000000', stack_to_agent: 'agt_11111111111111111111111111111111' },
        }));
        assert([-32001, -32602].includes(e.code), `the code is ${e.code}`);
        assert(!JSON.stringify(e).includes('agt_0000') && !JSON.stringify(e).includes('agt_1111'), 'the answer names an agent');
      },
    },

    // ─── the task flow ───
    {
      id: 'A20', level: 'MUST', title: 'tasks/send answers a task in state "submitted" with the server\'s own id, the session and the STACK metadata',
      async run() {
        if (needsAgents) return needsAgents;
        const task = resultOf(await call('tasks/send', sendParams({ trace: 'kept' }), 'send-1'));
        created.push(task.id);
        assert(typeof task.id === 'string' && task.id.length > 0, 'no task id');
        assert(task.status?.state === 'submitted', `state is ${JSON.stringify(task.status?.state)}`);
        assert(typeof task.status.timestamp === 'string' && ISO.test(task.status.timestamp), 'status.timestamp is not an ISO 8601 time');
        assert('sessionId' in task && task.sessionId === null, 'sessionId is not null when none was sent');
        assert(task.metadata?.stack_dropoff_id === task.id, 'metadata.stack_dropoff_id is not the task id');
        assert(task.metadata.trace === 'kept' && task.metadata.stack_from_agent === fromAgent && task.metadata.stack_to_agent === toAgent, 'the request metadata is not echoed');
      },
    },
    {
      id: 'A21', level: 'MUST', title: 'the task id is the server\'s: an id in params is not used as the task id, and a session id is echoed',
      async run() {
        if (needsAgents) return needsAgents;
        const r = resultOf(await call('tasks/send', { ...sendParams(), id: 'client-chosen-id', sessionId: 'session-1' }, 'send-2'));
        created.push(r.id);
        assert(r.id !== 'client-chosen-id', 'the client\'s id became the task id');
        assert(r.sessionId === 'session-1', `sessionId is ${JSON.stringify(r.sessionId)}`);
      },
    },
    {
      id: 'A22', level: 'MUST', title: 'tasks/get answers the task: a state from the A2A list, a time, and the sender, recipient and expiry in metadata',
      async run() {
        if (needsAgents) return needsAgents;
        const task = await send();
        const got = resultOf(await call('tasks/get', { id: task.id }, 'get-1'));
        assert(got.id === task.id, 'the id changed');
        assert(TASK_STATES.includes(got.status?.state), `state ${JSON.stringify(got.status?.state)} is not an A2A task state`);
        assert(got.status.state === 'working', `a task whose message is deposited reads "${got.status.state}", expected "working"`);
        assert(ISO.test(got.status.timestamp), 'status.timestamp is not an ISO 8601 time');
        assert(got.metadata?.stack_from_agent === fromAgent && got.metadata.stack_to_agent === toAgent, 'sender and recipient are missing from metadata');
        assert(typeof got.metadata.stack_expires_at === 'string' && ISO.test(got.metadata.stack_expires_at), 'metadata.stack_expires_at is not an ISO 8601 time');
        assert(got.metadata.stack_dropoff_id === task.id, 'metadata.stack_dropoff_id is not the task id');
      },
    },
    {
      id: 'A23', level: 'MUST', title: 'tasks/cancel answers state "canceled" with the id and no metadata; a second cancel is -32002',
      async run() {
        if (needsAgents) return needsAgents;
        const task = await send();
        const cancelled = resultOf(await call('tasks/cancel', { id: task.id }, 'cancel-1'));
        assert(cancelled.id === task.id, 'the id changed');
        assert(cancelled.status?.state === 'canceled' && ISO.test(cancelled.status.timestamp), 'the answer is not a canceled status with a time');
        const again = errorOf(await call('tasks/cancel', { id: task.id }, 'cancel-2'));
        assert(again.code === -32002, `a second cancel answered code ${again.code}`);
      },
    },
    {
      id: 'A24', level: 'MUST', title: 'a cancelled task reads as "failed" afterwards, as an expired one does',
      async run() {
        if (needsAgents) return needsAgents;
        const task = await send();
        resultOf(await call('tasks/cancel', { id: task.id }));
        const got = resultOf(await call('tasks/get', { id: task.id }));
        assert(got.status?.state === 'failed', `a cancelled task reads "${got.status?.state}"`);
      },
    },
    {
      id: 'A25', level: 'MUST', title: 'another caller cannot read or cancel the task: -32001',
      async run() {
        if (needsAgents) return needsAgents;
        if (!otherHeaders) return skip('needs otherHeaders: a second caller');
        const task = await send();
        const as = async (method) => {
          const r = await http(await endpoint(), {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...otherHeaders },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { id: task.id } }),
          });
          return errorOf(r);
        };
        assert((await as('tasks/get')).code === -32001, 'another caller read the task');
        assert((await as('tasks/cancel')).code === -32001, 'another caller cancelled the task');
      },
    },
  ];

  const groupOf = (id) => (['A01', 'A02', 'A03', 'A04', 'A05', 'A07'].includes(id) ? 'card' : id < 'A20' ? 'rpc' : 'flow');
  const wanted = checks.map((check) => (groups.includes(groupOf(check.id)) ? check : { ...check, run: async () => skip(`the ${groupOf(check.id)} checks were not asked for`) }));
  const report = await runChecks('a2a endpoint', wanted);
  // Leave nothing behind: cancel what the flow created.
  for (const id of created) {
    try {
      await call('tasks/cancel', { id }, 'cleanup');
    } catch {
      // The task may be cancelled already.
    }
  }
  return report;
}
