// A small server of the wire contract of spec/rest-api/SPEC.md, and nothing else: the error envelope, the reading of a
// request, a credential that is refused alike whatever is wrong with it, the governance step-up, a 402, the refusals of
// a customer's controls and the model cost cap. It keeps everything in memory. It is the public reference the `rest-api`
// suite is run against in continuous integration, and the starting point for a server of your own.
//
// `quirk` turns on ONE deliberate defect, for the tests of the suite itself (negative-controls.test.mjs): a conformance
// kit that cannot fail a broken server would certify anything.

import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';

export const QUIRKS = [
  'none',
  'plain-404', // the 404 is the framework's own body, not the envelope
  'echo-404', // the 404 echoes the query string
  'status-405', // a method a path does not serve is a 405
  'no-head', // HEAD is not answered
  'parser-500', // a body that is not JSON is a 500
  'verbose-401', // a refused credential says which way it was wrong
  'echo-validation', // a validation message carries the values that were sent
  'wrong-415', // an unknown content type is a 400
  'passport-500', // a token that is not a Passport is a 500
  'pending-accepted', // an approval nobody decided runs the change
  'reusable', // an approval can be used again
  'unbound', // an approval runs any change, not the one that was approved
  'bearer-decides', // a bearer credential can approve
  'no-details', // the step-up refusal has no approval id
  'cap-lenient', // a cap that is not a number is read as no cap
  'cap-ignored', // a cap on a call it cannot hold is ignored
  'payment-text', // a 402 that is not the envelope
  'socket-5xx', // CONTROL_SOCKET_UNAVAILABLE as a 503
  'extra-property', // an extra property beside "error"
  'per-job-open', // a send rule that names no recipients is accepted without being left to each Mission
  'stranger-allowed', // a send inside a Mission to someone it did not pin is allowed
  'names-recipient', // the refusal of a send to someone the Mission did not pin names the recipient
];

/** The recipient the `pinned` Mission of the per-job probes names. */
const PER_JOB_PINNED = 'ana@example.test';
const PER_JOB_STRANGER = 'stranger@evil.test';

const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const canonical = (value) => JSON.stringify(value, (_k, v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]])) : v));
const id = (prefix) => `${prefix}_${randomBytes(15).toString('base64url')}`;

/**
 * `gate` is the change this server asks a person to approve: unblocking an agent (`unblock`, what the STACK engine gates;
 * registering an agent needs no one's yes) or registering one (`register`, a server that gates registration).
 * @param {{ quirk?: string, apiKey?: string, host?: string, gate?: 'unblock' | 'register' }} [options]
 */
export async function startRestApiServer({ quirk = 'none', apiKey = `sk_live_${randomBytes(18).toString('base64url')}`, gate = 'unblock' } = {}) {
  if (!QUIRKS.includes(quirk)) throw new Error(`unknown quirk ${quirk}`);
  const approvals = new Map();
  const agents = new Map();
  let baseUrl = '';

  const envelope = (status, code, message, details) => ({
    status,
    body: { error: { code, message, ...(details ? { details } : {}) }, ...(quirk === 'extra-property' ? { statusCode: status } : {}) },
  });

  const rateHeaders = { 'x-ratelimit-limit': '500', 'x-ratelimit-remaining': '499', 'x-ratelimit-reset': '60' };

  function authenticate(request) {
    const header = request.headers.authorization;
    if (header === `Bearer ${apiKey}`) return null;
    if (quirk === 'verbose-401') {
      if (!header) return envelope(401, 'INVALID_API_KEY', 'Missing credential');
      return envelope(401, 'INVALID_API_KEY', 'Unknown key');
    }
    return envelope(401, 'INVALID_API_KEY', 'Invalid API key');
  }

  function approvalView(approval) {
    const { payload_hash: _hash, ...view } = approval;
    return view;
  }

  // One gated change: `subject` is { action, resourceId, summary, payload }. Without the header an approval is made and
  // refused; with it the approval must be decided, for this action and object, and for exactly this payload.
  function stepUp(request, subject, required) {
    const wanted = request.headers['x-governance-approval'];
    if (!wanted) {
      const created = {
        id: id('gvr'),
        action: subject.action,
        resource_id: subject.resourceId,
        summary: subject.summary,
        requested_via: 'operator_key',
        status: 'pending',
        payload_hash: sha256(canonical(subject.payload)),
        expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        created_at: new Date().toISOString(),
        decided_at: null,
        decided_via: null,
      };
      approvals.set(created.id, created);
      const page = `${baseUrl}/app/approve/${created.id}`;
      return envelope(
        403,
        'GOVERNANCE_APPROVAL_REQUIRED',
        `This action loosens a safety control and requires human approval. Ask the operator to approve request ${created.id} at ${page}, then retry the same call with header X-Governance-Approval: ${created.id}`,
        quirk === 'no-details' ? undefined : { approval_id: created.id, approval_url: page },
      );
    }
    const approval = approvals.get(String(wanted));
    if (!approval) return envelope(404, 'NOT_FOUND', `governance approval not found: ${wanted}`);
    if (approval.status === 'pending' && quirk !== 'pending-accepted') {
      return envelope(403, 'GOVERNANCE_APPROVAL_PENDING', 'governance approval is still pending: a person must approve it first', { approval_id: approval.id, status: 'pending' });
    }
    if (approval.status === 'rejected' || approval.status === 'expired') {
      return envelope(403, `GOVERNANCE_APPROVAL_${approval.status.toUpperCase()}`, `governance approval is ${approval.status}: request a new one`, { approval_id: approval.id, status: approval.status });
    }
    if (approval.status !== 'approved' && approval.status !== 'pending') return envelope(403, 'FORBIDDEN', `governance approval is ${approval.status}: request a new one`);
    if (quirk !== 'unbound' && (approval.action !== subject.action || approval.resource_id !== subject.resourceId)) return envelope(403, 'FORBIDDEN', 'governance approval does not match this action');
    if (quirk !== 'unbound' && approval.payload_hash !== sha256(canonical(subject.payload))) return envelope(403, 'FORBIDDEN', 'governance approval does not match this exact change');
    if (required && quirk !== 'reusable') approval.status = 'consumed';
    return null;
  }

  function validationMessage(issues, sent) {
    const base = JSON.stringify(issues);
    return quirk === 'echo-validation' ? `${base} received ${JSON.stringify(sent)}` : base;
  }

  async function handle(request, response) {
    const url = new URL(request.url, 'http://x');
    const method = request.method;
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');

    const send = ({ status, body, headers = {} }) => {
      const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
      response.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain' : 'application/json; charset=utf-8', ...headers });
      response.end(method === 'HEAD' ? undefined : text);
    };

    // The body, read the way section 3 says.
    let body;
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      const type = (request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
      if (type === 'application/json') {
        try { body = raw ? JSON.parse(raw) : {}; } catch {
          return send(quirk === 'parser-500' ? envelope(500, 'INTERNAL_ERROR', 'An unexpected error occurred') : envelope(400, 'INVALID_JSON', 'Request body is not valid JSON'));
        }
      } else if (type === '' || type === 'text/plain') {
        body = raw;
      } else {
        return send(quirk === 'wrong-415' ? envelope(400, 'INVALID_REQUEST', 'Content-Type must be application/json') : envelope(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json'));
      }
    }

    const route = `${method === 'HEAD' && quirk !== 'no-head' ? 'GET' : method} ${url.pathname}`;
    const authed = (handler) => {
      const refused = authenticate(request);
      return refused ? send(refused) : handler();
    };

    if (route === 'GET /health') return send({ status: 200, body: { status: 'ok' } });

    if (route === 'GET /v1/operators/me') {
      return authed(() => send({ status: 200, body: { id: 'op_reference', email: 'owner@example.test', tier: 'enterprise' }, headers: rateHeaders }));
    }

    if (route === 'POST /v1/passports/verify') {
      const schema = body !== null && typeof body === 'object' && !Array.isArray(body) && typeof body.token === 'string';
      if (!schema) {
        const sent = body;
        return send(envelope(400, 'VALIDATION_ERROR', validationMessage([{ code: 'invalid_type', path: ['token'], message: 'Required' }], sent)));
      }
      if (quirk === 'passport-500') return send(envelope(500, 'INTERNAL_ERROR', 'An unexpected error occurred'));
      return send(envelope(401, 'PASSPORT_INVALID', 'Passport is not valid'));
    }

    if (route === 'POST /v1/agents/register') {
      return authed(() => {
        if (body === null || typeof body !== 'object' || typeof body.name !== 'string') return send(envelope(400, 'VALIDATION_ERROR', validationMessage([{ path: ['name'], message: 'Required' }], body)));
        if (gate === 'register') {
          const refused = stepUp(request, { action: 'agent_register', resourceId: String(body.name), summary: `Register agent ${body.name}`, payload: body }, true);
          if (refused) return send(refused);
        }
        const agent = { id: id('agt'), name: body.name };
        agents.set(agent.id, agent);
        return send({ status: 201, body: agent, headers: rateHeaders });
      });
    }

    // Unblocking an agent releases a block, so it is the change a server that does not gate registration gates.
    let agentRoute = /^POST \/v1\/agents\/([^/]+)\/unblock$/.exec(route);
    if (agentRoute) {
      return authed(() => {
        const agentId = agentRoute[1];
        if (!agents.has(agentId)) return send(envelope(404, 'NOT_FOUND', `agent not found: ${agentId}`));
        const refused = stepUp(request, { action: 'agent_unblock', resourceId: agentId, summary: `Unblock agent ${agentId} for passport issuance`, payload: { agent_id: agentId } }, true);
        if (refused) return send(refused);
        return send({ status: 200, body: { unblocked: true, agent_id: agentId }, headers: rateHeaders });
      });
    }
    agentRoute = /^DELETE \/v1\/agents\/([^/]+)$/.exec(route);
    if (agentRoute) {
      return authed(() => {
        if (!agents.delete(agentRoute[1])) return send(envelope(404, 'NOT_FOUND', `agent not found: ${agentRoute[1]}`));
        return send({ status: 200, body: { deleted: true }, headers: rateHeaders });
      });
    }

    if (route === 'GET /v1/governance/approvals') {
      return authed(() => send({ status: 200, body: { approvals: [...approvals.values()].map(approvalView) } }));
    }
    let match = /^GET \/v1\/governance\/approvals\/([^/]+)$/.exec(route);
    if (match) {
      return authed(() => {
        const approval = approvals.get(match[1]);
        if (!approval) return send(envelope(404, 'NOT_FOUND', `governance approval not found: ${match[1]}`));
        return send({ status: 200, body: { approval: approvalView(approval), payload_hash: approval.payload_hash, approval_url: `${baseUrl}/app/approve/${approval.id}` } });
      });
    }
    match = /^POST \/v1\/governance\/approvals\/([^/]+)\/decide$/.exec(route);
    if (match) {
      const person = request.headers.cookie === 'session=person';
      if (!person && !(quirk === 'bearer-decides' && request.headers.authorization === `Bearer ${apiKey}`)) {
        return send(envelope(401, 'UNAUTHORIZED', 'a signed-in dashboard session is required to decide a governance approval'));
      }
      const approval = approvals.get(match[1]);
      if (!approval) return send(envelope(404, 'NOT_FOUND', `governance approval not found: ${match[1]}`));
      approval.status = body?.decision === 'approve' ? 'approved' : 'rejected';
      approval.decided_at = new Date().toISOString();
      approval.decided_via = 'dashboard';
      return send({ status: 200, body: { decision: body?.decision, approval: approvalView(approval) } });
    }

    if (route === 'POST /v1/team/members') {
      return authed(() => {
        if (quirk === 'payment-text') return send({ status: 402, body: 'Payment Required' });
        return send(envelope(402, 'LICENCE_REQUIRED', 'This feature needs a STACK licence that includes member roles beyond owner and member. Set STACK_LICENCE_KEY to a current licence key.', { feature: 'roles', licence: 'none' }));
      });
    }

    // Probe routes for the refusals of a customer's controls (they belong to this reference server, not to the specification).
    match = /^POST \/v1\/reference\/controls\/([a-z-]+)$/.exec(route);
    if (match) {
      return authed(() => {
        const decision = 'dec_reference';
        if (match[1] === 'denied') return send(envelope(403, 'CONTROL_DENIED', 'Your controls refused this action. Nothing was charged.', { decision_id: decision, reason_code: 'review_required', retry: { ref: 'ref_reference', after_seconds: 60 }, rule: { policy_id: 'pol_reference', policy_revision: 3, section: 'actions', rule: 'rule_1', code: 'review_required' } }));
        if (match[1] === 'limit') return send(envelope(403, 'CONTROL_LIMIT_EXCEEDED', 'Your controls set a limit that this action would pass. Nothing was charged.', { limit: { window: 'day', unit: 'cents' }, remaining: 12 }));
        if (match[1] === 'socket') return send(envelope(quirk === 'socket-5xx' ? 503 : 403, 'CONTROL_SOCKET_UNAVAILABLE', 'Your control server did not answer in time, so this action was refused.', { decision_id: decision, cause: 'timeout' }));
        if (match[1] === 'hosted') return send(envelope(503, 'CONTROL_UNAVAILABLE', "STACK's hosted controls could not decide this action just now.", { decision_id: decision }));
        return send(envelope(404, 'NOT_FOUND', 'no such probe'));
      });
    }

    // Recipients set per job (section 7.4): a policy write, and a send inside one of two Missions. `pinned` names
    // PER_JOB_PINNED, `unpinned` names no one. Like the probes above, they belong to this reference server.
    match = /^(PUT|POST) \/v1\/reference\/per-job\/(policy|send)$/.exec(route);
    if (match) {
      return authed(() => {
        const input = body !== null && typeof body === 'object' ? body : {};
        if (match[2] === 'policy') {
          if (input.recipients === 'per_mission' || quirk === 'per-job-open') return send({ status: 200, body: { ok: true } });
          return send(envelope(400, 'UNBOUNDED_SEND_RULE', 'Rule "reply" allows sending on the connection without naming who receives it. Bind body.to with eq or in, set the rule\'s recipients to "per_mission" so each Mission names them, or set the rule\'s effect to "review" or "deny".', { rules: [{ rule_id: 'reply', reason: 'unbound_recipient', unbound_paths: ['body.to'] }] }));
        }
        const deny = (code, message) => send(envelope(403, 'CONTROL_DENIED', message, { decision_id: 'dec_reference', reason_code: code, rule: { policy_id: 'pol_reference', policy_revision: 1, section: 'connections', rule: 'reply', code } }));
        if (input.mission !== 'pinned') return deny('recipients_not_pinned', 'This send is allowed only in a Mission that names who it may send to, and this Mission does not.');
        if (input.to !== PER_JOB_PINNED && quirk !== 'stranger-allowed') return deny('recipient_not_allowed', quirk === 'names-recipient' ? `${input.to} is not one this Mission may send to.` : 'This recipient is not one this Mission may send to.');
        return send({ status: 200, body: { sent: true } });
      });
    }

    // Model calls: one on the customer's own key, one on a key of the deployment's own.
    match = /^POST \/v1\/llm\/(openai\/images|openrouter\/chat\/completions)$/.exec(route);
    if (match) {
      return authed(() => {
        const raw = request.headers['x-max-cost-cents'];
        let cap = null;
        if (raw !== undefined) {
          const valid = /^[0-9]+$/.test(raw) && Number(raw) >= 1;
          if (!valid) {
            if (quirk !== 'cap-lenient') return send(envelope(400, 'VALIDATION_ERROR', JSON.stringify([{ message: 'Invalid cost cap' }])));
          } else cap = Number(raw);
        }
        const answer = () => send({ status: 200, body: match[1] === 'openai/images' ? { data: [] } : { choices: [] } });
        if (cap === null) return answer();
        if (match[1] === 'openai/images') {
          if (quirk === 'cap-ignored') return answer();
          return send(envelope(422, 'MODEL_COST_CAP', "A cost cap applies only to calls on a key of the deployment's own.", { reason: 'cost_cap_unavailable' }));
        }
        const worstCase = 25;
        if (worstCase > cap) {
          if (quirk === 'cap-ignored') return answer();
          return send(envelope(422, 'MODEL_COST_CAP', `The call could cost up to ${worstCase} cents, above the cap of ${cap} cents.`, { reason: 'cost_cap_exceeded', worst_case_cents: worstCase, max_cost_cents: cap }));
        }
        return answer();
      });
    }

    // No route.
    if (quirk === 'status-405' && method === 'DELETE') return send({ status: 405, body: envelope(405, 'METHOD_NOT_ALLOWED', 'Method not allowed').body });
    if (quirk === 'plain-404') return send({ status: 404, body: { message: `Route ${method}:${url.pathname} not found`, error: 'Not Found', statusCode: 404 } });
    // A path segment that is a token, and the query, are never echoed.
    const shown = url.pathname.split('/').map((segment) => (/^[A-Za-z0-9_-]{24,}$/.test(segment) ? '[redacted]' : segment)).join('/');
    const echoed = quirk === 'echo-404' ? `${url.pathname}${url.search}` : shown;
    return send(envelope(404, 'NOT_FOUND', `Route ${method}:${echoed} not found`));
  }

  const server = createServer((request, response) => {
    handle(request, response).catch(() => {
      if (!response.headersSent) response.writeHead(500, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  return {
    url: baseUrl,
    apiKey,
    /** The person at the approval page: decides an approval as a signed-in browser would. */
    approve: async (approvalId) => {
      const result = await fetch(`${baseUrl}/v1/governance/approvals/${approvalId}/decide`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: 'session=person' },
        body: JSON.stringify({ decision: 'approve' }),
      });
      if (!result.ok) throw new Error(`the approval could not be decided: ${result.status}`);
    },
    /** The probes that make this server answer a 402, the refusals of controls and a cost cap. */
    probes: {
      payment: { method: 'POST', path: '/v1/team/members', body: { email: 'a@example.test', role: 'admin' }, code: 'LICENCE_REQUIRED' },
      controls: [
        { code: 'CONTROL_DENIED', method: 'POST', path: '/v1/reference/controls/denied', body: {} },
        { code: 'CONTROL_LIMIT_EXCEEDED', method: 'POST', path: '/v1/reference/controls/limit', body: {} },
        { code: 'CONTROL_SOCKET_UNAVAILABLE', method: 'POST', path: '/v1/reference/controls/socket', body: {} },
        { code: 'CONTROL_UNAVAILABLE', method: 'POST', path: '/v1/reference/controls/hosted', body: {} },
      ],
      perJob: {
        unbounded: { method: 'PUT', path: '/v1/reference/per-job/policy', body: {} },
        policy: { method: 'PUT', path: '/v1/reference/per-job/policy', body: { recipients: 'per_mission' } },
        unpinned: { method: 'POST', path: '/v1/reference/per-job/send', body: { mission: 'unpinned', to: PER_JOB_PINNED } },
        stranger: { method: 'POST', path: '/v1/reference/per-job/send', body: { mission: 'pinned', to: PER_JOB_STRANGER } },
        pinned: { method: 'POST', path: '/v1/reference/per-job/send', body: { mission: 'pinned', to: PER_JOB_PINNED } },
        recipients: [PER_JOB_STRANGER],
      },
      costCap: { mode: 'own_key', method: 'POST', path: '/v1/llm/openai/images', body: { prompt: 'a cat' } },
      costCapDeploymentKey: { mode: 'deployment_key', method: 'POST', path: '/v1/llm/openrouter/chat/completions', body: { model: 'acme/chat-1', messages: [{ role: 'user', content: 'a cat' }] } },
    },
    agents,
    approvals,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
