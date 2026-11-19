// A reference A2A server of the STACK profile (spec/a2a/SPEC.md): the agent card and the
// JSON-RPC 2.0 endpoint with tasks/send, tasks/get and tasks/cancel over an in-memory task store.
// It is the smallest server that conforms; start an implementation of your own from it.
//
// Callers are identified by a bearer token (`tokens`: token to caller id). Agents belong to a
// caller. A task is a message deposited from one of the caller's agents to another.

import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createServer } from 'node:http';

/** Canonical JSON (RFC 8785 for the strings, booleans and arrays a card holds): keys sorted, no whitespace. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}

/**
 * The card a server serves for one of its agents: A2A 0.3 style, signed with the agent's key (a JWS
 * over the canonical card without `signatures`), and the Web Bot Auth key directory its `jku` names,
 * both on the server's own origin under the agent's id.
 */
export const REFERENCE_AGENT_CARD_PATH = '/v1/agent-identity/agents/agt_referenceagent00000000/agent-card.json';
export const REFERENCE_AGENT_DIRECTORY_PATH = '/v1/agent-identity/agents/agt_referenceagent00000000/http-message-signatures-directory';

export function createSignedAgentCard(origin) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const { x } = publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
  const card = {
    name: 'agt_referenceagent00000000',
    description: 'An AI agent operated through the reference server.',
    url: `${origin}/v1/a2a/jsonrpc`,
    version: '1.0.0',
    protocolVersion: '0.3.0',
    supportedInterfaces: [{ url: `${origin}/v1/a2a/jsonrpc`, protocolBinding: 'JSONRPC', protocolVersion: '0.3' }],
    provider: { organization: 'example', url: 'https://example.com' },
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [{ id: 'identity', name: 'Identity', description: 'Who this agent is and who stands behind it.', tags: ['identity'] }],
  };
  const protectedHeader = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid, typ: 'JOSE', jku: `${origin}${REFERENCE_AGENT_DIRECTORY_PATH}` })).toString('base64url');
  const signingInput = `${protectedHeader}.${Buffer.from(canonical(card)).toString('base64url')}`;
  const signature = sign(null, Buffer.from(signingInput), privateKey).toString('base64url');
  return {
    card: { ...card, signatures: [{ protected: protectedHeader, signature }] },
    directory: { keys: [{ kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', nbf: Math.floor(Date.now() / 1000) - 60 }] },
  };
}

const CODES = { invalidRequest: -32600, methodNotFound: -32601, invalidParams: -32602, taskNotFound: -32001, notCancelable: -32002 };

const result = (id, value) => ({ jsonrpc: '2.0', id: id ?? null, result: value });
const failure = (id, code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
const isId = (v) => typeof v === 'string' || typeof v === 'number' || v === null;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * @param {{ tokens: Record<string, string>, agents: Record<string, string[]>, baseUrl: () => string }} options
 *   `agents` maps a caller to the agent ids it owns; `baseUrl` is the server's own origin once it listens.
 */
export function createReferenceA2aHandler({ tokens, agents, baseUrl, agentCard = false }) {
  let served = null;
  /** @type {Map<string, { id: string, caller: string, from: string, to: string, state: 'deposited' | 'expired', at: Date, expires: Date }>} */
  const tasks = new Map();

  function card() {
    return {
      name: 'Reference',
      description: 'A reference A2A endpoint that relays a task from one agent of a caller to another.',
      url: `${baseUrl()}/v1/a2a/jsonrpc`,
      provider: { organization: 'example', url: 'https://example.com' },
      version: '0.2.1',
      defaultInputModes: ['text', 'data'],
      defaultOutputModes: ['text', 'data'],
      capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false },
      authentication: { schemes: ['bearer'] },
      skills: [{ id: 'reference.relay', name: 'Relay', description: 'Forward a task to an agent of the same caller.', tags: ['messaging'] }],
    };
  }

  function dispatch(caller, body) {
    const envelope = isObject(body) && body.jsonrpc === '2.0' && typeof body.method === 'string' ? body : null;
    if (!envelope) {
      return { status: 400, body: failure(isObject(body) && isId(body.id) ? body.id : null, CODES.invalidRequest, 'Invalid JSON-RPC envelope') };
    }
    const id = isId(envelope.id) ? envelope.id : null;
    const params = isObject(envelope.params) ? envelope.params : undefined;
    const reply = (value) => ({ status: 200, body: value });

    if (envelope.method === 'tasks/send') {
      const message = params?.message;
      const from = params?.metadata?.stack_from_agent;
      const to = params?.metadata?.stack_to_agent;
      if (!message || typeof message !== 'object') return reply(failure(id, CODES.invalidParams, 'params.message is required'));
      if (typeof from !== 'string' || typeof to !== 'string') {
        return reply(failure(id, CODES.invalidParams, 'params.metadata.stack_from_agent and stack_to_agent are required (STACK extension)'));
      }
      const own = agents[caller] ?? [];
      if (!own.includes(from) || !own.includes(to)) return reply(failure(id, CODES.taskNotFound, 'Task not found'));
      const task = {
        id: `dof_${randomBytes(16).toString('hex')}`,
        caller, from, to, state: 'deposited', at: new Date(), expires: new Date(Date.now() + 30 * 60_000),
      };
      tasks.set(task.id, task);
      return reply(result(id, {
        id: task.id,
        sessionId: typeof params.sessionId === 'string' ? params.sessionId : null,
        status: { state: 'submitted', timestamp: new Date().toISOString() },
        metadata: { ...(isObject(params.metadata) ? params.metadata : {}), stack_dropoff_id: task.id },
      }));
    }

    if (envelope.method === 'tasks/get' || envelope.method === 'tasks/cancel') {
      const taskId = typeof params?.id === 'string' ? params.id : null;
      if (!taskId) return reply(failure(id, CODES.invalidParams, 'params.id is required'));
      const task = tasks.get(taskId);
      if (!task || task.caller !== caller) return reply(failure(id, CODES.taskNotFound, 'Task not found'));
      if (envelope.method === 'tasks/get') {
        return reply(result(id, {
          id: task.id,
          status: { state: task.state === 'deposited' ? 'working' : 'failed', timestamp: task.at.toISOString() },
          metadata: {
            stack_dropoff_id: task.id,
            stack_from_agent: task.from,
            stack_to_agent: task.to,
            stack_expires_at: task.expires.toISOString(),
          },
        }));
      }
      if (task.state === 'expired') return reply(failure(id, CODES.notCancelable, 'Task cannot be changed'));
      task.state = 'expired';
      return reply(result(id, { id: task.id, status: { state: 'canceled', timestamp: new Date().toISOString() } }));
    }

    return reply(failure(id, CODES.methodNotFound, `Unknown method "${envelope.method}"`));
  }

  return async function handle(req, res) {
    const send = (status, value) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(value));
    };
    if (agentCard) served ??= createSignedAgentCard(baseUrl());
    if (served && req.method === 'GET' && req.url === REFERENCE_AGENT_CARD_PATH) return send(200, served.card);
    if (served && req.method === 'GET' && req.url === REFERENCE_AGENT_DIRECTORY_PATH) {
      res.writeHead(200, { 'content-type': 'application/http-message-signatures-directory+json' });
      return res.end(JSON.stringify(served.directory));
    }
    if (req.method === 'GET' && req.url === '/.well-known/agent.json') return send(200, card());
    if (req.method === 'POST' && req.url === '/v1/a2a/jsonrpc') {
      const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
      const caller = token ? tokens[token] : undefined;
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      if (!caller) return send(401, { error: { code: 'INVALID_API_KEY', message: 'Invalid API key' } });
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        return send(400, failure(null, CODES.invalidRequest, 'Invalid JSON-RPC envelope'));
      }
      const outcome = dispatch(caller, body);
      return send(outcome.status, outcome.body);
    }
    return send(404, { error: { code: 'NOT_FOUND', message: 'not found' } });
  };
}

/** Start the reference on an ephemeral loopback port. */
export async function startReferenceA2aServer(options = {}) {
  let origin = '';
  const handle = createReferenceA2aHandler({
    tokens: { 'test-token': 'caller_a', 'other-token': 'caller_b' },
    agents: { caller_a: ['agt_from', 'agt_to'], caller_b: ['agt_other'] },
    baseUrl: () => origin,
    ...options,
  });
  const server = createServer((req, res) => {
    handle(req, res).catch(() => res.writeHead(500).end());
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  return { url: origin, close: () => new Promise((resolve) => server.close(resolve)) };
}
