// The reference A2A server must pass the a2a suite, and the suite must fail servers that each
// have one deliberate defect.

import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { formatReport, runA2aSuite } from '../src/index.mjs';
import { REFERENCE_AGENT_CARD_PATH, createReferenceA2aHandler, startReferenceA2aServer } from './a2a-reference.mjs';
import { listen } from './support.mjs';

const OPTIONS = { headers: { authorization: 'Bearer test-token' }, fromAgent: 'agt_from', toAgent: 'agt_to', otherHeaders: { authorization: 'Bearer other-token' } };
const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

/** The reference handler behind a wrapper that can change what it says. */
async function withDefect(patch, extra = {}) {
  let origin = '';
  const handle = createReferenceA2aHandler({
    tokens: { 'test-token': 'caller_a', 'other-token': 'caller_b' },
    agents: { caller_a: ['agt_from', 'agt_to'], caller_b: ['agt_other'] },
    baseUrl: () => origin,
    ...extra,
  });
  const server = createServer((req, res) => {
    patch(req, res, handle).catch(() => res.writeHead(500).end());
  });
  const instance = await listen(server);
  origin = instance.url;
  return instance;
}

/** Collect what the reference writes so a defect can rewrite it. */
function intercept(res, rewrite) {
  const write = res.writeHead.bind(res);
  const end = res.end.bind(res);
  let status = 200;
  let headers = {};
  res.writeHead = (s, h) => {
    status = s;
    headers = h ?? {};
    return res;
  };
  res.end = (body) => {
    const out = rewrite({ status, headers, body: body ? JSON.parse(body) : undefined });
    write(out.status, out.headers);
    end(out.body === undefined ? undefined : JSON.stringify(out.body));
  };
}

describe('the reference A2A server', () => {
  it('passes the suite with the whole task flow, nothing skipped and no warning', async () => {
    const server = await startReferenceA2aServer();
    try {
      const report = await runA2aSuite({ url: server.url, ...OPTIONS, timeoutMs: 3000 });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.warnings, formatReport(report)).toBe(0);
      // The platform card is not signed: the one check of a signature is skipped, never passed.
      expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['A07']);
    } finally {
      await server.close();
    }
  });

  it('serves the signed card of an agent the suite verifies against the key directory its header names', async () => {
    const server = await startReferenceA2aServer({ agentCard: true });
    try {
      const report = await runA2aSuite({ url: `${server.url}${REFERENCE_AGENT_CARD_PATH}`, groups: ['card'], timeoutMs: 3000 });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.warnings, formatReport(report)).toBe(0);
      expect(report.results.find((r) => r.id === 'A07')?.status).toBe('pass');
      expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['A06', 'A10', 'A11', 'A12', 'A13', 'A14', 'A15', 'A16', 'A20', 'A21', 'A22', 'A23', 'A24', 'A25']);
    } finally {
      await server.close();
    }
  });

  it('skips the flow without agents, and the isolation check without a second caller', async () => {
    const server = await startReferenceA2aServer();
    try {
      const noAgents = await runA2aSuite({ url: server.url, headers: OPTIONS.headers, timeoutMs: 3000 });
      expect(noAgents.failed).toBe(0);
      expect(noAgents.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['A07', 'A20', 'A21', 'A22', 'A23', 'A24', 'A25']);
      const noOther = await runA2aSuite({ url: server.url, headers: OPTIONS.headers, fromAgent: 'agt_from', toAgent: 'agt_to', timeoutMs: 3000 });
      expect(noOther.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['A07', 'A25']);
    } finally {
      await server.close();
    }
  });
});

describe('the suite fails a server with one defect', () => {
  it('a signed card whose content was changed after it was signed', async () => {
    const server = await withDefect(async (req, res, handle) => {
      intercept(res, ({ status, headers, body }) => (body?.signatures ? { status, headers, body: { ...body, description: 'Changed after signing.' } } : { status, headers, body }));
      await handle(req, res);
    }, { agentCard: true });
    try {
      const report = await runA2aSuite({ url: `${server.url}${REFERENCE_AGENT_CARD_PATH}`, groups: ['card'], timeoutMs: 3000 });
      expect(mustFailed(report)).toEqual(['A07']);
    } finally {
      await server.close();
    }
  });

  it('one that answers without credentials', async () => {
    const server = await withDefect(async (req, res, handle) => {
      req.headers.authorization = 'Bearer test-token';
      await handle(req, res);
    });
    try {
      const report = await runA2aSuite({ url: server.url, ...OPTIONS, timeoutMs: 3000 });
      expect(mustFailed(report)).toEqual(['A10', 'A25']);
    } finally {
      await server.close();
    }
  });

  it('one that answers a malformed envelope with HTTP 200, and a bad id by echoing it', async () => {
    const server = await withDefect(async (req, res, handle) => {
      intercept(res, ({ status, headers, body }) => {
        if (status === 400) return { status: 200, headers, body };
        if (body?.error?.code === -32601) return { status, headers, body: { ...body, id: 'x' } };
        return { status, headers, body };
      });
      await handle(req, res);
    });
    try {
      const report = await runA2aSuite({ url: server.url, ...OPTIONS, timeoutMs: 3000 });
      expect(mustFailed(report)).toEqual(expect.arrayContaining(['A11', 'A12']));
    } finally {
      await server.close();
    }
  });

  it('one that names the task in its not-found error and adds data', async () => {
    const server = await withDefect(async (req, res, handle) => {
      intercept(res, ({ status, headers, body }) => {
        if (body?.error?.code === -32001) return { status, headers, body: { ...body, error: { ...body.error, message: 'Task not found: dof_00000000000000000000000000000000', data: { hint: 'x' } } } };
        return { status, headers, body };
      });
      await handle(req, res);
    });
    try {
      const report = await runA2aSuite({ url: server.url, ...OPTIONS, timeoutMs: 3000 });
      expect(mustFailed(report)).toEqual(expect.arrayContaining(['A15']));
    } finally {
      await server.close();
    }
  });

  it('one whose card advertises streaming but has no tasks/sendSubscribe, and omits the skills', async () => {
    const server = await withDefect(async (req, res, handle) => {
      if (req.url === '/.well-known/agent.json') {
        intercept(res, ({ status, headers, body }) => {
          const { skills: _skills, ...rest } = body;
          return { status, headers, body: { ...rest, capabilities: { ...rest.capabilities, streaming: true } } };
        });
      }
      await handle(req, res);
    });
    try {
      const report = await runA2aSuite({ url: server.url, ...OPTIONS, timeoutMs: 3000 });
      expect(mustFailed(report)).toEqual(['A05']);
    } finally {
      await server.close();
    }
  });

  it('one that uses the client\'s id as the task id and does not echo the session', async () => {
    const server = await withDefect(async (req, res, handle) => {
      if (req.method === 'POST') {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const text = Buffer.concat(chunks).toString('utf8');
        // Replay the body to the reference, and rewrite its answer to the send.
        const replay = Object.assign(Readable.from([Buffer.from(text, 'utf8')]), { method: req.method, url: req.url, headers: req.headers });
        let sent;
        try {
          sent = JSON.parse(text);
        } catch {
          sent = null;
        }
        intercept(res, ({ status, headers, body }) => {
          if (sent?.method === 'tasks/send' && body?.result) {
            return { status, headers, body: { ...body, result: { ...body.result, id: sent.params?.id ?? body.result.id, sessionId: null } } };
          }
          return { status, headers, body };
        });
        await handle(replay, res);
        return;
      }
      await handle(req, res);
    });
    try {
      const report = await runA2aSuite({ url: server.url, ...OPTIONS, timeoutMs: 3000 });
      expect(mustFailed(report)).toEqual(expect.arrayContaining(['A21']));
    } finally {
      await server.close();
    }
  });

  it('one that lets another caller read the task', async () => {
    const server = await withDefect(async (req, res, handle) => {
      // Every token is the first caller.
      req.headers.authorization = 'Bearer test-token';
      if (req.method !== 'POST') return handle(req, res);
      return handle(req, res);
    });
    try {
      const report = await runA2aSuite({ url: server.url, ...OPTIONS, timeoutMs: 3000 });
      expect(mustFailed(report)).toEqual(expect.arrayContaining(['A10', 'A25']));
    } finally {
      await server.close();
    }
  });
});

