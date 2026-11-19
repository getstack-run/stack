import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createStackMcpServer } from './index.js';

// The engine's own confirmation of a governance approval: it opens the approval page in the person's browser when
// the client can show one, and reports what was decided there. Nothing is asked in the chat and nothing is approved
// here (the in-chat flow with its attestation is the hosted server's: chat-confirmation.test.ts).

const BASE = 'http://api.test';
const APPROVAL = 'gvr_engine_1';
const LINK = `https://install.example/app/approve/${APPROVAL}`;

interface Call { method: string; path: string; headers: Record<string, string> }

/** The API as the page leaves it: `decided` is what the person did on the approval page. */
function fakeApi(state: { status: string }) {
  const calls: Call[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: { method: string; headers: Record<string, string> }) => {
    const path = url.slice(BASE.length);
    calls.push({ method: init.method, path, headers: init.headers });
    const json = (body: unknown, code = 200) => new Response(JSON.stringify(body), { status: code });
    if (path === '/v1/agents/agt_1/unblock') {
      return init.headers['X-Governance-Approval'] === APPROVAL
        ? json({ unblocked: true })
        : json({ error: { code: 'GOVERNANCE_APPROVAL_REQUIRED', message: 'needs approval', details: { approval_id: APPROVAL, approval_url: LINK } } }, 403);
    }
    if (path === `/v1/governance/approvals/${APPROVAL}` && init.method === 'GET') {
      return json({
        approval: { id: APPROVAL, action: 'agent_unblock', resource_id: 'agt_1', summary: 'Unblock agent agt_1', status: state.status, expires_at: '2026-10-21T12:00:00.000Z' },
        payload_hash: 'c'.repeat(64),
        approval_url: LINK,
      });
    }
    return json({ error: { message: 'not found' } }, 404);
  }));
  return calls;
}

type Elicitation = { mode?: string; url?: string; message: string };

async function connect(options: { capabilities: { form?: Record<string, never>; url?: Record<string, never> } | null; onPage?: () => 'accept' | 'decline' }) {
  const asked: Elicitation[] = [];
  const server = createStackMcpServer(BASE, 'oauth_access_token', {
    chat: { attestationKey: 'attestation-key-0123456789abcdefghijkl', sessionId: () => 'session', principal: 'operator:op_one', oauth: true },
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: 'engine-confirm-test', version: '0.0.0' },
    { capabilities: options.capabilities ? { elicitation: options.capabilities } : {} },
  );
  if (options.capabilities) {
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      const params = request.params as Elicitation;
      asked.push(params);
      return params.mode === 'url' ? { action: options.onPage?.() ?? 'accept' } : { action: 'decline' as const };
    });
  }
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, asked };
}

const unblock = (client: Client) => client.callTool({ name: 'stack_unblock_agent', arguments: { agent_id: 'agt_1' } });
const textOf = (result: unknown) => JSON.stringify(result);

afterEach(() => vi.unstubAllGlobals());

describe('the engine\'s confirmation of a governance approval', () => {
  it('opens the approval page for the person and retries with the approval once they have decided there', async () => {
    const state = { status: 'pending' };
    const calls = fakeApi(state);
    const { client, asked } = await connect({
      capabilities: { url: {} },
      // The person approves on the page, so what the API reads afterwards says so.
      onPage: () => {
        state.status = 'approved';
        return 'accept';
      },
    });
    const result = await unblock(client);

    expect(asked).toHaveLength(1);
    expect(asked[0]).toMatchObject({ mode: 'url', url: LINK });
    expect(result.isError).not.toBe(true);
    expect(textOf(result)).toContain('unblocked');
    // Nothing was decided in the chat, and the engine relays no attestation.
    expect(calls.some((call) => call.path.endsWith('/chat-decision'))).toBe(false);
    expect(calls.filter((call) => call.path === '/v1/agents/agt_1/unblock').at(-1)!.headers['X-Governance-Approval']).toBe(APPROVAL);
  });

  it('returns the link when the person leaves the page without deciding', async () => {
    const state = { status: 'pending' };
    const calls = fakeApi(state);
    const { client } = await connect({ capabilities: { url: {} } });
    const result = textOf(await unblock(client).catch((error: unknown) => ({ content: String(error) })));
    expect(result).toContain(LINK);
    expect(calls.some((call) => call.headers['X-Governance-Approval'] !== undefined)).toBe(false);
  });

  it('returns the link, and does not retry, when the page says the person rejected it', async () => {
    const state = { status: 'pending' };
    const calls = fakeApi(state);
    const { client } = await connect({
      capabilities: { url: {} },
      onPage: () => {
        state.status = 'rejected';
        return 'accept';
      },
    });
    await unblock(client).catch(() => undefined);
    expect(calls.some((call) => call.headers['X-Governance-Approval'] !== undefined)).toBe(false);
  });

  it('returns the link when the person declines to open the page', async () => {
    const state = { status: 'pending' };
    const calls = fakeApi(state);
    const { client, asked } = await connect({ capabilities: { url: {} }, onPage: () => 'decline' });
    const result = textOf(await unblock(client).catch((error: unknown) => ({ content: String(error) })));
    expect(asked).toHaveLength(1);
    expect(result).toContain(LINK);
    expect(calls.some((call) => call.headers['X-Governance-Approval'] !== undefined)).toBe(false);
  });

  it('never asks a form in the chat: a client that can only show a form gets the link', async () => {
    const state = { status: 'pending' };
    const calls = fakeApi(state);
    const { client, asked } = await connect({ capabilities: { form: {} } });
    const result = textOf(await unblock(client).catch((error: unknown) => ({ content: String(error) })));
    expect(asked).toHaveLength(0);
    expect(result).toContain(LINK);
    expect(calls.some((call) => call.path.endsWith('/chat-decision'))).toBe(false);
    // The API was not even asked about the approval: nothing here could use the answer.
    expect(calls.some((call) => call.path === `/v1/governance/approvals/${APPROVAL}`)).toBe(false);
  });

  it('returns the link to a client that cannot elicit at all', async () => {
    const state = { status: 'pending' };
    fakeApi(state);
    const { client } = await connect({ capabilities: null });
    expect(textOf(await unblock(client).catch((error: unknown) => ({ content: String(error) })))).toContain(LINK);
  });
});
