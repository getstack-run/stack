// Conformance suite for a service's MCP endpoint (spec/service-mcp/SPEC.md): the kit sends your
// endpoint exactly what STACK sends when an agent lists or calls your tools through STACK, and
// checks your answers.
//
// You give it your endpoint's address, the headers your credential travels in (the ones STACK
// injects from the customer's connection), and, if you want a call checked too, one tool that is
// safe to call with the arguments you give.
//
//   runServiceMcpSuite({ url, headers, tool?: { name, arguments }, fetch?, timeoutMs? })
//
// A check that needs something you did not give is reported as skipped, never as passed.

import { assert, fail, runChecks, skip } from './harness.mjs';

/** What STACK sends, section 3 of the specification. */
export const SERVICE_MCP_ACCEPT = 'application/json, text/event-stream';
export const SERVICE_MCP_PROTOCOL_VERSION = '2025-06-18';
export const SERVICE_MCP_TIMEOUT_MS = 30_000;
export const SERVICE_MCP_MAX_ANSWER_BYTES = 10 * 1024 * 1024;

export function initializeBody() {
  return {
    jsonrpc: '2.0',
    id: 0,
    method: 'initialize',
    params: { protocolVersion: SERVICE_MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'STACK', version: '1.0.0' } },
  };
}

export const INITIALIZED_BODY = { jsonrpc: '2.0', method: 'notifications/initialized' };

const VISIBLE_ASCII = /^[\x21-\x7E]+$/;

/** The JSON-RPC message in an answer: a JSON body, or the last `data:` event of an event stream. */
export function jsonRpcOf(text) {
  const events = text.split(/\r?\n/).filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trim()).filter(Boolean);
  try {
    const value = JSON.parse(events.length > 0 ? events[events.length - 1] : text);
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * @param {{
 *   url: string,
 *   headers?: Record<string, string>,
 *   tool?: { name: string, arguments?: Record<string, unknown> },
 *   fetch?: typeof fetch,
 *   timeoutMs?: number,
 * }} options
 */
export async function runServiceMcpSuite(options) {
  const { url, headers = {}, tool, timeoutMs = SERVICE_MCP_TIMEOUT_MS } = options;
  const send = options.fetch ?? globalThis.fetch;
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) throw new Error('give the service-mcp suite the address of your MCP endpoint');

  /** One request as STACK makes it: no redirect followed, a time limit, an answer size limit. */
  async function request(method, body, extra) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await send(url, {
        method,
        headers: { 'content-type': 'application/json', accept: SERVICE_MCP_ACCEPT, ...headers, ...extra },
        ...(body === null ? {} : { body: JSON.stringify(body) }),
        redirect: 'manual',
        signal: controller.signal,
      });
      const text = await res.text();
      return { status: res.status, sessionId: res.headers.get('mcp-session-id'), text, bytes: Buffer.byteLength(text) };
    } catch (error) {
      if (controller.signal.aborted) fail(`${method} ${body?.method ?? ''} was not answered within ${timeoutMs} ms`);
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  const answerOf = (step, res) => {
    assert(res.status < 300 || res.status >= 400, `${step} was answered with a redirect (${res.status}); STACK follows none`);
    assert(res.bytes <= SERVICE_MCP_MAX_ANSWER_BYTES, `${step} was answered with ${res.bytes} bytes; STACK reads at most ${SERVICE_MCP_MAX_ANSWER_BYTES}`);
    if (res.status < 200 || res.status >= 300) fail(`${step} was answered ${res.status}: ${res.text.slice(0, 200)}`);
    const rpc = jsonRpcOf(res.text);
    assert(rpc, `${step} was not answered with a JSON-RPC message, as JSON or as an event stream`);
    if (rpc.error) fail(`${step} was refused: ${String(JSON.stringify(rpc.error)).slice(0, 200)}`);
    assert(rpc.result && typeof rpc.result === 'object' && !Array.isArray(rpc.result), `${step} carried no result object`);
    return rpc.result;
  };

  // The session state the checks build in order; a later check is skipped when an earlier one could not set it up.
  let opened = null;
  let ready = false;

  const sessionHeaders = () => ({
    'mcp-protocol-version': opened.version,
    ...(opened.sessionId ? { 'mcp-session-id': opened.sessionId } : {}),
  });

  const report = await runChecks('service mcp endpoint', [
    {
      id: 'SM01', level: 'MUST', title: 'answers initialize, sent with Accept for JSON and event streams, with a result that names a protocol version',
      async run() {
        const res = await request('POST', initializeBody(), {});
        const result = answerOf('initialize', res);
        assert(typeof result.protocolVersion === 'string' && result.protocolVersion.length > 0, 'the initialize result names no protocolVersion');
        opened = { sessionId: res.sessionId, version: result.protocolVersion };
      },
    },
    {
      id: 'SM02', level: 'MUST', title: 'a session id, when the endpoint gives one, is visible ASCII of at most 1,024 characters',
      run() {
        if (!opened) return skip('initialize did not succeed');
        if (opened.sessionId === null) return skip('the endpoint keeps no session');
        assert(opened.sessionId.length <= 1024 && VISIBLE_ASCII.test(opened.sessionId), 'the session id holds a character that is not visible ASCII, or is too long');
      },
    },
    {
      id: 'SM03', level: 'MUST', title: 'takes notifications/initialized with the session and the protocol version, answering 2xx',
      async run() {
        if (!opened) return skip('initialize did not succeed');
        const res = await request('POST', INITIALIZED_BODY, sessionHeaders());
        assert(res.status >= 200 && res.status < 300, `notifications/initialized was answered ${res.status}: ${res.text.slice(0, 200)}`);
        ready = true;
      },
    },
    {
      id: 'SM04', level: 'MUST', title: 'answers tools/list in the session with tools that each have a name and an input schema',
      async run() {
        if (!ready) return skip('the session was not opened');
        const result = answerOf('tools/list', await request('POST', { jsonrpc: '2.0', id: 1, method: 'tools/list' }, sessionHeaders()));
        assert(Array.isArray(result.tools), 'the tools/list result has no tools list');
        for (const t of result.tools) {
          assert(t && typeof t.name === 'string' && t.name.length > 0, 'a listed tool has no name');
          assert(t.inputSchema && typeof t.inputSchema === 'object', `the tool ${t.name} has no inputSchema`);
        }
      },
    },
    {
      id: 'SM05', level: 'MUST', title: 'answers tools/call in the session with a content list',
      async run() {
        if (!tool) return skip('no tool to call was given');
        if (!ready) return skip('the session was not opened');
        const result = answerOf(`tools/call ${tool.name}`, await request('POST', {
          jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: tool.name, arguments: tool.arguments ?? {} },
        }, sessionHeaders()));
        assert(Array.isArray(result.content), `the result of ${tool.name} has no content list`);
      },
    },
    {
      id: 'SM06', level: 'SHOULD', title: 'ends a session on DELETE with 2xx, or answers 405 when it does not let a client end one',
      async run() {
        if (!opened) return skip('initialize did not succeed');
        if (opened.sessionId === null) return skip('the endpoint keeps no session');
        const res = await request('DELETE', null, sessionHeaders());
        assert((res.status >= 200 && res.status < 300) || res.status === 405, `DELETE was answered ${res.status}`);
      },
    },
  ]);
  return report;
}
