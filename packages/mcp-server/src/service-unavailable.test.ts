import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createApiClient, retryAfterSeconds, temporarilyUnavailableMessage } from './api-client.js';
import { createStackMcpServer } from './index.js';

// An upstream 503 means STACK cannot answer right now. The model must read a
// temporary outage with a wait, never a rejected credential: nothing here may
// suggest the token is invalid or should be rotated or re-authorized.

const BASE = 'http://api.test';

function respond(body: string | null, init: ResponseInit) {
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => new Response(body, init)));
}

async function callTool(name: string, args: Record<string, unknown>) {
  const server = createStackMcpServer(BASE, 'sk_test_unused');
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'unavailable-test', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const result = await client.callTool({ name, arguments: args });
  await client.close();
  const text = (result.content as Array<{ text: string }>)[0]!.text;
  return { result, text };
}

const envelope = (code: string, details?: Record<string, unknown>) =>
  JSON.stringify({ error: { code, message: 'STACK-side message that must not decide the text', ...(details ? { details } : {}) } });

const NO_CREDENTIAL_ADVICE = /invalid|credential|token|rotat|re-?authori|re-?auth|sign in|log ?in|expired/i;

afterEach(() => vi.unstubAllGlobals());

describe('a 503 from the STACK API', () => {
  it('becomes a tool error naming the cause, with the wait from the Retry-After header', async () => {
    respond(envelope('SERVICE_UNAVAILABLE', { retry_after_seconds: 99 }), { status: 503, headers: { 'Retry-After': '30', 'content-type': 'application/json' } });
    const { result, text } = await callTool('stack_list_agents', {});
    expect(result.isError).toBe(true);
    expect(text).toContain('STACK is temporarily unavailable, retry in 30 seconds');
    expect(text).not.toMatch(NO_CREDENTIAL_ADVICE);
  });

  it('takes the wait from error.details.retry_after_seconds when there is no header', async () => {
    respond(envelope('SERVICE_UNAVAILABLE', { retry_after_seconds: 12 }), { status: 503, headers: { 'content-type': 'application/json' } });
    const { result, text } = await callTool('stack_list_agents', {});
    expect(result.isError).toBe(true);
    expect(text).toContain('STACK is temporarily unavailable, retry in 12 seconds');
    expect(text).not.toMatch(NO_CREDENTIAL_ADVICE);
  });

  it('reads a bare 503 from the platform proxy, with no body or a non-JSON body, as retry in 5 seconds', async () => {
    for (const [body, init] of [
      [null, { status: 503 }],
      ['', { status: 503 }],
      ['upstream connect error or disconnect/reset before headers', { status: 503, headers: { 'content-type': 'text/plain' } }],
      ['<html>503 Service Unavailable</html>', { status: 503, headers: { 'content-type': 'text/html' } }],
    ] as const) {
      respond(body, init);
      const { result, text } = await callTool('stack_list_agents', {});
      expect(result.isError, String(body)).toBe(true);
      expect(text, String(body)).toContain('STACK is temporarily unavailable, retry in 5 seconds');
      expect(text, String(body)).not.toMatch(NO_CREDENTIAL_ADVICE);
    }
  });

  it('gives every 503 code the same message', async () => {
    for (const code of ['SERVICE_UNAVAILABLE', 'CONTROL_UNAVAILABLE', 'PROVIDER_CAPACITY_UNAVAILABLE']) {
      respond(envelope(code), { status: 503, headers: { 'Retry-After': '7', 'content-type': 'application/json' } });
      const { result, text } = await callTool('stack_list_agents', {});
      expect(result.isError, code).toBe(true);
      expect(text, code).toContain('STACK is temporarily unavailable, retry in 7 seconds');
      expect(text, code).not.toMatch(NO_CREDENTIAL_ADVICE);
    }
  });

  it('is not hidden by a governance approval hook or turned into an approval link', async () => {
    respond(envelope('SERVICE_UNAVAILABLE', { retry_after_seconds: 3 }), { status: 503 });
    const { api } = createApiClient(BASE, 'sk_test_key');
    await expect(api('POST', '/v1/agents/register', {})).rejects.toThrow('STACK is temporarily unavailable, retry in 3 seconds');
  });
});

describe('the wait in a 503', () => {
  const at = (header: string | null, details?: unknown) => retryAfterSeconds(header, details === undefined ? undefined : { error: { details } });

  it('is clamped to 1 through 300 seconds', () => {
    expect(at('0')).toBe(1);
    expect(at('1')).toBe(1);
    expect(at('300')).toBe(300);
    expect(at('9999')).toBe(300);
    expect(at(null, { retry_after_seconds: 0 })).toBe(1);
    expect(at(null, { retry_after_seconds: 100000 })).toBe(300);
  });

  it('prefers the header, then the details, then 5', () => {
    expect(at('20', { retry_after_seconds: 8 })).toBe(20);
    expect(at(null, { retry_after_seconds: 8 })).toBe(8);
    expect(at(null)).toBe(5);
    expect(at('')).toBe(5);
  });

  it('ignores a value that is not a whole number of seconds or a date', () => {
    expect(at('soon', { retry_after_seconds: 'later' })).toBe(5);
    expect(at('-3')).toBe(5);
    expect(at('2.5')).toBe(5);
    expect(at(null, { retry_after_seconds: 2.5 })).toBe(5);
    expect(at(null, { retry_after_seconds: Number.NaN })).toBe(5);
  });

  it('reads an HTTP date in the Retry-After header', () => {
    const now = Date.parse('2026-10-21T12:00:00Z');
    expect(retryAfterSeconds('Wed, 21 Oct 2026 12:00:45 GMT', undefined, now)).toBe(45);
    expect(retryAfterSeconds('Wed, 21 Oct 2026 11:00:00 GMT', undefined, now)).toBe(1);
  });

  it('is worded as one sentence that names the cause and asks for no credential change', () => {
    expect(temporarilyUnavailableMessage(1)).toMatch(/^STACK is temporarily unavailable, retry in 1 second\b/);
    expect(temporarilyUnavailableMessage(30)).toMatch(/^STACK is temporarily unavailable, retry in 30 seconds\b/);
    expect(temporarilyUnavailableMessage(30)).not.toMatch(NO_CREDENTIAL_ADVICE);
  });
});

describe('a 503 that a retry will not fix', () => {
  it('keeps the API message for a revoked customer key, which is not an outage', async () => {
    respond(
      JSON.stringify({ error: { code: 'CMEK_REVOKED', message: 'STACK cannot use the configured customer KMS key' } }),
      { status: 503, headers: { 'content-type': 'application/json' } },
    );
    const { result, text } = await callTool('stack_list_agents', {});
    expect(result.isError).toBe(true);
    expect(text).toBe('STACK cannot use the configured customer KMS key');
  });
});

describe('statuses that are not a 503', () => {
  it('still reports a 401 as an authentication failure with the API message', async () => {
    respond(JSON.stringify({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } }), { status: 401, headers: { 'content-type': 'application/json' } });
    const { result, text } = await callTool('stack_list_agents', {});
    expect(result.isError).toBe(true);
    expect(text).toBe('Invalid or expired token');
    expect(text).not.toMatch(/temporarily unavailable/i);
  });

  it('keeps other server errors as they were', async () => {
    respond('<html>bad gateway</html>', { status: 502, headers: { 'content-type': 'text/html' } });
    const { result, text } = await callTool('stack_list_agents', {});
    expect(result.isError).toBe(true);
    expect(text).toBe('API error: 502');
  });
});
