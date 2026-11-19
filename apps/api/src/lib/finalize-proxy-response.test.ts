import { describe, expect, it, vi } from 'vitest';
import { finalizeProxyResponse } from './finalize-proxy-response.js';

const ctx = {
  operatorId: 'op_1',
  agentId: 'agt_1',
  passportJti: 'jti_1',
  mode: 'standard' as const,
  tier: 'studio' as const,
};

describe('finalizeProxyResponse', () => {
  it('removes the injected credential from bodies and headers in every mode', async () => {
    const secret = `sk_test_${'a'.repeat(24)}`;
    const detector = { scanOutput: vi.fn().mockResolvedValue({ match: null, redactedBody: null }) };
    const result = await finalizeProxyResponse({
      detector: detector as never,
      detectorContext: ctx,
      response: {
        status: 200,
        headers: { 'x-request-id': `prefix-${secret}`, 'content-type': 'application/json' },
        body: { nested: { value: `echo:${secret}` } },
      },
      rawCredential: JSON.stringify({ secret_key: secret }),
      service: 'stripe',
      method: 'POST',
    });
    expect(JSON.stringify(result.response)).not.toContain(secret);
    expect(result.response.headers).toEqual({ 'content-type': 'application/json' });
    expect(result.response.body).toEqual({ nested: { value: 'echo:[REDACTED BY STACK]' } });
  });

  it('drops a detector-matched header before the permitted response is retained', async () => {
    const detector = {
      scanOutput: vi.fn().mockResolvedValue({
        match: { pattern_id: 'leak', severity: 'critical', matched_text: 'secret', field_path: 'headers.x-request-id' },
        redactedBody: null,
      }),
    };
    const result = await finalizeProxyResponse({
      detector: detector as never,
      detectorContext: ctx,
      response: { status: 200, headers: { 'x-request-id': 'secret', etag: 'safe' }, body: 'ok' },
      rawCredential: 'not-a-match',
      service: 'stripe',
      method: 'POST',
    });
    expect(result.response.headers).toEqual({ etag: 'safe' });
  });

  it('scrubs short configured secrets instead of relying on a length heuristic', async () => {
    const detector = { scanOutput: vi.fn().mockResolvedValue({ match: null, redactedBody: null }) };
    const result = await finalizeProxyResponse({
      detector: detector as never,
      detectorContext: ctx,
      response: { status: 200, headers: {}, body: { echoed: 'value=abc123' } },
      rawCredential: JSON.stringify({ secret_key: 'abc123' }),
      service: 'stripe',
      method: 'POST',
    });
    expect(result.response.body).toEqual({ echoed: 'value=[REDACTED BY STACK]' });
  });

  it('scrubs a credential echoed as a JSON object key', async () => {
    const secret = `sk_test_${'k'.repeat(24)}`;
    const detector = { scanOutput: vi.fn().mockResolvedValue({ match: null, redactedBody: null }) };
    const result = await finalizeProxyResponse({
      detector: detector as never,
      detectorContext: ctx,
      response: { status: 200, headers: {}, body: { [secret]: 'echoed in a key' } },
      rawCredential: JSON.stringify({ secret_key: secret }),
      service: 'stripe',
      method: 'POST',
    });
    expect(JSON.stringify(result.response.body)).not.toContain(secret);
    expect(result.response.body).toEqual({ '[REDACTED BY STACK]': 'echoed in a key' });
  });

  it('scrubs the exact injected Basic authorization value in every mode', async () => {
    const accountSid = 'AC123456789';
    const authToken = 'twilio-secret';
    const injected = `Basic ${Buffer.from(`${accountSid}:${authToken}`).toString('base64')}`;
    const detector = { scanOutput: vi.fn().mockResolvedValue({ match: null, redactedBody: null }) };
    const result = await finalizeProxyResponse({
      detector: detector as never,
      detectorContext: { ...ctx, mode: 'logged' },
      response: { status: 200, headers: {}, body: { echoed: injected } },
      rawCredential: JSON.stringify({ account_sid: accountSid, auth_token: authToken }),
      injectedAuthHeaders: { Authorization: injected },
      service: 'twilio',
      method: 'POST',
    });
    expect(JSON.stringify(result.response.body)).not.toContain(injected);
    expect(result.response.body).toEqual({ echoed: '[REDACTED BY STACK]' });
  });

  it('uses the detector redaction body when policy requires it', async () => {
    const detector = {
      scanOutput: vi.fn().mockResolvedValue({
        match: { pattern_id: 'leak', severity: 'critical', matched_text: 'secret', field_path: 'body' },
        redactedBody: { redacted: true },
      }),
    };
    const result = await finalizeProxyResponse({
      detector: detector as never,
      detectorContext: { ...ctx, mode: 'enforced' },
      response: { status: 200, headers: {}, body: 'secret' },
      rawCredential: 'unrelated-secret',
      service: 'stripe',
      method: 'POST',
    });
    expect(result.response.body).toEqual({ redacted: true });
  });
});
