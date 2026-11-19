import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { recordUpstreamNotFound } from './upstream-response.js';
import { emitIntentAndOutcomeClaims } from './signed-claims.js';

// What an answered call leaves behind names where the call went, never its query string and never a credential a
// connection put into the path it sent to.

const QUERY_SECRET = ['q', 'secret', 'value', '4471'].join('-');
const CREDENTIAL_IN_PATH = ['bot', '123456789', ':', 'AAHf9xQk2LmZ0pRt7VwYb3Nc8DsE1uGiJ'].join('');

describe('upstream evidence', () => {
  it('a 404 event names the path the agent sent, redacted, not the one with the credential in it', async () => {
    const record = vi.fn(async () => ({}));
    recordUpstreamNotFound(
      { securityEvent: { record } } as never,
      { log: { error: vi.fn() } } as never,
      { input: { service: 'telegram', method: 'GET', url: `https://api.telegram.org/{{bot_token}}/getMe?chat_id=${QUERY_SECRET}` } } as never,
      { claims: { stk: {} }, jti: 'pas_one', agentId: 'agt_one', operatorId: 'op_one' } as never,
      { intentServices: [] } as never,
      { resolvedUrl: `https://api.telegram.org/${CREDENTIAL_IN_PATH}/getMe`, authHeaders: {}, connAllowedHosts: [] } as never,
      { status: 404 } as never,
    );
    await Promise.resolve();
    const written = JSON.stringify(record.mock.calls);
    expect(written).not.toContain(QUERY_SECRET);
    expect(written).not.toContain('AAHf9xQk2LmZ0pRt7VwYb3Nc8DsE1uGiJ');
    expect(written).toContain('api.telegram.org');
  });

  it('the signed claim of a call that went through carries no query string and no interpolated credential', async () => {
    const payloads: Array<Record<string, unknown>> = [];
    await emitIntentAndOutcomeClaims(
      { claimRegistry: { registerClaim: vi.fn(async (call: { payload: Record<string, unknown> }) => { payloads.push(call.payload); return { claimId: 'pc_one' }; }) } } as never,
      { input: { service: 'telegram', method: 'POST', url: `https://api.telegram.org/{{bot_token}}/sendMessage?chat_id=${QUERY_SECRET}`, body: { text: 'hello' } } } as never,
      { jti: 'pas_one', agentId: 'agt_one', operatorId: 'op_one', mode: 'logged', missionRef: 'ms_one' } as never,
      { skipped: true } as never,
      { resolvedUrl: `https://api.telegram.org/${CREDENTIAL_IN_PATH}/sendMessage`, authHeaders: {}, connAllowedHosts: [] } as never,
      { status: 200, body: { ok: true } } as never,
      { redactedBody: null, match: null } as never,
      Date.now(),
    );
    const signed = JSON.stringify(payloads);
    expect(payloads.map((p) => p['type'])).toEqual(['intent_claim', 'intent_outcome']);
    expect(signed).not.toContain(QUERY_SECRET);
    expect(signed).not.toContain('AAHf9xQk2LmZ0pRt7VwYb3Nc8DsE1uGiJ');
    expect(payloads[0]).toMatchObject({ action: 'POST https://api.telegram.org/%7B%7Bbot_token%7D%7D/sendMessage' });
    expect(payloads[1]).toMatchObject({ actual_method_path: 'POST /%7B%7Bbot_token%7D%7D/sendMessage' });
  });

  it('the outcome hashes the same parameters the intent states, so the two agree and a guess at the query cannot be confirmed from the hash', async () => {
    const payloads: Array<Record<string, unknown>> = [];
    const url = `https://api.telegram.org/{{bot_token}}/sendMessage?chat_id=${QUERY_SECRET}`;
    await emitIntentAndOutcomeClaims(
      { claimRegistry: { registerClaim: vi.fn(async (call: { payload: Record<string, unknown> }) => { payloads.push(call.payload); return { claimId: 'pc_one' }; }) } } as never,
      { input: { service: 'telegram', method: 'POST', url, body: { text: 'hello' } } } as never,
      { jti: 'pas_one', agentId: 'agt_one', operatorId: 'op_one', mode: 'logged', missionRef: 'ms_one' } as never,
      { skipped: true } as never,
      { resolvedUrl: 'https://api.telegram.org/x/sendMessage', authHeaders: {}, connAllowedHosts: [] } as never,
      { status: 200, body: { ok: true } } as never,
      { redactedBody: null, match: null } as never,
      Date.now(),
    );
    const sha = (text: string) => createHash('sha256').update(text).digest('hex');
    expect(payloads[1]!['actual_parameters_hash']).toBe(sha(JSON.stringify(payloads[0]!['parameters'])));
    expect(payloads[1]!['actual_parameters_hash']).not.toBe(sha(JSON.stringify({ service: 'telegram', method: 'POST', url, body: { text: 'hello' } })));
  });
});
