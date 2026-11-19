import { describe, expect, it } from 'vitest';
import {
  generateWebhookSecret,
  signStandardWebhook,
  verifyStandardWebhook,
} from '../../shared/src/utils/standard-webhooks.js';
import {
  signControlSocketAnswer,
  verifyControlSocketRequest,
  type ControlDecisionRequest,
} from './control-socket-server.js';

// The shared signer is the one STACK itself signs and verifies with. It is
// imported by path here only, to prove the SDK's own copy interoperates; the
// published SDK does not depend on @stack/shared.

const SECRET = `whsec_${Buffer.alloc(32, 7).toString('base64')}`;
const OTHER_SECRET = `whsec_${Buffer.alloc(32, 9).toString('base64')}`;
const NOW = 1_800_000_000;

const REQUEST: ControlDecisionRequest = {
  type: 'stack.decision.request',
  version: '1',
  decision_id: 'dec_abcdefghijklmnop',
  created_at: '2026-10-21T10:00:00.000Z',
  deadline_at: '2026-10-21T10:00:01.500Z',
  test: false,
  operator_id: 'op_1',
  socket_id: 'csk_1',
  account: { id: 'acct_1' },
  agent: { id: 'agt_1', passport_jti: null, mission_id: 'ms_1' },
  actor: { kind: 'agent' },
  action: { type: 'email.send' },
  target: { recipient_domain: 'example.com' },
  amount: null,
  purpose: { agent_stated: null },
  retry_ref: null,
  request_digest: `sha256:${'a'.repeat(64)}`,
};

function signedRequest(overrides: { secrets?: string[]; id?: string; timestamp?: number; body?: string } = {}) {
  const body = overrides.body ?? JSON.stringify(REQUEST);
  const headers = signStandardWebhook({
    id: overrides.id ?? REQUEST.decision_id,
    body,
    secrets: overrides.secrets ?? [SECRET],
    timestamp: overrides.timestamp ?? NOW,
  });
  return { headers, body };
}

describe('verifyControlSocketRequest', () => {
  it('accepts a request signed the way STACK signs it, and reads it', () => {
    const { headers, body } = signedRequest();
    const result = verifyControlSocketRequest({ headers, body, secret: SECRET, now: NOW });
    expect(result).toEqual({ ok: true, request: REQUEST });
  });

  it('takes node-style headers with any casing, and a Headers object', () => {
    const { headers, body } = signedRequest();
    const upper = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toUpperCase(), value]));
    expect(verifyControlSocketRequest({ headers: upper, body, secret: SECRET, now: NOW }).ok).toBe(true);
    expect(verifyControlSocketRequest({ headers: new Headers(headers), body, secret: SECRET, now: NOW }).ok).toBe(true);
  });

  it('reads a body given as bytes', () => {
    const { headers, body } = signedRequest();
    expect(verifyControlSocketRequest({ headers, body: Buffer.from(body), secret: SECRET, now: NOW }).ok).toBe(true);
  });

  it('accepts either secret while a rotation is live, and refuses a stranger', () => {
    const rotated = signedRequest({ secrets: [OTHER_SECRET, SECRET] });
    expect(verifyControlSocketRequest({ ...rotated, secret: SECRET, now: NOW }).ok).toBe(true);
    expect(verifyControlSocketRequest({ ...rotated, secret: [OTHER_SECRET], now: NOW }).ok).toBe(true);
    const stranger = signedRequest({ secrets: [OTHER_SECRET] });
    expect(verifyControlSocketRequest({ ...stranger, secret: SECRET, now: NOW })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('refuses a body changed after signing', () => {
    const { headers, body } = signedRequest();
    const tampered = body.replace('email.send', 'wallet.payment');
    expect(verifyControlSocketRequest({ headers, body: tampered, secret: SECRET, now: NOW })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('refuses a stale or future timestamp, and honours a wider tolerance', () => {
    const { headers, body } = signedRequest();
    expect(verifyControlSocketRequest({ headers, body, secret: SECRET, now: NOW + 301 })).toEqual({ ok: false, reason: 'stale' });
    expect(verifyControlSocketRequest({ headers, body, secret: SECRET, now: NOW - 301 })).toEqual({ ok: false, reason: 'stale' });
    expect(verifyControlSocketRequest({ headers, body, secret: SECRET, now: NOW + 301, toleranceSeconds: 600 }).ok).toBe(true);
  });

  it('refuses missing headers and a malformed timestamp or signature without throwing', () => {
    const { headers, body } = signedRequest();
    expect(verifyControlSocketRequest({ headers: {}, body, secret: SECRET, now: NOW })).toEqual({ ok: false, reason: 'missing_headers' });
    expect(
      verifyControlSocketRequest({ headers: { ...headers, 'webhook-timestamp': 'soon' }, body, secret: SECRET, now: NOW }),
    ).toEqual({ ok: false, reason: 'bad_timestamp' });
    expect(
      verifyControlSocketRequest({ headers: { ...headers, 'webhook-signature': 'v1,!!!' }, body, secret: SECRET, now: NOW }),
    ).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('refuses a signed body that is not a decision request, or whose id differs from the message id', () => {
    const notJson = signedRequest({ body: 'not json' });
    expect(verifyControlSocketRequest({ ...notJson, secret: SECRET, now: NOW })).toEqual({ ok: false, reason: 'bad_body' });
    const wrongShape = signedRequest({ body: JSON.stringify({ hello: 'world' }) });
    expect(verifyControlSocketRequest({ ...wrongShape, secret: SECRET, now: NOW })).toEqual({ ok: false, reason: 'bad_body' });
    const wrongId = signedRequest({ id: 'dec_zzzzzzzzzzzzzzzz' });
    expect(verifyControlSocketRequest({ ...wrongId, secret: SECRET, now: NOW })).toEqual({ ok: false, reason: 'id_mismatch' });
  });

  it('throws on a malformed secret, which is configuration, not input', () => {
    const { headers, body } = signedRequest();
    expect(() => verifyControlSocketRequest({ headers, body, secret: 'not-a-secret', now: NOW })).toThrow(/whsec_/);
    expect(() => verifyControlSocketRequest({ headers, body, secret: [], now: NOW })).toThrow(/secret/);
  });
});

describe('signControlSocketAnswer', () => {
  it('signs an answer STACK verifies, with the decision id as the message id', () => {
    const signed = signControlSocketAnswer({
      decisionId: REQUEST.decision_id,
      requestDigest: REQUEST.request_digest,
      verdict: 'deny',
      reason: { code: 'over_budget', message: 'Over the weekly limit' },
      policyRef: 'rule-12',
      secrets: [SECRET],
      timestamp: NOW,
    });
    expect(signed.headers['webhook-id']).toBe(REQUEST.decision_id);
    expect(JSON.parse(signed.body)).toEqual({
      decision_id: REQUEST.decision_id,
      request_digest: REQUEST.request_digest,
      verdict: 'deny',
      reason: { code: 'over_budget', message: 'Over the weekly limit' },
      policy_ref: 'rule-12',
    });
    const verified = verifyStandardWebhook({ headers: signed.headers, body: signed.body, secrets: [SECRET], toleranceSeconds: 300, now: NOW });
    expect(verified).toEqual({ ok: true, id: REQUEST.decision_id, timestamp: NOW });
  });

  it('carries a pending approval as retry, and omits fields not given', () => {
    const signed = signControlSocketAnswer({
      decisionId: REQUEST.decision_id,
      requestDigest: REQUEST.request_digest,
      verdict: 'deny',
      retry: { ref: 'apr_1', after_seconds: 30 },
      secrets: SECRET,
    });
    expect(JSON.parse(signed.body)).toEqual({
      decision_id: REQUEST.decision_id,
      request_digest: REQUEST.request_digest,
      verdict: 'deny',
      retry: { ref: 'apr_1', after_seconds: 30 },
    });
  });

  it('signs with every secret while a rotation is live', () => {
    const signed = signControlSocketAnswer({
      decisionId: REQUEST.decision_id,
      requestDigest: REQUEST.request_digest,
      verdict: 'allow',
      secrets: [SECRET, OTHER_SECRET],
      timestamp: NOW,
    });
    expect(signed.headers['webhook-signature'].split(' ')).toHaveLength(2);
    for (const secret of [SECRET, OTHER_SECRET]) {
      const verified = verifyStandardWebhook({ headers: signed.headers, body: signed.body, secrets: [secret], toleranceSeconds: 300, now: NOW });
      expect(verified.ok).toBe(true);
    }
  });

  it('refuses a reason STACK would drop, and signing with no secret', () => {
    const base = { decisionId: REQUEST.decision_id, requestDigest: REQUEST.request_digest, verdict: 'deny' as const, secrets: [SECRET] };
    expect(() => signControlSocketAnswer({ ...base, reason: { code: 'Over Budget' } })).toThrow(/reason code/);
    expect(() => signControlSocketAnswer({ ...base, reason: { code: 'over_budget', message: 'x'.repeat(201) } })).toThrow(/reason message/);
    expect(() => signControlSocketAnswer({ ...base, secrets: [] })).toThrow(/secret/);
  });
});

describe('interoperating with the shared signer', () => {
  it('verifies what the shared signer signs, with a freshly generated secret', () => {
    const secret = generateWebhookSecret();
    const body = JSON.stringify(REQUEST);
    const headers = signStandardWebhook({ id: REQUEST.decision_id, body, secrets: [secret] });
    expect(verifyControlSocketRequest({ headers, body, secret }).ok).toBe(true);
  });

  it('signs what the shared verifier accepts, with a freshly generated secret', () => {
    const secret = generateWebhookSecret();
    const signed = signControlSocketAnswer({
      decisionId: REQUEST.decision_id,
      requestDigest: REQUEST.request_digest,
      verdict: 'allow',
      secrets: [secret],
    });
    expect(verifyStandardWebhook({ headers: signed.headers, body: signed.body, secrets: [secret], toleranceSeconds: 300 }).ok).toBe(true);
  });
});
