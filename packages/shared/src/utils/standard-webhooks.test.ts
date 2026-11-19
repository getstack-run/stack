import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  generateWebhookSecret,
  signStandardWebhook,
  verifyStandardWebhook,
  WEBHOOK_ID_HEADER,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_TIMESTAMP_HEADER,
} from './standard-webhooks.js';

const SECRET = `whsec_${Buffer.from('0123456789abcdef0123456789abcdef').toString('base64')}`;
const OTHER = `whsec_${Buffer.from('fedcba9876543210fedcba9876543210').toString('base64')}`;

describe('Standard Webhooks signing', () => {
  it('signs id.timestamp.body with HMAC-SHA256 under the secret bytes', () => {
    const headers = signStandardWebhook({ id: 'msg_1', body: '{"a":1}', secrets: [SECRET], timestamp: 1_700_000_000 });
    const expected = createHmac('sha256', Buffer.from('0123456789abcdef0123456789abcdef'))
      .update('msg_1.1700000000.{"a":1}')
      .digest('base64');
    expect(headers[WEBHOOK_ID_HEADER]).toBe('msg_1');
    expect(headers[WEBHOOK_TIMESTAMP_HEADER]).toBe('1700000000');
    expect(headers[WEBHOOK_SIGNATURE_HEADER]).toBe(`v1,${expected}`);
  });

  it('verifies what it signed, and refuses a changed body, id, timestamp or secret', () => {
    const headers = signStandardWebhook({ id: 'msg_1', body: 'hello', secrets: [SECRET], timestamp: 1_700_000_000 });
    const verify = (over: Partial<Parameters<typeof verifyStandardWebhook>[0]> = {}) =>
      verifyStandardWebhook({ headers, body: 'hello', secrets: [SECRET], toleranceSeconds: 300, now: 1_700_000_100, ...over });
    expect(verify()).toEqual({ ok: true, id: 'msg_1', timestamp: 1_700_000_000 });
    expect(verify({ body: 'hellp' })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(verify({ secrets: [OTHER] })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(verify({ headers: { ...headers, [WEBHOOK_ID_HEADER]: 'msg_2' } })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(verify({ headers: { ...headers, [WEBHOOK_TIMESTAMP_HEADER]: '1700000001' } })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('refuses a timestamp outside the tolerance in either direction, and a malformed or missing header', () => {
    const headers = signStandardWebhook({ id: 'm', body: 'x', secrets: [SECRET], timestamp: 1_700_000_000 });
    const at = (now: number) => verifyStandardWebhook({ headers, body: 'x', secrets: [SECRET], toleranceSeconds: 300, now });
    expect(at(1_700_000_300).ok).toBe(true);
    expect(at(1_700_000_301)).toEqual({ ok: false, reason: 'stale' });
    expect(at(1_699_999_699)).toEqual({ ok: false, reason: 'stale' });
    expect(verifyStandardWebhook({ headers: {}, body: 'x', secrets: [SECRET], toleranceSeconds: 300 })).toEqual({ ok: false, reason: 'missing_headers' });
    expect(verifyStandardWebhook({
      headers: { ...headers, [WEBHOOK_TIMESTAMP_HEADER]: 'soon' }, body: 'x', secrets: [SECRET], toleranceSeconds: 300,
    })).toEqual({ ok: false, reason: 'bad_timestamp' });
    expect(verifyStandardWebhook({
      headers: { ...headers, [WEBHOOK_SIGNATURE_HEADER]: 'v2,abc' }, body: 'x', secrets: [SECRET], toleranceSeconds: 300, now: 1_700_000_000,
    })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('signs with both secrets during a rotation, and a receiver holding either accepts it', () => {
    const headers = signStandardWebhook({ id: 'm', body: 'x', secrets: [SECRET, OTHER], timestamp: 1_700_000_000 });
    expect(headers[WEBHOOK_SIGNATURE_HEADER].split(' ')).toHaveLength(2);
    for (const secret of [SECRET, OTHER]) {
      expect(verifyStandardWebhook({ headers, body: 'x', secrets: [secret], toleranceSeconds: 300, now: 1_700_000_000 }).ok).toBe(true);
    }
  });

  it('reads headers from a Headers object and any header case', () => {
    const signed = signStandardWebhook({ id: 'm', body: 'x', secrets: [SECRET], timestamp: 1_700_000_000 });
    const headers = new Headers(signed);
    expect(verifyStandardWebhook({ headers, body: 'x', secrets: [SECRET], toleranceSeconds: 300, now: 1_700_000_000 }).ok).toBe(true);
    const upper = Object.fromEntries(Object.entries(signed).map(([k, v]) => [k.toUpperCase(), v]));
    expect(verifyStandardWebhook({ headers: upper, body: 'x', secrets: [SECRET], toleranceSeconds: 300, now: 1_700_000_000 }).ok).toBe(true);
  });

  it('generates a secret of 32 random bytes in the whsec_ form, and refuses a malformed one', () => {
    const secret = generateWebhookSecret();
    expect(secret).toMatch(/^whsec_[A-Za-z0-9+/]{43}=$/);
    expect(generateWebhookSecret()).not.toBe(secret);
    expect(() => signStandardWebhook({ id: 'm', body: 'x', secrets: ['not-a-secret'] })).toThrow();
    expect(() => signStandardWebhook({ id: 'm', body: 'x', secrets: [] })).toThrow();
  });
});
