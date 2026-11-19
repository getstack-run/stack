import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  generateWebhookSecret,
  signStandardWebhook,
  verifyStandardWebhook,
} from '../../shared/src/utils/standard-webhooks.js';
import { createReplayGuard, verifyWebhook, webhookSecretKey } from './webhook.js';

// The shared signer is the one STACK itself signs with. It is imported by path
// here only, to prove the SDK's own copy interoperates; the published SDK does
// not depend on @stack/shared.

const SECRET = `whsec_${Buffer.alloc(32, 7).toString('base64')}`;
const OTHER = `whsec_${Buffer.alloc(32, 9).toString('base64')}`;
/** A secret from before the signed scheme: 64 hexadecimal characters. */
const LEGACY = Buffer.alloc(32, 0x5c).toString('hex');
const NOW = 1_800_000_000;
const BODY = JSON.stringify({ id: 'msg_1', event_type: 'test', severity: 'info', payload: {}, timestamp: '2026-10-24T00:00:00.000Z' });

const signed = (over: { secrets?: string[]; id?: string; timestamp?: number; body?: string } = {}) => ({
  headers: signStandardWebhook({ id: over.id ?? 'msg_1', body: over.body ?? BODY, secrets: over.secrets ?? [SECRET], timestamp: over.timestamp ?? NOW }),
  body: over.body ?? BODY,
});

describe('verifyWebhook', () => {
  it('accepts a message signed the way STACK signs every webhook, and reads it', () => {
    const { headers, body } = signed();
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW })).toEqual({
      ok: true,
      id: 'msg_1',
      timestamp: NOW,
      payload: JSON.parse(BODY),
    });
  });

  it('takes node-style headers with any casing, a Headers object and a byte body', () => {
    const { headers, body } = signed();
    const nodeStyle = { 'Webhook-Id': headers['webhook-id'], 'WEBHOOK-TIMESTAMP': headers['webhook-timestamp'], 'webhook-signature': [headers['webhook-signature']] };
    expect(verifyWebhook({ headers: nodeStyle, body, secret: SECRET, now: NOW }).ok).toBe(true);
    expect(verifyWebhook({ headers: new Headers(headers), body: Buffer.from(body), secret: SECRET, now: NOW }).ok).toBe(true);
  });

  it('refuses a captured request replayed after the tolerance, in either direction', () => {
    const { headers, body } = signed();
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW + 300 }).ok).toBe(true);
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW + 301 })).toEqual({ ok: false, reason: 'stale' });
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW - 301 })).toEqual({ ok: false, reason: 'stale' });
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW + 3_600, toleranceSeconds: 7_200 }).ok).toBe(true);
  });

  it('refuses a tampered body, a changed id or timestamp, a wrong secret and a missing or malformed header', () => {
    const { headers, body } = signed();
    const check = (over: Record<string, unknown> = {}) => verifyWebhook({ headers, body, secret: SECRET, now: NOW, ...over } as never);
    expect(check({ body: body.replace('test', 'tesu') })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(check({ headers: { ...headers, 'webhook-id': 'msg_2' } })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(check({ headers: { ...headers, 'webhook-timestamp': String(NOW + 1) } })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(check({ secret: OTHER })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(check({ headers: {} })).toEqual({ ok: false, reason: 'missing_headers' });
    expect(check({ headers: { ...headers, 'webhook-timestamp': 'soon' } })).toEqual({ ok: false, reason: 'bad_timestamp' });
    expect(check({ headers: { ...headers, 'webhook-signature': 'v1,!!!' } })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(check({ headers: { ...headers, 'webhook-signature': 'v2,abc' } })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('accepts either secret during a rotation, and a signature list holding an unknown version', () => {
    const { headers, body } = signed({ secrets: [SECRET, OTHER] });
    expect(headers['webhook-signature'].split(' ')).toHaveLength(2);
    for (const secret of [SECRET, OTHER]) expect(verifyWebhook({ headers, body, secret, now: NOW }).ok).toBe(true);
    expect(verifyWebhook({ headers, body, secret: [OTHER, generateWebhookSecret()], now: NOW }).ok).toBe(true);
    const odd = { ...headers, 'webhook-signature': `v2,${Buffer.alloc(32).toString('base64')} ${headers['webhook-signature']}` };
    expect(verifyWebhook({ headers: odd, body, secret: SECRET, now: NOW }).ok).toBe(true);
  });

  it('reads a body that is not a JSON object as bad_body, after the signature', () => {
    for (const text of ['not json', '[1,2]', '"x"', 'null']) {
      const { headers, body } = signed({ body: text });
      expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW })).toEqual({ ok: false, reason: 'bad_body' });
    }
  });

  it('throws on a malformed secret or none, which is configuration and never a verdict on a request', () => {
    const { headers, body } = signed();
    expect(() => verifyWebhook({ headers, body, secret: [], now: NOW })).toThrow(/secret/);
    expect(() => verifyWebhook({ headers, body, secret: 'short', now: NOW })).toThrow(/16 bytes/);
    expect(() => verifyWebhook({ headers, body, secret: 'whsec_AAAA', now: NOW })).toThrow(/16 bytes/);
  });

  it('verifies with the secret a destination held before the scheme, as every Standard Webhooks library reads it', () => {
    const { headers, body } = signed({ secrets: [LEGACY] });
    expect(verifyWebhook({ headers, body, secret: LEGACY, now: NOW }).ok).toBe(true);
    // The key is the string read as base64, which is what the published libraries compute from the same text.
    const expected = createHmac('sha256', Buffer.from(LEGACY, 'base64')).update(`msg_1.${NOW}.${body}`).digest('base64');
    expect(headers['webhook-signature']).toBe(`v1,${expected}`);
    // A value its owner chose, not base64: the key is its UTF-8 bytes.
    const chosen = 'a chosen secret, 30+ bytes long!';
    expect(webhookSecretKey(chosen)).toEqual(Buffer.from(chosen, 'utf8'));
    const again = signed({ secrets: [chosen] });
    expect(verifyWebhook({ headers: again.headers, body: again.body, secret: chosen, now: NOW }).ok).toBe(true);
    expect(verifyStandardWebhook({ headers: again.headers, body: again.body, secrets: [chosen], toleranceSeconds: 300, now: NOW }).ok).toBe(true);
  });

  it('keeps the ids it has been given and refuses a repeat inside the window, only for a genuine message', () => {
    const replayGuard = createReplayGuard();
    const { headers, body } = signed();
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW, replayGuard }).ok).toBe(true);
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW + 5, replayGuard })).toEqual({ ok: false, reason: 'replayed' });
    // A forged message with the same id does not take the id's place.
    const fresh = createReplayGuard();
    expect(verifyWebhook({ headers: { ...headers, 'webhook-signature': 'v1,AAAA' }, body, secret: SECRET, now: NOW, replayGuard: fresh }).ok).toBe(false);
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW, replayGuard: fresh }).ok).toBe(true);
    // After a failed delivery the id is given back, so STACK's retry is handled.
    fresh.forget('msg_1');
    expect(verifyWebhook({ headers, body, secret: SECRET, now: NOW + 1, replayGuard: fresh }).ok).toBe(true);
  });

  it('forgets an id once its window has passed and bounds what it remembers', () => {
    const guard = createReplayGuard({ ttlSeconds: 10, maxEntries: 2 });
    expect(guard.firstSeen('a', 0)).toBe(true);
    expect(guard.firstSeen('a', 5_000)).toBe(false);
    expect(guard.firstSeen('a', 10_001)).toBe(true);
    expect(guard.firstSeen('b', 10_002)).toBe(true);
    expect(guard.firstSeen('c', 10_003)).toBe(true);
    // 'a' was the oldest and made room.
    expect(guard.firstSeen('a', 10_004)).toBe(true);
  });
});
