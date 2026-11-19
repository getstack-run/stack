import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { UnsafeUrlError, generateWebhookSecret, signStandardWebhook, verifyStandardWebhook } from '@stack/shared';
import { NotificationService } from './notification-service.js';

vi.mock('@stack/shared', async (importActual) => ({
  ...await importActual<typeof import('@stack/shared')>(),
  publicFetch: (input: string, init: RequestInit) => globalThis.fetch(input, init),
}));

/**
 * Shift 3 - complete mediation.
 *
 * This dispatcher posts security events to an operator-supplied URL from
 * inside our network, and it did so with no URL guard at all. The destination
 * was checked nowhere on the send path, so a nominated URL pointing at
 * localhost, a link-local address or the cloud metadata endpoint was simply
 * fetched. The content it carries is exactly what an attacker would want
 * redirected inward: STACK's own incident stream.
 *
 * Two properties are pinned here:
 *   1. A refused destination means fetch is never reached. Not "fetched and
 *      then flagged" - the request must not happen.
 *   2. The verification challenge that proves control of a webhook goes
 *      through the same guard, because that path also POSTs to a URL the
 *      caller chose.
 */

const CHANNEL = {
  id: 'nch_1',
  active: true,
  verified: true,
  events: ['security.event'],
  min_severity: 'info',
  destination_ids: ['ndst_1'],
  destination_id: null,
  channel_type: 'webhook',
  destination: 'https://hooks.example.com/stack',
  webhook_secret_encrypted: Buffer.from('ciphertext').toString('base64'),
};

const EVENT = {
  operatorId: 'op_1',
  eventType: 'security.event',
  severity: 'critical' as const,
  payload: { detail: 'a credential left its service' },
};

/** A secret as destinations carried them before the signed scheme: 64 hexadecimal characters. */
const LEGACY_SECRET = 'c0ffee'.repeat(10) + 'abcd';

/** Decrypts every stored secret to the same signing key. */
function secretCrypto(plaintext: string = LEGACY_SECRET) {
  return { encryptDirect: vi.fn(), decryptDirect: vi.fn(async () => Buffer.from(plaintext)) } as never;
}

function makeService(destination: string, destinationOperatorId = 'op_1') {
  const channelRepo = {
    findByOperator: vi.fn(async () => [{ ...CHANNEL }]),
    findById: vi.fn(async () => ({ ...CHANNEL })),
  };
  const destinationRepo = {
    findById: vi.fn(async () => ({
      id: 'ndst_1',
      operator_id: destinationOperatorId,
      channel_type: 'webhook',
      destination,
      webhook_secret_encrypted: Buffer.from('ciphertext').toString('base64'),
      verified: true,
    })),
    update: vi.fn(async () => {}),
  };
  const svc = new NotificationService({} as never, channelRepo as never, null);
  svc.setDestinationRepo(destinationRepo as never);
  svc.setSecretCrypto(secretCrypto());
  return { svc, destinationRepo };
}

/** Stands in for assertPublicUrl without touching DNS. */
const guard = async (raw: string, options: { allowedProtocols?: string[] } = {}) => {
  const url = new URL(raw);
  const allowed = options.allowedProtocols ?? ['https:', 'http:'];
  if (!allowed.includes(url.protocol)) {
    throw new UnsafeUrlError(`Protocol ${url.protocol} not allowed`);
  }
  if (['localhost', '169.254.169.254', '10.0.0.5'].includes(url.hostname)) {
    throw new UnsafeUrlError(`Host ${url.hostname} is not allowed`);
  }
  return url;
};

describe('NotificationService - webhook destination guard', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    fetchSpy = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('never fetches a loopback destination', async () => {
    const { svc } = makeService('https://localhost/collect');
    svc.setUrlGuard(guard as never);

    await svc.publishEvent(EVENT);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('never fetches the cloud metadata address', async () => {
    const { svc } = makeService('https://169.254.169.254/latest/meta-data/');
    svc.setUrlGuard(guard as never);

    await svc.publishEvent(EVENT);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('never fetches an RFC 1918 address', async () => {
    const { svc } = makeService('https://10.0.0.5/collect');
    svc.setUrlGuard(guard as never);

    await svc.publishEvent(EVENT);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('refuses a plaintext destination - incident detail does not travel unencrypted', async () => {
    const { svc } = makeService('http://hooks.example.com/stack');
    svc.setUrlGuard(guard as never);

    await svc.publishEvent(EVENT);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('delivers to a public https destination, signed', async () => {
    const { svc } = makeService('https://hooks.example.com/stack');
    svc.setUrlGuard(guard as never);

    await svc.publishEvent(EVENT);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://hooks.example.com/stack');
    expect(init.redirect).toBe('manual');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect((init.headers as Record<string, string>)['webhook-signature']).toMatch(/^v1,/);
  });

  it('never dispatches through another operator\'s destination row', async () => {
    const { svc } = makeService('https://hooks.example.com/stack', 'op_other');
    svc.setUrlGuard(guard as never);

    await svc.publishEvent(EVENT);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('records a fixed rejection category without the destination or event payload', async () => {
    const errorSpy = vi.spyOn(console, 'error');
    const { svc } = makeService('https://169.254.169.254/latest/meta-data/');
    svc.setUrlGuard(guard as never);

    await svc.publishEvent(EVENT);

    const lines = errorSpy.mock.calls.map((c) => c.map(String).join(' '));
    const refusal = lines.find((l) => l.includes('destination refused'));
    expect(refusal).toBeDefined();
    expect(refusal).toContain('unsafe_url');
    expect(refusal).not.toContain('169.254.169.254');
    expect(refusal).not.toContain('a credential left its service');
  });
});

describe('NotificationService - webhook verification challenge', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  function makeDb() {
    return {
      insert: () => ({
        values: () => ({ onConflictDoUpdate: async () => {} }),
      }),
    } as never;
  }

  function makeVerifyService(destination: string) {
    const channelRepo = { findByOperator: vi.fn(async () => []), findById: vi.fn(async () => null) };
    const destinationRepo = {
      findById: vi.fn(async () => ({
        id: 'ndst_1',
        operator_id: 'op_1',
        channel_type: 'webhook',
        destination,
        webhook_secret_encrypted: Buffer.from('ciphertext').toString('base64'),
        verified: false,
      })),
      update: vi.fn(async () => {}),
    };
    const svc = new NotificationService(makeDb(), channelRepo as never, null);
    svc.setDestinationRepo(destinationRepo as never);
    svc.setSecretCrypto(secretCrypto());
    svc.setUrlGuard(guard as never);
    return svc;
  }

  beforeEach(() => {
    vi.clearAllMocks();
    fetchSpy = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('posts the code to the nominated endpoint, signed', async () => {
    const svc = makeVerifyService('https://hooks.example.com/stack');

    const res = await svc.sendDestinationVerificationCode('ndst_1', 'op_1');

    expect(res.sent).toBe(true);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://hooks.example.com/stack');
    expect(init.redirect).toBe('manual');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(body.event_type).toBe('stack.destination.verification');
    expect(String(body.verification_code)).toMatch(/^\d{6}$/);
    const headers = init.headers as Record<string, string>;
    expect(headers['webhook-id']).toBe(body.id);
    expect(verifyStandardWebhook({ headers, body: String(init.body), secrets: [LEGACY_SECRET], toleranceSeconds: 300 }).ok).toBe(true);
  });

  it('refuses to send a challenge to a private address', async () => {
    const svc = makeVerifyService('https://10.0.0.5/collect');

    await expect(svc.sendDestinationVerificationCode('ndst_1', 'op_1')).rejects.toThrow(
      /destination refused/i,
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('NotificationService - Standard Webhooks signing', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  const NOW = 1_790_000_000_000;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    fetchSpy = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  /** A destination with the current secret, and optionally a rotation `rotatedAgoMs` ago that left a previous one. */
  function serviceFor(secrets: { current: string; previous?: string; rotatedAgoMs?: number }) {
    const decrypt = vi.fn(async (ciphertext: Buffer) => Buffer.from(ciphertext.toString() === 'current' ? secrets.current : secrets.previous ?? ''));
    const destinationRepo = {
      findById: vi.fn(async () => ({
        id: 'ndst_1',
        operator_id: 'op_1',
        channel_type: 'webhook',
        destination: 'https://hooks.example.com/stack',
        webhook_secret_encrypted: Buffer.from('current').toString('base64'),
        webhook_secret_previous_encrypted: secrets.previous ? Buffer.from('previous').toString('base64') : null,
        webhook_secret_rotated_at: secrets.rotatedAgoMs === undefined ? null : new Date(NOW - secrets.rotatedAgoMs),
        verified: true,
      })),
    };
    const svc = new NotificationService({} as never, { findByOperator: vi.fn(async () => [{ ...CHANNEL }]) } as never, null);
    svc.setDestinationRepo(destinationRepo as never);
    svc.setSecretCrypto({ encryptDirect: vi.fn(), decryptDirect: decrypt } as never);
    svc.setUrlGuard(guard as never);
    return svc;
  }

  const sent = () => {
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    return { headers: init.headers as Record<string, string>, body: String(init.body) };
  };

  it('carries webhook-id, webhook-timestamp and webhook-signature, and no other signature header', async () => {
    const secret = generateWebhookSecret();
    await serviceFor({ current: secret }).publishEvent(EVENT);

    const { headers, body } = sent();
    expect(headers['webhook-id']).toMatch(/^msg_/);
    expect(JSON.parse(body).id).toBe(headers['webhook-id']);
    expect(verifyStandardWebhook({ headers, body, secrets: [secret], toleranceSeconds: 300, now: NOW / 1000 })).toMatchObject({ ok: true, id: headers['webhook-id'] });
    expect(Object.keys(headers).filter((name) => /signature/i.test(name))).toEqual(['webhook-signature']);
  });

  it('is verifiable with the secret a destination already holds (hexadecimal, from before the scheme)', async () => {
    await serviceFor({ current: LEGACY_SECRET }).publishEvent(EVENT);
    const { headers, body } = sent();
    expect(verifyStandardWebhook({ headers, body, secrets: [LEGACY_SECRET], toleranceSeconds: 300, now: NOW / 1000 }).ok).toBe(true);
  });

  it('refuses a captured delivery replayed after the tolerance, and a body changed in transit', async () => {
    const secret = generateWebhookSecret();
    await serviceFor({ current: secret }).publishEvent(EVENT);
    const { headers, body } = sent();
    const check = (over: Partial<Parameters<typeof verifyStandardWebhook>[0]> = {}) =>
      verifyStandardWebhook({ headers, body, secrets: [secret], toleranceSeconds: 300, now: NOW / 1000, ...over });
    expect(check()).toMatchObject({ ok: true });
    expect(check({ now: NOW / 1000 + 301 })).toEqual({ ok: false, reason: 'stale' });
    expect(check({ body: body.replace('critical', 'info') })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('signs with both secrets for 24 hours after a rotation, and with the new one only after that', async () => {
    const current = generateWebhookSecret();
    const previous = generateWebhookSecret();
    await serviceFor({ current, previous, rotatedAgoMs: 23 * 3_600_000 }).publishEvent(EVENT);
    const during = sent();
    expect(during.headers['webhook-signature']!.split(' ')).toHaveLength(2);
    for (const secret of [current, previous]) {
      expect(verifyStandardWebhook({ headers: during.headers, body: during.body, secrets: [secret], toleranceSeconds: 300, now: NOW / 1000 }).ok).toBe(true);
    }

    fetchSpy.mockClear();
    await serviceFor({ current, previous, rotatedAgoMs: 25 * 3_600_000 }).publishEvent(EVENT);
    const after = sent();
    expect(after.headers['webhook-signature']!.split(' ')).toHaveLength(1);
    expect(verifyStandardWebhook({ headers: after.headers, body: after.body, secrets: [previous], toleranceSeconds: 300, now: NOW / 1000 }).ok).toBe(false);
    expect(verifyStandardWebhook({ headers: after.headers, body: after.body, secrets: [current], toleranceSeconds: 300, now: NOW / 1000 }).ok).toBe(true);
  });

  it('is interoperable with a message signed by the shared helper (one scheme, one implementation)', () => {
    const secret = generateWebhookSecret();
    const headers = signStandardWebhook({ id: 'msg_x', body: '{}', secrets: [secret], timestamp: NOW / 1000 });
    expect(verifyStandardWebhook({ headers, body: '{}', secrets: [secret], toleranceSeconds: 300, now: NOW / 1000 }).ok).toBe(true);
  });
});
