import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NotificationService, type NotificationSendMeter } from './notification-service.js';

vi.mock('@stack/shared', async (importActual) => ({
  ...await importActual<typeof import('@stack/shared')>(),
  publicFetch: (input: string, init: RequestInit) => globalThis.fetch(input, init),
}));

/**
 * SMS and email cost real money per send, and until 2026-07-26 nothing counted
 * them: `smsPerMonth` was declared in the tier limits and read by no code. Because
 * every audit write fans out to this dispatcher, send volume tracks audit
 * volume, so an uncapped SMS lane was the largest uncontrolled spend in the
 * system.
 *
 * These tests pin the gate: every path that hands a message to a vendor asks
 * the meter first, and a refusal means the vendor is never called. The
 * verification-code paths matter as much as the dispatcher — they bypass
 * publishEvent entirely, and an unauthenticated stream of verification
 * requests could otherwise burn the Twilio balance.
 */

function makeMeter(verdict: { allowed: boolean; reason?: string }) {
  const calls: Array<{ operatorId: string; channelType: string }> = [];
  const meter: NotificationSendMeter = {
    authorizeSend: vi.fn(async (operatorId: string, channelType: string) => {
      calls.push({ operatorId, channelType });
      return verdict;
    }),
  };
  return { meter, calls };
}

function makeTwilio() {
  return { sendSms: vi.fn(async () => {}) };
}

function makeEmail() {
  return {
    sendEmail: vi.fn(async (
      _to: string,
      _subject: string,
      _text: string,
      _html?: string,
      _options?: { skipSignature?: boolean },
    ) => {}),
  };
}

const CHANNEL = {
  id: 'nch_1',
  operator_id: 'op_1',
  active: true,
  verified: true,
  events: ['security.event'],
  min_severity: 'info',
  destination_ids: null,
  destination_id: null,
  channel_type: 'sms',
  destination: '+46701740606',
  webhook_secret_encrypted: null,
};

const EVENT = {
  operatorId: 'op_1',
  eventType: 'security.event',
  severity: 'critical' as const,
  payload: {},
};

function makeService(twilio: ReturnType<typeof makeTwilio>) {
  const channelRepo = {
    findByOperator: vi.fn(async () => [{ ...CHANNEL }]),
    findById: vi.fn(async () => ({ ...CHANNEL })),
  };
  const db = {} as never;
  return {
    channelRepo,
    svc: new NotificationService(db, channelRepo as never, twilio as never),
  };
}

describe('NotificationService — send allowance gate', () => {
  beforeEach(() => vi.clearAllMocks());

  it('sends when the meter allows it', async () => {
    const twilio = makeTwilio();
    const { svc } = makeService(twilio);
    const { meter, calls } = makeMeter({ allowed: true });
    svc.setSendMeter(meter);

    const result = await svc.publishEvent(EVENT);

    expect(twilio.sendSms).toHaveBeenCalledTimes(1);
    expect(calls).toEqual([{ operatorId: 'op_1', channelType: 'sms' }]);
    expect(result.dispatched).toBe(1);
  });

  it('hands the meter the text and where it goes, so it is priced by its segments at the destination', async () => {
    const twilio = makeTwilio();
    const { svc } = makeService(twilio);
    const { meter } = makeMeter({ allowed: true });
    svc.setSendMeter(meter);

    await svc.publishEvent(EVENT);

    const sent = (twilio.sendSms.mock.calls[0] as unknown as [string, string]);
    expect(meter.authorizeSend).toHaveBeenCalledWith('op_1', 'sms', { to: '+46701740606', body: sent[1] });
  });

  it('does not call the vendor when the allowance is spent and the wallet is empty', async () => {
    const twilio = makeTwilio();
    const { svc } = makeService(twilio);
    const { meter } = makeMeter({ allowed: false, reason: 'over allowance, no balance' });
    svc.setSendMeter(meter);

    const result = await svc.publishEvent(EVENT);

    // The whole point: refused means not sent, not "sent and billed later".
    expect(twilio.sendSms).not.toHaveBeenCalled();
    // And it is not counted as dispatched: a caller that falls back to e-mail when nothing was sent must see 0.
    expect(result.dispatched).toBe(0);
  });

  it('gates the verification-code path, which bypasses the dispatcher entirely', async () => {
    const twilio = makeTwilio();
    const channelRepo = {
      findByOperator: vi.fn(async () => []),
      // A code is only ever sent to a channel that is not yet verified.
      findById: vi.fn(async () => ({ ...CHANNEL, operator_id: 'op_1', verified: false })),
    };
    const insert = vi.fn(() => ({
      values: vi.fn(() => ({ onConflictDoUpdate: vi.fn(async () => {}) })),
    }));
    const svc = new NotificationService({ insert } as never, channelRepo as never, twilio as never);
    const { meter, calls } = makeMeter({ allowed: false, reason: 'over allowance' });
    svc.setSendMeter(meter);

    const result = await svc.sendVerificationCode('nch_1', 'op_1');

    expect(calls).toEqual([{ operatorId: 'op_1', channelType: 'sms' }]);
    expect(twilio.sendSms).not.toHaveBeenCalled();
    expect(result.sent).toBe(false);
  });

  it('asks the meter once per send, so a fan-out to N destinations is counted N times', async () => {
    const twilio = makeTwilio();
    const channelRepo = {
      findByOperator: vi.fn(async () => [
        { ...CHANNEL, destination_ids: ['nd_1', 'nd_2', 'nd_3'] },
      ]),
    };
    const destinationRepo = {
      findById: vi.fn(async (id: string) => ({
        id,
        operator_id: 'op_1',
        verified: true,
        channel_type: 'sms',
        destination: '+46701740605',
        webhook_secret_encrypted: null,
      })),
    };
    const svc = new NotificationService({} as never, channelRepo as never, twilio as never);
    svc.setDestinationRepo(destinationRepo as never);
    const { meter, calls } = makeMeter({ allowed: true });
    svc.setSendMeter(meter);

    await svc.publishEvent(EVENT);

    expect(calls).toHaveLength(3);
    expect(twilio.sendSms).toHaveBeenCalledTimes(3);
  });

  it('sends normally when no meter is wired, so dev and test are not silently muted', async () => {
    const twilio = makeTwilio();
    const { svc } = makeService(twilio);

    await svc.publishEvent(EVENT);

    expect(twilio.sendSms).toHaveBeenCalledTimes(1);
  });

  it('gates email as well as SMS', async () => {
    const twilio = makeTwilio();
    const email = makeEmail();
    const channelRepo = {
      findByOperator: vi.fn(async () => [{ ...CHANNEL, channel_type: 'email', destination: 'a@b.c' }]),
    };
    const svc = new NotificationService({} as never, channelRepo as never, twilio as never);
    svc.setEmailService(email as never);
    const { meter, calls } = makeMeter({ allowed: false });
    svc.setSendMeter(meter);

    await svc.publishEvent(EVENT);

    expect(calls).toEqual([{ operatorId: 'op_1', channelType: 'email' }]);
    expect(email.sendEmail).not.toHaveBeenCalled();
  });

  it('fails verification safely when SMS has no provider', async () => {
    const channelRepo = {
      findByOperator: vi.fn(async () => []),
      findById: vi.fn(async () => ({ ...CHANNEL, operator_id: 'op_1', verified: false })),
    };
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const svc = new NotificationService({} as never, channelRepo as never, null);

    await expect(svc.sendVerificationCode('nch_1', 'op_1')).rejects.toMatchObject({
      code: 'SERVICE_UNAVAILABLE',
      statusCode: 503,
    });
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it('fails destination verification safely when email has no provider', async () => {
    const channelRepo = {
      findByOperator: vi.fn(async () => []),
      findById: vi.fn(async () => null),
    };
    const destinationRepo = {
      findById: vi.fn(async () => ({
        ...CHANNEL,
        operator_id: 'op_1',
        verified: false,
        channel_type: 'email',
        destination: 'owner@example.invalid',
      })),
    };
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const svc = new NotificationService({} as never, channelRepo as never, null);
    svc.setDestinationRepo(destinationRepo as never);

    await expect(svc.sendDestinationVerificationCode('nd_1', 'op_1')).rejects.toMatchObject({
      code: 'SERVICE_UNAVAILABLE',
      statusCode: 503,
    });
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it('does not count or print an email event when its provider is absent', async () => {
    const channelRepo = {
      findByOperator: vi.fn(async () => [{
        ...CHANNEL,
        channel_type: 'email',
        destination: 'owner@example.invalid',
      }]),
    };
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const svc = new NotificationService({} as never, channelRepo as never, null);

    const result = await svc.publishEvent(EVENT);

    expect(result.dispatched).toBe(0);
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  });
});

describe('NotificationService — secret storage', () => {
  beforeEach(() => vi.clearAllMocks());

  it('encrypts webhook secrets with operator and resource-bound context', async () => {
    const encryptDirect = vi.fn(async () => Buffer.from('encrypted-secret'));
    const svc = new NotificationService({} as never, {} as never, null);
    svc.setSecretCrypto({ encryptDirect, decryptDirect: vi.fn() } as never);

    const result = await svc.createWebhookSecret(
      'op_1',
      'ndst_1',
      'notification_destination_webhook_secret',
    );

    expect(result.secret).toMatch(/^whsec_/);
    expect(result.encrypted).toBe(Buffer.from('encrypted-secret').toString('base64'));
    expect(encryptDirect).toHaveBeenCalledWith(Buffer.from(result.secret, 'utf8'), {
      operatorId: 'op_1',
      context: {
        operator_id: 'op_1',
        notification_resource_id: 'ndst_1',
        purpose: 'notification_destination_webhook_secret',
      },
    });
  });

  it('stores only a salted verification-code hash and still verifies the delivered code', async () => {
    let storedVerification: Record<string, unknown> | undefined;
    const updateReturning = vi.fn(async () => [{
      code_hash: storedVerification?.['code_hash'] ?? null,
    }]);
    const updateWhere = vi.fn(() => ({ returning: updateReturning }));
    const deleteWhere = vi.fn(async () => []);
    const db = {
      insert: vi.fn(() => ({
        values: vi.fn((values: Record<string, unknown>) => {
          storedVerification = values;
          return { onConflictDoUpdate: vi.fn(async () => []) };
        }),
      })),
      update: vi.fn(() => ({ set: vi.fn(() => ({ where: updateWhere })) })),
      delete: vi.fn(() => ({ where: deleteWhere })),
      query: {
        notificationChannelVerifications: {
          findFirst: vi.fn(async () => storedVerification),
        },
      },
    };
    const destination = {
      id: 'ndst_1',
      operator_id: 'op_1',
      channel_type: 'email',
      destination: 'owner@example.invalid',
      verified: false,
      webhook_secret_encrypted: null,
    };
    const destinationRepo = {
      findById: vi.fn(async () => destination),
      update: vi.fn(async () => ({ ...destination, verified: true })),
    };
    const email = makeEmail();
    const svc = new NotificationService(db as never, {} as never, null);
    svc.setDestinationRepo(destinationRepo as never);
    svc.setEmailService(email as never);

    await svc.sendDestinationVerificationCode('ndst_1', 'op_1');

    expect(storedVerification).not.toHaveProperty('code');
    expect(storedVerification?.['code_hash']).toMatch(/^s1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$/);
    const deliveredText = String(email.sendEmail.mock.calls[0]?.[2] ?? '');
    const deliveredCode = deliveredText.match(/\b\d{6}\b/)?.[0];
    expect(deliveredCode).toBeDefined();

    const result = await svc.verifyDestinationCode('ndst_1', 'op_1', deliveredCode!);

    expect(result).toEqual({ verified: true });
    expect(destinationRepo.update).toHaveBeenCalledWith('ndst_1', { verified: true });
  });

  it('decrypts an encrypted webhook secret only at dispatch time', async () => {
    const secret = 'c0ffee'.repeat(10) + 'abcd';
    const decryptDirect = vi.fn(async () => Buffer.from(secret));
    const channelRepo = {
      findByOperator: vi.fn(async () => [{
        ...CHANNEL,
        channel_type: 'webhook',
        destination: 'https://hooks.example.test/stack',
        webhook_secret_encrypted: Buffer.from('ciphertext').toString('base64'),
      }]),
    };
    const svc = new NotificationService({} as never, channelRepo as never, null);
    svc.setSecretCrypto({ encryptDirect: vi.fn(), decryptDirect } as never);
    svc.setUrlGuard(vi.fn(async () => new URL('https://hooks.example.test/stack')) as never);
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    await svc.publishEvent(EVENT);

    expect(decryptDirect).toHaveBeenCalledWith(Buffer.from('ciphertext'), {
      operatorId: 'op_1',
      expectedContext: {
        operator_id: 'op_1',
        notification_resource_id: 'nch_1',
        purpose: 'notification_channel_webhook_secret',
      },
    });
    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Record<string, string>;
    expect(headers['webhook-signature']).toMatch(/^v1,/);
    expect(headers['X-Stack-Signature']).toBeUndefined();
    vi.unstubAllGlobals();
  });
});
