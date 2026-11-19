import { beforeEach, describe, expect, it, vi } from 'vitest';

const sentry = vi.hoisted(() => ({ captureMessage: vi.fn() }));
vi.mock('@sentry/node', () => ({ captureMessage: sentry.captureMessage }));

import { MemoryObjectStore, ObjectStoreUnavailableError } from '@stack/vault';
import { maybeRunArchiveStoreProbe } from './archive-store-probe.js';

function makeRedis(lockHeld = false) {
  const values = new Map<string, string>();
  return {
    values,
    set: vi.fn(async (key: string, value: string, ...args: unknown[]) => {
      if (args.includes('NX') && (lockHeld || values.has(key))) return null;
      values.set(key, value);
      return 'OK';
    }),
  };
}

beforeEach(() => {
  sentry.captureMessage.mockClear();
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
});

describe('maybeRunArchiveStoreProbe', () => {
  it('records a healthy store for the admin room and stays quiet in Sentry', async () => {
    const redis = makeRedis();
    const result = await maybeRunArchiveStoreProbe({ archiveStore: new MemoryObjectStore(), redis: redis as never, sentryDsn: 'https://dsn.invalid/1' });
    expect(result).toMatchObject({ ok: true, site: 'worker' });
    expect(JSON.parse(redis.values.get('archive_store_status:worker')!)).toMatchObject({ ok: true });
    expect(sentry.captureMessage).not.toHaveBeenCalled();
  });

  it('reports an unusable store to the admin room and to Sentry, with the fixed reason only', async () => {
    const redis = makeRedis();
    const store = new MemoryObjectStore();
    store.check = async () => {
      throw new ObjectStoreUnavailableError('check', 'access_denied', new Error('arn:aws:s3:::secret-bucket'));
    };
    const result = await maybeRunArchiveStoreProbe({ archiveStore: store, redis: redis as never, sentryDsn: 'https://dsn.invalid/1' });
    expect(result).toMatchObject({ ok: false, reason: 'access_denied' });
    expect(sentry.captureMessage).toHaveBeenCalledTimes(1);
    const [message, context] = sentry.captureMessage.mock.calls[0]!;
    expect(JSON.stringify([message, context])).not.toContain('secret-bucket');
    expect(context).toMatchObject({ level: 'error', tags: { kind: 'archive_store_unreachable', reason: 'access_denied' } });
  });

  it('runs once per window: a second machine skips while the lock is held', async () => {
    const redis = makeRedis(true);
    const store = new MemoryObjectStore();
    const check = vi.spyOn(store, 'check');
    await expect(maybeRunArchiveStoreProbe({ archiveStore: store, redis: redis as never })).resolves.toBeNull();
    expect(check).not.toHaveBeenCalled();
  });

  it('never throws when Redis cannot take the lock', async () => {
    const redis = { set: vi.fn(async () => { throw new Error('redis down'); }) };
    await expect(maybeRunArchiveStoreProbe({ archiveStore: new MemoryObjectStore(), redis: redis as never })).resolves.toBeNull();
  });
});
