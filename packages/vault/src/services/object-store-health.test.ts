import { describe, expect, it, vi } from 'vitest';
import {
  ARCHIVE_STORE_STATUS_TTL_SECONDS,
  archiveStoreStatusKey,
  probeObjectStore,
  readArchiveStoreStatus,
} from './object-store-health.js';
import { MemoryObjectStore, ObjectStoreUnavailableError, type ObjectStore } from './object-store.js';

class FakeRedis {
  readonly values = new Map<string, { value: string; ttl: number }>();
  set = vi.fn(async (key: string, value: string, _ex: 'EX', ttl: number) => {
    this.values.set(key, { value, ttl });
    return 'OK';
  });
  mget = vi.fn(async (...keys: string[]) => keys.map((key) => this.values.get(key)?.value ?? null));
}

function storeThatFails(reason: 'access_denied' | 'bucket_missing' | 'unreachable'): ObjectStore {
  const store = new MemoryObjectStore();
  store.check = async () => {
    throw new ObjectStoreUnavailableError('check', reason, new Error('arn:aws:s3:::secret-bucket denied'));
  };
  return store;
}

const NOW = new Date('2026-10-21T10:00:00.000Z');

describe('probeObjectStore', () => {
  it('records a healthy store with an expiry, so a dead prober shows as unknown', async () => {
    const redis = new FakeRedis();
    const result = await probeObjectStore({ store: new MemoryObjectStore(), redis: redis as never, site: 'worker', now: () => NOW });
    expect(result).toEqual({ ok: true, site: 'worker', checked_at: NOW.toISOString() });
    const written = redis.values.get(archiveStoreStatusKey('worker'))!;
    expect(JSON.parse(written.value)).toEqual(result);
    expect(written.ttl).toBe(ARCHIVE_STORE_STATUS_TTL_SECONDS);
  });

  it('records why a store is not usable, without the provider text, and never throws', async () => {
    const redis = new FakeRedis();
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const result = await probeObjectStore({ store: storeThatFails('access_denied'), redis: redis as never, site: 'api', now: () => NOW });
      expect(result).toEqual({ ok: false, site: 'api', checked_at: NOW.toISOString(), reason: 'access_denied' });
      expect(redis.values.get(archiveStoreStatusKey('api'))!.value).not.toContain('secret-bucket');
    } finally {
      errors.mockRestore();
    }
  });

  it('treats an unexpected failure as unreachable', async () => {
    const store = new MemoryObjectStore();
    store.check = async () => {
      throw new Error('boom');
    };
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const result = await probeObjectStore({ store, redis: new FakeRedis() as never, site: 'worker', now: () => NOW });
      expect(result).toMatchObject({ ok: false, reason: 'unreachable' });
    } finally {
      errors.mockRestore();
    }
  });

  it('still returns the verdict when the status cannot be written', async () => {
    const redis = new FakeRedis();
    redis.set.mockRejectedValue(new Error('redis down'));
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      const result = await probeObjectStore({ store: new MemoryObjectStore(), redis: redis as never, site: 'worker', now: () => NOW });
      expect(result.ok).toBe(true);
    } finally {
      warns.mockRestore();
    }
  });
});

describe('readArchiveStoreStatus', () => {
  it('is unknown before any probe has reported', async () => {
    await expect(readArchiveStoreStatus(new FakeRedis() as never)).resolves.toEqual({ status: 'unknown', checked_at: null, failing: [] });
  });

  it('is ok when every site that reported is healthy', async () => {
    const redis = new FakeRedis();
    await probeObjectStore({ store: new MemoryObjectStore(), redis: redis as never, site: 'worker', now: () => NOW });
    await expect(readArchiveStoreStatus(redis as never)).resolves.toEqual({ status: 'ok', checked_at: NOW.toISOString(), failing: [] });
  });

  it('is failed, naming the site and reason, when any site cannot use the store', async () => {
    const redis = new FakeRedis();
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      await probeObjectStore({ store: new MemoryObjectStore(), redis: redis as never, site: 'worker', now: () => NOW });
      await probeObjectStore({ store: storeThatFails('bucket_missing'), redis: redis as never, site: 'api', now: () => NOW });
    } finally {
      errors.mockRestore();
    }
    await expect(readArchiveStoreStatus(redis as never)).resolves.toEqual({
      status: 'failed',
      checked_at: NOW.toISOString(),
      failing: [{ site: 'api', reason: 'bucket_missing' }],
    });
  });

  it('ignores a stored value it cannot parse instead of reporting a false all-clear', async () => {
    const redis = new FakeRedis();
    redis.values.set(archiveStoreStatusKey('api'), { value: 'not json', ttl: 1 });
    await expect(readArchiveStoreStatus(redis as never)).resolves.toMatchObject({ status: 'unknown' });
  });
});
