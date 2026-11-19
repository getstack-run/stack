import { createServer, type Socket } from 'node:net';
import { Redis } from 'ioredis';
import { describe, expect, it, vi } from 'vitest';
import { ServiceUnavailableError } from '@stack/shared';
import { isRevoked } from './context.js';
import type { PassportContext } from './types.js';

function redisDown() {
  const error = new Error('Reached the max retries per request limit (which is 2).');
  error.name = 'MaxRetriesPerRequestError';
  return error;
}

function contextWith(redisGet: () => Promise<string | null>, dbRevoked = false) {
  const isRevokedInDb = vi.fn(async () => dbRevoked);
  const ctx = {
    redis: { get: vi.fn(redisGet) },
    passportRepo: { isRevoked: isRevokedInDb },
  } as unknown as PassportContext;
  return { ctx, isRevokedInDb };
}

describe('isRevoked', () => {
  it('answers from the Redis flag without reading the database', async () => {
    const { ctx, isRevokedInDb } = contextWith(async () => '1');
    await expect(isRevoked(ctx, 'jti_a')).resolves.toBe(true);
    expect(isRevokedInDb).not.toHaveBeenCalled();
  });

  it('falls back to the database when there is no flag', async () => {
    const { ctx, isRevokedInDb } = contextWith(async () => null, true);
    await expect(isRevoked(ctx, 'jti_a')).resolves.toBe(true);
    expect(isRevokedInDb).toHaveBeenCalledWith('jti_a');
  });

  it('fails closed and retriable when Redis is unreachable, never as an unhandled error', async () => {
    const { ctx, isRevokedInDb } = contextWith(async () => {
      throw redisDown();
    });
    const outcome = await isRevoked(ctx, 'jti_a').catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
    expect((outcome as ServiceUnavailableError).statusCode).toBe(503);
    // An unreadable flag is not "not revoked": nothing is answered from the database either.
    expect(isRevokedInDb).not.toHaveBeenCalled();
  });

  it('does not hide a Redis reply error behind a 503', async () => {
    const { ctx } = contextWith(async () => {
      throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value');
    });
    await expect(isRevoked(ctx, 'jti_a')).rejects.toThrow('WRONGTYPE');
  });

  it('answers 503 and consults no database when a real Redis client accepts the socket and never answers', async () => {
    // A Redis that accepts the socket and never answers. The client is configured as the API's is (`commandTimeout`), so its own timeout error, not a hand-made one, reaches isRevoked.
    const sockets = new Set<Socket>();
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address() as { port: number };
    const redis = new Redis(`redis://127.0.0.1:${address.port}`, { maxRetriesPerRequest: 2, commandTimeout: 500 });
    redis.on('error', () => {});
    try {
      const isRevokedInDb = vi.fn(async () => false);
      const ctx = { redis, passportRepo: { isRevoked: isRevokedInDb } } as unknown as PassportContext;
      const outcome = await isRevoked(ctx, 'jti_silent').catch((error: unknown) => error);
      expect(outcome).toBeInstanceOf(ServiceUnavailableError);
      expect((outcome as ServiceUnavailableError).statusCode).toBe(503);
      expect(isRevokedInDb).not.toHaveBeenCalled();
    } finally {
      redis.disconnect();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 15_000);
});
