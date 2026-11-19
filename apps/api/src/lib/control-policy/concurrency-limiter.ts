// How many actions one agent has running at the same moment, for a policy's
// concurrency limit.
//
// One sorted set per (customer, agent): the members are lease ids and the score
// of each is the moment its lease runs out. An action takes a lease before it
// starts and returns it when it ends; a machine that dies mid-action never
// returns its lease, so every lease expires on its own and a crash can never
// hold a slot forever. Acquire is one script: it drops the expired leases,
// refuses when `limit` leases are live and otherwise adds this one, so parallel
// acquires cannot pass the limit.
//
// The script reads the time from Redis, so machines whose clocks differ agree
// on when a lease ends. A caller may pass its own clock (tests do).

import { randomBytes } from 'node:crypto';
import { CONTROL_CONCURRENCY_LEASE_SECONDS } from '@stack/shared';
import type { RedisClient } from '../../config/wiring/infra.js';

/** Time in milliseconds: the caller's when given, else Redis's own. */
const NOW_LUA = `
local now = tonumber(ARGV[1])
if not now then
  local t = redis.call('TIME')
  now = t[1] * 1000 + math.floor(t[2] / 1000)
end
`;

const ACQUIRE_LUA = `${NOW_LUA}
local limit = tonumber(ARGV[2])
local leaseMs = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= limit then return 0 end
redis.call('ZADD', KEYS[1], now + leaseMs, ARGV[4])
-- The key outlives its longest lease by a margin, and never shrinks while a longer lease is live.
local wanted = leaseMs + tonumber(ARGV[5])
if redis.call('PTTL', KEYS[1]) < wanted then redis.call('PEXPIRE', KEYS[1], wanted) end
return 1
`;

const LIVE_LUA = `${NOW_LUA}
return redis.call('ZCOUNT', KEYS[1], '(' .. now, '+inf')
`;

/** How long a key lingers after its last lease would have ended. */
const KEY_TTL_MARGIN_MS = 60_000;
const MAX_LEASE_SECONDS = 24 * 60 * 60;

export interface ConcurrencyLimiterOptions {
  /** Milliseconds since the epoch. Absent: Redis's own clock. */
  now?: () => number;
}

export interface ConcurrencyScope {
  operatorId: string;
  agentId: string;
}

export class ConcurrencyLimiter {
  private readonly now: (() => number) | undefined;

  constructor(
    private readonly redis: RedisClient,
    options: ConcurrencyLimiterOptions = {},
  ) {
    this.now = options.now;
  }

  private key(scope: ConcurrencyScope): string {
    return `stack:control:concurrency:${scope.operatorId}:${scope.agentId}`;
  }

  private clock(): string {
    return this.now ? String(this.now()) : '';
  }

  /** Take a lease, or null when `limit` actions of this agent are already running. */
  async acquire(
    input: ConcurrencyScope & { limit: number; leaseSeconds?: number },
  ): Promise<{ leaseId: string } | null> {
    const leaseSeconds = input.leaseSeconds ?? CONTROL_CONCURRENCY_LEASE_SECONDS;
    if (!Number.isSafeInteger(input.limit) || input.limit <= 0) {
      throw new Error(`A concurrency limit must be a positive whole number, got ${input.limit}`);
    }
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds <= 0 || leaseSeconds > MAX_LEASE_SECONDS) {
      throw new Error(`A lease must last a whole number of seconds up to ${MAX_LEASE_SECONDS}, got ${leaseSeconds}`);
    }
    const leaseId = randomBytes(16).toString('hex');
    const taken = Number(
      await this.redis.eval(
        ACQUIRE_LUA,
        1,
        this.key(input),
        this.clock(),
        input.limit,
        leaseSeconds * 1000,
        leaseId,
        KEY_TTL_MARGIN_MS,
      ),
    );
    return taken === 1 ? { leaseId } : null;
  }

  /** Give a lease back. A lease that is unknown or already expired is a no-op. */
  async release(input: ConcurrencyScope & { leaseId: string }): Promise<void> {
    await this.redis.zrem(this.key(input), input.leaseId);
  }

  /** How many leases are live, read only. */
  async live(input: ConcurrencyScope): Promise<number> {
    return Number(await this.redis.eval(LIVE_LUA, 1, this.key(input), this.clock()));
  }
}
