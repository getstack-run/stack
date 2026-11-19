import { randomUUID } from 'node:crypto';
import { isRedisOutageError } from './transient-db-error.js';

/** Long enough that one UTC day's key outlives the day, short enough that tomorrow's key is a fresh one. */
export const DAILY_LOCK_TTL_SECONDS = 26 * 3600;

/** The part of the Redis client a lock needs. */
export interface LockRedis {
  set(key: string, value: string, mode: 'EX', seconds: number, flag: 'NX'): Promise<unknown>;
  get(key: string): Promise<string | null>;
}

/**
 * Take a date-keyed daily lock (`SET key value EX ttl NX`, never released): true
 * when this call holds it, false when another run does. The value is the time
 * and a token only this call knows (`<ISO time>#<token>`; a reader that shows
 * the time reads the part before `#`).
 *
 * A Redis command can fail after the server ran it: the reply is late, the
 * client's command timeout fires, and the caller sees an outage error for a
 * `SET` that took the key. Treating that as "not taken" would skip the day's
 * job (the next tick finds the key held, and tomorrow is a new key). So when
 * the `SET` fails as an outage the key is read once: if it holds this call's
 * token, this call holds the lock. If the read fails too, or the key holds
 * something else or nothing, the original error is thrown and the tick retries.
 *
 * When the read fails too (the same silent socket) the value is remembered for
 * this key, and the next call reads the key first: if it holds the remembered
 * value, the earlier `SET` had landed and this process holds the day. Without
 * that, the retry's own `SET` would find the key held by this process's own lost
 * attempt and skip the day.
 */
const unconfirmed = new Map<string, string>();

/** For tests: what this process remembers of attempts whose outcome it could not read. */
export function forgetUnconfirmedDailyLocks(): void {
  unconfirmed.clear();
}

/** For tests: how many attempts are remembered. */
export function unconfirmedDailyLockCount(): number {
  return unconfirmed.size;
}

export async function takeDailyLock(redis: LockRedis, key: string): Promise<boolean> {
  // A day that has passed has nothing left to confirm: its key is gone, and nothing will ask for it again.
  const today = new Date().toISOString().slice(0, 10);
  for (const remembered of [...unconfirmed.keys()]) {
    const day = /\d{4}-\d{2}-\d{2}/.exec(remembered)?.[0];
    if (day && day < today) unconfirmed.delete(remembered);
  }
  const earlier = unconfirmed.get(key);
  if (earlier !== undefined) {
    // A failed read here is an outage like any other: the tick retries and the memory stays.
    const held = await redis.get(key);
    unconfirmed.delete(key);
    if (held === earlier) return true;
    if (held !== null) return false;
  }
  const token = randomUUID();
  const value = `${new Date().toISOString()}#${token}`;
  try {
    return (await redis.set(key, value, 'EX', DAILY_LOCK_TTL_SECONDS, 'NX')) === 'OK';
  } catch (err) {
    if (!isRedisOutageError(err)) throw err;
    let held: string | null;
    try {
      held = await redis.get(key);
    } catch {
      unconfirmed.set(key, value);
      throw err;
    }
    if (held === value) return true;
    // Another run holds the day: this one has nothing to do.
    if (held !== null) return false;
    throw err;
  }
}
