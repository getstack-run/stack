import { PARTNER_MAIL_RATE_PER_HOUR } from '../constants/index.js';
import { RateLimitedError } from '../errors/index.js';

/** The slice of a Redis client the limit needs. */
export interface PartnerMailRedis {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
}

/**
 * Every invitation and every release mails a stranger on STACK's behalf, with the partner's address in it. A partner
 * may start only so many in an hour, the two together, so a stolen partner key cannot be used to send STACK-branded
 * mail to anyone in bulk. Throws `RATE_LIMITED` past the limit (the count includes the refused attempt, so
 * hammering does not shorten the wait).
 */
export async function takePartnerMailSlot(redis: PartnerMailRedis, partnerId: string): Promise<void> {
  const key = `partner-mail:rate:${partnerId}`;
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, 3600);
  if (count > PARTNER_MAIL_RATE_PER_HOUR) {
    throw new RateLimitedError('Too many releases and invitations this hour. Try again later.', {
      limit: PARTNER_MAIL_RATE_PER_HOUR,
      window_seconds: 3600,
    });
  }
}
