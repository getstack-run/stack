// How a signing secret reaches the person when the caller must not hold it.
//
// A chat assistant works with an OAuth token, and whatever a tool returns goes
// into the model's context. So a secret created or rotated through one is never
// in the answer: the call returns a link to the Console instead, and the person
// reads the secret there, once, signed in. The link carries a random token in its
// fragment (a fragment is never sent to a server or written to a log). Only the
// token's hash is held, in Redis, bound to the customer and the address, for an
// hour; reading it consumes it.

import { createHash, randomBytes } from 'node:crypto';
import type { ControlSecretReveal, ControlSocketTarget } from '@stack/shared';

/** How long the link works. */
export const SECRET_REVEAL_TTL_SECONDS = 60 * 60;

const KEY_PREFIX = 'stack:control-secret-reveal:';

export interface SecretRevealRedis {
  set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown>;
  getdel(key: string): Promise<string | null>;
}

export interface SecretRevealDeps {
  redis: SecretRevealRedis;
  /** The Console's origin, as `DASHBOARD_URL`. */
  dashboardUrl: string;
  now?: () => number;
}

const keyOf = (token: string): string => `${KEY_PREFIX}${createHash('sha256').update(token).digest('hex')}`;

export class ControlSecretRevealStore {
  private readonly now: () => number;

  constructor(private readonly deps: SecretRevealDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  /** A single-use link to read the current secret of one address. */
  async issue(operatorId: string, target: ControlSocketTarget): Promise<ControlSecretReveal> {
    const token = randomBytes(32).toString('base64url');
    await this.deps.redis.set(keyOf(token), JSON.stringify({ operator_id: operatorId, target }), 'EX', SECRET_REVEAL_TTL_SECONDS);
    return {
      url: `${this.deps.dashboardUrl.replace(/\/+$/, '')}/app/control-secret#${token}`,
      expires_at: new Date(this.now() + SECRET_REVEAL_TTL_SECONDS * 1000).toISOString(),
    };
  }

  /**
   * Spend a token. Null when it is unknown, used, expired or belongs to another
   * customer; a token presented by the wrong customer is gone either way.
   */
  async redeem(operatorId: string, token: string): Promise<{ target: ControlSocketTarget } | null> {
    const raw = await this.deps.redis.getdel(keyOf(token));
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as { operator_id?: unknown; target?: unknown };
      if (parsed.operator_id !== operatorId) return null;
      if (parsed.target !== 'decision' && parsed.target !== 'events') return null;
      return { target: parsed.target };
    } catch {
      return null;
    }
  }
}
