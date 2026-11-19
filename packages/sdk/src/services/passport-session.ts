// PassportSession helper.
//
// Wraps a passport token + its expiry timestamp. Auto-refreshes via
// /v1/passports/refresh when the next call would land within the
// configured grace window of expiry. Lets operators write LLM-call
// loops without manual passport bookkeeping:
//
//   const session = await stack.issuePassport({ agent_id, mission_ids: [missionId] });
//   for (let i = 0; i < 1000; i++) {
//     await stack.llm.anthropic.messages.create(body, { passport: session });
//     // session auto-refreshes transparently when its current token
//     // is within 60s of expiry.
//   }
//
// Provider calls accept either a raw string token OR a PassportSession;
// the raw-string path stays available for callers who own their own
// passport lifecycle.

import type { HttpClient } from '../client.js';
import type { IssuedPassport, IssuePassportInput } from '../types.js';
import { MissionNotLiveError, StackError } from '../errors.js';

/**
 * Map an API refusal caused by the passport's Mission (403 "Mission ms_x
 * is completed|revoked|has expired", 404 "Mission ms_x not found", 403
 * "...exactly one Mission") to a MissionNotLiveError. Anything else → null.
 */
export function missionRefusal(err: unknown): MissionNotLiveError | null {
  if (!(err instanceof StackError) || (err.status !== 403 && err.status !== 404)) return null;
  const m = /Mission (ms_[\w-]+) (?:is (completed|revoked)|has (expired)|(not found))/.exec(err.message);
  if (m) {
    const state = m[2] === 'completed' ? 'completed'
      : m[2] === 'revoked' ? 'revoked'
        : m[3] ? 'expired' : 'not_found';
    return new MissionNotLiveError(m[1]!, state, err);
  }
  if (/exactly one Mission/.test(err.message)) return new MissionNotLiveError(null, 'unbound', err);
  return null;
}

export class PassportSession {
  private currentToken: string;
  private expSeconds: number;

  constructor(
    private readonly client: HttpClient,
    issued: IssuedPassport,
    private readonly issueInput: IssuePassportInput,
  ) {
    this.currentToken = issued.token;
    this.expSeconds = decodeJwtExp(issued.token);
  }

  /**
   * Return the current token, auto-refreshing if within `graceSeconds`
   * of expiry. Default grace: 60 seconds (long enough for a slow
   * upstream LLM call to complete on the refreshed token).
   */
  async getToken(graceSeconds = 60): Promise<string> {
    const nowSec = Math.floor(Date.now() / 1000);
    if (this.expSeconds - nowSec > graceSeconds) {
      return this.currentToken;
    }
    // Refresh. Errors propagate — the caller's LLM call would have
    // failed anyway with an expired token; failing here at least
    // surfaces "expired + couldn't refresh" rather than a confusing
    // 401 from the gateway. A refusal because the Mission ended becomes
    // a MissionNotLiveError: retrying cannot succeed.
    let refreshed: IssuedPassport;
    try {
      refreshed = await this.client.post<IssuedPassport>(
        '/v1/passports/refresh',
        {
          token: this.currentToken,
          ttl_seconds: this.issueInput.ttl_seconds,
        },
      );
    } catch (err) {
      throw missionRefusal(err) ?? err;
    }
    this.currentToken = refreshed.token;
    this.expSeconds = decodeJwtExp(refreshed.token);
    return this.currentToken;
  }

  /** Current token without triggering a refresh. */
  get token(): string {
    return this.currentToken;
  }

  /** Expiry as a Date. */
  get expiresAt(): Date {
    return new Date(this.expSeconds * 1000);
  }
}

/**
 * Decode the `exp` claim (unix seconds) from a passport JWT without
 * verifying the signature. We're a client of the token — the server
 * already signed it. Only used for refresh-timing math.
 */
function decodeJwtExp(token: string): number {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('PassportSession: token is not a JWT (expected 3 dot-separated segments)');
  }
  const payloadB64 = parts[1]!;
  // base64url → base64
  const normalized = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const decoded = typeof atob === 'function'
    ? atob(padded)
    : Buffer.from(padded, 'base64').toString('utf8');
  const payload = JSON.parse(decoded) as { exp?: number };
  if (typeof payload.exp !== 'number') {
    throw new Error('PassportSession: token payload missing numeric `exp` claim');
  }
  return payload.exp;
}
