// Scope Drift Detector — L3 behavioral signal.
//
// Runs after the hard scope-rule check (credential_outside_scope) has
// already passed. Scores each call's distance from the passport's
// declared intent and accumulates per session. Fires when cumulative
// drift OR single-call novelty crosses threshold — catching the pattern
// BEFORE a hard violation occurs.
//
// Scoring (drift units × 100 to stay in ints via Redis INCRBY):
//   - Service is in intent_services (declared): 0
//   - Service is in granted_providers but NOT declared: +30 (0.30)
//   - First time this passport has hit (service:pathname): +50 (0.50)
// Fire conditions (whichever trips first, once per passport):
//   - Single-call delta ≥ 80 → novelty fire
//   - Cumulative ≥ 200 → drift fire

import type { Redis } from 'ioredis';
import type { SecurityEventService, PassportService } from '@stack/vault';

const CUMULATIVE_THRESHOLD = 200;           // 2.00 drift units
const NOVELTY_THRESHOLD = 80;               // 0.80 single-call
const GRANTED_UNDECLARED_DELTA = 30;        // service granted but not declared
const NOVEL_PATHNAME_DELTA = 50;            // first time on this service+path
const KEY_TTL_SECONDS = 7200;               // 2h — passport max is 1h

export interface ScopeDriftInput {
  jti: string;
  operatorId: string;
  agentId: string;
  service: string;
  intentServices: string[];
  grantedProviders: string[];
  /** Tiered novelty key. proxy: "service:pathname". credentials: "service". */
  noveltyKey: string;
  accountabilityMode?: string;
}

export interface ScopeDriftDeps {
  redis: Redis;
  securityEvent: SecurityEventService;
  /** When supplied, enforced-mode passports are auto-revoked on fire.
   *  Logged/standard modes only record the security event. */
  passport?: PassportService;
}

export async function scoreScopeDrift(
  input: ScopeDriftInput,
  deps: ScopeDriftDeps,
): Promise<void> {
  const { jti, operatorId, agentId, service, intentServices, grantedProviders, noveltyKey, accountabilityMode } = input;
  const { redis, securityEvent, passport } = deps;

  // Two pipelined round trips instead of up to five sequential ones
  // . The reads and writes are the same as before; only the round
  // trips are batched.
  //
  // Round 1: the fire-once-per-passport guard (downstream consumers —
  // notifications, ops dashboards — don't want repeated drift fires for the
  // same session) and novelty via SADD, which returns 1 if newly added.
  const seenKey = `scope_drift_seen:${jti}`;
  const [alreadyFired, newlyRaw] = await execPipeline(
    redis.pipeline().get(`scope_drift_fired:${jti}`).sadd(seenKey, noveltyKey),
  );
  const newly = Number(newlyRaw);
  if (alreadyFired) {
    // Nothing more to score. A set this call just created still gets its TTL.
    if (newly === 1) await redis.expire(seenKey, KEY_TTL_SECONDS);
    return;
  }

  let delta = 0;
  const inIntent = intentServices.includes(service);
  const inGranted = grantedProviders.includes(service);
  if (!inIntent && inGranted) {
    delta += GRANTED_UNDECLARED_DELTA;
  }
  if (newly === 1) {
    delta += NOVEL_PATHNAME_DELTA;
  }

  if (delta === 0) return;

  // Round 2: TTL on a newly added novelty member, then accumulate.
  const round2 = redis.pipeline();
  if (newly === 1) round2.expire(seenKey, KEY_TTL_SECONDS);
  round2.incrby(`scope_drift:${jti}`, delta).expire(`scope_drift:${jti}`, KEY_TTL_SECONDS);
  const results = await execPipeline(round2);
  const cumulative = Number(results[newly === 1 ? 1 : 0]);

  let fireReason: string | null = null;
  if (delta >= NOVELTY_THRESHOLD) {
    fireReason = `Single-call novelty ${(delta / 100).toFixed(2)}`;
  } else if (cumulative >= CUMULATIVE_THRESHOLD) {
    fireReason = `Cumulative drift ${(cumulative / 100).toFixed(2)} crossed threshold`;
  }

  if (fireReason) {
    await redis.set(`scope_drift_fired:${jti}`, '1', 'EX', KEY_TTL_SECONDS);
    await securityEvent.record({
      operatorId,
      agentId,
      passportJti: jti,
      signalType: 'scope_drift',
      severity: accountabilityMode === 'logged' ? 'info' : 'warning',
      message: `Scope drift: ${fireReason}`,
      metadata: {
        service,
        delta_units: delta / 100,
        cumulative_units: cumulative / 100,
        in_intent: inIntent,
        in_granted: inGranted,
        novel_path: newly === 1,
      },
    });

    // Enforced-mode agents are on a short leash — a detector fire is a
    // hard stop. Revoke the passport so the subsequent proxy call is
    // denied at verify() time. Cascade to delegated children happens
    // inside revoke(). Logged and standard modes just emit the event.
    if (accountabilityMode === 'enforced' && passport) {
      try {
        await passport.revoke({ jti, operatorId, reason: `scope_drift_fire: ${fireReason}` });
      } catch {
        // A race (passport already revoked elsewhere) is fine — the
        // security event is what ops dashboards pivot on.
      }
    }
  }
}

/** Run a pipeline and fail exactly as the equivalent sequential calls would. */
async function execPipeline(pipeline: ReturnType<Redis['pipeline']>): Promise<unknown[]> {
  const results = await pipeline.exec();
  if (!results) throw new Error('Redis pipeline was discarded');
  return results.map(([error, value]) => {
    if (error) throw error;
    return value;
  });
}
