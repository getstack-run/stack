/**
 * Cross-Call Drift Detector — L6 of the prompt-injection defense
 * stack.
 *
 * The L1-L5 chain catches injection content. L6 catches what comes
 * AFTER a successful injection: an agent that silently shifted
 * behavior between calls. Per passport, we maintain a running mean
 * + standard deviation for two dimensions:
 *
 *   - body length (L) — bytes of the request body
 *   - Shannon entropy (H) — bits/char, captures format change (e.g.
 *     suddenly returning compressed/base64 data instead of prose)
 *
 * On every call we compute the z-score for the current observation
 * against the rolling stats; if either |z| ≥ Z_THRESHOLD we fire.
 *
 * Cold-start gate: needs ≥ COLD_START_N prior observations before
 * any z-score is trusted. Otherwise the first call always looks like
 * an outlier (mean = its own value, stddev = 0).
 *
 * State lives in Redis under `behavior_drift:<jti>` as a small JSON
 * blob. TTL matches passport-max so state never outlives the
 * passport. INCR-style isn't enough — we need sumsq for variance —
 * so we round-trip a JSON blob with optimistic last-write-wins.
 * Concurrent calls on the same passport will race; this is OK
 * because the worst case is a slightly-stale baseline, never
 * cross-tenant leak.
 *
 * Severity: warning. Single-call statistical outliers are rarely
 * conclusive — we surface the signal but never auto-revoke.
 */

import type { Redis } from 'ioredis';
import type { SecurityEventService } from '@stack/vault';

const Z_THRESHOLD = 3.0;          // 3σ — ~99.7% of normal traffic stays under
const COLD_START_N = 5;           // need at least this many prior calls
const STATE_TTL_SECONDS = 7200;   // 2h — passport max is 1h
const MAX_TRACKED_LENGTH = 1_000_000; // 1MB — caps a pathologically large body
// Zero-variance fallback: when the baseline is byte-identical (common
// for agents looping over a single template), z-scores divide by zero
// and never fire. Fall back to "deviation ≥ 3× mean" so a sudden
// 50KB body in a session of 100-byte heartbeats still trips. The
// 0.01 floor on mean avoids div-by-zero on empty baselines.
const ZERO_VAR_DEVIATION_RATIO = 3.0;

interface DriftState {
  /** Number of observations recorded so far (excluding current). */
  n: number;
  /** Running sum of length values. */
  sum_l: number;
  /** Running sum of squared length values (for variance). */
  sumsq_l: number;
  /** Running sum of entropy values. */
  sum_h: number;
  /** Running sum of squared entropy values. */
  sumsq_h: number;
  /** Last fire jti+seq, to dedupe back-to-back fires on the same outlier. */
  last_fire_n?: number;
}

export interface CrossCallDriftInput {
  jti: string;
  operatorId: string;
  agentId: string;
  /** The current call's request body — same shape as scanForPromptInjection
   * input. Strings used as-is; objects JSON-stringified. null/undefined
   * skipped (no observation recorded). */
  body: unknown;
}

export interface CrossCallDriftDeps {
  redis: Redis;
  securityEvent: SecurityEventService;
}

function stateKey(jti: string): string {
  return `behavior_drift:${jti}`;
}

/** Shannon entropy in bits/char over the printable byte distribution.
 * Bounded [0, 8]. Empty strings return 0. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<number, number>();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  let h = 0;
  const len = s.length;
  for (const c of counts.values()) {
    const p = c / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Compute mean + sample stddev from running sum + sumsq + n. */
function meanStddev(sum: number, sumsq: number, n: number): { mean: number; stddev: number } {
  if (n < 2) return { mean: n === 1 ? sum : 0, stddev: 0 };
  const mean = sum / n;
  // Sample variance with Bessel's correction. Guard against tiny
  // negatives from floating-point cancellation.
  const variance = Math.max(0, (sumsq - n * mean * mean) / (n - 1));
  return { mean, stddev: Math.sqrt(variance) };
}

/**
 * Score the current call against rolling stats and update state.
 *
 * Always best-effort: any error reading/writing Redis or recording
 * the security event is swallowed and logged. The proxy hot path
 * MUST NOT fail because the drift detector failed.
 */
export async function scoreCrossCallDrift(
  input: CrossCallDriftInput,
  deps: CrossCallDriftDeps,
): Promise<void> {
  const { jti, operatorId, agentId, body } = input;
  if (body == null) return;

  // Reduce body to a measurable string. Object → JSON.
  let text: string;
  try {
    text = typeof body === 'string' ? body : JSON.stringify(body);
  } catch {
    return; // non-serializable; skip observation
  }
  if (!text) return;
  const length = Math.min(text.length, MAX_TRACKED_LENGTH);
  const entropy = shannonEntropy(text);

  let state: DriftState;
  try {
    const raw = await deps.redis.get(stateKey(jti));
    state = raw ? (JSON.parse(raw) as DriftState) : {
      n: 0, sum_l: 0, sumsq_l: 0, sum_h: 0, sumsq_h: 0,
    };
  } catch {
    state = { n: 0, sum_l: 0, sumsq_l: 0, sum_h: 0, sumsq_h: 0 };
  }

  // Compute z-scores against PRIOR state (cold-start gated).
  let firedDimension: 'length' | 'entropy' | null = null;
  let z = 0;
  let priorMean = 0;
  let priorStddev = 0;
  if (state.n >= COLD_START_N) {
    const { mean: meanL, stddev: stdL } = meanStddev(state.sum_l, state.sumsq_l, state.n);
    const { mean: meanH, stddev: stdH } = meanStddev(state.sum_h, state.sumsq_h, state.n);
    // Standard z-test when variance is non-zero. Zero-variance fallback
    // for rigid baselines: a single observation that's ≥3× mean away
    // counts as an outlier even though σ=0 makes z undefined.
    const zL = stdL > 0
      ? Math.abs((length - meanL) / stdL)
      : (meanL > 0 && Math.abs(length - meanL) / meanL >= ZERO_VAR_DEVIATION_RATIO ? Z_THRESHOLD : 0);
    const zH = stdH > 0
      ? Math.abs((entropy - meanH) / stdH)
      : (meanH > 0 && Math.abs(entropy - meanH) / meanH >= ZERO_VAR_DEVIATION_RATIO ? Z_THRESHOLD : 0);
    if (zL >= Z_THRESHOLD && zL >= zH) {
      firedDimension = 'length'; z = zL; priorMean = meanL; priorStddev = stdL;
    } else if (zH >= Z_THRESHOLD) {
      firedDimension = 'entropy'; z = zH; priorMean = meanH; priorStddev = stdH;
    }
  }

  // Update state with this observation. Done regardless of fire so the
  // baseline keeps adapting. (An attacker who triggered a fire and is
  // now operating at the new baseline will still trip subsequent z-tests
  // if they shift again — the rolling stats catch sustained anomalies
  // across multiple shifts, not just the first.)
  const next: DriftState = {
    n: state.n + 1,
    sum_l: state.sum_l + length,
    sumsq_l: state.sumsq_l + length * length,
    sum_h: state.sum_h + entropy,
    sumsq_h: state.sumsq_h + entropy * entropy,
    ...(state.last_fire_n !== undefined ? { last_fire_n: state.last_fire_n } : {}),
  };

  if (firedDimension !== null) {
    // Dedupe: do not refire on the same observation if a parallel call
    // already raced through. last_fire_n records the n at last fire;
    // we only fire when n has advanced past it.
    if (state.last_fire_n === undefined || state.n > state.last_fire_n) {
      next.last_fire_n = state.n;
      try {
        await deps.securityEvent.record({
          operatorId,
          agentId,
          passportJti: jti,
          signalType: 'behavior_drift',
          severity: 'warning',
          message: `Cross-call ${firedDimension} drift z=${z.toFixed(2)} on call #${state.n + 1}`,
          metadata: {
            dimension: firedDimension,
            z_score: Number(z.toFixed(3)),
            current_length: length,
            current_entropy: Number(entropy.toFixed(3)),
            baseline_n: state.n,
            baseline_mean: Number(priorMean.toFixed(3)),
            baseline_stddev: Number(priorStddev.toFixed(3)),
            threshold: Z_THRESHOLD,
          },
        });
      } catch {
        // never fail the proxy path
      }
    }
  }

  try {
    await deps.redis.set(stateKey(jti), JSON.stringify(next), 'EX', STATE_TTL_SECONDS);
  } catch {
    // best-effort persist
  }
}

// Test-only helpers exported for the unit test suite.
export const __test__ = {
  Z_THRESHOLD,
  COLD_START_N,
  meanStddev,
};
