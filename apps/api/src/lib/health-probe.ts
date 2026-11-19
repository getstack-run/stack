import { safeErrorSummary } from '@stack/shared';

/** How long one dependency probe may take before it counts as down. */
export const HEALTH_PROBE_TIMEOUT_MS = 2000;

export type HealthReason = 'database_unreachable' | 'redis_unreachable' | 'database_and_redis_unreachable';

export type HealthResult =
  | { ok: true }
  | {
      ok: false;
      /** The only part of a failure that may reach a response. */
      reason: HealthReason;
      /** Operator-side detail for the log line; never sent to a caller. */
      failures: Array<{ dependency: 'database' | 'redis'; error: ReturnType<typeof safeErrorSummary> }>;
    };

export interface HealthProbes {
  database(): Promise<unknown>;
  redis(): Promise<unknown>;
}

async function probe(run: () => Promise<unknown>, name: string, timeoutMs: number): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  const pending = run();
  // A late rejection after the timeout wins the race must not become unhandled.
  pending.catch(() => {});
  try {
    await Promise.race([
      pending,
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`${name} health probe timeout`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Probe the two dependencies every authenticated request needs, in parallel,
 * each with its own cap. The platform's check turns a failure into a 503 and pulls the
 * machine out of rotation; the response names only which dependency, never
 * its address or the driver's error text.
 */
export async function probeHealth(
  probes: HealthProbes,
  timeoutMs = HEALTH_PROBE_TIMEOUT_MS,
): Promise<HealthResult> {
  const [database, redis] = await Promise.allSettled([
    probe(probes.database, 'database', timeoutMs),
    probe(probes.redis, 'redis', timeoutMs),
  ]);
  const failures: Array<{ dependency: 'database' | 'redis'; error: ReturnType<typeof safeErrorSummary> }> = [];
  if (database.status === 'rejected') failures.push({ dependency: 'database', error: safeErrorSummary(database.reason) });
  if (redis.status === 'rejected') failures.push({ dependency: 'redis', error: safeErrorSummary(redis.reason) });
  if (failures.length === 0) return { ok: true };
  const reason: HealthReason = failures.length === 2
    ? 'database_and_redis_unreachable'
    : failures[0]!.dependency === 'redis' ? 'redis_unreachable' : 'database_unreachable';
  return { ok: false, reason, failures };
}

export interface HealthAnswer {
  statusCode: 200 | 503;
  /** What `GET /health` sends: the dependency named in `reason` and nothing else of a failure. */
  body: { status: 'ok' | 'degraded'; reason?: HealthReason; timestamp: string };
  /** Operator-side detail for the log line; never sent to a caller. */
  failures: Array<{ dependency: 'database' | 'redis'; error: ReturnType<typeof safeErrorSummary> }>;
}

/**
 * What `GET /health` answers: 200 while the database and Redis answer,
 * otherwise 503 with the dependency named. The route itself is in `start.ts`
 * (rate-limit exempt, so an uptime monitor sharing an upstream address with
 * bursty traffic is not answered 429 while the API is up).
 */
export async function answerHealth(probes: HealthProbes, timeoutMs?: number): Promise<HealthAnswer> {
  const result = await probeHealth(probes, timeoutMs);
  const timestamp = new Date().toISOString();
  if (result.ok) return { statusCode: 200, body: { status: 'ok', timestamp }, failures: [] };
  return { statusCode: 503, body: { status: 'degraded', reason: result.reason, timestamp }, failures: result.failures };
}

/** How long one health answer is reused. */
export const HEALTH_ANSWER_TTL_MS = 1_000;

/**
 * `answerHealth` shared for `ttlMs`: callers that arrive while a probe runs wait
 * for that one, and callers within `ttlMs` of an answer get it. `/health` is
 * unauthenticated and exempt from the rate limit (so a monitor behind a shared
 * address is not answered 429), which means nothing else bounds how often it
 * reaches Postgres and Redis: with this, a flood costs one `select 1` and one
 * `PING` a second per machine. A failure is reused too, so a dependency that is
 * down is not probed once per request either.
 */
export function memoiseHealth(
  probes: HealthProbes,
  options: {
    ttlMs?: number;
    now?: () => number;
    /** Called once per probe that failed (not per request that reuses the answer), for the log. */
    onDegraded?: (answer: HealthAnswer) => void;
    /** Called once per probe, whatever it found (not per request that reuses the answer): the deployment's record of the verdict. Must not throw. */
    onProbe?: (answer: HealthAnswer) => void;
  } = {},
): () => Promise<HealthAnswer> {
  const { ttlMs = HEALTH_ANSWER_TTL_MS, now = Date.now, onDegraded, onProbe } = options;
  let last: { at: number; answer: HealthAnswer } | null = null;
  let inFlight: Promise<HealthAnswer> | null = null;
  return () => {
    if (last && now() - last.at < ttlMs) return Promise.resolve(last.answer);
    if (inFlight) return inFlight;
    inFlight = answerHealth(probes)
      .then((answer) => {
        last = { at: now(), answer };
        if (answer.statusCode !== 200) onDegraded?.(answer);
        try {
          onProbe?.(answer);
        } catch {
          // A record of the verdict never changes the verdict.
        }
        return answer;
      })
      .finally(() => {
        inFlight = null;
      });
    return inFlight;
  };
}
