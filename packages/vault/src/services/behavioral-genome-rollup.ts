// daily behavioral_genome rollup.
//
// Extracted into its own module so the worker (which has
// `void main()` at the bottom of apps/worker/src/worker.ts + Sentry init at the top —
// both unwanted side effects on import) AND the close-gate smoke
// can both invoke
// the SAME code path. Pure function: no module-level state, no side
// effects on import. Identical body to the pre-5.1.6 inline version
// in apps/worker/src/jobs/behavioral-genome-rollup.ts (verbatim move, no signature change).
//
// Lives in @stack/vault rather than apps/worker/ because the function
// is tightly coupled to BehavioralGenomeService (vault) and because
// apps/api/src/scripts can't cleanly import from apps/worker/src.
// @stack/vault is a workspace dep of both api + worker, so the import
// resolves cleanly from either side.
//
// Behavior:
//   Once per UTC day, aggregates the previous full UTC day of
//   audit_log activity per passport into a signed behavioral_genome claim,
//   for the accounts with controls on (every account on an install, where
//   controls are always on).
//
//   Lock TTL: 1 hour (not 26h). Idempotency is enforced inside
//   emitForWindow via dedupe-by-(passport_jti, window_start_ms), so the
//   Redis lock is just anti-collision between concurrent worker machines.
//   Once dedupe is in place, "ran twice today" is safe — the second
//   pass sees existing rows and returns deduped:true.
//
//   Per-tick cap: 250. On a busy day with >250 eligible passports the
//   next tick picks up the remainder; dedupe makes multi-tick spread safe.
//
//   Operator filter: the behavioural baseline is a controls feature. The
//   caller passes `eligible`, asked once per operator with activity in the
//   window (the worker asks whether the account has controls on); an operator
//   it refuses, or whose answer cannot be read, gets no claim this run. Without
//   it every operator is eligible.
//
//   Three-mode env gate via BEHAVIORAL_GENOME_MODE:
//     - 'off'  → skip entirely (kill-switch for emergencies)
//     - 'dry'  → query + log what would be emitted, no writes
//     - 'live' (default) → full rollup
//
//   Sentry escalation: Redis acquire failures are swallowed and retried
//   on the next tick (Redis down doesn't escalate every 10s). Other hard
//   errors (DB query failure, per-passport emit failure) log via console
//   which Sentry's worker error pipeline captures via the poll loop's
//   outer try/catch as a "sustained issue" only after 3 consecutive
//   transient errors.

import { and, gte, lt, isNotNull, inArray } from 'drizzle-orm';
import { auditLog, type Database } from '@stack/shared';
import { safeErrorSummary } from '@stack/shared';
import type { BehavioralGenomeService } from './behavioral-genome-service.js';
import type { Redis } from 'ioredis';

export async function maybeRunBehavioralGenomeRollup(
  behavioralGenome: BehavioralGenomeService,
  db: Database,
  redis: Redis,
  options: { eligible?: (operatorId: string) => Promise<boolean> } = {},
) {
  const mode = (process.env['BEHAVIORAL_GENOME_MODE'] ?? 'live') as 'off' | 'dry' | 'live';
  if (mode === 'off') return;

  const now = new Date();
  const dateKey = `behavioral_genome_lock:${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${String(now.getUTCDate()).padStart(2, '0')}`;
  let acquired: string | null;
  try {
    acquired = await redis.set(dateKey, now.toISOString(), 'EX', 3600, 'NX');
  } catch (err) {
    // Transient Redis blip → swallow + retry next tick rather than
    // escalating to Sentry every 10s. The poll-loop outer catch only
    // counts non-transient DB errors toward the 3-tick Sentry trip.
    console.error('[BEHAVIORAL_GENOME] redis acquire failed so retry next tick:', safeErrorSummary(err));
    return;
  }
  if (acquired !== 'OK') return;

  // Window: previous full UTC calendar day [yesterday 00:00, today 00:00).
  const todayMs = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const yesterdayMs = todayMs - 86_400_000;

  const inWindow = and(
    gte(auditLog.timestamp, yesterdayMs),
    lt(auditLog.timestamp, todayMs),
    isNotNull(auditLog.passport_jti),
  );
  let rows: Array<{ passport_jti: string | null; operator_id: string }>;
  try {
    let eligibleIds: string[] | null = null;
    if (options.eligible) {
      const active = await db
        .selectDistinct({ operator_id: auditLog.operator_id })
        .from(auditLog)
        .where(inWindow);
      eligibleIds = [];
      for (const { operator_id } of active) {
        try {
          if (await options.eligible(operator_id)) eligibleIds.push(operator_id);
        } catch (err) {
          console.error('[BEHAVIORAL_GENOME] eligibility unreadable so operator skipped:', operator_id, safeErrorSummary(err));
        }
      }
      if (eligibleIds.length === 0) return;
    }
    rows = await db
      .selectDistinct({
        passport_jti: auditLog.passport_jti,
        operator_id: auditLog.operator_id,
      })
      .from(auditLog)
      .where(eligibleIds ? and(inWindow, inArray(auditLog.operator_id, eligibleIds)) : inWindow)
      .limit(250);
  } catch (err) {
    console.error('[BEHAVIORAL_GENOME] passport query failed:', safeErrorSummary(err));
    return;
  }
  if (rows.length === 0) return;

  let emitted = 0;
  let deduped = 0;
  let empty = 0;
  let failed = 0;

  for (const r of rows) {
    if (!r.passport_jti) continue; // defensive — isNotNull predicate above should filter
    if (mode === 'dry') {
      console.log(`[BEHAVIORAL_GENOME] dry-run would emit for passport=${r.passport_jti}`);
      continue;
    }
    try {
      const result = await behavioralGenome.emitForWindow(
        r.operator_id,
        r.passport_jti,
        yesterdayMs,
        todayMs,
      );
      if (result.deduped) deduped += 1;
      else if (!result.emitted) empty += 1;
      else emitted += 1;
    } catch (err) {
      failed += 1;
      console.error('[BEHAVIORAL_GENOME] emitForWindow failed:', r.passport_jti, safeErrorSummary(err));
    }
  }
  console.log(
    `[BEHAVIORAL_GENOME] day=${dateKey.split(':')[1]} ` +
    `scanned=${rows.length} emitted=${emitted} deduped=${deduped} empty=${empty} failed=${failed}`,
  );
}
