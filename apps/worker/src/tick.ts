import type { WorkerRuntime } from './runtime.js';
import * as Sentry from '@sentry/node';
import { JOB_NOT_CONFIGURED_CODE, reportJob, safeErrorSummary } from '@stack/shared';
import type { JobOutcome, TickSlot, WorkerExtension } from './extension.js';
import { maybeRunArchiveStoreProbe } from './jobs/archive-store-probe.js';
import { maybeRunAuditChainVerifier } from './jobs/audit-chain-verifier.js';
import { runAuditRetention } from './jobs/audit-retention.js';
import { runBehavioralGenomeRollup } from './jobs/behavioral-genome-rollup.js';
import { maybeRunClaimRetentionPrune } from './jobs/claim-retention-prune.js';
import { runCmekMigrationTick } from './jobs/cmek-migration.js';
import { runEmailChangeRetry } from './jobs/email-change-retry.js';
import { expireDropoffs } from './jobs/expire-dropoffs.js';
import { expireIntentApprovals } from './jobs/expire-intent-approvals.js';
import { runInboundRetention } from './jobs/inbound-retention.js';
import { recoverFleets } from './jobs/fleet-recovery.js';
import { autoRevokeExpiredClaims } from './jobs/identity-auto-revoke.js';
import { maybeRunMissionExpirySweep } from './jobs/mission-expiry.js';
import { runOAuthRetryCleanup } from './jobs/oauth-retry-cleanup.js';
import { runOperatorErasureRetry } from './jobs/operator-erasure-retry.js';
import { runProxyMaintenance } from './jobs/proxy-maintenance.js';
import { detectCheckpointSilence, detectExpiredNoCheckout } from './jobs/security-signals.js';
import { isTransientDependencyError, workerJobFailureCode } from './transient-db-error.js';

/**
 * One poll tick: every job, in order. The order is load-bearing in two places.
 * The audit retention step runs the usage rollup, then the cold archive, then
 * the prune (see `jobs/audit-retention.ts`). And each job is told apart from
 * its neighbours: a job that throws is recorded as down (`job:worker:<name>`,
 * with a fixed code) and its error goes to Sentry on its own (as `createPoll`
 * does for any error that is not a database or Redis outage), and the jobs after
 * it still run. A tick that ran every job to the end is a clean tick whatever
 * individual jobs did: one failing job must not make the worker look dead. The
 * one exception is an unreachable database or Redis: every job after it would
 * wait out the same timeout, so the tick ends there and fails with that error,
 * which `createPoll` classifies as an outage (not a clean tick). A job that
 * catches its own errors says so through its `JobOutcome`. Each job guards its
 * own cadence or Redis lock, so most of them return immediately; the next tick,
 * 10 seconds later, retries whatever did not run.
 *
 * The jobs below are the engine's. A deployment's own jobs (STACK's billing,
 * accounts, payouts, marketplace review, emails and cockpit) run in the named
 * slots of its extension, each at the place it has always run; an install with
 * no extension runs the engine's alone.
 */
export async function runTick<Parts extends object = object>(
  rt: WorkerRuntime & Parts,
  ext: WorkerExtension<Parts> | null = null,
): Promise<void> {
  /** The outage (unreachable database or Redis) that ended the tick, if any. */
  let outage: unknown = null;
  let ended = false;

  // Runs one job, reports how it ended, and keeps its error for the end of the tick.
  const run = async (name: string, job: (outcome: JobOutcome) => Promise<unknown>): Promise<void> => {
    if (ended) return;
    const job_ = `worker:${name}`;
    let failed: string | null = null;
    let degraded: string | null = null;
    let off: string | null = null;
    try {
      await job({
        failed: (code = 'failed') => {
          failed ??= code;
        },
        degraded: (code) => {
          degraded ??= code;
        },
        off: (code = JOB_NOT_CONFIGURED_CODE) => {
          off ??= code;
        },
      });
    } catch (error) {
      reportJob(ext?.observeJob, { job: job_, state: 'down', code: workerJobFailureCode(error) });
      if (isTransientDependencyError(error)) {
        outage ??= error;
        ended = true;
      } else {
        // Seen by Sentry per job, as the poll sees any other error; a failing job never fails the tick.
        console.error('Worker job failed:', name, safeErrorSummary(error));
        Sentry.captureException(error, { tags: { source: 'worker.job', job: name } });
      }
      return;
    }
    if (failed !== null) reportJob(ext?.observeJob, { job: job_, state: 'down', code: failed });
    else if (degraded !== null) reportJob(ext?.observeJob, { job: job_, state: 'degraded', code: degraded });
    else if (off !== null) reportJob(ext?.observeJob, { job: job_, state: 'off', code: off });
    else reportJob(ext?.observeJob, { job: job_, state: 'ok' });
  };

  const slot = async (name: TickSlot): Promise<void> => {
    for (const job of ext?.jobs[name] ?? []) await run(job.name, (outcome) => job.run(rt, outcome));
  };

  await slot('start');
  // HeadBucket on the audit object store, every ten minutes; never throws.
  const archiveProbe = ended ? null : await maybeRunArchiveStoreProbe(rt);
  if (archiveProbe) {
    try {
      ext?.observeArchiveStoreProbe?.(archiveProbe);
    } catch {
      // A record of the verdict never changes the tick.
    }
  }

  await run('expire_dropoffs', () => expireDropoffs(rt));
  // Intent approvals nobody decided before their time ran out end as expired.
  await run('expire_intent_approvals', () => expireIntentApprovals(rt));
  await slot('afterDropoffs');

  await run('oauth_retry_cleanup', () => runOAuthRetryCleanup(rt));
  await run('operator_erasure_retry', () => runOperatorErasureRetry(rt));
  await run('email_change_retry', () => runEmailChangeRetry(rt));
  await slot('afterRetries');

  // Signal 6 (checkpoint_silence): enforced passports overdue for checkpoints.
  await run('checkpoint_silence', () => detectCheckpointSilence(rt));
  // Signal 7 (expired_no_checkout): passports that expired without checkout.
  await run('expired_no_checkout', () => detectExpiredNoCheckout(rt));
  // Revoke expired identity claims, and their passports, for operators with auto-revoke on.
  await run('identity_auto_revoke', () => autoRevokeExpiredClaims(rt.db, rt));
  await slot('afterIdentityRevoke');

  await run('fleet_recovery', () => recoverFleets(rt));
  await run('proxy_maintenance', (outcome) => runProxyMaintenance(rt, outcome));

  // Skipped entirely when CMEK is not configured (dev mode).
  if (rt.cmekMigrationWorker) {
    const cmekMigrationWorker = rt.cmekMigrationWorker;
    await run('cmek_migration', () => runCmekMigrationTick({ cmekMigrationWorker, state: rt.state }));
  } else {
    reportJob(ext?.observeJob, { job: 'worker:cmek_migration', state: 'off', code: JOB_NOT_CONFIGURED_CODE });
  }

  await run('audit_retention', (outcome) => runAuditRetention(rt, ext?.retention, outcome));

  // Daily passport_claims retention prune. Bounds the claims registry's growth
  // against the same per-tier windows; op_stack_system claims are never pruned.
  await run('claim_retention_prune', (outcome) => maybeRunClaimRetentionPrune(rt, outcome));

  await run('genome_rollup', () => runBehavioralGenomeRollup(rt));
  await slot('afterGenomeRollup');

  // Every-tick sweep of missions whose `expires_at` has passed.
  await run('mission_expiry', (outcome) => maybeRunMissionExpirySweep(rt, outcome));
  await slot('afterMissionExpiry');

  // Every 10 minutes: delete completed inbound-webhook receipts past the 48-hour dedupe window.
  await run('inbound_retention', (outcome) => runInboundRetention(rt, new Date(), outcome));

  // Audit-chain integrity verifier, every 6 hours. Results go to Admin and the
  // daily digest; broken chains also raise a fatal Sentry alert.
  await run('audit_chain_verifier', (outcome) => maybeRunAuditChainVerifier(rt, outcome));
  await slot('end');

  // An outage is not a clean tick: the poll classifies it (and the heartbeat is withheld).
  if (outage !== null) throw outage;
}
