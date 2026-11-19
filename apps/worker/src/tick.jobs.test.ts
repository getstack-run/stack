import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { JobReport } from '@stack/shared';

const sentry = vi.hoisted(() => ({ captureException: vi.fn() }));
vi.mock('@sentry/node', () => sentry);

// Every job of the tick reports how it ended, and a job that throws no longer stops the jobs after it. The jobs are stubs here (the
// order is pinned by tick.order.test.ts): `h.behave` says which of them throw or say they failed.
const h = vi.hoisted(() => {
  const calls: string[] = [];
  const behave = new Map<string, (outcome: { failed(code?: string): void; degraded(code: string): void } | undefined) => void>();
  const rec = (names: string[]): Record<string, (...args: unknown[]) => Promise<void>> =>
    Object.fromEntries(
      names.map((name) => [
        name,
        async (...args: unknown[]) => {
          calls.push(name);
          const outcome = args.find((a) => a && typeof a === 'object' && 'failed' in (a as object)) as never;
          behave.get(name)?.(outcome);
        },
      ]),
    );
  return { calls, behave, rec };
});

vi.mock('./jobs/archive-store-probe.js', () => h.rec(['maybeRunArchiveStoreProbe']));
vi.mock('./jobs/audit-chain-verifier.js', () => h.rec(['maybeRunAuditChainVerifier']));
vi.mock('./jobs/audit-retention.js', () => h.rec(['runAuditRetention']));
vi.mock('./jobs/behavioral-genome-rollup.js', () => h.rec(['runBehavioralGenomeRollup']));
vi.mock('./jobs/claim-retention-prune.js', () => h.rec(['maybeRunClaimRetentionPrune']));
vi.mock('./jobs/cmek-migration.js', () => h.rec(['runCmekMigrationTick']));
vi.mock('./jobs/email-change-retry.js', () => h.rec(['runEmailChangeRetry']));
vi.mock('./jobs/expire-dropoffs.js', () => h.rec(['expireDropoffs']));
vi.mock('./jobs/expire-intent-approvals.js', () => h.rec(['expireIntentApprovals']));
vi.mock('./jobs/inbound-retention.js', () => h.rec(['runInboundRetention']));
vi.mock('./jobs/fleet-recovery.js', () => h.rec(['recoverFleets']));
vi.mock('./jobs/identity-auto-revoke.js', () => h.rec(['autoRevokeExpiredClaims']));
vi.mock('./jobs/mission-expiry.js', () => h.rec(['maybeRunMissionExpirySweep']));
vi.mock('./jobs/oauth-retry-cleanup.js', () => h.rec(['runOAuthRetryCleanup']));
vi.mock('./jobs/operator-erasure-retry.js', () => h.rec(['runOperatorErasureRetry']));
vi.mock('./jobs/proxy-maintenance.js', () => h.rec(['runProxyMaintenance']));
vi.mock('./jobs/security-signals.js', () => h.rec(['detectCheckpointSilence', 'detectExpiredNoCheckout']));

import { createPoll, type TickOutcome } from './loop.js';
import { createTickObserver } from './tick-observer.js';
import { runTick } from './tick.js';
import { fullRuntime } from './tick.order.test-support.js';
import type { WorkerExtension } from './extension.js';

function extension(observeJob: (report: JobReport) => void, jobs: WorkerExtension['jobs'] = {}): WorkerExtension {
  return { observeJob, jobs } as unknown as WorkerExtension;
}

describe('the tick reports every job and carries on past a failure', () => {
  beforeEach(() => {
    h.calls.length = 0;
    h.behave.clear();
  });

  it('reports each engine job ok, under the name of its check, and an unconfigured one off', async () => {
    const reports: JobReport[] = [];
    const rt = { ...fullRuntime(), cmekMigrationWorker: undefined } as never;
    await runTick(rt, extension((r) => reports.push(r)));
    const names = reports.map((r) => r.job);
    expect(names).toContain('worker:expire_dropoffs');
    expect(names).toContain('worker:audit_chain_verifier');
    expect(reports.find((r) => r.job === 'worker:cmek_migration')).toEqual({ job: 'worker:cmek_migration', state: 'off', code: 'not_configured' });
    expect(reports.filter((r) => r.state === 'ok').length).toBe(names.length - 1);
    for (const name of names) expect(name).toMatch(/^worker:[a-z0-9_]+$/);
  });

  it('a throwing job reads down with its code, the jobs after it still run, Sentry gets its error and the tick is clean', async () => {
    const reports: JobReport[] = [];
    h.behave.set('expireIntentApprovals', () => {
      throw new Error('boom: secret text');
    });
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    sentry.captureException.mockClear();
    await expect(runTick(fullRuntime(), extension((r) => reports.push(r)))).resolves.toBeUndefined();
    expect(sentry.captureException).toHaveBeenCalledOnce();
    expect(sentry.captureException.mock.calls[0]![0]).toMatchObject({ message: 'boom: secret text' });
    expect(sentry.captureException.mock.calls[0]![1]).toEqual({ tags: { source: 'worker.job', job: 'expire_intent_approvals' } });
    expect(reports).toContainEqual({ job: 'worker:expire_intent_approvals', state: 'down', code: 'failed' });
    expect(h.calls).toContain('maybeRunAuditChainVerifier');
    expect(h.calls.indexOf('maybeRunAuditChainVerifier')).toBeGreaterThan(h.calls.indexOf('expireIntentApprovals'));
    expect(JSON.stringify(reports)).not.toContain('secret');
  });

  it('a database that is unreachable ends the tick instead of making every job wait out its timeout', async () => {
    const reports: JobReport[] = [];
    h.behave.set('expireDropoffs', () => {
      throw Object.assign(new Error('connect'), { code: 'ECONNREFUSED' });
    });
    sentry.captureException.mockClear();
    await expect(runTick(fullRuntime(), extension((r) => reports.push(r)))).rejects.toThrow();
    expect(sentry.captureException).not.toHaveBeenCalled();
    expect(reports).toContainEqual({ job: 'worker:expire_dropoffs', state: 'down', code: 'database_unreachable' });
    expect(h.calls).not.toContain('maybeRunAuditChainVerifier');
  });

  it('a job that catches its own error and says so reads down; one that finished part of its work reads degraded', async () => {
    const reports: JobReport[] = [];
    h.behave.set('maybeRunClaimRetentionPrune', (o) => o?.failed('prune_failed'));
    h.behave.set('maybeRunMissionExpirySweep', (o) => o?.degraded('complete_failed'));
    await runTick(fullRuntime(), extension((r) => reports.push(r)));
    expect(reports).toContainEqual({ job: 'worker:claim_retention_prune', state: 'down', code: 'prune_failed' });
    expect(reports).toContainEqual({ job: 'worker:mission_expiry', state: 'degraded', code: 'complete_failed' });
  });

  it('runs a deployment job in its slot with its own name', async () => {
    const reports: JobReport[] = [];
    const ran: string[] = [];
    const ext = extension((r) => reports.push(r), {
      start: [
        { name: 'first', run: async () => { throw new Error('x'); } },
        { name: 'second', run: async () => { ran.push('second'); } },
      ],
    });
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await expect(runTick(fullRuntime(), ext)).resolves.toBeUndefined();
    expect(ran).toEqual(['second']);
    expect(reports).toContainEqual({ job: 'worker:first', state: 'down', code: 'failed' });
    expect(reports).toContainEqual({ job: 'worker:second', state: 'ok' });
  });


  describe('the heartbeat after a tick', () => {
    function worker(ext: WorkerExtension) {
      const redis = { set: vi.fn(async () => 'OK') };
      const told: TickOutcome[] = [];
      const withTick = { ...ext, observeTick: (o: TickOutcome) => void told.push(o) } as WorkerExtension;
      const poll = createPoll({
        tick: () => runTick(fullRuntime(), withTick),
        sentryDsn: undefined,
        onTick: createTickObserver(redis, withTick),
      });
      return { redis, told, poll };
    }

    it('a tick with one throwing job still writes the heartbeat and tells the deployment it was clean, and Sentry has the error', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => undefined);
      sentry.captureException.mockClear();
      h.behave.set('expireDropoffs', () => {
        throw new Error('a job broke');
      });
      const w = worker(extension(() => {}));
      await w.poll();
      expect(w.told).toEqual([{ ok: true }]);
      expect(w.redis.set).toHaveBeenCalledWith('worker:heartbeat', expect.any(String), 'EX', 60);
      expect(sentry.captureException).toHaveBeenCalledOnce();
      expect(h.calls).toContain('maybeRunAuditChainVerifier');
    });

    it('a Redis outage in a job writes no heartbeat and is told as a Redis failure', async () => {
      vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      vi.spyOn(console, 'error').mockImplementation(() => undefined);
      h.behave.set('expireDropoffs', () => {
        throw new Error('Connection is closed.');
      });
      const w = worker(extension(() => {}));
      await w.poll();
      expect(w.told).toEqual([{ ok: false, kind: 'redis' }]);
      expect(w.redis.set).not.toHaveBeenCalled();
    });
  });
});
