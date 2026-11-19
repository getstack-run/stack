import { beforeEach, describe, expect, it, vi } from 'vitest';

// The order jobs run in one tick is load-bearing (the audit retention step runs
// the usage rollup, the cold archive and the prune in that sequence, and a job
// that throws ends the tick). This test pins the exact order for an install (the
// engine's jobs alone), so no refactor of how jobs are registered can reorder them
// without a failing test. STACK's hosted deployment, the engine's jobs with its own in
// their slots, is pinned by the deployment's own test.
const h = vi.hoisted(() => {
  const calls: string[] = [];
  const rec = (names: string[]): Record<string, () => Promise<void>> =>
    Object.fromEntries(
      names.map((name) => [
        name,
        async () => {
          calls.push(name);
        },
      ]),
    );
  return { calls, rec };
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

import { runTick } from './tick.js';
import { ENGINE_ORDER, fullRuntime } from './tick.order.test-support.js';

describe('runTick job order', () => {
  beforeEach(() => {
    h.calls.length = 0;
  });

  it('runs only the engine jobs, in the same relative order, with no extension', async () => {
    await runTick(fullRuntime(), null);
    expect(h.calls).toEqual(ENGINE_ORDER);
  });
});
