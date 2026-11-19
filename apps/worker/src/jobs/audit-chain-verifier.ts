import * as Sentry from '@sentry/node';
import { operators } from '@stack/shared';
import { runAuditCheck } from '../audit-check.js';
import type { JobOutcome } from '../extension.js';
import type { WorkerRuntime } from '../runtime.js';

/**
 * Audit-chain integrity verifier. Walks every operator's hash chain
 * every 6 hours or after an Admin request. Stores explicit job status
 * in Redis and alerts Sentry on chain breaks. No audit rows are changed.
 */
export async function maybeRunAuditChainVerifier(
  deps: Pick<WorkerRuntime, 'audit' | 'db' | 'redis' | 'auditCheckSkipOperatorIds'>,
  outcome?: JobOutcome,
): Promise<void> {
  const { audit, db, redis, auditCheckSkipOperatorIds } = deps;
  const result = await runAuditCheck(redis, {
    listOperators: () => db.select({ id: operators.id }).from(operators),
    verify: (id) => audit.verifyChain(id),
    skipOperatorIds: auditCheckSkipOperatorIds,
    reportBroken: (result) =>
      Sentry.captureException(
        new Error(`Audit chain integrity break: ${result.broken} operator chain(s).`),
        {
          level: 'fatal',
          tags: { source: 'worker.audit_chain_verifier', kind: 'audit_chain_broken' },
          extra: {
            broken_operator_ids: result.broken_operator_ids,
            checked_count: result.checked,
            broken_count: result.broken,
          },
        },
      ),
  });
  // A run that could not read every chain says so; a broken chain is its own alarm (Sentry), not a failure of the job.
  if (result?.status === 'failed') outcome?.failed('verify_failed');
  else if (result?.status === 'partial') outcome?.degraded('verify_partial');
}
