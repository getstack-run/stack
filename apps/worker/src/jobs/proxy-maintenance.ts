import { safeErrorSummary } from '@stack/shared';
import type { JobOutcome } from '../extension.js';
import type { WorkerRuntime } from '../runtime.js';

/**
 * Queued post-response work stored before the signed records stopped carrying a query string still holds the full URL in
 * its encrypted context. One pass per process rewrites those (it does nothing once none is left, and a work item that is
 * completed clears its context anyway); a failed pass is tried again on the next tick.
 */
let queuedUrlsRedacted = false;

/**
 * Proxy housekeeping, in order: mark expired dispatch leases outcome-unknown,
 * scrub expired replay payloads, run the post-response completion tick, then
 * the accounting tick.
 *
 * PostgreSQL owns proxy counts, fractional accrual and Wallet obligations. The
 * accounting tick recovers a crash between reservation and settlement, then
 * overwrites Redis with a rebuildable projection.
 */
export async function runProxyMaintenance(
  deps: Pick<WorkerRuntime, 'proxyOperations' | 'proxyPostResponse' | 'proxyAccounting'>,
  outcome?: JobOutcome,
): Promise<void> {
  const { proxyOperations, proxyPostResponse, proxyAccounting } = deps;

  if (!queuedUrlsRedacted) {
    try {
      const redaction = await proxyOperations.redactQueuedPostResponseContexts();
      queuedUrlsRedacted = true;
      if (redaction.redacted > 0 || redaction.unreadable > 0) {
        console.log(
          `[PROXY] Rewrote ${redaction.redacted} queued post-response context(s) without their query strings` +
            (redaction.unreadable > 0 ? `; ${redaction.unreadable} could not be read.` : '.'),
        );
      }
    } catch (error) {
      console.error('[PROXY] Rewriting queued post-response contexts failed', safeErrorSummary(error));
      outcome?.degraded('redaction_failed');
    }
  }

  const unknownProxyDispatches = await proxyOperations.markExpiredDispatchesUnknown();
  if (unknownProxyDispatches > 0) {
    console.log(
      `[PROXY] Marked ${unknownProxyDispatches} expired dispatch lease(s) outcome unknown.`,
    );
  }
  const expiredProxyPayloads = await proxyOperations.expireReplay();
  if (expiredProxyPayloads > 0) {
    console.log(`[PROXY] Scrubbed ${expiredProxyPayloads} expired replay payload(s).`);
  }
  const proxyPostResponseResult = await proxyPostResponse.tick();
  if (proxyPostResponseResult.completed > 0 || proxyPostResponseResult.failed > 0) {
    console.log(
      `[PROXY POST-RESPONSE] completed=${proxyPostResponseResult.completed} ` +
        `waiting=${proxyPostResponseResult.waiting} failed=${proxyPostResponseResult.failed}`,
    );
  }

  const proxyAccountingResult = await proxyAccounting.tick();
  if (proxyAccountingResult.settlements > 0) {
    console.log(
      `[PROXY ACCOUNTING] ${proxyAccountingResult.settlements} wallet obligation(s) settled.`,
    );
  }
  if (proxyAccountingResult.projectionFailures > 0) {
    console.warn(
      '[PROXY ACCOUNTING] Redis projections pending retry:',
      proxyAccountingResult.projectionFailures,
    );
  }
}
