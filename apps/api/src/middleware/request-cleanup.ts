import type { FastifyInstance } from 'fastify';
import { safeErrorSummary } from '@stack/shared';
import { onRequestEnd } from './request-end.js';

/**
 * Approval reservation release. The gate reserves (approved -> consuming) at
 * admit so concurrent calls cannot both spend one human approval; the route
 * clears `request.approvalToRelease` on a successful consume. Anything still
 * set when the request ends is a call that admitted but did not finish (a
 * later gate refused it, the upstream failed, or the client hung up first), so
 * the reservation is released back to 'approved' for retry. One uniform hook,
 * so every failure path (including thrown refusals) is covered without a
 * release at each throw.
 */
export function registerApprovalRelease(app: FastifyInstance): void {
  onRequestEnd(app, (request) => {
    const release = request.approvalToRelease;
    if (!release) return;
    request.approvalToRelease = undefined as never;
    void release().catch((err: unknown) => {
      console.error('[approval] reservation release failed', safeErrorSummary(err));
    });
  });
}

/**
 * Early-started L3 scans. The proxy starts the classifier in parallel with its
 * remaining gates; a route that finishes the scan clears
 * `request.pendingInputScanAbort`. Anything left belongs to a request that was
 * refused, failed or abandoned first: cancel the classifier call and release
 * its hold. Records nothing.
 */
export function registerScanAbort(app: FastifyInstance): void {
  onRequestEnd(app, (request) => {
    const abort = request.pendingInputScanAbort;
    if (!abort) return;
    request.pendingInputScanAbort = undefined as never;
    abort();
  });
}
