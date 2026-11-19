// Ends the engine's pending items whose time has run out, and tells the agent that waited on each how it ended. Every
// API machine runs it; each item moves once (a conditional update, or for an authority request the one removal from the
// expiry list that counted), and only the machine that moved it announces it, so nothing is told twice.
//
// Once a minute: intent approvals and fleet reviews nobody decided (`expired`), held actions' reviews nobody decided
// (`expired`), authority requests nobody decided (`expired`), and proxied writes whose outcome stayed unknown for
// PROXY_OPERATION_UNRESOLVED_AFTER_DAYS with nothing settling it (`unresolved`: never sent again; the owner is told
// too), and identity verification sessions nobody finished by their time (`expired`; no agent waits on one, so nobody
// is woken: the session reads `expired`). Nothing here is on an action's path.

import { PROXY_OPERATION_UNRESOLVED_AFTER_DAYS, runPass, safeErrorSummary, type JobObserver, type PassHandle } from '@stack/shared';
import type { Services } from './services.js';
import { announceDecision } from '../lib/decision-reached.js';
import { announceExpiredAuthorityRequests } from '../routes/authority-flows/setup-requests.js';

const PASS_INTERVAL_MS = 60 * 1000;

type RunnerServices = Pick<Services, 'intentApproval' | 'controlReviews' | 'proxyOperation' | 'identity' | 'notification' | 'registries' | 'redis' | 'kms'>;

/** The proxied writes this pass marked unresolved: each agent is told, and each owner. Returns how many. */
async function announceUnresolvedWrites(services: RunnerServices, now: Date, pass: PassHandle): Promise<number> {
  const rows = await services.proxyOperation.markUnresolvedDue(now);
  for (const row of rows) {
    // A decision names a write by the hash of the operation id its agent sent: all STACK keeps of it.
    await announceDecision(services.registries, {
      operatorId: row.operator_id,
      agentId: row.agent_id,
      kind: 'proxy_operation',
      itemId: `sha256:${row.operation_key_hash}`,
      result: 'unresolved',
      occurredAt: now,
    });
    try {
      await services.notification.publishEvent({
        operatorId: row.operator_id,
        eventType: 'proxy_operation.unresolved',
        severity: 'warning',
        payload: {
          operation_id_hash: `sha256:${row.operation_key_hash}`,
          agent_id: row.agent_id,
          provider: row.provider,
          method: row.method,
          message: `A ${row.method} to ${row.provider} has had no known result for ${PROXY_OPERATION_UNRESOLVED_AFTER_DAYS} days. STACK will not send it again. Check it with the provider, and authorise a replacement if it never happened.`,
        },
      });
    } catch (error) {
      console.error('[DECISION_ENDS] telling the owner of an unresolved write failed', safeErrorSummary(error));
      pass.degraded('notice_failed');
    }
  }
  return rows.length;
}

/** One pass; the runner's tick, and what tests call. Each step catches its own failure so the next still runs, and reports it. */
export async function runDecisionEndsPass(services: RunnerServices, now: Date = new Date(), observe?: JobObserver): Promise<void> {
  await runPass(
    observe,
    'decision_ends:intent_approvals',
    async () => {
      const expired = await services.intentApproval.expireDue(now);
      if (expired > 0) console.log(`[DECISION_ENDS] ${expired} intent approval(s) or fleet review(s) expired`);
    },
    (error) => console.error('[DECISION_ENDS] intent approval expiry failed', safeErrorSummary(error)),
  );
  await runPass(
    observe,
    'decision_ends:held_reviews',
    async () => {
      const expired = await services.controlReviews.expirePending();
      if (expired > 0) console.log(`[DECISION_ENDS] ${expired} held action review(s) expired`);
    },
    (error) => console.error('[DECISION_ENDS] held action review expiry failed', safeErrorSummary(error)),
  );
  await runPass(
    observe,
    'decision_ends:authority_requests',
    async () => {
      const expired = await announceExpiredAuthorityRequests(services, now.getTime());
      if (expired > 0) console.log(`[DECISION_ENDS] ${expired} authority request(s) expired`);
    },
    (error) => console.error('[DECISION_ENDS] authority request expiry failed', safeErrorSummary(error)),
  );
  await runPass(
    observe,
    'decision_ends:unresolved_writes',
    async (pass) => {
      const unresolved = await announceUnresolvedWrites(services, now, pass);
      if (unresolved > 0) console.log(`[DECISION_ENDS] ${unresolved} proxied write(s) unresolved`);
    },
    (error) => console.error('[DECISION_ENDS] unresolved write sweep failed', safeErrorSummary(error)),
  );
  await runPass(
    observe,
    'decision_ends:identity_sessions',
    async () => {
      const expired = await services.identity.expireDue(now);
      if (expired > 0) console.log(`[DECISION_ENDS] ${expired} identity verification session(s) expired`);
    },
    (error) => console.error('[DECISION_ENDS] identity verification expiry failed', safeErrorSummary(error)),
  );
}

export function startDecisionEndsRunner(services: RunnerServices, observe?: JobObserver): () => void {
  let running = false;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    void runDecisionEndsPass(services, new Date(), observe).finally(() => {
      running = false;
    });
  }, PASS_INTERVAL_MS);
  timer.unref();
  return () => clearInterval(timer);
}
