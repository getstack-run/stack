// Keeps the verified e-mail domains of single sign-on honest (spec/sso-login/SPEC.md section 9.5). Every API machine runs
// it; each pass takes the verified domains whose DNS record has not been looked up for an hour with one conditional
// statement, so machines never look the same one up twice, and looks them up again. A domain whose record is seen gone
// for the lapse time stops belonging to the account; one added and never proved is dropped after two weeks. Nothing here
// is on a sign-in's path: a sign-in reads what this keeps fresh, and looks the record up itself only when it is stale.

import { runPass, safeErrorSummary, type JobObserver } from '@stack/shared';
import type { Services } from './services.js';

const PASS_INTERVAL_MS = 5 * 60 * 1000;

type RunnerServices = Pick<Services, 'ssoDomains'>;

/** One pass; the runner's tick, and what tests call. */
export async function runSsoDomainPass(services: RunnerServices, observe?: JobObserver): Promise<void> {
  await runPass(
    observe,
    'sso_domain:recheck',
    async () => {
      const run = await services.ssoDomains.recheckDue();
      if (run.lapsed + run.dropped > 0) {
        console.log(`[SSO_DOMAIN] ${run.lapsed} domain(s) lapsed, ${run.dropped} unverified claim(s) dropped`);
      }
    },
    (error) => console.error('[SSO_DOMAIN] upkeep pass failed', safeErrorSummary(error)),
  );
}

export function startSsoDomainRunner(services: RunnerServices, observe?: JobObserver): () => void {
  let running = false;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    void runSsoDomainPass(services, observe).finally(() => {
      running = false;
    });
  }, PASS_INTERVAL_MS);
  timer.unref();
  return () => clearInterval(timer);
}
