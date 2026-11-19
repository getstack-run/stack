// The engine's entry point: the API of a self-managed install, with no plans, no meter and no bill.
// STACK's own deployment starts from an entry point of its own; this entry refuses to serve it (entry-guard.ts).
//
// The guard runs first, before the API's environment is read; start.ts initialises Sentry and the
// process-level guards on import, so it comes before anything else of the API.
import './entry-guard.js';
import { startApi } from './start.js';

startApi(null).catch(() => {
  console.error('[server] Failed to start: diagnostic details suppressed.');
  process.exit(1);
});
