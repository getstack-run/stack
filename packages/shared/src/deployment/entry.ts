import { readDeployment } from './index.js';

type Env = Record<string, string | undefined>;

/**
 * The engine's own entry points (`apps/api/dist/server.js`, the worker's and the
 * MCP server's) run the engine alone: no plans, no meter, no bill, and the
 * licence key gates the enterprise features. They start only when the deployment
 * says it is self-managed, in every environment: `STACK_DEPLOYMENT` unset reads
 * as `hosted`, so a machine that forgot the variable, a staging box, a stale
 * image or a start command that still points at the engine's entry fails to boot
 * instead of serving without a meter or without the licence check.
 */
export function assertEngineEntryAllowed(env: Env = process.env): void {
  if (!readDeployment(env).selfManaged) {
    throw new Error(
      '[BOOT] The engine entry point runs a self-managed install; STACK_DEPLOYMENT=self_managed is required. A hosted deployment starts from its own entry point.',
    );
  }
}

/** The hosted entry points serve STACK's own deployment, never a self-managed install. */
export function assertHostedEntryAllowed(env: Env = process.env): void {
  if (readDeployment(env).selfManaged) {
    throw new Error('[BOOT] The hosted entry point cannot run with STACK_DEPLOYMENT=self_managed; start the engine entry point instead.');
  }
}
