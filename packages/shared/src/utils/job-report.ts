// How a background job says what happened on one pass. The engine's runners and jobs report through a `JobObserver` and import nothing
// of the deployment: a deployment that keeps a record of its systems fills the seam (STACK's hosted deployment records each pass as a
// check named `job:<name>`), an install that does not leaves it absent and nothing is recorded.
//
// A report carries a job name and, when the pass did not complete, a fixed lower-case code (`failed`, `redis_unreachable`): never the
// error's message, which can hold a provider's text, an address or a credential shape.

import { isRedisUnavailableError } from '../errors/index.js';

export type JobReport =
  | { job: string; state: 'ok' }
  | { job: string; state: 'degraded' | 'down' | 'off'; code: string };

/** Told how each pass of a job ended. Must not throw; `reportJob` guards the call anyway. */
export type JobObserver = (report: JobReport) => void;

/** The code of a pass that threw and whose error the job does not classify. */
export const JOB_FAILED_CODE = 'failed';
/** The code of a job that is not configured on this machine (a service nobody set up). */
export const JOB_NOT_CONFIGURED_CODE = 'not_configured';

/** A fixed code for a thrown error: Redis being unreachable, else `failed`. A job that knows more passes its own classifier. */
export function jobFailureCode(error: unknown): string {
  return isRedisUnavailableError(error) ? 'redis_unreachable' : JOB_FAILED_CODE;
}

/** Tells the observer, and never lets a record of the work change the work. */
export function reportJob(observe: JobObserver | undefined, report: JobReport): void {
  try {
    observe?.(report);
  } catch {
    // A record of a job never changes what the job did.
  }
}

/** What a pass can say about itself while it runs: it finished, but part of what it had to do did not get done. */
export interface PassHandle {
  /** The pass caught an error of its own and only logged it: it is reported `down` with this fixed code (`failed` when none is given). */
  failed(code?: string): void;
  /** There was nothing for the pass to do because what it works on is not configured here: reported `off` with this fixed code. */
  off(code?: string): void;
  /** The pass completed but could not do all of its work (a notice that did not go out): reported `degraded` with this fixed code. */
  degraded(code: string): void;
}

export interface PassOptions {
  /** Classifies a thrown error into a fixed code. Absent: `redis_unreachable` or `failed`. */
  classify?: (error: unknown) => string;
}

/**
 * Runs one pass of a background job and reports how it ended: `ok` when it completed, `down` with a fixed code when it threw
 * (`onError` is the pass's own log line for it), `degraded` when it completed with part of its work undone. Never throws.
 */
export async function runPass(
  observe: JobObserver | undefined,
  job: string,
  run: (pass: PassHandle) => Promise<unknown>,
  onError: (error: unknown) => void,
  options: PassOptions = {},
): Promise<void> {
  let degradedCode: string | null = null;
  let failedCode: string | null = null;
  let offCode: string | null = null;
  try {
    await run({
      failed: (code = JOB_FAILED_CODE) => {
        failedCode ??= code;
      },
      degraded: (code) => {
        degradedCode ??= code;
      },
      off: (code = JOB_NOT_CONFIGURED_CODE) => {
        offCode ??= code;
      },
    });
  } catch (error) {
    try {
      onError(error);
    } catch {
      // A log line never changes the outcome.
    }
    let code = JOB_FAILED_CODE;
    try {
      code = (options.classify ?? jobFailureCode)(error);
    } catch {
      // An unclassifiable error is a plain failure.
    }
    reportJob(observe, { job, state: 'down', code });
    return;
  }
  if (failedCode !== null) reportJob(observe, { job, state: 'down', code: failedCode });
  else if (offCode !== null && degradedCode === null) reportJob(observe, { job, state: 'off', code: offCode });
  else reportJob(observe, degradedCode === null ? { job, state: 'ok' } : { job, state: 'degraded', code: degradedCode });
}
