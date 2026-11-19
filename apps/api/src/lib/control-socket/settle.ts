// What an allowed action leaves open, and telling it how the action ended.

import { safeErrorSummary } from '@stack/shared';
import type { ActionOutcome, SettleHook } from './types.js';

/** Tell everything an allowed action left open how it ended. One hook failing never stops the rest. */
export async function runSettle(hooks: readonly SettleHook[], outcome: ActionOutcome): Promise<void> {
  for (const hook of hooks) {
    try {
      await hook(outcome);
    } catch (error) {
      console.error('[CONTROL] settling an allowed action failed', safeErrorSummary(error));
    }
  }
}
