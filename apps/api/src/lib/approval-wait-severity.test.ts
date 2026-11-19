import { describe, expect, it } from 'vitest';
import { approvalWaitSeverity } from './approval-wait-severity.js';

describe('the severity of an approval-gate refusal on the model gateway, A2A and skills', () => {
  it.each(['missing', 'wrong_status', 'expired'])('is a warning for %s: the agent is waiting on the person', (reason) => {
    expect(approvalWaitSeverity(reason)).toBe('warning');
  });

  it.each(['wrong_passport', 'already_consumed', 'requires_unmet', 'not_found', 'call_mismatch', 'anything_else'])('stays critical for %s', (reason) => {
    expect(approvalWaitSeverity(reason)).toBe('critical');
  });
});
