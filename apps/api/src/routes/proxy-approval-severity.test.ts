import { describe, it, expect } from 'vitest';
import { approvalGateDenialSeverity } from './proxy.js';

// D2 — approval-gate denial severity. A `critical` here + on_critical:
// block auto-bricks the whole agent, so a fat-finger (missing header, typo'd/
// expired approval) must NOT be critical. Genuine misuse (someone else's
// approval, a replayed one, an unmet requirement) stays critical and keeps
// bricking by design. Fail-closed: unknown reasons stay critical.

describe('approvalGateDenialSeverity (D2)', () => {
  it('grades usage errors as warning (no brick)', () => {
    for (const reason of ['missing', 'not_found', 'expired', 'wrong_status']) {
      expect(approvalGateDenialSeverity(reason), reason).toBe('warning');
    }
  });

  it('keeps genuine-misuse reasons critical (still bricks by design)', () => {
    for (const reason of ['wrong_passport', 'already_consumed', 'requires_unmet']) {
      expect(approvalGateDenialSeverity(reason), reason).toBe('critical');
    }
  });

  it('is fail-closed (critical) on an unrecognized reason', () => {
    expect(approvalGateDenialSeverity('some_future_reason')).toBe('critical');
    expect(approvalGateDenialSeverity('')).toBe('critical');
  });

  it("specifically: the missing-header fat-finger — the tester-agent brick cause — is a warning", () => {
    expect(approvalGateDenialSeverity('missing')).toBe('warning');
  });
});
