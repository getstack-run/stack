// How an approval-gate refusal on the model gateway, A2A and skills is graded.
//
// An agent that retries while its intent waits for the person (`wrong_status`, a pending approval), that sends no
// approval yet (`missing`) or one whose time ran out (`expired`) is waiting correctly, so it is a warning and never
// blocks the agent. Presenting another agent's approval, replaying a spent one or a prerequisite not met stays critical.

const WAITING_REASONS = new Set(['missing', 'wrong_status', 'expired']);

export function approvalWaitSeverity(gateReason: string): 'warning' | 'critical' {
  return WAITING_REASONS.has(gateReason) ? 'warning' : 'critical';
}
