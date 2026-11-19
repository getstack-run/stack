import { describe, expect, it } from 'vitest';
import { ForbiddenError } from '@stack/shared';
import { assertDropoffAgentBinding } from './dropoff-authority.js';

// Mission attribution for drop-offs moved into beginAgentRuntime; its
// invariants (stored-Passport validation, no bare Mission selector, fail closed
// on zero/ambiguous Missions) are tested in agent-runtime.test.ts.
describe('drop-off participant binding', () => {
  it('prevents an authenticated agent from claiming another participant identity', () => {
    expect(() => assertDropoffAgentBinding({ agentId: 'agt_one' } as never, 'agt_two'))
      .toThrow(ForbiddenError);
    expect(() => assertDropoffAgentBinding({ agentId: 'agt_one' } as never, 'agt_one'))
      .not.toThrow();
    expect(() => assertDropoffAgentBinding({} as never, 'agt_two')).not.toThrow();
  });
});
