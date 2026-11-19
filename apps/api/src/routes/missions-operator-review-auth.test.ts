import { describe, expect, it } from 'vitest';
import { ForbiddenError } from '@stack/shared';
import { assertOperatorReviewReader, resolveOperatorReviewAuthor } from './operator-reviews.js';

const ownerSession = { isDashboardSession: true, operatorId: 'op_one' };

describe('Operator review route authorization', () => {
  it('allows the account owner dashboard session to author', () => {
    expect(resolveOperatorReviewAuthor(ownerSession as never)).toEqual({
      kind: 'operator_owner',
      operator_id: 'op_one',
    });
  });

  it.each(['standard', 'admin'] as const)('allows an active %s member dashboard session', (role) => {
    expect(resolveOperatorReviewAuthor({
      ...ownerSession,
      memberId: 'mem_one',
      memberRole: role,
    } as never)).toEqual({
      kind: 'team_member',
      member_id: 'mem_one',
      role_at_signing: role,
    });
  });

  it('rejects a readonly member', () => {
    expect(() => resolveOperatorReviewAuthor({
      ...ownerSession,
      memberId: 'mem_one',
      memberRole: 'readonly',
    } as never)).toThrow(ForbiddenError);
  });

  it.each([
    ['operator API key', { operatorId: 'op_one' }],
    ['OAuth token', { operatorId: 'op_one', memberId: 'mem_one', memberRole: 'admin' }],
    ['agent JWT', { ...ownerSession, agentId: 'agt_one' }],
    ['passport', { ...ownerSession, agentId: 'agt_one' }],
  ])('rejects %s authoring', (_name, request) => {
    expect(() => resolveOperatorReviewAuthor(request as never)).toThrow(ForbiddenError);
  });

  it('allows direct read credentials and readonly sessions', () => {
    expect(() => assertOperatorReviewReader({} as never)).not.toThrow();
    expect(() => assertOperatorReviewReader({ memberRole: 'readonly' } as never)).not.toThrow();
  });

  it('rejects agents and passports from evidence reads', () => {
    expect(() => assertOperatorReviewReader({ agentId: 'agt_one' } as never)).toThrow(ForbiddenError);
  });
});
