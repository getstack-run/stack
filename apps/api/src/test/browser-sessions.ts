import { InvalidApiKeyError, SESSION_JWT_AUDIENCE } from '@stack/shared';
import { assertOperatorActive, type BrowserDecisionSession } from '@stack/vault';
import type { BrowserSessionIdentity, BrowserSessions, VerifiedBrowserSession } from '../lib/browser-session.js';

type SessionServices = {
  operator: { getById(id: string): Promise<BrowserSessionIdentity['operator']> };
  member: { findById(id: string): Promise<NonNullable<BrowserSessionIdentity['member']> | undefined> };
  dashboardSessions: { assertActive(session: VerifiedBrowserSession): Promise<unknown>; assertActiveInTransaction(tx: never, session: VerifiedBrowserSession): Promise<unknown> };
};

/**
 * A Console session as a deployment that has one reads it, over a hand-built services fake's own `operator`, `member`
 * and `dashboardSessions`: the cookie named `stack_session`, the signed-in person rechecked against the account, the
 * proof kept as the decision's evidence. A fake takes it as a getter, so it reads the fake it sits in:
 *
 *   get browserSessions() { return fakeBrowserSessions(this); },
 *
 * STACK's own adapter lives with its hosted code and is checked by the deployment's own tests.
 */
export function fakeBrowserSessions(fake: object): BrowserSessions {
  const services = () => fake as SessionServices;
  return {
    extractCookie(header) {
      const values = (header ?? '').split(';').map((part) => part.trim())
        .filter((part) => part.startsWith('stack_session='))
        .map((part) => part.slice('stack_session='.length));
      if (values.length !== 1 || !values[0]) return null;
      try {
        const token = decodeURIComponent(values[0]);
        return token && token.length <= 4096 && !/\s/.test(token) ? token : null;
      } catch { return null; }
    },
    async identity(session, currentOperator) {
      if (session.aud !== SESSION_JWT_AUDIENCE || typeof session.payload['email'] !== 'string') throw new InvalidApiKeyError();
      await services().dashboardSessions.assertActive(session);
      const email = session.payload['email'].trim().toLowerCase();
      if (!email) throw new InvalidApiKeyError();
      const operator = currentOperator ?? await services().operator.getById(session.sub);
      assertOperatorActive(operator);
      const memberId = session.payload['member_id'];
      if (memberId !== undefined) {
        if (typeof memberId !== 'string' || !memberId || session.payload['is_member'] !== true) throw new InvalidApiKeyError();
        const member = await services().member.findById(memberId);
        if (!member || member.status !== 'active' || member.operator_id !== operator.id
          || !['readonly', 'standard', 'admin'].includes(member.role)
          || member.email.trim().toLowerCase() !== email) throw new InvalidApiKeyError();
        return { operator, member };
      }
      if (session.payload['role'] !== undefined
        || (session.payload['owner_session_revision'] !== undefined && typeof session.payload['owner_session_revision'] !== 'string')
        || (session.payload['is_member'] !== undefined && session.payload['is_member'] !== false)
        || operator.email.trim().toLowerCase() !== email
        || (session.payload['owner_session_revision'] ?? '0') !== (operator.owner_session_revision ?? '0')) throw new InvalidApiKeyError();
      return { operator, member: null };
    },
    decisionSession(session): BrowserDecisionSession {
      return {
        email: session.payload['email'] as string,
        ownerSessionRevision: (session.payload['owner_session_revision'] as string | undefined) ?? '0',
        ...(session.payload['member_id'] !== undefined ? { memberId: session.payload['member_id'] as string } : {}),
        ...(session.payload['exp'] !== undefined ? { expiresAt: session.payload['exp'] as number } : {}),
        ...(session.payload['sid'] !== undefined ? { sessionId: session.payload['sid'] as string } : {}),
        ...(session.payload['jti'] !== undefined ? { tokenId: session.payload['jti'] as string } : {}),
        ...(session.payload['auth_time'] !== undefined ? { authenticatedAt: session.payload['auth_time'] as number } : {}),
      };
    },
    async assertActive(session) {
      await services().dashboardSessions.assertActive(session);
    },
    async assertActiveInTransaction(tx, session) {
      await services().dashboardSessions.assertActiveInTransaction(tx as never, session);
    },
  };
}
