import { eq } from 'drizzle-orm';
import { acquireOAuthOperatorLock, ForbiddenError, operators, teamMembers, type Database } from '@stack/shared';

/** Proof copied only from an already verified dashboard JWT. */
export interface BrowserDecisionSession {
  email: string;
  ownerSessionRevision?: string;
  memberId?: string;
  expiresAt?: number;
  sessionId?: string;
  tokenId?: string;
  authenticatedAt?: number;
}

export async function assertBrowserDecisionSession(
  tx: Parameters<Parameters<Database['transaction']>[0]>[0],
  operatorId: string,
  session: BrowserDecisionSession,
  options: {
    allowedMemberRoles?: readonly ('standard' | 'admin')[];
    requiredConnectionId?: string;
  } = {},
): Promise<void> {
  await acquireOAuthOperatorLock(tx, operatorId);
  const [operator] = await tx.select({ status: operators.status, email: operators.email, revision: operators.owner_session_revision })
    .from(operators).where(eq(operators.id, operatorId)).for('update');
  if (!operator || operator.status !== 'active' || typeof session.email !== 'string' || !session.email.trim()) {
    throw new ForbiddenError('The dashboard session is no longer authorized');
  }
  const email = session.email.trim().toLowerCase();
  if (session.memberId !== undefined) {
    const [member] = await tx.select().from(teamMembers).where(eq(teamMembers.id, session.memberId)).for('update');
    if (!member || member.operator_id !== operatorId || member.status !== 'active'
      || !(options.allowedMemberRoles ?? ['admin']).includes(member.role as 'standard' | 'admin')
      || member.email.trim().toLowerCase() !== email
      || (options.requiredConnectionId !== undefined
        && member.allowed_connections !== null
        && !member.allowed_connections.includes(options.requiredConnectionId))) {
      throw new ForbiddenError('The dashboard member is no longer authorized');
    }
  } else if (operator.email.trim().toLowerCase() !== email || operator.revision !== (session.ownerSessionRevision ?? '0')) {
    throw new ForbiddenError('The dashboard owner session is no longer authorized');
  }
  if (session.expiresAt !== undefined && (!Number.isFinite(session.expiresAt) || session.expiresAt * 1000 <= Date.now())) {
    throw new ForbiddenError('The dashboard session has expired');
  }
}
