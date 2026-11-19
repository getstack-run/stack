import { eq } from 'drizzle-orm';
import { acquireOAuthOperatorLock, ForbiddenError, operators, teamMembers, type Database } from '@stack/shared';

/**
 * Re-prove, inside the deciding transaction, that the principal behind a chat
 * confirmation may still approve governance changes for this account: the
 * operator is active, and a member is an ACTIVE ADMIN of exactly this
 * operator. The role comes from the row, never from the access token, so a
 * downgrade bites before the token expires.
 */
export async function assertChatDecisionPrincipal(
  tx: Parameters<Parameters<Database['transaction']>[0]>[0],
  operatorId: string,
  memberId: string | undefined,
): Promise<void> {
  await acquireOAuthOperatorLock(tx, operatorId);
  const [operator] = await tx.select({ status: operators.status })
    .from(operators).where(eq(operators.id, operatorId)).for('update');
  if (!operator || operator.status !== 'active') {
    throw new ForbiddenError('The account is not active');
  }
  if (memberId === undefined) return;
  const [member] = await tx.select({ operator_id: teamMembers.operator_id, status: teamMembers.status, role: teamMembers.role })
    .from(teamMembers).where(eq(teamMembers.id, memberId)).for('update');
  if (!member || member.operator_id !== operatorId || member.status !== 'active' || member.role !== 'admin') {
    throw new ForbiddenError('Approving a governance change requires the admin role');
  }
}
