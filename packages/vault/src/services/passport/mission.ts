import { ForbiddenError, NotFoundError } from '@stack/shared';
import type { LiveMission, PassportContext } from './types.js';

/**
 * Resolve the one live Mission a Passport is bound to.
 * Returns null only for a STACK platform Passport, which must carry no
 * Mission. Every other Passport must carry exactly one Mission that
 * exists under this operator and is not completed, revoked or expired.
 */
export async function requireLiveMission(
  ctx: PassportContext,
  operatorId: string,
  missionIds: readonly string[] | undefined,
  platformIntent: unknown,
): Promise<LiveMission | null> {
  if (platformIntent) {
    if (missionIds && missionIds.length > 0) {
      throw new ForbiddenError('A platform Passport is not bound to a Mission');
    }
    return null;
  }
  if (!missionIds || missionIds.length !== 1) {
    throw new ForbiddenError('A Passport must be bound to exactly one Mission');
  }
  const missionId = missionIds[0]!;
  const mission = await ctx.missionLookup().findById(missionId);
  // A foreign Mission reads as missing: existence is not disclosed across operators.
  if (!mission || mission.operator_id !== operatorId) throw new NotFoundError('Mission', missionId);
  if (mission.completed_at) throw new ForbiddenError(`Mission ${missionId} is completed`);
  if (mission.revoked_at) throw new ForbiddenError(`Mission ${missionId} is revoked`);
  if (mission.expires_at.getTime() <= Date.now())
    throw new ForbiddenError(`Mission ${missionId} has expired`);
  return mission;
}

/**
 * A Passport never outlives its Mission. One second is held back because
 * the signer stamps expiry from its own clock read, a moment later.
 */
export function clampToMission(ttl: number, mission: LiveMission | null): number {
  if (!mission) return ttl;
  const remaining = Math.floor((mission.expires_at.getTime() - Date.now()) / 1000) - 1;
  if (remaining <= 0) throw new ForbiddenError(`Mission ${mission.mission_id} has expired`);
  return Math.min(ttl, remaining);
}
