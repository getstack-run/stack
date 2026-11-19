// Side effects of a mission transition: the in-transaction Passport revoke plan, the post-commit
// Redis sync and revocation publish, the behavioural diff over the mission window, and the twin
// divergence evaluation. Everything here is best-effort except the transactional revoke plan; the
// database revoke is authoritative.

import { safeErrorSummary } from '@stack/shared';
import { BehavioralGenomeClaim as BehavioralGenomeClaimSchema } from '@stack/shared';
import type { MissionTransaction } from '../../repositories/mission-repo.js';
import type { BehavioralDiffResult } from '../behavioral-genome-service.js';
import { type MissionServiceDeps } from './types.js';

/**
 * plan the in-transaction revoke of the Mission's Passports.
 * `step` is handed to the repository transition; `rows()` reads what it
 * revoked once the transaction has committed.
 */
export function endBoundPassports(
  deps: MissionServiceDeps,
  operatorId: string,
  missionId: string,
  reason: string,
  revokeAttachedClaims: boolean,
) {
  const revoker = deps.passportRevoker;
  let revoked: Array<{ jti: string; expires_at: Date }> = [];
  return {
    step: revoker
      ? {
          operatorId,
          run: async (tx: MissionTransaction) => {
            revoked = await revoker.revokeInTransaction(tx, {
              operatorId,
              missionId,
              reason,
              revokeAttachedClaims,
            });
          },
        }
      : undefined,
    rows: () => revoked,
  };
}

/** Post-commit: write the Redis revocation flags. The database revoke already committed and is authoritative. */
export async function syncEndedPassports(
  deps: MissionServiceDeps,
  rows: Array<{ jti: string; expires_at: Date }>,
): Promise<string[]> {
  if (rows.length > 0 && deps.passportRevoker) {
    try {
      await deps.passportRevoker.afterCommit(rows);
    } catch (err) {
      // verify() falls back to the database on a Redis miss, so a failed
      // cache write cannot resurrect a revoked Passport.
      console.error(
        '[MissionService] Redis revocation sync failed after Mission end:',
        safeErrorSummary(err),
      );
    }
  }
  return rows.map((row) => row.jti);
}

export async function publishMissionEnd(
  deps: MissionServiceDeps,
  operatorId: string,
  missionId: string,
  reason: string,
  jtis: string[],
): Promise<void> {
  if (!deps.publishMissionRevocation) return;
  try {
    await deps.publishMissionRevocation({
      operator_id: operatorId,
      mission_id: missionId,
      revoke_reason: reason,
      cascaded_passport_jtis: jtis,
    });
  } catch (err) {
    console.error(
      '[MissionService] publishMissionRevocation failed:', missionId,
      safeErrorSummary(err),
    );
  }
}

/**
 * Fire twin runtime divergence evaluation at mission
 * close. Best-effort: failure logs + returns. Mission terminal claim
 * is already signed + persisted when this fires, so a twin eval
 * crash never rolls back the mission. Mirrors the behavioral_diff
 * + publishMissionRevocation best-effort shape.
 *
 * Fire-and-forget by design — the divergence claim chains
 * independently off the passport; the caller doesn't need to await
 * it. No-twin-run case returns cleanly inside
 * TwinOrchestrationService.evaluateDivergence so no gating needed
 * here.
 */
export function fireTwinDivergenceEvaluation(
  deps: MissionServiceDeps,
  missionId: string,
  operatorId: string,
  phase: 'complete' | 'revoke',
): void {
  if (!deps.twinOrchestration) return;
  deps.twinOrchestration
    .evaluateDivergence({ missionId, operatorId })
    .catch((err: unknown) => {
      console.error(
        '[MissionService] evaluateDivergence failed:', phase, missionId,
        safeErrorSummary(err),
      );
    });
}

/**
 * Compute behavioral_diff for the mission window.
 *
 * Best-effort: any failure (no behavioralGenome wired, no passport_jti
 * on the mission, no baseline_profile, baseline fails
 * BehavioralGenomeClaim parse, computeMissionWindowGenome throws,
 * computeDiffFromPayloads throws) returns null. The mission lifecycle
 * completes regardless of diff success; the diff is evidence, not a
 * gating signal.
 *
 * Used by complete() and revoke() so the diff shape is consistent
 * across all terminal states.
 */
export async function computeMissionDiff(
  deps: MissionServiceDeps,
  passportJti: string | null,
  baselineProfile: Record<string, unknown> | null,
  startedAtMs: number,
  missionId: string,
): Promise<BehavioralDiffResult | null> {
  if (!passportJti || !baselineProfile || !deps.behavioralGenome) {
    return null;
  }
  try {
    const baselineParse = BehavioralGenomeClaimSchema.safeParse(baselineProfile);
    if (!baselineParse.success) {
      console.warn(
        '[MissionService] baseline parse failed so diff skipped:', missionId,
      );
      return null;
    }
    const missionWindowGenome = await deps.behavioralGenome.computeMissionWindowGenome(
      passportJti,
      startedAtMs,
    );
    return deps.behavioralGenome.computeDiffFromPayloads(
      missionWindowGenome,
      baselineParse.data,
    );
  } catch (err) {
    console.warn(
      '[MissionService] behavioral_diff computation failed:', missionId,
      safeErrorSummary(err),
    );
    return null;
  }
}
