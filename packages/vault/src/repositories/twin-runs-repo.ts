// TwinRunsRepository.
//
// Persistence layer for the `twin_runs` table — one row per mission
// with an active twin run.
//
// Read paths:
//   - findByMissionId — TwinOrchestrationService.startTwinForMission
//     idempotency check + evaluateDivergence lookup
//   - findByRealPassportJti — ClaimRegistryService post-persist hook
//     (5.3.3) to mirror intent_claims under the twin
//
// Write paths:
//   - insert — startTwinForMission opens the run
//   - appendClaimPair — mirrorIntent / mirrorOutcome record real↔twin pairs
//   - markEvaluated — evaluateDivergence terminal transition (CAS on status)
//   - markFailed — terminal failure transition (CAS on status)

import { and, eq, sql } from 'drizzle-orm';
import { type Database, twinRuns } from '@stack/shared';

export type TwinRunRow = typeof twinRuns.$inferSelect;

export type TwinRunStatus = 'running' | 'evaluated' | 'failed';

export interface InsertTwinRunInput {
  id: string;
  mission_id: string;
  real_passport_jti: string;
  twin_passport_jti: string;
}

export interface ClaimPairEntry {
  real_claim_id: string;
  twin_claim_id: string;
  kind: 'intent' | 'outcome';
}

export class TwinRunsRepository {
  constructor(private db: Database) {}

  async insert(input: InsertTwinRunInput): Promise<void> {
    await this.db.insert(twinRuns).values({
      id: input.id,
      mission_id: input.mission_id,
      real_passport_jti: input.real_passport_jti,
      twin_passport_jti: input.twin_passport_jti,
    });
  }

  async findByMissionId(missionId: string): Promise<TwinRunRow | null> {
    const row = await this.db.query.twinRuns.findFirst({
      where: eq(twinRuns.mission_id, missionId),
    });
    return row ?? null;
  }

  async findByRealPassportJti(jti: string): Promise<TwinRunRow | null> {
    const row = await this.db.query.twinRuns.findFirst({
      where: eq(twinRuns.real_passport_jti, jti),
    });
    return row ?? null;
  }

  /**
   * Append a (real, twin) pair to claim_pairs. Idempotent on
   * (real_claim_id, kind) — if the pair is already recorded, the row
   * is a no-op.
   *
   * Uses a single UPDATE with a SQL-side check (NOT EXISTS over the
   * existing array) so concurrent mirrorIntent/mirrorOutcome calls
   * for the same real_claim_id don't double-write.
   */
  async appendClaimPair(args: {
    twinRunId: string;
    realClaimId: string;
    twinClaimId: string;
    kind: 'intent' | 'outcome';
  }): Promise<void> {
    const entry: ClaimPairEntry = {
      real_claim_id: args.realClaimId,
      twin_claim_id: args.twinClaimId,
      kind: args.kind,
    };
    // jsonb_array || jsonb concat — but only if no existing entry has
    // matching (real_claim_id, kind). Postgres-native idempotency.
    await this.db
      .update(twinRuns)
      .set({
        claim_pairs: sql`CASE
          WHEN EXISTS (
            SELECT 1 FROM jsonb_array_elements(${twinRuns.claim_pairs}) AS elt
            WHERE elt->>'real_claim_id' = ${args.realClaimId}
              AND elt->>'kind' = ${args.kind}
          ) THEN ${twinRuns.claim_pairs}
          ELSE ${twinRuns.claim_pairs} || ${JSON.stringify(entry)}::jsonb
        END`,
      })
      .where(eq(twinRuns.id, args.twinRunId));
  }

  /**
   * Terminal: status='evaluated' + divergence_claim_id + evaluated_at=now.
   * CAS on status='running' so repeat calls (or a race against
   * markFailed) return cleanly without overwriting a prior terminal.
   * Returns true on transition, false if the CAS missed (row already
   * in a terminal state).
   */
  async markEvaluated(args: {
    twinRunId: string;
    divergenceClaimId: string;
  }): Promise<boolean> {
    const updated = await this.db
      .update(twinRuns)
      .set({
        status: 'evaluated',
        divergence_claim_id: args.divergenceClaimId,
        evaluated_at: new Date(),
      })
      .where(and(eq(twinRuns.id, args.twinRunId), eq(twinRuns.status, 'running')))
      .returning({ id: twinRuns.id });
    return updated.length > 0;
  }

  /**
   * Terminal: status='failed'. Same CAS shape as markEvaluated.
   * Failure reason captured by the caller in logs / security_events
   * (no dedicated metadata column on twin_runs — keeps the row tight).
   */
  async markFailed(twinRunId: string): Promise<boolean> {
    const updated = await this.db
      .update(twinRuns)
      .set({
        status: 'failed',
        evaluated_at: new Date(),
      })
      .where(and(eq(twinRuns.id, twinRunId), eq(twinRuns.status, 'running')))
      .returning({ id: twinRuns.id });
    return updated.length > 0;
  }
}
