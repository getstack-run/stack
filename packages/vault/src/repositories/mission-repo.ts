// MissionRepository.
//
// The signed MissionClaim envelope in passport_claims is canonical;
// this table is a denormalized cache for fast filtering at the proxy
// gate hot path. Every lifecycle transition (complete / revoke) emits
// a NEW mission claim (claims are immutable) and updates the row's
// claim_id pointer to the latest. To walk the prior-version chain for
// a mission_id, query passport_claims WHERE body_json->>'mission_id'
// = ? ORDER BY issued_at_ms.
//
// Cap-counting helpers (countIntentsByMissionId, etc.) take the
// stable mission_id (ms_*) directly. Producer convention post-5.0.4:
// mission_ref on intent_claim and the other six retrofitted claim
// schemas points to the mission_id (ms_*) — stable across the
// mission's lifecycle. This keeps cap queries O(1)-indexed on
// passport_claims.body_json without needing to resolve mission_id →
// claim_id at every check.

import { and, asc, desc, eq, inArray, isNull, lt, or, sql } from 'drizzle-orm';
import {
  type Database,
  acquireOAuthOperatorLock,
  ConflictError,
  missions,
  missionOutputs,
  passports,
  passportClaims,
  dropoffs,
} from '@stack/shared';
import { PassportClaimsRepository } from './passport-claims-repo.js';

export type MissionTerminalState =
  | 'completed_successful'
  | 'completed_expired'
  | 'completed_cap_breached'
  | 'revoked_adversarial'
  | 'revoked_operator_clean';

export type MissionTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export type MissionRevokeReason =
  | 'adversarial'
  | 'cap_breach_hard'
  | 'operator_initiated_clean'
  | 'cascade_from_passport';

export class MissionRepository {
  constructor(private db: Database) {}

  // ── CRUD ────────────────────────────────────────────────────────

  async insert(data: typeof missions.$inferInsert) {
    const [row] = await this.db.insert(missions).values(data).returning();
    return row!;
  }

  /** The signed authority record and its operational row must commit together. */
  async createWithClaim(
    data: Omit<typeof missions.$inferInsert, 'claim_id'>,
    signAndPersist: (writer: Pick<PassportClaimsRepository, 'insert'>) => Promise<string>,
  ) {
    return this.db.transaction(async (tx) => {
      const claimId = await signAndPersist(new PassportClaimsRepository(tx as unknown as Database));
      const [row] = await tx.insert(missions).values({ ...data, claim_id: claimId }).returning();
      return row!;
    });
  }

  async findById(missionId: string) {
    return this.db.query.missions.findFirst({
      where: eq(missions.mission_id, missionId),
    });
  }

  async transitionWithClaim(
    missionId: string,
    expectedClaimId: string,
    patch: Parameters<MissionRepository['updateLifecycle']>[1],
    signAndPersist: (writer: Pick<PassportClaimsRepository, 'insert'>) => Promise<string>,
    output?: Omit<typeof missionOutputs.$inferInsert, 'mission_id' | 'operator_id'>,
    /**
     * ends the Mission's Passports in the same transaction as the
     * Mission's terminal state. The operator lock is taken first, before the
     * Mission row lock, matching the order Passport issuance uses. A throw
     * rolls the whole transition back.
     */
    endBoundPassports?: { operatorId: string; run: (tx: MissionTransaction) => Promise<void> },
  ) {
    return this.db.transaction(async tx => {
      if (endBoundPassports) await acquireOAuthOperatorLock(tx, endBoundPassports.operatorId);
      const [current] = await tx.select().from(missions).where(eq(missions.mission_id, missionId)).for('update');
      if (!current || current.claim_id !== expectedClaimId || current.completed_at || current.revoked_at) throw new ConflictError('Conflict');
      if (endBoundPassports && current.operator_id !== endBoundPassports.operatorId) throw new ConflictError('Conflict');
      if (output) await tx.insert(missionOutputs).values({ ...output, mission_id: missionId, operator_id: current.operator_id });
      const claimId = await signAndPersist(new PassportClaimsRepository(tx as unknown as Database));
      const [row] = await tx.update(missions).set({ ...patch, claim_id: claimId }).where(eq(missions.mission_id, missionId)).returning();
      if (endBoundPassports) await endBoundPassports.run(tx);
      return row!;
    });
  }

  async findOutput(operatorId: string, missionId: string) {
    const [row] = await this.db.select({
      output_encrypted: missionOutputs.output_encrypted,
      output_digest: missionOutputs.output_digest,
      claim: passportClaims.body_json,
    }).from(missionOutputs)
      .innerJoin(missions, eq(missions.mission_id, missionOutputs.mission_id))
      .innerJoin(passportClaims, eq(passportClaims.claim_id, missions.claim_id))
      .where(and(eq(missionOutputs.operator_id, operatorId), eq(missionOutputs.mission_id, missionId)));
    return row;
  }

  /**
   * Update the row's claim_id pointer + lifecycle fields. Called on
   * every lifecycle transition (complete / revoke). The transition
   * itself emits a new signed mission claim via ClaimRegistryService;
   * this updates the denormalized cache to point at the latest.
   *
   * Lifecycle field updates are partial — pass only the fields that
   * change. Idempotent at the SQL level (UPDATE always succeeds even
   * if the row is already in the target state); MissionService is the
   * gate that enforces "can't transition from terminal".
   */
  async updateLifecycle(
    missionId: string,
    patch: {
      claim_id?: string;
      completed_at?: Date | null;
      revoked_at?: Date | null;
      revoked_reason?: MissionRevokeReason | null;
      terminal_state?: MissionTerminalState | null;
      expires_at?: Date;
      coverage_cap_cents?: number | null;
    },
  ) {
    const [row] = await this.db
      .update(missions)
      .set(patch)
      .where(eq(missions.mission_id, missionId))
      .returning();
    return row ?? null;
  }

  // ── Pausing ─────────────────────────────────────────────────────

  /**
   * A cap paused the Mission: one conditional update, so of parallel calls that reach the cap one pauses it and the rest
   * find it paused. Only a live Mission that is not already paused. Returns the row when this call paused it.
   */
  async pause(missionId: string, cap: string, service: string | null) {
    const [row] = await this.db
      .update(missions)
      .set({ paused_at: sql`now()`, paused_cap: cap, paused_service: service })
      .where(and(
        eq(missions.mission_id, missionId),
        isNull(missions.paused_at),
        isNull(missions.completed_at),
        isNull(missions.revoked_at),
      ))
      .returning();
    return row ?? null;
  }

  /**
   * The owner let a paused Mission go on: the pause is cleared, with the raised limit when there is one. Only a live
   * Mission still paused. Returns the row when this call resumed it.
   */
  async resume(
    missionId: string,
    operatorId: string,
    raised: Partial<Pick<typeof missions.$inferInsert, 'max_actions' | 'max_dropoff_bytes' | 'coverage_cap_cents' | 'max_duration_seconds' | 'max_concurrent_intents' | 'max_actions_per_service'>> = {},
  ) {
    const [row] = await this.db
      .update(missions)
      .set({ ...raised, paused_at: null, paused_cap: null, paused_service: null })
      .where(and(
        eq(missions.mission_id, missionId),
        eq(missions.operator_id, operatorId),
        sql`${missions.paused_at} IS NOT NULL`,
        isNull(missions.completed_at),
        isNull(missions.revoked_at),
      ))
      .returning();
    return row ?? null;
  }

  /** The owner's pre-approval of the Mission's print-on-demand orders. Only a live Mission of this operator. */
  async setMakingAllowance(missionId: string, operatorId: string, cents: number | null) {
    const [row] = await this.db
      .update(missions)
      .set({ making_orders_up_to_cents: cents })
      .where(and(
        eq(missions.mission_id, missionId),
        eq(missions.operator_id, operatorId),
        isNull(missions.completed_at),
        isNull(missions.revoked_at),
      ))
      .returning();
    return row ?? null;
  }

  /**
   * Change the recipient pins of a live Mission of this operator, in one transaction with the row locked so two additions
   * at once both land. `merge` is handed the pins as stored. Answers `missing` for a Mission that is not the operator's and
   * `ended` for one completed, revoked or past its expiry.
   */
  async updateRecipientPins(
    operatorId: string,
    missionId: string,
    merge: (current: unknown) => Array<{ path: string; op: 'eq' | 'in'; value: string | number | string[] }>,
  ): Promise<{ status: 'updated'; row: typeof missions.$inferSelect } | { status: 'missing' | 'ended' }> {
    return this.db.transaction(async (tx) => {
      const [row] = await tx.select().from(missions)
        .where(and(eq(missions.mission_id, missionId), eq(missions.operator_id, operatorId)))
        .for('update')
        .limit(1);
      if (!row) return { status: 'missing' as const };
      if (row.completed_at !== null || row.revoked_at !== null || row.expires_at.getTime() <= Date.now()) return { status: 'ended' as const };
      const [updated] = await tx.update(missions).set({ recipient_pins: merge(row.recipient_pins) })
        .where(eq(missions.mission_id, missionId))
        .returning();
      return { status: 'updated' as const, row: updated! };
    });
  }

  // ── Listing ─────────────────────────────────────────────────────

  /**
   * List missions for an operator. Filters:
   *   - status='active'    → completed_at IS NULL AND revoked_at IS NULL
   *   - status='completed' → completed_at IS NOT NULL AND revoked_at IS NULL
   *   - status='revoked'   → revoked_at IS NOT NULL
   *   - status='paused'    → a live Mission a cap paused, waiting for the owner's review
   *   - status omitted     → all (newest started_at first)
   */
  async listByOperator(
    operatorId: string,
    opts?: {
      status?: 'active' | 'completed' | 'revoked' | 'paused';
      agentId?: string;
      page?: number;
      limit?: number;
    },
  ) {
    const limit = opts?.limit ?? 50;
    const offset = ((opts?.page ?? 1) - 1) * limit;
    const baseWhere = this.operatorFilter(operatorId, opts?.agentId);
    let where = baseWhere;
    if (opts?.status === 'active') {
      where = and(baseWhere, isNull(missions.completed_at), isNull(missions.revoked_at))!;
    } else if (opts?.status === 'completed') {
      where = and(baseWhere, sql`${missions.completed_at} IS NOT NULL`, isNull(missions.revoked_at))!;
    } else if (opts?.status === 'revoked') {
      where = and(baseWhere, sql`${missions.revoked_at} IS NOT NULL`)!;
    } else if (opts?.status === 'paused') {
      where = and(baseWhere, sql`${missions.paused_at} IS NOT NULL`, isNull(missions.completed_at), isNull(missions.revoked_at))!;
    }
    return this.db.query.missions.findMany({
      where,
      orderBy: [desc(missions.started_at), desc(missions.mission_id)],
      limit,
      offset,
    });
  }

  async countByOperator(operatorId: string, status?: 'active' | 'completed' | 'revoked' | 'paused', agentId?: string) {
    const baseWhere = this.operatorFilter(operatorId, agentId);
    let where = baseWhere;
    if (status === 'active') {
      where = and(baseWhere, isNull(missions.completed_at), isNull(missions.revoked_at))!;
    } else if (status === 'completed') {
      where = and(baseWhere, sql`${missions.completed_at} IS NOT NULL`, isNull(missions.revoked_at))!;
    } else if (status === 'revoked') {
      where = and(baseWhere, sql`${missions.revoked_at} IS NOT NULL`)!;
    } else if (status === 'paused') {
      where = and(baseWhere, sql`${missions.paused_at} IS NOT NULL`, isNull(missions.completed_at), isNull(missions.revoked_at))!;
    }
    const result = await this.db
      .select({ c: sql<number>`count(*)::int` })
      .from(missions)
      .where(where);
    return result[0]?.c ?? 0;
  }

  async hasAgent(missionId: string, operatorId: string, agentId: string) {
    const row = await this.db.query.missions.findFirst({
      columns: { mission_id: true },
      where: and(eq(missions.mission_id, missionId), this.operatorFilter(operatorId, agentId)),
    });
    return !!row;
  }

  private operatorFilter(operatorId: string, agentId?: string) {
    // Expiry/revocation does not erase history. The mission's baseline-source
    // passport_jti is not a runtime-authority relationship.
    return and(
      eq(missions.operator_id, operatorId),
      agentId ? sql`(${missions.assigned_agent_id} = ${agentId} OR EXISTS (
        SELECT 1 FROM passports AS mission_passport
        WHERE mission_passport.operator_id = ${operatorId}
          AND mission_passport.agent_id = ${agentId}
          AND mission_passport.mission_ids @> ARRAY[${missions.mission_id}]::text[]
      ))` : undefined,
    )!;
  }

  async listPassports(operatorId: string, missionId: string, opts: { agentId?: string; page?: number; limit?: number }) {
    const page = opts.page ?? 1;
    const limit = opts.limit ?? 20;
    const where = and(
      eq(passports.operator_id, operatorId),
      sql`${passports.mission_ids} @> ARRAY[${missionId}]::text[]`,
      opts.agentId ? eq(passports.agent_id, opts.agentId) : undefined,
    );
    const [items, counts] = await Promise.all([
      this.db.query.passports.findMany({
        where, orderBy: [desc(passports.issued_at), desc(passports.jti)],
        limit, offset: (page - 1) * limit,
      }),
      this.db.select({ c: sql<number>`count(*)::int` }).from(passports).where(where),
    ]);
    const total = counts[0]?.c ?? 0;
    return { items, page, limit, total, has_more: page * limit < total };
  }

  /** One bounded query for the evidence badges on a page of missions. */
  async countEvidenceByMissionIds(
    operatorId: string,
    missionIds: string[],
  ): Promise<Map<string, { dossier_count: number; evidence_pack_count: number }>> {
    if (missionIds.length === 0) return new Map();
    const dossierMissionRef = sql<string>`${passportClaims.body_json}->>'mission_ref'`;
    const packMissionRef = sql<string>`${passportClaims.body_json}->'scope'->>'ref'`;
    const missionRef = sql<string>`CASE
      WHEN ${passportClaims.type} = 'dossier' THEN ${dossierMissionRef}
      ELSE ${packMissionRef}
    END`;
    const rows = await this.db
      .select({
        mission_id: missionRef,
        dossier_count: sql<number>`count(*) FILTER (WHERE ${passportClaims.type} = 'dossier')::int`,
        evidence_pack_count: sql<number>`count(*) FILTER (WHERE ${passportClaims.type} = 'evidence_pack')::int`,
      })
      .from(passportClaims)
      .where(and(
        eq(passportClaims.operator_id, operatorId),
        isNull(passportClaims.revoked_at),
        or(
          and(
            eq(passportClaims.type, 'dossier'),
            inArray(dossierMissionRef, missionIds),
          ),
          and(
            eq(passportClaims.type, 'evidence_pack'),
            sql`${passportClaims.body_json}->'scope'->>'kind' = 'mission'`,
            inArray(packMissionRef, missionIds),
          ),
        ),
      ))
      .groupBy(missionRef);
    return new Map(rows.map((row) => [row.mission_id, {
      dossier_count: row.dossier_count,
      evidence_pack_count: row.evidence_pack_count,
    }]));
  }

  // ── Worker helpers ──────────────────────────────────────────────

  /**
   * Sweep helper for the expiry worker (5.0.6). Returns mission rows
   * whose expires_at has passed AND that are still active (not
   * completed, not revoked). Caller calls MissionService.complete with
   * terminal_state='completed_expired' for each.
   */
  async findExpiredActive(now: Date = new Date(), limit = 100) {
    return this.db
      .select()
      .from(missions)
      .where(
        and(
          isNull(missions.completed_at),
          isNull(missions.revoked_at),
          lt(missions.expires_at, now),
        )!,
      )
      .orderBy(asc(missions.expires_at))
      .limit(limit);
  }

  // ── Cap-counting helpers (proxy gate hot path) ──────────────────
  //
  // These take the stable mission_id (ms_*) directly. Post-5.0.4
  // producer convention: `mission_ref` on every cap-counted claim
  // type IS the mission_id, so these queries are a single JSONB
  // extraction with no claim-id resolution hop.

  /**
   * Count intent_claim claims emitted under a mission. Used to
   * enforce `max_actions` cap. Counts only non-revoked claims (a
   * revoked claim was either a mistake or got cascade-revoked when
   * its passport revoked — either way, it doesn't count against the
   * cap that's protecting against runaway behavior).
   */
  async countIntentsByMissionId(missionId: string): Promise<number> {
    const result = await this.db
      .select({ c: sql<number>`count(*)::int` })
      .from(passportClaims)
      .where(
        and(
          eq(passportClaims.type, 'intent_claim'),
          sql`${passportClaims.body_json}->>'mission_ref' = ${missionId}`,
          isNull(passportClaims.revoked_at),
        )!,
      );
    return result[0]?.c ?? 0;
  }

  /**
   * Count intents under a mission grouped by service (the intent's
   * `target` field on the http_call variant — for skill_invocation and
   * other intent_types, target is the skill_id / etc.). Used to enforce
   * `max_actions_per_service` cap. Returns a map service → count.
   */
  async countIntentsByMissionIdGroupedByService(
    missionId: string,
  ): Promise<Record<string, number>> {
    const rows = await this.db
      .select({
        service: sql<string>`${passportClaims.body_json}->>'target'`,
        c: sql<number>`count(*)::int`,
      })
      .from(passportClaims)
      .where(
        and(
          eq(passportClaims.type, 'intent_claim'),
          sql`${passportClaims.body_json}->>'mission_ref' = ${missionId}`,
          isNull(passportClaims.revoked_at),
        )!,
      )
      .groupBy(sql`${passportClaims.body_json}->>'target'`);
    const out: Record<string, number> = {};
    for (const r of rows) {
      if (r.service) out[r.service] = r.c;
    }
    return out;
  }

  /**
   * Count intents that are currently in-flight (intent_claim exists
   * with no paired intent_outcome yet). Used to enforce
   * `max_concurrent_intents` cap. Approximate — a few-second race
   * between outcome emission and this query is tolerable for a cap
   * that exists to catch runaway-loop shapes, not exact accounting.
   */
  async countInflightIntentsByMissionId(
    missionId: string,
  ): Promise<number> {
    // Intent claims under this mission
    const intentClaimsForMission = this.db
      .$with('intent_claims_for_mission')
      .as(
        this.db
          .select({ claim_id: passportClaims.claim_id })
          .from(passportClaims)
          .where(
            and(
              eq(passportClaims.type, 'intent_claim'),
              sql`${passportClaims.body_json}->>'mission_ref' = ${missionId}`,
              isNull(passportClaims.revoked_at),
            )!,
          ),
      );
    // Intent outcomes referencing those claim_ids
    const result = await this.db
      .with(intentClaimsForMission)
      .select({ c: sql<number>`count(*)::int` })
      .from(intentClaimsForMission)
      .where(
        sql`${intentClaimsForMission.claim_id} NOT IN (
          SELECT (body_json->>'intent_claim_ref') FROM passport_claims
          WHERE type = 'intent_outcome' AND revoked_at IS NULL
        )`,
      );
    return result[0]?.c ?? 0;
  }

  // ── Cap-counting helper — dropoff sums (5.0.5b) ──────
  //
  // Uses the mission_id column on dropoffs (migration 0008). A partial index
  // means the query is cheap: the index only contains rows under a mission.
  // The wallet's side of the Mission's cost cap is `MissionSpendSource`.

  /** Sum immutable deposited plaintext bytes attributable to a mission. */
  async sumDropoffBytesByMission(missionId: string): Promise<number> {
    const result = await this.db
      .select({
        s: sql<number>`COALESCE(SUM(${dropoffs.deposited_bytes}), 0)::bigint`,
      })
      .from(dropoffs)
      .where(eq(dropoffs.mission_id, missionId));
    return Number(result[0]?.s ?? 0);
  }
}
