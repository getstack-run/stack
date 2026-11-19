import { eq, and, isNull, inArray, sql } from 'drizzle-orm';
import { DATA_TRAIL_WINDOW_SECONDS, type Database, passportClaims, passports } from '@stack/shared';

/** Observations kept per (Mission, source) for the data-flow rule. */
export const OBSERVATIONS_PER_SOURCE = 100;
/** Distinct sources one Mission's observations may span inside the window before the read refuses. */
export const MAX_OBSERVED_SOURCES = 64;
/** Newest observations of one agent the undeclared-counterparty check reads as the agent's "seen" set. */
export const AGENT_SEEN_OBSERVATIONS = 1000;
/** Sources of any age one read walks past before it refuses (each costs one index probe). */
export const MAX_WALKED_SOURCES = 1024;

/**
 * passport_claims repo. Append-only with soft-revoke; no UPDATE of
 * body_json after attach (claims are tamper-evident by their signed
 * claim_hash). If a body needs to change, attach a new claim and
 * revoke the old.
 *
 * Three call paths:
 *   1. attach — passport-service.attachClaim writes a new row
 *      after validating the body against the registered Zod schema
 *      and signing the claim_hash.
 *   2. cascade-revoke — passport-service.revoke + cascadeRevoke
 *      walk a passport's children and call markAllRevokedByPassportId
 *      for each, marking attached claims as revoked.
 *   3. audit chain binding — audit middleware reads
 *      findActiveHashesByPassportId at write time to populate
 *      audit_log.passport_claims_at_event.
 */
export class PassportClaimsRepository {
  constructor(private db: Database) {}

  // ── Attach ────────────────────────────────────────────────

  async insert(data: typeof passportClaims.$inferInsert) {
    const [row] = await this.db.insert(passportClaims).values(data).returning();
    return row!;
  }

  /**
   * Append a claim under its producer's key: one claim per (operator, source
   * operation, role), so a retry returns the claim already written. A claim on
   * a Passport locks that Passport first (a revoked one is born revoked); an
   * operator-scoped claim (no Passport, such as an account's mail on the data
   * trail) is keyed the same way without a parent to lock.
   */
  async insertFromSource(data: typeof passportClaims.$inferInsert & {
    operator_id: string;
    source_operation_id: string;
    source_role: string;
  }) {
    return this.db.transaction(async (tx) => {
      if (data.passport_id === undefined || data.passport_id === null) {
        const [created] = await tx.insert(passportClaims).values({ ...data, passport_id: null })
          .onConflictDoNothing()
          .returning();
        if (created) return created;
        const existing = await tx.query.passportClaims.findFirst({
          where: and(
            eq(passportClaims.operator_id, data.operator_id),
            eq(passportClaims.source_operation_id, data.source_operation_id),
            eq(passportClaims.source_role, data.source_role),
          ),
        });
        if (!existing) {
          throw new Error('Operator claim idempotency conflict did not resolve to its producer');
        }
        return existing;
      }
      const [parent] = await tx.select({
        jti: passports.jti,
        revoked_at: passports.revoked_at,
        revoked_reason: passports.revoked_reason,
      }).from(passports).where(and(
        eq(passports.jti, data.passport_id as string),
        eq(passports.operator_id, data.operator_id),
      )).for('update');
      if (!parent) throw new Error('Cannot append a source claim to a missing Passport');
      const [created] = await tx.insert(passportClaims).values({
        ...data,
        ...(parent.revoked_at ? {
          revoked_at: parent.revoked_at,
          revoked_reason: parent.revoked_reason ?? 'passport_revoked',
        } : {}),
      })
        .onConflictDoNothing()
        .returning();
      if (created) return created;
      const existing = await tx.query.passportClaims.findFirst({
        where: and(
          eq(passportClaims.operator_id, data.operator_id),
          eq(passportClaims.source_operation_id, data.source_operation_id),
          eq(passportClaims.source_role, data.source_role),
        ),
      });
      if (!existing) {
        throw new Error('Passport claim idempotency conflict did not resolve to its producer');
      }
      return existing;
    });
  }

  // ── Read ────────────────────────────────────────────────────────

  async findByClaimId(claimId: string) {
    return this.db.query.passportClaims.findFirst({
      where: eq(passportClaims.claim_id, claimId),
    });
  }

  async findEvidencePackByPackId(packId: string, operatorId: string) {
    return this.db.query.passportClaims.findFirst({
      where: and(
        eq(passportClaims.operator_id, operatorId),
        eq(passportClaims.type, 'evidence_pack'),
        sql`${passportClaims.body_json}->>'pack_id' = ${packId}`,
      ),
    });
  }

  /**
   * intent_denial dedup lookup.
   *
   * Find an active denial claim on the passport whose attempted_intent
   * has the given named_intent AND whose parameters_hash matches. Used
   * by ClaimRegistryService.recordIntentDenial to fold repeated denials
   * of the same Intent shape into one claim with an incrementing
   * retry_count (per ADR Design Decision 7 / D2 lock).
   *
   * Queries body_json via JSONB path operators — both fields are
   * stored at deterministic locations inside the IntentDenialClaim
   * payload shape.
   */
  async findActiveDenialByDedupKey(
    passportId: string,
    namedIntent: string,
    parametersHash: string,
  ): Promise<typeof passportClaims.$inferSelect | undefined> {
    const rows = await this.db.execute<typeof passportClaims.$inferSelect>(sql`
      SELECT * FROM passport_claims
      WHERE passport_id = ${passportId}
        AND type = 'intent_denial'
        AND revoked_at IS NULL
        AND body_json -> 'attempted_intent' ->> 'named_intent' = ${namedIntent}
        AND body_json ->> 'parameters_hash' = ${parametersHash}
      LIMIT 1
    `);
    return (rows as unknown as typeof passportClaims.$inferSelect[])[0];
  }

  /**
   * Increment metadata.retry_count on an existing intent_denial row.
   * Append-only carve-out per ADR Design Decision 7: the signed
   * envelope stays immutable (envelope_cose, claim_hash, claim_id all
   * unchanged), and the storage-only retry_count counter ticks up
   * inside body_json. Verifier interpretation: signed claim attests
   * the original denial event; metadata.retry_count tracks operational
   * retry behaviour.
   */
  async incrementDenialMetadataRetryCount(claimId: string): Promise<number> {
    const result = await this.db.execute<{ retry_count: number }>(sql`
      UPDATE passport_claims
      SET body_json = jsonb_set(
        body_json,
        '{metadata,retry_count}',
        to_jsonb(COALESCE((body_json -> 'metadata' ->> 'retry_count')::int, 1) + 1)
      )
      WHERE claim_id = ${claimId}
      RETURNING (body_json -> 'metadata' ->> 'retry_count')::int AS retry_count
    `);
    return (result as unknown as { retry_count: number }[])[0]?.retry_count ?? 0;
  }

  async findActiveByPassportId(passportId: string) {
    return this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.passport_id, passportId),
        isNull(passportClaims.revoked_at),
      ),
    });
  }

  /**
   * Observed content for the data-flow rule, narrow enough for the proxy
   * hot path.
   *
   * `findActiveByPassportId` above is the wrong tool here: it is uncapped,
   * unordered, has no `(passport_id, type)` index behind it, and returns
   * full rows including `envelope_cose` — the largest column on the table.
   * Calling it on every proxied request would pull every intent_claim,
   * intent_outcome and detector_signal on the passport just to filter for
   * entity_observation in JavaScript, which is what the intent simulator
   * does today and is exactly what must not happen per-request.
   *
   * This selects three JSONB fields from one claim type, so the work is an
   * index scan plus a narrow projection. Ordered newest-first and capped,
   * because a passport lives at most an hour and the newest observations
   * are the ones a flow decision is about.
   */
  async findObservedContentByPassportId(passportId: string, limit = 200) {
    return this.db
      .select({
        entities: sql<string[] | null>`${passportClaims.body_json}->'entities'`,
        requestEntities: sql<string[] | null>`${passportClaims.body_json}->'request_entities'`,
        fingerprints: sql<string[] | null>`${passportClaims.body_json}->'content_fingerprints'`,
        sourceService: sql<string | null>`${passportClaims.body_json}->>'source_service'`,
      })
      .from(passportClaims)
      .where(
        and(
          eq(passportClaims.passport_id, passportId),
          eq(passportClaims.type, 'entity_observation'),
          isNull(passportClaims.revoked_at),
        ),
      )
      .orderBy(sql`${passportClaims.issued_at_ms} DESC NULLS LAST`)
      .limit(limit);
  }

  /**
   * What an agent has read on this Mission, for the data-flow rule.
   *
   * WHY BY MISSION. Keyed by Passport, the record of what was read was lost
   * every time the Passport changed: a refresh, a delegation to a child, a
   * second root Passport on the same Mission. The data is still in the
   * agent's context after any of those, so the record has to outlive the
   * Passport. The Mission is the job, and every agent action carries exactly
   * one (`requireMissionRef`), so observations are read by `mission_ref`.
   *
   * WHY PER SOURCE. A global newest-200 cap let ~200 unrelated reads push a
   * sensitive source's observations out of the window: read the bank once,
   * read Slack 500 times, then post the balance. Retention is therefore the
   * newest `perSourceLimit` observations FOR EACH source, so unrelated
   * traffic can never evict another source's record. Sources are walked with
   * a skip scan over `pc_observation_mission_source_idx`, so the cost is
   * bounded by sources x perSourceLimit, not by how busy the Mission has been.
   *
   * WHY A TIME WINDOW. An agent account has one standing Mission that is
   * extended in place and never replaced. Counting every observation it ever
   * made would taint every later send with every source it ever read, so only
   * observations recorded within `windowSeconds` (DATA_TRAIL_WINDOW_SECONDS)
   * count. Re-reading a source records it again and keeps it on the trail.
   * The walk over sources is not windowed (a source that went quiet costs one
   * index probe, however old its rows are); a source counts only when its
   * newest observation is inside the window.
   *
   * WHY REVOKED CLAIMS COUNT. Revoking a Passport does not make the agent
   * forget what it read under it, so its observations still constrain where
   * the Mission's content may go. They are not filtered on `revoked_at`.
   *
   * More than `maxSources` sources inside the window, or a walk that would
   * pass `MAX_WALKED_SOURCES` sources of any age, throws rather than silently
   * dropping some: the caller's error path decides (alarm, and fail closed
   * when controls are on). A Mission reaching that many services is not a
   * realistic shape.
   *
   * Observations recorded without a `mission_ref` (before every action
   * carried a Mission) are still read through this Passport, as before.
   */
  async findObservedContentForFlow(input: {
    operatorId: string;
    passportId: string | null;
    missionId: string | null;
    perSourceLimit?: number;
    maxSources?: number;
    windowSeconds?: number;
    /** The clock, for tests. */
    now?: number;
  }): Promise<Array<{ entities: string[] | null; requestEntities: string[] | null; fingerprints: string[] | null; sourceService: string | null }>> {
    if (!input.missionId) return input.passportId ? this.findObservedContentByPassportId(input.passportId) : [];
    const perSource = Math.max(1, Math.min(input.perSourceLimit ?? OBSERVATIONS_PER_SOURCE, 1000));
    const maxSources = Math.max(1, Math.min(input.maxSources ?? MAX_OBSERVED_SOURCES, 256));
    const windowSeconds = Math.max(1, input.windowSeconds ?? DATA_TRAIL_WINDOW_SECONDS);
    const sinceMs = (input.now ?? Date.now()) - windowSeconds * 1000;
    const { operatorId, missionId, passportId } = input;
    const result = await this.db.execute<{
      entities: string[] | null;
      request_entities: string[] | null;
      fingerprints: string[] | null;
      source_service: string | null;
      source_rank: number;
    }>(sql`
      WITH RECURSIVE sources(s, newest, n) AS (
        (SELECT pc.body_json->>'source_service', pc.issued_at_ms, 1
           FROM passport_claims pc
          WHERE pc.operator_id = ${operatorId} AND pc.type = 'entity_observation'
            AND pc.body_json->>'mission_ref' = ${missionId}
            AND pc.body_json->>'source_service' IS NOT NULL
          ORDER BY pc.body_json->>'source_service', pc.issued_at_ms DESC NULLS LAST
          LIMIT 1)
        UNION ALL
        SELECT nxt.s, nxt.newest, sources.n + 1
          FROM sources
          CROSS JOIN LATERAL (
            SELECT pc.body_json->>'source_service' AS s, pc.issued_at_ms AS newest
              FROM passport_claims pc
             WHERE pc.operator_id = ${operatorId} AND pc.type = 'entity_observation'
               AND pc.body_json->>'mission_ref' = ${missionId}
               AND pc.body_json->>'source_service' > sources.s
             ORDER BY pc.body_json->>'source_service', pc.issued_at_ms DESC NULLS LAST
             LIMIT 1
          ) nxt
         WHERE sources.n < ${MAX_WALKED_SOURCES}
      ),
      live AS (
        SELECT s, row_number() OVER (ORDER BY s) AS n FROM sources WHERE newest >= ${sinceMs}
      )
      SELECT o.entities, o.request_entities, o.fingerprints, live.s AS source_service, live.n AS source_rank
        FROM live
        CROSS JOIN LATERAL (
          SELECT pc.body_json->'entities' AS entities,
                 pc.body_json->'request_entities' AS request_entities,
                 pc.body_json->'content_fingerprints' AS fingerprints
            FROM passport_claims pc
           WHERE pc.operator_id = ${operatorId} AND pc.type = 'entity_observation'
             AND pc.body_json->>'mission_ref' = ${missionId}
             AND pc.body_json->>'source_service' = live.s
             AND pc.issued_at_ms >= ${sinceMs}
           ORDER BY pc.issued_at_ms DESC NULLS LAST
           LIMIT ${perSource}
        ) o
       WHERE live.n <= ${maxSources + 1}
      UNION ALL
      SELECT NULL, NULL, NULL, NULL, -1
       WHERE (SELECT max(n) FROM sources) >= ${MAX_WALKED_SOURCES}
      ${passportId ? sql`
      UNION ALL
      SELECT pc.body_json->'entities', pc.body_json->'request_entities', pc.body_json->'content_fingerprints', pc.body_json->>'source_service', 0
        FROM passport_claims pc
       WHERE pc.passport_id = ${passportId} AND pc.type = 'entity_observation' AND pc.revoked_at IS NULL
         AND pc.body_json->>'mission_ref' IS NULL` : sql``}
    `);
    const rows = result as unknown as Array<{
      entities: string[] | null;
      request_entities: string[] | null;
      fingerprints: string[] | null;
      source_service: string | null;
      source_rank: number;
    }>;
    if (rows.some((row) => Number(row.source_rank) < 0 || Number(row.source_rank) > maxSources)) {
      throw new Error(`Mission observations span more than ${maxSources} sources`);
    }
    return rows.map((row) => ({
      entities: row.entities,
      requestEntities: row.request_entities,
      fingerprints: row.fingerprints,
      sourceService: row.source_service,
    }));
  }

  /**
   * Every entity (a host, an address, an account id, as the one-way digest or the text it was recorded as) the
   * agent's recent observations hold, across all of its Missions and Passports. This is the agent's own "seen"
   * set for the undeclared-counterparty check: a counterparty a job dealt with last week is not new to the agent
   * today. Bounded to the newest `limit` observations of the agent, so one read stays cheap however long the
   * agent has been running; no per-Mission or per-source cut applies.
   */
  async findObservedEntitiesForAgent(input: {
    operatorId: string;
    agentId: string;
    limit?: number;
  }): Promise<string[]> {
    const limit = Math.max(1, Math.min(input.limit ?? AGENT_SEEN_OBSERVATIONS, 5000));
    const result = await this.db.execute<{ entity: string }>(sql`
      WITH recent AS (
        SELECT pc.body_json->'entities' AS entities
          FROM passport_claims pc
         WHERE pc.operator_id = ${input.operatorId}
           AND pc.type = 'entity_observation'
           AND pc.body_json->>'agent_id' = ${input.agentId}
         ORDER BY pc.issued_at_ms DESC NULLS LAST
         LIMIT ${limit}
      )
      SELECT DISTINCT jsonb_array_elements_text(entities) AS entity
        FROM recent
       WHERE jsonb_typeof(entities) = 'array'
    `);
    return (result as unknown as Array<{ entity: string }>).map((row) => row.entity);
  }

  /**
   * fetch the most recent active claim of a given type
   * attached to a passport. Generic helper used by:
   *   - BehavioralGenomeService.getLatestForPassport (chain pointer
   *     resolution + mission baseline snapshot)
   *   - BehavioralDriftDetector — fetches the prior
   *     genome to compute z-score diff against
   *
   * Ordering: `issued_at_ms DESC NULLS LAST`. Legacy rows without
   * issued_at_ms sort last; in practice every current claim carries
   * this column. Limit 1 — caller wants the single newest claim.
   */
  async getLatestByType(
    passportId: string,
    claimType: string,
  ): Promise<typeof passportClaims.$inferSelect | undefined> {
    const rows = await this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.passport_id, passportId),
        eq(passportClaims.type, claimType),
        isNull(passportClaims.revoked_at),
      ),
      orderBy: (pc, { sql }) => [sql`${pc.issued_at_ms} DESC NULLS LAST`],
      limit: 1,
    });
    return rows[0];
  }

  /**
   * dedupe lookup for the behavioral_genome producer path.
   *
   * Find an active claim of `claimType` attached to `passportId` whose
   * `body_json.window_start_ms` exactly matches the given value. Used by
   * BehavioralGenomeService.emitForWindow as a crash-safety check:
   * passport_claims has no UNIQUE constraint on (passport_id, type,
   * window_start_ms), so a worker restart that re-enters the rollup loop
   * after partial completion would otherwise produce duplicate genome
   * claims with different ids but identical payloads. This dedupe makes
   * the producer idempotent across crashes + lock TTL boundaries.
   *
   * JSONB text-extract on `body_json->>'window_start_ms'` — compared as
   * text against the millisecond integer's decimal string form. Postgres
   * stores JSONB numbers losslessly so text round-trip is exact for
   * integer millis. Existing pc_passport_id_idx + claim_type filter
   * narrow to a tiny result set before the JSONB predicate runs; no new
   * index needed today.
   *
   * Filter: `revoked_at IS NULL` — revoked rows do NOT count as dedupe
   * hits (a revoked claim is the legitimate trigger to re-emit).
   */
  async findActiveByTypeAndWindow(
    passportId: string,
    claimType: string,
    windowStartMs: number,
  ): Promise<typeof passportClaims.$inferSelect | undefined> {
    const rows = await this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.passport_id, passportId),
        eq(passportClaims.type, claimType),
        isNull(passportClaims.revoked_at),
        sql`${passportClaims.body_json}->>'window_start_ms' = ${windowStartMs.toString()}`,
      ),
      limit: 1,
    });
    return rows[0];
  }

  /**
   * `requires_unmet` runtime
   * enforcement substrate.
   *
   * Returns active `intent_outcome` claim rows whose `claim_id` is in
   * `claimIds` AND whose source passport shares `sessionId`. The
   * `session_id` predicate is how "same delegation chain" is enforced
   * — every passport in a delegation chain inherits the root's
   * session_id (the passports table in packages/shared/src/db/schema/passports.ts + delegate() in passport-service).
   *
   * Used by both `ApprovalGateService.check` (producer-side runtime
   * enforcement) and `IntentSimulationService.simulate` section 2g
   * (simulator-side mirror), via the shared `enforceRequires` helper
   * in `requires-enforcer.ts`. Single code path means simulator and
   * runtime cannot drift.
   *
   * Short-circuits on empty `claimIds` (no SQL fired).
   *
   * Filter pinned: `revoked_at IS NULL` — revoked outcomes do NOT
   * satisfy a `requires` entry. Type filter to `intent_outcome` is
   * performed at the SQL level so the join doesn't drag unrelated
   * rows.
   */
  async findActiveOutcomesByClaimIdsAndSessionId(
    claimIds: string[],
    sessionId: string,
  ): Promise<Array<{ claim_id: string; type: string; body_json: unknown }>> {
    if (claimIds.length === 0) return [];
    // Use drizzle's query builder rather than raw SQL — the postgres-js
    // driver does not auto-serialise JS arrays as Postgres arrays when
    // bound via sql\`\` templates, so `= ANY(${claimIds})` lands as a
    // single comma-joined string (malformed array literal at runtime).
    // The query builder's inArray() emits a parametrised IN (...) list
    // which postgres accepts without ceremony.
    const rows = await this.db
      .select({
        claim_id: passportClaims.claim_id,
        type: passportClaims.type,
        body_json: passportClaims.body_json,
      })
      .from(passportClaims)
      .innerJoin(passports, eq(passports.jti, passportClaims.passport_id))
      .where(
        and(
          inArray(passportClaims.claim_id, claimIds),
          isNull(passportClaims.revoked_at),
          isNull(passports.revoked_at),
          eq(passportClaims.type, 'intent_outcome'),
          eq(passports.session_id, sessionId),
        ),
      );
    return rows as Array<{ claim_id: string; type: string; body_json: unknown }>;
  }

  /**
   * twin runtime divergence eval, detector_signal_set
   * dimension. Find active detector_signal claims whose
   * `body_json.intent_claim_ref` matches one of the provided intent
   * claim ids. Returns claim_id + body_json (the body carries
   * detector_key + severity + intent_claim_ref).
   *
   * Same JSONB pattern as findActiveByTypeAndWindow. Empty input is
   * a no-op (no SQL fires).
   */
  async findDetectorSignalsByIntentRefs(
    intentClaimIds: string[],
  ): Promise<Array<{ claim_id: string; body_json: unknown }>> {
    if (intentClaimIds.length === 0) return [];
    // postgres-js doesn't auto-serialise JS arrays as Postgres arrays
    // when bound via sql`` templates (same trap as
    // findActiveOutcomesByClaimIdsAndSessionId line 197-200). Build a
    // parameterised IN (...) literal via sql.join so each id binds as
    // its own param.
    const rows = await this.db
      .select({
        claim_id: passportClaims.claim_id,
        body_json: passportClaims.body_json,
      })
      .from(passportClaims)
      .where(
        and(
          eq(passportClaims.type, 'detector_signal'),
          isNull(passportClaims.revoked_at),
          sql`${passportClaims.body_json}->>'intent_claim_ref' IN (${sql.join(intentClaimIds.map((id) => sql`${id}`), sql`, `)})`,
        ),
      );
    return rows as Array<{ claim_id: string; body_json: unknown }>;
  }

  /**
   * list active claims of a given type bound to a mission
   * via their payload's `mission_ref` field. Used by DossierService.
   * findByMission (returns zero-or-more dossier envelopes for a mission)
   * and reusable by any future mission-scoped claim-type read paths.
   *
   * JSONB text-extract on `body_json->>'mission_ref'` — same pattern as
   * findActiveByTypeAndWindow (5.1.3) and findDetectorSignalsByIntentRefs
   * (5.3.4). Operator filter is applied alongside so a cross-tenant
   * mission_ref collision (statistically impossible but cheap to gate)
   * cannot leak rows.
   *
   * Ordering: `issued_at_ms ASC NULLS LAST` — chronological emission
   * order. Dossier edits chain via prior_dossier_ref so chronological
   * ordering exposes the edit history naturally. Callers wanting the
   * latest can take the last element.
   *
   * Filter: `revoked_at IS NULL` — revoked dossiers do not surface.
   */
  async findActiveByTypeAndMissionRef(
    claimType: string,
    missionRef: string,
    operatorId: string,
    pagination?: { page: number; limit: number },
  ): Promise<Array<typeof passportClaims.$inferSelect>> {
    return this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.type, claimType),
        eq(passportClaims.operator_id, operatorId),
        isNull(passportClaims.revoked_at),
        sql`${passportClaims.body_json}->>'mission_ref' = ${missionRef}`,
      ),
      orderBy: (pc, { sql, asc }) => [sql`${pc.issued_at_ms} ASC NULLS LAST`, asc(pc.claim_id)],
      ...(pagination ? { limit: pagination.limit + 1, offset: (pagination.page - 1) * pagination.limit } : {}),
    });
  }

  /**
   * Resolve the signed source records that a human dossier can cite.
   * The operator and mission predicates are part of the database read.
   * Unknown and foreign references therefore return the same empty set.
   * Revoked source claims remain valid historical evidence.
   */
  async findDossierSourceClaims(
    operatorId: string,
    missionId: string,
    checkpointIds: string[],
    detectorSignalClaimIds: string[],
  ): Promise<Array<typeof passportClaims.$inferSelect>> {
    const sourcePredicates = [];
    if (checkpointIds.length > 0) {
      sourcePredicates.push(sql`(
        ${passportClaims.type} = 'checkpoint_approval'
        AND ${passportClaims.body_json}->>'mission_ref' = ${missionId}
        AND ${passportClaims.body_json}->>'checkpoint_id' IN (
          ${sql.join(checkpointIds.map((id) => sql`${id}`), sql`, `)}
        )
      )`);
    }
    if (detectorSignalClaimIds.length > 0) {
      sourcePredicates.push(sql`(
        ${passportClaims.type} = 'detector_signal'
        AND ${passportClaims.body_json}->>'mission_ref' = ${missionId}
        AND ${passportClaims.claim_id} IN (
          ${sql.join(detectorSignalClaimIds.map((id) => sql`${id}`), sql`, `)}
        )
      )`);
    }
    if (sourcePredicates.length === 0) return [];

    return this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.operator_id, operatorId),
        sql`(${sql.join(sourcePredicates, sql` OR `)})`,
      ),
      orderBy: (pc, { asc }) => [asc(pc.claim_id)],
    });
  }

  /**
   * claim set for a mission-scope evidence pack export.
   *
   * Union of three predicates over the operator's claims:
   *   - `body_json->>'mission_ref' = ${missionId}` — every later phases
   *     mission-aware claim type (intent_*, detector_signal,
   *     skill_invocation, twin_divergence, dossier, etc.) carries
   *     `mission_ref` (ms_*) when bound to a mission.
   *   - `body_json->>'mission_id' = ${missionId}` — MissionClaim
   *     itself uses `mission_id` (not `mission_ref`) for the binding
   *     field (see schemas/passport-claims/mission.ts).
   *   - passport_id belongs to the mission's operator-scoped passport
   *     set, with optional mission-window bounds for pack export.
   *
   * Ordering: `issued_at_ms ASC NULLS LAST, claim_id ASC` —
   * deterministic chronological order. The pack producer hashes the
   * resulting `claim_hash` list into a Merkle root; ordering MUST be
   * deterministic between producer and verifier.
   *
   * Revocation policy: returns BOTH revoked and active rows. The pack
   * format carries `revoked_at_ms` per claim entry (sampled at export
   * time), so a revoked claim still appears in the pack with its
   * revocation timestamp populated. Excluding revoked rows would
   * silently hide the revocation history a forensic verifier wants.
   *
   * Claims also enter through passports.mission_ids[]. Optional time
   * bounds limit that passport-set branch to the mission window.
   * Direct mission references remain included for terminal mission
   * claims and later human-authored dossier claims.
   */
  async findInMissionScope(
    missionId: string,
    operatorId: string,
    t0Ms?: number,
    t1Ms?: number,
    pagination?: { page: number; limit: number },
  ): Promise<Array<typeof passportClaims.$inferSelect>> {
    // Keep the subquery alias explicit. Drizzle's relational query builder
    // rewrites imported table-column references to the outer
    // `passportClaims` alias inside raw fragments. That produced
    // `SELECT "passportClaims"."jti" FROM passports` at runtime.
    const missionPassportClaim = sql`EXISTS (
      SELECT 1
      FROM passports AS mission_passport
      WHERE mission_passport.jti = ${passportClaims.passport_id}
        AND mission_passport.operator_id = ${operatorId}
        AND mission_passport.mission_ids @> ARRAY[${missionId}]::text[]
    )`;
    const boundedMissionPassportClaim = t0Ms !== undefined && t1Ms !== undefined
      ? sql`(
          ${missionPassportClaim}
          AND ${passportClaims.issued_at_ms} >= ${t0Ms}
          AND ${passportClaims.issued_at_ms} < ${t1Ms}
        )`
      : missionPassportClaim;

    return this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.operator_id, operatorId),
        sql`(
          ${passportClaims.body_json}->>'mission_ref' = ${missionId}
          OR ${passportClaims.body_json}->>'mission_id' = ${missionId}
          OR ${boundedMissionPassportClaim}
        )`,
      ),
      orderBy: (pc, { sql, asc }) => [sql`${pc.issued_at_ms} ASC NULLS LAST`, asc(pc.claim_id)],
      ...(pagination ? { limit: pagination.limit + 1, offset: (pagination.page - 1) * pagination.limit } : {}),
    });
  }

  /**
   * claim set for a session-scope evidence pack export.
   *
   * Joins `passports` so the predicate runs against the passport's
   * `session_id` (the column is on passports, not on passport_claims).
   * Returns every claim attached to ANY passport in the session,
   * including delegated children — they share the root's session_id
   * by construction (passport-service.delegate at issue time).
   *
   * Ordering: deterministic by `(issued_at_ms ASC NULLS LAST,
   * claim_id ASC)` to match the mission-scope pattern.
   *
   * Revocation policy: same as findInMissionScope — returns active
   * AND revoked rows so the pack can carry the revocation snapshot.
   */
  async findInSessionScope(
    sessionId: string,
    operatorId: string,
  ): Promise<Array<typeof passportClaims.$inferSelect>> {
    const rows = await this.db
      .select({
        claim_id: passportClaims.claim_id,
        passport_id: passportClaims.passport_id,
        type: passportClaims.type,
        body_json: passportClaims.body_json,
        claim_hash: passportClaims.claim_hash,
        signature: passportClaims.signature,
        attached_at: passportClaims.attached_at,
        operator_id: passportClaims.operator_id,
        subject: passportClaims.subject,
        envelope_version: passportClaims.envelope_version,
        claim_version: passportClaims.claim_version,
        envelope_cose: passportClaims.envelope_cose,
        issuer: passportClaims.issuer,
        issued_at_ms: passportClaims.issued_at_ms,
        receipt: passportClaims.receipt,
        revoked_at: passportClaims.revoked_at,
        revoked_reason: passportClaims.revoked_reason,
      })
      .from(passportClaims)
      .innerJoin(passports, eq(passports.jti, passportClaims.passport_id))
      .where(
        and(
          eq(passportClaims.operator_id, operatorId),
          eq(passports.session_id, sessionId),
        ),
      )
      .orderBy(
        sql`${passportClaims.issued_at_ms} ASC NULLS LAST`,
        sql`${passportClaims.claim_id} ASC`,
      );
    return rows as unknown as Array<typeof passportClaims.$inferSelect>;
  }

  /**
   * claim set for a period-scope evidence pack export.
   *
   * Half-open interval `[t0_ms, t1_ms)` over `issued_at_ms`. Operator
   * filter applied first (avoids cross-tenant scan). Ordering matches
   * the other scope methods.
   *
   * Boundary-anchor claim handling (per 5.4.0 ADR Design decision 3)
   * is NOT applied here — that's a service-layer concern in 5.4.4 that
   * runs a second query for the most-recent claim per affected
   * passport just below t0_ms. The repo method is the simple time-
   * window predicate; the producer composes the anchor query around it.
   */
  async findInTimeWindow(
    operatorId: string,
    t0Ms: number,
    t1Ms: number,
  ): Promise<Array<typeof passportClaims.$inferSelect>> {
    return this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.operator_id, operatorId),
        sql`${passportClaims.issued_at_ms} >= ${t0Ms}`,
        sql`${passportClaims.issued_at_ms} < ${t1Ms}`,
      ),
      orderBy: (pc, { sql, asc }) => [sql`${pc.issued_at_ms} ASC NULLS LAST`, asc(pc.claim_id)],
    });
  }

  /**
   * Return the final signed claim before t0 for every supplied passport.
   * Callers derive the passport set from operator-scoped in-window rows.
   * DISTINCT ON makes the choice stable when a passport has many claims.
   */
  async findPeriodBoundaryClaims(
    operatorId: string,
    passportIds: string[],
    t0Ms: number,
  ): Promise<Array<typeof passportClaims.$inferSelect>> {
    if (passportIds.length === 0) return [];
    const passportIdList = sql.join(passportIds.map((id) => sql`${id}`), sql`, `);
    return this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.operator_id, operatorId),
        inArray(passportClaims.passport_id, passportIds),
        sql`${passportClaims.issued_at_ms} < ${t0Ms}`,
        sql`(
          ${passportClaims.passport_id},
          ${passportClaims.issued_at_ms},
          ${passportClaims.claim_id}
        ) IN (
          SELECT DISTINCT ON (boundary.passport_id)
            boundary.passport_id,
            boundary.issued_at_ms,
            boundary.claim_id
          FROM passport_claims AS boundary
          WHERE boundary.operator_id = ${operatorId}
            AND boundary.passport_id IN (${passportIdList})
            AND boundary.issued_at_ms < ${t0Ms}
          ORDER BY
            boundary.passport_id,
            boundary.issued_at_ms DESC NULLS LAST,
            boundary.claim_id DESC
        )`,
      ),
      orderBy: (pc, { sql, asc }) => [sql`${pc.issued_at_ms} ASC NULLS LAST`, asc(pc.claim_id)],
    });
  }

  /**
   * Part of the Signed Primitive epic — list active envelope-shape
   * claims by the subject URI (`stack://operator/{op}/passport/{jti}`).
   * Hot path for ClaimRegistryService.listBySubject(); hits the partial
   * index `pc_subject_active_idx` (subject WHERE revoked_at IS NULL).
   *
   * Returns ALL rows for the subject, including legacy JWS-shape rows
   * (envelope_cose IS NULL); the service layer filters or coerces per
   * caller need.
   */
  async findActiveBySubject(subject: string) {
    return this.db.query.passportClaims.findMany({
      where: and(
        eq(passportClaims.subject, subject),
        isNull(passportClaims.revoked_at),
      ),
    });
  }

  /**
   * Used by the audit middleware to assemble the sorted set of
   * attached-claim hashes that will be hashed into the chain entry.
   * Returns hashes only, not full rows — this is a hot path.
   *
   * Sorted by drizzle naturally on text comparison; the caller
   * (computeAuditEntryHash) re-sorts to be safe.
   *
   * CR1 invariant: this resolver returns
   * EVERY active claim attached to the passport, regardless of
   * claim_type. The WHERE clause filters on `passport_id` and
   * `revoked_at IS NULL` only — there is no claim_type predicate. New
   * claim types added by (intent_claim, intent_outcome
   * detector_signal, intent_denial, intent_simulation) participate
   * in the audit chain binding automatically. Verified by the unit
   * test below + the smoke at apps/api/src/scripts/
   * verify-claim-signing-modes.ts step 10 (audit-binding integration).
   * If you ever add a claim_type filter here, you MUST also update
   * the audit chain integrity contract — claims of filtered types
   * would no longer be tamper-bound to the audit chain.
   */
  async findActiveHashesByPassportId(passportId: string): Promise<string[]> {
    // cap the chain-binding array at the top 50
    // most recent active claims, ordered by issued_at_ms DESC. Rationale:
    // a passport that issues 5000 detector_signal claims in a week
    // would otherwise bloat passport_claims_at_event to ~320 KB per
    // audit_log row. Capping at 50 keeps the audit row's claim-binding
    // portion under ~3.2 KB. Verifiers needing the full active claim
    // set can re-query passport_claims directly; the chain hash binds
    // the head, not the tail.
    const rows = await this.db
      .select({ claim_hash: passportClaims.claim_hash })
      .from(passportClaims)
      .where(
        and(
          eq(passportClaims.passport_id, passportId),
          isNull(passportClaims.revoked_at),
        ),
      )
      .orderBy(sql`${passportClaims.issued_at_ms} DESC NULLS LAST`)
      .limit(50);
    return rows.map((r) => r.claim_hash);
  }

  /**
   * Variant for batch audit writes — takes a list of passport ids
   * (e.g. a passport + its delegation parents) and returns ALL active
   * claim hashes attached to any of them. Single round-trip.
   */
  async findActiveHashesByPassportIds(passportIds: string[]): Promise<string[]> {
    if (passportIds.length === 0) return [];
    // same head-cap as findActiveHashesByPassportId
    // scaled up to 50-per-passport. For a delegation chain of N
    // passports, the bound is 50 * N hashes. Worst case 4-hop chain =
    // 200 hashes ≈ 12.8 KB per audit row. Acceptable.
    const rows = await this.db
      .select({ claim_hash: passportClaims.claim_hash })
      .from(passportClaims)
      .where(
        and(
          inArray(passportClaims.passport_id, passportIds),
          isNull(passportClaims.revoked_at),
        ),
      )
      .orderBy(sql`${passportClaims.issued_at_ms} DESC NULLS LAST`)
      .limit(50 * passportIds.length);
    return rows.map((r) => r.claim_hash);
  }

  // ── Cascade-revoke ────────────────────────────────────────

  /**
   * Mark a single claim revoked. Idempotent: re-revoking a revoked
   * claim is a no-op (revoked_at stays unchanged).
   */
  async markRevoked(claimId: string, reason: string, revokedAt: Date = new Date()) {
    await this.db
      .update(passportClaims)
      .set({ revoked_at: revokedAt, revoked_reason: reason })
      .where(
        and(
          eq(passportClaims.claim_id, claimId),
          isNull(passportClaims.revoked_at),
        ),
      );
  }

  /**
   * Mark every active claim attached to a passport revoked. Used by
   * cascade-revoke when the passport itself is revoked. Returns the
   * claim_hashes of the revoked rows so the caller can stamp the
   * audit chain with one claim.revoke entry per cascaded claim.
   */
  async markAllRevokedByPassportId(
    passportId: string,
    reason: string,
    revokedAt: Date = new Date(),
    transaction?: Parameters<Parameters<Database['transaction']>[0]>[0],
  ): Promise<{ claim_id: string; claim_hash: string }[]> {
    const rows = await (transaction ?? this.db)
      .update(passportClaims)
      .set({ revoked_at: revokedAt, revoked_reason: reason })
      .where(
        and(
          eq(passportClaims.passport_id, passportId),
          isNull(passportClaims.revoked_at),
        ),
      )
      .returning({
        claim_id: passportClaims.claim_id,
        claim_hash: passportClaims.claim_hash,
      });
    return rows;
  }

  // ── Retention prune ─────────────────────

  /**
   * Delete passport_claims rows older than the retention window, the same
   * `retentionDays` for every account.
   *
   * Rules:
   *  - Revoked rows: delete when revoked_at < (now - days).
   *  - Active rows: delete when attached_at < (now - days). NOTE:
   *    deleting active claims has a real consequence — the cryptographic
   *    proof is destroyed. For STACK-internal observation claims
   *    (detector_signal, checkpoint_approval, skill_invocation,
   *    identity_claim, etc.) this is acceptable: the legacy projection
   *    table holds the user-facing record, and a Rekor receipt
   *    would be the durable copy when transparency-log publishing ships.
   *  - Dogfood carve-out: rows where operator_id = STACK_SYSTEM_OPERATOR_ID
   *    are NEVER pruned. System claims are low-volume + load-bearing for
   *    audit-chain provenance.
   *
   * Returns the number of rows deleted.
   */
  async pruneExpired(retentionDays: number, stackSystemOperatorId: string): Promise<number> {
    if (!(retentionDays > 0) || !Number.isFinite(retentionDays)) {
      throw new Error('Retention prune needs a positive, finite number of days');
    }
    // postgres-js doesn't auto-convert JS Date objects in sql`` templates
    // to TIMESTAMP literals; pass an ISO string and cast it.
    const cutoffIso = new Date(Date.now() - retentionDays * 86400 * 1000).toISOString();
    const result = await this.db.execute(sql`
      DELETE FROM passport_claims
      WHERE operator_id IS NOT NULL
        AND operator_id != ${stackSystemOperatorId}
        AND operator_id IN (SELECT id FROM operators)
        AND (
          (revoked_at IS NOT NULL AND revoked_at < ${cutoffIso}::timestamptz)
          OR (revoked_at IS NULL AND attached_at < ${cutoffIso}::timestamptz)
        )
    `);
    return (result as unknown as { rowCount?: number }).rowCount ?? 0;
  }
}
