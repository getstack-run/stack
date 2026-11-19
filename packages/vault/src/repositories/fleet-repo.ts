import { and, desc, eq, getTableColumns, gte, inArray, sql } from 'drizzle-orm';
import {
  type Database, type FleetLimits, FleetPolicyInput, ForbiddenError, ConflictError,
  agents, fleetPolicies, fleetPolicyRevisions, fleetMemberships, fleetMissions, acquireOAuthOperatorLock,
  fleetOperations, fleetMissionStarts, missions, generateId, proxyOperations, fleetDigest, sha256,
} from '@stack/shared';

export type FleetTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];
export type FleetPolicyRow = typeof fleetPolicies.$inferSelect;
export type FleetMissionRow = typeof fleetMissions.$inferSelect;
export type FleetMembershipRow = typeof fleetMemberships.$inferSelect;

export class FleetRepository {
  constructor(readonly db: Database) {}

  async policy(operatorId: string, id: string, tx: FleetTransaction | Database = this.db) {
    const [row] = await tx.select().from(fleetPolicies).where(and(eq(fleetPolicies.id, id), eq(fleetPolicies.operator_id, operatorId)));
    if (!row) throw new ForbiddenError();
    const [revision] = await tx.select().from(fleetPolicyRevisions).where(and(eq(fleetPolicyRevisions.policy_id, id), eq(fleetPolicyRevisions.revision, row.revision)));
    if (!revision) throw new ForbiddenError();
    return { ...row, definition: FleetPolicyInput.parse(revision.definition) };
  }

  async list(operatorId: string) {
    const rows = await this.policyListQuery(operatorId);
    return rows.map(row => ({ ...row, definition: FleetPolicyInput.parse(row.definition) }));
  }

  private policyListQuery(operatorId: string) {
    return this.db.select({ ...getTableColumns(fleetPolicies), definition: fleetPolicyRevisions.definition })
      .from(fleetPolicies).innerJoin(fleetPolicyRevisions, and(eq(fleetPolicyRevisions.policy_id, fleetPolicies.id),
        eq(fleetPolicyRevisions.revision, fleetPolicies.revision)))
      .where(eq(fleetPolicies.operator_id, operatorId)).orderBy(desc(fleetPolicies.created_at), fleetPolicies.id);
  }

  async listPage(operatorId: string, page: number, limit: number) {
    const [rows, [count]] = await Promise.all([
      this.policyListQuery(operatorId).limit(limit).offset((page - 1) * limit),
      this.db.select({ total: sql<number>`count(*)::int` }).from(fleetPolicies).where(eq(fleetPolicies.operator_id, operatorId)),
    ]);
    const total = count?.total ?? 0;
    return { items: rows.map(row => ({ ...row, definition: FleetPolicyInput.parse(row.definition) })),
      page, limit, total, has_more: page * limit < total };
  }

  async members(operatorId: string, policyId: string, pagination?: { page: number; limit: number }) {
    await this.policy(operatorId, policyId);
    const where = and(eq(fleetMemberships.operator_id, operatorId), eq(fleetMemberships.policy_id, policyId));
    const query = this.db.select({ id: fleetMemberships.id, agent_id: fleetMemberships.agent_id, agent_name: agents.name,
      identity_expires_at: fleetMemberships.identity_expires_at, revoked_at: fleetMemberships.revoked_at })
      .from(fleetMemberships).innerJoin(agents, and(eq(agents.id, fleetMemberships.agent_id), eq(agents.operator_id, operatorId)))
      .where(where).orderBy(fleetMemberships.id);
    if (!pagination) return query;
    const { page, limit } = pagination;
    const [items, [count]] = await Promise.all([query.limit(limit).offset((page - 1) * limit),
      this.db.select({ total: sql<number>`count(*)::int` }).from(fleetMemberships).where(where)]);
    const total = count?.total ?? 0;
    return { items, page, limit, total, has_more: page * limit < total };
  }

  async memberSummary(operatorId: string, agentId: string) {
    const member = await this.membership(operatorId, agentId);
    if (!member) return null;
    const policy = await this.policy(operatorId, member.policy_id);
    return { policy_id: policy.id, policy_name: policy.definition.name, revision: policy.revision,
      membership_id: member.id, identity_expires_at: member.identity_expires_at,
      revoked_at: member.revoked_at, policy_status: policy.status, policy_expires_at: policy.definition.expires_at };
  }

  async policySummary(operatorId: string, policyId: string, tx: FleetTransaction | Database = this.db) {
    const { root_agent_id: _root, ...policy } = await this.policy(operatorId, policyId, tx);
    const width = policy.definition.window_seconds * 1000;
    const windowStart = new Date(policy.created_at.getTime() + Math.floor((Date.now() - policy.created_at.getTime()) / width) * width);
    const since = windowStart.toISOString();
    const [row] = await tx.select({
      actions: sql<number>`count(*) filter (where ${fleetOperations.created_at} >= ${since})::int`,
      concurrent_actions: sql<number>`count(*) filter (where ${fleetOperations.state} in ('reserved','dispatched','unknown'))::int`,
      reserved_spend_cents: sql<string>`coalesce(sum(${fleetOperations.reserved_spend_cents}) filter (where ${fleetOperations.created_at} >= ${since}),0)`,
      dropoff_bytes: sql<string>`coalesce(sum(${fleetOperations.reserved_bytes}) filter (where ${fleetOperations.created_at} >= ${since}),0)`,
      unknown_actions: sql<number>`count(*) filter (where ${fleetOperations.state} = 'unknown')::int`,
    }).from(fleetOperations).where(and(eq(fleetOperations.operator_id, operatorId), eq(fleetOperations.policy_id, policyId),
      sql`${fleetOperations.state} <> 'cancelled'`));
    return { policy, usage: { actions: row?.actions ?? 0, concurrent_actions: row?.concurrent_actions ?? 0,
      reserved_spend_cents: Number(row?.reserved_spend_cents ?? 0), dropoff_bytes: Number(row?.dropoff_bytes ?? 0),
      unknown_actions: row?.unknown_actions ?? 0 }, window_started_at: windowStart.toISOString(), window_seconds: policy.definition.window_seconds };
  }

  async rootForAgent(agentId: string) {
    const [row] = await this.db.select().from(fleetPolicies).where(eq(fleetPolicies.root_agent_id, agentId));
    return row;
  }

  async membership(operatorId: string, agentId: string, tx: FleetTransaction | Database = this.db) {
    const [row] = await tx.select().from(fleetMemberships).where(and(eq(fleetMemberships.agent_id, agentId), eq(fleetMemberships.operator_id, operatorId)));
    return row;
  }

  async mission(operatorId: string, missionId: string, tx: FleetTransaction | Database = this.db) {
    const [row] = await tx.select().from(fleetMissions).where(and(eq(fleetMissions.mission_id, missionId), eq(fleetMissions.operator_id, operatorId)));
    return row;
  }

  async missionSummary(operatorId: string, missionId: string) {
    return this.db.transaction(async tx => {
      const binding = await this.mission(operatorId, missionId, tx);
      if (!binding) return null;
      const fleet = await this.policySummary(operatorId, binding.policy_id, tx);
      const policy = fleet.policy;
      const totals = async (where: ReturnType<typeof and>) => {
        const [row] = await tx.select({
          actions: sql<number>`count(*)::int`,
          concurrent_actions: sql<number>`count(*) filter (where ${fleetOperations.state} in ('reserved','dispatched','unknown'))::int`,
          reserved_spend_cents: sql<string>`coalesce(sum(${fleetOperations.reserved_spend_cents}),0)`,
          dropoff_bytes: sql<string>`coalesce(sum(${fleetOperations.reserved_bytes}),0)`,
          unknown_actions: sql<number>`count(*) filter (where ${fleetOperations.state} = 'unknown')::int`,
        }).from(fleetOperations).where(and(eq(fleetOperations.operator_id, operatorId), where, sql`${fleetOperations.state} <> 'cancelled'`));
        return { actions: row?.actions ?? 0, concurrent_actions: row?.concurrent_actions ?? 0,
          reserved_spend_cents: Number(row?.reserved_spend_cents ?? 0), dropoff_bytes: Number(row?.dropoff_bytes ?? 0), unknown_actions: row?.unknown_actions ?? 0 };
      };
      const missionUsage = await totals(eq(fleetOperations.mission_id, missionId));
      return {
        policy_id: policy.id, policy_name: policy.definition.name, policy_revision: binding.policy_revision,
        current_policy_revision: policy.revision, policy_status: policy.status,
        agent_id: binding.agent_id, membership_id: binding.membership_id,
        authorized_access: binding.access, authorized_operations: binding.operations,
        limits: binding.limits, usage: missionUsage,
        fleet_limits: policy.definition.limits, fleet_usage: fleet.usage,
        window_started_at: fleet.window_started_at, window_seconds: fleet.window_seconds,
      };
    });
  }

  async withPolicy<T>(operatorId: string, id: string, work: (tx: FleetTransaction, policy: Awaited<ReturnType<FleetRepository['policy']>>) => Promise<T>, lockOperator = false): Promise<T> {
    return this.db.transaction(async tx => {
      if (lockOperator) await acquireOAuthOperatorLock(tx, operatorId);
      const rows = await tx.select({ id: fleetPolicies.id }).from(fleetPolicies).where(and(eq(fleetPolicies.id, id), eq(fleetPolicies.operator_id, operatorId))).for('update');
      if (!rows.length) throw new ForbiddenError();
      return work(tx, await this.policy(operatorId, id, tx));
    });
  }

  async liveMission(operatorId: string, missionId: string, agentId: string, tx: FleetTransaction | Database = this.db, allowDelegate = false) {
    const binding = await this.mission(operatorId, missionId, tx);
    if (!binding) throw new ForbiddenError();
    const policy = await this.policy(operatorId, binding.policy_id, tx);
    const member = await this.membership(operatorId, agentId, tx);
    const missionQuery = tx.select().from(missions).where(and(eq(missions.mission_id, missionId), eq(missions.operator_id, operatorId)));
    const [mission] = await (tx === this.db ? missionQuery : missionQuery.for('share'));
    const [agent] = await tx.select().from(agents).where(and(eq(agents.id, agentId), eq(agents.operator_id, operatorId)));
    const now = Date.now();
    if (policy.status !== 'active' || policy.revoked_at || Date.parse(policy.definition.expires_at) <= now || binding.policy_revision !== policy.revision ||
        !member || member.policy_id !== policy.id || member.revoked_at || member.identity_expires_at.getTime() <= now ||
        (binding.agent_id !== agentId && (!allowDelegate || !policy.definition.allow_delegation)) ||
        (binding.agent_id === agentId && member.id !== binding.membership_id) ||
        !mission || mission.completed_at || mission.revoked_at || mission.expires_at.getTime() <= now ||
        !agent || agent.status !== 'active' || agent.passport_blocked || agent.credential_access !== 'proxy_only' || agent.accountability_mode !== 'enforced') throw new ForbiddenError();
    return { binding, policy, member, mission };
  }

  async claimStart(input: typeof fleetMissionStarts.$inferInsert) {
    const [created] = await this.db.insert(fleetMissionStarts).values(input).onConflictDoNothing().returning();
    if (created) return { row: created, created: true };
    const [existing] = await this.db.select().from(fleetMissionStarts).where(and(eq(fleetMissionStarts.operator_id, input.operator_id), eq(fleetMissionStarts.policy_id, input.policy_id), eq(fleetMissionStarts.agent_id, input.agent_id), eq(fleetMissionStarts.key_hash, input.key_hash)));
    if (!existing || existing.payload_hash !== input.payload_hash) throw new ConflictError('Conflict');
    return { row: existing, created: false };
  }

  async completeStart(id: string, binding: typeof fleetMissions.$inferInsert) {
    return this.db.transaction(async tx => {
      await tx.insert(fleetMissions).values(binding).onConflictDoNothing();
      await tx.update(fleetMissionStarts).set({ state: 'ready' }).where(and(eq(fleetMissionStarts.id, id), eq(fleetMissionStarts.operator_id, binding.operator_id)));
    });
  }

  async reserve(input: {
    operatorId: string; policyId: string; missionId: string; agentId: string;
    operationKeyHash: string; requestHash: string; producer: string; ruleId: string;
    maxSpendCents?: number; bytes?: number; intentClaimId?: string;
  }) {
    return this.withPolicy(input.operatorId, input.policyId, async (tx, policy) => {
      const live = await this.liveMission(input.operatorId, input.missionId, input.agentId, tx, true);
      if (live.policy.id !== input.policyId) throw new ForbiddenError();
      if (!input.intentClaimId) throw new ForbiddenError();
      await this.assertAdmissionLineage(input.operatorId, input.policyId, input.intentClaimId, input.agentId, input.missionId, input.requestHash, tx);
      const [existing] = await tx.select().from(fleetOperations).where(and(eq(fleetOperations.mission_id, input.missionId), eq(fleetOperations.operation_key_hash, input.operationKeyHash)));
      if (existing) {
        if (existing.agent_id !== input.agentId || existing.request_hash !== input.requestHash || existing.producer !== input.producer) throw new ConflictError('Conflict');
        return { operation: existing, replay: true };
      }
      const spend = input.maxSpendCents;
      if ((policy.definition.limits.max_spend_cents !== undefined || live.binding.limits.max_spend_cents !== undefined) && spend === undefined) throw new ForbiddenError();
      if (spend !== undefined && (!Number.isSafeInteger(spend) || spend < 0)) throw new ForbiddenError();
      const bytes = input.bytes ?? 0;
      if (!Number.isSafeInteger(bytes) || bytes < 0) throw new ForbiddenError();
      const now = Date.now();
      // Window boundaries remain anchored to the policy's original creation.
      const width = policy.definition.window_seconds * 1000;
      const windowStart = new Date(policy.created_at.getTime() + Math.floor((now - policy.created_at.getTime()) / width) * width);
      const totals = async (where: ReturnType<typeof and>) => {
        const [row] = await tx.select({ actions: sql<number>`count(*)::int`, spend: sql<string>`coalesce(sum(${fleetOperations.reserved_spend_cents}),0)`, bytes: sql<string>`coalesce(sum(${fleetOperations.reserved_bytes}),0)` }).from(fleetOperations).where(and(where, sql`${fleetOperations.state} <> 'cancelled'`));
        return { actions: row?.actions ?? 0, spend: Number(row?.spend ?? 0), bytes: Number(row?.bytes ?? 0) };
      };
      const fleetTotal = await totals(and(eq(fleetOperations.policy_id, policy.id), gte(fleetOperations.created_at, windowStart)));
      const missionTotal = await totals(eq(fleetOperations.mission_id, input.missionId));
      const concurrent = async (where: ReturnType<typeof and>) => {
        const [row] = await tx.select({ count: sql<number>`count(*)::int` }).from(fleetOperations).where(and(where, inArray(fleetOperations.state, ['reserved', 'dispatched', 'unknown'])));
        return row?.count ?? 0;
      };
      const check = (limits: FleetLimits, used: typeof fleetTotal, active: number) => {
        if (used.actions >= limits.max_actions || active >= limits.max_concurrent_actions ||
            (limits.max_spend_cents !== undefined && used.spend + (spend ?? 0) > limits.max_spend_cents) ||
            (limits.max_dropoff_bytes !== undefined && used.bytes + bytes > limits.max_dropoff_bytes)) throw new ForbiddenError();
      };
      check(policy.definition.limits, fleetTotal, await concurrent(eq(fleetOperations.policy_id, policy.id)));
      check(live.binding.limits, missionTotal, await concurrent(eq(fleetOperations.mission_id, input.missionId)));
      const [operation] = await tx.insert(fleetOperations).values({
        id: generateId('fop'), operator_id: input.operatorId, policy_id: policy.id, policy_revision: policy.revision,
        mission_id: input.missionId, agent_id: input.agentId, operation_key_hash: input.operationKeyHash,
        request_hash: input.requestHash, producer: input.producer, rule_id: input.ruleId,
        intent_claim_id: input.intentClaimId ?? null,
        reserved_spend_cents: spend ?? 0, reserved_bytes: bytes, window_start: windowStart,
      }).returning();
      return { operation: operation!, replay: false };
    });
  }

  async dispatch(operatorId: string, policyId: string, operationId: string, beforeDispatch?: (tx: FleetTransaction) => Promise<void>) {
    return this.withPolicy(operatorId, policyId, async (tx) => {
      const [operation] = await tx.select().from(fleetOperations).where(and(eq(fleetOperations.id, operationId), eq(fleetOperations.operator_id, operatorId), eq(fleetOperations.policy_id, policyId))).for('update');
      if (!operation || operation.state !== 'reserved' || operation.created_at.getTime() + 300_000 <= Date.now()) throw new ConflictError('Conflict');
      if (!operation.intent_claim_id) throw new ForbiddenError();
      await this.liveMission(operatorId, operation.mission_id, operation.agent_id, tx, true);
      await this.assertAdmissionLineage(operatorId, policyId, operation.intent_claim_id, operation.agent_id, operation.mission_id, operation.request_hash, tx);
      await beforeDispatch?.(tx);
      await tx.update(fleetOperations).set({ state: 'dispatched' }).where(eq(fleetOperations.id, operationId));
    });
  }

  /** All delegated ancestors remain live authority. Called again under the
   * policy lock at reservation and dispatch, which serializes member revoke. */
  async assertPassportLineage(operatorId: string, policyId: string, passportJti: string,
    tx: FleetTransaction | Database = this.db, allowExpiredLeaf = false): Promise<void> {
    const rows = await tx.execute(sql`
      WITH RECURSIVE chain AS (
        SELECT p.*, 0 AS hop, p.delegation_depth AS leaf_depth, p.session_id AS leaf_session
        FROM passports p WHERE p.operator_id = ${operatorId} AND p.jti = ${passportJti}
        UNION ALL
        SELECT p.*, c.hop + 1, c.leaf_depth, c.leaf_session
        FROM passports p JOIN chain c ON p.jti = c.parent_passport_id
        WHERE p.operator_id = ${operatorId} AND c.hop < 4
      )
      SELECT count(*) = max(c.leaf_depth) + 1 AND min(c.delegation_depth) = 0
        AND bool_and(c.revoked_at IS NULL AND c.session_id = c.leaf_session
          AND c.delegation_depth = c.leaf_depth - c.hop
          AND (c.expires_at > now() OR (${allowExpiredLeaf} AND c.hop = 0))
          AND a.status = 'active' AND a.passport_blocked = false
          AND CASE WHEN c.delegation_depth = 0
            THEN c.agent_id = policy.root_agent_id AND c.parent_passport_id IS NULL
            ELSE m.id IS NOT NULL AND m.policy_id = policy.id AND m.revoked_at IS NULL AND m.identity_expires_at > now()
          END) AS valid
      FROM chain c JOIN agents a ON a.id = c.agent_id AND a.operator_id = ${operatorId}
      JOIN fleet_policies policy ON policy.id = ${policyId} AND policy.operator_id = ${operatorId} AND policy.status = 'active'
      LEFT JOIN fleet_memberships m ON m.agent_id = c.agent_id AND m.operator_id = ${operatorId}
    `);
    if (rows[0]?.valid !== true) throw new ForbiddenError();
  }

  private async assertAdmissionLineage(operatorId: string, policyId: string, claimId: string,
    agentId: string, missionId: string, requestHash: string, tx: FleetTransaction) {
    const rows = await tx.execute(sql`SELECT passport_id FROM passport_claims
      WHERE claim_id = ${claimId} AND operator_id = ${operatorId} AND type = 'intent_claim'
        AND revoked_at IS NULL
        AND body_json->>'agent_id' = ${agentId} AND body_json->>'mission_ref' = ${missionId}
        AND body_json->'policy_decision'->>'origin' = 'fleet_policy'
        AND body_json->'policy_decision'->>'policy_id' = ${policyId}
        AND body_json->'policy_decision'->>'request_hash' = ${requestHash}
        AND envelope_cose IS NOT NULL`);
    const passportId = rows[0]?.passport_id;
    if (typeof passportId !== 'string') throw new ForbiddenError();
    await this.assertPassportLineage(operatorId, policyId, passportId, tx);
  }

  async linkProxyOperation(input: { operatorId: string; fleetOperationId: string; proxyOperationId: string;
    operationKey: string; requestHash: string }, tx: FleetTransaction) {
    const [fleet] = await tx.select().from(fleetOperations).where(and(eq(fleetOperations.id, input.fleetOperationId),
      eq(fleetOperations.operator_id, input.operatorId))).for('update');
    const [proxy] = await tx.select().from(proxyOperations).where(and(eq(proxyOperations.id, input.proxyOperationId),
      eq(proxyOperations.operator_id, input.operatorId)));
    if (!fleet || !proxy || fleet.producer !== 'proxy' || fleet.agent_id !== proxy.agent_id ||
        fleet.request_hash !== input.requestHash || fleet.operation_key_hash !== fleetDigest(input.operationKey) ||
        proxy.operation_key_hash !== sha256(input.operationKey) ||
        (fleet.proxy_operation_id && fleet.proxy_operation_id !== proxy.id)) throw new ForbiddenError();
    await tx.update(fleetOperations).set({ proxy_operation_id: proxy.id }).where(eq(fleetOperations.id, fleet.id));
  }

  /** Proven durable outcomes release concurrency, retaining the charged action
   * and its conservative spend. An elapsed lease alone is never evidence. */
  async reconcileProxyOutcomes() {
    return this.db.update(fleetOperations).set({ state: 'settled', settled_at: new Date() }).where(and(
      inArray(fleetOperations.state, ['dispatched', 'unknown']),
      sql`exists (select 1 from ${proxyOperations} p where p.id = ${fleetOperations.proxy_operation_id}
        and p.operator_id = ${fleetOperations.operator_id} and p.agent_id = ${fleetOperations.agent_id}
        and ((p.adapter_kind = 'generic' and p.delivery_state = 'response_received' and p.response_hash is not null)
          or (p.adapter_kind = 'stripe' and p.reconciliation_state = 'confirmed'
            and p.reconciliation_provider_status in ('succeeded','failed','canceled')
            and p.reconciliation_evidence_hash is not null and p.contradictory_evidence_hash is null)))`,
    )).returning({ id: fleetOperations.id });
  }

  async settle(operatorId: string, operationId: string, state: 'settled' | 'unknown' | 'cancelled', actualSpendCents?: number) {
    return this.db.transaction(async tx => {
      const [operation] = await tx.select().from(fleetOperations).where(and(eq(fleetOperations.id, operationId), eq(fleetOperations.operator_id, operatorId))).for('update');
      if (!operation) throw new ForbiddenError();
      if (operation.state === 'settled' || operation.state === 'cancelled') return;
      if (state === 'cancelled' && operation.state !== 'reserved') throw new ConflictError('Conflict');
      if (state !== 'cancelled' && operation.state === 'reserved') throw new ConflictError('Conflict');
      if (actualSpendCents !== undefined && (!Number.isSafeInteger(actualSpendCents) || actualSpendCents < 0 || actualSpendCents > operation.reserved_spend_cents)) throw new ForbiddenError();
      await tx.update(fleetOperations).set({ state, settled_at: state === 'unknown' ? null : new Date(), ...(state === 'settled' && actualSpendCents !== undefined ? { reserved_spend_cents: actualSpendCents } : {}) }).where(eq(fleetOperations.id, operationId));
    });
  }

  /** Only reservations that provably never dispatched may be released by time.
   * The dispatch fence rejects expired reservations even before this sweep.
   * Dispatched and unknown work retains its allowance until an outcome proves
   * settlement, including across policy windows and process restarts.
   */
  async recoverExpiredReservations(): Promise<number> {
    const rows = await this.db.execute(sql`
      WITH expired AS (
        SELECT id FROM fleet_operations
        WHERE state = 'reserved' AND created_at <= now() - interval '5 minutes'
        ORDER BY created_at LIMIT 500 FOR UPDATE SKIP LOCKED
      )
      UPDATE fleet_operations AS operation SET state = 'cancelled', settled_at = now()
      FROM expired WHERE operation.id = expired.id AND operation.state = 'reserved'
      RETURNING operation.id
    `);
    return rows.length;
  }
}
