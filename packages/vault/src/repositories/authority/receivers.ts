import { and, desc, eq, gt, inArray, sql } from 'drizzle-orm';
import {
  agents,
  authorityIdempotencyKeys,
  authorityReceiverKeys,
  authorityReceivers,
  generateId,
  serviceConnections,
} from '@stack/shared';
import { sha256 as digest } from '../../services/authority/digest.js';
import type {
  AuthorityReceiverKeyRecord,
  AuthorityReceiverRecord,
  AuthorityRuntimeBoundary,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { receiverKeyRow, receiverRow } from './rows.js';

/** Receivers, their signing keys, verification challenges, and runtime receiver resolution. */
export class AuthorityReceiverRepository extends AuthorityAggregateRepository {
  async findReceiver(operatorId: string, receiverId: string) {
    const [row] = await this.db.select().from(authorityReceivers).where(and(
      eq(authorityReceivers.managed_by_operator_id, operatorId), eq(authorityReceivers.id, receiverId),
    )).limit(1);
    return row ? receiverRow(row) : null;
  }

  async findReceiverById(receiverId: string) {
    const [row] = await this.db.select().from(authorityReceivers).where(eq(authorityReceivers.id, receiverId)).limit(1);
    return row ? receiverRow(row) : null;
  }

  async findReceiverByCanonicalId(identifier: string) {
    const [row] = await this.db.select().from(authorityReceivers).where(eq(authorityReceivers.canonical_identifier, identifier)).limit(1);
    return row ? receiverRow(row) : null;
  }

  async findNativeReceiversByCanonicalId(identifier: string) {
    return (await this.db.select().from(authorityReceivers).where(and(
      eq(authorityReceivers.mode, 'native'), eq(authorityReceivers.canonical_identifier, identifier),
    ))).map(receiverRow);
  }

  async findManagedReceiverByCanonicalId(operatorId: string, identifier: string) {
    const [row] = await this.db.select().from(authorityReceivers).where(and(
      eq(authorityReceivers.managed_by_operator_id, operatorId),
      eq(authorityReceivers.canonical_identifier, identifier),
    )).limit(1);
    return row ? receiverRow(row) : null;
  }

  async isOwnedActiveServiceConnection(operatorId: string, connectionId: string) {
    const [row] = await this.db.select({ id: serviceConnections.id }).from(serviceConnections).where(and(
      eq(serviceConnections.operator_id, operatorId), eq(serviceConnections.id, connectionId),
      eq(serviceConnections.status, 'active'),
    )).limit(1);
    return Boolean(row);
  }

  async findReceiverKey(receiverId: string, keyId: string, use: AuthorityReceiverKeyRecord['use']) {
    const [row] = await this.db.select().from(authorityReceiverKeys).where(and(
      eq(authorityReceiverKeys.receiver_id, receiverId), eq(authorityReceiverKeys.key_id, keyId), eq(authorityReceiverKeys.use, use),
    )).limit(1);
    return row ? receiverKeyRow(row) : null;
  }

  async resolveRuntimeReceivers(operatorId: string, boundary: AuthorityRuntimeBoundary) {
    if (boundary.kind !== 'proxy' && boundary.kind !== 'llm') {
      const identifier = boundary.kind === 'skill' ? `stack:skill:${boundary.skillId}`
        : boundary.kind === 'dropoff' ? `stack:dropoff:${boundary.participantAgentId}` : `stack:agent:${boundary.receiverAgentId}`;
      if (!await this.isOwnedInternalReceiver(operatorId, identifier)) return [];
    }
    const predicate = boundary.kind === 'proxy' || boundary.kind === 'llm'
      ? eq(authorityReceivers.proxy_service_connection_id, boundary.serviceConnectionId)
      : eq(authorityReceivers.canonical_identifier,
        boundary.kind === 'skill' ? `stack:skill:${boundary.skillId}`
          : boundary.kind === 'dropoff' ? `stack:dropoff:${boundary.participantAgentId}` : `stack:agent:${boundary.receiverAgentId}`);
    return (await this.db.select().from(authorityReceivers).where(and(
      eq(authorityReceivers.managed_by_operator_id, operatorId), predicate,
      eq(authorityReceivers.mode, boundary.kind === 'proxy' || boundary.kind === 'llm' ? 'proxy_bridge' : 'internal'),
      eq(authorityReceivers.status, 'active'),
    ))).map(receiverRow);
  }

  async isOwnedInternalReceiver(operatorId: string, identifier: string): Promise<boolean> {
    const match = /^stack:(skill|agent|dropoff):([A-Za-z0-9_-]+)$/.exec(identifier);
    if (!match) return false;
    if (match[1] === 'skill') {
      // A skill is a deployment's own kind of receiver; an install with no skills owns none.
      const directory = this.ctx.receiverDirectories.find((candidate) => candidate.kind === 'skill');
      return directory ? directory.isOwnedActive(operatorId, match[2]!) : false;
    }
    const [row] = await this.db.select({ id: agents.id }).from(agents).where(and(
      eq(agents.id, match[2]!), eq(agents.operator_id, operatorId), eq(agents.status, 'active'),
    )).limit(1);
    return Boolean(row);
  }

  async insertReceiver(row: AuthorityReceiverRecord & {
    canonical_identifier: string; display_name: string; proxy_service_connection_id: string | null; created_at: Date;
  }) {
    const [created] = await this.db.insert(authorityReceivers).values(row).returning();
    return receiverRow(created!);
  }

  async listReceivers(operatorId: string) {
    return (await this.db.select().from(authorityReceivers).where(eq(authorityReceivers.managed_by_operator_id, operatorId))
      .orderBy(desc(authorityReceivers.created_at))).map(receiverRow);
  }

  async createReceiverVerificationChallenge(input: {
    operatorId: string; receiverId: string; challengeId: string; challengeHash: string; expiresAt: Date;
  }) {
    const now = new Date();
    const [row] = await this.db.insert(authorityIdempotencyKeys).values({
      id: generateId('aik'), operator_id: input.operatorId,
      route_key: `receiver.verification:${input.receiverId}`,
      idempotency_key_hash: digest(input.challengeId), request_hash: input.challengeHash,
      state: 'started', response_body: null,
      created_at: now, updated_at: now, expires_at: input.expiresAt,
    }).onConflictDoNothing().returning({ id: authorityIdempotencyKeys.id });
    return Boolean(row);
  }

  async consumeReceiverVerificationChallenge(input: {
    operatorId: string; receiverId: string; challengeId: string; challengeHash: string; now: Date;
  }) {
    const [row] = await this.db.update(authorityIdempotencyKeys).set({
      state: 'completed', response_status: 204, response_body: {}, updated_at: input.now,
    }).where(and(
      eq(authorityIdempotencyKeys.operator_id, input.operatorId),
      eq(authorityIdempotencyKeys.route_key, `receiver.verification:${input.receiverId}`),
      eq(authorityIdempotencyKeys.idempotency_key_hash, digest(input.challengeId)),
      eq(authorityIdempotencyKeys.request_hash, input.challengeHash),
      eq(authorityIdempotencyKeys.state, 'started'), gt(authorityIdempotencyKeys.expires_at, input.now),
    )).returning({ id: authorityIdempotencyKeys.id });
    return Boolean(row);
  }

  async markReceiverVerified(operatorId: string, receiverId: string, now: Date) {
    const [row] = await this.db.update(authorityReceivers).set({
      verified_at: now,
      status: sql`case when ${authorityReceivers.current_profile_version_id} is null then 'pending' else 'active' end`,
    }).where(and(eq(authorityReceivers.managed_by_operator_id, operatorId), eq(authorityReceivers.id, receiverId),
      inArray(authorityReceivers.status, ['pending', 'active']))).returning();
    return row ? receiverRow(row) : null;
  }

  async insertReceiverKey(row: AuthorityReceiverKeyRecord & { created_at: Date; revoked_at: Date | null }) {
    const [created] = await this.db.insert(authorityReceiverKeys).values({
      ...row, public_jwk: row.public_jwk as Record<string, unknown>,
    }).returning();
    return receiverKeyRow(created!);
  }

  async listReceiverKeys(receiverId: string, use?: AuthorityReceiverKeyRecord['use']) {
    const conditions = [eq(authorityReceiverKeys.receiver_id, receiverId)];
    if (use) conditions.push(eq(authorityReceiverKeys.use, use));
    return (await this.db.select().from(authorityReceiverKeys).where(and(...conditions))).map(receiverKeyRow);
  }

  async revokeReceiverKey(operatorId: string, receiverId: string, keyId: string, _reason: string, now: Date) {
    const owned = await this.findReceiver(operatorId, receiverId);
    if (!owned) return null;
    const [row] = await this.db.update(authorityReceiverKeys).set({ status: 'revoked', revoked_at: now })
      .where(and(eq(authorityReceiverKeys.receiver_id, receiverId), eq(authorityReceiverKeys.key_id, keyId),
        eq(authorityReceiverKeys.status, 'active'))).returning();
    return row ? receiverKeyRow(row) : null;
  }
}
