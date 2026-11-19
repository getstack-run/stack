import { and, eq, sql } from 'drizzle-orm';
import {
  ConflictError,
  authorityIdempotencyKeys,
  canonicalize,
  generateId,
} from '@stack/shared';
import { sha256 as digest } from '../../services/authority/digest.js';
import type { AuthorityRepositoryPort } from '../../services/authority/port.js';
import { AuthorityAggregateRepository } from './context.js';

/** The authority idempotency ledger: replayable mutations and one-time assertion identifiers. */
export class AuthorityLedgerRepository extends AuthorityAggregateRepository {
  async idempotent<T>(input: {
    ledgerId: string;
    operatorId: string;
    operation: string;
    idempotencyKey: string;
    payloadHash: string;
    workflowPayloadEncrypted: string;
    matchesExistingRequest(encrypted: string, existingLedgerId: string): Promise<boolean>;
    responseStatus: number;
  }, mutation: (repo: AuthorityRepositoryPort) => Promise<T>): Promise<T> {
    const keyHash = digest(input.idempotencyKey);
    return this.db.transaction(async (tx) => {
      const now = new Date();
      await tx.execute(sql`
        update ${authorityIdempotencyKeys}
        set response_body=null, workflow_payload_encrypted=null,
            workflow_phase=case when workflow_phase is null then null else 'erased' end,
            updated_at=${now.toISOString()}::timestamptz
        where id in (
          select id from ${authorityIdempotencyKeys}
          where route_key like 'authority.use.result:%'
            and response_readable_until<=${now.toISOString()}::timestamptz
            and (response_body is not null or workflow_payload_encrypted is not null)
          order by response_readable_until asc
          limit 256
        )`);
      await tx.execute(sql`
        delete from ${authorityIdempotencyKeys}
        where id in (
          select id from ${authorityIdempotencyKeys}
          where operator_id=${input.operatorId} and expires_at<=${now.toISOString()}::timestamptz
            and route_key not like 'authority.use.result:%'
          order by expires_at asc
          limit 256
        )`);
      const [claimed] = await tx.insert(authorityIdempotencyKeys).values({
        id: input.ledgerId, operator_id: input.operatorId, route_key: input.operation,
        idempotency_key_hash: keyHash, request_hash: input.payloadHash, state: 'started',
        workflow_payload_encrypted: input.workflowPayloadEncrypted,
        created_at: now, updated_at: now, expires_at: new Date(now.getTime() + 24 * 60 * 60 * 1000),
      }).onConflictDoNothing().returning();
      if (!claimed) {
        const [existing] = await tx.select().from(authorityIdempotencyKeys).where(and(
          eq(authorityIdempotencyKeys.operator_id, input.operatorId),
          eq(authorityIdempotencyKeys.route_key, input.operation),
          eq(authorityIdempotencyKeys.idempotency_key_hash, keyHash),
        )).limit(1);
        if (existing?.route_key.startsWith('authority.use.result:')
          && (!existing.response_readable_until || existing.response_readable_until <= now)) {
          throw new ConflictError('Proxy-mediated authority result replay has expired');
        }
        if (!existing || !existing.workflow_payload_encrypted
          || !(await input.matchesExistingRequest(existing.workflow_payload_encrypted, existing.id))) {
          throw new ConflictError('Idempotency-Key was already used with a different payload');
        }
        if (existing.state !== 'completed' || existing.response_body === null) {
          throw new ConflictError('idempotent mutation is still in progress');
        }
        return existing.response_body as T;
      }
      const result = await mutation(this.ctx.forTransaction(tx));
      const resultRecord = result && typeof result === 'object' ? result as Record<string, unknown> : null;
      await tx.update(authorityIdempotencyKeys).set({
        state: 'completed', response_status: input.responseStatus,
        response_body: result as Record<string, unknown>, updated_at: new Date(),
        ...(input.operation.startsWith('authority.use.result:') ? {
          response_readable_until: new Date(now.getTime() + 24 * 60 * 60 * 1000),
          response_tombstone_hash: digest(canonicalize(result)),
        } : {}),
        ...(resultRecord?.resource_type === 'proof_collection_session' && typeof resultRecord.id === 'string'
          ? { resource_type: 'proof_collection_session', resource_id: resultRecord.id } : {}),
      }).where(eq(authorityIdempotencyKeys.id, claimed.id));
      return result;
    });
  }

  async consumeReceiverJti(input: { receiverId: string; jtiHash: string; expiresAt: Date }) {
    const receiver = await this.repo.findReceiverById(input.receiverId);
    if (!receiver) return false;
    const now = new Date();
    const [row] = await this.db.insert(authorityIdempotencyKeys).values({
      id: generateId('aik'), operator_id: receiver.managed_by_operator_id,
      route_key: `receiver.assertion:${input.receiverId}`, idempotency_key_hash: input.jtiHash,
      request_hash: input.jtiHash, state: 'completed', response_status: 204, response_body: {},
      created_at: now, updated_at: now,
      expires_at: new Date(Math.max(input.expiresAt.getTime(), now.getTime() + 24 * 60 * 60 * 1000)),
    }).onConflictDoNothing().returning({ id: authorityIdempotencyKeys.id });
    return Boolean(row);
  }

  async consumeAuthorityJti(input: {
    operatorId: string; namespace: string; jtiHash: string; expiresAt: Date;
  }) {
    const now = new Date();
    const [row] = await this.db.insert(authorityIdempotencyKeys).values({
      id: generateId('aik'), operator_id: input.operatorId,
      route_key: `authority.assertion:${input.namespace}`,
      idempotency_key_hash: input.jtiHash, request_hash: input.jtiHash,
      state: 'completed', response_status: 204, response_body: {},
      created_at: now, updated_at: now,
      expires_at: new Date(Math.max(input.expiresAt.getTime(), now.getTime() + 24 * 60 * 60 * 1000)),
    }).onConflictDoNothing().returning({ id: authorityIdempotencyKeys.id });
    return Boolean(row);
  }
}
