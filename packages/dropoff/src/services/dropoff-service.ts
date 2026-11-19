import type { ErrorObject } from 'ajv';
import {
  ids,
  type CreateDropoffInput,
  namedDropoffRecipients,
  NotFoundError,
  ForbiddenError,
  ConflictError,
  DropoffExpiredError,
  DropoffAlreadyCollectedError,
  SchemaValidationError,
  sha256,
  secureCompare,
  assertSafeJsonSchema,
  assertBoundedJsonValue,
  DROPOFF_DEFAULT_TTL_SECONDS,
} from '@stack/shared';
import {
  DropoffRepository,
  type DropoffDbTransaction,
  type DropoffRecipient,
  type DropoffRow,
} from '../repositories/dropoff-repo.js';

import Ajv from 'ajv';
const ajv = new (Ajv as unknown as typeof Ajv.default)({
  allErrors: false,
  strictSchema: true,
  validateSchema: true,
  loopEnum: 50,
  loopRequired: 50,
});
const validatorCache = new Map<string, ReturnType<typeof ajv.compile>>();

function compileValidator(schema: Record<string, unknown>) {
  assertSafeJsonSchema(schema);
  const cacheKey = sha256(JSON.stringify(schema));
  const cached = validatorCache.get(cacheKey);
  if (cached) return cached;
  const validate = ajv.compile(schema);
  if (validatorCache.size >= 256) validatorCache.clear();
  validatorCache.set(cacheKey, validate);
  return validate;
}

export interface DropoffEncryptor {
  /**
   * Encrypt payload. Optional `context` is forwarded to the KMS envelope as
   * AAD + KMS EncryptionContext. When `operator_id` is present in the
   * context, the implementation routes the data key under the operator's
   * CMEK (if configured) instead of the platform default key. Drop-off
   * callers bind new writes to the operator, store and drop-off ID so
   * customer-managed encryption covers drop-off payloads end-to-end and one
   * envelope cannot be replayed onto another drop-off.
   */
  encrypt(plaintext: string, context?: Record<string, string>): Promise<{ ciphertext: string; keyRef: string }>;
  decrypt(ciphertext: string, expectedContext?: Record<string, string>): Promise<string>;
}

/** Public lifecycle record. Ciphertext and its fingerprint never cross this boundary. */
export interface DropoffView {
  id: string;
  operator_id: string;
  from_agent_id: string;
  /** The first agent named. */
  to_agent_id: string;
  /** Every agent named, in the order named: each can see and collect it. */
  to_agent_ids: string[];
  /** The agent that collected it; null until one has. */
  collected_by_agent_id: string | null;
  schema: Record<string, unknown>;
  status: string;
  on_expire: string;
  created_at: Date;
  deposited_at: Date | null;
  collected_at: Date | null;
  expires_at: Date;
  mission_id: string | null;
  deposited_bytes: number;
}

export interface DropoffStatusView {
  id: string;
  from_agent: string;
  /** The first agent named. */
  to_agent: string;
  /** Every agent named, in the order named. */
  to_agents: string[];
  /** The agent that collected it; null until one has. */
  collected_by: string | null;
  status: string;
  created_at: Date;
  deposited_at: Date | null;
  collected_at: Date | null;
  expires_at: Date;
  mission_id: string | null;
  deposited_bytes: number;
}

type DropoffViewRow = Pick<DropoffRow,
  | 'id' | 'operator_id' | 'from_agent_id' | 'to_agent_id' | 'schema'
  | 'status' | 'on_expire' | 'created_at' | 'deposited_at' | 'collected_at'
  | 'expires_at' | 'mission_id' | 'deposited_bytes'
>;

/** The agents a drop-off names, with the one that collected it. Without them a drop-off names its first agent alone. */
export function toDropoffView(row: DropoffViewRow, recipients?: readonly DropoffRecipient[]): DropoffView {
  const named = recipients && recipients.length > 0 ? recipients : [{ agent_id: row.to_agent_id, collected_at: null }];
  return {
    id: row.id,
    operator_id: row.operator_id,
    from_agent_id: row.from_agent_id,
    to_agent_id: row.to_agent_id,
    to_agent_ids: named.map((r) => r.agent_id),
    collected_by_agent_id: row.status === 'collected'
      ? (named.find((r) => r.collected_at !== null)?.agent_id ?? (named.length === 1 ? named[0]!.agent_id : null))
      : null,
    schema: row.schema,
    status: row.status,
    on_expire: row.on_expire,
    created_at: row.created_at,
    deposited_at: row.deposited_at,
    collected_at: row.collected_at,
    expires_at: row.expires_at,
    mission_id: row.mission_id,
    deposited_bytes: row.deposited_bytes,
  };
}

function isExpired(expiresAt: Date): boolean {
  return expiresAt.getTime() <= Date.now();
}

export class DropoffService {
  constructor(
    private repo: DropoffRepository,
    private encryptor: DropoffEncryptor,
  ) {}

  async create(
    operatorId: string,
    input: CreateDropoffInput,
    transaction?: DropoffDbTransaction,
  ): Promise<DropoffView> {
    // Reject hostile or unbounded schemas before they become durable. The
    // compilation result is cached for later deposits.
    compileValidator(input.schema);
    if (!transaction) {
      return this.repo.transaction((tx) => this.create(operatorId, input, tx));
    }

    const recipients = namedDropoffRecipients(input);
    // Every agent named, and the sender, must be the customer's own. A foreign or unknown one reads as missing,
    // whoever the caller is: the routes check this too, and this is the last word.
    const participants = [...new Set([input.from_agent, ...recipients])];
    if ((await this.repo.countAgentsOfOperator(operatorId, participants, transaction)) !== participants.length) {
      throw new NotFoundError('Agent', recipients.find((agent) => agent !== input.from_agent) ?? input.from_agent);
    }

    const ttl = input.ttl_seconds ?? DROPOFF_DEFAULT_TTL_SECONDS;
    const expiresAt = new Date(Date.now() + ttl * 1000);

    const row = await this.repo.create({
      id: ids.dropoff(),
      operator_id: operatorId,
      from_agent_id: input.from_agent,
      to_agent_id: recipients[0]!,
      schema: input.schema,
      status: 'created',
      // Legacy retry/fail values remain accepted by the wire schema during
      // the compatibility window, but the only real behavior is expire+purge.
      on_expire: 'notify',
      expires_at: expiresAt,
    }, transaction);
    await this.repo.addRecipients(row.id, operatorId, recipients, transaction);
    return toDropoffView(row, recipients.map((agent_id) => ({ agent_id, collected_at: null })));
  }

  async deposit(
    dropoffId: string,
    operatorId: string,
    fromAgentId: string,
    payload: Record<string, unknown>,
    /** Derived from a verified active Passport by the API layer. */
    missionId: string | null = null,
    transaction?: DropoffDbTransaction,
    /**
     * Where the payload's content came from, computed by the API layer
     * against the depositor's Mission observations (`DropoffProvenance`).
     * Stored with the row and handed to the collector.
     */
    provenance: Record<string, unknown> | null = null,
  ): Promise<DropoffView> {
    if (!transaction) {
      let expiryError: DropoffExpiredError | null = null;
      const result = await this.repo.transaction(async (tx) => {
        try {
          return await this.deposit(dropoffId, operatorId, fromAgentId, payload, missionId, tx, provenance);
        } catch (err) {
          if (!(err instanceof DropoffExpiredError)) throw err;
          expiryError = err;
          return null;
        }
      });
      if (expiryError) throw expiryError;
      if (!result) throw new ConflictError('Dropoff deposit did not complete');
      return result;
    }

    const dropoff = await this.repo.findByIdForUpdate(dropoffId, transaction);
    // Unknown, cross-tenant and wrong-participant resources deliberately
    // collapse to one absence response.
    if (
      !dropoff ||
      dropoff.operator_id !== operatorId ||
      dropoff.from_agent_id !== fromAgentId
    ) {
      throw new NotFoundError('Dropoff', dropoffId);
    }

    // Check status
    if (dropoff.status === 'expired') throw new DropoffExpiredError(dropoffId);
    if (dropoff.status !== 'created') {
      throw new DropoffAlreadyCollectedError(dropoffId);
    }

    // Check expiry
    if (isExpired(dropoff.expires_at)) {
      await this.repo.expireActive(dropoffId, operatorId, transaction);
      throw new DropoffExpiredError(dropoffId);
    }

    // Validate payload against declared schema
    assertBoundedJsonValue(payload);
    const validate = compileValidator(dropoff.schema);
    const valid = validate(payload);
    if (!valid) {
      throw new SchemaValidationError({
        errors: validate.errors?.map((e: ErrorObject) => ({
          path: e.instancePath,
          message: e.message,
        })),
      });
    }

    // Encrypt payload. Context carries operator_id so the KMS envelope routes
    // through the per-operator CMEK resolver. Drop-off payloads are ephemeral
    // (≤24h TTL) — the migration worker doesn't backfill them; new writes
    // target the customer key automatically once cmek_status flips to
    // 'migrating' or 'active' on the operator row.
    const payloadJson = JSON.stringify(payload);
    const payloadHash = sha256(payloadJson);
    const { ciphertext } = await this.encryptor.encrypt(payloadJson, {
      operator_id: operatorId,
      store: 'dropoff_payload',
      dropoff_id: dropoffId,
    });

    // Count the canonical plaintext JSON bytes. The value survives envelope
    // deletion, so collection can never reclaim mission allowance.
    const depositedBytes = new TextEncoder().encode(payloadJson).byteLength;

    if (missionId) {
      // Different drop-off rows share this mission-row lock, so current+new
      // can never race past max_dropoff_bytes.
      const mission = await this.repo.findMissionForUpdate(missionId, operatorId, transaction);
      if (
        !mission ||
        mission.revoked_at ||
        mission.completed_at ||
        isExpired(mission.expires_at)
      ) {
        throw new ForbiddenError('Mission cannot authorize this drop-off');
      }
      if (mission.max_dropoff_bytes !== null) {
        const usedBytes = await this.repo.sumDepositedBytesForMission(missionId, transaction);
        if (usedBytes + depositedBytes > mission.max_dropoff_bytes) {
          throw new ForbiddenError('Mission drop-off byte limit exceeded');
        }
      }
    }

    const deposited = await this.repo.deposit(
      dropoffId,
      operatorId,
      payloadHash,
      ciphertext,
      depositedBytes,
      missionId,
      2,
      transaction,
      provenance,
    );
    if (!deposited) {
      // The DB clock is authoritative. If TTL elapsed during encryption,
      // purge through the legal expiry transition rather than storing late.
      await this.repo.expireActive(dropoffId, operatorId, transaction);
      throw new DropoffExpiredError(dropoffId);
    }
    return toDropoffView(deposited, (await this.repo.recipientsOf([deposited], transaction)).get(deposited.id));
  }

  async collect(
    dropoffId: string,
    operatorId: string,
    toAgentId: string,
    transaction?: DropoffDbTransaction,
  ): Promise<Record<string, unknown>> {
    return (await this.collectWithProvenance(dropoffId, operatorId, toAgentId, transaction)).payload;
  }

  /**
   * Collect, also returning the provenance recorded at deposit (null for a
   * deposit made without one). The API layer writes it to the collector's
   * Mission before the custody transfer commits.
   */
  async collectWithProvenance(
    dropoffId: string,
    operatorId: string,
    toAgentId: string,
    transaction?: DropoffDbTransaction,
  ): Promise<{ payload: Record<string, unknown>; provenance: Record<string, unknown> | null }> {
    if (!transaction) {
      let expiryError: DropoffExpiredError | null = null;
      const result = await this.repo.transaction(async (tx) => {
        try {
          return await this.collectWithProvenance(dropoffId, operatorId, toAgentId, tx);
        } catch (err) {
          if (!(err instanceof DropoffExpiredError)) throw err;
          expiryError = err;
          return null;
        }
      });
      if (expiryError) throw expiryError;
      if (!result) throw new ConflictError('Dropoff collection did not complete');
      return result;
    }

    // The row lock serialises every agent a group drop-off names: the one that gets the lock first collects it, and
    // each later one finds it collected and is told who took it.
    const dropoff = await this.repo.findByIdForUpdate(dropoffId, transaction);
    if (
      !dropoff ||
      dropoff.operator_id !== operatorId ||
      !(await this.repo.isRecipient(dropoffId, toAgentId, transaction))
    ) {
      throw new NotFoundError('Dropoff', dropoffId);
    }

    if (dropoff.status === 'collected') {
      throw new DropoffAlreadyCollectedError(
        dropoffId,
        (await this.repo.collectorOf(dropoff, transaction)) ?? undefined,
      );
    }
    if (dropoff.status === 'expired') throw new DropoffExpiredError(dropoffId);
    if (dropoff.status !== 'deposited') {
      throw new NotFoundError('Dropoff (no deposit yet)', dropoffId);
    }
    if (isExpired(dropoff.expires_at)) {
      await this.repo.expireActive(dropoffId, operatorId, transaction);
      throw new DropoffExpiredError(dropoffId);
    }

    // Envelope version is a stored compatibility decision, never inferred by
    // retrying multiple contexts. v2 binds the ciphertext to this exact
    // drop-off. v1 exists only for rows identified before migration 0069.
    if (!dropoff.payload_encrypted) {
      throw new Error('Payload missing — data integrity error');
    }
    if (dropoff.payload_envelope_version !== 1 && dropoff.payload_envelope_version !== 2) {
      throw new Error('Unsupported drop-off payload envelope version');
    }
    const plaintext = dropoff.payload_envelope_version === 2
      ? await this.encryptor.decrypt(dropoff.payload_encrypted, {
        operator_id: operatorId,
        store: 'dropoff_payload',
        dropoff_id: dropoffId,
      })
      : await this.encryptor.decrypt(dropoff.payload_encrypted, {
        operator_id: operatorId,
        store: 'dropoff_payload',
      });
    if (!dropoff.payload_hash) {
      throw new Error('Payload hash missing — data integrity error');
    }
    const actualHash = sha256(plaintext);
    if (!secureCompare(actualHash, dropoff.payload_hash)) {
      throw new Error('Drop-off payload integrity verification failed');
    }
    const payload = JSON.parse(plaintext) as Record<string, unknown>;
    assertBoundedJsonValue(payload);

    // Custody transfer — mark collected, purge encrypted payload
    const collected = await this.repo.collect(dropoffId, operatorId, transaction);
    if (!collected) {
      await this.repo.expireActive(dropoffId, operatorId, transaction);
      throw new DropoffExpiredError(dropoffId);
    }
    await this.repo.markRecipientCollected(dropoffId, toAgentId, transaction);

    return { payload, provenance: dropoff.provenance ?? null };
  }

  async getStatus(
    dropoffId: string,
    operatorId: string,
    participantAgentId?: string,
  ): Promise<DropoffStatusView> {
    const dropoff = await this.repo.findById(dropoffId);
    if (
      !dropoff ||
      dropoff.operator_id !== operatorId ||
      (participantAgentId &&
        dropoff.from_agent_id !== participantAgentId &&
        !(await this.repo.isRecipient(dropoffId, participantAgentId)))
    ) {
      throw new NotFoundError('Dropoff', dropoffId);
    }
    const view = toDropoffView(dropoff, (await this.repo.recipientsOf([dropoff])).get(dropoff.id));

    return {
      id: dropoff.id,
      from_agent: dropoff.from_agent_id,
      to_agent: dropoff.to_agent_id,
      to_agents: view.to_agent_ids,
      collected_by: view.collected_by_agent_id,
      status: dropoff.status,
      created_at: dropoff.created_at,
      deposited_at: dropoff.deposited_at,
      collected_at: dropoff.collected_at,
      expires_at: dropoff.expires_at,
      mission_id: dropoff.mission_id,
      deposited_bytes: dropoff.deposited_bytes,
    };
  }

  async listForOperator(operatorId: string, participantAgentId?: string): Promise<DropoffView[]> {
    const rows = participantAgentId
      ? await this.repo.findByParticipant(operatorId, participantAgentId)
      : await this.repo.findByOperator(operatorId);
    return this.withRecipients(rows);
  }

  /** Say that the deployment's deposit hooks have run for this drop-off. */
  async markDepositAnnounced(dropoffId: string): Promise<void> {
    await this.repo.markDepositAnnounced(dropoffId);
  }

  async listPendingForAgent(agentId: string): Promise<DropoffView[]> {
    return this.withRecipients(await this.repo.findPendingForAgent(agentId));
  }

  private async withRecipients(rows: DropoffViewRow[], transaction?: DropoffDbTransaction): Promise<DropoffView[]> {
    const named = await this.repo.recipientsOf(rows, transaction);
    return rows.map((row) => toDropoffView(row, named.get(row.id)));
  }

  async expire(
    dropoffId: string,
    operatorId: string,
    producerAgentId?: string,
    transaction?: DropoffDbTransaction,
  ): Promise<DropoffView> {
    if (!transaction) {
      return this.repo.transaction((tx) => this.expire(dropoffId, operatorId, producerAgentId, tx));
    }

    const dropoff = await this.repo.findByIdForUpdate(dropoffId, transaction);
    if (
      !dropoff ||
      dropoff.operator_id !== operatorId ||
      (producerAgentId && dropoff.from_agent_id !== producerAgentId)
    ) {
      throw new NotFoundError('Dropoff', dropoffId);
    }
    if (dropoff.status === 'expired') throw new DropoffExpiredError(dropoffId);
    if (dropoff.status === 'collected') throw new DropoffAlreadyCollectedError(dropoffId);
    if (dropoff.status !== 'created' && dropoff.status !== 'deposited') {
      throw new ConflictError('Dropoff is not active');
    }

    // The depositor ending its own drop-off is told nothing; anyone else ending it (the owner) is announced to it.
    const byDepositor = producerAgentId !== undefined && producerAgentId === dropoff.from_agent_id;
    const expired = await this.repo.expireActive(dropoffId, operatorId, transaction, byDepositor);
    if (!expired) throw new ConflictError('Dropoff is not active');
    return toDropoffView(expired, (await this.repo.recipientsOf([expired], transaction)).get(expired.id));
  }

  /** Called by worker to expire overdue dropoffs */
  async expireOverdue(
    transaction?: DropoffDbTransaction,
    limit = 100,
  ): Promise<Array<Omit<DropoffView, 'to_agent_ids' | 'collected_by_agent_id'>>> {
    if (!transaction) {
      return this.repo.transaction((tx) => this.expireOverdue(tx, limit));
    }
    const candidates = await this.repo.findExpiredForUpdate(limit, transaction);
    if (candidates.length === 0) return [];
    const expired = await this.repo.markExpired(candidates.map((d) => d.id), transaction);
    // The sweep reads no recipients: it must keep working against the schema from before the recipients table, and
    // all it hands on is which drop-offs it ended.
    return expired.map((row) => {
      const { to_agent_ids: _named, collected_by_agent_id: _collector, ...swept } = toDropoffView(row);
      return swept;
    });
  }
}
