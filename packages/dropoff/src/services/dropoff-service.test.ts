import { describe, expect, it, vi } from 'vitest';
import {
  DropoffAlreadyCollectedError,
  DropoffExpiredError,
  ForbiddenError,
  NotFoundError,
  SchemaValidationError,
  sha256,
} from '@stack/shared';
import {
  type DropoffDbTransaction,
  type DropoffRow,
  DropoffRepository,
} from '../repositories/dropoff-repo.js';
import { DropoffService, toDropoffView, type DropoffEncryptor } from './dropoff-service.js';

const tx = {} as DropoffDbTransaction;
const now = new Date();

function row(overrides: Partial<DropoffRow> = {}): DropoffRow {
  return {
    id: 'dof_test',
    operator_id: 'op_test',
    from_agent_id: 'agt_from',
    to_agent_id: 'agt_to',
    schema: { type: 'object' },
    status: 'created',
    on_expire: 'notify',
    payload_hash: null,
    payload_encrypted: null,
    payload_envelope_version: 2,
    deposited_bytes: 0,
    created_at: now,
    deposited_at: null,
    collected_at: null,
    expires_at: new Date(now.getTime() + 60_000),
    mission_id: null,
    provenance: null,
    deposit_announced_at: null,
    end_announced_at: null,
    ...overrides,
  };
}

/** The repository calls that name and record recipients, for a drop-off whose one named agent is `agt_to`. */
function recipientMocks(named: readonly string[] = ['agt_to']) {
  return {
    countAgentsOfOperator: vi.fn(async (_operator: string, agents: readonly string[]) => agents.length),
    addRecipients: vi.fn(async () => undefined),
    isRecipient: vi.fn(async (_dropoff: string, agent: string) => named.includes(agent)),
    markRecipientCollected: vi.fn(async () => undefined),
    recipientsOf: vi.fn(async () => new Map()),
    collectorOf: vi.fn(async () => ({ agent_id: 'agt_to', name: null })),
  };
}

function encryptor(): DropoffEncryptor {
  return {
    encrypt: vi.fn(async (plaintext: string) => ({
      ciphertext: `encrypted:${plaintext}`,
      keyRef: 'test',
    })),
    decrypt: vi.fn(async (ciphertext: string) => ciphertext.replace(/^encrypted:/, '')),
  };
}

describe('drop-off lifecycle security boundary', () => {
  it('rejects hostile schemas before creating a durable drop-off', async () => {
    const create = vi.fn();
    const service = new DropoffService({ create } as unknown as DropoffRepository, encryptor());

    await expect(service.create('op_test', {
      from_agent: 'agt_from',
      to_agent: 'agt_to',
      schema: { $ref: 'https://attacker.invalid/schema.json' },
      ttl_seconds: 60,
      on_expire: 'notify',
    }, tx)).rejects.toThrow('safe JSON Schema subset');
    expect(create).not.toHaveBeenCalled();
  });

  it('projects every lifecycle row to a DTO with no ciphertext or payload fingerprint', () => {
    const view = toDropoffView(row({
      payload_hash: 'secret-fingerprint',
      payload_encrypted: 'secret-envelope',
      deposited_bytes: 27,
    }));

    expect(view).toMatchObject({ id: 'dof_test', deposited_bytes: 27 });
    expect(view).not.toHaveProperty('payload_hash');
    expect(view).not.toHaveProperty('payload_encrypted');
  });

  it('normalizes legacy expiry choices to the only implemented purge behavior', async () => {
    const create = vi.fn(async (data: Partial<DropoffRow>) => row(data));
    const service = new DropoffService({ ...recipientMocks(), create } as unknown as DropoffRepository, encryptor());

    const result = await service.create('op_test', {
      from_agent: 'agt_from',
      to_agent: 'agt_to',
      schema: { type: 'object' },
      ttl_seconds: 60,
      on_expire: 'retry',
    }, tx);

    expect(create).toHaveBeenCalledWith(expect.objectContaining({ on_expire: 'notify' }), tx);
    expect(result.on_expire).toBe('notify');
  });

  it('collapses wrong-producer and wrong-reader access into NotFound', async () => {
    const stored = row();
    const repo = {
      ...recipientMocks(),
      findByIdForUpdate: vi.fn(async () => stored),
      findById: vi.fn(async () => stored),
    } as unknown as DropoffRepository;
    const crypto = encryptor();
    const service = new DropoffService(repo, crypto);

    await expect(service.deposit(
      stored.id,
      stored.operator_id,
      'agt_intruder',
      { value: 1 },
      null,
      tx,
    )).rejects.toBeInstanceOf(NotFoundError);
    await expect(service.getStatus(stored.id, stored.operator_id, 'agt_intruder'))
      .rejects.toBeInstanceOf(NotFoundError);
    expect(crypto.encrypt).not.toHaveBeenCalled();
  });

  it('counts canonical plaintext bytes and rejects a mission deposit beyond the cumulative cap', async () => {
    const payload = { value: 'é' };
    const bytes = new TextEncoder().encode(JSON.stringify(payload)).byteLength;
    const deposit = vi.fn();
    const repo = {
      ...recipientMocks(),
      findByIdForUpdate: vi.fn(async () => row()),
      findMissionForUpdate: vi.fn(async () => ({
        operator_id: 'op_test',
        max_dropoff_bytes: bytes,
        revoked_at: null,
        completed_at: null,
        expires_at: new Date(Date.now() + 60_000),
      })),
      sumDepositedBytesForMission: vi.fn(async () => 1),
      deposit,
    } as unknown as DropoffRepository;
    const service = new DropoffService(repo, encryptor());

    await expect(service.deposit(
      'dof_test',
      'op_test',
      'agt_from',
      payload,
      'ms_test',
      tx,
    )).rejects.toBeInstanceOf(ForbiddenError);
    expect(deposit).not.toHaveBeenCalled();
  });

  it('allows exactly one concurrent collector and leaves the second no payload to decrypt', async () => {
    const stored = row({
      status: 'deposited',
      payload_hash: sha256('{"value":1}'),
      payload_encrypted: 'encrypted:{"value":1}',
      deposited_bytes: 11,
      deposited_at: now,
    });
    let queue = Promise.resolve();
    const repo = {
      ...recipientMocks(),
      transaction<T>(callback: (transaction: DropoffDbTransaction) => Promise<T>): Promise<T> {
        const result = queue.then(() => callback(tx));
        queue = result.then(() => undefined, () => undefined);
        return result;
      },
      findByIdForUpdate: vi.fn(async () => ({ ...stored })),
      collect: vi.fn(async () => {
        if (stored.status !== 'deposited') return undefined;
        stored.status = 'collected';
        stored.payload_encrypted = null;
        stored.collected_at = new Date();
        return { ...stored };
      }),
      expireActive: vi.fn(),
    } as unknown as DropoffRepository;
    const crypto = encryptor();
    const service = new DropoffService(repo, crypto);

    const results = await Promise.allSettled([
      service.collect(stored.id, stored.operator_id, stored.to_agent_id),
      service.collect(stored.id, stored.operator_id, stored.to_agent_id),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result) => result.status === 'rejected');
    expect(rejected).toMatchObject({ reason: expect.any(DropoffAlreadyCollectedError) });
    expect(crypto.decrypt).toHaveBeenCalledTimes(1);
    expect(stored.payload_encrypted).toBeNull();
  });

  it('uses only the explicitly-versioned legacy context for pre-migration rows', async () => {
    const stored = row({
      status: 'deposited',
      payload_hash: sha256('{"value":1}'),
      payload_encrypted: 'legacy-context-envelope',
      payload_envelope_version: 1,
      deposited_bytes: 11,
      deposited_at: now,
    });
    const repo = {
      ...recipientMocks(),
      findByIdForUpdate: vi.fn(async () => ({ ...stored })),
      collect: vi.fn(async () => ({ ...stored, status: 'collected', payload_encrypted: null })),
      expireActive: vi.fn(),
    } as unknown as DropoffRepository;
    const decrypt = vi.fn(async (_ciphertext: string, _context?: Record<string, string>) => {
      return '{"value":1}';
    });
    const service = new DropoffService(repo, {
      ...encryptor(),
      decrypt,
    });

    await expect(service.collect(stored.id, stored.operator_id, stored.to_agent_id, tx))
      .resolves.toEqual({ value: 1 });
    expect(decrypt).toHaveBeenCalledTimes(1);
    expect(decrypt).toHaveBeenCalledWith(stored.payload_encrypted, {
      operator_id: stored.operator_id,
      store: 'dropoff_payload',
    });
  });

  it('does not hide KMS or integrity failures behind the legacy context fallback', async () => {
    const stored = row({
      status: 'deposited',
      payload_hash: sha256('{"value":1}'),
      payload_encrypted: 'new-context-envelope',
      deposited_bytes: 11,
      deposited_at: now,
    });
    const repo = {
      ...recipientMocks(),
      findByIdForUpdate: vi.fn(async () => ({ ...stored })),
      expireActive: vi.fn(),
    } as unknown as DropoffRepository;
    const failure = new Error('KMS unavailable');
    const decrypt = vi.fn(async () => { throw failure; });
    const service = new DropoffService(repo, { ...encryptor(), decrypt });

    await expect(service.collect(stored.id, stored.operator_id, stored.to_agent_id, tx))
      .rejects.toBe(failure);
    expect(decrypt).toHaveBeenCalledTimes(1);
  });

  it('rejects plaintext whose stored payload hash does not match before collection', async () => {
    const stored = row({
      status: 'deposited',
      payload_hash: sha256('{"value":"expected"}'),
      payload_encrypted: 'encrypted:{"value":"tampered"}',
      deposited_bytes: 20,
      deposited_at: now,
    });
    const collect = vi.fn();
    const repo = {
      ...recipientMocks(),
      findByIdForUpdate: vi.fn(async () => ({ ...stored })),
      collect,
      expireActive: vi.fn(),
    } as unknown as DropoffRepository;
    const crypto = encryptor();
    const service = new DropoffService(repo, crypto);

    await expect(service.collect(stored.id, stored.operator_id, stored.to_agent_id, tx))
      .rejects.toThrow('payload integrity verification failed');
    expect(crypto.decrypt).toHaveBeenCalledTimes(1);
    expect(collect).not.toHaveBeenCalled();
  });

  it('commits expiry purge before returning an expired error to a late collector', async () => {
    const stored = row({
      status: 'deposited',
      payload_hash: sha256('{"value":1}'),
      payload_encrypted: 'encrypted:{"value":1}',
      deposited_bytes: 11,
      deposited_at: new Date(now.getTime() - 120_000),
      expires_at: new Date(now.getTime() - 60_000),
    });
    const repo = {
      ...recipientMocks(),
      transaction: async <T>(callback: (transaction: DropoffDbTransaction) => Promise<T>) => callback(tx),
      findByIdForUpdate: vi.fn(async () => ({ ...stored })),
      expireActive: vi.fn(async () => {
        stored.status = 'expired';
        stored.payload_encrypted = null;
        return { ...stored };
      }),
    } as unknown as DropoffRepository;
    const crypto = encryptor();
    const service = new DropoffService(repo, crypto);

    await expect(service.collect(stored.id, stored.operator_id, stored.to_agent_id))
      .rejects.toBeInstanceOf(DropoffExpiredError);
    expect(stored).toMatchObject({ status: 'expired', payload_encrypted: null });
    expect(crypto.decrypt).not.toHaveBeenCalled();
  });
});

describe('who is told a drop-off was expired', () => {
  function expiring() {
    const stored = row({ status: 'deposited', deposited_at: new Date(now.getTime() - 60_000) });
    const repo = {
      ...recipientMocks(),
      transaction: async <T>(callback: (transaction: DropoffDbTransaction) => Promise<T>) => callback(tx),
      findByIdForUpdate: vi.fn(async () => ({ ...stored })),
      expireActive: vi.fn(async () => ({ ...stored, status: 'expired' })),
    };
    return { repo, service: new DropoffService(repo as unknown as DropoffRepository, encryptor()) };
  }

  it('marks the end announced when the depositor expired its own drop-off: there is nobody to tell', async () => {
    const { repo, service } = expiring();
    await service.expire('dof_test', 'op_test', 'agt_from');
    expect(repo.expireActive).toHaveBeenCalledWith('dof_test', 'op_test', tx, true);
  });

  it('leaves the end for the depositor to be told when the owner expired it', async () => {
    const { repo, service } = expiring();
    await service.expire('dof_test', 'op_test');
    expect(repo.expireActive).toHaveBeenCalledWith('dof_test', 'op_test', tx, false);
  });
});

describe('drop-off deposit against the declared schema', () => {
  const declared = {
    type: 'object',
    properties: { count: { type: 'integer' } },
    required: ['count'],
    additionalProperties: false,
  };

  function setup() {
    const deposit = vi.fn();
    const repo = {
      ...recipientMocks(),
      findByIdForUpdate: vi.fn(async () => row({ schema: declared })),
      deposit,
    } as unknown as DropoffRepository;
    const crypto = encryptor();
    return { service: new DropoffService(repo, crypto), crypto, deposit };
  }

  it('refuses a payload that breaks the schema and stores nothing', async () => {
    const { service, crypto, deposit } = setup();

    const failure = await service
      .deposit('dof_test', 'op_test', 'agt_from', { count: 'secret-value' }, null, tx)
      .catch((e: unknown) => e);

    expect(failure).toBeInstanceOf(SchemaValidationError);
    const error = failure as SchemaValidationError;
    expect(error.statusCode).toBe(400);
    expect(error.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(error.details).toEqual({ errors: [{ path: '/count', message: 'must be integer' }] });
    // Neither the error nor its details may carry the rejected payload.
    expect(JSON.stringify(error.details)).not.toContain('secret-value');
    expect(crypto.encrypt).not.toHaveBeenCalled();
    expect(deposit).not.toHaveBeenCalled();
  });

  it('refuses a payload with a missing required field or an undeclared one', async () => {
    const { service, crypto, deposit } = setup();

    await expect(service.deposit('dof_test', 'op_test', 'agt_from', {}, null, tx))
      .rejects.toBeInstanceOf(SchemaValidationError);
    await expect(service.deposit('dof_test', 'op_test', 'agt_from', { count: 1, extra: true }, null, tx))
      .rejects.toBeInstanceOf(SchemaValidationError);
    expect(crypto.encrypt).not.toHaveBeenCalled();
    expect(deposit).not.toHaveBeenCalled();
  });
});
