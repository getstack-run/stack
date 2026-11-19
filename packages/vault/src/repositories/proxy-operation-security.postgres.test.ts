import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { and, eq, sql } from 'drizzle-orm';
import { agents, canonicalize, operators, passportClaims, passports, proxyOperationEvidence, proxyOperations, serviceConnections, services, sha256, createDb, type Database } from '@stack/shared';
import { KmsService, type EncryptionContext } from '../crypto/kms.js';
import {
  ProxyOperationService,
  responseAad,
  type AdmitProxyOperationInput,
} from '../services/proxy-operation-service.js';
import { ProxyOperationRepository, PROXY_REPLAY_CAPACITY_BYTES } from './proxy-operation-repo.js';
import { PassportClaimsRepository } from './passport-claims-repo.js';
import { OperatorRepository } from './operator-repo.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';

const databaseUrl = process.env['DATABASE_URL'];
const isDedicatedDatabase = isDedicatedVaultTestDatabase(databaseUrl);

class ContextBoundKms {
  decryptions = 0;

  async encrypt(plaintext: string, context?: EncryptionContext) {
    return {
      ciphertext: Buffer.from(JSON.stringify({ plaintext, context })).toString('base64'),
      keyRef: 'proxy-security-test-key',
    };
  }

  async decrypt(ciphertext: string, context?: EncryptionContext) {
    this.decryptions += 1;
    const envelope = JSON.parse(Buffer.from(ciphertext, 'base64').toString()) as {
      plaintext: string;
      context?: EncryptionContext;
    };
    if (JSON.stringify(envelope.context) !== JSON.stringify(context))
      throw new Error('AAD mismatch');
    return envelope.plaintext;
  }
}

describe.runIf(isDedicatedDatabase)('proxy response storage security in PostgreSQL', () => {
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const operatorId = `op_proxy_security_${suffix}`;
  const agentId = `agt_proxy_security_${suffix}`;
  const passportJti = `pas_proxy_security_${suffix}`;
  const serviceId = `svc_proxy_security_${suffix}`;
  const connectionId = `scon_proxy_security_${suffix}`;
  const provider = `proxysecurity_${suffix}`;
  let db: Database;
  let repository: ProxyOperationRepository;
  let kms: ContextBoundKms;
  let operationService: ProxyOperationService;

  beforeAll(async () => {
    db = createDb(databaseUrl!);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${suffix}`,
    });
    await db
      .insert(agents)
      .values({ id: agentId, operator_id: operatorId, name: 'Proxy security agent' });
    await db.insert(services).values({
      id: serviceId,
      provider,
      name: 'Proxy security provider',
      description: 'Fixture',
      oauth_auth_url: 'https://auth.example.invalid',
      oauth_token_url: 'https://token.example.invalid',
      scopes_available: ['write'],
    });
    await db.insert(serviceConnections).values({
      id: connectionId,
      operator_id: operatorId,
      service_id: serviceId,
      provider,
      scopes: ['write'],
      credential_ref: 'fixture',
      credential_encrypted: 'fixture',
      allowed_hosts: ['api.example.invalid'],
    });
    await db.insert(passports).values({
      jti: passportJti,
      operator_id: operatorId,
      agent_id: agentId,
      session_id: `ses_${suffix}`,
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
    });
    repository = new ProxyOperationRepository(db);
    kms = new ContextBoundKms();
    operationService = new ProxyOperationService(repository, kms as unknown as KmsService);
  });

  afterAll(async () => {
    if (!db) return;
    await db.transaction(async (tx) => {
      // This runs only against the dedicated local acceptance database. The
      // production append-only trigger must remain enabled for application code.
      await tx.execute(sql`set local session_replication_role = replica`);
      await tx.delete(proxyOperations).where(eq(proxyOperations.operator_id, operatorId));
      await tx.delete(passports).where(eq(passports.operator_id, operatorId));
      await tx.delete(serviceConnections).where(eq(serviceConnections.operator_id, operatorId));
      await tx.delete(agents).where(eq(agents.operator_id, operatorId));
      await tx.delete(operators).where(eq(operators.id, operatorId));
      await tx.delete(services).where(eq(services.id, serviceId));
    });
    await db.$client.end();
  });

  function admission(
    operationKey: string,
    tenant = { operatorId, agentId, passportJti, connectionId },
  ): AdmitProxyOperationInput {
    const destinationConfigHash = `sha256:${sha256('destination')}` as const;
    const finalUrl = 'https://api.example.invalid/v1/write';
    const bodyBytes = '{"amount":100}';
    const headers = { 'content-type': 'application/json' };
    const identity = {
      version: 1,
      operator_id: tenant.operatorId,
      agent_id: tenant.agentId,
      passport_jti: tenant.passportJti,
      authority_use_id: null,
      approval_id: null,
      service_connection_id: tenant.connectionId,
      credential_version: 1,
      destination_config_hash: destinationConfigHash,
      service: provider,
      method: 'POST',
      origin: 'https://api.example.invalid',
      pathname: '/v1/write',
      query_pairs: [],
      headers: Object.entries(headers),
      body_kind: 'json',
      body_bytes: bodyBytes,
    };
    return {
      operatorId: tenant.operatorId,
      operationKey,
      agentId: tenant.agentId,
      passportJti: tenant.passportJti,
      connectionId: tenant.connectionId,
      serviceId,
      credentialVersion: 1,
      provider,
      destinationConfigHash,
      scopeDescriptor: {
        version: 1,
        provider,
        serviceId,
        connectionId: tenant.connectionId,
        scopes: ['write'],
        intents: [provider],
        constraints: [],
        policy: null,
        allowDataFrom: [],
        discloseTo: [],
        resource: { method: 'POST', origin: 'https://api.example.invalid', pathname: '/v1/write' },
        authorityRefs: [],
      },
      preparedRequest: {
        version: 1,
        service: provider,
        method: 'POST',
        finalUrl,
        headers,
        bodyBytes,
        bodyKind: 'json',
        requestHash: `sha256:${sha256(canonicalize(identity))}`,
        persistence: {
          origin: 'https://api.example.invalid',
          pathnameHash: `sha256:${sha256('/v1/write')}`,
          queryHash: `sha256:${sha256('[]')}`,
          destinationConfigHash,
          headerNames: ['content-type'],
          headersHash: `sha256:${sha256(canonicalize(headers))}`,
          bodyHash: `sha256:${sha256(bodyBytes)}`,
          bodyBytes: Buffer.byteLength(bodyBytes),
        },
      },
      effectCorrelationHash: `sha256:${sha256(`effect:${operationKey}`)}`,
      accountingPeriod: '2099-12',
      accountingCents: 0,
      accountingObligationId: `obl_${sha256(operationKey).slice(0, 32)}`,
      adapter: { kind: 'generic' },
    };
  }

  async function dispatched(operationKey: string) {
    const admitted = await operationService.admit(admission(operationKey));
    if (admitted.state !== 'created') throw new Error('fixture admission failed');
    const claim = await operationService.claimDispatch({
      operatorId,
      operationId: admitted.operation.id,
      operationKey,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    if (claim.state !== 'acquired' || !claim.dispatchToken) throw new Error('fixture claim failed');
    return { admitted, claim };
  }

  async function response(
    item: Awaited<ReturnType<typeof dispatched>>,
    service = operationService,
  ) {
    return service.storePermittedResponse({
      operatorId,
      operationId: item.admitted.operation.id,
      dispatchToken: item.claim.dispatchToken!,
      dispatchFence: item.claim.dispatchFence,
      status: 200,
      rawHeaders: { 'content-type': 'application/json', 'set-cookie': 'must-not-be-stored' },
      screenedBody: { private: 'screened value' },
      capacityBytes: 64 * 1024,
      transportEvidenceHash: `sha256:${sha256(item.admitted.operation.id)}`,
    });
  }

  it('uses authenticated encryption for every response AAD field and denies CMEK revocation without fallback', async () => {
    const item = await dispatched(`operation_real_kms_${'k'.repeat(24)}`);
    const keyArn = 'arn:aws:kms:eu-north-1:123456789012:key/proxy-test';
    const dataKey = Buffer.alloc(32, 17);
    let revoked = false;
    const send = vi
      .spyOn(KMSClient.prototype, 'send')
      .mockImplementation(async (command: unknown) => {
        if (command instanceof GenerateDataKeyCommand) {
          expect(command.input.KeyId).toBe(keyArn);
          return { Plaintext: dataKey, CiphertextBlob: Buffer.from('wrapped-key') };
        }
        if (command instanceof DecryptCommand) {
          if (revoked)
            throw Object.assign(new Error('grant revoked'), { name: 'AccessDeniedException' });
          return { Plaintext: dataKey };
        }
        throw new Error('Unexpected AWS operation');
      });
    const evict = vi.fn();
    const realKms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'platform-key' });
    realKms.setOperatorKeyHandlers({ resolve: async () => ({ keyArn, status: 'active' }), evict });
    const encryptedService = new ProxyOperationService(repository, realKms);
    try {
      const stored = await response(item, encryptedService);
      expect(stored!.response_encrypted).not.toContain('screened value');
      const aad = responseAad(operatorId, item.admitted.operation.id);
      for (const field of Object.keys(aad)) {
        const wrongContext = { ...aad, [field]: `different-${field}` };
        await expect(realKms.decrypt(stored!.response_encrypted!, wrongContext)).rejects.toThrow(
          'context',
        );
        // Even rewriting the plaintext context in the envelope cannot forge its AES-GCM tag.
        const forged = JSON.parse(Buffer.from(stored!.response_encrypted!, 'base64').toString());
        forged.ctx = wrongContext;
        await expect(
          realKms.decrypt(Buffer.from(JSON.stringify(forged)).toString('base64'), wrongContext),
        ).rejects.toThrow();
      }
      await expect(
        encryptedService.readReplay(operatorId, `operation_real_kms_${'k'.repeat(24)}`),
      ).resolves.toMatchObject({
        state: 'available',
        headers: { 'content-type': 'application/json' },
      });
      revoked = true;
      const before = send.mock.calls.length;
      await expect(
        encryptedService.readReplay(operatorId, `operation_real_kms_${'k'.repeat(24)}`),
      ).rejects.toThrow();
      expect(send.mock.calls.length - before).toBe(1);
      expect(evict).toHaveBeenCalledWith(operatorId);
      expect(
        (await repository.findByOperationKey(
          operatorId,
          sha256(`operation_real_kms_${'k'.repeat(24)}`),
        ))!.response_encrypted,
      ).toBe(stored!.response_encrypted);
      revoked = false;
      await expect(
        encryptedService.readReplay(operatorId, `operation_real_kms_${'k'.repeat(24)}`),
      ).resolves.toMatchObject({ state: 'available' });
    } finally {
      send.mockRestore();
    }
  });

  it('serializes competing aggregate reservations and accounts for encrypted envelope overhead', async () => {
    const [sum] = await db
      .select({
        used: sql<number>`coalesce(sum(${proxyOperations.capacity_reserved_bytes}) filter
      (where ${proxyOperations.capacity_released_at} is null), 0)::bigint`,
      })
      .from(proxyOperations)
      .where(eq(proxyOperations.operator_id, operatorId));
    const capacityBytes = Math.floor((PROXY_REPLAY_CAPACITY_BYTES - Number(sum!.used)) / 2) + 1;
    const keys = ['a', 'b'].map((value) => `operation_capacity_${value.repeat(24)}`);
    const admissions = await Promise.all(keys.map((key) => operationService.admit(admission(key))));
    const claims = await Promise.all(
      admissions.map((admitted, index) => {
        if (admitted.state !== 'created') throw new Error('fixture admission failed');
        return operationService.claimDispatch({
          operatorId,
          operationId: admitted.operation.id,
          operationKey: keys[index]!,
          admissionFence: admitted.operation.admission_fence,
          capacityBytes,
          requestEvidenceHash: admitted.operation.request_hash,
        });
      }),
    );
    expect(claims.map((claim) => claim.state).sort()).toEqual(['acquired', 'capacity_exceeded']);
    for (let i = 0; i < claims.length; i++) {
      const admitted = admissions[i]!;
      if (admitted.state !== 'created') throw new Error('fixture admission failed');
      const row = await repository.findByOperationKey(operatorId, sha256(keys[i]!));
      if (claims[i]!.state === 'capacity_exceeded') {
        expect(row).toMatchObject({
          delivery_state: 'admitted',
          transport_attempts: 0,
          dispatch_owner_hash: null,
          capacity_reserved_bytes: 0,
          accounting_state: 'reserved',
        });
      }
      await repository.erasePayloads(operatorId, admitted.operation.id);
    }
    const item = await dispatched(`operation_overhead_${'o'.repeat(24)}`);
    const stored = await response(item);
    expect(stored!.capacity_used_bytes).toBe(Buffer.byteLength(stored!.response_encrypted!));
    expect(stored!.capacity_reserved_bytes).toBe(stored!.capacity_used_bytes);
    expect(stored!.capacity_used_bytes).toBeGreaterThan(
      Buffer.byteLength(JSON.stringify({ private: 'screened value' })),
    );
  });

  it('rolls back a failed response transaction, preserves the tombstone, and fences capture after account-wide scrub', async () => {
    const item = await dispatched(`operation_db_failure_${'d'.repeat(24)}`);
    // Fail after the real operation UPDATE, while storeResponse updates its attempt.
    // PostgreSQL must roll back the already-written response with that transaction.
    const transaction = db.transaction.bind(db);
    const intercept = vi.spyOn(db, 'transaction').mockImplementation((async (
      callback: (tx: unknown) => Promise<unknown>,
    ) =>
      transaction(async (tx) => {
        const update = tx.update.bind(tx);
        let updates = 0;
        tx.update = ((table: Parameters<typeof update>[0]) => {
          updates += 1;
          if (updates === 2) throw new Error('injected database failure after response UPDATE');
          return update(table);
        }) as typeof tx.update;
        return callback(tx);
      })) as typeof db.transaction);
    try {
      await expect(response(item)).rejects.toThrow('injected database failure');
    } finally {
      intercept.mockRestore();
    }
    const before = await repository.findByOperationKey(
      operatorId,
      sha256(`operation_db_failure_${'d'.repeat(24)}`),
    );
    expect(before).toMatchObject({
      delivery_state: 'dispatching',
      accounting_state: 'committed',
      transport_attempts: 1,
      response_encrypted: null,
      replay_state: 'none',
    });
    await repository.markOutcomeUnknown({
      operatorId,
      operationId: item.admitted.operation.id,
      dispatchOwnerHash: sha256(item.claim.dispatchToken!),
      dispatchFence: item.claim.dispatchFence,
    });
    expect(await repository.erasePayloads(operatorId)).toBeGreaterThan(0);
    expect(await response(item)).toBeNull();
    const rows = await db
      .select()
      .from(proxyOperations)
      .where(eq(proxyOperations.operator_id, operatorId));
    expect(
      rows.every(
        (row) =>
          row.prepared_request_encrypted === null &&
          row.scope_descriptor_encrypted === null &&
          row.response_encrypted === null &&
          row.replay_state === 'erased',
      ),
    ).toBe(true);
    await expect(
      operationService.readReplay(operatorId, `operation_db_failure_${'d'.repeat(24)}`),
    ).resolves.toEqual({ state: 'unavailable', reason: 'outcome_unknown' });
  });

  it('binds encrypted responses to their operator, operation, version and purpose', async () => {
    const firstKey = `operation_aad_first_${'a'.repeat(24)}`;
    const secondKey = `operation_aad_second_${'b'.repeat(24)}`;
    const first = await dispatched(firstKey);
    const second = await dispatched(secondKey);
    for (const item of [first, second]) {
      await operationService.storePermittedResponse({
        operatorId,
        operationId: item.admitted.operation.id,
        dispatchToken: item.claim.dispatchToken!,
        dispatchFence: item.claim.dispatchFence,
        status: 200,
        rawHeaders: { 'content-type': 'application/json' },
        screenedBody: { ok: true },
        capacityBytes: 64 * 1024,
        transportEvidenceHash: `sha256:${sha256(item.admitted.operation.id)}`,
      });
    }
    const [firstRow] = await db
      .select()
      .from(proxyOperations)
      .where(
        and(
          eq(proxyOperations.id, first.admitted.operation.id),
          eq(proxyOperations.operator_id, operatorId),
        ),
      );
    await db
      .update(proxyOperations)
      .set({ response_encrypted: firstRow!.response_encrypted })
      .where(
        and(
          eq(proxyOperations.id, second.admitted.operation.id),
          eq(proxyOperations.operator_id, operatorId),
        ),
      );
    await expect(operationService.readReplay(operatorId, secondKey)).rejects.toThrow(
      'AAD mismatch',
    );
  });

  it('rejects cross-tenant ciphertext substitution and removes every proxy payload on account deletion', async () => {
    const otherOperator = `${operatorId}_other`;
    const otherAgent = `${agentId}_other`;
    const otherConnection = `${connectionId}_other`;
    const otherPassport = `${passportJti}_other`;
    await db
      .insert(operators)
      .values({
        id: otherOperator,
        email: `${otherOperator}@test.invalid`,
        api_key_hash: `hash_other_${suffix}`,
      });
    await db
      .insert(agents)
      .values({ id: otherAgent, operator_id: otherOperator, name: 'Other tenant' });
    await db
      .insert(serviceConnections)
      .values({
        id: otherConnection,
        operator_id: otherOperator,
        service_id: serviceId,
        provider,
        scopes: ['write'],
        credential_ref: 'fixture',
        credential_encrypted: 'fixture',
      });
    await db
      .insert(passports)
      .values({
        jti: otherPassport,
        operator_id: otherOperator,
        agent_id: otherAgent,
        session_id: `ses_other_${suffix}`,
        expires_at: new Date(Date.now() + 60 * 60 * 1000),
      });
    const key = `operation_other_tenant_${'n'.repeat(24)}`;
    const input = admission(key, {
      operatorId: otherOperator,
      agentId: otherAgent,
      connectionId: otherConnection,
      passportJti: otherPassport,
    });
    const admitted = await operationService.admit(input);
    if (admitted.state !== 'created') throw new Error('other tenant admission failed');
    const claim = await operationService.claimDispatch({
      operatorId: otherOperator,
      operationId: admitted.operation.id,
      operationKey: key,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    if (claim.state !== 'acquired' || !claim.dispatchToken)
      throw new Error('other tenant claim failed');
    const capture = () =>
      operationService.storePermittedResponse({
        operatorId: otherOperator,
        operationId: admitted.operation.id,
        dispatchToken: claim.dispatchToken!,
        dispatchFence: claim.dispatchFence,
        status: 200,
        rawHeaders: {},
        screenedBody: { other: 'private' },
        capacityBytes: 64 * 1024,
        transportEvidenceHash: `sha256:${sha256(key)}`,
      });
    try {
      const source = await dispatched(`operation_cross_tenant_source_${'s'.repeat(24)}`);
      const stored = await response(source);
      await capture();
      await db
        .update(proxyOperations)
        .set({ response_encrypted: stored!.response_encrypted })
        .where(
          and(
            eq(proxyOperations.operator_id, otherOperator),
            eq(proxyOperations.id, admitted.operation.id),
          ),
        );
      await expect(operationService.readReplay(otherOperator, key)).rejects.toThrow('AAD mismatch');
      await new OperatorRepository(db).deleteById(otherOperator);
      expect(
        await db
          .select()
          .from(proxyOperations)
          .where(eq(proxyOperations.operator_id, otherOperator)),
      ).toEqual([]);
      await expect(capture()).resolves.toBeNull();
      await expect(operationService.readReplay(otherOperator, key)).resolves.toEqual({
        state: 'unavailable',
        reason: 'none',
      });
      expect(
        await repository.findByOperationKey(
          operatorId,
          sha256(`operation_cross_tenant_source_${'s'.repeat(24)}`),
        ),
      ).not.toBeNull();
    } finally {
      await new OperatorRepository(db).deleteById(otherOperator);
    }
  });

  it('cannot restore a payload after explicit erasure, even from the original dispatch owner', async () => {
    const operationKey = `operation_erasure_${'e'.repeat(24)}`;
    const item = await dispatched(operationKey);
    expect(await repository.erasePayloads(operatorId, item.admitted.operation.id)).toBe(1);
    await expect(
      operationService.storePermittedResponse({
        operatorId,
        operationId: item.admitted.operation.id,
        dispatchToken: item.claim.dispatchToken!,
        dispatchFence: item.claim.dispatchFence,
        status: 200,
        rawHeaders: {},
        screenedBody: { should_not_return: true },
        capacityBytes: 64 * 1024,
        transportEvidenceHash: `sha256:${sha256('late-response')}`,
      }),
    ).resolves.toBeNull();
    const [row] = await db
      .select()
      .from(proxyOperations)
      .where(eq(proxyOperations.id, item.admitted.operation.id));
    expect(row).toMatchObject({
      replay_state: 'erased',
      prepared_request_encrypted: null,
      scope_descriptor_encrypted: null,
      response_encrypted: null,
      capacity_used_bytes: 0,
    });
  });

  it('refuses replay after the 24-hour cutoff before attempting KMS decryption', async () => {
    const operationKey = `operation_expiry_${'x'.repeat(24)}`;
    const item = await dispatched(operationKey);
    const storedAt = new Date('2026-09-10T00:00:00Z');
    await operationService.storePermittedResponse({
      operatorId,
      operationId: item.admitted.operation.id,
      dispatchToken: item.claim.dispatchToken!,
      dispatchFence: item.claim.dispatchFence,
      status: 200,
      rawHeaders: {},
      screenedBody: { ok: true },
      capacityBytes: 64 * 1024,
      transportEvidenceHash: `sha256:${sha256('expiry-response')}`,
      now: storedAt,
    });
    const decryptions = kms.decryptions;
    await expect(
      operationService.readReplay(operatorId, operationKey, new Date('2026-09-11T00:00:01Z')),
    ).resolves.toEqual({ state: 'unavailable', reason: 'expired' });
    expect(kms.decryptions).toBe(decryptions);
    expect(await repository.expireReplay(new Date('2026-09-11T00:00:01Z'))).toBeGreaterThanOrEqual(
      1,
    );
    const [expired] = await db
      .select()
      .from(proxyOperations)
      .where(eq(proxyOperations.id, item.admitted.operation.id));
    expect(expired).toMatchObject({
      replay_state: 'expired',
      prepared_request_encrypted: null,
      scope_descriptor_encrypted: null,
      response_encrypted: null,
      capacity_used_bytes: 0,
    });
    await expect(response(item)).resolves.toBeNull();
  });

  it('replays a stored Stripe 500 without spending another transport attempt', async () => {
    const operationKey = `operation_stripe_retry_${'t'.repeat(24)}`;
    const input = admission(operationKey);
    input.adapter = {
      kind: 'stripe',
      nativeIdempotencyKey: `stack_test_${sha256(operationKey)}`,
      providerAccount: 'credential-owner',
    };
    const admitted = await operationService.admit(input);
    if (admitted.state !== 'created') throw new Error('fixture admission failed');
    const first = await operationService.claimDispatch({
      operatorId,
      operationId: admitted.operation.id,
      operationKey,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    if (first.state !== 'acquired' || !first.dispatchToken) throw new Error('fixture claim failed');
    await operationService.storePermittedResponse({
      operatorId,
      operationId: admitted.operation.id,
      dispatchToken: first.dispatchToken,
      dispatchFence: first.dispatchFence,
      status: 500,
      rawHeaders: {},
      screenedBody: { error: 'provider unresolved' },
      capacityBytes: 64 * 1024,
      transportEvidenceHash: `sha256:${sha256('stripe-500')}`,
    });
    expect(
      await repository.recordReconciliation({
        operatorId,
        operationId: admitted.operation.id,
        dispatchOwnerHash: sha256(first.dispatchToken),
        dispatchFence: first.dispatchFence,
        state: 'not_found',
        evidenceHash: `sha256:${sha256('stripe-not-found')}`,
      }),
    ).toBe(true);

    const retry = await operationService.claimStripeRetry({
      operatorId,
      operationId: admitted.operation.id,
      capacityBytes: 128 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    expect(retry.state).toBe('replay');
    const [row] = await db
      .select()
      .from(proxyOperations)
      .where(eq(proxyOperations.id, admitted.operation.id));
    expect(row).toMatchObject({
      delivery_state: 'response_received',
      replay_state: 'available',
      reconciliation_state: 'not_found',
      transport_attempts: 1,
      response_status: 500,
    });
  });

  it('recovers a missing Stripe response after confirmed evidence without erasing that evidence', async () => {
    const operationKey = `operation_stripe_confirmed_retry_${'q'.repeat(24)}`;
    const input = admission(operationKey);
    input.adapter = {
      kind: 'stripe',
      nativeIdempotencyKey: `stack_test_${sha256(operationKey)}`,
      providerAccount: 'credential-owner',
    };
    const admitted = await operationService.admit(input);
    if (admitted.state !== 'created') throw new Error('fixture admission failed');
    const first = await operationService.claimDispatch({
      operatorId,
      operationId: admitted.operation.id,
      operationKey,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    if (first.state !== 'acquired' || !first.dispatchToken) throw new Error('fixture claim failed');
    await operationService.markOutcomeUnknown({
      operatorId,
      operationId: admitted.operation.id,
      dispatchToken: first.dispatchToken,
      dispatchFence: first.dispatchFence,
      transportEvidenceHash: `sha256:${sha256('lost-response')}`,
    });
    const evidenceHash = `sha256:${sha256('confirmed-refund')}`;
    const resourceHash = `sha256:${sha256('re_confirmed')}`;
    expect(
      await repository.recordReconciliation({
        operatorId,
        operationId: admitted.operation.id,
        dispatchOwnerHash: sha256(first.dispatchToken),
        dispatchFence: first.dispatchFence,
        state: 'confirmed',
        resourceHash,
        evidenceHash,
        providerStatus: 'succeeded',
      }),
    ).toBe(true);

    const retry = await operationService.claimStripeRetry({
      operatorId,
      operationId: admitted.operation.id,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    expect(retry.state).toBe('acquired');
    const [row] = await db
      .select()
      .from(proxyOperations)
      .where(eq(proxyOperations.id, admitted.operation.id));
    expect(row).toMatchObject({
      delivery_state: 'dispatching',
      replay_state: 'none',
      reconciliation_state: 'confirmed',
      reconciliation_resource_hash: resourceHash,
      reconciliation_evidence_hash: evidenceHash,
      reconciliation_provider_status: 'succeeded',
      transport_attempts: 2,
    });
  });

  it('reopens not_found only after a retry transport claim is acquired', async () => {
    const operationKey = `operation_stripe_not_found_retry_${'n'.repeat(24)}`;
    const input = admission(operationKey);
    input.adapter = {
      kind: 'stripe',
      nativeIdempotencyKey: `stack_test_${sha256(operationKey)}`,
      providerAccount: 'credential-owner',
    };
    const admitted = await operationService.admit(input);
    if (admitted.state !== 'created') throw new Error('fixture admission failed');
    const first = await operationService.claimDispatch({
      operatorId,
      operationId: admitted.operation.id,
      operationKey,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    if (first.state !== 'acquired' || !first.dispatchToken) throw new Error('fixture claim failed');
    await operationService.markOutcomeUnknown({
      operatorId,
      operationId: admitted.operation.id,
      dispatchToken: first.dispatchToken,
      dispatchFence: first.dispatchFence,
    });
    const evidenceHash = `sha256:${sha256('not-found-before-retry')}`;
    expect(
      await repository.recordReconciliation({
        operatorId,
        operationId: admitted.operation.id,
        dispatchOwnerHash: sha256(first.dispatchToken),
        dispatchFence: first.dispatchFence,
        state: 'not_found',
        evidenceHash,
      }),
    ).toBe(true);
    const before = await repository.findByOperationKey(operatorId, sha256(operationKey));
    expect(before).toMatchObject({
      delivery_state: 'outcome_unknown',
      reconciliation_state: 'not_found',
      reconciliation_evidence_hash: evidenceHash,
      transport_attempts: 1,
    });

    const retry = await operationService.claimStripeRetry({
      operatorId,
      operationId: admitted.operation.id,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    expect(retry.state).toBe('acquired');
    const after = await repository.findByOperationKey(operatorId, sha256(operationKey));
    expect(after).toMatchObject({
      delivery_state: 'dispatching',
      reconciliation_state: 'pending',
      reconciliation_evidence_hash: null,
      reconciliation_resource_hash: null,
      reconciliation_provider_status: null,
      transport_attempts: 2,
    });
  });

  it('does not claim Stripe transport after the retry deadline', async () => {
    const operationKey = `operation_stripe_deadline_${'d'.repeat(24)}`;
    const input = admission(operationKey);
    input.adapter = {
      kind: 'stripe',
      nativeIdempotencyKey: `stack_test_${sha256(operationKey)}`,
      providerAccount: 'credential-owner',
    };
    const admitted = await operationService.admit(input);
    if (admitted.state !== 'created') throw new Error('fixture admission failed');
    const first = await operationService.claimDispatch({
      operatorId,
      operationId: admitted.operation.id,
      operationKey,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    if (first.state !== 'acquired' || !first.dispatchToken) throw new Error('fixture claim failed');
    await operationService.markOutcomeUnknown({
      operatorId,
      operationId: admitted.operation.id,
      dispatchToken: first.dispatchToken,
      dispatchFence: first.dispatchFence,
    });
    await db
      .update(proxyOperations)
      .set({ retry_deadline: new Date(Date.now() - 1_000) })
      .where(eq(proxyOperations.id, admitted.operation.id));

    await expect(
      operationService.claimStripeRetry({
        operatorId,
        operationId: admitted.operation.id,
        capacityBytes: 64 * 1024,
        requestEvidenceHash: admitted.operation.request_hash,
      }),
    ).resolves.toMatchObject({ state: 'outcome_unknown' });
    const row = await repository.findByOperationKey(operatorId, sha256(operationKey));
    expect(row).toMatchObject({ delivery_state: 'outcome_unknown', transport_attempts: 1 });
  });

  it.each([409, 429])(
    'classifies a stored Stripe %s from later provider evidence',
    async (status) => {
      const operationKey = `operation_stripe_preexecution_${status}_${'h'.repeat(24)}`;
      const input = admission(operationKey);
      input.adapter = {
        kind: 'stripe',
        nativeIdempotencyKey: `stack_test_${sha256(operationKey)}`,
        providerAccount: 'credential-owner',
      };
      const admitted = await operationService.admit(input);
      if (admitted.state !== 'created') throw new Error('fixture admission failed');
      const claim = await operationService.claimDispatch({
        operatorId,
        operationId: admitted.operation.id,
        operationKey,
        admissionFence: admitted.operation.admission_fence,
        capacityBytes: 64 * 1024,
        requestEvidenceHash: admitted.operation.request_hash,
      });
      if (claim.state !== 'acquired' || !claim.dispatchToken)
        throw new Error('fixture claim failed');
      await operationService.storePermittedResponse({
        operatorId,
        operationId: admitted.operation.id,
        dispatchToken: claim.dispatchToken,
        dispatchFence: claim.dispatchFence,
        status,
        rawHeaders: {},
        screenedBody: { error: 'provider pre-execution response' },
        capacityBytes: 64 * 1024,
        transportEvidenceHash: `sha256:${sha256(`stripe-${status}`)}`,
      });
      const providerEvidenceHash = `sha256:${sha256(`stripe-${status}-not-found`)}`;
      expect(
        await repository.recordReconciliation({
          operatorId,
          operationId: admitted.operation.id,
          dispatchOwnerHash: sha256(claim.dispatchToken),
          dispatchFence: claim.dispatchFence,
          state: 'not_found',
          evidenceHash: providerEvidenceHash,
        }),
      ).toBe(true);

      const [row] = await db
        .select()
        .from(proxyOperations)
        .where(eq(proxyOperations.id, admitted.operation.id));
      expect(row).toMatchObject({
        response_status: status,
        replay_state: 'available',
        reconciliation_state: 'not_found',
        reconciliation_evidence_hash: providerEvidenceHash,
        transport_attempts: 1,
      });
    },
  );

  it.each(['contradictory', 'expired'] as const)(
    'keeps %s Stripe evidence fail-closed',
    async (state) => {
      const operationKey = `operation_stripe_closed_${state}_${'z'.repeat(24)}`;
      const input = admission(operationKey);
      input.adapter = {
        kind: 'stripe',
        nativeIdempotencyKey: `stack_test_${sha256(operationKey)}`,
        providerAccount: 'credential-owner',
      };
      const admitted = await operationService.admit(input);
      if (admitted.state !== 'created') throw new Error('fixture admission failed');
      const first = await operationService.claimDispatch({
        operatorId,
        operationId: admitted.operation.id,
        operationKey,
        admissionFence: admitted.operation.admission_fence,
        capacityBytes: 64 * 1024,
        requestEvidenceHash: admitted.operation.request_hash,
      });
      if (first.state !== 'acquired' || !first.dispatchToken)
        throw new Error('fixture claim failed');
      await operationService.markOutcomeUnknown({
        operatorId,
        operationId: admitted.operation.id,
        dispatchToken: first.dispatchToken,
        dispatchFence: first.dispatchFence,
      });
      expect(
        await repository.recordReconciliation({
          operatorId,
          operationId: admitted.operation.id,
          dispatchOwnerHash: sha256(first.dispatchToken),
          dispatchFence: first.dispatchFence,
          state,
          evidenceHash: `sha256:${sha256(state)}`,
        }),
      ).toBe(true);

      await expect(
        operationService.claimStripeRetry({
          operatorId,
          operationId: admitted.operation.id,
          capacityBytes: 64 * 1024,
          requestEvidenceHash: admitted.operation.request_hash,
        }),
      ).resolves.toMatchObject({ state: 'outcome_unknown' });

      await expect(
        operationService.markResponseScreening({
          operatorId,
          operationId: admitted.operation.id,
          dispatchToken: first.dispatchToken,
          dispatchFence: first.dispatchFence,
        }),
      ).resolves.toBe(false);
      await expect(
        operationService.storePermittedResponse({
          operatorId,
          operationId: admitted.operation.id,
          dispatchToken: first.dispatchToken,
          dispatchFence: first.dispatchFence,
          status: 200,
          rawHeaders: {},
          screenedBody: { must_not_replace_provider_evidence: true },
          capacityBytes: 64 * 1024,
          transportEvidenceHash: `sha256:${sha256(`late-${state}`)}`,
        }),
      ).resolves.toBeNull();
      const [closed] = await db
        .select()
        .from(proxyOperations)
        .where(eq(proxyOperations.id, admitted.operation.id));
      expect(closed).toMatchObject({
        delivery_state: 'outcome_unknown',
        replay_state: 'none',
        reconciliation_state: state,
      });
    },
  );

  it('blocks a fresh handle while a received Stripe response is effect-unresolved, then releases it on terminal evidence', async () => {
    const effectCorrelationHash = `sha256:${sha256('shared-stripe-effect')}` as const;
    const originalKey = `operation_stripe_unresolved_${'u'.repeat(24)}`;
    const originalInput = admission(originalKey);
    originalInput.effectCorrelationHash = effectCorrelationHash;
    originalInput.adapter = {
      kind: 'stripe',
      nativeIdempotencyKey: `stack_test_${sha256(originalKey)}`,
      providerAccount: 'credential-owner',
    };
    const original = await operationService.admit(originalInput);
    if (original.state !== 'created') throw new Error('fixture admission failed');
    const claim = await operationService.claimDispatch({
      operatorId,
      operationId: original.operation.id,
      operationKey: originalKey,
      admissionFence: original.operation.admission_fence,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: original.operation.request_hash,
    });
    if (claim.state !== 'acquired' || !claim.dispatchToken) throw new Error('fixture claim failed');
    await operationService.storePermittedResponse({
      operatorId,
      operationId: original.operation.id,
      dispatchToken: claim.dispatchToken,
      dispatchFence: claim.dispatchFence,
      status: 500,
      rawHeaders: {},
      screenedBody: { error: 'provider unresolved' },
      capacityBytes: 64 * 1024,
      transportEvidenceHash: `sha256:${sha256('stripe-unresolved-response')}`,
    });

    const replacementKey = `operation_stripe_replacement_${'v'.repeat(24)}`;
    const replacementInput = admission(replacementKey);
    replacementInput.effectCorrelationHash = effectCorrelationHash;
    const replacement = await operationService.admit(replacementInput);
    if (replacement.state !== 'created') throw new Error('replacement admission failed');
    await expect(
      operationService.transaction((tx) =>
        repository.guardAndConsumeReplacement(
          {
            operatorId,
            replacementOperationId: replacement.operation.id,
            replacementOperationKeyHash: sha256(replacementKey),
            replacementRequestHash: replacement.operation.request_hash,
            effectCorrelationHash,
          },
          tx,
        ),
      ),
    ).resolves.toEqual({ state: 'authorization_required' });

    const evidenceHash = `sha256:${sha256('stripe-terminal-success')}`;
    expect(
      await repository.recordReconciliation({
        operatorId,
        operationId: original.operation.id,
        dispatchOwnerHash: sha256(claim.dispatchToken),
        dispatchFence: claim.dispatchFence,
        state: 'confirmed',
        resourceHash: `sha256:${sha256('re_terminal')}`,
        evidenceHash,
        providerStatus: 'succeeded',
      }),
    ).toBe(true);

    const laterKey = `operation_stripe_later_${'w'.repeat(24)}`;
    const laterInput = admission(laterKey);
    laterInput.effectCorrelationHash = effectCorrelationHash;
    const later = await operationService.admit(laterInput);
    if (later.state !== 'created') throw new Error('later admission failed');
    await expect(
      operationService.transaction((tx) =>
        repository.guardAndConsumeReplacement(
          {
            operatorId,
            replacementOperationId: later.operation.id,
            replacementOperationKeyHash: sha256(laterKey),
            replacementRequestHash: later.operation.request_hash,
            effectCorrelationHash,
          },
          tx,
        ),
      ),
    ).resolves.toEqual({ state: 'not_required' });
  });

  it('keeps a terminal provider conclusion immutable while appending contradictory late evidence', async () => {
    const operationKey = `operation_late_evidence_${'l'.repeat(24)}`;
    const input = admission(operationKey);
    input.adapter = {
      kind: 'stripe',
      nativeIdempotencyKey: `stack_test_${sha256(operationKey)}`,
      providerAccount: 'credential-owner',
    };
    const admitted = await operationService.admit(input);
    if (admitted.state !== 'created') throw new Error('fixture admission failed');
    const claim = await operationService.claimDispatch({
      operatorId,
      operationId: admitted.operation.id,
      operationKey,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: 64 * 1024,
      requestEvidenceHash: admitted.operation.request_hash,
    });
    if (claim.state !== 'acquired' || !claim.dispatchToken) throw new Error('fixture claim failed');
    const owner = sha256(claim.dispatchToken);
    const confirmedEvidence = `sha256:${sha256('confirmed')}`;
    const contradictoryEvidence = `sha256:${sha256('contradictory')}`;
    expect(
      await repository.recordReconciliation({
        operatorId,
        operationId: admitted.operation.id,
        dispatchOwnerHash: owner,
        dispatchFence: claim.dispatchFence,
        state: 'confirmed',
        resourceHash: `sha256:${sha256('refund-one')}`,
        evidenceHash: confirmedEvidence,
        providerStatus: 'succeeded',
      }),
    ).toBe(true);
    expect(
      await repository.recordReconciliation({
        operatorId,
        operationId: admitted.operation.id,
        dispatchOwnerHash: owner,
        dispatchFence: claim.dispatchFence,
        state: 'contradictory',
        resourceHash: `sha256:${sha256('refund-two')}`,
        evidenceHash: contradictoryEvidence,
        late: true,
      }),
    ).toBe(true);

    const [row] = await db
      .select()
      .from(proxyOperations)
      .where(eq(proxyOperations.id, admitted.operation.id));
    expect(row).toMatchObject({
      reconciliation_state: 'confirmed',
      reconciliation_evidence_hash: confirmedEvidence,
      contradictory_evidence_hash: contradictoryEvidence,
    });
    const evidence = await db
      .select()
      .from(proxyOperationEvidence)
      .where(eq(proxyOperationEvidence.operation_id, admitted.operation.id));
    expect(evidence).toHaveLength(2);
    expect(evidence.map((entry) => entry.kind)).toEqual(
      expect.arrayContaining(['reconciliation', 'contradictory']),
    );
  });

  it('keeps metadata visible but denies payload replay after the originating Passport is revoked', async () => {
    const operationKey = `operation_revoked_passport_${'p'.repeat(24)}`;
    const item = await dispatched(operationKey);
    await operationService.storePermittedResponse({
      operatorId,
      operationId: item.admitted.operation.id,
      dispatchToken: item.claim.dispatchToken!,
      dispatchFence: item.claim.dispatchFence,
      status: 200,
      rawHeaders: {},
      screenedBody: { private: true },
      capacityBytes: 64 * 1024,
      transportEvidenceHash: `sha256:${sha256('revoked-passport-response')}`,
    });
    await db
      .update(passports)
      .set({ revoked_at: new Date(), revoked_reason: 'fixture' })
      .where(eq(passports.jti, passportJti));
    try {
      const decryptions = kms.decryptions;
      await expect(
        operationService.authorizeRead({
          operatorId,
          operationKey,
          currentAgentId: agentId,
          includeResponse: true,
          freshAuthority: {
            services: [
              {
                service_id: serviceId,
                service_name: provider,
                connection_id: connectionId,
                scopes: ['write'],
              },
            ],
            intentServices: [provider],
          },
        }),
      ).resolves.toMatchObject({
        metadata: { replayState: 'available' },
        replay: { state: 'unavailable', reason: 'none' },
      });
      expect(kms.decryptions).toBe(decryptions);
    } finally {
      await db
        .update(passports)
        .set({ revoked_at: null, revoked_reason: null })
        .where(eq(passports.jti, passportJti));
    }
  });

  it('keeps revoked Passport outcomes as history but excludes them from prerequisites and refuses new source claims', async () => {
    const claims = new PassportClaimsRepository(db);
    const claimId = `pc_revocation_${suffix}`;
    await claims.insertFromSource({
      claim_id: claimId,
      passport_id: passportJti,
      type: 'intent_outcome',
      body_json: { status: 'succeeded' },
      claim_hash: sha256('revocation-fixture'),
      signature: '',
      operator_id: operatorId,
      subject: `stack://${operatorId}/passport/${passportJti}`,
      envelope_version: 1,
      claim_version: 1,
      envelope_cose: 'fixture',
      issuer: operatorId,
      issued_at_ms: Date.now(),
      receipt: null,
      source_operation_id: `pop_revocation_${suffix}`,
      source_role: 'proxy_outcome',
    });
    await db
      .update(passports)
      .set({ revoked_at: new Date(), revoked_reason: 'fixture' })
      .where(eq(passports.jti, passportJti));
    try {
      await expect(
        claims.findActiveOutcomesByClaimIdsAndSessionId([claimId], `ses_${suffix}`),
      ).resolves.toEqual([]);
      const late = await claims.insertFromSource({
        claim_id: `pc_after_revocation_${suffix}`,
        passport_id: passportJti,
        type: 'intent_outcome',
        body_json: { status: 'succeeded' },
        claim_hash: sha256('after-revocation'),
        signature: '',
        operator_id: operatorId,
        subject: `stack://${operatorId}/passport/${passportJti}`,
        envelope_version: 1,
        claim_version: 1,
        envelope_cose: 'fixture',
        issuer: operatorId,
        issued_at_ms: Date.now(),
        receipt: null,
        source_operation_id: `pop_after_revocation_${suffix}`,
        source_role: 'proxy_outcome',
      });
      expect(late.revoked_at).toBeInstanceOf(Date);
      expect(late.revoked_reason).toBe('fixture');
      const historical = await db
        .select()
        .from(passportClaims)
        .where(eq(passportClaims.claim_id, claimId));
      expect(historical).toHaveLength(1);
      await expect(
        claims.findActiveOutcomesByClaimIdsAndSessionId([late.claim_id], `ses_${suffix}`),
      ).resolves.toEqual([]);
    } finally {
      await db
        .update(passports)
        .set({ revoked_at: null, revoked_reason: null })
        .where(eq(passports.jti, passportJti));
    }
  });
});
