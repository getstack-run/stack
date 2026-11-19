import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { canonicalize } from '@stack/shared';
import type { EncryptionContext, KmsService } from '../crypto/kms.js';
import type { ProxyOperationRepository, ProxyOperationRow } from '../repositories/proxy-operation-repo.js';
import {
  ProxyOperationService,
  admissionOwnerHashFor,
  preparedAad,
  responseAad,
  type AdmitProxyOperationInput,
} from './proxy-operation-service.js';

class FakeKms {
  encryptions: Array<{ plaintext: string; context?: EncryptionContext }> = [];
  decryptions: Array<{ ciphertext: string; context?: EncryptionContext }> = [];

  async encrypt(plaintext: string, context?: EncryptionContext) {
    this.encryptions.push({ plaintext, context });
    return {
      ciphertext: Buffer.from(JSON.stringify({ plaintext, context })).toString('base64'),
      keyRef: 'fixture-key',
    };
  }

  async decrypt(ciphertext: string, context?: EncryptionContext) {
    this.decryptions.push({ ciphertext, context });
    const envelope = JSON.parse(Buffer.from(ciphertext, 'base64').toString()) as {
      plaintext: string;
      context?: EncryptionContext;
    };
    if (JSON.stringify(envelope.context) !== JSON.stringify(context)) throw new Error('AAD mismatch');
    return envelope.plaintext;
  }
}

class FakeRepository {
  row: ProxyOperationRow | null = null;
  originalPassportReplayable = true;

  async findByOperationKey(operatorId: string, operationKeyHash: string) {
    return this.row?.operator_id === operatorId && this.row.operation_key_hash === operationKeyHash
      ? this.row
      : null;
  }

  async findVisibleByOperationKey(operatorId: string, operationKeyHash: string) {
    return this.findByOperationKey(operatorId, operationKeyHash);
  }

  async originalPassportAllowsReplay() {
    return this.originalPassportReplayable;
  }

  async insertAdmitted(input: Record<string, unknown>) {
    this.row = {
      delivery_state: 'admitted',
      replay_state: 'none',
      accounting_state: 'reserved',
      admission_fence: 1,
      dispatch_fence: 0,
      transport_attempts: 0,
      ...input,
    } as unknown as ProxyOperationRow;
    return { state: 'created' as const, operation: this.row };
  }

  async storeResponse(input: Record<string, unknown>) {
    if (!this.row) return null;
    this.row = {
      ...this.row,
      delivery_state: 'response_received',
      replay_state: 'available',
      response_status: input['status'] as number,
      response_hash: input['responseHash'] as string,
      response_encrypted: input['ciphertext'] as string,
      response_key_ref: input['keyRef'] as string,
      response_ciphertext_bytes: input['ciphertextBytes'] as number,
      response_readable_until: input['readableUntil'] as Date,
    };
    return this.row;
  }

  async claimDispatch(input: Record<string, unknown>) {
    if (!this.row || this.row.delivery_state !== 'admitted'
      || this.row.admission_owner_hash !== input['admissionOwnerHash']) {
      return { state: 'busy' as const, operation: this.row! };
    }
    this.row = {
      ...this.row,
      delivery_state: 'dispatching',
      accounting_state: 'committed',
      accounting_committed_at: new Date(),
      dispatch_owner_hash: input['dispatchOwnerHash'] as string,
      dispatch_fence: 1,
      transport_attempts: 1,
    };
    return { state: 'acquired' as const, operation: this.row, dispatchFence: 1 };
  }
}

function admission(now = new Date('2026-09-10T00:00:00Z')): AdmitProxyOperationInput {
  const destinationConfigHash = `sha256:${'d'.repeat(64)}` as const;
  const prepared = {
    version: 1 as const,
    service: 'stripe',
    method: 'POST' as const,
    finalUrl: 'https://api.stripe.com/v1/payment_intents?expand%5B%5D=customer',
    headers: { 'content-type': 'application/json' },
    bodyBytes: '{"amount":100}',
    bodyKind: 'json' as const,
    persistence: {
      origin: 'https://api.stripe.com',
      pathnameHash: `sha256:${'a'.repeat(64)}` as const,
      queryHash: `sha256:${'b'.repeat(64)}` as const,
      destinationConfigHash,
      headerNames: ['content-type'],
      headersHash: `sha256:${'c'.repeat(64)}` as const,
      bodyHash: `sha256:${'e'.repeat(64)}` as const,
      bodyBytes: 14,
    },
  };
  const identity = {
    version: 1, operator_id: 'op_fixture', agent_id: 'agt_fixture', passport_jti: 'ppt_fixture',
    authority_use_id: null, approval_id: null, service_connection_id: 'scon_fixture',
    credential_version: 3, destination_config_hash: destinationConfigHash, service: 'stripe', method: 'POST',
    origin: prepared.persistence.origin, pathname: '/v1/payment_intents',
    query_pairs: [['expand[]', 'customer']], headers: Object.entries(prepared.headers),
    body_kind: 'json', body_bytes: prepared.bodyBytes,
  };
  return {
    operatorId: 'op_fixture',
    operationKey: 'abcdefghijklmnopqrstuv',
    agentId: 'agt_fixture',
    passportJti: 'ppt_fixture',
    connectionId: 'scon_fixture',
    serviceId: 'svc_stripe',
    credentialVersion: 3,
    provider: 'stripe',
    destinationConfigHash,
    scopeDescriptor: {
      version: 1,
      provider: 'stripe',
      serviceId: 'svc_stripe',
      connectionId: 'scon_fixture',
      scopes: ['payments:write'],
      intents: ['stripe'],
      constraints: [],
      policy: null,
      allowDataFrom: [],
      discloseTo: [],
      resource: {
        method: 'POST',
        origin: 'https://api.stripe.com',
        pathname: '/v1/payment_intents',
      },
      authorityRefs: [],
    },
    preparedRequest: {
      ...prepared,
      requestHash: `sha256:${createHash('sha256').update(canonicalize(identity)).digest('hex')}`,
    },
    effectCorrelationHash: `sha256:${'9'.repeat(64)}` as const,
    accountingPeriod: '2026-09',
    accountingCents: 0,
    accountingObligationId: 'proxy-obligation',
    adapter: { kind: 'stripe', nativeIdempotencyKey: 'native-key', providerAccount: 'acct_123' },
    now,
  };
}

function refreshPreparedRequestHash(input: AdmitProxyOperationInput): void {
  const url = new URL(input.preparedRequest.finalUrl);
  const identity = {
    version: 1,
    operator_id: input.operatorId,
    agent_id: input.agentId,
    passport_jti: input.passportJti,
    authority_use_id: input.authorityUseId ?? null,
    approval_id: input.approvalId ?? null,
    service_connection_id: input.connectionId,
    credential_version: input.credentialVersion,
    destination_config_hash: input.destinationConfigHash,
    service: input.preparedRequest.service,
    method: input.preparedRequest.method,
    origin: input.preparedRequest.persistence.origin,
    pathname: url.pathname,
    query_pairs: [...url.searchParams.entries()],
    headers: Object.entries(input.preparedRequest.headers),
    body_kind: input.preparedRequest.bodyKind,
    body_bytes: input.preparedRequest.bodyBytes,
  };
  input.preparedRequest.requestHash = `sha256:${createHash('sha256').update(canonicalize(identity)).digest('hex')}`;
}

describe('ProxyOperationService security boundaries', () => {
  it('encrypts exact prepared bytes with operation-scoped AAD and stores only commitments in plaintext', async () => {
    const repo = new FakeRepository();
    const kms = new FakeKms();
    const service = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      kms as unknown as KmsService,
    );
    const result = await service.admit(admission());
    expect(result.state).toBe('created');
    if (result.state !== 'created') return;
    expect(kms.encryptions[0]?.context).toEqual(preparedAad('op_fixture', result.operation.id));
    expect(repo.row?.prepared_request_encrypted).not.toContain('{"amount":100}');
    expect(repo.row?.request_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(repo.row?.destination_config_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(repo.row?.retry_deadline).toEqual(new Date('2026-09-10T23:00:00Z'));
  });

  it('rejects changed immutable content under the same operation key', async () => {
    const repo = new FakeRepository();
    const service = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      new FakeKms() as unknown as KmsService,
    );
    expect((await service.admit(admission())).state).toBe('created');
    const changed = admission();
    changed.credentialVersion = 4;
    refreshPreparedRequestHash(changed);
    expect((await service.admit(changed)).state).toBe('conflict');
  });

  it('stores only allowlisted headers and enforces the read cutoff before KMS decrypt', async () => {
    const repo = new FakeRepository();
    const kms = new FakeKms();
    const service = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      kms as unknown as KmsService,
    );
    const admitted = await service.admit(admission());
    if (admitted.state !== 'created') throw new Error('fixture admission failed');
    repo.row = {
      ...admitted.operation,
      delivery_state: 'dispatching',
      dispatch_owner_hash: 'f'.repeat(64),
      dispatch_fence: 1,
    };
    await service.storePermittedResponse({
      operatorId: 'op_fixture', operationId: admitted.operation.id,
      dispatchToken: 'not-checked-by-fake', dispatchFence: 1, status: 201,
      rawHeaders: {
        'Content-Type': 'application/json',
        'Idempotent-Replayed': 'true',
        'Set-Cookie': 'session=secret',
        Authorization: 'Bearer upstream-secret',
        Location: 'https://example.test/callback?token=secret',
      },
      screenedBody: { id: 'pi_safe' }, capacityBytes: 1_000_000,
      transportEvidenceHash: 'evidence', now: new Date('2026-09-10T00:00:00Z'),
    });
    expect(kms.encryptions[2]?.context).toEqual(responseAad('op_fixture', admitted.operation.id));
    expect(await service.readReplay('op_fixture', admission().operationKey,
      new Date('2026-09-10T12:00:00Z'))).toEqual({
      state: 'available', status: 201,
      headers: { 'content-type': 'application/json', 'idempotent-replayed': 'true' }, body: { id: 'pi_safe' },
    });
    const decrypts = kms.decryptions.length;
    expect(await service.readReplay('op_fixture', admission().operationKey,
      new Date('2026-09-11T00:00:01Z'))).toEqual({ state: 'unavailable', reason: 'expired' });
    expect(kms.decryptions).toHaveLength(decrypts);
  });

  it('recovers pre-dispatch ownership from the authenticated operation key after a crash', async () => {
    const repo = new FakeRepository();
    const firstProcess = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      new FakeKms() as unknown as KmsService,
    );
    const admitted = await firstProcess.admit(admission());
    if (admitted.state !== 'created') throw new Error('fixture admission failed');
    expect(admitted.operation.admission_owner_hash).toBe(
      admissionOwnerHashFor('op_fixture', admission().operationKey),
    );

    const replacementProcess = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      new FakeKms() as unknown as KmsService,
    );
    const claimed = await replacementProcess.claimDispatch({
      operatorId: 'op_fixture',
      operationId: admitted.operation.id,
      operationKey: admission().operationKey,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: 1024,
      requestEvidenceHash: 'evidence',
    });
    expect(claimed.state).toBe('acquired');
    expect(repo.row?.accounting_state).toBe('committed');
  });

  it('requires a fresh Passport to cover the encrypted original authority references before replay', async () => {
    const repo = new FakeRepository();
    const kms = new FakeKms();
    const service = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      kms as unknown as KmsService,
    );
    const input = admission();
    input.scopeDescriptor.authorityRefs = [{ binding_id: 'arb_fixture', proof_ids: ['arp_fixture'] }];
    const admitted = await service.admit(input);
    if (admitted.state !== 'created') throw new Error('fixture admission failed');

    const baseAuthority = {
      services: [{
        service_id: 'svc_stripe',
        service_name: 'stripe',
        connection_id: 'scon_fixture',
        scopes: ['payments:write'],
      }],
      intentServices: ['stripe'],
      authorityRefs: [{ binding_id: 'arb_fixture', proof_ids: ['arp_fixture'] }],
    };
    await expect(service.authorizeRead({
      operatorId: 'op_fixture', operationKey: input.operationKey,
      currentAgentId: 'agt_fixture', freshAuthority: baseAuthority,
    })).resolves.toMatchObject({ metadata: { connectionId: 'scon_fixture', serviceId: 'svc_stripe' } });

    await expect(service.authorizeRead({
      operatorId: 'op_fixture', operationKey: input.operationKey,
      currentAgentId: 'agt_fixture', freshAuthority: { ...baseAuthority, authorityRefs: [] },
    })).resolves.toBeNull();
  });

  it('returns authorized tombstone metadata after expiry without decrypting scrubbed payloads', async () => {
    const repo = new FakeRepository();
    const kms = new FakeKms();
    const service = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      kms as unknown as KmsService,
    );
    const input = admission();
    const admitted = await service.admit(input);
    if (admitted.state !== 'created' || !repo.row) throw new Error('fixture admission failed');
    repo.row = {
      ...repo.row,
      replay_state: 'expired',
      scope_descriptor_encrypted: null,
      scope_descriptor_key_ref: null,
      prepared_request_encrypted: null,
      prepared_request_key_ref: null,
      response_encrypted: null,
      response_key_ref: null,
      response_ciphertext_bytes: null,
    };
    const decryptions = kms.decryptions.length;
    await expect(service.authorizeRead({
      operatorId: 'op_fixture', operationKey: input.operationKey,
      currentAgentId: 'agt_fixture', includeResponse: true,
      freshAuthority: {
        services: [{
          service_id: 'svc_stripe', service_name: 'stripe',
          connection_id: 'scon_fixture', scopes: ['payments:write'],
        }],
      },
    })).resolves.toMatchObject({
      metadata: { replayState: 'expired' },
      replay: { state: 'unavailable', reason: 'expired' },
    });
    expect(kms.decryptions).toHaveLength(decryptions);
  });

  it('keeps authorized tombstone metadata visible after explicit payload erasure', async () => {
    const repo = new FakeRepository();
    const kms = new FakeKms();
    const service = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      kms as unknown as KmsService,
    );
    const input = admission();
    const admitted = await service.admit(input);
    if (admitted.state !== 'created' || !repo.row) throw new Error('fixture admission failed');
    repo.row = {
      ...repo.row,
      replay_state: 'erased',
      scope_descriptor_encrypted: null,
      scope_descriptor_key_ref: null,
      prepared_request_encrypted: null,
      prepared_request_key_ref: null,
      response_encrypted: null,
      response_key_ref: null,
      response_ciphertext_bytes: null,
    };
    const decryptions = kms.decryptions.length;
    await expect(service.authorizeRead({
      operatorId: 'op_fixture', operationKey: input.operationKey,
      currentAgentId: 'agt_fixture', includeResponse: true,
      freshAuthority: {
        services: [{
          service_id: 'svc_stripe', service_name: 'stripe',
          connection_id: 'scon_fixture', scopes: ['payments:write'],
        }],
      },
    })).resolves.toMatchObject({
      metadata: { replayState: 'erased' },
      replay: { state: 'unavailable', reason: 'erased' },
    });
    expect(kms.decryptions).toHaveLength(decryptions);
  });

  it('permits read-only Stripe reconciliation after a response was received but the effect is unresolved', async () => {
    const repo = new FakeRepository();
    const kms = new FakeKms();
    const service = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      kms as unknown as KmsService,
    );
    const input = admission();
    input.preparedRequest.finalUrl = 'https://api.stripe.com/v1/refunds';
    input.preparedRequest.headers['stripe-account'] = 'acct_123';
    input.preparedRequest.persistence.pathnameHash = `sha256:${'7'.repeat(64)}`;
    input.preparedRequest.persistence.queryHash = `sha256:${'8'.repeat(64)}`;
    input.preparedRequest.persistence.headerNames = ['content-type', 'stripe-account'];
    input.scopeDescriptor.resource.pathname = '/v1/refunds';
    refreshPreparedRequestHash(input);
    const admitted = await service.admit(input);
    if (admitted.state !== 'created' || !repo.row) throw new Error('fixture admission failed');
    repo.row = {
      ...repo.row,
      delivery_state: 'response_received',
      replay_state: 'available',
      response_status: 500,
    };

    await expect(service.readStripeReconciliationTarget({
      operatorId: input.operatorId,
      operationKey: input.operationKey,
      now: new Date('2026-09-10T12:00:00Z'),
    })).resolves.toMatchObject({
      metadata: { deliveryState: 'response_received', responseStatus: 500 },
      stripeAccount: 'acct_123',
    });
  });

  it('returns status but never decrypts a stored response after the originating Passport is revoked', async () => {
    const repo = new FakeRepository();
    const kms = new FakeKms();
    const service = new ProxyOperationService(
      repo as unknown as ProxyOperationRepository,
      kms as unknown as KmsService,
    );
    const input = admission();
    const admitted = await service.admit(input);
    if (admitted.state !== 'created' || !repo.row) throw new Error('fixture admission failed');
    repo.row = {
      ...repo.row,
      delivery_state: 'response_received',
      replay_state: 'available',
      response_status: 200,
      response_hash: `sha256:${'f'.repeat(64)}`,
      response_readable_until: new Date('2026-09-11T00:00:00Z'),
      response_encrypted: 'must-not-decrypt',
    };
    repo.originalPassportReplayable = false;
    const decryptions = kms.decryptions.length;
    await expect(service.authorizeRead({
      operatorId: input.operatorId,
      operationKey: input.operationKey,
      currentAgentId: input.agentId,
      includeResponse: true,
      now: new Date('2026-09-10T12:00:00Z'),
      freshAuthority: {
        services: [{
          service_id: input.serviceId,
          service_name: input.provider,
          connection_id: input.connectionId,
          scopes: ['payments:write'],
        }],
        intentServices: ['stripe'],
      },
    })).resolves.toMatchObject({
      metadata: { replayState: 'available' },
      replay: { state: 'unavailable', reason: 'none' },
    });
    expect(kms.decryptions).toHaveLength(decryptions);
  });
});
