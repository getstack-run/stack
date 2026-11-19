// Admission and dispatch authority: bind a prepared request to its authority and scope, persist it
// encrypted, and release the prepared request only to the fenced dispatch owner.

import { randomUUID } from 'node:crypto';
import { canonicalize, ProxyOperationId } from '@stack/shared';
import { type ProxyOperationTransaction } from '../../repositories/proxy-operation-repo.js';
import { assertScopeDescriptorBinding, sameBinding } from './scope.js';
import {
  type PreparedProxyRequest,
  type AdmitProxyOperationInput,
  type AdmitProxyOperationResult,
  type ProxyOperationDeps,
} from './types.js';
import {
  ENVELOPE_VERSION,
  REPLAY_TTL_MS,
  STRIPE_RETRY_TTL_MS,
  OWNER_LEASE_MS,
  admissionOwnerHashFor,
  preparedAad,
  scopeAad,
  sha256,
  proxyOwnerTokenMatches,
} from './envelope.js';

export async function admit(
  deps: ProxyOperationDeps,
  input: AdmitProxyOperationInput,
  transaction?: ProxyOperationTransaction,
): Promise<AdmitProxyOperationResult> {
  if (!ProxyOperationId.safeParse(input.operationKey).success) {
    throw new Error('Proxy operation key must be 22 to 256 base64url characters');
  }
  if (input.credentialVersion < 1 || !Number.isSafeInteger(input.credentialVersion)) {
    throw new Error('Credential version must be a positive integer');
  }
  if (input.preparedRequest.version !== ENVELOPE_VERSION) {
    throw new Error('Unsupported prepared proxy request version');
  }
  if (input.preparedRequest.method !== input.preparedRequest.method.toUpperCase()) {
    throw new Error('Prepared proxy method must be canonical uppercase');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(input.effectCorrelationHash)) {
    throw new Error('Proxy effect correlation must be a canonical sha256 hash');
  }

  const operationKeyHash = sha256(input.operationKey);
  const existing = await deps.repository.findByOperationKey(input.operatorId, operationKeyHash, transaction);
  const expectedIdentity = {
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
    pathname: new URL(input.preparedRequest.finalUrl).pathname,
    query_pairs: [...new URL(input.preparedRequest.finalUrl).searchParams.entries()],
    headers: Object.entries(input.preparedRequest.headers),
    body_kind: input.preparedRequest.bodyKind,
    body_bytes: input.preparedRequest.bodyBytes,
  };
  const requestHash = `sha256:${sha256(canonicalize(expectedIdentity))}`;
  if (input.preparedRequest.requestHash !== requestHash
    || input.preparedRequest.persistence.destinationConfigHash !== input.destinationConfigHash) {
    throw new Error('Prepared proxy request commitment does not match its authority binding');
  }
  const adapter = input.adapter ?? { kind: 'generic' as const };
  const destinationConfigHash = input.destinationConfigHash;
  assertScopeDescriptorBinding(input.scopeDescriptor, input);
  const scopeCommitmentHash = `sha256:${sha256(canonicalize(input.scopeDescriptor))}`;
  const nativeKeyHash = adapter.kind === 'stripe' ? sha256(adapter.nativeIdempotencyKey) : null;
  const providerAccountHash = adapter.kind === 'stripe' ? sha256(adapter.providerAccount) : null;
  if (existing) {
    return sameBinding(existing, input, requestHash, nativeKeyHash, providerAccountHash)
      ? { state: 'replay', operation: existing }
      : { state: 'conflict', operation: existing };
  }

  const now = input.now ?? new Date();
  const operationId = `pop_${randomUUID()}`;
  // The stable operation key is authenticated by the route and is the only
  // admission capability that survives a process crash. Persist only a
  // domain-separated hash so PostgreSQL cannot recover the public handle.
  const admissionOwnerHash = admissionOwnerHashFor(input.operatorId, input.operationKey);
  const preparedContext = preparedAad(input.operatorId, operationId);
  const encrypted = await deps.kms.encrypt(canonicalize(input.preparedRequest), preparedContext);
  const scopeEncrypted = await deps.kms.encrypt(
    canonicalize(input.scopeDescriptor),
    scopeAad(input.operatorId, operationId),
  );
  const tombstoneHash = sha256(canonicalize({
    operatorId: input.operatorId,
    operationKeyHash,
    requestHash,
    effectCorrelationHash: input.effectCorrelationHash,
    agentId: input.agentId,
    passportJti: input.passportJti,
    authorityUseId: input.authorityUseId ?? null,
    approvalId: input.approvalId ?? null,
    connectionId: input.connectionId,
    credentialVersion: input.credentialVersion,
    destinationConfigHash,
    scopeCommitmentHash,
    adapterKind: adapter.kind,
    nativeKeyHash,
    providerAccountHash,
  }));
  const result = await deps.repository.insertAdmitted({
    id: operationId,
    operator_id: input.operatorId,
    operation_key_hash: operationKeyHash,
    request_hash: requestHash,
    effect_correlation_hash: input.effectCorrelationHash,
    tombstone_hash: tombstoneHash,
    prepared_request_version: ENVELOPE_VERSION,
    prepared_request_encrypted: encrypted.ciphertext,
    prepared_request_key_ref: encrypted.keyRef,
    prepared_request_readable_until: new Date(now.getTime() + REPLAY_TTL_MS),
    agent_id: input.agentId,
    passport_jti: input.passportJti,
    authority_use_id: input.authorityUseId ?? null,
    approval_id: input.approvalId ?? null,
    service_connection_id: input.connectionId,
    service_id: input.serviceId,
    credential_version: input.credentialVersion,
    provider: input.provider,
    method: input.preparedRequest.method,
    destination_config_hash: destinationConfigHash,
    scope_commitment_hash: scopeCommitmentHash,
    scope_descriptor_version: ENVELOPE_VERSION,
    scope_descriptor_encrypted: scopeEncrypted.ciphertext,
    scope_descriptor_key_ref: scopeEncrypted.keyRef,
    destination_origin: input.preparedRequest.persistence.origin,
    pathname_hash: input.preparedRequest.persistence.pathnameHash,
    query_hash: input.preparedRequest.persistence.queryHash,
    header_names: input.preparedRequest.persistence.headerNames,
    headers_hash: input.preparedRequest.persistence.headersHash,
    body_hash: input.preparedRequest.persistence.bodyHash,
    body_bytes: input.preparedRequest.persistence.bodyBytes,
    adapter_kind: adapter.kind,
    native_idempotency_key_hash: nativeKeyHash,
    provider_account_hash: providerAccountHash,
    retry_deadline: adapter.kind === 'stripe' ? new Date(now.getTime() + STRIPE_RETRY_TTL_MS) : null,
    reconciliation_state: adapter.kind === 'stripe' ? 'pending' : 'not_required',
    admission_owner_hash: admissionOwnerHash,
    admission_lease_expires_at: new Date(now.getTime() + OWNER_LEASE_MS),
    accounting_period: input.accountingPeriod,
    accounting_cents: input.accountingCents,
    accounting_obligation_id: input.accountingObligationId,
    accounting_reserved_at: now,
    created_at: now,
    updated_at: now,
  }, transaction);
  if (result.state === 'capacity_exceeded') {
    return { state: 'capacity_exceeded', limit: result.limit, used: result.used };
  }
  if (result.state === 'existing') {
    return sameBinding(result.operation, input, requestHash, nativeKeyHash, providerAccountHash)
      ? { state: 'replay', operation: result.operation }
      : { state: 'conflict', operation: result.operation };
  }
  return { state: 'created', operation: result.operation };
}

export async function decryptPreparedRequest(deps: ProxyOperationDeps, input: {
  operatorId: string;
  operationKey: string;
  dispatchToken: string;
  dispatchFence: number;
  now?: Date;
}): Promise<PreparedProxyRequest> {
  const operation = await deps.repository.findByOperationKey(
    input.operatorId,
    sha256(input.operationKey),
  );
  if (!operation || !operation.dispatch_owner_hash
    || operation.dispatch_fence !== input.dispatchFence
    || !proxyOwnerTokenMatches(input.dispatchToken, operation.dispatch_owner_hash)) {
    throw new Error('Proxy dispatch ownership does not match');
  }
  if (!operation.prepared_request_encrypted || operation.replay_state === 'erased'
    || operation.replay_state === 'expired'
    || operation.prepared_request_readable_until <= (input.now ?? new Date())) {
    throw new Error('Prepared proxy request is no longer available');
  }
  const plaintext = await deps.kms.decrypt(
    operation.prepared_request_encrypted,
    preparedAad(input.operatorId, operation.id),
  );
  const prepared = JSON.parse(plaintext) as PreparedProxyRequest;
  if (prepared.version !== ENVELOPE_VERSION || prepared.method !== operation.method) {
    throw new Error('Stored prepared proxy request envelope is invalid');
  }
  return prepared;
}
