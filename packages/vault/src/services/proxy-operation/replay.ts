// Stored responses and status reads: store only the detector-screened body and safe headers, read
// a replay back, and authorize metadata or replay reads against the caller's fresh authority.

import { canonicalize, ProxyOperationId } from '@stack/shared';
import { type ProxyOperationRow } from '../../repositories/proxy-operation-repo.js';
import {
  type ProxyScopeDescriptor,
  type ProxyPostResponseContext,
  type FreshProxyAuthority,
  type ProxyReplayResult,
  type ProxyOperationMetadata,
  type ResponseEnvelope,
  type ProxyOperationDeps,
} from './types.js';
import {
  ENVELOPE_VERSION,
  REPLAY_TTL_MS,
  SAFE_PROXY_REPLAY_HEADERS,
  responseAad,
  scopeAad,
  postResponseAad,
  parseResponseEnvelope,
  sha256,
} from './envelope.js';
import { scopeCovers } from './scope.js';

/** Store only the detector-screened body and a fixed safe-header projection. */
export async function storePermittedResponse(deps: ProxyOperationDeps, input: {
  operatorId: string;
  operationId: string;
  dispatchToken: string;
  dispatchFence: number;
  status: number;
  rawHeaders: Record<string, string>;
  screenedBody: unknown;
  capacityBytes: number;
  transportEvidenceHash: string;
  providerRequestId?: string;
  postResponseContext?: ProxyPostResponseContext;
  now?: Date;
}): Promise<ProxyOperationRow | null> {
  if (input.status < 100 || input.status > 599) throw new Error('Invalid upstream response status');
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.rawHeaders)) {
    const canonicalName = name.toLowerCase();
    if (SAFE_PROXY_REPLAY_HEADERS.has(canonicalName)) headers[canonicalName] = value;
  }
  const envelope: ResponseEnvelope = {
    v: ENVELOPE_VERSION,
    status: input.status,
    headers,
    body: input.screenedBody,
  };
  const serialized = canonicalize(envelope);
  const encrypted = await deps.kms.encrypt(serialized, responseAad(input.operatorId, input.operationId));
  const workEncrypted = input.postResponseContext
    ? await deps.kms.encrypt(
        canonicalize(input.postResponseContext),
        postResponseAad(input.operatorId, input.operationId),
      )
    : null;
  const ciphertextBytes = Buffer.byteLength(encrypted.ciphertext, 'utf8');
  if (ciphertextBytes > input.capacityBytes) {
    throw new Error('Encrypted proxy response exceeds reserved replay capacity');
  }
  const now = input.now ?? new Date();
  return deps.repository.storeResponse({
    operatorId: input.operatorId,
    operationId: input.operationId,
    dispatchOwnerHash: sha256(input.dispatchToken),
    dispatchFence: input.dispatchFence,
    status: input.status,
    responseHash: sha256(serialized),
    ciphertext: encrypted.ciphertext,
    keyRef: encrypted.keyRef,
    ciphertextBytes,
    readableUntil: new Date(now.getTime() + REPLAY_TTL_MS),
    transportEvidenceHash: input.transportEvidenceHash,
    providerRequestIdHash: input.providerRequestId ? sha256(input.providerRequestId) : undefined,
    postResponseContext: workEncrypted ?? undefined,
  });
}

export async function readReplay(
  deps: ProxyOperationDeps,
  operatorId: string,
  operationKey: string,
  now = new Date(),
): Promise<ProxyReplayResult> {
  const operation = await deps.repository.findByOperationKey(operatorId, sha256(operationKey));
  if (!operation) return { state: 'unavailable', reason: 'none' };
  if (operation.delivery_state === 'outcome_unknown') {
    return { state: 'unavailable', reason: 'outcome_unknown' };
  }
  if (operation.replay_state === 'screening') return { state: 'unavailable', reason: 'screening' };
  if (operation.replay_state === 'erased') return { state: 'unavailable', reason: 'erased' };
  if (operation.replay_state === 'expired'
    || !operation.response_readable_until
    || operation.response_readable_until <= now) {
    return { state: 'unavailable', reason: 'expired' };
  }
  if (operation.replay_state !== 'available' || !operation.response_encrypted) {
    return { state: 'unavailable', reason: 'none' };
  }
  const plaintext = await deps.kms.decrypt(
    operation.response_encrypted,
    responseAad(operatorId, operation.id),
  );
  return parseResponseEnvelope(plaintext);
}

export async function readMetadata(
  deps: ProxyOperationDeps,
  operatorId: string,
  operationKey: string,
) {
  const operation = await deps.repository.findByOperationKey(operatorId, sha256(operationKey));
  if (!operation) return null;
  return metadataFrom(operation);
}

export async function authorizeHumanMetadata(deps: ProxyOperationDeps, input: {
  operatorId: string;
  operationKey: string;
  allowedConnections?: readonly string[];
}): Promise<ProxyOperationMetadata | null> {
  if (!ProxyOperationId.safeParse(input.operationKey).success) return null;
  const operation = await deps.repository.findVisibleByOperationKey(
    input.operatorId,
    sha256(input.operationKey),
    input.allowedConnections,
  );
  if (!operation) return null;
  return metadataFrom(operation);
}

export async function authorizeRead(deps: ProxyOperationDeps, input: {
  operatorId: string;
  operationKey: string;
  currentAgentId: string;
  allowedConnections?: readonly string[];
  freshAuthority: FreshProxyAuthority;
  includeResponse?: boolean;
  now?: Date;
}): Promise<{ metadata: ProxyOperationMetadata; replay?: ProxyReplayResult } | null> {
  const operation = await deps.repository.findByOperationKey(
    input.operatorId,
    sha256(input.operationKey),
  );
  if (!operation || operation.agent_id !== input.currentAgentId
    || (input.allowedConnections !== undefined
      && !input.allowedConnections.includes(operation.service_connection_id))
  ) {
    return null;
  }
  const currentService = input.freshAuthority.services.find((candidate) =>
    candidate.service_id === operation.service_id
    && candidate.service_name === operation.provider
    && candidate.connection_id === operation.service_connection_id);
  if (!currentService) return null;

  if (input.includeResponse && operation.replay_state === 'available'
    && !await deps.repository.originalPassportAllowsReplay(
      input.operatorId,
      operation.passport_jti,
      operation.agent_id,
      input.now,
    )) {
    return {
      metadata: metadataFrom(operation),
      replay: { state: 'unavailable', reason: 'none' },
    };
  }

  // The tombstone remains readable as status metadata after its customer
  // payloads are scrubbed. No scope or response ciphertext is decrypted in
  // this branch; the fresh Passport still has to carry the exact service and
  // connection that owned the operation.
  if (!operation.scope_descriptor_encrypted || operation.replay_state === 'expired') {
    const metadata = metadataFrom(operation);
    if (!input.includeResponse) return { metadata };
    return {
      metadata,
      replay: {
        state: 'unavailable',
        reason: operation.replay_state === 'erased' ? 'erased' : 'expired',
      },
    };
  }
  const plaintext = await deps.kms.decrypt(
    operation.scope_descriptor_encrypted,
    scopeAad(input.operatorId, operation.id),
  );
  const original = JSON.parse(plaintext) as ProxyScopeDescriptor;
  const freshScope: ProxyScopeDescriptor = {
    ...original,
    scopes: currentService.scopes,
    intents: input.freshAuthority.intentServices ?? [],
    constraints: currentService.constraints ?? [],
    policy: currentService.policy ?? null,
    allowDataFrom: currentService.allow_data_from ?? [],
    discloseTo: input.freshAuthority.discloseTo ?? [],
    authorityRefs: input.freshAuthority.authorityRefs ?? [],
  };
  if (`sha256:${sha256(canonicalize(original))}` !== operation.scope_commitment_hash
    || !scopeCovers(freshScope, original)) {
    return null;
  }
  const metadata = metadataFrom(operation);
  if (!input.includeResponse) return { metadata };
  return {
    metadata,
    replay: await readReplay(deps, input.operatorId, input.operationKey, input.now),
  };
}

export function metadataFrom(operation: ProxyOperationRow): ProxyOperationMetadata {
  return {
    id: operation.id,
    requestHash: operation.request_hash,
    tombstoneHash: operation.tombstone_hash,
    scopeCommitmentHash: operation.scope_commitment_hash,
    agentId: operation.agent_id,
    passportJti: operation.passport_jti,
    authorityUseId: operation.authority_use_id,
    approvalId: operation.approval_id,
    connectionId: operation.service_connection_id,
    serviceId: operation.service_id,
    credentialVersion: operation.credential_version,
    destinationConfigHash: operation.destination_config_hash,
    provider: operation.provider,
    method: operation.method,
    adapterKind: operation.adapter_kind,
    deliveryState: operation.delivery_state,
    replayState: operation.replay_state,
    accountingState: operation.accounting_state,
    reconciliationState: operation.reconciliation_state,
    reconciliationEvidenceHash: operation.reconciliation_evidence_hash,
    reconciliationProviderStatus: operation.reconciliation_provider_status as
      | 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled' | null,
    transportAttempts: operation.transport_attempts,
    responseStatus: operation.response_status,
    responseHash: operation.response_hash,
    dispatchedAt: operation.dispatch_started_at,
    responseReceivedAt: operation.response_received_at,
    unresolvedAt: operation.unresolved_at,
    retryDeadline: operation.retry_deadline,
    responseReadableUntil: operation.response_readable_until,
    createdAt: operation.created_at,
    updatedAt: operation.updated_at,
  };
}
