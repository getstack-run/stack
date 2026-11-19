// Scope descriptor commitments: that an admitted operation matches the authority it was admitted
// under, that a repeated admission is the same logical request, and that a fresh Passport still
// covers the scope the operation was admitted with.

import { canonicalize } from '@stack/shared';
import { type ProxyOperationRow } from '../../repositories/proxy-operation-repo.js';
import { type ProxyScopeDescriptor, type AdmitProxyOperationInput } from './types.js';
import { sha256 } from './envelope.js';

export function scopeCovers(fresh: ProxyScopeDescriptor, original: ProxyScopeDescriptor): boolean {
  if (fresh.version !== 1
    || fresh.provider !== original.provider
    || fresh.serviceId !== original.serviceId
    || fresh.connectionId !== original.connectionId
    || fresh.resource.method !== original.resource.method
    || fresh.resource.origin !== original.resource.origin
    || fresh.resource.pathname !== original.resource.pathname) return false;
  const contains = (superset: readonly string[], subset: readonly string[]) => {
    const values = new Set(superset);
    return subset.every((value) => values.has(value));
  };
  return contains(fresh.scopes, original.scopes)
    && contains(fresh.intents, original.intents)
    && contains(fresh.allowDataFrom, original.allowDataFrom)
    && contains(fresh.discloseTo, original.discloseTo)
    && contains(
      fresh.authorityRefs.map((value) => canonicalize(value)),
      original.authorityRefs.map((value) => canonicalize(value)),
    )
    // Constraints and policy have provider-specific semantics. Equality is
    // deliberately conservative until the route supplies a proven normalizer.
    && canonicalize(fresh.constraints) === canonicalize(original.constraints)
    && canonicalize(fresh.policy) === canonicalize(original.policy);
}

export function assertScopeDescriptorBinding(
  scope: ProxyScopeDescriptor,
  input: AdmitProxyOperationInput,
): void {
  const url = new URL(input.preparedRequest.finalUrl);
  if (scope.version !== 1 || scope.provider !== input.provider
    || scope.serviceId !== input.serviceId
    || scope.connectionId !== input.connectionId
    || scope.resource.method !== input.preparedRequest.method
    || scope.resource.origin !== input.preparedRequest.persistence.origin
    || scope.resource.pathname !== url.pathname) {
    throw new Error('Proxy scope descriptor does not match the prepared operation');
  }
}

export function sameBinding(
  operation: ProxyOperationRow,
  input: AdmitProxyOperationInput,
  requestHash: string,
  nativeKeyHash: string | null,
  providerAccountHash: string | null,
): boolean {
  const destinationConfigHash = input.destinationConfigHash;
  return operation.request_hash === requestHash
    && operation.effect_correlation_hash === input.effectCorrelationHash
    && operation.agent_id === input.agentId
    && operation.passport_jti === input.passportJti
    && operation.authority_use_id === (input.authorityUseId ?? null)
    && operation.approval_id === (input.approvalId ?? null)
    && operation.service_connection_id === input.connectionId
    && operation.service_id === input.serviceId
    && operation.credential_version === input.credentialVersion
    && operation.provider === input.provider
    && operation.method === input.preparedRequest.method
    && operation.destination_config_hash === destinationConfigHash
    && operation.scope_commitment_hash === `sha256:${sha256(canonicalize(input.scopeDescriptor))}`
    && operation.adapter_kind === (input.adapter?.kind ?? 'generic')
    && operation.native_idempotency_key_hash === nativeKeyHash
    && operation.provider_account_hash === providerAccountHash;
}
