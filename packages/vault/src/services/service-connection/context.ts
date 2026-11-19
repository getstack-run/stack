import type { Redis } from 'ioredis';
import { ForbiddenError } from '@stack/shared';
import type { ServiceRepository } from '../../repositories/service-repo.js';
import type { AgentRepository } from '../../repositories/agent-repo.js';
import type { KmsService } from '../../crypto/kms.js';
import type { ServiceConnectionHooks } from './hooks.js';

const SANDBOX_DECRYPT_CACHE_TTL_MS = 60 * 60 * 1000;

/** The state every connection operation reads. Built once by ServiceConnectionService. */
export interface ServiceConnectionContext {
  readonly serviceRepo: ServiceRepository;
  readonly agentRepo: AgentRepository;
  readonly kms: KmsService;
  readonly redis: Redis | undefined;
  readonly hooks: ServiceConnectionHooks;
  decryptCredential(
    operatorId: string,
    connectionId: string,
    encrypted: string,
    provider: string,
  ): Promise<string>;
}

/**
 * KMS decryption with a sandbox-only cache. The public landing-page demo runner
 * decrypts the same sentinel credentials thousands of times per day; each call
 * hit AWS KMS (~9.2k calls/day, a free-tier overrun). Sentinel values never
 * change, so caching the decrypted output is safe and removes 99% of the KMS
 * pressure. Real operator credentials are NEVER cached: caching plaintext
 * credentials in process memory is a security regression for any non-sandbox
 * tenant. Operator id is the sole gate.
 */
export function createCredentialDecryptor(
  kms: KmsService,
  cachedOperatorIds: readonly string[] = [],
): ServiceConnectionContext['decryptCredential'] {
  const sandboxCache = new Map<string, { decrypted: string; expiresAt: number }>();
  return async (operatorId, connectionId, encrypted, provider) => {
    if (!cachedOperatorIds.includes(operatorId)) {
      return kms.decrypt(encrypted, { operator_id: operatorId, provider });
    }
    const key = `${operatorId}::${connectionId}`;
    const cached = sandboxCache.get(key);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.decrypted;
    }
    const decrypted = await kms.decrypt(encrypted, {
      operator_id: operatorId,
      provider,
    });
    sandboxCache.set(key, {
      decrypted,
      expiresAt: Date.now() + SANDBOX_DECRYPT_CACHE_TTL_MS,
    });
    return decrypted;
  };
}

/** Undefined means owner-wide access; a present list is an exact connection ceiling. */
export function assertConnectionAccess(
  allowedConnections: readonly string[] | undefined,
  connectionId?: string,
): void {
  if (allowedConnections === undefined) return;
  if (!connectionId || !allowedConnections.includes(connectionId)) {
    throw new ForbiddenError('Service connection is outside this member access grant');
  }
}
