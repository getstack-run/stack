/** State and helpers every authority module shares: dependencies, clock, adapter registries and the idempotency ledger. */
import {
  ForbiddenError,
  ServiceUnavailableError,
  canonicalize,
  generateId,
  sha256 as rawSha256,
} from '@stack/shared';
import { createHash, timingSafeEqual } from 'node:crypto';
import type { AuthorityPresentationProtocol } from './presentation-protocol.js';
import type { AuthorityProofAdapter, AuthorityServiceDeps } from './contracts.js';
import type { AuthorityRepositoryPort } from './port.js';
import { committedEnvelope, sha256 } from './digest.js';

export class AuthorityCore {
  readonly adapters = new Map<string, AuthorityProofAdapter>();
  readonly presentationProtocols = new Map<string, AuthorityPresentationProtocol>();
  readonly now: () => Date;

  constructor(readonly deps: AuthorityServiceDeps) {
    this.now = deps.now ?? (() => new Date());
    for (const adapter of deps.adapters ?? []) {
      const key = `${adapter.key}@${adapter.version}`;
      if (this.adapters.has(key)) throw new Error(`duplicate authority proof adapter ${key}`);
      this.adapters.set(key, adapter);
    }
    for (const protocol of deps.presentationProtocols ?? []) {
      const key = `${protocol.key}@${protocol.version}`;
      if (this.presentationProtocols.has(key))
        throw new Error(`duplicate authority presentation protocol ${key}`);
      this.presentationProtocols.set(key, protocol);
    }
  }

  async idempotent<T>(
    operatorId: string,
    operation: string,
    idempotencyKey: string,
    payload: unknown,
    mutation: (repo: AuthorityRepositoryPort) => Promise<T>,
    responseStatus = 200,
  ): Promise<T> {
    if (!idempotencyKey) throw new ForbiddenError('Idempotency-Key is required');
    if (!Number.isInteger(responseStatus) || responseStatus < 100 || responseStatus > 599) {
      throw new ForbiddenError('idempotent response status is invalid');
    }
    const canonicalPayload = canonicalize(payload ?? {});
    const ledgerId = generateId('aik');
    const committed = committedEnvelope(payload ?? {});
    const context = {
      operator_id: operatorId,
      ledger_id: ledgerId,
      operation,
      idempotency_key_hash: rawSha256(idempotencyKey),
      store: 'authority_idempotency_request',
    };
    const encrypted = await this.deps.kms.encrypt(committed.plaintext, context);
    return this.deps.repo.idempotent(
      {
        ledgerId,
        operatorId,
        operation,
        idempotencyKey,
        payloadHash: sha256(encrypted.ciphertext),
        workflowPayloadEncrypted: encrypted.ciphertext,
        matchesExistingRequest: async (existingEncrypted, existingLedgerId) => {
          const plaintext = await this.deps.kms.decrypt(existingEncrypted, {
            ...context,
            ledger_id: existingLedgerId,
          });
          let stored: unknown;
          try {
            stored = JSON.parse(plaintext);
          } catch {
            return false;
          }
          if (
            !stored ||
            typeof stored !== 'object' ||
            Array.isArray(stored) ||
            !Object.prototype.hasOwnProperty.call(stored, 'value')
          )
            return false;
          const storedCanonical = canonicalize((stored as Record<string, unknown>).value);
          const left = createHash('sha256').update(canonicalPayload).digest();
          const right = createHash('sha256').update(storedCanonical).digest();
          return timingSafeEqual(left, right) && canonicalPayload.length === storedCanonical.length;
        },
        responseStatus,
      },
      mutation,
    );
  }

  presentationProtocolForConfig(config: Record<string, unknown>): AuthorityPresentationProtocol {
    const protocol = config.protocol;
    if (!protocol || typeof protocol !== 'object' || Array.isArray(protocol)) {
      throw new ForbiddenError('receiver profile does not declare a presentation protocol');
    }
    const record = protocol as Record<string, unknown>;
    const key = `${String(record.key ?? '')}@${String(record.version ?? '')}`;
    const adapter = this.presentationProtocols.get(key);
    if (!adapter)
      throw new ServiceUnavailableError('required receiver presentation protocol is unavailable');
    return adapter;
  }
}
