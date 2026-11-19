/** Dispatch and completion of authority uses. */
import { ConflictError, ServiceUnavailableError, canonicalize, generateId } from '@stack/shared';
import { createHash, timingSafeEqual } from 'node:crypto';
import type { AuthorityDbTransaction } from './records.js';
import type { AuthorityServiceDeps } from './contracts.js';
import { AuthorityCore } from './core.js';
import { RuntimeAuthorityCompletionService } from '../runtime-authority-completion-service.js';
import { committedEnvelope, sha256 } from './digest.js';

export class RuntimeUseService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(core: AuthorityCore) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async markRuntimeAuthorityDispatched(operatorId: string, useId: string): Promise<void> {
    const row = await this.deps.repo.markAuthorityUseDispatched(operatorId, useId, this.now());
    if (!row)
      throw new ConflictError('authority use is missing or cannot transition to dispatched');
  }

  async claimRuntimeAuthorityDispatch(
    operatorId: string,
    useId: string,
    transaction: AuthorityDbTransaction,
  ): Promise<void> {
    const row = await this.deps.repo.claimAuthorityUseDispatched(
      operatorId,
      useId,
      this.now(),
      transaction,
    );
    if (!row) throw new ConflictError('authority use is missing or already dispatched');
  }

  async completeRuntimeAuthorityUse(input: {
    operatorId: string;
    useId: string;
    outcome: 'succeeded' | 'failed';
    exactResult: unknown;
    intentClaimId?: string;
    outcomeClaimId?: string;
  }): Promise<void> {
    const resultHash = await this.commitRuntimeResult(
      input.operatorId,
      input.useId,
      input.outcome,
      input.exactResult,
    );
    await this.completeRuntimeAuthorityUseByHash({ ...input, resultHash });
  }

  /**
   * Proxy operations retain the one encrypted response envelope. Authority
   * receives only its commitment so the old idempotency ledger cannot create a
   * second exact-result copy with a different retention lifecycle.
   */
  async completeRuntimeAuthorityUseByHash(input: {
    operatorId: string;
    useId: string;
    outcome: 'succeeded' | 'failed';
    resultHash: string;
    intentClaimId?: string;
    outcomeClaimId?: string;
  }): Promise<void> {
    await new RuntimeAuthorityCompletionService({
      repo: this.deps.repo,
      claimIssuer: this.deps.claimIssuer,
      now: this.now,
    }).completeRuntimeAuthorityUseByHash(input);
  }

  async commitRuntimeResult(
    operatorId: string,
    useId: string,
    outcome: 'succeeded' | 'failed',
    exactResult: unknown,
  ): Promise<string> {
    const operation = `authority.use.result:${useId}`;
    const idempotencyKey = `${useId}:${outcome}`;
    const ledgerId = generateId('aik');
    const canonicalResult = canonicalize({ outcome, exact_result: exactResult });
    const committed = committedEnvelope({ outcome, exact_result: exactResult });
    const context = {
      operator_id: operatorId,
      ledger_id: ledgerId,
      authority_use_id: useId,
      operation,
      store: 'authority_use_result',
    };
    const encrypted = await this.deps.kms.encrypt(committed.plaintext, context);
    const response = await this.deps.repo.idempotent(
      {
        ledgerId,
        operatorId,
        operation,
        idempotencyKey,
        payloadHash: sha256(encrypted.ciphertext),
        workflowPayloadEncrypted: encrypted.ciphertext,
        responseStatus: 200,
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
          const left = createHash('sha256').update(canonicalResult).digest();
          const right = createHash('sha256').update(storedCanonical).digest();
          return canonicalResult.length === storedCanonical.length && timingSafeEqual(left, right);
        },
      },
      async () => ({ result_hash: committed.hash }),
    );
    const resultHash = (response as { result_hash?: unknown }).result_hash;
    if (typeof resultHash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(resultHash)) {
      throw new ServiceUnavailableError('authority result commitment is unavailable');
    }
    return resultHash;
  }
}
