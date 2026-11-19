/** Authority principals: creation, listing, archival and account read models. */
import {
  ForbiddenError,
  NotFoundError,
  generateId,
  type CreateAuthorityPrincipalInput,
} from '@stack/shared';
import type { AuthorityServiceDeps } from './contracts.js';
import { AuthorityCore } from './core.js';
import { safeBinding, safePrincipal, safeProof, safeReceiver } from './redaction.js';

export class PrincipalService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(private readonly core: AuthorityCore) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async createPrincipal(
    operatorId: string,
    input: CreateAuthorityPrincipalInput,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      'principal.create',
      idempotencyKey,
      input,
      async (repo) => {
        const id = generateId('prn');
        const encrypted = input.label
          ? await this.deps.kms.encrypt(input.label, {
              operator_id: operatorId,
              principal_id: id,
              store: 'authority_principal_label',
            })
          : null;
        return safePrincipal(
          await repo.insertPrincipal({
            id,
            operator_id: operatorId,
            kind: input.kind,
            label_encrypted: encrypted?.ciphertext ?? null,
            status: 'active',
            created_at: this.now(),
            revoked_at: null,
            revoked_reason: null,
            erased_at: null,
            tombstone_hash: null,
            tombstone_claim_id: null,
          }),
        );
      },
      201,
    );
  }

  async resolveAgentKeyThumbprint(operatorId: string, agentId: string): Promise<string> {
    const agentKey = await this.deps.repo.resolveCurrentAgentKey(operatorId, agentId);
    if (!agentKey?.active) throw new ForbiddenError('authority binding agent key is unavailable');
    return agentKey.thumbprint;
  }

  async listPrincipals(operatorId: string) {
    return Promise.all((await this.deps.repo.listPrincipals(operatorId)).map(safePrincipal));
  }

  async listAccountRecords(
    operatorId: string,
    kind: 'principals' | 'proofs' | 'receivers',
    page: number,
    limit: number,
    related?: { id: string; version?: number | undefined },
  ) {
    if (
      !Number.isSafeInteger(page) ||
      page < 1 ||
      page > 100_000 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 50
    )
      throw new ForbiddenError('invalid authority page');
    if (related) {
      if (
        kind === 'proofs'
          ? !Number.isSafeInteger(related.version) || related.version! < 1
          : related.version !== undefined
      ) {
        throw new ForbiddenError('invalid authority record version');
      }
      const owned =
        kind === 'principals'
          ? await this.deps.repo.findPrincipal(operatorId, related.id)
          : kind === 'proofs'
            ? await this.deps.repo.findProof(operatorId, related.id, related.version)
            : await this.deps.repo.findReceiver(operatorId, related.id);
      if (!owned) throw new NotFoundError('AuthorityRecord', related.id);
      const records = await this.deps.repo.listAccountRecordBindings(
        operatorId,
        kind,
        related.id,
        related.version,
        page,
        limit,
      );
      return {
        bindings: records.slice(0, limit).map(safeBinding),
        page,
        limit,
        has_more: records.length > limit,
      };
    }
    const records = await this.deps.repo.listAccountRecords(operatorId, kind, page, limit);
    if (records.principals)
      return {
        principals: records.principals.slice(0, limit).map(safePrincipal),
        page,
        limit,
        has_more: records.principals.length > limit,
      };
    if (records.proofs)
      return {
        proofs: records.proofs.slice(0, limit).map(safeProof),
        page,
        limit,
        has_more: records.proofs.length > limit,
      };
    return {
      receivers: records.receivers.slice(0, limit).map(safeReceiver),
      page,
      limit,
      has_more: records.receivers.length > limit,
    };
  }

  async getPrincipal(operatorId: string, principalId: string) {
    const row = await this.deps.repo.findPrincipal(operatorId, principalId);
    if (!row) throw new NotFoundError('AuthorityPrincipal', principalId);
    return safePrincipal(row);
  }

  async archivePrincipal(
    operatorId: string,
    principalId: string,
    reason: string,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `principal.archive:${principalId}`,
      idempotencyKey,
      { reason },
      async (repo) => {
        const row = await repo.archivePrincipal(operatorId, principalId, reason, this.now());
        if (!row) throw new NotFoundError('AuthorityPrincipal', principalId);
        return safePrincipal(row);
      },
    );
  }
}
