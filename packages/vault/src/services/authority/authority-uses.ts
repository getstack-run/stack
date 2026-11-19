/** Read models over authority uses and presentations. */
import { ForbiddenError, NotFoundError } from '@stack/shared';
import type { AuthorityServiceDeps } from './contracts.js';
import { AuthorityCore } from './core.js';
import { safePresentation, safeUse } from './redaction.js';

export class AuthorityUseQueryService {
  private readonly deps: AuthorityServiceDeps;

  constructor(core: AuthorityCore) {
    this.deps = core.deps;
  }

  async listAuthorityUses(operatorId: string) {
    return (await this.deps.repo.listAuthorityUses(operatorId)).map((row) => safeUse(row));
  }

  async listAgentAuthorityUses(
    operatorId: string,
    agentId: string,
    page: number,
    limit: number,
    binding?: { id: string; version: number },
  ) {
    if (
      !Number.isSafeInteger(page) ||
      page < 1 ||
      page > 100_000 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 50
    ) {
      throw new ForbiddenError('invalid authority page');
    }
    const result = await this.deps.repo.listAgentAuthorityUses(
      operatorId,
      agentId,
      page,
      limit,
      binding,
    );
    return {
      items: result.uses.map((row) => safeUse(row)),
      presentations: result.presentations.map(safePresentation),
      page,
      limit,
      has_more: result.has_more,
    };
  }

  async getAuthorityUse(operatorId: string, useId: string) {
    const row = await this.deps.repo.findAuthorityUseForOperator(operatorId, useId);
    if (!row) throw new NotFoundError('AuthorityUse', useId);
    return safeUse(row);
  }

  async listAuthorityPresentations(operatorId: string) {
    return (await this.deps.repo.listPresentationsForOperator(operatorId)).map(safePresentation);
  }

  async getAuthorityPresentation(operatorId: string, presentationId: string) {
    const row = await this.deps.repo.findPresentationForOperator(operatorId, presentationId);
    if (!row) throw new NotFoundError('AuthorityPresentation', presentationId);
    return safePresentation(row);
  }
}
