import type { Database } from '@stack/shared';
import {
  OperatorService,
  OperatorErasureService,
  MemberService,
  type AuditArchiveService,
  type AuditService,
  type ErasureStep,
  type MemberRepository,
  type OperatorRepository,
} from '@stack/vault';

export interface OperatorAccounts {
  operator: OperatorService;
  operatorErasure: OperatorErasureService;
  member: MemberService;
}

/**
 * Operators, erasure, and team members. The plan each call is metered against
 * (the billing account) is the deployment's: it is built next, from the
 * operator service this returns (`ApiExtension.entitlements`).
 */
export function createOperatorAccounts(deps: {
  db: Database;
  operatorRepo: OperatorRepository;
  memberRepo: MemberRepository;
  audit: AuditService;
  auditArchive: AuditArchiveService;
  /** What a deployment keeps outside the database goes with the account, and the erasure waits until it has. */
  erasureBefore: readonly ErasureStep[];
  /** The deployment's own account service, built on the same repository. Absent: the engine's. */
  operatorService?: (repo: OperatorRepository) => OperatorService;
}): OperatorAccounts {
  const { db, operatorRepo, memberRepo, audit, auditArchive, erasureBefore } = deps;
  const operator = deps.operatorService ? deps.operatorService(operatorRepo) : new OperatorService(operatorRepo);
  // Wire the db handle so OperatorService can list + revoke MCP sessions
  // (OAuth refresh-token families). dashboard surface.
  operator.setDb(db);

  const operatorErasure = new OperatorErasureService({
    db,
    operatorRepo,
    archive: auditArchive,
    before: [...erasureBefore],
  });
  operator.setErasureService(operatorErasure);

  const member = new MemberService(memberRepo);
  // Wire the db handle so member.revoke can cascade OAuth refresh-token
  // revocation. Without this a refresh token outlives team membership.
  member.setDb(db);
  member.setAuditService(audit);

  return { operator, operatorErasure, member };
}
