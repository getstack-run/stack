import { and, asc, desc, eq } from 'drizzle-orm';
import {
  authorityPrincipals,
  authorityProofs,
  authorityReceivers,
} from '@stack/shared';
import type { AuthorityPrincipalRecord } from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { proofRow, receiverRow } from './rows.js';

/** Principals, and the account-level record listings that page over principals, proofs and receivers. */
export class AuthorityPrincipalRepository extends AuthorityAggregateRepository {
  async insertPrincipal(row: AuthorityPrincipalRecord) {
    const [created] = await this.db.insert(authorityPrincipals).values(row).returning();
    return created as AuthorityPrincipalRecord;
  }

  async listPrincipals(operatorId: string) {
    return (await this.db.select().from(authorityPrincipals)
      .where(eq(authorityPrincipals.operator_id, operatorId)).orderBy(desc(authorityPrincipals.created_at))) as AuthorityPrincipalRecord[];
  }

  async listAccountRecords(operatorId: string, kind: 'principals' | 'proofs' | 'receivers', page: number, limit: number) {
    const offset = (page - 1) * limit;
    if (kind === 'principals') return { principals: await this.db.select().from(authorityPrincipals)
      .where(eq(authorityPrincipals.operator_id, operatorId))
      .orderBy(desc(authorityPrincipals.created_at), asc(authorityPrincipals.id))
      .limit(limit + 1).offset(offset) as AuthorityPrincipalRecord[] };
    if (kind === 'proofs') return { proofs: (await this.db.select().from(authorityProofs)
      .where(eq(authorityProofs.operator_id, operatorId))
      .orderBy(desc(authorityProofs.created_at), asc(authorityProofs.id), desc(authorityProofs.version))
      .limit(limit + 1).offset(offset)).map(proofRow) };
    return { receivers: (await this.db.select().from(authorityReceivers)
      .where(eq(authorityReceivers.managed_by_operator_id, operatorId))
      .orderBy(desc(authorityReceivers.created_at), asc(authorityReceivers.id))
      .limit(limit + 1).offset(offset)).map(receiverRow) };
  }

  async findPrincipal(operatorId: string, principalId: string) {
    const [row] = await this.db.select().from(authorityPrincipals).where(and(
      eq(authorityPrincipals.operator_id, operatorId), eq(authorityPrincipals.id, principalId),
    )).limit(1);
    return row as AuthorityPrincipalRecord | undefined ?? null;
  }

  async archivePrincipal(operatorId: string, principalId: string, reason: string, now: Date) {
    const [row] = await this.db.update(authorityPrincipals).set({ status: 'revoked', revoked_at: now, revoked_reason: reason })
      .where(and(eq(authorityPrincipals.operator_id, operatorId), eq(authorityPrincipals.id, principalId), eq(authorityPrincipals.status, 'active'))).returning();
    return row as AuthorityPrincipalRecord | undefined ?? null;
  }
}
