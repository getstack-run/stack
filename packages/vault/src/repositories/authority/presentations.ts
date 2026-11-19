import { and, desc, eq, inArray } from 'drizzle-orm';
import { authorityPresentations } from '@stack/shared';
import type {
  AuthorityPresentationPatch,
  AuthorityPresentationRecord,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { presentationRow } from './rows.js';

/** Presentations of an authority use to a receiver. */
export class AuthorityPresentationRepository extends AuthorityAggregateRepository {
  async insertPresentation(row: AuthorityPresentationRecord) {
    const [created] = await this.db.insert(authorityPresentations).values(row).returning();
    return presentationRow(created!);
  }

  async findPresentation(receiverId: string, presentationId: string) {
    const [row] = await this.db.select().from(authorityPresentations).where(and(
      eq(authorityPresentations.receiver_id, receiverId), eq(authorityPresentations.id, presentationId),
    )).limit(1);
    return row ? presentationRow(row) : null;
  }

  async listPresentationsForOperator(operatorId: string) {
    return (await this.db.select().from(authorityPresentations).where(eq(authorityPresentations.operator_id, operatorId))
      .orderBy(desc(authorityPresentations.created_at))).map(presentationRow);
  }

  async findPresentationForOperator(operatorId: string, presentationId: string) {
    const [row] = await this.db.select().from(authorityPresentations).where(and(
      eq(authorityPresentations.operator_id, operatorId), eq(authorityPresentations.id, presentationId),
    )).limit(1);
    return row ? presentationRow(row) : null;
  }

  async updatePresentation(input: {
    receiverId: string; presentationId: string; from: AuthorityPresentationRecord['status'][];
    patch: AuthorityPresentationPatch;
  }) {
    const [row] = await this.db.update(authorityPresentations).set(input.patch).where(and(
      eq(authorityPresentations.receiver_id, input.receiverId), eq(authorityPresentations.id, input.presentationId),
      inArray(authorityPresentations.status, input.from),
    )).returning();
    return row ? presentationRow(row) : null;
  }
}
