import { and, eq, inArray } from 'drizzle-orm';
import {
  evidencePackArtifacts,
  type Database,
} from '@stack/shared';
import { PassportClaimsRepository } from './passport-claims-repo.js';

export type EvidencePackArtifactRow = typeof evidencePackArtifacts.$inferSelect;
export type EvidencePackArtifactInsert = typeof evidencePackArtifacts.$inferInsert;

export interface EvidencePackArtifactTransaction {
  artifacts: EvidencePackArtifactRepository;
  claimPersistence: Pick<PassportClaimsRepository, 'insert'>;
}

/**
 * Operator-scoped metadata for exact manifest bytes in object storage.
 *
 * There are no update or delete methods. Migration 0053 also rejects those
 * operations at the database boundary. The transaction helper gives the pack
 * producer one transaction for its signed claim row and artifact metadata.
 */
export class EvidencePackArtifactRepository {
  constructor(private readonly db: Database) {}

  async transaction<T>(
    callback: (context: EvidencePackArtifactTransaction) => Promise<T>,
  ): Promise<T> {
    return this.db.transaction(async (tx) => callback({
      artifacts: new EvidencePackArtifactRepository(tx as unknown as Database),
      claimPersistence: new PassportClaimsRepository(tx as unknown as Database),
    }));
  }

  async create(input: EvidencePackArtifactInsert): Promise<EvidencePackArtifactRow> {
    const [row] = await this.db
      .insert(evidencePackArtifacts)
      .values(input)
      .returning();
    return row!;
  }

  async findByPackIdAndOperator(
    packId: string,
    operatorId: string,
  ): Promise<EvidencePackArtifactRow | null> {
    const row = await this.db.query.evidencePackArtifacts.findFirst({
      where: and(
        eq(evidencePackArtifacts.pack_id, packId),
        eq(evidencePackArtifacts.operator_id, operatorId),
      ),
    });
    return row ?? null;
  }

  async findByPackIdsAndOperator(
    packIds: string[],
    operatorId: string,
  ): Promise<EvidencePackArtifactRow[]> {
    if (packIds.length === 0) return [];
    return this.db.query.evidencePackArtifacts.findMany({
      where: and(
        eq(evidencePackArtifacts.operator_id, operatorId),
        inArray(evidencePackArtifacts.pack_id, packIds),
      ),
    });
  }
}
