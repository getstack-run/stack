import { eq } from 'drizzle-orm';
import { type Database, operatorPiiConfig } from '@stack/shared';

/**
 * One row per operator. Absence means "built-in defaults" — the repository
 * never inserts on read, same contract as OperatorDetectorConfigRepository.
 */
export interface PiiConfigRow {
  id: string;
  operator_id: string;
  enabled: boolean;
  /** NULL means PII_DEFAULT_THRESHOLD. */
  threshold: number | null;
  /** NULL means every country. */
  countries: string[] | null;
  created_at: Date;
  updated_at: Date;
}

export class OperatorPiiConfigRepository {
  constructor(private db: Database) {}

  async findByOperator(operatorId: string): Promise<PiiConfigRow | undefined> {
    return this.db.query.operatorPiiConfig.findFirst({
      where: eq(operatorPiiConfig.operator_id, operatorId),
    }) as Promise<PiiConfigRow | undefined>;
  }

  /**
   * Partial update. A field left `undefined` is untouched; passing `null`
   * explicitly clears it back to the built-in default. That distinction is
   * the whole reason the columns are nullable, so it has to survive the
   * round trip rather than being collapsed by `??`.
   */
  async upsert(input: {
    id: string;
    operator_id: string;
    enabled?: boolean;
    threshold?: number | null;
    countries?: string[] | null;
  }): Promise<PiiConfigRow> {
    const existing = await this.findByOperator(input.operator_id);
    if (existing) {
      const [row] = await this.db
        .update(operatorPiiConfig)
        .set({
          ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
          ...(input.threshold !== undefined ? { threshold: input.threshold } : {}),
          ...(input.countries !== undefined ? { countries: input.countries } : {}),
          updated_at: new Date(),
        })
        .where(eq(operatorPiiConfig.id, existing.id))
        .returning();
      return row! as PiiConfigRow;
    }
    const [row] = await this.db
      .insert(operatorPiiConfig)
      .values({
        id: input.id,
        operator_id: input.operator_id,
        enabled: input.enabled ?? true,
        threshold: input.threshold ?? null,
        countries: input.countries ?? null,
      })
      .returning();
    return row! as PiiConfigRow;
  }

  async delete(operatorId: string): Promise<boolean> {
    const result = await this.db
      .delete(operatorPiiConfig)
      .where(eq(operatorPiiConfig.operator_id, operatorId))
      .returning();
    return result.length > 0;
  }
}
