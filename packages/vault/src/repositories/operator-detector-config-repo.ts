import { and, eq } from 'drizzle-orm';
import {
  type Database,
  operatorDetectorConfig,
  type OperatorCustomPattern,
  type OperatorWhitelistPattern,
} from '@stack/shared';

export interface DetectorConfigRow {
  id: string;
  operator_id: string;
  detector_key: string;
  custom_patterns: OperatorCustomPattern[];
  whitelist_patterns: OperatorWhitelistPattern[];
  severity_overrides: Record<string, 'warning' | 'critical'>;
  enabled: boolean;
  created_at: Date;
  updated_at: Date;
}

export class OperatorDetectorConfigRepository {
  constructor(private db: Database) {}

  async findByOperator(operatorId: string): Promise<DetectorConfigRow[]> {
    return this.db.query.operatorDetectorConfig.findMany({
      where: eq(operatorDetectorConfig.operator_id, operatorId),
    }) as Promise<DetectorConfigRow[]>;
  }

  async findByOperatorAndDetector(
    operatorId: string,
    detectorKey: string,
  ): Promise<DetectorConfigRow | undefined> {
    return this.db.query.operatorDetectorConfig.findFirst({
      where: and(
        eq(operatorDetectorConfig.operator_id, operatorId),
        eq(operatorDetectorConfig.detector_key, detectorKey),
      ),
    }) as Promise<DetectorConfigRow | undefined>;
  }

  async upsert(input: {
    id: string;
    operator_id: string;
    detector_key: string;
    custom_patterns?: OperatorCustomPattern[];
    whitelist_patterns?: OperatorWhitelistPattern[];
    severity_overrides?: Record<string, 'warning' | 'critical'>;
    enabled?: boolean;
  }): Promise<DetectorConfigRow> {
    const existing = await this.findByOperatorAndDetector(
      input.operator_id,
      input.detector_key,
    );
    if (existing) {
      const [row] = await this.db
        .update(operatorDetectorConfig)
        .set({
          ...(input.custom_patterns !== undefined ? { custom_patterns: input.custom_patterns } : {}),
          ...(input.whitelist_patterns !== undefined ? { whitelist_patterns: input.whitelist_patterns } : {}),
          ...(input.severity_overrides !== undefined ? { severity_overrides: input.severity_overrides } : {}),
          ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
          updated_at: new Date(),
        })
        .where(eq(operatorDetectorConfig.id, existing.id))
        .returning();
      return row! as DetectorConfigRow;
    }
    const [row] = await this.db
      .insert(operatorDetectorConfig)
      .values({
        id: input.id,
        operator_id: input.operator_id,
        detector_key: input.detector_key,
        custom_patterns: input.custom_patterns ?? [],
        whitelist_patterns: input.whitelist_patterns ?? [],
        severity_overrides: input.severity_overrides ?? {},
        enabled: input.enabled ?? true,
      })
      .returning();
    return row! as DetectorConfigRow;
  }

  async delete(operatorId: string, detectorKey: string): Promise<boolean> {
    const result = await this.db
      .delete(operatorDetectorConfig)
      .where(
        and(
          eq(operatorDetectorConfig.operator_id, operatorId),
          eq(operatorDetectorConfig.detector_key, detectorKey),
        ),
      )
      .returning();
    return result.length > 0;
  }
}
