// external chain-head anchor log repo.
//
// Append-only DB mirror of public anchor commits (for example
// `example-org/anchors`). Sole writer is the worker cron via
// `ExternalAnchorService.anchorOperator`. Readers:
//
//   - `EvidencePackService.export` populates
//     `EvidencePackClaim.external_chain_anchors[]` by looking up
//     `getAnchorAtOrBefore(operatorId, exportTimeMs)`.
//   - Dashboard / verifier UX surfaces the latest anchor per operator.
//
// No update path — anchors are point-in-time facts. Multiple rows per
// (operator, UTC day) are allowed when the cron re-runs same-day (lock
// released early, machine restart); the most-recent row by
// `anchored_at_ms` is the head and prior rows stay as forensic trail.

import { and, desc, eq, lte } from 'drizzle-orm';
import { type Database, externalAnchors } from '@stack/shared';

export type ExternalAnchorRow = typeof externalAnchors.$inferSelect;
export type ExternalAnchorInsert = typeof externalAnchors.$inferInsert;

export class ExternalAnchorRepository {
  constructor(private db: Database) {}

  async insert(row: ExternalAnchorInsert): Promise<ExternalAnchorRow> {
    const [inserted] = await this.db.insert(externalAnchors).values(row).returning();
    return inserted!;
  }

  /**
   * Most-recent anchor publication for an operator, or null when the
   * operator has never been anchored. Hits the `ext_anchors_op_time_idx`
   * partial-leading-key path.
   */
  async findLatest(operatorId: string): Promise<ExternalAnchorRow | null> {
    const rows = await this.db
      .select()
      .from(externalAnchors)
      .where(eq(externalAnchors.operator_id, operatorId))
      .orderBy(desc(externalAnchors.anchored_at_ms))
      .limit(1);
    return rows[0] ?? null;
  }

  /**
   * Most-recent anchor with `anchored_at_ms <= tMs`. Used by
   * EvidencePackService.export to capture the anchor in effect at
   * pack-export time. Returns null when no anchor exists at or before
   * the cutoff.
   */
  async findAtOrBefore(operatorId: string, tMs: number): Promise<ExternalAnchorRow | null> {
    const rows = await this.db
      .select()
      .from(externalAnchors)
      .where(
        and(
          eq(externalAnchors.operator_id, operatorId),
          lte(externalAnchors.anchored_at_ms, tMs),
        ),
      )
      .orderBy(desc(externalAnchors.anchored_at_ms))
      .limit(1);
    return rows[0] ?? null;
  }
}
