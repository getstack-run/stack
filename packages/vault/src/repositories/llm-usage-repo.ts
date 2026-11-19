// LlmUsageRepository.
//
// Persistence layer for the `llm_usage` table, one row per successful /v1/llm/<provider>/* call.
// The class holds the database handle and delegates each method to the module that owns it under
// `./llm-usage/`:
//
//   - writes.ts              insert a usage row
//   - queries.ts             the per-mission cost sum, the cursor list and the daily summary
//   - types.ts               input, result and filter types
//
// A deployment with a wallet extends the class (in the hosted folder) with the wallet's side of the
// ledger: the fee
// accumulator, sealed skill machine time, settlement plans, the detail behind a captured hold and
// the wallet timeline. The engine's own never owes a wallet fee, so a row that claims one is refused.
//
// sumTotalCostByMission(operatorId, missionId) is what MissionService.checkGate reads, next to the
// Mission's credit spend (`MissionSpendSource`), to enforce coverage_cap_cents on gross provider cost
// rather than only the STACK markup.

import { SpendRefusedError, type Database } from '@stack/shared';
import * as queries from './llm-usage/queries.js';
import * as writes from './llm-usage/writes.js';
import type {
  InsertLlmUsageInput,
  ListArgs,
  LlmUsageTransaction,
  SummaryArgs,
} from './llm-usage/types.js';

export * from './llm-usage/types.js';

export class LlmUsageRepository {
  constructor(protected readonly db: Database) {}

  insert(input: InsertLlmUsageInput) {
    return writes.insert(this.db, input, (tx, row) => this.afterInsert(tx, row));
  }

  /**
   * Runs in the transaction of a new row that owes a wallet fee. An install has no wallet, so the
   * row is refused and nothing is written; a deployment with a wallet credits its accumulator.
   */
  protected afterInsert(_tx: LlmUsageTransaction, _input: InsertLlmUsageInput): Promise<void> {
    return Promise.reject(
      new SpendRefusedError('This install has no wallet: a call cannot owe a wallet fee.', 'NO_WALLET_ON_INSTALL'),
    );
  }

  /**
   * Sum total_cost_cents for all llm_usage rows attributed to the given mission of the given
   * operator. Rows with no recorded cost contribute 0.
   */
  sumTotalCostByMission(operatorId: string, missionId: string, before?: Date, since?: Date) {
    return queries.sumTotalCostByMission(this.db, operatorId, missionId, before, since);
  }

  /** Cursor-paginated list, operator-scoped. */
  list(args: ListArgs) {
    return queries.list(this.db, args);
  }

  /** GROUP BY provider [+ model] + UTC day, with SUM tokens/cost + COUNT calls. */
  summary(args: SummaryArgs) {
    return queries.summary(this.db, args);
  }
}
