import { drizzle } from 'drizzle-orm/pg-proxy';
import { describe, expect, it } from 'vitest';
import type { Database } from '@stack/shared';
import { LlmUsageRepository } from './llm-usage-repo.js';

describe('mission LLM cost sum', () => {
  it('sums only the named operator\'s usage for a mission', async () => {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = drizzle(async (sql, params) => {
      queries.push({ sql, params });
      return { rows: [['700']] };
    });
    const repo = new LlmUsageRepository(db as unknown as Database);
    await expect(repo.sumTotalCostByMission('op_one', 'ms_one')).resolves.toBe(700);
    expect(queries).toHaveLength(1);
    expect(queries[0]!.sql).toMatch(/where .*"operator_id" = .*"mission_id" = /);
    expect(queries[0]!.params).toEqual(['op_one', 'ms_one']);
  });
});
