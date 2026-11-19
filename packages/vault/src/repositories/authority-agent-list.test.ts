import { drizzle } from 'drizzle-orm/pg-proxy';
import { describe, expect, it } from 'vitest';
import type { Database } from '@stack/shared';
import { AuthorityRepository } from './authority-repo.js';

describe('agent authority database query', () => {
  it('keeps tenant and agent filters when locating an exact historical binding version', async () => {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = drizzle(async (sql, params) => { queries.push({ sql, params }); return { rows: [] }; });
    const repo = new AuthorityRepository(db as unknown as Database);
    await repo.listAgentBindings('op_one', 'agt_one', 1, 20, { id: 'abn_old', version: 7 });
    expect(queries).toHaveLength(1);
    expect(queries[0]!.sql).toMatch(/where .*operator_id.*agent_id.*id.*version.*order by .*limit /);
    expect(queries[0]!.params).toEqual(['op_one', 'op_one', 'agt_one', 'abn_old', 7, 21]);
  });

  it('filters use history by tenant, agent and exact binding version before pagination', async () => {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = drizzle(async (sql, params) => { queries.push({ sql, params }); return { rows: [] }; });
    const repo = new AuthorityRepository(db as unknown as Database);
    const result = await repo.listAgentAuthorityUses('op_one', 'agt_one', 2, 20, { id: 'abn_one', version: 3 });
    expect(result).toEqual({ uses: [], presentations: [], has_more: false });
    expect(queries).toHaveLength(1);
    expect(queries[0]!.sql).toMatch(/where .*operator_id.*agent_id.*binding_id.*binding_version.*order by .*created_at.*id.*limit .*offset /);
    expect(queries[0]!.params).toEqual(['op_one', 'agt_one', 'abn_one', 3, 21, 20]);
  });

  it('scopes tenant and agent in SQL before the stable page boundary, without requiring live Passports', async () => {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = drizzle(async (sql, params) => {
      queries.push({ sql, params });
      return { rows: [] };
    });
    const repo = new AuthorityRepository(db as unknown as Database);
    const result = await repo.listAgentBindings('op_one', 'agt_one', 3, 10);
    expect(result).toEqual({ bindings: [], links: [], principals: [], receivers: [], proofs: [], has_more: false });
    expect(queries).toHaveLength(1);
    const query = queries[0]!;
    expect(query.sql).toContain('"authority_bindings"."operator_id" =');
    expect(query.sql).toContain('"authority_bindings"."agent_id" =');
    expect(query.sql).toMatch(/where .*operator_id.*agent_id.*order by .*created_at.*id.*version.*limit .*offset /);
    expect(query.sql).not.toMatch(/"passports"|"expires_at" [<>]|"revoked_at" is null/);
    expect(query.params).toEqual(['op_one', 'op_one', 'agt_one', 11, 20]);
  });
});
