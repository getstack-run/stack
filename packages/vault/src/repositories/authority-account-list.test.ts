import { drizzle } from 'drizzle-orm/pg-proxy';
import { describe, expect, it } from 'vitest';
import type { Database } from '@stack/shared';
import { AuthorityRepository } from './authority-repo.js';

describe('account authority database pages', () => {
  function setup() {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = drizzle(async (sql, params) => { queries.push({ sql, params }); return { rows: [] }; });
    return { repo: new AuthorityRepository(db as unknown as Database), queries };
  }

  it.each(['principals', 'proofs', 'receivers'] as const)('bounds %s inside the tenant before paging', async (kind) => {
    const { repo, queries } = setup();
    await repo.listAccountRecords('op_one', kind, 2, 20);
    expect(queries).toHaveLength(1);
    expect(queries[0]!.sql).toMatch(/where .*operator_id.*order by .*created_at.*id.*limit .*offset /);
    expect(queries[0]!.params).toEqual(['op_one', 21, 20]);
    if (kind === 'proofs') expect(queries[0]!.sql).toMatch(/order by .*created_at.*id.*version/);
    if (kind === 'receivers') expect(queries[0]!.sql).toContain('managed_by_operator_id');
  });

  it('matches exact proof versions and exact binding versions without multiplying rows', async () => {
    const { repo, queries } = setup();
    await repo.listAccountRecordBindings('op_one', 'proofs', 'apf_one', 3, 2, 20);
    const query = queries[0]!;
    expect(query.sql).toMatch(/exists.*authority_binding_proofs/s);
    expect(query.sql).toContain('"binding_version" = "authority_bindings"."version"');
    expect(query.sql).toMatch(/proof_id.*proof_version/s);
    expect(query.params).toEqual(['op_one', 'op_one', 'apf_one', 3, 21, 20]);
  });

  it('includes principal bindings and exact authoriser links within the same tenant', async () => {
    const { repo, queries } = setup();
    await repo.listAccountRecordBindings('op_one', 'principals', 'apr_one', undefined, 1, 20);
    expect(queries[0]!.sql).toMatch(/principal_id.*or.*exists.*authoriser_principal_id/s);
    expect(queries[0]!.params).toEqual(['op_one', 'apr_one', 'op_one', 'apr_one', 21]);
  });
});
