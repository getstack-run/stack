import { drizzle } from 'drizzle-orm/pg-proxy';
import { PgDialect } from 'drizzle-orm/pg-core';
import type { SQL } from 'drizzle-orm';
import { describe, expect, it, vi } from 'vitest';
import type { Database } from '@stack/shared';
import { AuthorityRepository } from './authority-repo.js';

const dialect = new PgDialect();
const render = (query: SQL) => dialect.sqlToQuery(query);

describe('authority repository tenant scoping', () => {
  it('joins binding claims to the same tenant when reading one binding', async () => {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = drizzle(async (sql, params) => { queries.push({ sql, params }); return { rows: [] }; });
    const repo = new AuthorityRepository(db as unknown as Database);
    await repo.findBinding('op_one', 'abn_one', 3);
    expect(queries).toHaveLength(1);
    expect(queries[0]!.sql).toMatch(/left join "passport_claims" on .*"passport_claims"."operator_id" = /);
    expect(queries[0]!.params).toEqual(['op_one', 'op_one', 'abn_one', 3, 1]);
  });

  it('scopes the final profile activation to the owning tenant and profile kind', async () => {
    const wheres: SQL[] = [];
    const profile = { id: 'apv_one', profile_key: 'key_one', receiver_id: null };
    const update = () => ({
      set: () => ({
        where: (condition: SQL) => {
          wheres.push(condition);
          return {
            returning: async () => [{ id: 'apv_one', status: 'active' }],
            then: (resolve: (value: unknown) => unknown) => resolve(undefined),
          };
        },
      }),
    });
    const tx = {
      select: () => ({ from: () => ({ where: () => ({ limit: async () => [profile] }) }) }),
      update,
    };
    const db = { transaction: async (work: (tx: unknown) => unknown) => work(tx) };
    const repo = new AuthorityRepository(db as unknown as Database);
    await repo.activateProfileVersion('op_one', 'proof', 'apv_one', new Date('2026-10-01T00:00:00Z'));
    expect(wheres).toHaveLength(2);
    const activation = render(wheres[1]!);
    expect(activation.sql).toContain('"owner_operator_id" = $');
    expect(activation.sql).toContain('"profile_kind" = $');
    expect(activation.params).toEqual(expect.arrayContaining(['op_one', 'proof', 'apv_one']));
  });

  it('locks the authority use by tenant and receiver, not by id alone', async () => {
    const executed: SQL[] = [];
    const presentation = {
      id: 'apr_one', receiver_id: 'rcv_one', operator_id: 'op_one', authority_use_id: 'use_one', status: 'verified',
    };
    const use = { id: 'use_one', receiver_id: 'rcv_one', operator_id: 'op_one' };
    let reads = 0;
    const db = {
      select: () => ({ from: () => ({ where: () => ({ limit: async () => [reads++ === 0 ? presentation : use] }) }) }),
    };
    const transaction = { execute: vi.fn(async (query: SQL) => { executed.push(query); }) };
    const repo = new AuthorityRepository(db as unknown as Database, transaction as never);
    const locked = await repo.lockPresentationAndUseForReceipt('rcv_one', 'apr_one');
    expect(locked?.use.id).toBe('use_one');
    expect(executed).toHaveLength(2);
    const lockUse = render(executed[1]!);
    expect(lockUse.sql).toMatch(/operator_id\s*=\s*\$/);
    expect(lockUse.sql).toMatch(/receiver_id\s*=\s*\$/);
    expect(lockUse.params).toEqual(['use_one', 'rcv_one', 'op_one']);
  });

  it('refuses a presentation whose authority use belongs to a different tenant', async () => {
    const presentation = {
      id: 'apr_one', receiver_id: 'rcv_one', operator_id: 'op_one', authority_use_id: 'use_one', status: 'verified',
    };
    const foreignUse = { id: 'use_one', receiver_id: 'rcv_one', operator_id: 'op_other' };
    let reads = 0;
    const db = {
      select: () => ({ from: () => ({ where: () => ({ limit: async () => [reads++ === 0 ? presentation : foreignUse] }) }) }),
    };
    const transaction = { execute: vi.fn(async () => undefined) };
    const repo = new AuthorityRepository(db as unknown as Database, transaction as never);
    await expect(repo.lockPresentationAndUseForReceipt('rcv_one', 'apr_one')).resolves.toBeNull();
  });
});
