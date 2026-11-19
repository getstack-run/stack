import { describe, it, expect } from 'vitest';
import { IntentApprovalRepository } from './intent-approval-repo.js';

/**
 * `markConsumed` CAS substrate.
 *
 * The producer gate flips `approved` → `consumed` after the first
 * successful 2xx-3xx outcome. The transition is an atomic CAS so
 * concurrent in-flight calls cannot double-consume.
 *
 * These unit tests pin the CAS predicate (only flips when status is
 * exactly `approved`, returns `true` on hit / `false` on miss). The
 * race-against-real-Postgres semantics are exercised by the integration
 * smoke (enforced + approved + replay → 403 already_consumed).
 */

type RowState = 'pending' | 'approved' | 'rejected' | 'expired' | 'consumed';

describe('IntentApprovalRepository.markConsumed (CAS)', () => {
  // The repo uses drizzle's `and(eq(id, X), eq(status, 'approved'))`.
  // The drizzle helpers compile down to a query object that's opaque to
  // a stub, so each test injects a fake whose `update().set().where()
  // .returning()` chain evaluates the CAS predicate against the local
  // row state directly. The predicate is encoded structurally: the SET
  // only takes effect when the row's current status is 'approved'.
  function singleRowFake(id: string, initial: RowState) {
    const row: { id: string; status: RowState } = { id, status: initial };
    const db = {
      update: () => ({
        set: (patch: Partial<{ status: RowState }>) => ({
          where: () => ({
            returning: () => {
              // Reconstruct the CAS predicate the repo encodes:
              // status MUST be 'approved' for the flip to fire.
              if (row.status !== 'approved') return Promise.resolve([]);
              if (patch.status) row.status = patch.status;
              return Promise.resolve([{ id: row.id }]);
            },
          }),
        }),
      }),
    };
    return { db, row };
  }

  it('flips approved → consumed and returns true', async () => {
    const { db, row } = singleRowFake('ia_test_1', 'approved');
    const repo = new IntentApprovalRepository(db as never);
    const ok = await repo.markConsumed('ia_test_1');
    expect(ok).toBe(true);
    expect(row.status).toBe('consumed');
  });

  it('returns false when row is already consumed (idempotent)', async () => {
    const { db, row } = singleRowFake('ia_test_2', 'consumed');
    const repo = new IntentApprovalRepository(db as never);
    const ok = await repo.markConsumed('ia_test_2');
    expect(ok).toBe(false);
    expect(row.status).toBe('consumed');
  });

  it('returns false when row is still pending (CAS miss)', async () => {
    const { db, row } = singleRowFake('ia_test_3', 'pending');
    const repo = new IntentApprovalRepository(db as never);
    const ok = await repo.markConsumed('ia_test_3');
    expect(ok).toBe(false);
    expect(row.status).toBe('pending');
  });

  it('returns false when row is rejected (CAS miss)', async () => {
    const { db, row } = singleRowFake('ia_test_4', 'rejected');
    const repo = new IntentApprovalRepository(db as never);
    const ok = await repo.markConsumed('ia_test_4');
    expect(ok).toBe(false);
    expect(row.status).toBe('rejected');
  });

  it('returns false when row is expired (CAS miss)', async () => {
    const { db, row } = singleRowFake('ia_test_5', 'expired');
    const repo = new IntentApprovalRepository(db as never);
    const ok = await repo.markConsumed('ia_test_5');
    expect(ok).toBe(false);
    expect(row.status).toBe('expired');
  });

  it('concurrent race: exactly one of two flips wins', async () => {
    // Two concurrent markConsumed calls on the same approved row. The
    // fake's mutation is synchronous so the second to read sees consumed
    // status and returns []. This mirrors the Postgres CAS semantics:
    // UPDATE ... WHERE status='approved' RETURNING id only returns a
    // row if the SET took effect. The PG row lock + the WHERE predicate
    // ensure exactly one transaction wins.
    const { db, row } = singleRowFake('ia_race', 'approved');
    const repo = new IntentApprovalRepository(db as never);
    const [a, b] = await Promise.all([
      repo.markConsumed('ia_race'),
      repo.markConsumed('ia_race'),
    ]);
    expect([a, b].sort()).toEqual([false, true]);
    expect(row.status).toBe('consumed');
  });
});
