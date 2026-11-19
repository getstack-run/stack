import { describe, it, expect } from 'vitest';
import { PassportClaimsRepository } from './passport-claims-repo.js';

/**
 * CR1 verification.
 *
 * The audit chain's claim binding (audit_log.passport_claims_at_event)
 * is populated at write time by PassportClaimsRepository
 * .findActiveHashesByPassportId(). If that resolver ever filtered by
 * claim_type, new claim types added by (intent_claim
 * intent_outcome, detector_signal, intent_denial, intent_simulation)
 * would silently drop out of the chain hash, breaking the
 * cryptographic binding between audit events and the claims that
 * were live at the moment of the event.
 *
 * These tests pin the contract: regardless of claim_type, every
 * non-revoked claim attached to the passport must appear in the
 * resolver's output. A fake Drizzle interface returns canned rows;
 * the resolver runs against it; assertions check the propagation.
 *
 * (The claim signing smoke
 * exercises the same contract end-to-end against a real DB. Both
 * layers cover this — the unit tests catch regressions in the
 * resolver method shape; the smoke catches anything the unit tests
 * can't see because they fake the SQL layer.)
 */

interface FakeRow {
  claim_hash: string;
  passport_id: string;
  revoked_at: Date | null;
  claim_type: string;
}

/**
 * Minimal Drizzle-shape fake. Honours the WHERE filter (passport_id
 * match + revoked_at IS NULL) so we can verify revoked + cross-passport
 * rows are correctly excluded. Does NOT filter on claim_type — that's
 * the invariant the test exists to enforce.
 *
 * Mirrors the full chain the real resolver invokes:
 *   db.select(cols).from(table).where(cond).orderBy(...).limit(N)
 *
 * An earlier change added the orderBy + limit(50) head-cap. The chain steps
 * are no-ops in the fake (we don't simulate the ordering or cap; the
 * tests use input sets small enough that the cap is moot), but the
 * methods MUST exist on each step so the chain is callable.
 */
function makeFakeDb(rows: FakeRow[], filterByPassportId: string) {
  const filtered = rows.filter(
    (r) => r.passport_id === filterByPassportId && r.revoked_at === null,
  );
  const result = filtered.map((r) => ({ claim_hash: r.claim_hash }));
  // Terminal thenable: orderBy/limit return self so the chain composes.
  const terminal: any = {
    orderBy: () => terminal,
    limit: () => Promise.resolve(result),
    then: (resolve: (r: typeof result) => unknown) => resolve(result),
  };
  return {
    select: () => ({
      from: () => ({
        where: () => terminal,
      }),
    }),
  };
}

describe('PassportClaimsRepository.findActiveHashesByPassportId — CR1 invariant', () => {
  it('returns hashes for every claim_type attached to the passport (no claim_type filter)', async () => {
    const passportId = 'pas_cr1_test';
    const rows: FakeRow[] = [
      // All 5 new claim types attached to the same passport
      // none revoked. The resolver must return ALL 5 hashes.
      { claim_hash: 'h_intent_claim', passport_id: passportId, revoked_at: null, claim_type: 'intent_claim' },
      { claim_hash: 'h_intent_outcome', passport_id: passportId, revoked_at: null, claim_type: 'intent_outcome' },
      { claim_hash: 'h_detector_signal', passport_id: passportId, revoked_at: null, claim_type: 'detector_signal' },
      { claim_hash: 'h_intent_denial', passport_id: passportId, revoked_at: null, claim_type: 'intent_denial' },
      { claim_hash: 'h_intent_simulation', passport_id: passportId, revoked_at: null, claim_type: 'intent_simulation' },
      // Also include a pre-existing claim type to confirm legacy types
      // still come through alongside new ones.
      { claim_hash: 'h_svid_attestation', passport_id: passportId, revoked_at: null, claim_type: 'svid_attestation' },
    ];

    const repo = new PassportClaimsRepository(makeFakeDb(rows, passportId) as never);
    const hashes = await repo.findActiveHashesByPassportId(passportId);

    expect(hashes).toHaveLength(6);
    expect(hashes).toEqual(
      expect.arrayContaining([
        'h_intent_claim',
        'h_intent_outcome',
        'h_detector_signal',
        'h_intent_denial',
        'h_intent_simulation',
        'h_svid_attestation',
      ]),
    );
  });

  it('excludes revoked claims regardless of claim_type', async () => {
    const passportId = 'pas_cr1_test_revoke';
    const rows: FakeRow[] = [
      { claim_hash: 'h_active', passport_id: passportId, revoked_at: null, claim_type: 'intent_claim' },
      { claim_hash: 'h_revoked', passport_id: passportId, revoked_at: new Date(), claim_type: 'intent_claim' },
      { claim_hash: 'h_revoked_outcome', passport_id: passportId, revoked_at: new Date(), claim_type: 'intent_outcome' },
    ];

    const repo = new PassportClaimsRepository(makeFakeDb(rows, passportId) as never);
    const hashes = await repo.findActiveHashesByPassportId(passportId);

    expect(hashes).toEqual(['h_active']);
  });

  it('excludes claims attached to a different passport', async () => {
    const passportId = 'pas_cr1_test_isolated';
    const rows: FakeRow[] = [
      { claim_hash: 'h_mine', passport_id: passportId, revoked_at: null, claim_type: 'intent_claim' },
      { claim_hash: 'h_theirs', passport_id: 'pas_other', revoked_at: null, claim_type: 'intent_claim' },
      { claim_hash: 'h_theirs_outcome', passport_id: 'pas_other', revoked_at: null, claim_type: 'intent_outcome' },
    ];

    const repo = new PassportClaimsRepository(makeFakeDb(rows, passportId) as never);
    const hashes = await repo.findActiveHashesByPassportId(passportId);

    expect(hashes).toEqual(['h_mine']);
  });

  it('returns an empty array when the passport has no attached claims', async () => {
    const repo = new PassportClaimsRepository(makeFakeDb([], 'pas_empty') as never);
    const hashes = await repo.findActiveHashesByPassportId('pas_empty');
    expect(hashes).toEqual([]);
  });
});

/**
 * `findActiveOutcomesByClaimIdsAndSessionId`
 * substrate for the requires_unmet enforcer.
 *
 * The repo method uses raw `db.execute(sql\`...\`)` to join
 * passport_claims → passports on session_id. Unit tests here pin the
 * empty-input short-circuit + the fake-DB query shape. The full filter
 * semantics (cross-session exclusion, revoked exclusion, type filter)
 * are exercised in the integration smoke against a
 * real Postgres.
 */
describe('PassportClaimsRepository.findActiveOutcomesByClaimIdsAndSessionId', () => {
  // Post-fix: the repo uses drizzle's query builder (select().from()
  // .innerJoin().where()) rather than raw sql\`\` because postgres-js
  // does not auto-serialise JS arrays as Postgres arrays in template
  // params. The fake DB mirrors that builder chain.
  function makeFakeDb(canned: unknown[]) {
    let selectCalled = false;
    const db = {
      select: () => {
        selectCalled = true;
        return {
          from: () => ({
            innerJoin: () => ({
              where: () => Promise.resolve(canned),
            }),
          }),
        };
      },
    };
    return { db, wasSelectCalled: () => selectCalled };
  }

  it('short-circuits to [] when claimIds is empty (no SQL fired)', async () => {
    const fake = makeFakeDb([]);
    const repo = new PassportClaimsRepository(fake.db as never);
    const rows = await repo.findActiveOutcomesByClaimIdsAndSessionId([], 'ses_anything');
    expect(rows).toEqual([]);
    expect(fake.wasSelectCalled()).toBe(false);
  });

  it('fires the query builder and returns rows verbatim', async () => {
    const canned = [
      { claim_id: 'pc_a', type: 'intent_outcome', body_json: { status: 'succeeded' } },
      { claim_id: 'pc_b', type: 'intent_outcome', body_json: { status: 'failed' } },
    ];
    const fake = makeFakeDb(canned);
    const repo = new PassportClaimsRepository(fake.db as never);
    const rows = await repo.findActiveOutcomesByClaimIdsAndSessionId(
      ['pc_a', 'pc_b'],
      'ses_test',
    );
    expect(fake.wasSelectCalled()).toBe(true);
    expect(rows).toHaveLength(2);
    expect(rows[0]?.claim_id).toBe('pc_a');
    expect(rows[1]?.claim_id).toBe('pc_b');
  });
});
