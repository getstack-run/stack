import { describe, it, expect } from 'vitest';
import { enforceRequires } from './requires-enforcer.js';

/**
 * requires_unmet enforcer.
 *
 * Pure-function tests. The repo dep is faked end-to-end so we exercise
 * the filter logic in isolation. Real same-session / cross-session
 * Postgres semantics are exercised by the C8 integration smokes.
 */

interface RepoRow {
  claim_id: string;
  type: string;
  body_json: unknown;
}

function makeRepo(canned: RepoRow[]) {
  let lastClaimIds: string[] | null = null;
  let lastSessionId: string | null = null;
  const repo = {
    findActiveOutcomesByClaimIdsAndSessionId: async (
      claimIds: string[],
      sessionId: string,
    ): Promise<RepoRow[]> => {
      lastClaimIds = claimIds;
      lastSessionId = sessionId;
      // Fake: returns only canned rows whose claim_id is requested.
      return canned.filter((row) => claimIds.includes(row.claim_id));
    },
  };
  return {
    repo,
    getLastClaimIds: () => lastClaimIds,
    getLastSessionId: () => lastSessionId,
  };
}

describe('enforceRequires', () => {
  it('returns allowed=true with NO repo call when requires is empty', async () => {
    const { repo, getLastClaimIds } = makeRepo([]);
    const result = await enforceRequires({ passportClaimsRepo: repo }, {
      sessionId: 'ses_x',
      requires: [],
    });
    expect(result).toEqual({ allowed: true });
    expect(getLastClaimIds()).toBeNull(); // no SQL fired
  });

  it('returns allowed=true when every requires entry has a succeeded outcome', async () => {
    const { repo } = makeRepo([
      { claim_id: 'pc_a', type: 'intent_outcome', body_json: { status: 'succeeded' } },
      { claim_id: 'pc_b', type: 'intent_outcome', body_json: { status: 'succeeded' } },
    ]);
    const result = await enforceRequires({ passportClaimsRepo: repo }, {
      sessionId: 'ses_ok',
      requires: ['pc_a', 'pc_b'],
    });
    expect(result).toEqual({ allowed: true });
  });

  it('returns allowed=false with all missing ids when none are satisfied', async () => {
    const { repo } = makeRepo([]); // no rows at all
    const result = await enforceRequires({ passportClaimsRepo: repo }, {
      sessionId: 'ses_none',
      requires: ['pc_x', 'pc_y'],
    });
    expect(result).toEqual({
      allowed: false,
      failingRequires: ['pc_x', 'pc_y'],
    });
  });

  it('returns allowed=false with only the missing id (mixed batch)', async () => {
    const { repo } = makeRepo([
      { claim_id: 'pc_a', type: 'intent_outcome', body_json: { status: 'succeeded' } },
    ]);
    const result = await enforceRequires({ passportClaimsRepo: repo }, {
      sessionId: 'ses_mix',
      requires: ['pc_a', 'pc_missing'],
    });
    expect(result).toEqual({
      allowed: false,
      failingRequires: ['pc_missing'],
    });
  });

  it('rejects outcomes with non-succeeded status (failed)', async () => {
    const { repo } = makeRepo([
      { claim_id: 'pc_f', type: 'intent_outcome', body_json: { status: 'failed' } },
    ]);
    const result = await enforceRequires({ passportClaimsRepo: repo }, {
      sessionId: 'ses_failed',
      requires: ['pc_f'],
    });
    expect(result).toEqual({
      allowed: false,
      failingRequires: ['pc_f'],
    });
  });

  it('rejects outcomes with non-succeeded status (cancelled / timeout)', async () => {
    const { repo } = makeRepo([
      { claim_id: 'pc_c', type: 'intent_outcome', body_json: { status: 'cancelled' } },
      { claim_id: 'pc_t', type: 'intent_outcome', body_json: { status: 'timeout' } },
    ]);
    const result = await enforceRequires({ passportClaimsRepo: repo }, {
      sessionId: 'ses_ct',
      requires: ['pc_c', 'pc_t'],
    });
    expect(result).toEqual({
      allowed: false,
      failingRequires: ['pc_c', 'pc_t'],
    });
  });

  it('rejects rows whose type is not intent_outcome (defense-in-depth)', async () => {
    // The repo SQL already filters to type='intent_outcome', but the
    // helper also rejects to survive a future repo change that loosens
    // the SQL filter.
    const { repo } = makeRepo([
      { claim_id: 'pc_w', type: 'intent_claim', body_json: { status: 'succeeded' } },
    ]);
    const result = await enforceRequires({ passportClaimsRepo: repo }, {
      sessionId: 'ses_type',
      requires: ['pc_w'],
    });
    expect(result).toEqual({
      allowed: false,
      failingRequires: ['pc_w'],
    });
  });

  it('threads sessionId verbatim to the repo', async () => {
    const { repo, getLastSessionId } = makeRepo([]);
    await enforceRequires({ passportClaimsRepo: repo }, {
      sessionId: 'ses_specific_123',
      requires: ['pc_z'],
    });
    expect(getLastSessionId()).toBe('ses_specific_123');
  });
});
