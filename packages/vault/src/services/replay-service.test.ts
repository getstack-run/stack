import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { ReplayService, type ReplayServiceDeps } from './replay-service.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { ReconstructClaimInput } from '@stack/shared';

/**
 * ReplayService invariants.
 *
 *   RS1: reconstructMissionTimeline calls findInMissionScope with (missionId, operatorId)
 *   RS2: rows with null body_json are skipped
 *   RS3: claim_id + claim_hash flow through to event entries
 *   RS4: issued_at_ms from row column drives ordering
 *   RS5: legacy rows with null issued_at_ms fall back to attached_at.getTime()
 *   RS6: reconstructFromClaims passes its input straight through to the shared helper
 *   RS7: timeline output equals shared helper output for the same claim set
 */

type RowShape = {
  claim_id: string;
  claim_hash: string;
  type: string;
  body_json: Record<string, unknown> | null;
  issued_at_ms: number | null;
  attached_at: Date;
  envelope_cose?: string | null;
  keep_claim_hash?: boolean;
};

const TEST_ENVELOPE = Buffer.from('signed-envelope').toString('base64url');
const TEST_ENVELOPE_HASH = createHash('sha256').update(Buffer.from(TEST_ENVELOPE, 'base64url')).digest('hex');

function makeRepo(rows: RowShape[]): {
  repo: PassportClaimsRepository;
  calls: Array<{ missionId: string; operatorId: string; t0Ms?: number; t1Ms?: number; pagination?: { page: number; limit: number } }>;
} {
  const calls: Array<{ missionId: string; operatorId: string; t0Ms?: number; t1Ms?: number; pagination?: { page: number; limit: number } }> = [];
  const repo = {
    findInMissionScope: async (missionId: string, operatorId: string, t0Ms?: number, t1Ms?: number, pagination?: { page: number; limit: number }) => {
      calls.push({ missionId, operatorId, t0Ms, t1Ms, ...(pagination ? { pagination } : {}) });
      return rows.map((row) => ({
        ...row,
        envelope_cose: row.envelope_cose === undefined ? TEST_ENVELOPE : row.envelope_cose,
        claim_hash: row.keep_claim_hash ? row.claim_hash : TEST_ENVELOPE_HASH,
      })) as unknown as ReturnType<PassportClaimsRepository['findInMissionScope']>;
    },
  } as unknown as PassportClaimsRepository;
  return { repo, calls };
}

function makeService(rows: RowShape[]) {
  const { repo, calls } = makeRepo(rows);
  const deps: ReplayServiceDeps = {
    passportClaimsRepo: repo,
    missionRepo: {
      findById: async (missionId) => ({
        mission_id: missionId,
        operator_id: 'op_y',
        started_at: new Date(100),
        completed_at: new Date(10_000),
        revoked_at: null,
      }),
    },
    claimVerifier: {
      verifyClaim: async (claimId) => {
        const row = rows.find((candidate) => candidate.claim_id === claimId);
        if (!row || row.envelope_cose === null) return { valid: false, error: 'no envelope' };
        return {
          valid: true,
          envelope: {
            envelope_version: 1,
            issuer: 'op_y',
            subject: 'stack://operator/op_y',
            issued_at: row.issued_at_ms ?? row.attached_at.getTime(),
            claim_type: row.type as never,
            claim_version: 1,
            payload: row.body_json ?? {},
            receipt: null,
            co_signatures: [],
          },
        };
      },
    },
  };
  return { service: new ReplayService(deps), calls };
}

describe('ReplayService.reconstructMissionTimeline', () => {
  it('pages verified records without publishing partial reconstructed totals or mission state', async () => {
    const rows = Array.from({ length: 21 }, (_, index): RowShape => ({
      claim_id: `pc_page_${index}`, claim_hash: '', type: 'intent_claim',
      body_json: { action: `action ${index}` }, issued_at_ms: 200 + index, attached_at: new Date(200 + index),
    }));
    const { service, calls } = makeService(rows);
    const result = await service.listMissionClaimPage('ms_page', 'op_y', { page: 2, limit: 20 });
    expect(calls[0]?.pagination).toEqual({ page: 2, limit: 20 });
    expect(result.events).toHaveLength(20);
    expect(result).toMatchObject({ view: 'claim_page', page: 2, limit: 20, has_more: true });
    expect(result).not.toHaveProperty('cap_usage');
    expect(result).not.toHaveProperty('mission');
    expect(result.events[0]).toMatchObject({ kind: 'intent_claim', body: { action: 'action 0' } });
  });
  it('reads the verified immutable envelope instead of mutable body_json', async () => {
    const rows: RowShape[] = [{
      claim_id: 'pc_signed',
      claim_hash: 'hash_signed',
      type: 'intent_claim',
      body_json: { source: 'mutable projection' },
      issued_at_ms: 999,
      attached_at: new Date(999),
    }];
    const { repo } = makeRepo(rows);
    const service = new ReplayService({
      passportClaimsRepo: repo,
      missionRepo: {
        findById: async () => ({
          mission_id: 'ms_x', operator_id: 'op_y', started_at: new Date(100),
          completed_at: new Date(10_000), revoked_at: null,
        }),
      },
      claimVerifier: {
        verifyClaim: async () => ({
          valid: true,
          envelope: {
            issuer: 'op_y',
            claim_type: 'intent_claim',
            issued_at: 123,
            payload: { source: 'signed envelope' },
          },
        }),
      },
    } as unknown as ReplayServiceDeps);

    const timeline = await service.reconstructMissionTimeline('ms_x', 'op_y');
    expect(timeline.events[0]!.at_ms).toBe(123);
    expect(timeline.events[0]!.body).toEqual({ source: 'signed envelope' });
  });

  it('fails closed when a mission claim envelope does not verify', async () => {
    const rows: RowShape[] = [{
      claim_id: 'pc_bad',
      claim_hash: 'hash_bad',
      type: 'intent_claim',
      body_json: {},
      issued_at_ms: 1,
      attached_at: new Date(1),
    }];
    const { repo } = makeRepo(rows);
    const service = new ReplayService({
      passportClaimsRepo: repo,
      missionRepo: {
        findById: async () => ({
          mission_id: 'ms_x', operator_id: 'op_y', started_at: new Date(100),
          completed_at: new Date(10_000), revoked_at: null,
        }),
      },
      claimVerifier: {
        verifyClaim: async () => ({ valid: false, error: 'signature mismatch' }),
      },
    } as unknown as ReplayServiceDeps);

    await expect(service.reconstructMissionTimeline('ms_x', 'op_y'))
      .rejects.toThrow(/pc_bad.*signature mismatch/i);
  });

  it('fails closed when the stored claim hash does not match the signed envelope', async () => {
    const { service } = makeService([{
      claim_id: 'pc_bad_hash',
      claim_hash: '0'.repeat(64),
      type: 'intent_claim',
      body_json: {},
      issued_at_ms: 1,
      attached_at: new Date(1),
      keep_claim_hash: true,
    }]);
    await expect(service.reconstructMissionTimeline('ms_x', 'op_y'))
      .rejects.toThrow(/pc_bad_hash.*hash mismatch/i);
  });

  it('RS1 calls findInMissionScope with (missionId, operatorId)', async () => {
    const { service, calls } = makeService([]);
    await service.reconstructMissionTimeline('ms_x', 'op_y');
    expect(calls).toEqual([{
      missionId: 'ms_x', operatorId: 'op_y', t0Ms: 100, t1Ms: 10_000,
    }]);
  });

  it('fails closed before reading claims for an unknown or foreign mission', async () => {
    const { repo, calls } = makeRepo([]);
    const service = new ReplayService({
      passportClaimsRepo: repo,
      missionRepo: { findById: async () => ({
        mission_id: 'ms_x', operator_id: 'op_other', started_at: new Date(1),
        completed_at: new Date(2), revoked_at: null,
      }) },
      claimVerifier: { verifyClaim: async () => ({ valid: false }) },
    } as ReplayServiceDeps);
    await expect(service.reconstructMissionTimeline('ms_x', 'op_y')).rejects.toThrow(/not found/i);
    expect(calls).toEqual([]);
  });

  it('RS2 rows without immutable envelopes fail closed', async () => {
    const { service } = makeService([
      {
        claim_id: 'pc_skip',
        claim_hash: 'h1',
        type: 'intent_claim',
        body_json: null,
        issued_at_ms: 1,
        attached_at: new Date(1),
        envelope_cose: null,
      },
    ]);
    await expect(service.reconstructMissionTimeline('ms_x', 'op_y'))
      .rejects.toThrow(/pc_skip.*no immutable envelope/i);
  });

  it('RS3 claim_id + claim_hash flow through to event entries', async () => {
    const { service } = makeService([
      {
        claim_id: 'pc_a',
        claim_hash: 'hash_a',
        type: 'detector_signal',
        body_json: {},
        issued_at_ms: 1,
        attached_at: new Date(1),
      },
    ]);
    const timeline = await service.reconstructMissionTimeline('ms_x', 'op_y');
    expect(timeline.events[0]!.claim_id).toBe('pc_a');
    expect(timeline.events[0]!.claim_hash).toBe(TEST_ENVELOPE_HASH);
  });

  it('RS4 issued_at_ms from row column drives ordering', async () => {
    const { service } = makeService([
      {
        claim_id: 'pc_late',
        claim_hash: 'h1',
        type: 'intent_claim',
        body_json: {},
        issued_at_ms: 200,
        attached_at: new Date(200),
      },
      {
        claim_id: 'pc_early',
        claim_hash: 'h2',
        type: 'intent_claim',
        body_json: {},
        issued_at_ms: 100,
        attached_at: new Date(100),
      },
    ]);
    const timeline = await service.reconstructMissionTimeline('ms_x', 'op_y');
    expect(timeline.events.map((e) => e.claim_id)).toEqual(['pc_early', 'pc_late']);
  });

  it('RS5 null issued_at_ms falls back to attached_at.getTime()', async () => {
    const { service } = makeService([
      {
        claim_id: 'pc_legacy',
        claim_hash: 'h1',
        type: 'intent_claim',
        body_json: {},
        issued_at_ms: null,
        attached_at: new Date(5000),
      },
    ]);
    const timeline = await service.reconstructMissionTimeline('ms_x', 'op_y');
    expect(timeline.events[0]!.at_ms).toBe(5000);
  });

  it('RS6 reconstructFromClaims passes its input through to shared helper', () => {
    const { service } = makeService([]);
    const claims: ReconstructClaimInput[] = [
      {
        type: 'intent_claim',
        body: {},
        issued_at_ms: 1,
        claim_id: 'pc_a',
        claim_hash: 'h',
      },
    ];
    const timeline = service.reconstructFromClaims('ms_x', 'op_y', claims);
    expect(timeline.events).toHaveLength(1);
    expect(timeline.events[0]!.kind).toBe('intent_submitted');
  });

  it('RS7 both paths produce identical output for identical claim sets', async () => {
    const rows: RowShape[] = [
      {
        claim_id: 'pc_open',
        claim_hash: 'h',
        type: 'mission',
        body_json: { mission_id: 'ms_x', terminal_state: null },
        issued_at_ms: 1000,
        attached_at: new Date(1000),
      },
      {
        claim_id: 'pc_intent',
        claim_hash: 'h2',
        type: 'intent_claim',
        body_json: {},
        issued_at_ms: 1500,
        attached_at: new Date(1500),
      },
    ];
    const { service } = makeService(rows);
    const live = await service.reconstructMissionTimeline('ms_x', 'op_y');
    const fromClaims = service.reconstructFromClaims(
      'ms_x',
      'op_y',
      rows.map((r) => ({
        type: r.type,
        body: r.body_json!,
        issued_at_ms: r.issued_at_ms ?? r.attached_at.getTime(),
        claim_id: r.claim_id,
        claim_hash: TEST_ENVELOPE_HASH,
      })),
    );
    expect(live).toEqual(fromClaims);
  });
});
