import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import type { IntentClaim } from '@stack/shared';
import {
  ApprovalGateService,
  type GateInput,
} from './approval-gate-service.js';

/**
 * ApprovalGateService unit tests.
 *
 * Covers all 8 gate_reason paths + skip-on-non-enforced + the
 * requires_unmet thread-through. Real Postgres CAS + per-producer
 * shape comparators are exercised in the C8 integration smokes.
 */

interface FakeApprovalRow {
  id: string;
  operator_id: string;
  agent_id?: string;
  passport_jti: string;
  intent_claim_id: string;
  status: 'pending' | 'approved' | 'consuming' | 'rejected' | 'expired' | 'consumed';
  consuming_owner_hash?: string | null;
  expires_at: Date;
}

function buildIntentClaim(overrides: Partial<IntentClaim> = {}): IntentClaim {
  return {
    type: 'intent_claim',
    intent_type: 'http_call',
    agent_id: 'ag_test',
    named_intent: 'stripe:refund',
    target: 'stripe',
    action: 'POST https://api.stripe.com/v1/refunds',
    parameters: { method: 'POST', url: 'https://api.stripe.com/v1/refunds' },
    estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
    accountability: 'enforced',
    reason: null,
    requires: [],
    user_subject: null,
    mission_ref: null,
    submitted_at: Date.now(),
    ...overrides,
  } as IntentClaim;
}

function buildDeps(opts: {
  rows?: FakeApprovalRow[];
  claim?: IntentClaim;
  outcomeRows?: Array<{ claim_id: string; type: string; body_json: unknown }>;
}) {
  const rowMap = new Map((opts.rows ?? []).map((r) => [r.id, r]));
  const claim = opts.claim ?? buildIntentClaim();
  const outcomes = opts.outcomeRows ?? [];

  return {
    approvalRepo: {
      // A row names its agent; the fixtures that do not say are the test agent's.
      findById: async (id: string) => {
        const row = rowMap.get(id);
        if (row && row.agent_id === undefined) row.agent_id = 'ag_test';
        return row;
      },
      // markReserved (approved -> consuming) is the single-winner admit added
      // to close approval.consume-is-racy. The gate now calls it at the end of
      // check(); the fake must model the CAS or every admit denies.
      markReserved: async (id: string, ownerHash?: string) => {
        const row = rowMap.get(id);
        if (!row || row.status !== 'approved') return false;
        row.status = 'consuming';
        row.consuming_owner_hash = ownerHash ?? null;
        return true;
      },
      releaseReservation: async (id: string, ownerHash?: string) => {
        const row = rowMap.get(id);
        if (!row || row.status !== 'consuming') return false;
        if ((row.consuming_owner_hash ?? null) !== (ownerHash ?? null)) return false;
        row.status = 'approved';
        row.consuming_owner_hash = null;
        return true;
      },
      markConsumed: async (id: string, ownerHash?: string) => {
        const row = rowMap.get(id);
        if (!row || (row.status !== 'consuming' && row.status !== 'approved')) return false;
        if (ownerHash) {
          if (row.status !== 'consuming' || row.consuming_owner_hash !== ownerHash) return false;
        } else if (row.status === 'consuming' && row.consuming_owner_hash != null) {
          return false;
        }
        row.status = 'consumed';
        row.consuming_owner_hash = ownerHash ?? null;
        return true;
      },
    } as never,
    claimRegistry: {
      getClaim: async (claimId: string) => {
        return {
          claim_id: claimId,
          body_json: claim,
        } as never;
      },
    },
    passportClaimsRepo: {
      findActiveOutcomesByClaimIdsAndSessionId: async (
        claimIds: string[],
        _sessionId: string,
      ) => outcomes.filter((row) => claimIds.includes(row.claim_id)),
    },
  };
}

function baseInput(overrides: Partial<GateInput> = {}): GateInput {
  return {
    passportJti: 'pas_test',
    agentId: 'ag_test',
    missionId: null,
    operatorId: 'op_test',
    sessionId: 'ses_test',
    accountabilityMode: 'enforced',
    approvalIdHeader: 'ia_test',
    ...overrides,
  };
}

const fiveMinAhead = () => new Date(Date.now() + 5 * 60 * 1000);

describe('ApprovalGateService.check — gate_reason taxonomy', () => {
  it('returns skipped=true for standard mode (no header required)', async () => {
    const gate = new ApprovalGateService(buildDeps({}));
    const result = await gate.check(baseInput({ accountabilityMode: 'standard', approvalIdHeader: undefined }));
    expect(result).toEqual({ allowed: true, skipped: true });
  });

  it('returns skipped=true for logged mode (gate is enforced-only)', async () => {
    const gate = new ApprovalGateService(buildDeps({}));
    const result = await gate.check(baseInput({ accountabilityMode: 'logged', approvalIdHeader: undefined }));
    expect(result).toEqual({ allowed: true, skipped: true });
  });

  it('denies enforced + missing header with gate_reason=missing', async () => {
    const gate = new ApprovalGateService(buildDeps({}));
    const result = await gate.check(baseInput({ approvalIdHeader: undefined }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('missing');
      expect(result.metadata.gate_reason).toBe('missing');
      expect(result.metadata.approval_id).toBeNull();
    }
  });

  it('denies enforced + unknown approval id with gate_reason=not_found', async () => {
    const gate = new ApprovalGateService(buildDeps({ rows: [] }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_unknown' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('not_found');
      expect(result.metadata.gate_reason).toBe('not_found');
      expect(result.metadata.approval_id).toBe('ia_unknown');
    }
  });

  it('denies enforced + cross-operator approval id with gate_reason=not_found (existence hidden)', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_x',
      operator_id: 'op_OTHER',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_x' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('not_found');
    }
  });

  it('denies when approval belongs to a different passport with gate_reason=wrong_passport', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_wp',
      operator_id: 'op_test',
      passport_jti: 'pas_OTHER',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_wp' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('wrong_passport');
      expect(result.metadata.gate_reason).toBe('wrong_passport');
    }
  });

  it('denies consumed approval with gate_reason=already_consumed', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_consumed',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'consumed',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_consumed' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('already_consumed');
    }
  });

  it('denies pending approval with gate_reason=wrong_status', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_pending',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'pending',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_pending' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('wrong_status');
    }
  });

  it('denies rejected approval with gate_reason=wrong_status', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_rej',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'rejected',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_rej' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('wrong_status');
    }
  });

  it('denies status=expired row with gate_reason=expired', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_exp_status',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'expired',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_exp_status' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('expired');
    }
  });

  it('denies approved-but-past-TTL row with gate_reason=expired', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_exp_ttl',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: new Date(Date.now() - 1000), // 1s past
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_exp_ttl' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('expired');
    }
  });

  it('allows approved + within-TTL + matching passport, returns IntentClaim', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_ok',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: fiveMinAhead(),
    };
    const claim = buildIntentClaim({ target: 'slack' });
    const gate = new ApprovalGateService(buildDeps({ rows: [row], claim }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_ok' }));
    expect(result.allowed).toBe(true);
    if (result.allowed && !result.skipped) {
      expect(result.intentClaim.target).toBe('slack');
      expect(result.approvalId).toBe('ia_ok');
      expect(result.intentClaimId).toBe('pc_intent');
    }
  });

  it('denies when requires_unmet — missing outcome on this session', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_req',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: fiveMinAhead(),
    };
    const claim = buildIntentClaim({ requires: ['pc_dependency'] });
    const gate = new ApprovalGateService(buildDeps({
      rows: [row],
      claim,
      outcomeRows: [], // none satisfied
    }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_req' }));
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBe('requires_unmet');
      expect(result.metadata.failing_requires).toEqual(['pc_dependency']);
      // intentClaim is non-null because we loaded it before checking requires
      expect(result.intentClaim).not.toBeNull();
    }
  });

  it('allows when requires_unmet → all satisfied', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_req_ok',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: fiveMinAhead(),
    };
    const claim = buildIntentClaim({ requires: ['pc_dep_ok'] });
    const gate = new ApprovalGateService(buildDeps({
      rows: [row],
      claim,
      outcomeRows: [
        { claim_id: 'pc_dep_ok', type: 'intent_outcome', body_json: { status: 'succeeded' } },
      ],
    }));
    const result = await gate.check(baseInput({ approvalIdHeader: 'ia_req_ok' }));
    expect(result.allowed).toBe(true);
  });

  it('returns a non-dispatch replay result only to the operation that owns the reservation', async () => {
    const ownerHash = 'a'.repeat(64);
    const row: FakeApprovalRow = {
      id: 'ia_owned',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));

    await expect(gate.check(baseInput({
      approvalIdHeader: row.id,
      reservationOwnerHash: ownerHash,
    }))).resolves.toMatchObject({ allowed: true, skipped: false });
    expect(row).toMatchObject({ status: 'consuming', consuming_owner_hash: ownerHash });

    const replay = await gate.check(baseInput({
      approvalIdHeader: row.id,
      reservationOwnerHash: ownerHash,
    }));
    expect(replay).toMatchObject({
      allowed: false,
      replay: true,
      reason: 'already_consumed',
      intentClaimId: row.intent_claim_id,
    });
    expect(replay).not.toHaveProperty('approvalId');

    const foreign = await gate.check(baseInput({
      approvalIdHeader: row.id,
      reservationOwnerHash: 'b'.repeat(64),
    }));
    expect(foreign).toMatchObject({ allowed: false, reason: 'already_consumed' });
    expect(foreign).not.toHaveProperty('replay', true);
    await expect(gate.releaseReservation(row.id, 'b'.repeat(64))).resolves.toBe(false);
    await expect(gate.markConsumed(row.id, 'b'.repeat(64))).resolves.toBe(false);
    await expect(gate.markConsumed(row.id, ownerHash)).resolves.toBe(true);
    expect(row).toMatchObject({ status: 'consumed', consuming_owner_hash: ownerHash });

    const completedReplay = await gate.check(baseInput({
      approvalIdHeader: row.id,
      reservationOwnerHash: ownerHash,
    }));
    expect(completedReplay).toMatchObject({ allowed: false, replay: true });
    await expect(gate.markConsumed(row.id, ownerHash)).resolves.toBe(false);
    await expect(gate.releaseReservation(row.id, ownerHash)).resolves.toBe(false);
  });

  it('hashes a stable operation handle before storing reservation ownership', async () => {
    const operationHandle = 'AbCdEfGhIjKlMnOpQrStUv';
    const row: FakeApprovalRow = {
      id: 'ia_raw_owner',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));

    await expect(gate.check(baseInput({
      approvalIdHeader: row.id,
      reservationOwner: operationHandle,
    }))).resolves.toMatchObject({ allowed: true, skipped: false });
    expect(row.consuming_owner_hash).toBe(
      createHash('sha256').update(operationHandle, 'utf8').digest('hex'),
    );

    const replay = await gate.check(baseInput({
      approvalIdHeader: row.id,
      reservationOwner: operationHandle,
    }));
    expect(replay).toMatchObject({ allowed: false, replay: true });
  });

  it('rejects ambiguous or malformed reservation owners before reading an approval', async () => {
    const gate = new ApprovalGateService(buildDeps({}));
    await expect(gate.check(baseInput({
      reservationOwner: 'A'.repeat(22),
      reservationOwnerHash: 'a'.repeat(64),
    }))).rejects.toThrow('not both');
    await expect(gate.check(baseInput({
      reservationOwner: 'not base64url!',
    }))).rejects.toThrow('22-256 character base64url');
  });
});

describe('ApprovalGateService.markConsumed', () => {
  it('returns true on first call for an approved row', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_consume_1',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'approved',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const ok = await gate.markConsumed('ia_consume_1');
    expect(ok).toBe(true);
    expect(row.status).toBe('consumed');
  });

  it('returns false on second call (idempotent)', async () => {
    const row: FakeApprovalRow = {
      id: 'ia_consume_2',
      operator_id: 'op_test',
      passport_jti: 'pas_test',
      intent_claim_id: 'pc_intent',
      status: 'consumed',
      expires_at: fiveMinAhead(),
    };
    const gate = new ApprovalGateService(buildDeps({ rows: [row] }));
    const ok = await gate.markConsumed('ia_consume_2');
    expect(ok).toBe(false);
  });
});

describe('ApprovalGateService.check — bound to the agent and the Mission, not the passport', () => {
  const row = (): FakeApprovalRow => ({
    id: 'ia_test', operator_id: 'op_test', passport_jti: 'pas_before_refresh', intent_claim_id: 'pc_test',
    status: 'approved', expires_at: fiveMinAhead(),
  });
  const claim = buildIntentClaim({ mission_ref: 'ms_job' });

  it('admits the approval through a refreshed passport of the same agent under the same Mission', async () => {
    const gate = new ApprovalGateService(buildDeps({ rows: [row()], claim }));
    const result = await gate.check(baseInput({ passportJti: 'pas_after_refresh', missionId: 'ms_job' }));
    expect(result.allowed).toBe(true);
  });

  it('refuses it for another agent, or under another Mission', async () => {
    for (const input of [{ agentId: 'ag_other', missionId: 'ms_job' }, { missionId: 'ms_other' }, { missionId: null }]) {
      const gate = new ApprovalGateService(buildDeps({ rows: [row()], claim }));
      const result = await gate.check(baseInput({ passportJti: 'pas_after_refresh', ...input }));
      expect(result).toMatchObject({ allowed: false, reason: 'wrong_passport' });
    }
  });

  it('keeps the passport binding for an approval whose intent named no Mission', async () => {
    const legacy = buildIntentClaim({ mission_ref: null });
    const refreshed = await new ApprovalGateService(buildDeps({ rows: [row()], claim: legacy })).check(baseInput({ passportJti: 'pas_after_refresh' }));
    expect(refreshed).toMatchObject({ allowed: false, reason: 'wrong_passport' });
    const same = await new ApprovalGateService(buildDeps({ rows: [row()], claim: legacy })).check(baseInput({ passportJti: 'pas_before_refresh' }));
    expect(same.allowed).toBe(true);
  });
});
