import { describe, it, expect } from 'vitest';
import { ForbiddenError, NotFoundError, type IntentClaim } from '@stack/shared';
import {
  INTENT_APPROVAL_USE_WINDOW_SECONDS,
  IntentApprovalService,
  type IntentApprovalDeps,
  type ApprovalRowView,
} from './intent-approval-service.js';
import type { IntentApprovalRepository, IntentApprovalStatus } from '../repositories/intent-approval-repo.js';
import type { ClaimRegistryService, RegisterClaimInput, RegisterClaimResult } from './claim-registry-service.js';
import type { PassportService } from './passport-service.js';
import type { IntentSimulationService, SimulateInput, SimulateResult } from './intent-simulation-service.js';

/**
 * IntentApprovalService invariants:
 *
 *  S1: submit verifies passport then registers intent_claim
 *  S2: submit runs simulation when intentSimulation dep present
 *  S3: submit skips simulation when intentSimulation dep absent
 *  S4: submit skips simulation when input.skipSimulation=true (even with dep)
 *  S5: submit refuses an expiresInSeconds over 24 hours instead of cutting it, and takes one up to it
 *  S6: submit's expiresInSeconds falls back to default (900) when 0/negative/undefined
 *  S7: submit fires onSubmit callback (best-effort; errors don't propagate)
 *
 *  L1: listPending returns items + total scoped to operator + status=pending
 *
 *  F1: findById returns row when operator matches
 *  F2: findById returns null (not 403) when operator does NOT match — cross-tenant existence hidden
 *
 *  A1: approve transitions pending → approved
 *  A2: approve on non-pending row → ForbiddenError
 *  A3: approve on cross-operator row → NotFoundError (existence hidden)
 *  A4: approve on missing row → NotFoundError
 *  A5: approve races (CAS lost) → ForbiddenError
 *
 *  R1: reject transitions pending → rejected
 *  R2: reject fires onReject callback after CAS commits
 *  R3: reject with blockFuture=true persists the flag
 *  R4: reject's onReject errors are swallowed (best-effort)
 */

let claimSeq = 0;

interface DecisionLog {
  id: string;
  decision: string;
  notes?: string;
  memberId?: string;
  blockFuture?: boolean;
}

function makeStubRepo(): {
  repo: IntentApprovalRepository;
  inserted: Array<Record<string, unknown>>;
  decisions: DecisionLog[];
  rows: Map<string, Record<string, unknown>>;
  forceCasLoss: { value: boolean };
} {
  const inserted: Array<Record<string, unknown>> = [];
  const decisions: DecisionLog[] = [];
  const rows = new Map<string, Record<string, unknown>>();
  const forceCasLoss = { value: false };

  const repo = {
    insert: async (data: Record<string, unknown>) => {
      const row = { ...data };
      inserted.push(row);
      rows.set(data['id'] as string, row);
      return row;
    },
    findById: async (id: string) => rows.get(id) ?? null,
    listByOperator: async (operatorId: string, opts?: { status?: IntentApprovalStatus }) => {
      return Array.from(rows.values()).filter(
        (r) => r['operator_id'] === operatorId && (!opts?.status || r['status'] === opts.status),
      );
    },
    countByOperator: async (operatorId: string, status?: IntentApprovalStatus) => {
      return Array.from(rows.values()).filter(
        (r) => r['operator_id'] === operatorId && (!status || r['status'] === status),
      ).length;
    },
    markDecided: async (
      id: string,
      decision: 'approved' | 'rejected',
      opts: { notes?: string; decidedByMemberId?: string; blockFuture?: boolean; useUntil?: Date; now?: Date },
    ) => {
      if (forceCasLoss.value) return null;
      const row = rows.get(id);
      if (!row || row['status'] !== 'pending') return null;
      row['status'] = decision;
      row['decided_at'] = opts.now ?? new Date();
      if (decision === 'approved' && opts.useUntil) row['expires_at'] = opts.useUntil;
      if (opts.notes !== undefined) row['notes'] = opts.notes;
      if (opts.decidedByMemberId !== undefined) row['decided_by_member_id'] = opts.decidedByMemberId;
      if (opts.blockFuture !== undefined) row['block_future'] = opts.blockFuture;
      decisions.push({ id, decision, ...opts });
      return row;
    },
    sweepExpired: async () => 0,
  } as unknown as IntentApprovalRepository;

  return { repo, inserted, decisions, rows, forceCasLoss };
}

function makeStubPassportService(claims?: Partial<{
  operator_id: string;
  agent_id: string;
  services: unknown[];
  intent_services: string[];
  accountability: 'enforced' | 'logged' | 'standard';
}>): { service: PassportService; verifyCalls: number } {
  let verifyCalls = 0;
  const service = {
    verify: async () => {
      verifyCalls++;
      return {
        jti: 'pas_test_1',
        stk: {
          operator_id: claims?.operator_id ?? 'op_test',
          agent_id: claims?.agent_id ?? 'ag_test',
          services: claims?.services ?? [],
          intent_services: claims?.intent_services ?? [],
          accountability: claims?.accountability ?? 'standard',
        },
      };
    },
  } as unknown as PassportService;
  return { service, get verifyCalls() { return verifyCalls; } } as { service: PassportService; verifyCalls: number };
}

function makeStubClaimRegistry(): { service: ClaimRegistryService; calls: RegisterClaimInput[] } {
  const calls: RegisterClaimInput[] = [];
  const service = {
    registerClaim: async (input: RegisterClaimInput): Promise<RegisterClaimResult> => {
      calls.push(input);
      const claimId = `pc_test_${++claimSeq}`;
      return { claimId, envelopeCose: 'stub', subject: `stack://operator/${input.operatorId}/passport/${input.passportJti}` };
    },
  } as unknown as ClaimRegistryService;
  return { service, calls };
}

function makeStubSimulation(): { service: IntentSimulationService; calls: SimulateInput[] } {
  const calls: SimulateInput[] = [];
  const service = {
    simulate: async (input: SimulateInput): Promise<SimulateResult> => {
      calls.push(input);
      return {
        allowed: true,
        denialReasons: [],
        simulatedCost: input.intent.estimated_cost,
        predictedDetectorFires: [],
        simulatedAt: Date.now(),
        claimId: `pc_sim_${++claimSeq}`,
        diagnostics: {},
      };
    },
  } as unknown as IntentSimulationService;
  return { service, calls };
}

function makeService(opts: {
  withSimulation?: boolean;
  onSubmit?: (row: ApprovalRowView) => Promise<void>;
  onReject?: (row: ApprovalRowView) => Promise<void>;
  forceCasLoss?: boolean;
  passportClaims?: Parameters<typeof makeStubPassportService>[0];
} = {}) {
  const stubRepo = makeStubRepo();
  const stubPassport = makeStubPassportService(opts.passportClaims);
  const stubReg = makeStubClaimRegistry();
  const stubSim = opts.withSimulation ? makeStubSimulation() : null;
  if (opts.forceCasLoss) stubRepo.forceCasLoss.value = true;

  const deps: IntentApprovalDeps = {
    repo: stubRepo.repo,
    passportService: stubPassport.service,
    claimRegistry: stubReg.service,
    ...(stubSim ? { intentSimulation: stubSim.service } : {}),
    ...(opts.onSubmit ? { onSubmit: opts.onSubmit } : {}),
    ...(opts.onReject ? { onReject: opts.onReject } : {}),
  };
  return {
    service: new IntentApprovalService(deps),
    stubRepo,
    stubReg,
    stubSim,
  };
}

function makeIntent(overrides: Partial<IntentClaim> = {}): IntentClaim {
  return {
    type: 'intent_claim',
    intent_type: 'http_call',
    agent_id: 'ag_test',
    named_intent: 'stripe:charges:create',
    target: 'stripe',
    action: 'POST /v1/charges',
    parameters: { url: 'https://api.stripe.com/v1/charges', method: 'POST' },
    estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
    accountability: 'enforced',
    reason: null,
    requires: [],
    user_subject: null,
    mission_ref: null,
    submitted_at: Date.now(),
    ...overrides,
  };
}

describe('IntentApprovalService', () => {
  describe('S — submit', () => {
    it('S1: verifies passport then registers intent_claim', async () => {
      const { service, stubReg } = makeService();
      const result = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      expect(result.status).toBe('pending');
      expect(stubReg.calls).toHaveLength(1);
      expect(stubReg.calls[0]!.claimType).toBe('intent_claim');
    });

    it('S2: runs simulation when intentSimulation dep is present', async () => {
      const { service, stubSim } = makeService({ withSimulation: true });
      const result = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      expect(stubSim!.calls).toHaveLength(1);
      expect(result.simulatedClaimId).toBeDefined();
      expect(result.simulation).toBeDefined();
    });

    it('S3: skips simulation when intentSimulation dep is absent', async () => {
      const { service } = makeService({ withSimulation: false });
      const result = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      expect(result.simulatedClaimId).toBeUndefined();
      expect(result.simulation).toBeUndefined();
    });

    it('S4: skips simulation when skipSimulation=true (even with dep wired)', async () => {
      const { service, stubSim } = makeService({ withSimulation: true });
      const result = await service.submit({ passportToken: 'tok', intent: makeIntent(), skipSimulation: true });
      expect(stubSim!.calls).toHaveLength(0);
      expect(result.simulatedClaimId).toBeUndefined();
    });

    it('S5: expiresInSeconds over 24 hours is refused, not cut; one up to 24 hours is kept as named', async () => {
      const { service } = makeService();
      await expect(service.submit({ passportToken: 'tok', intent: makeIntent(), expiresInSeconds: 86_401 })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
      const before = Date.now();
      const result = await service.submit({ passportToken: 'tok', intent: makeIntent(), expiresInSeconds: 86_400 });
      const delta = result.expiresAt.getTime() - before;
      expect(delta).toBeGreaterThan(86_300 * 1000);
      expect(delta).toBeLessThanOrEqual(86_400 * 1000 + 100); // allow some test timing slack
    });

    it('S6: expiresInSeconds <= 0 / undefined falls back to default (900)', async () => {
      const { service } = makeService();
      const before = Date.now();
      const result = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      const delta = result.expiresAt.getTime() - before;
      expect(delta).toBeGreaterThan(850 * 1000);
      expect(delta).toBeLessThanOrEqual(900 * 1000 + 100);
    });

    it('S7: fires onSubmit callback after row inserted', async () => {
      let called: ApprovalRowView | null = null;
      const { service } = makeService({ onSubmit: async (row) => { called = row; } });
      await service.submit({ passportToken: 'tok', intent: makeIntent() });
      // onSubmit is fire-and-forget; give the microtask a tick to flush
      await new Promise((r) => setImmediate(r));
      expect(called).not.toBeNull();
      expect(called!.status).toBe('pending');
    });
  });

  describe('L — listPending', () => {
    it('L1: returns items + total scoped to operator + status=pending', async () => {
      const { service } = makeService();
      await service.submit({ passportToken: 'tok', intent: makeIntent() });
      await service.submit({ passportToken: 'tok', intent: makeIntent({ named_intent: 'stripe:charges:refund' }) });
      const result = await service.listPending('op_test');
      expect(result.total).toBe(2);
      expect(result.items).toHaveLength(2);
      expect(result.items.every((r) => r.status === 'pending')).toBe(true);
    });
  });

  describe('F — findById', () => {
    it('F1: returns row when operator matches', async () => {
      const { service } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      const row = await service.findById(submit.approvalId, 'op_test');
      expect(row).not.toBeNull();
      expect(row!.id).toBe(submit.approvalId);
    });

    it('F2: returns null (not 403) when operator does not match', async () => {
      const { service } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      const row = await service.findById(submit.approvalId, 'op_intruder');
      expect(row).toBeNull();
    });
  });

  describe('A — approve', () => {
    it('A1: transitions pending → approved', async () => {
      const { service, stubRepo } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      const result = await service.approve({ id: submit.approvalId, operatorId: 'op_test' });
      expect(result.status).toBe('approved');
      expect(result.decidedAt).toBeInstanceOf(Date);
      expect(stubRepo.rows.get(submit.approvalId)!['status']).toBe('approved');
    });

    it('A2: approve on already-approved row → ForbiddenError', async () => {
      const { service } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      await service.approve({ id: submit.approvalId, operatorId: 'op_test' });
      await expect(
        service.approve({ id: submit.approvalId, operatorId: 'op_test' }),
      ).rejects.toBeInstanceOf(ForbiddenError);
    });

    it('A3: cross-operator approve → NotFoundError (existence hidden)', async () => {
      const { service } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      await expect(
        service.approve({ id: submit.approvalId, operatorId: 'op_intruder' }),
      ).rejects.toBeInstanceOf(NotFoundError);
    });

    it('A4: missing row → NotFoundError', async () => {
      const { service } = makeService();
      await expect(
        service.approve({ id: 'ia_does_not_exist', operatorId: 'op_test' }),
      ).rejects.toBeInstanceOf(NotFoundError);
    });

    it('A5: CAS lost (concurrent decision) → ForbiddenError', async () => {
      const { service, stubRepo } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      // Simulate concurrent decision by flipping the row status before approve calls markDecided.
      stubRepo.rows.get(submit.approvalId)!['status'] = 'pending';
      stubRepo.forceCasLoss.value = true;
      await expect(
        service.approve({ id: submit.approvalId, operatorId: 'op_test' }),
      ).rejects.toBeInstanceOf(ForbiddenError);
    });
  });

  describe('A — the approval window', () => {
    it('A6: an approval is usable for one hour from the decision, however late in the pending window it came', async () => {
      const { service, stubRepo } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent(), expiresInSeconds: 60 });
      const before = Date.now();
      await service.approve({ id: submit.approvalId, operatorId: 'op_test' });
      const until = (stubRepo.rows.get(submit.approvalId)!['expires_at'] as Date).getTime();
      expect(until - before).toBeGreaterThanOrEqual(INTENT_APPROVAL_USE_WINDOW_SECONDS * 1000 - 1000);
      expect(until - before).toBeLessThanOrEqual(INTENT_APPROVAL_USE_WINDOW_SECONDS * 1000 + 1000);
    });

    it('A7: refuses to approve a pending approval past its time', async () => {
      const { service, stubRepo } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      stubRepo.rows.get(submit.approvalId)!['expires_at'] = new Date(Date.now() - 1000);
      await expect(service.approve({ id: submit.approvalId, operatorId: 'op_test' })).rejects.toThrow(/expired/);
      expect(stubRepo.rows.get(submit.approvalId)!['status']).toBe('pending');
    });
  });

  describe('R — reject', () => {
    it('R1: transitions pending → rejected', async () => {
      const { service, stubRepo } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      const result = await service.reject({ id: submit.approvalId, operatorId: 'op_test' });
      expect(result.status).toBe('rejected');
      expect(stubRepo.rows.get(submit.approvalId)!['status']).toBe('rejected');
    });

    it('R2: fires onReject callback after CAS commits', async () => {
      let called: ApprovalRowView | null = null;
      const { service } = makeService({ onReject: async (row) => { called = row; } });
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      await service.reject({ id: submit.approvalId, operatorId: 'op_test' });
      await new Promise((r) => setImmediate(r));
      expect(called).not.toBeNull();
      expect(called!.status).toBe('rejected');
    });

    it('R3: blockFuture=true persists the flag', async () => {
      const { service, stubRepo } = makeService();
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      await service.reject({ id: submit.approvalId, operatorId: 'op_test', blockFuture: true });
      expect(stubRepo.rows.get(submit.approvalId)!['block_future']).toBe(true);
    });

    it('R4: onReject errors are swallowed (best-effort)', async () => {
      const { service } = makeService({
        onReject: async () => { throw new Error('downstream notification failed'); },
      });
      const submit = await service.submit({ passportToken: 'tok', intent: makeIntent() });
      // Should NOT reject — the decision is committed regardless of side-effect failure.
      const result = await service.reject({ id: submit.approvalId, operatorId: 'op_test' });
      expect(result.status).toBe('rejected');
    });
  });
});
