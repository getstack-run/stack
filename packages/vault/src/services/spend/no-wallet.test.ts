import { describe, expect, it, vi } from 'vitest';
import { SpendRefusedError } from '@stack/shared';
import { LlmUsageRepository } from '../../repositories/llm-usage-repo.js';
import type { InsertLlmUsageInput } from '../../repositories/llm-usage/types.js';
import { LlmUsageService } from '../llm-usage-service.js';
import { ProxyAccountingReconciler } from '../proxy-accounting-reconciler.js';
import { ProxyOperationService } from '../proxy-operation-service.js';
import {
  NO_MISSION_SPEND,
  NO_PROXY_HOLDS,
  type ProxyHoldLedger,
} from './spend-ledger.js';

// An install has no wallet. These tests give the engine what an install has (no ledger for the usage service, the
// null ledger that refuses every method for the proxy), and show that what an install does never reaches one (a call
// on the customer's own key, a proxy call) while what would spend STACK's money fails closed.

/** The null ledger, remembering every method that was touched, so a path that merely names one is caught too. */
function watched<T extends object>(target: T): { ledger: T; touched: string[] } {
  const touched: string[] = [];
  const ledger = new Proxy(target, {
    get(object, property, receiver) {
      if (typeof property === 'string') touched.push(property);
      return Reflect.get(object, property, receiver);
    },
  });
  return { ledger, touched };
}

function usageService() {
  const repo = { insert: vi.fn(async (_input: InsertLlmUsageInput) => undefined), list: vi.fn(), summary: vi.fn() };
  const service = new LlmUsageService({
    repo: repo as never,
    securityEvent: { record: vi.fn(async () => undefined) } as never,
    openRouterPricing: { get: vi.fn(async () => ({ input_cents_per_1m: 100, output_cents_per_1m: 200 })) } as never,
  });
  return { service, repo };
}

const OWN_KEY_CALL = {
  operatorId: 'op_install',
  provider: 'anthropic' as const,
  model: 'claude-opus-4-7',
  requestBytes: 10_000,
  maxOutputTokens: 5_000,
  completionCount: 1,
  imageCount: 0,
};

describe('a model call on the customer\'s own key, on an install with no wallet', () => {
  it('is authorized, recorded and released without ever reaching the spend ledger', async () => {
    const { service, repo } = usageService();

    const authorization = await service.authorizeGateway(OWN_KEY_CALL);
    expect(authorization).toEqual(expect.objectContaining({ bounded: true, heldCents: 0 }));
    expect(authorization).not.toHaveProperty('walletHoldId');

    const recorded = await service.record({
      operatorId: 'op_install',
      agentId: 'agt_install',
      passportJti: 'pas_install',
      missionId: null,
      provider: 'anthropic',
      model: 'claude-opus-4-7',
      usage: { prompt_tokens: 1_000, completion_tokens: 200, total_tokens: 1_200 },
      streaming: false,
      authorization,
    });
    expect(recorded).not.toHaveProperty('walletDebited');
    expect(repo.insert).toHaveBeenCalledWith(expect.objectContaining({
      wallet_hold_id: null,
      wallet_fee_kind: null,
      stack_fee_payer: 'none',
    }));

    await expect(service.releaseGatewayAuthorization('op_install', authorization)).resolves.toBeUndefined();
  });

  it('a streamed call is the same: nothing is held, so nothing is captured or released', async () => {
    const { service, repo } = usageService();
    const authorization = await service.authorizeGateway(OWN_KEY_CALL);
    await service.record({
      operatorId: 'op_install',
      agentId: 'agt_install',
      passportJti: 'pas_install',
      missionId: 'ms_install',
      provider: 'anthropic',
      model: 'claude-opus-4-7',
      usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
      streaming: true,
      authorization,
    });
    expect(repo.insert).toHaveBeenCalledOnce();
  });

  it('a call that would run on a key of the deployment\'s own is not something the engine can make: it has no way to hold one', () => {
    const { service } = usageService();
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(service)).filter((name) => name !== 'constructor');
    expect(methods.sort()).toEqual([
      'assertGatewayInput', 'authorizeGateway', 'list', 'lookup', 'record', 'recordPricingMiss', 'releaseGatewayAuthorization', 'summary',
    ]);
  });
});

describe('a usage row on an install\'s own ledger', () => {
  function repoOver(inserted: boolean) {
    const returning = vi.fn(async () => (inserted ? [{ id: 'llm_row' }] : []));
    const tx = { insert: () => ({ values: () => ({ onConflictDoNothing: () => ({ returning }) }) }) };
    const db = { transaction: async (work: (tx: unknown) => Promise<void>) => work(tx) };
    return new LlmUsageRepository(db as never);
  }
  const ROW: InsertLlmUsageInput = {
    id: 'llm_row',
    operator_id: 'op_install',
    agent_id: 'agt_install',
    passport_jti: 'pas_install',
    mission_id: null,
    provider: 'anthropic',
    model: 'claude-opus-4-7',
    prompt_tokens: 1,
    completion_tokens: 1,
    total_tokens: 2,
    provider_cost_cents: 0,
    markup_cents: 0,
    total_cost_cents: 0,
    provider_cost_microcents: 0,
    markup_microcents: 0,
    total_cost_microcents: 0,
    cost_basis: 'catalog',
    cached_prompt_tokens: null,
    wallet_debited: false,
    surface: 'gateway',
    provider_payer: 'customer_provider',
    stack_fee_payer: 'none',
    wallet_hold_id: null,
    streaming: false,
  };

  it('is written when it owes no wallet fee', async () => {
    await expect(repoOver(true).insert(ROW)).resolves.toBeUndefined();
  });

  it('is refused, and rolled back, when it claims a wallet fee: there is no wallet to credit', async () => {
    const owing = { ...ROW, wallet_fee_kind: 'gateway', wallet_fee_microcents: 5 };
    await expect(repoOver(true).insert(owing)).rejects.toMatchObject({ code: 'NO_WALLET_ON_INSTALL' });
  });
});

describe('a proxy call on an install with no wallet', () => {
  const EVALUATION = {
    operatorId: 'op_install',
    operationKey: 'k'.repeat(43),
    evaluationCommitmentHash: `sha256:${'a'.repeat(64)}`,
    accountingPeriod: '2026-10',
    verdict: 'admitted' as const,
    allowanceLimit: null,
    overageUnits10000thCent: 0,
  };

  function serviceWith(wholeCentsToReserve: number, holds?: ProxyHoldLedger) {
    const repository = {
      recordAccountingReceipt: vi.fn(async () => ({
        state: 'created',
        wholeCentsToReserve,
        receipt: { period_sequence: 1 },
      })),
      transaction: async (work: (tx: unknown) => Promise<unknown>) => work({}),
    };
    return new ProxyOperationService(repository as never, {} as never, holds);
  }

  it('records its receipt without reaching the hold ledger: an evaluation never charges', async () => {
    const { ledger, touched } = watched(NO_PROXY_HOLDS);
    await expect(serviceWith(0, ledger).recordEvaluation(EVALUATION)).resolves.toMatchObject({ state: 'created' });
    expect(touched).toEqual([]);
  });

  it('a service built with no ledger at all has the null one, so a charge that does appear is refused', async () => {
    const refusal = await serviceWith(1).recordEvaluation(EVALUATION).catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(SpendRefusedError);
    expect(refusal).toMatchObject({ code: 'NO_WALLET_ON_INSTALL' });
  });

  it('the worker\'s reconciler finds nothing to settle: the null ledger lists no boundary and the tick settles none', async () => {
    const proxyRepository = {
      listAccountingProjectionKeys: vi.fn(async () => []),
      commitAccountingThroughSequence: vi.fn(),
      getAccountingProjection: vi.fn(),
    };
    const reconciler = new ProxyAccountingReconciler(proxyRepository as never, NO_PROXY_HOLDS, { set: vi.fn() });
    await expect(reconciler.tick()).resolves.toEqual({ settlements: 0, projectedPeriods: 0, projectionFailures: 0 });
    expect(proxyRepository.commitAccountingThroughSequence).not.toHaveBeenCalled();
  });
});

describe('a Mission on an install with no wallet', () => {
  it('has spent no credit and is never an account\'s Mission, so only its model usage counts against the cap', async () => {
    expect(await NO_MISSION_SPEND.spentCents('op_install', 'ms_install')).toBe(0);
    expect(await NO_MISSION_SPEND.governedByAccountBudget('ms_install')).toBe(false);
  });
});
