import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { ContractPlanEntitlements } from '@stack/vault';
import { NO_METER, actionHandedBack, isSystemOperator, type ActionMeter } from '../lib/action-meter.js';
import { actionPoolSnapshot } from '../lib/action-pool.js';
import { enforceOverage, meterAction, meterPassportUpkeep, peekOverage, recordCheck, registerMeterRefund } from './meter.js';

/**
 * The meter facade the engine's routes call. It forwards to the deployment's
 * `actionMeter` and knows nothing of what counting means, so an install with no
 * plans (`NO_METER`) counts nothing, refuses nothing and is never charged.
 */

function recordingMeter(): { meter: ActionMeter; calls: string[] } {
  const calls: string[] = [];
  const meter: ActionMeter = {
    meterAction: vi.fn(async () => void calls.push('meterAction')),
    enforce: vi.fn(async () => void calls.push('enforce')),
    peek: vi.fn(async () => {
      calls.push('peek');
      return { used: 3, cap: 10, walletBalanceCents: 0, overagePriceCents: 0, wouldDeny: false };
    }),
    recordCheck: vi.fn(async () => {
      calls.push('recordCheck');
      return { checksThisMonth: 1, centsCharged: 0 };
    }),
    recordDecision: vi.fn(async () => {
      calls.push('recordDecision');
      return { checksThisMonth: 1, centsCharged: 0 };
    }),
    passportUpkeep: vi.fn(async () => void calls.push('passportUpkeep')),
    pool: vi.fn(async () => ({ limit: 10, used: 3 })),
  };
  return { meter, calls };
}

describe('the meter facade', () => {
  it('forwards each call to the deployment\'s meter with the arguments it was given', async () => {
    const { meter, calls } = recordingMeter();
    const services = { actionMeter: meter };
    const request = { operatorId: 'op_1', agentId: 'agt_1' } as never;
    await meterAction(services, request, undefined, 'key_1');
    await enforceOverage(services, 'op_1', 'action');
    await peekOverage(services, 'op_1', 'action');
    await recordCheck(services, 'op_1', 2);
    await meterPassportUpkeep(services, request, 'agt_1');
    expect(calls).toEqual(['meterAction', 'enforce', 'peek', 'recordCheck', 'passportUpkeep']);
    expect(meter.meterAction).toHaveBeenCalledWith(request, undefined, 'key_1', 'agt_1', undefined);
    expect(meter.recordCheck).toHaveBeenCalledWith('op_1', 2);
  });

  it('counts nothing, refuses nothing and charges nothing on an install with no meter', async () => {
    const services = { actionMeter: NO_METER };
    await expect(meterAction(services, { operatorId: 'op_1' } as never)).resolves.toBeUndefined();
    await expect(enforceOverage(services, 'op_1', 'action')).resolves.toBeUndefined();
    await expect(peekOverage(services, 'op_1', 'action')).resolves.toEqual({
      used: 0, cap: Infinity, walletBalanceCents: 0, overagePriceCents: 0, wouldDeny: false,
    });
    await expect(recordCheck(services, 'op_1', 5)).resolves.toEqual({ checksThisMonth: 0, centsCharged: 0 });
  });
});

describe('the action pool readout', () => {
  const entitlements = new ContractPlanEntitlements({
    findById: async (id: string) => ({ id, status: 'active', parent_operator_id: null }) as never,
  });

  it('reads the plan from the entitlements and the count from the meter that wrote it', async () => {
    const { meter } = recordingMeter();
    const now = new Date('2026-10-15T12:00:00Z');
    await expect(actionPoolSnapshot({ actionMeter: meter, entitlements }, 'op_1', now)).resolves.toEqual({
      plan: 'contract', limit: 10, used: 3, remaining: 7, period: '2026-10',
    });
  });

  it('shows no limit and nothing used when no meter counts', async () => {
    const now = new Date('2026-10-15T12:00:00Z');
    await expect(actionPoolSnapshot({ actionMeter: NO_METER, entitlements }, 'op_1', now)).resolves.toEqual({
      plan: 'contract', limit: null, used: 0, remaining: null, period: '2026-10',
    });
  });
});

describe('the refund rule', () => {
  it('hands back client mistakes and STACK-side outages, and keeps policy denials and ordinary failures counted', () => {
    for (const [status, stackSide, refundAction, handedBack] of [
      [200, false, false, false],
      [400, false, false, true],
      [404, false, false, true],
      [429, false, false, true],
      [402, false, false, false],
      [403, false, false, false],
      [500, false, false, false],
      [503, false, false, false],
      [503, true, false, true],
      // A refused action never ran, whatever the status.
      [403, false, true, true],
      [500, false, true, true],
      [200, false, true, false],
    ] as const) {
      expect(actionHandedBack(status, stackSide, refundAction), `${status} ${stackSide} ${refundAction}`).toBe(handedBack);
    }
  });

  it('runs a request\'s rollback when the response ends, by that rule, and only once', async () => {
    const app = Fastify();
    registerMeterRefund(app);
    const rollback = vi.fn(async () => undefined);
    app.post('/bad', async (request, reply) => {
      request.meterRollback = rollback;
      return reply.status(400).send({});
    });
    app.post('/denied', async (request, reply) => {
      request.meterRollback = rollback;
      return reply.status(403).send({});
    });
    app.post('/refused', async (request, reply) => {
      request.meterRollback = rollback;
      request.refundAction = true;
      return reply.status(403).send({});
    });
    app.post('/uncounted', async (_request, reply) => reply.status(400).send({}));
    try {
      await app.inject({ method: 'POST', url: '/denied', payload: {} });
      expect(rollback).not.toHaveBeenCalled();
      await app.inject({ method: 'POST', url: '/bad', payload: {} });
      await app.inject({ method: 'POST', url: '/refused', payload: {} });
      await app.inject({ method: 'POST', url: '/uncounted', payload: {} });
      await vi.waitFor(() => expect(rollback).toHaveBeenCalledTimes(2));
    } finally {
      await app.close();
    }
  });
});

describe('the system operator', () => {
  it('is STACK\'s own operator and nobody else', () => {
    expect(isSystemOperator('op_stack_system')).toBe(true);
    expect(isSystemOperator('op_a_real_customer')).toBe(false);
    // Any other id is a customer to the engine; a deployment's own exempt operators are its meter's to name.
    expect(isSystemOperator('op_a_demo_account')).toBe(false);
  });

  it('follows the configured system operator id', () => {
    const before = process.env['STACK_SYSTEM_OPERATOR_ID'];
    process.env['STACK_SYSTEM_OPERATOR_ID'] = 'op_custom_system';
    try {
      expect(isSystemOperator('op_custom_system')).toBe(true);
      expect(isSystemOperator('op_stack_system')).toBe(true);
    } finally {
      if (before === undefined) delete process.env['STACK_SYSTEM_OPERATOR_ID'];
      else process.env['STACK_SYSTEM_OPERATOR_ID'] = before;
    }
  });
});
