import { describe, expect, it, vi } from 'vitest';
import { maybeRunBehavioralGenomeRollup } from './behavioral-genome-rollup.js';
import { ContractPlanEntitlements } from './entitlements/entitlements.js';
import type { BehavioralGenomeService } from './behavioral-genome-service.js';

/**
 * The behavioural baseline is a controls feature: the daily rollup signs a genome only for the passports of an
 * account with controls on. On an install every active account has controls (the contract plan), with no
 * subscription and no licence key.
 */

const ACTIVITY = [
  { passport_jti: 'pas_a', operator_id: 'op_on' },
  { passport_jti: 'pas_b', operator_id: 'op_off' },
];

/** A database whose two reads answer the operators with activity, then their passports (filtered by the ids asked). */
function stubDb() {
  const reads: unknown[] = [];
  const db = {
    selectDistinct: (columns: Record<string, unknown>) => ({
      from: () => ({
        where: (condition: unknown) => {
          reads.push(condition);
          if (!('passport_jti' in columns)) {
            const operatorIds = [...new Set(ACTIVITY.map((row) => row.operator_id))];
            return Promise.resolve(operatorIds.map((operator_id) => ({ operator_id })));
          }
          return { limit: async () => ACTIVITY };
        },
      }),
    }),
  };
  return { db: db as never, reads };
}

function redis() {
  return { set: vi.fn(async () => 'OK') } as never;
}

function genome() {
  const emitForWindow = vi.fn(async (_operatorId: string, _passportJti: string) => ({ emitted: true, deduped: false }));
  return { service: { emitForWindow } as unknown as BehavioralGenomeService, emitForWindow };
}

describe('the behavioural baseline rollup', () => {
  it('asks once per operator with activity, and signs nothing when no account has controls', async () => {
    const { db } = stubDb();
    const { service, emitForWindow } = genome();
    const eligible = vi.fn(async (_operatorId: string) => false);
    await maybeRunBehavioralGenomeRollup(service, db, redis(), { eligible });
    expect(eligible.mock.calls.map(([id]) => id).sort()).toEqual(['op_off', 'op_on']);
    expect(emitForWindow).not.toHaveBeenCalled();
  });

  it('an account whose controls cannot be read is skipped, never graded on a guess', async () => {
    const { db } = stubDb();
    const { service, emitForWindow } = genome();
    await maybeRunBehavioralGenomeRollup(service, db, redis(), {
      eligible: async (operatorId) => {
        if (operatorId === 'op_off') throw new Error('billing account unavailable');
        return false;
      },
    });
    expect(emitForWindow).not.toHaveBeenCalled();
  });

  it('on an install every active account is eligible, with no subscription and no licence key', async () => {
    const { db } = stubDb();
    const { service, emitForWindow } = genome();
    const operators = {
      findById: vi.fn(async (id: string) => ({
        id, status: 'active', tier: 'enterprise', parent_operator_id: null, is_partner: false,
        controls_status: 'none', platform_status: 'none', suspended_reason: null, deleted_at: null,
      })),
    };
    const install = new ContractPlanEntitlements(operators as never);
    await maybeRunBehavioralGenomeRollup(service, db, redis(), { eligible: (id) => install.controlsEnabled(id) });
    expect(emitForWindow.mock.calls.map(([operatorId]) => operatorId).sort()).toEqual(['op_off', 'op_on']);
  });
});
