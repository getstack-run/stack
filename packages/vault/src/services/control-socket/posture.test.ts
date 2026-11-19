import { describe, expect, it, vi } from 'vitest';
import type { ControlActionType } from '@stack/shared';
import { ControlPosture } from './posture.js';
import type { ControlSocketRuntime } from './control-socket-service.js';

function socket(over: Partial<ControlSocketRuntime> = {}): ControlSocketRuntime {
  return { socketId: 'csk_1', modeSetting: 'auto', decisionUrl: null, decisionStatus: 'unverified', timeoutMs: 1_500, onUnavailable: 'refuse', checkedTypes: null, ...over };
}

function posture(runtime: ControlSocketRuntime, controls: boolean | Error = true) {
  const controlsEnabled = vi.fn(async () => {
    if (controls instanceof Error) throw controls;
    return controls;
  });
  return { posture: new ControlPosture({ sockets: { runtime: async () => runtime }, controls: { controlsEnabled } }), controlsEnabled };
}

const only = (...kinds: ControlActionType[]) => new Set<ControlActionType>(kinds);

describe('which hosted checks apply to a kind of action', () => {
  it('controls on, every kind checked: hosted, and everything applies', async () => {
    const { posture: p } = posture(socket());
    expect(await p.decision('op_1', 'model.call')).toMatchObject({ decider: 'hosted', checked: true });
    expect(await p.hostedApplies('op_1', 'proxy.call')).toBe(true);
    expect(await p.hostedApplies('op_1', null)).toBe(true);
    expect(await p.budgetEnforced('op_1', 'card.checkout')).toBe(true);
  });

  it('a kind that is not checked is not asked and runs no hosted check, limit or budget refusal', async () => {
    const { posture: p } = posture(socket({ checkedTypes: only('email.send') }));
    expect(await p.decision('op_1', 'model.call')).toMatchObject({ decider: 'hosted', checked: false });
    expect(await p.decision('op_1', 'email.send')).toMatchObject({ decider: 'hosted', checked: true });
    expect(await p.hostedApplies('op_1', 'model.call')).toBe(false);
    expect(await p.hostedApplies('op_1', 'email.send')).toBe(true);
    // Content that is no action of the agent's own follows the controls alone.
    expect(await p.hostedApplies('op_1', null)).toBe(true);
    expect(await p.budgetEnforced('op_1', 'model.call')).toBe(false);
    expect(await p.budgetEnforced('op_1', 'email.send')).toBe(true);
  });

  it('controls off: nobody is asked, nothing hosted runs, and a budget set before a downgrade keeps enforcing', async () => {
    const { posture: p } = posture(socket(), false);
    expect(await p.decision('op_1', 'model.call')).toMatchObject({ decider: 'none', checked: false });
    expect(await p.hostedApplies('op_1', 'model.call')).toBe(false);
    expect(await p.hostedApplies('op_1', null)).toBe(false);
    expect(await p.budgetEnforced('op_1', 'model.call')).toBe(true);
  });

  it('having chosen none switches off every hosted check, but never a budget the customer set', async () => {
    const { posture: p } = posture(socket({ modeSetting: 'none' }));
    expect(await p.decision('op_1', 'model.call')).toMatchObject({ decider: 'none', checked: false });
    expect(await p.hostedApplies('op_1', 'model.call')).toBe(false);
    expect(await p.hostedApplies('op_1', null)).toBe(false);
    // Starting a controls subscription later must not quietly stop an existing budget.
    expect(await p.budgetEnforced('op_1', 'model.call')).toBe(true);
    expect(await p.budgetEnforced('op_1', null)).toBe(true);
    const off = posture(socket({ modeSetting: 'none' }), false);
    expect(await off.posture.budgetEnforced('op_1', 'model.call')).toBe(true);
  });

  it('a customer on their own server is decided by it and never waits on the controls read to be asked', async () => {
    const { posture: p, controlsEnabled } = posture(socket({ modeSetting: 'remote', decisionStatus: 'enforcing', checkedTypes: only('email.send') }));
    expect(await p.decision('op_1', 'email.send')).toMatchObject({ decider: 'remote', checked: true });
    expect(await p.decision('op_1', 'model.call')).toMatchObject({ decider: 'remote', checked: false });
    expect(controlsEnabled).not.toHaveBeenCalled();
    // The hosted inline checks still follow the owner's controls and the same kind choice.
    expect(await p.hostedApplies('op_1', 'email.send')).toBe(true);
    expect(await p.hostedApplies('op_1', 'model.call')).toBe(false);
  });

  it('an unreadable controls status throws, so the call fails closed', async () => {
    const { posture: p } = posture(socket(), new Error('billing down'));
    await expect(p.decision('op_1', 'model.call')).rejects.toThrow('billing down');
    await expect(p.hostedApplies('op_1', 'model.call')).rejects.toThrow('billing down');
    await expect(p.budgetEnforced('op_1', 'model.call')).rejects.toThrow('billing down');
  });
});
