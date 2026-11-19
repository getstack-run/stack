import { describe, expect, it, vi } from 'vitest';
import { agentDetectorMode } from './agent-detector-mode.js';

const OFF = { mode: 'standard', skipL3: true, withhold: { warning: false, critical: false } };

function services(over: { account: boolean; controls: boolean }) {
  return {
    accountDetection: {
      forAgent: vi.fn(async () => (over.account ? (over.controls ? { mode: 'enforced', skipL3: false, withhold: { warning: true, critical: true } } : OFF) : null)),
      forOperator: vi.fn(async () => OFF),
    },
    entitlements: { controlsEnabled: vi.fn(async () => over.controls) },
  };
}

describe('agentDetectorMode', () => {
  it('an agent outside an account keeps its Passport mode while its owner has controls', async () => {
    expect(await agentDetectorMode(services({ account: false, controls: true }) as never, 'op', 'agt', 'enforced', 'proxy.call')).toEqual({ mode: 'enforced' });
  });

  it('an agent outside an account without controls is flagged and delivered, like an account agent: no enforced mode, no classifier', async () => {
    const outside = await agentDetectorMode(services({ account: false, controls: false }) as never, 'op', 'agt', 'enforced', 'model.call');
    const inside = await agentDetectorMode(services({ account: true, controls: false }) as never, 'op', 'agt', 'enforced', 'model.call');
    expect(outside).toEqual({ mode: 'standard', skipL3: true });
    expect(outside).toEqual(inside);
  });

  it('fails closed when the controls of an agent outside an account cannot be read', async () => {
    const s = services({ account: false, controls: true });
    s.entitlements.controlsEnabled.mockRejectedValue(new Error('unreadable'));
    await expect(agentDetectorMode(s as never, 'op', 'agt', 'enforced')).rejects.toThrow('unreadable');
  });
});
