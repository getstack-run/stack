import { describe, expect, it, vi } from 'vitest';
import { EngineRegistries } from '../config/registries.js';
import { announceDecision, decisionAnnouncer } from './decision-reached.js';

const event = { operatorId: 'op_a', agentId: 'agt_a', kind: 'dropoff', itemId: 'dof_1', result: 'collected' };

describe('announcing the end of a pending item', () => {
  it('tells every hook the deployment registered, in order', async () => {
    const registries = new EngineRegistries();
    const seen: string[] = [];
    registries.decisionReached.register(async () => { seen.push('first'); });
    registries.decisionReached.register(async (e) => { seen.push(`second:${e.result}`); });
    await announceDecision(registries, event);
    expect(seen).toEqual(['first', 'second:collected']);
  });

  it('never fails the decision for a hook that throws, and still runs the rest', async () => {
    const registries = new EngineRegistries();
    const after = vi.fn(async () => {});
    registries.decisionReached.register(async () => { throw new Error('wakes are down'); });
    registries.decisionReached.register(after);
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await expect(announceDecision(registries, event)).resolves.toBeUndefined();
    expect(after).toHaveBeenCalledWith(event);
    log.mockRestore();
  });

  it('does nothing in an install with no hook, and reads the registry each time as one callback', async () => {
    const registries = new EngineRegistries();
    const announce = decisionAnnouncer(registries);
    await expect(announce(event)).resolves.toBeUndefined();
    const hook = vi.fn(async () => {});
    registries.decisionReached.register(hook);
    await announce(event);
    expect(hook).toHaveBeenCalledTimes(1);
  });
});
