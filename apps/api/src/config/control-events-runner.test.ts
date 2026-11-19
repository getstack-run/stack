import { afterEach, describe, expect, it, vi } from 'vitest';
import { runControlEventsPass, runControlUpkeep, startControlEventsRunner } from './control-events-runner.js';
import { CONTROL_EVENTS_FAILING_EVENT, notifyEventsFailing } from './wiring/control-socket.js';

afterEach(() => vi.useRealTimers());

const run = { claimed: 0, delivered: 0, retrying: 0, deadLettered: 0, failing: 0, idle: 0 };

describe('the control events runner', () => {
  it('one pass delivers what is due and never throws: a failing pass is logged, not fatal', async () => {
    const deliverDue = vi.fn(async () => run);
    await expect(runControlEventsPass({ controlEvents: { deliverDue } as never })).resolves.toBeUndefined();
    expect(deliverDue).toHaveBeenCalledTimes(1);

    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await expect(runControlEventsPass({ controlEvents: { deliverDue: async () => { throw new Error('db down'); } } as never })).resolves.toBeUndefined();
    expect(error).toHaveBeenCalledWith('[CONTROL_EVENTS] delivery pass failed', expect.anything());
    // A dead-lettered batch or a failing socket is loud.
    error.mockClear();
    await runControlEventsPass({ controlEvents: { deliverDue: async () => ({ ...run, deadLettered: 1, failing: 2 }) } as never });
    expect(error).toHaveBeenCalledWith('[CONTROL_EVENTS] batches dead-lettered and sockets failing:', 1, 2);
    error.mockRestore();
  });

  it('ticks every two seconds without overlapping, trims the decision log hourly, and stops when told', async () => {
    vi.useFakeTimers();
    let release: () => void = () => undefined;
    const deliverDue = vi.fn(() => new Promise<typeof run>((resolve) => { release = () => resolve(run); }));
    const pruneDecisions = vi.fn(async () => ({ requestsCleared: 0, rowsDeleted: 0 }));
    const sweep = vi.fn(async () => ({ expired: 0, folded: 0 }));
    const stop = startControlEventsRunner({ controlEvents: { deliverDue, sweep } as never, controlSocketRepo: { pruneDecisions } as never });

    await vi.advanceTimersByTimeAsync(2_000);
    expect(deliverDue).toHaveBeenCalledTimes(1);
    // The pass is still running: the next tick does not start another.
    await vi.advanceTimersByTimeAsync(4_000);
    expect(deliverDue).toHaveBeenCalledTimes(1);
    release();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(pruneDecisions).toHaveBeenCalledWith(30, 90);
    expect(pruneDecisions).toHaveBeenCalledTimes(1);
    // Retention of the events outbox runs on the same hourly beat, for every customer.
    expect(sweep).toHaveBeenCalledTimes(1);
    expect(deliverDue).toHaveBeenCalledTimes(2);

    stop();
    release();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(deliverDue).toHaveBeenCalledTimes(2);
  });
});

describe('the hourly upkeep', () => {
  it('sweeps the events outbox and trims the decision log, and one failing does not stop the other', async () => {
    const sweep = vi.fn(async () => ({ expired: 2, folded: 1 }));
    const pruneDecisions = vi.fn(async () => ({ requestsCleared: 0, rowsDeleted: 0 }));
    await runControlUpkeep({ controlEvents: { sweep } as never, controlSocketRepo: { pruneDecisions } as never });
    expect(sweep).toHaveBeenCalledTimes(1);
    expect(pruneDecisions).toHaveBeenCalledWith(30, 90);

    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await runControlUpkeep({
      controlEvents: { sweep: async () => { throw new Error('db down'); } } as never,
      controlSocketRepo: { pruneDecisions } as never,
    });
    expect(error).toHaveBeenCalledWith('[CONTROL_EVENTS] outbox sweep failed', expect.anything());
    expect(pruneDecisions).toHaveBeenCalledTimes(2);
    await runControlUpkeep({
      controlEvents: { sweep } as never,
      controlSocketRepo: { pruneDecisions: async () => { throw new Error('db down'); } } as never,
    });
    expect(error).toHaveBeenCalledWith('[CONTROL] decision log trim failed', expect.anything());
    error.mockRestore();
  });
});

describe('telling the owner delivery paused', () => {
  it('publishes one warning event to the owner\'s own notification rules, naming no address and no secret', async () => {
    const publishEvent = vi.fn(async () => ({ dispatched: 1 }));
    await notifyEventsFailing({ publishEvent }, 'op_1');
    expect(publishEvent).toHaveBeenCalledTimes(1);
    const event = (publishEvent.mock.calls[0] as unknown as [{ operatorId: string; eventType: string; severity: string; payload: Record<string, unknown> }])[0];
    expect(event).toMatchObject({ operatorId: 'op_1', eventType: CONTROL_EVENTS_FAILING_EVENT, severity: 'warning' });
    expect(CONTROL_EVENTS_FAILING_EVENT).toBe('control.events_failing');
    expect(String(event.payload['message'])).toMatch(/verify it again/);
    expect(JSON.stringify(event)).not.toMatch(/https?:|whsec_/);
  });
});
