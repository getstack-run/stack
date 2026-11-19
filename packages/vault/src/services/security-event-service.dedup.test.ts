import { describe, expect, it, vi } from 'vitest';
import { SecurityEventService } from './security-event-service.js';

/**
 * the dedup gate on SecurityEventService.record. The gate
 * runs FIRST: a suppressed repeat produces no claim, no row, no
 * auto-block check, no notification (the incident emailed the
 * operator once per event, 613 times).
 *
 *   D1 — first occurrence records normally (SETNX wins).
 *   D2 — repeat within the window is fully suppressed (repo untouched).
 *   D3 — no dedupKey → no gate, every occurrence records.
 *   D4 — Redis outage fails OPEN: record rather than lose the signal.
 *   D5 — the gate key is operator-scoped.
 */

function makeService(setResult: () => Promise<unknown>) {
  const repo = {
    create: vi.fn(async (row: Record<string, unknown>) => ({ ...row })),
  };
  const agentRepo = { findById: vi.fn(async () => null), update: vi.fn() };
  const store = { set: vi.fn(setResult) };
  const svc = new SecurityEventService(repo as never, agentRepo as never);
  svc.setDedupStore(store);
  return { svc, repo, store };
}

const BASE = {
  operatorId: 'op_x',
  agentId: 'agt_x',
  signalType: 'credential_burst' as const,
  severity: 'warning' as const,
  message: 'LLM gateway markup debit failed',
};

describe('SecurityEventService dedup', () => {
  it('D1 first occurrence (SETNX wins) records normally', async () => {
    const { svc, repo, store } = makeService(async () => 'OK');
    const event = await svc.record({ ...BASE, dedupKey: 'k1' });
    expect(store.set).toHaveBeenCalledWith(
      'stack:sec_event_dedup:op_x:k1',
      '1',
      'EX',
      3600,
      'NX',
    );
    expect(repo.create).toHaveBeenCalledTimes(1);
    expect(event).not.toBeNull();
  });

  it('D2 repeat within the window is fully suppressed', async () => {
    const { svc, repo } = makeService(async () => null); // key exists
    const event = await svc.record({ ...BASE, dedupKey: 'k1' });
    expect(repo.create).not.toHaveBeenCalled();
    expect(event).toBeNull();
  });

  it('D3 no dedupKey → no gate, records every time', async () => {
    const { svc, repo, store } = makeService(async () => null);
    await svc.record({ ...BASE });
    await svc.record({ ...BASE });
    expect(store.set).not.toHaveBeenCalled();
    expect(repo.create).toHaveBeenCalledTimes(2);
  });

  it('D4 Redis outage fails OPEN (records rather than losing the signal)', async () => {
    const { svc, repo } = makeService(async () => {
      throw new Error('redis down');
    });
    const event = await svc.record({ ...BASE, dedupKey: 'k1' });
    expect(repo.create).toHaveBeenCalledTimes(1);
    expect(event).not.toBeNull();
  });

  it('D5 custom window + operator scoping in the key', async () => {
    const { svc, store } = makeService(async () => 'OK');
    await svc.record({
      ...BASE,
      operatorId: 'op_other',
      dedupKey: 'llm_markup_insufficient:agt_x',
      dedupWindowSeconds: 600,
    });
    expect(store.set).toHaveBeenCalledWith(
      'stack:sec_event_dedup:op_other:llm_markup_insufficient:agt_x',
      '1',
      'EX',
      600,
      'NX',
    );
  });
});

/**
 * counting and dismissal on the same gate.
 *
 *   C1 — the first occurrence remembers its event id on the gate key, so repeats can be counted on it.
 *   C2 — a repeat raises the count on that event and still creates no row.
 *   C3 — a repeat of a critical is counted too, and the agent's own block setting still applies to it.
 *   C4 — a store with no `get` still suppresses repeats (it just cannot count them).
 *   C5 — a dismissal hides new warnings of the same type for that agent, never a critical.
 *   C6 — dismissing an agent's open warnings resolves them and starts the window per signal type.
 */
function makeCountingService(options: { gateHeld?: boolean; gateValue?: string | null; dismissed?: boolean } = {}) {
  const repo = {
    create: vi.fn(async (row: Record<string, unknown>) => ({ ...row, id: row['id'] as string, created_at: new Date() })),
    addRepeat: vi.fn(async () => undefined),
    resolveOpenForAgent: vi.fn(async () => [
      { id: 'sev_1', signal_type: 'credential_outside_scope', severity: 'warning', mission_id: null },
      { id: 'sev_2', signal_type: 'credential_outside_scope', severity: 'warning', mission_id: null },
      { id: 'sev_3', signal_type: 'undeclared_target', severity: 'warning', mission_id: null },
    ]),
  };
  const agentRepo = { findById: vi.fn(async () => ({ id: 'agt_x', on_critical: 'block', eval_traffic: false })), update: vi.fn() };
  const kv = new Map<string, string>();
  const store = {
    set: vi.fn(async (key: string, value: string, _ex: 'EX', _seconds: number, nx?: 'NX') => {
      if (nx === 'NX') {
        if (options.gateHeld) return null;
        if (kv.has(key)) return null;
      }
      kv.set(key, value);
      return 'OK';
    }),
    get: vi.fn(async (key: string) => {
      if (key.includes('sec_event_dismissed')) return options.dismissed ? '1' : null;
      return options.gateHeld ? (options.gateValue ?? null) : (kv.get(key) ?? null);
    }),
  };
  const blocker = { blockAgent: vi.fn(async () => undefined) };
  const svc = new SecurityEventService(repo as never, agentRepo as never);
  svc.setDedupStore(store);
  svc.setAgentBlocker(blocker as never);
  return { svc, repo, store, blocker, kv };
}

describe('SecurityEventService counting and dismissal', () => {
  it('C1 the first occurrence remembers its event id on the gate key', async () => {
    const { svc, store } = makeCountingService();
    const event = await svc.record({ ...BASE, dedupKey: 'k1' });
    expect(store.set).toHaveBeenLastCalledWith('stack:sec_event_dedup:op_x:k1', event!.id, 'EX', 3600);
  });

  it('C2 a repeat raises the count on the first event and creates no row', async () => {
    const { svc, repo } = makeCountingService({ gateHeld: true, gateValue: 'sev_first' });
    expect(await svc.record({ ...BASE, dedupKey: 'k1' })).toBeNull();
    expect(repo.create).not.toHaveBeenCalled();
    expect(repo.addRepeat).toHaveBeenCalledWith('sev_first', 'op_x');
  });

  it('C2b two identical signals in a row make one event with a count', async () => {
    const { svc, repo } = makeCountingService();
    const first = await svc.record({ ...BASE, dedupKey: 'k1' });
    const second = await svc.record({ ...BASE, dedupKey: 'k1' });
    expect(first).not.toBeNull();
    expect(second).toBeNull();
    expect(repo.create).toHaveBeenCalledTimes(1);
    expect(repo.addRepeat).toHaveBeenCalledWith(first!.id, 'op_x');
  });

  it('C3 a repeated critical is counted and the agent block setting still applies', async () => {
    const { svc, repo, blocker } = makeCountingService({ gateHeld: true, gateValue: 'sev_first' });
    await svc.record({ ...BASE, severity: 'critical', dedupKey: 'k1' });
    expect(repo.addRepeat).toHaveBeenCalledTimes(1);
    expect(repo.create).not.toHaveBeenCalled();
    expect(blocker.blockAgent).toHaveBeenCalledTimes(1);
  });

  it('C4 a store without get still suppresses repeats', async () => {
    const repo = { create: vi.fn(), addRepeat: vi.fn() };
    const svc = new SecurityEventService(repo as never, { findById: vi.fn() } as never);
    svc.setDedupStore({ set: vi.fn(async () => null) });
    expect(await svc.record({ ...BASE, dedupKey: 'k1' })).toBeNull();
    expect(repo.create).not.toHaveBeenCalled();
    expect(repo.addRepeat).not.toHaveBeenCalled();
  });

  it('C5 a dismissal hides new warnings of the same type for that agent, never a critical', async () => {
    const { svc, repo } = makeCountingService({ dismissed: true });
    expect(await svc.record({ ...BASE })).toBeNull();
    expect(repo.create).not.toHaveBeenCalled();
    const critical = await svc.record({ ...BASE, severity: 'critical' });
    expect(critical).not.toBeNull();
    expect(repo.create).toHaveBeenCalledTimes(1);
  });

  it('C6 dismissing an agent resolves its open warnings and hides each signal type for a day', async () => {
    const { svc, repo, store } = makeCountingService();
    const resolved = await svc.dismissOpenForAgent('op_x', 'agt_x', 'operator:op_x');
    expect(resolved).toHaveLength(3);
    expect(repo.resolveOpenForAgent).toHaveBeenCalledWith('op_x', 'agt_x', 'operator:op_x', ['info', 'warning']);
    const keys = store.set.mock.calls.map((call) => call[0]).filter((key) => key.includes('sec_event_dismissed'));
    expect(keys.sort()).toEqual([
      'stack:sec_event_dismissed:op_x:agt_x:credential_outside_scope',
      'stack:sec_event_dismissed:op_x:agt_x:undeclared_target',
    ]);
    expect(store.set).toHaveBeenCalledWith(keys[0], '1', 'EX', 86400);
  });
});
