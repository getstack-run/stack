import { describe, expect, it, vi } from 'vitest';
import { trailEntityDigest } from '@stack/shared';
import { observeEntities } from './signed-claims.js';

// What a proxied call read and sent is recorded on the trail as one-way
// digests, never as text, and the "counterparty this passport has not dealt
// with before" flag still works against them (and against the text rows that
// were recorded before the trail kept digests).

const SELLER = 'seller.ops@counterparty.example';
const PAYLOAD = { accounts: [{ owner: 'Dana Whitfield', email: 'dana.whitfield@bank.example' }] };

function world(history: string[] = []) {
  const claims: Array<Record<string, any>> = [];
  const events: Array<Record<string, any>> = [];
  const reads = vi.fn(async () => (history.length > 0 ? [{ sourceService: 'custom_mailer', entities: history, fingerprints: [] }] : []));
  const services = {
    claimRegistry: { registerClaim: vi.fn(async (c: Record<string, any>) => { claims.push(c); return { claimId: `pc_${claims.length}` }; }) },
    securityEvent: { record: vi.fn(async (e: Record<string, any>) => { events.push(e); }) },
    passportClaimsRepo: { findObservedContentForFlow: reads },
    mission: { findById: vi.fn(async () => null) },
  };
  return { services, claims, events, reads };
}

function observe(w: ReturnType<typeof world>) {
  return observeEntities(
    w.services as never,
    { input: { service: 'custom_mailer', method: 'POST', url: 'https://api.mailer.example/send', body: { to: SELLER } }, isMutation: true, operationKey: null } as never,
    { jti: 'pas_1', agentId: 'agt_1', operatorId: 'op_1', missionIds: ['ms_1'], missionRef: 'ms_1' } as never,
    { resolvedUrl: 'https://api.mailer.example/send' } as never,
    { status: 200, headers: {}, body: JSON.stringify(PAYLOAD) } as never,
  );
}

/** The undeclared-counterparty check runs detached: wait for its read, then for the macrotask it ends in. */
async function settleUndeclaredCheck(w: ReturnType<typeof world>) {
  await vi.waitFor(() => { if (w.reads.mock.calls.length === 0) throw new Error('the check has not read the trail yet'); });
  await new Promise<void>((resolve) => setImmediate(resolve));
}

describe('a proxied call records what it read and sent as one-way digests', () => {
  it('stores no address, name or id, only digests, aligned with their types', async () => {
    const w = world();
    await observe(w);
    expect(w.claims).toHaveLength(1);
    const payload = w.claims[0]!.payload;
    expect(payload.entities.length).toBeGreaterThan(0);
    expect(payload.entities.every((entity: string) => /^(h|money|acct):[0-9a-f]+$/.test(entity))).toBe(true);
    expect(payload.entities).toContain(trailEntityDigest(SELLER));
    expect(payload.entities).toContain(trailEntityDigest('dana.whitfield@bank.example'));
    expect(payload.entity_types).toHaveLength(payload.entities.length);
    const stored = JSON.stringify(w.claims);
    for (const plain of [SELLER, 'seller.ops', 'dana.whitfield', 'bank.example', 'Whitfield']) {
      expect(stored, plain).not.toContain(plain);
    }
    expect(payload).toMatchObject({ source_service: 'custom_mailer', mission_ref: 'ms_1' });
  });
});

describe('the undeclared counterparty flag against digests', () => {
  it('flags a counterparty the Mission has not dealt with', async () => {
    const w = world();
    await observe(w);
    await settleUndeclaredCheck(w);
    expect(w.events).toHaveLength(1);
    expect(w.events[0]).toMatchObject({ signalType: 'undeclared_target', severity: 'warning' });
  });

  it('does not flag what an earlier call of the same Mission recorded as digests', async () => {
    const first = world();
    await observe(first);
    const recorded: string[] = first.claims[0]!.payload.entities;
    expect(recorded).toContain(trailEntityDigest(SELLER));

    const second = world(recorded);
    await observe(second);
    await settleUndeclaredCheck(second);
    expect(second.events).toEqual([]);
  });

  it('does not flag a counterparty recorded earlier as text, before the trail kept digests', async () => {
    const w = world([SELLER, 'api.mailer.example', '/send']);
    await observe(w);
    await settleUndeclaredCheck(w);
    expect(w.events).toEqual([]);
  });

  it('still flags when the history holds a different counterparty', async () => {
    const w = world([trailEntityDigest('someone.else@counterparty.example')]);
    await observe(w);
    await settleUndeclaredCheck(w);
    expect(w.events).toHaveLength(1);
  });
});
