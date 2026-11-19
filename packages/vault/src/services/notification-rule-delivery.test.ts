import { describe, it, expect, vi } from 'vitest';
import { NotificationService } from './notification-service.js';

vi.mock('@stack/shared', async (importActual) => ({
  ...await importActual<typeof import('@stack/shared')>(),
  publicFetch: (input: string, init: RequestInit) => globalThis.fetch(input, init),
}));

/**
 * A rule is On only when it can deliver. `NotificationService.describeRule` is the one place that says so, and it reads
 * exactly what `publishEvent` reads before it sends: the rule is active, and at least one delivery method it names is the
 * operator's own and verified (or, for a rule stored with no delivery method at all, the rule itself is verified).
 */

interface Dest { id: string; operator_id: string; channel_type: string; destination: string; verified: boolean }

function rule(over: Record<string, unknown> = {}) {
  return {
    id: 'nch_1', operator_id: 'op_1', active: true, verified: false, events: ['passport.flagged'], min_severity: 'warning',
    destination_ids: null as string[] | null, destination_id: null as string | null, channel_type: 'email', destination: 'a@example.com',
    webhook_secret_encrypted: null, ...over,
  };
}

function service(dests: Dest[]) {
  const byId = new Map(dests.map((d) => [d.id, d]));
  const svc = new NotificationService({} as never, {} as never, null);
  svc.setDestinationRepo({ findById: vi.fn(async (id: string) => byId.get(id)) } as never);
  return svc;
}

const verified: Dest = { id: 'ndest_v', operator_id: 'op_1', channel_type: 'email', destination: 'a@example.com', verified: true };
const unverified: Dest = { id: 'ndest_u', operator_id: 'op_1', channel_type: 'email', destination: 'b@example.com', verified: false };

describe('NotificationService.describeRule', () => {
  it('delivers when the rule is active and a delivery method it names is verified', async () => {
    const out = await service([verified]).describeRule(rule({ destination_ids: ['ndest_v'] }) as never);
    expect(out.delivers).toBe(true);
    expect(out.methods.map((m) => m.id)).toEqual(['ndest_v']);
  });

  it('does not deliver when the rule is active but its only delivery method is unverified', async () => {
    const out = await service([unverified]).describeRule(rule({ destination_ids: ['ndest_u'] }) as never);
    expect(out.delivers).toBe(false);
    expect(out.methods).toHaveLength(1);
  });

  it('does not deliver when the rule is active and has no delivery method and was never verified', async () => {
    expect((await service([]).describeRule(rule() as never)).delivers).toBe(false);
  });

  it('does not deliver when the rule is switched off, however verified its method is', async () => {
    const out = await service([verified]).describeRule(rule({ active: false, destination_ids: ['ndest_v'] }) as never);
    expect(out.delivers).toBe(false);
  });

  it('delivers when one of several methods is verified', async () => {
    const out = await service([unverified, verified]).describeRule(rule({ destination_ids: ['ndest_u', 'ndest_v'] }) as never);
    expect(out.delivers).toBe(true);
  });

  it('never counts another account\'s delivery method', async () => {
    const foreign = { ...verified, id: 'ndest_f', operator_id: 'op_2' };
    const out = await service([foreign]).describeRule(rule({ destination_ids: ['ndest_f'] }) as never);
    expect(out.delivers).toBe(false);
    expect(out.methods).toEqual([]);
  });

  it('keeps a rule stored before delivery methods existed deliverable once the rule itself is verified', async () => {
    expect((await service([]).describeRule(rule({ verified: true }) as never)).delivers).toBe(true);
  });

  it('flips when the method is verified later, with the rule untouched', async () => {
    const method = { ...unverified };
    const svc = service([method]);
    const stored = rule({ destination_ids: ['ndest_u'] });
    expect((await svc.describeRule(stored as never)).delivers).toBe(false);
    method.verified = true;
    expect((await svc.describeRule(stored as never)).delivers).toBe(true);
    expect(stored.active).toBe(true);
  });

  it('agrees with publishEvent: what it says delivers is what dispatch sends to, and nothing else', async () => {
    const sendEmail = vi.fn(async () => ({}));
    for (const [dests, stored, sends] of [
      [[verified], rule({ events: ['x'], min_severity: 'info', destination_ids: ['ndest_v'] }), true],
      [[unverified], rule({ events: ['x'], min_severity: 'info', destination_ids: ['ndest_u'] }), false],
      [[], rule({ events: ['x'], min_severity: 'info' }), false],
      [[], rule({ events: ['x'], min_severity: 'info', verified: true }), true],
    ] as const) {
      sendEmail.mockClear();
      const svc = new NotificationService({} as never, { findByOperator: vi.fn(async () => [stored]) } as never, null);
      const byId = new Map(dests.map((d) => [d.id, d]));
      svc.setDestinationRepo({ findById: vi.fn(async (id: string) => byId.get(id)) } as never);
      svc.setEmailService({ sendEmail } as never);
      const { dispatched } = await svc.publishEvent({ operatorId: 'op_1', eventType: 'x', severity: 'critical', payload: {} });
      expect(dispatched > 0).toBe(sends);
      expect((await svc.describeRule(stored as never)).delivers).toBe(sends);
    }
  });
});
