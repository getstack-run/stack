// eval-traffic quiet routing at the SecurityEventService.record
// choke point. Detection stays on; ≤ warning auto-resolves + skips
// notification; critical stays fully live; lookup failure fails open.

import { describe, it, expect } from 'vitest';
import { SecurityEventService } from './security-event-service.js';

const OP = 'op_test';
const AGENT = 'agt_eval';

function makeService(opts?: { evalTraffic?: boolean; agentLookupFails?: boolean; onCritical?: string }) {
  const created: Array<Record<string, unknown>> = [];
  const notifications: Array<Record<string, unknown>> = [];
  const blocks: Array<Record<string, unknown>> = [];
  const securityEventRepo = {
    async create(data: Record<string, unknown>) {
      created.push(data);
      return { id: data['id'], created_at: new Date('2026-09-04T12:00:00.000Z'), ...data };
    },
  };
  const agentRepo = {
    async findById(id: string) {
      if (opts?.agentLookupFails) throw new Error('db down');
      return {
        id,
        eval_traffic: opts?.evalTraffic ?? false,
        on_critical: opts?.onCritical ?? 'notify',
        passport_blocked: false,
      };
    },
    async update(id: string, patch: Record<string, unknown>) {
      blocks.push({ id, ...patch });
    },
  };
  const svc = new SecurityEventService(securityEventRepo as never, agentRepo as never);
  svc.setAgentBlocker({
    async blockAgent(operatorId: string, agentId: string, reason: string) {
      blocks.push({ operatorId, agentId, reason });
      return { revoked_count: 1 };
    },
  } as never);
  svc.setNotificationService({
    async publishEvent(evt: Record<string, unknown>) {
      notifications.push(evt);
    },
  } as never);
  return { svc, created, notifications, blocks };
}

const base = {
  operatorId: OP,
  agentId: AGENT,
  signalType: 'prompt_injection' as const,
  severity: 'warning' as const,
  message: 'test signal',
};

describe('SecurityEventService — eval_traffic quiet routing', () => {
  it('normal agent: warning records unresolved + notifies', async () => {
    const { svc, created, notifications } = makeService();
    await svc.record(base);
    expect(created[0]!['resolved']).toBeUndefined();
    expect(notifications).toHaveLength(1);
  });

  it('eval agent: warning records PRE-RESOLVED (auto:eval_traffic) and skips notification', async () => {
    const { svc, created, notifications } = makeService({ evalTraffic: true });
    const event = await svc.record(base);
    expect(event).toBeTruthy(); // still recorded — evals can assert on it
    expect(created[0]!['resolved']).toBe(true);
    expect(created[0]!['resolved_by']).toBe('auto:eval_traffic');
    expect(created[0]!['resolved_at']).toBeInstanceOf(Date);
    expect(notifications).toHaveLength(0);
  });

  it('eval agent: info also auto-resolves', async () => {
    const { svc, created } = makeService({ evalTraffic: true });
    await svc.record({ ...base, severity: 'info' });
    expect(created[0]!['resolved']).toBe(true);
  });

  it('eval agent: CRITICAL stays fully live — unresolved, notified, auto-block honored', async () => {
    const { svc, created, notifications, blocks } = makeService({
      evalTraffic: true,
      onCritical: 'block',
    });
    await svc.record({ ...base, severity: 'critical' });
    expect(created[0]!['resolved']).toBeUndefined();
    expect(notifications).toHaveLength(1);
    expect(blocks).toEqual([{
      operatorId: OP,
      agentId: AGENT,
      reason: 'Auto-blocked: prompt_injection — test signal',
    }]);
  });

  it('third-party content: critical is recorded and notified but never auto-blocks the agent', async () => {
    const { svc, created, notifications, blocks } = makeService({ onCritical: 'block' });
    const event = await svc.record({ ...base, severity: 'critical', skipAgentAutoBlock: true });
    expect(event?.id).toBe(created[0]!['id']);
    expect(notifications).toHaveLength(1);
    expect(blocks).toEqual([]);
  });

  it('agent lookup failure fails OPEN: recorded loud (unresolved + notified)', async () => {
    const { svc, created, notifications } = makeService({ evalTraffic: true, agentLookupFails: true });
    await svc.record(base);
    expect(created[0]!['resolved']).toBeUndefined();
    expect(notifications).toHaveLength(1);
  });
});
