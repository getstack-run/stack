import { describe, expect, it } from 'vitest';
import { MissionService, type MissionServiceDeps } from './mission-service.js';

/**
 * The two checkGate options beginAgentRuntime (apps/api/src/lib/agent-runtime.ts)
 * relies on:
 *
 *  A1: `internal` skips Mission service-scope narrowing for STACK-internal
 *      actions (drop-offs, A2A, skills, authority), which a Mission cannot list,
 *      while lifecycle and caps still apply.
 *  A2: `alreadyCounted` discounts, once, the approved intent an action executes,
 *      so the last approved action at a cap is not refused for the count its own
 *      submission added. It never lifts a cap that is already past.
 */

function missionRow(over: Record<string, unknown> = {}) {
  return {
    mission_id: 'ms_one', operator_id: 'op_one', claim_id: 'pc_one', passport_jti: null,
    assigned_agent_id: null, authorization_digest: null,
    intent_summary: 'work', intent_services: ['slack'], expected_counterparties: [],
    max_actions: null, max_dropoff_bytes: null, coverage_cap_cents: null, max_duration_seconds: null,
    max_concurrent_intents: null, max_actions_per_service: {}, cap_behavior: {},
    baseline_profile: null, expected_output_shape: null,
    started_at: new Date(), expires_at: new Date(Date.now() + 3_600_000),
    completed_at: null, revoked_at: null, revoked_reason: null, terminal_state: null,
    ...over,
  };
}

function service(row: Record<string, unknown>, counts: { intents?: number; byService?: Record<string, number>; inflight?: number } = {}) {
  const repo = {
    findById: async () => row,
    countIntentsByMissionId: async () => counts.intents ?? 0,
    countIntentsByMissionIdGroupedByService: async () => counts.byService ?? {},
    countInflightIntentsByMissionId: async () => counts.inflight ?? 0,
    sumWalletDebitCentsByMission: async () => 0,
    sumDropoffBytesByMission: async () => 0,
  };
  return new MissionService({ repo, claimRegistry: {} } as unknown as MissionServiceDeps);
}

describe('MissionService.checkGate admission options', () => {
  it('A1: an internal action passes a service-narrowed Mission', async () => {
    const svc = service(missionRow({ intent_services: ['slack'] }));
    await expect(svc.checkGate({ missionId: 'ms_one', requestedService: 'stack:dropoff' }))
      .resolves.toMatchObject({ allowed: false, reason: 'mission_scope_mismatch' });
    await expect(svc.checkGate({ missionId: 'ms_one', requestedService: 'stack:dropoff', internal: true }))
      .resolves.toMatchObject({ allowed: true });
  });

  it('A1: internal does not bypass lifecycle or caps', async () => {
    await expect(service(missionRow({ revoked_at: new Date(), revoked_reason: 'operator_initiated_clean' }))
      .checkGate({ missionId: 'ms_one', requestedService: 'stack:a2a', internal: true }))
      .resolves.toMatchObject({ allowed: false, reason: 'mission_revoked' });
    await expect(service(missionRow({ completed_at: new Date() }))
      .checkGate({ missionId: 'ms_one', requestedService: 'stack:a2a', internal: true }))
      .resolves.toMatchObject({ allowed: false, reason: 'mission_completed' });
    await expect(service(missionRow({ expires_at: new Date(Date.now() - 1) }))
      .checkGate({ missionId: 'ms_one', requestedService: 'stack:a2a', internal: true }))
      .resolves.toMatchObject({ allowed: false, reason: 'cap_max_duration_seconds' });
    await expect(service(missionRow({ max_actions: 2 }), { intents: 2 })
      .checkGate({ missionId: 'ms_one', requestedService: 'stack:skill', internal: true }))
      .resolves.toMatchObject({ allowed: false, reason: 'cap_max_actions' });
  });

  it('A2: the approved intent executing at the cap is admitted once', async () => {
    const svc = service(missionRow({ max_actions: 2 }), { intents: 2 });
    await expect(svc.checkGate({ missionId: 'ms_one', requestedService: 'slack' }))
      .resolves.toMatchObject({ allowed: false, reason: 'cap_max_actions' });
    await expect(svc.checkGate({ missionId: 'ms_one', requestedService: 'slack', alreadyCounted: { target: 'slack' } }))
      .resolves.toMatchObject({ allowed: true });
  });

  it('A2: the discount never lifts a cap that is already past', async () => {
    const svc = service(missionRow({ max_actions: 2 }), { intents: 3 });
    await expect(svc.checkGate({ missionId: 'ms_one', requestedService: 'slack', alreadyCounted: { target: 'slack' } }))
      .resolves.toMatchObject({ allowed: false, reason: 'cap_max_actions' });
  });

  it('A2: per-service and concurrency caps discount only the matching intent', async () => {
    const perService = service(missionRow({ max_actions_per_service: { slack: 1 } }), { byService: { slack: 1 } });
    await expect(perService.checkGate({ missionId: 'ms_one', requestedService: 'slack', alreadyCounted: { target: 'slack' } }))
      .resolves.toMatchObject({ allowed: true });
    await expect(perService.checkGate({ missionId: 'ms_one', requestedService: 'slack', alreadyCounted: { target: 'github' } }))
      .resolves.toMatchObject({ allowed: false, reason: 'cap_max_actions_per_service' });
    const concurrent = service(missionRow({ max_concurrent_intents: 1 }), { inflight: 1 });
    await expect(concurrent.checkGate({ missionId: 'ms_one', requestedService: 'slack' }))
      .resolves.toMatchObject({ allowed: false, reason: 'cap_max_concurrent_intents' });
    await expect(concurrent.checkGate({ missionId: 'ms_one', requestedService: 'slack', alreadyCounted: { target: 'slack' } }))
      .resolves.toMatchObject({ allowed: true });
  });
});
