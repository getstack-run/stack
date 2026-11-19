import { describe, expect, it, vi } from 'vitest';
import { MissionService } from './mission-service.js';

const missionRow = {
  mission_id: 'ms_one',
  operator_id: 'op_owner',
  claim_id: 'pc_mission',
  passport_jti: null,
  intent_summary: 'Review invoices',
  intent_services: [],
  expected_counterparties: [],
  max_actions: null,
  max_dropoff_bytes: null,
  coverage_cap_cents: null,
  max_duration_seconds: null,
  max_concurrent_intents: null,
  max_actions_per_service: {},
  cap_behavior: {},
  baseline_profile: null,
  expected_output_shape: null,
  started_at: new Date('2026-08-01T00:00:00.000Z'),
  expires_at: new Date('2026-08-01T00:15:00.000Z'),
  completed_at: new Date('2026-08-01T00:10:00.000Z'),
  revoked_at: null,
  revoked_reason: null,
  terminal_state: 'completed_successful',
};

describe('MissionService.listByOperator evidence summary', () => {
  it('keeps a completed mission duration fixed instead of counting time since completion', async () => {
    const repo = {
      findById: vi.fn(async () => missionRow),
      countIntentsByMissionId: vi.fn(async () => 3),
      countIntentsByMissionIdGroupedByService: vi.fn(async () => ({})),
      countInflightIntentsByMissionId: vi.fn(async () => 0),
      sumWalletDebitCentsByMission: vi.fn(async () => 0),
      sumDropoffBytesByMission: vi.fn(async () => 0),
    };
    const service = new MissionService({ repo } as never);
    expect((await service.getCapUsage('ms_one'))?.duration_seconds.used).toBe(600);
  });

  it('returns bounded counts and pagination metadata', async () => {
    const repo = {
      listByOperator: vi.fn(async () => [missionRow]),
      countByOperator: vi.fn(async () => 3),
      countEvidenceByMissionIds: vi.fn(async () => new Map([
        ['ms_one', { dossier_count: 2, evidence_pack_count: 1 }],
      ])),
    };
    const service = new MissionService({ repo } as never);

    const result = await service.listByOperator('op_owner', { page: 2, limit: 1 });

    expect(result).toMatchObject({
      page: 2,
      limit: 1,
      total: 3,
      has_more: true,
      items: [{
        mission_id: 'ms_one',
        dossier_count: 2,
        evidence_pack_count: 1,
      }],
    });
    expect(repo.countEvidenceByMissionIds).toHaveBeenCalledWith('op_owner', ['ms_one']);
  });
});
