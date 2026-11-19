import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConflictError, ForbiddenError } from '@stack/shared';
import { hostedFeatureGate } from '../config/licence-service.js';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    const token = String((request['headers'] as { authorization?: string }).authorization ?? '').replace(/^Bearer /, '');
    request['operatorId'] = token === 'member-foreign' ? 'op_other' : 'op_owner';
    request['operatorTier'] = 'enterprise';
    request['isAdmin'] = false;
    request['isPlatformStaff'] = false;
    request['isPartner'] = false;
    if (token === 'member' || token === 'member-foreign') {
      request['memberId'] = token === 'member' ? 'mem_owner' : 'mem_foreign';
      request['memberRole'] = 'standard';
    }
    if (token === 'agent' || token === 'passport') request['agentId'] = 'agt_owner';
  },
}));

vi.mock('../middleware/meter.js', () => ({ meterAction: vi.fn(async () => {}) }));

import { registerMissionsRoutes } from './missions.js';

const apps: ReturnType<typeof Fastify>[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const body = {
  narrative: 'Reviewed by a person.',
  lessons_learned: '',
  incident_classification: 'inconclusive',
};

async function makeApp(options?: { createError?: Error }) {
  const create = vi.fn(async (_missionId: string, _input: unknown, memberId: string) => {
    if (options?.createError) throw options.createError;
    return {
      claim_id: 'pc_dossier',
      claim: { authored_by_member_id: memberId },
    };
  });
  const services = {
    mission: {
      findById: vi.fn(async () => ({ mission_id: 'ms_done', operator_id: 'op_owner' })),
    },
    dossier: { create, findByMission: vi.fn(async () => []) },
    audit: { write: vi.fn(async () => {}) },
    features: hostedFeatureGate,
    entitlements: { controlsEnabled: async () => true },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerMissionsRoutes(app, services as never);
  await app.ready();
  return { app, create };
}

describe('POST /v1/missions/:id/dossier principal gate', () => {
  it.each(['agent', 'passport', 'operator'])('rejects %s authentication', async (token) => {
    const { app, create } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/missions/ms_done/dossier',
      headers: { authorization: `Bearer ${token}` },
      payload: body,
    });
    expect(response.statusCode).toBe(403);
    expect(create).not.toHaveBeenCalled();
  });

  it('accepts a same-operator member and records the real member id', async () => {
    const { app, create } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/missions/ms_done/dossier',
      headers: { authorization: 'Bearer member' },
      payload: body,
    });
    expect(response.statusCode).toBe(201);
    expect(create).toHaveBeenCalledWith('ms_done', expect.any(Object), 'mem_owner');
  });

  it('hides a foreign mission from a foreign member', async () => {
    const { app, create } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/missions/ms_done/dossier',
      headers: { authorization: 'Bearer member-foreign' },
      payload: body,
    });
    expect(response.statusCode).toBe(404);
    expect(create).not.toHaveBeenCalled();
  });

  it('returns 409 when the mission is not terminal', async () => {
    const { app, create } = await makeApp({
      createError: new ConflictError('mission ms_done is not terminal'),
    });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/missions/ms_done/dossier',
      headers: { authorization: 'Bearer member' },
      payload: body,
    });
    expect(response.statusCode).toBe(409);
    expect(create).toHaveBeenCalledOnce();
  });

  it('returns 403 when the operator tier cannot issue a dossier claim', async () => {
    const { app, create } = await makeApp({
      createError: new ForbiddenError("claim type 'dossier' is not permitted for tier 'free'"),
    });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/missions/ms_done/dossier',
      headers: { authorization: 'Bearer member' },
      payload: body,
    });
    expect(response.statusCode).toBe(403);
    expect(create).toHaveBeenCalledOnce();
  });
});

describe('GET /v1/missions evidence summary', () => {
  it('returns mapped pagination, evidence counts, and passport_jti', async () => {
    const startedAt = new Date('2026-08-16T08:00:00.000Z');
    const expiresAt = new Date('2026-08-16T09:00:00.000Z');
    const listByOperator = vi.fn(async () => ({
      items: [{
        mission_id: 'ms_page_2',
        operator_id: 'op_owner',
        claim_id: 'pc_mission',
        passport_jti: 'jti_real',
        intent_summary: 'Review evidence.',
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
        started_at: startedAt,
        expires_at: expiresAt,
        completed_at: null,
        revoked_at: null,
        revoked_reason: null,
        terminal_state: null,
        dossier_count: 2,
        evidence_pack_count: 1,
      }],
      page: 2,
      limit: 2,
      total: 5,
      has_more: true,
    }));
    const services = {
      mission: { listByOperator },
      dossier: { findByMission: vi.fn(async () => []) },
      audit: { write: vi.fn(async () => {}) },
      entitlements: { controlsEnabled: async () => true },
    };
    const app = Fastify();
    apps.push(app);
    app.setErrorHandler(errorHandler);
    registerMissionsRoutes(app, services as never);
    await app.ready();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/missions?page=2&limit=2',
      headers: { authorization: 'Bearer member' },
    });

    expect(response.statusCode).toBe(200);
    expect(listByOperator).toHaveBeenCalledWith('op_owner', { page: 2, limit: 2 });
    expect(response.json()).toMatchObject({
      page: 2,
      limit: 2,
      total: 5,
      has_more: true,
      items: [{
        mission_id: 'ms_page_2',
        passport_jti: 'jti_real',
        dossier_count: 2,
        evidence_pack_count: 1,
      }],
    });
  });
});
