import Fastify from 'fastify';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { ControlsRequiredFeature } from '@stack/shared';
import { createErrorHandler } from './error-handler.js';
import { requireControls } from './require-controls.js';
import type { RouteRecord } from '../route-table.js';

// Reading the record is a controls feature, and so is changing the detector settings: without controls each route
// below answers 402 CONTROLS_REQUIRED before its handler runs. STACK keeps writing the record either way.

/** The routes the record is read through, and the detector settings writes, with the gate each must run. */
const RECORD_READS = [
  'GET /v1/audit',
  'GET /v1/audit/export',
  'GET /v1/audit/chain-head',
  'GET /v1/audit/verify-chain',
  'POST /v1/evidence-packs',
  'GET /v1/evidence-packs',
  'GET /v1/evidence-packs/:pack_id',
  'GET /v1/evidence-packs/:pack_id/download',
  'POST /v1/missions/:id/dossier',
  'GET /v1/missions/:id/dossiers',
  'GET /v1/missions/:id/replay',
  'GET /v1/passports/:jti/report',
  'GET /v1/missions/:id/operator-reviews/:claim_id/download',
];
const DETECTOR_SETTINGS = ['PUT /v1/detectors/:detector_key/config', 'DELETE /v1/detectors/:detector_key/config'];
/**
 * The rest of what controls add (the Console plan's decision 1): control policies and their simulation, control reviews,
 * PII redaction settings, the detector settings reads, the list of Missions, fleets and pending intent checks. Writes of policies and detector settings refuse already (`CONTROLS_NOT_ENABLED`, and the detector gate above).
 */
const CONTROLS_FEATURES = [
  'GET /v1/control-policies',
  'GET /v1/control-policies/default',
  'GET /v1/control-policies/agents/:agentId',
  'GET /v1/control-policies/:id/revisions',
  'POST /v1/control-policies/simulate',
  'GET /v1/control-reviews',
  'GET /v1/control-reviews/:id',
  'GET /v1/pii/config',
  'PUT /v1/pii/config',
  'DELETE /v1/pii/config',
  'GET /v1/detectors/config',
  'GET /v1/detectors/:detector_key/config',
  'GET /v1/missions',
  'GET /v1/fleets',
  'GET /v1/fleets/:id',
  'GET /v1/fleets/membership/:agentId',
  'POST /v1/fleets',
  'PUT /v1/fleets/:id',
  'POST /v1/fleets/:id/revoke',
  'GET /v1/fleets/:id/members',
  'POST /v1/fleets/:id/members/:agentId/revoke',
  'POST /v1/fleets/:id/enrollment-challenges',
  'POST /v1/fleets/:id/enroll',
  'POST /v1/fleets/session',
  'GET /v1/intents/pending',
];
/**
 * What controls do not gate: revocation, passports, one Mission read, warnings, billing and usage, and the control socket
 * with its decisions (self-hosted controls need no subscription) and security events (flags still exist without controls).
 */
const NOT_GATED = [
  'POST /v1/passports/revoke',
  'POST /v1/passports/revoke-all',
  'POST /v1/passports/issue',
  // Opening a Mission is not gated: every Passport of an agent outside an agent account is issued under one.
  'POST /v1/missions',
  'POST /v1/missions/start',
  'GET /v1/missions/:id',
  'GET /v1/security-events',
  'GET /v1/control-socket',
  'GET /v1/control-decisions',
  'GET /v1/control-decisions/:id',
];

describe('the routes of the record carry the controls gate', () => {
  let routes: RouteRecord[] = [];
  beforeAll(async () => {
    const { collectRouteTable } = await import('../route-table.js');
    routes = await collectRouteTable(null);
  }, 180_000);
  const gatesOf = (key: string) => {
    const route = routes.find((r) => `${r.method} ${r.url}` === key);
    expect(route, `${key} is registered`).toBeDefined();
    return route!.gates;
  };

  it.each([...RECORD_READS, ...DETECTOR_SETTINGS, ...CONTROLS_FEATURES])('%s runs requireControlsGate', (key) => {
    expect(gatesOf(key)).toContain('requireControlsGate');
  });

  it.each(NOT_GATED)('%s is not a controls feature', (key) => {
    expect(gatesOf(key)).not.toContain('requireControlsGate');
  });
});

describe('requireControls', () => {
  const apps: Array<ReturnType<typeof Fastify>> = [];
  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  async function app(controls: () => Promise<boolean>, feature?: ControlsRequiredFeature) {
    const handler = vi.fn(async () => ({ ok: true }));
    const instance = Fastify();
    apps.push(instance);
    instance.setErrorHandler(createErrorHandler());
    instance.addHook('onRequest', async (request) => {
      (request as unknown as { operatorId: string }).operatorId = 'op_1';
    });
    const services = { entitlements: { controlsEnabled: vi.fn(controls) } };
    instance.get('/record', { preHandler: requireControls(services as never, feature) }, handler);
    await instance.ready();
    return { instance, handler, services };
  }

  it('answers 402 CONTROLS_REQUIRED for the record without controls, and the handler never runs', async () => {
    const { instance, handler, services } = await app(async () => false);
    const res = await instance.inject({ method: 'GET', url: '/record' });
    expect(res.statusCode).toBe(402);
    expect(res.json()).toEqual({
      error: {
        code: 'CONTROLS_REQUIRED',
        message:
          'Reading the record needs controls. STACK keeps the record either way: switch controls on in billing to read all of it, including everything from before.',
        details: { feature: 'record' },
      },
    });
    expect(handler).not.toHaveBeenCalled();
    expect(services.entitlements.controlsEnabled).toHaveBeenCalledWith('op_1');
  });

  it('names the detector settings when they are what was refused', async () => {
    const { instance } = await app(async () => false, 'detector_settings');
    const res = await instance.inject({ method: 'GET', url: '/record' });
    expect(res.statusCode).toBe(402);
    expect(res.json().error).toMatchObject({
      code: 'CONTROLS_REQUIRED',
      message: 'Changing detector settings needs controls. Switch controls on in billing.',
      details: { feature: 'detector_settings' },
    });
  });

  it.each(['policies', 'reviews', 'pii_settings', 'detector_reads', 'missions', 'fleets', 'intent_checks', 'wallet_caps', 'budget'] as const)(
    'names %s when that is what was refused, says controls are off and where the owner switches them on',
    async (feature) => {
      const { instance, handler } = await app(async () => false, feature);
      const res = await instance.inject({ method: 'GET', url: '/record' });
      expect(res.statusCode).toBe(402);
      const error = res.json().error;
      expect(error).toMatchObject({ code: 'CONTROLS_REQUIRED', details: { feature } });
      expect(error.message).toContain('controls are off');
      expect(error.message).toContain('The owner switches them on in the Console, at the Billing page.');
      expect(handler).not.toHaveBeenCalled();
    },
  );

  it('lets a customer with controls through', async () => {
    const { instance, handler } = await app(async () => true);
    const res = await instance.inject({ method: 'GET', url: '/record' });
    expect(res.statusCode).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('fails closed when controls cannot be read', async () => {
    const { instance, handler } = await app(async () => {
      throw new Error('billing account unreadable');
    });
    const res = await instance.inject({ method: 'GET', url: '/record' });
    expect(res.statusCode).toBeGreaterThanOrEqual(500);
    expect(handler).not.toHaveBeenCalled();
  });
});
