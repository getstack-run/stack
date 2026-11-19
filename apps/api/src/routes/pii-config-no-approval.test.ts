import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';

const context = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));
const stepUp = vi.hoisted(() => ({ inputs: [] as unknown[] }));
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: object) => Object.assign(request, context.current),
}));
vi.mock('../middleware/governance-stepup.js', () => ({
  enforceGovernanceStepUp: vi.fn(async (_services: unknown, _request: unknown, input: unknown) => {
    stepUp.inputs.push(input);
  }),
}));
import { registerPiiConfigRoutes } from './pii-config.js';

/**
 * The owner's own change of PII redaction applies at once, loosening included, by session, key or chat. An agent
 * context never reaches the routes. These used to ask for a governance step-up (`pii_config_upsert`,
 * `pii_config_reset`).
 */

const ROW = {
  operator_id: 'op_1',
  enabled: false,
  threshold: 0.9,
  countries: ['SE'],
  created_at: new Date('2026-11-01T00:00:00Z'),
  updated_at: new Date('2026-11-01T00:00:00Z'),
};

function app() {
  const server = Fastify({ logger: false });
  server.setErrorHandler(createErrorHandler());
  const services = {
    entitlements: { controlsEnabled: vi.fn(async () => true) },
    operatorPiiConfig: {
      getForOperator: vi.fn(async () => null),
      isLoosening: vi.fn(() => true),
      upsert: vi.fn(async () => ROW),
      reset: vi.fn(async () => true),
    },
    audit: { write: vi.fn(async () => undefined) },
  };
  registerPiiConfigRoutes(server, services as never);
  return { server, services };
}

afterEach(() => {
  stepUp.inputs.length = 0;
  context.current = {};
});

describe('PUT /v1/pii/config', () => {
  it('applies a loosening change at once and asks no one', async () => {
    context.current = { operatorId: 'op_1' };
    const { server, services } = app();
    const response = await server.inject({
      method: 'PUT',
      url: '/v1/pii/config',
      payload: { enabled: false, threshold: 0.9, countries: ['SE'] },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().direction).toBe('loosening');
    expect(stepUp.inputs).toEqual([]);
    expect(services.operatorPiiConfig.upsert).toHaveBeenCalledTimes(1);
    expect(services.audit.write).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'pii.config.upsert.loosening', outcome: 'success' }),
    );
  });

  it('still refuses an agent context, and changes nothing', async () => {
    context.current = { operatorId: 'op_1', agentId: 'agt_1' };
    const { server, services } = app();
    const response = await server.inject({ method: 'PUT', url: '/v1/pii/config', payload: { enabled: false } });
    expect(response.statusCode).toBe(403);
    expect(services.operatorPiiConfig.upsert).not.toHaveBeenCalled();
  });
});

describe('DELETE /v1/pii/config', () => {
  it('resets at once and asks no one', async () => {
    context.current = { operatorId: 'op_1' };
    const { server, services } = app();
    const response = await server.inject({ method: 'DELETE', url: '/v1/pii/config' });
    expect(response.statusCode).toBe(200);
    expect(stepUp.inputs).toEqual([]);
    expect(services.operatorPiiConfig.reset).toHaveBeenCalledWith('op_1');
  });
});
