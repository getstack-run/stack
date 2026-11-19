import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';
import type { Services } from '../config/services.js';

/**
 * Accountability and notification routes read query strings and bodies
 * through schemas. Malformed input is a 400 with the standard validation
 * envelope; valid input still reaches the service as before.
 */

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    request['operatorId'] = 'op_owner';
    request['operatorTier'] = 'pro';
  },
}));
vi.mock('../middleware/governance-stepup.js', () => ({ enforceGovernanceStepUp: vi.fn(async () => undefined) }));

const { registerAccountabilityRoutes } = await import('./accountability.js');

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp() {
  const getReviewQueue = vi.fn(async () => ({ items: [], total: 0 }));
  const verifyDestinationCode = vi.fn(async () => ({ verified: true }));
  const verifyCode = vi.fn(async () => ({ verified: true }));
  const channelCreate = vi.fn(async (row: Record<string, unknown>) => ({ ...row }));
  const destinationCreate = vi.fn(async (row: Record<string, unknown>) => ({ ...row }));
  const sendDestinationVerificationCode = vi.fn(async () => ({ sent: true }));
  const services = {
    accountability: { getReviewQueue },
    notificationDestination: {
      findById: vi.fn(async (id: string) => ({ id, operator_id: 'op_owner', verified: true, channel_type: 'email', destination: 'a@example.test' })),
      findByOperatorAndTypeAndDest: vi.fn(async () => undefined),
      create: destinationCreate,
    },
    operator: { getById: vi.fn(async () => ({ id: 'op_owner', email: 'owner@example.test' })) },
    notificationChannel: {
      findById: vi.fn(async (id: string) => ({ id, operator_id: 'op_owner' })),
      create: channelCreate,
    },
    notification: { verifyDestinationCode, verifyCode, sendDestinationVerificationCode, describeRule: vi.fn(async () => ({ methods: [], delivers: false })) },
    audit: { write: vi.fn(async () => undefined) },
  } as unknown as Services;
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerAccountabilityRoutes(app, services);
  await app.ready();
  return { app, getReviewQueue, verifyDestinationCode, verifyCode, channelCreate, destinationCreate, sendDestinationVerificationCode };
}

function post(app: ReturnType<typeof Fastify>, url: string, payload: unknown) {
  return app.inject({
    method: 'POST',
    url,
    headers: { authorization: 'Bearer operator', 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });
}

function get(app: ReturnType<typeof Fastify>, url: string) {
  return app.inject({ method: 'GET', url, headers: { authorization: 'Bearer operator' } });
}

function expectValidationError(res: { statusCode: number; json: () => { error: { code: string } } }) {
  expect(res.statusCode).toBe(400);
  expect(res.json().error.code).toBe('VALIDATION_ERROR');
}

describe('GET /v1/passports/reviews query', () => {
  it.each([
    ['a non-numeric limit', '?limit=many'],
    ['a non-numeric page', '?page=first'],
    ['a repeated limit', '?limit=5&limit=6'],
  ])('rejects %s', async (_label, query) => {
    const { app, getReviewQueue } = await makeApp();
    expectValidationError(await get(app, `/v1/passports/reviews${query}`));
    expect(getReviewQueue).not.toHaveBeenCalled();
  });

  it('passes absent parameters through as undefined', async () => {
    const { app, getReviewQueue } = await makeApp();
    const res = await get(app, '/v1/passports/reviews');
    expect(res.statusCode).toBe(200);
    expect(getReviewQueue).toHaveBeenCalledWith('op_owner', { status: undefined, page: undefined, limit: undefined });
  });

  it('passes valid parameters through', async () => {
    const { app, getReviewQueue } = await makeApp();
    await get(app, '/v1/passports/reviews?status=pending&page=3&limit=25');
    expect(getReviewQueue).toHaveBeenCalledWith('op_owner', { status: 'pending', page: 3, limit: 25 });
  });

  it('keeps clamping out-of-range numbers and treats an empty value as absent', async () => {
    const { app, getReviewQueue } = await makeApp();
    await get(app, '/v1/passports/reviews?page=0&limit=500');
    expect(getReviewQueue).toHaveBeenLastCalledWith('op_owner', { status: undefined, page: 1, limit: 100 });
    await get(app, '/v1/passports/reviews?page=&limit=-4');
    expect(getReviewQueue).toHaveBeenLastCalledWith('op_owner', { status: undefined, page: undefined, limit: 1 });
  });
});

describe.each([
  ['destination', '/v1/notifications/destinations/dst_1/verify'],
  ['channel', '/v1/notifications/channels/ch_1/verify'],
])('POST verify (%s)', (kind, url) => {
  it.each([
    ['an array', []],
    ['an empty object', {}],
    ['a numeric code', { code: 123456 }],
    ['an empty code', { code: '' }],
  ])('rejects %s', async (_label, payload) => {
    const { app, verifyDestinationCode, verifyCode } = await makeApp();
    expectValidationError(await post(app, url, payload));
    expect(verifyDestinationCode).not.toHaveBeenCalled();
    expect(verifyCode).not.toHaveBeenCalled();
  });

  it('verifies a valid code', async () => {
    const { app, verifyDestinationCode, verifyCode } = await makeApp();
    const res = await post(app, url, { code: '123456' });
    expect(res.statusCode).toBe(200);
    const verifier = kind === 'destination' ? verifyDestinationCode : verifyCode;
    expect(verifier).toHaveBeenCalledWith(kind === 'destination' ? 'dst_1' : 'ch_1', 'op_owner', '123456');
  });
});

describe('POST /v1/notifications/channels body', () => {
  it.each([
    ['an array', []],
    ['a string', 'email'],
    ['a destination-based body without events', { destination_id: 'dst_1' }],
    ['an inline body without a destination', { channel_type: 'email' }],
  ])('rejects %s', async (_label, payload) => {
    const { app, channelCreate } = await makeApp();
    expectValidationError(await post(app, '/v1/notifications/channels', payload));
    expect(channelCreate).not.toHaveBeenCalled();
  });

  it('creates a destination-based rule', async () => {
    const { app, channelCreate } = await makeApp();
    const res = await post(app, '/v1/notifications/channels', { destination_ids: ['dst_1'], events: ['passport.flagged'] });
    expect(res.statusCode).toBe(201);
    expect(channelCreate).toHaveBeenCalledWith(expect.objectContaining({
      operator_id: 'op_owner',
      destination_ids: ['dst_1'],
      events: ['passport.flagged'],
      min_severity: 'warning',
    }));
  });

  it('creates an inline email rule as an unverified delivery method attached to the rule, and sends its code once', async () => {
    const { app, channelCreate, destinationCreate, sendDestinationVerificationCode } = await makeApp();
    const res = await post(app, '/v1/notifications/channels', { channel_type: 'email', destination: 'a@example.test' });
    expect(res.statusCode).toBe(201);
    expect(destinationCreate).toHaveBeenCalledWith(expect.objectContaining({
      operator_id: 'op_owner', channel_type: 'email', destination: 'a@example.test', verified: false,
    }));
    const destinationId = (destinationCreate.mock.calls[0]![0] as { id: string }).id;
    expect(channelCreate).toHaveBeenCalledWith(expect.objectContaining({
      channel_type: 'email',
      destination: 'a@example.test',
      destination_ids: [destinationId],
      verified: false,
    }));
    expect(sendDestinationVerificationCode).toHaveBeenCalledTimes(1);
    expect(res.json()).toMatchObject({ delivers: false, delivery_methods: [] });
  });
});
