import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Services } from '../config/services.js';
import { createErrorHandler } from '../middleware/error-handler.js';
import { registerOperatorRoutes } from './operators.js';

// The real auth middleware needs the full service graph; these tests are about
// how the route reads its body, so authenticate as a fixed operator.
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: { operatorId: string }) => {
    request.operatorId = 'op_owner';
  },
}));

const apps: Array<ReturnType<typeof Fastify>> = [];
afterEach(async () => Promise.all(apps.splice(0).map((app) => app.close())));

function harness() {
  const deleteAccount = vi.fn(async (_operatorId: string, _confirmEmail: string) => ({ status: 'completed' }));
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerOperatorRoutes(app, { operator: { deleteAccount } } as unknown as Services);
  return { app, deleteAccount };
}

function remove(app: ReturnType<typeof Fastify>, payload: unknown) {
  return app.inject({
    method: 'DELETE',
    url: '/v1/operators/me',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });
}

describe('DELETE /v1/operators/me body', () => {
  it.each([
    ['an empty object', {}],
    ['a non-string confirm_email', { confirm_email: 42 }],
    ['a null confirm_email', { confirm_email: null }],
    ['a null body', null],
  ])('answers %s with 400 VALIDATION_ERROR and deletes nothing', async (_name, payload) => {
    const { app, deleteAccount } = harness();
    const response = await remove(app, payload);
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
    expect(deleteAccount).not.toHaveBeenCalled();
  });

  it('passes a string confirm_email to the erasure service, ignoring extra fields', async () => {
    const { app, deleteAccount } = harness();
    const response = await remove(app, { confirm_email: 'owner@test.invalid', extra: true });
    expect(response.statusCode).toBe(204);
    expect(deleteAccount).toHaveBeenCalledWith('op_owner', 'owner@test.invalid');
  });
});
