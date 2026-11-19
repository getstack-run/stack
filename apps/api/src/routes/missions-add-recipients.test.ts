import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConflictError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';
import { EngineRegistries } from '../config/registries.js';
import { MISSION_PINS_CHANNEL } from '../config/wiring/control-socket.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    const token = String((request['headers'] as { authorization?: string }).authorization ?? '').replace(/^Bearer /, '');
    request['operatorId'] = 'op_owner';
    if (token === 'agent') request['agentId'] = 'agt_owner';
    if (token === 'readonly' || token === 'standard') {
      request['memberId'] = `mem_${token}`;
      request['memberRole'] = token;
    }
  },
}));

import { registerMissionsRoutes } from './missions.js';

// The owner adds who a running Mission may send to; an agent never can, and a Mission that has ended takes none.

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });

async function makeApp() {
  const findById = vi.fn(async (id: string, scope?: { operatorId: string }) =>
    id === 'ms_work' && scope?.operatorId === 'op_owner' ? { mission_id: 'ms_work', operator_id: 'op_owner', assigned_agent_id: 'agt_owner' } : null);
  const addRecipientPins = vi.fn(async (_operatorId: string, _missionId: string, added: unknown[]) => added);
  const publish = vi.fn(async () => 1);
  const write = vi.fn(async () => undefined);
  const registries = new EngineRegistries();
  registries.messageSenders.register(async () => ({ recipients: ['+14155550199'] }));
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerMissionsRoutes(app, {
    mission: { findById, addRecipientPins },
    redis: { publish },
    audit: { write },
    registries,
  } as never);
  await app.ready();
  const post = (token: string, payload: unknown, id = 'ms_work') =>
    app.inject({ method: 'POST', url: `/v1/missions/${id}/recipients`, headers: { authorization: `Bearer ${token}` }, payload: payload as never });
  return { post, addRecipientPins, publish, write };
}

describe('POST /v1/missions/:id/recipients', () => {
  it('adds the owner\'s recipients and the caller of a call it names, tells every machine, and writes one audit row', async () => {
    const { post, addRecipientPins, publish, write } = await makeApp();
    const response = await post('owner-key', { recipients: ['ana@example.com'], reply_to_message: 'acall_1' });
    expect(response.statusCode).toBe(200);
    expect(addRecipientPins).toHaveBeenCalledWith('op_owner', 'ms_work', [{ path: '*', op: 'in', value: ['ana@example.com', '+14155550199'] }]);
    expect(response.json()).toEqual({ mission_id: 'ms_work', recipient_pins: [{ path: '*', op: 'in', value: ['ana@example.com', '+14155550199'] }] });
    expect(publish).toHaveBeenCalledWith(MISSION_PINS_CHANNEL, 'op_owner ms_work');
    expect(write).toHaveBeenCalledWith(expect.objectContaining({ action: 'missions.recipients.add', payload_hash: expect.stringMatching(/^[0-9a-f]{64}$/) }));
  });

  it('lets a standard member add, and refuses a read-only member and an agent before anything changes', async () => {
    const { post, addRecipientPins } = await makeApp();
    expect((await post('standard', { recipients: ['ana@example.com'] })).statusCode).toBe(200);
    expect((await post('readonly', { recipients: ['ana@example.com'] })).statusCode).toBe(403);
    expect((await post('agent', { recipients: ['ana@example.com'] })).statusCode).toBe(403);
    expect(addRecipientPins).toHaveBeenCalledTimes(1);
  });

  it('refuses a body that adds no one, answers 404 for another account\'s Mission and 409 for one that has ended', async () => {
    const { post, addRecipientPins } = await makeApp();
    expect((await post('owner-key', {})).statusCode).toBe(400);
    expect((await post('owner-key', { recipients: ['ana@example.com'] }, 'ms_other')).statusCode).toBe(404);
    addRecipientPins.mockRejectedValueOnce(new ConflictError('This Mission has ended, so its recipients cannot be changed.'));
    expect((await post('owner-key', { recipients: ['ana@example.com'] })).statusCode).toBe(409);
  });
});
