import { describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import { ControlLimitExceededError } from '@stack/shared';
import { createErrorHandler } from './error-handler.js';

// A Mission's money cap refuses a spend at the budget ledger's counter, wherever the spend reserved; the error handler is
// the one place every such refusal reaches, so the cap's behaviour follows there: pause (the default) pauses the Mission
// for its owner's review and the agent reads MISSION_PAUSED; end_mission and refuse_action answer the spend refusal.

async function answerFor(behavior: 'pause' | 'refuse_action' | 'end_mission' | null, error: Error) {
  const spendCapReached = vi.fn(async () => behavior);
  const app = Fastify({ logger: false });
  app.setErrorHandler(createErrorHandler({ missions: { spendCapReached } }));
  app.get('/spend', async () => { throw error; });
  try {
    const response = await app.inject({ method: 'GET', url: '/spend' });
    return { status: response.statusCode, body: response.json() as { error: { code: string; message: string; details?: Record<string, unknown> } }, spendCapReached };
  } finally {
    await app.close();
  }
}

const missionRefusal = () => new ControlLimitExceededError('mission', 'cents', 20, null, 'mission_spend', 'ms_spend');

describe('a spend the Mission\'s money cap refused', () => {
  it('pauses the Mission and answers MISSION_PAUSED when the cap pauses it', async () => {
    const { status, body, spendCapReached } = await answerFor('pause', missionRefusal());
    expect(spendCapReached).toHaveBeenCalledWith('ms_spend');
    expect(status).toBe(403);
    expect(body.error).toMatchObject({ code: 'MISSION_PAUSED', details: { mission_id: 'ms_spend', cap: 'coverage_cap_cents' } });
  });

  it.each(['refuse_action', 'end_mission'] as const)('answers the spend refusal when the cap is %s', async (behavior) => {
    const { status, body, spendCapReached } = await answerFor(behavior, missionRefusal());
    expect(spendCapReached).toHaveBeenCalledWith('ms_spend');
    expect(status).toBe(403);
    expect(body.error).toMatchObject({ code: 'CONTROL_LIMIT_EXCEEDED', message: "This action would pass the Mission's spend limit. Nothing was charged." });
    expect(JSON.stringify(body)).not.toContain('ms_spend');
  });

  it('asks nothing of the Missions for a policy limit that names no Mission', async () => {
    const { body, spendCapReached } = await answerFor('pause', new ControlLimitExceededError('day', 'cents', 0));
    expect(spendCapReached).not.toHaveBeenCalled();
    expect(body.error.code).toBe('CONTROL_LIMIT_EXCEEDED');
  });

  it('answers the refusal when the cap behaviour cannot be applied', async () => {
    const spendCapReached = vi.fn(async () => { throw new Error('database down'); });
    const app = Fastify({ logger: false });
    app.setErrorHandler(createErrorHandler({ missions: { spendCapReached } }));
    app.get('/spend', async () => { throw missionRefusal(); });
    try {
      const response = await app.inject({ method: 'GET', url: '/spend' });
      expect((response.json() as { error: { code: string } }).error.code).toBe('CONTROL_LIMIT_EXCEEDED');
    } finally {
      await app.close();
    }
  });
});
