import { describe, expect, it, vi } from 'vitest';
import { MISSION_RECIPIENT_ANY_PATH, MissionsService } from './missions.js';

describe('MissionsService lifecycle', () => {
  it('start posts the operator form unchanged and returns the bound passport', async () => {
    const result = {
      mission_id: 'ms_a', claim_id: 'pc_a', expires_at: '2026-10-01T12:00:00.000Z',
      passport: { token: 't', jti: 'pas_a', expires_at: '2026-10-01T11:15:00.000Z' },
    };
    const post = vi.fn(async () => result);
    const service = new MissionsService({ post } as never);
    const input = {
      agent_id: 'agt_a',
      mission: { intent_summary: 'Triage inbox', intent_services: ['gmail'], expires_in_seconds: 3600 },
      passport: { ttl_seconds: 600 },
    };

    const started = await service.start(input);

    expect(post).toHaveBeenCalledWith('/v1/missions/start', input);
    expect(started.passport.token).toBe('t');
  });

  it('open forwards agent_id, list filters by agent_id', async () => {
    const post = vi.fn(async () => ({ mission_id: 'ms_a', claim_id: 'pc_a', expires_at: 'x' }));
    const get = vi.fn(async () => ({ items: [] }));
    const service = new MissionsService({ post, get } as never);

    await service.open({ intent_summary: 'Triage inbox', agent_id: 'agt_a' });
    await service.list({ agent_id: 'agt_a', status: 'active' });

    expect(post).toHaveBeenCalledWith('/v1/missions', { intent_summary: 'Triage inbox', agent_id: 'agt_a' });
    expect(get).toHaveBeenCalledWith('/v1/missions?agent_id=agt_a&status=active');
  });
});

describe('MissionsService recipients', () => {
  const recipients = {
    recipients: ['Ana@example.com', '+14155550100'],
    recipient_pins: [{ path: 'url.pathname', op: 'eq' as const, value: '/v1/chats/42' }],
    reply_to_message: 'msg_abc',
  };

  it('open sends the recipient fields as given', async () => {
    const post = vi.fn(async () => ({ mission_id: 'ms_a', claim_id: 'pc_a', expires_at: 'x' }));
    const service = new MissionsService({ post } as never);

    await service.open({ intent_summary: 'Answer one customer', agent_id: 'agt_a', ...recipients });

    expect(post).toHaveBeenCalledWith('/v1/missions', { intent_summary: 'Answer one customer', agent_id: 'agt_a', ...recipients });
  });

  it('start sends the recipient fields inside the Mission spec', async () => {
    const post = vi.fn(async () => ({}));
    const service = new MissionsService({ post } as never);
    const input = { agent_id: 'agt_a', mission: { intent_summary: 'Answer one customer', ...recipients } };

    await service.start(input);

    expect(post).toHaveBeenCalledWith('/v1/missions/start', input);
  });

  it('get returns recipient_pins as the API sends them', async () => {
    const pins = [{ path: '*', op: 'in', value: ['ana@example.com'] }];
    const get = vi.fn(async () => ({ mission_id: 'ms_a', recipient_pins: pins }));
    const service = new MissionsService({ get } as never);

    const mission = await service.get('ms_a');

    expect(mission.recipient_pins).toEqual(pins);
    expect(MISSION_RECIPIENT_ANY_PATH).toBe('*');
  });
});

describe('MissionsService evidence reads', () => {
  it('uses the activity and Operator review routes', async () => {
    const get = vi.fn(async () => ({ items: [] }));
    const service = new MissionsService({ get } as never);

    await service.activity('ms_one/two');
    await service.listOperatorReviews('ms_one/two');

    expect(get).toHaveBeenNthCalledWith(1, '/v1/missions/ms_one%2Ftwo/replay');
    expect(get).toHaveBeenNthCalledWith(
      2,
      '/v1/missions/ms_one%2Ftwo/operator-reviews',
    );
  });

  it('downloads the exact signed Operator review bytes', async () => {
    const expected = new Uint8Array([0xd2, 0x84, 0x43]);
    const getBytes = vi.fn(async () => expected);
    const service = new MissionsService({ getBytes } as never);

    const actual = await service.downloadOperatorReview('ms_one/two', 'pc_review/one');

    expect(actual).toBe(expected);
    expect(getBytes).toHaveBeenCalledWith(
      '/v1/missions/ms_one%2Ftwo/operator-reviews/pc_review%2Fone/download',
    );
  });

  it('keeps replay and dossier reads as compatibility aliases', async () => {
    const get = vi.fn(async () => ({ items: [] }));
    const service = new MissionsService({ get } as never);

    await service.replay('ms_one');
    await service.listDossiers('ms_one');

    expect(get).toHaveBeenNthCalledWith(1, '/v1/missions/ms_one/replay');
    expect(get).toHaveBeenNthCalledWith(2, '/v1/missions/ms_one/operator-reviews');
  });

  it('keeps the old dossier response shape and excludes new review claims', async () => {
    const get = vi.fn(async () => ({
      items: [
        {
          claim_id: 'pc_old',
          claim_type: 'dossier',
          issued_at_ms: 1,
          claim: { type: 'dossier', narrative: 'old' },
        },
        {
          claim_id: 'pc_new',
          claim_type: 'operator_review',
          issued_at_ms: 2,
          claim: { type: 'operator_review', overall_judgment: 'new' },
        },
      ],
    }));
    const service = new MissionsService({ get } as never);

    const result = await service.listDossiers('ms_one');

    expect(result.items).toEqual([
      {
        claim_id: 'pc_old',
        operator_id: null,
        issued_at_ms: 1,
        body: { type: 'dossier', narrative: 'old' },
      },
    ]);
  });
});
