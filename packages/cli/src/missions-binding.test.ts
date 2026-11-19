import { beforeEach, describe, expect, it, vi } from 'vitest';

const output = vi.hoisted(() => ({ stdout: [] as string[], stderr: [] as string[] }));
vi.mock('node:process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:process')>();
  return {
    ...actual,
    exit: (code?: number) => { throw new Error(`exit ${code}`); },
    stdout: { write: (chunk: string) => { output.stdout.push(chunk); return true; } },
    stderr: { isTTY: false, write: (chunk: string) => { output.stderr.push(chunk); return true; } },
  };
});
vi.mock('./api.js', async (importOriginal) => ({
  ...await importOriginal<object>(),
  api: vi.fn(),
  requireToken: vi.fn(async () => 'synthetic-token'),
}));
vi.mock('./format.js', async (importOriginal) => ({ ...await importOriginal<object>(), printJson: vi.fn() }));

import { api } from './api.js';
import { cmdPassport, resolveSingleMissionId } from './passports.js';
import { cmdMissions } from './missions.js';
import { cmdPartner } from './partner.js';
import { quickstartMissionStartBody } from './quickstart.js';
import { MissionLease, proxyMissionStartBody, type MissionLeaseOps, type MissionStartResult } from './proxy-serve.js';

const apiMock = vi.mocked(api);

beforeEach(() => {
  vi.clearAllMocks();
  output.stdout.length = 0;
  output.stderr.length = 0;
});

describe('passport issue Mission binding', () => {
  it('accepts exactly one Mission through --mission or the --missions alias', () => {
    expect(resolveSingleMissionId('ms_a', undefined)).toEqual({ missionId: 'ms_a' });
    expect(resolveSingleMissionId(undefined, 'ms_a')).toEqual({ missionId: 'ms_a' });
    expect(resolveSingleMissionId(undefined, 'ms_a,ms_b')).toHaveProperty('error');
    expect(resolveSingleMissionId('ms_a,ms_b', undefined)).toHaveProperty('error');
    expect(resolveSingleMissionId(undefined, undefined)).toHaveProperty('error');
    expect(resolveSingleMissionId(true, undefined)).toHaveProperty('error');
    expect(resolveSingleMissionId('agt_x', undefined)).toHaveProperty('error');
    expect(resolveSingleMissionId('ms_a', 'ms_a')).toHaveProperty('error');
  });

  it('refuses to issue without a Mission and makes no API call', async () => {
    await expect(cmdPassport(['issue', '--agent', 'agt_x', '--intent', 'triage'])).rejects.toThrow('exit 2');
    expect(apiMock).not.toHaveBeenCalled();
    expect(output.stderr.join('')).toContain('--mission <ms_id>');
  });

  it('refuses several Missions on the --missions alias', async () => {
    await expect(cmdPassport(['issue', '--agent', 'agt_x', '--intent', 'triage', '--missions', 'ms_a,ms_b']))
      .rejects.toThrow('exit 2');
    expect(apiMock).not.toHaveBeenCalled();
  });

  it.each([['--mission'], ['--missions']])('binds one Mission and keeps the --services scope narrowing (%s)', async (flag) => {
    apiMock.mockImplementation(async (method: string, path: string) => {
      if (method === 'GET' && path === '/v1/agents/agt_x/permissions') return [
        { grant_id: 'g1', service_connection_id: 'sc_slack', provider: 'slack', scopes: ['chat:write'] },
        { grant_id: 'g2', service_connection_id: 'sc_gh', provider: 'github', scopes: ['repo'] },
      ];
      return { token: 'a.b.c', jti: 'pp_1', expires_at: new Date().toISOString() };
    });
    await cmdPassport(['issue', '--agent', 'agt_x', '--intent', 'triage', flag, 'ms_one', '--services', 'slack', '--json']);
    expect(apiMock).toHaveBeenLastCalledWith('POST', '/v1/passports/issue', { body: {
      agent_id: 'agt_x',
      mission_ids: ['ms_one'],
      intent: { summary: 'triage', services: ['slack'] },
      scopes: [{ service_connection_id: 'sc_slack', scopes: ['chat:write'] }],
    } });
  });
});

describe('missions open and start', () => {
  it('maps --agent to agent_id on open', async () => {
    apiMock.mockResolvedValue({ mission_id: 'ms_1', claim_id: 'mc_1', expires_at: new Date().toISOString() });
    await cmdMissions(['open', '--agent', 'agt_x', '--intent-summary', 'triage', '--services', 'slack', '--json']);
    expect(apiMock).toHaveBeenCalledWith('POST', '/v1/missions', { body: {
      intent_summary: 'triage', intent_services: ['slack'], agent_id: 'agt_x',
    } });
  });

  it('posts the operator form of start with --agent', async () => {
    apiMock.mockResolvedValue({
      mission_id: 'ms_1', claim_id: 'mc_1', expires_at: new Date().toISOString(),
      passport: { token: 'a.b.c', jti: 'pp_1', expires_at: new Date().toISOString() },
    });
    await cmdMissions(['start', '--agent', 'agt_x', '--intent-summary', 'triage', '--services', 'slack,github',
      '--expires-in', '1800', '--ttl', '600', '--json']);
    expect(apiMock).toHaveBeenCalledWith('POST', '/v1/missions/start', { body: {
      agent_id: 'agt_x',
      mission: { intent_summary: 'triage', intent_services: ['slack', 'github'], expires_in_seconds: 1800 },
      passport: { ttl_seconds: 600 },
    } });
  });

  it('omits passport fields on start when --ttl is absent', async () => {
    apiMock.mockResolvedValue({ mission_id: 'ms_1', claim_id: 'mc_1', expires_at: '', passport: { token: 't', jti: 'j', expires_at: '' } });
    await cmdMissions(['start', '--agent', 'agt_x', '--intent-summary', 'triage', '--json']);
    expect(apiMock).toHaveBeenCalledWith('POST', '/v1/missions/start', { body: {
      agent_id: 'agt_x', mission: { intent_summary: 'triage' },
    } });
  });

  it('sends who the Mission may send to on open: a list, repeatable pins and a message to reply to', async () => {
    apiMock.mockResolvedValue({ mission_id: 'ms_1', claim_id: 'mc_1', expires_at: new Date().toISOString() });
    await cmdMissions(['open', '--agent', 'agt_x', '--intent-summary', 'triage',
      '--recipients', 'Ana@example.com, ben@example.com',
      '--pin', 'url.pathname=/v1/chats/42', '--pin', 'body.cc=a@x.com,b@x.com', '--pin', '*=ana@example.com',
      '--reply-to', 'msg_1', '--json']);
    expect(apiMock).toHaveBeenCalledWith('POST', '/v1/missions', { body: {
      intent_summary: 'triage', agent_id: 'agt_x',
      recipients: ['Ana@example.com', 'ben@example.com'],
      recipient_pins: [
        { path: 'url.pathname', op: 'eq', value: '/v1/chats/42' },
        { path: 'body.cc', op: 'in', value: ['a@x.com', 'b@x.com'] },
        { path: '*', op: 'eq', value: 'ana@example.com' },
      ],
      reply_to_message: 'msg_1',
    } });
  });

  it('puts the recipient fields inside the Mission on start', async () => {
    apiMock.mockResolvedValue({ mission_id: 'ms_1', claim_id: 'mc_1', expires_at: '', passport: { token: 't', jti: 'j', expires_at: '' } });
    await cmdMissions(['start', '--agent', 'agt_x', '--intent-summary', 'triage', '--reply-to', 'msg_1', '--json']);
    expect(apiMock).toHaveBeenCalledWith('POST', '/v1/missions/start', { body: {
      agent_id: 'agt_x', mission: { intent_summary: 'triage', reply_to_message: 'msg_1' },
    } });
  });

  it.each([
    [['--pin', 'body.to']],
    [['--pin', '=a@x.com']],
    [['--pin']],
    [['--pin', 'body.to=a@x.com', '--pin', 'body.to=b@x.com']],
    [['--recipients']],
    [['--reply-to']],
  ])('refuses a bad recipient flag (%j) before any request', async (flags) => {
    await expect(cmdMissions(['open', '--intent-summary', 'triage', ...flags])).rejects.toThrow('exit 2');
    expect(apiMock).not.toHaveBeenCalled();
    expect(output.stderr.join('')).toContain('usage: ');
  });

  it('requires --intent-summary on the operator form of start', async () => {
    await expect(cmdMissions(['start', '--agent', 'agt_x'])).rejects.toThrow('exit 2');
    expect(apiMock).not.toHaveBeenCalled();
  });
});

describe('partner account issue-passport', () => {
  it('requires one Mission and sends it as mission_ids', async () => {
    await expect(cmdPartner(['account', 'issue-passport', '--account', 'op_t', '--agent', 'agt_x'])).rejects.toThrow('exit 2');
    expect(apiMock).not.toHaveBeenCalled();
    apiMock.mockResolvedValue({});
    await cmdPartner(['account', 'issue-passport', '--account', 'op_t', '--agent', 'agt_x', '--mission', 'ms_t']);
    expect(apiMock).toHaveBeenCalledWith('POST', '/v1/partner/accounts/op_t/passports/issue', { body: {
      agent_id: 'agt_x', mission_ids: ['ms_t'],
    } });
  });
});

describe('quickstart and proxy serve start bodies', () => {
  it('quickstart opens one short Mission for the provider', () => {
    expect(quickstartMissionStartBody('agt_x', 'openai')).toEqual({
      agent_id: 'agt_x',
      mission: { intent_summary: 'quickstart: one governed openai call', intent_services: ['openai'], expires_in_seconds: 900 },
    });
  });

  it('proxy serve opens a Mission with an explicit expiry', () => {
    expect(proxyMissionStartBody('agt_x', ['anthropic', 'openai'], 3600)).toEqual({
      agent_id: 'agt_x',
      mission: {
        intent_summary: 'proxy serve: governed LLM calls (anthropic, openai)',
        intent_services: ['anthropic', 'openai'],
        expires_in_seconds: 3600,
      },
    });
  });
});

describe('MissionLease', () => {
  const T0 = Date.parse('2026-10-01T00:00:00Z');
  const iso = (offsetSeconds: number) => new Date(T0 + offsetSeconds * 1000).toISOString();
  const started = (id: string, missionAt: number, passportAt: number, token: string): MissionStartResult => ({
    mission_id: id, expires_at: iso(missionAt), passport: { token, jti: `pp_${token}`, expires_at: iso(passportAt) },
  });

  function harness() {
    let now = T0;
    const ops = {
      start: vi.fn<MissionLeaseOps['start']>()
        .mockResolvedValueOnce(started('ms_1', 3600, 900, 't1'))
        .mockResolvedValueOnce(started('ms_2', 7200, 4500, 't3')),
      refresh: vi.fn<MissionLeaseOps['refresh']>(async () => ({ token: 't2', expires_at: iso(1800) })),
      get: vi.fn<MissionLeaseOps['get']>(async () => ({ revoked_at: null })),
      complete: vi.fn<MissionLeaseOps['complete']>(async () => ({})),
      now: () => now,
    };
    return { ops, setNow: (seconds: number) => { now = T0 + seconds * 1000; } };
  }

  it('uses the issued token, refreshes near passport expiry, rotates before Mission expiry, completes on close', async () => {
    const { ops, setNow } = harness();
    const lease = await MissionLease.open(ops);
    expect(await lease.getToken()).toBe('t1');
    expect(ops.refresh).not.toHaveBeenCalled();

    setNow(850);
    expect(await lease.getToken()).toBe('t2');
    expect(ops.refresh).toHaveBeenCalledWith('t1');

    setNow(3490);
    const [a, b] = await Promise.all([lease.getToken(), lease.getToken()]);
    expect([a, b]).toEqual(['t3', 't3']);
    expect(ops.start).toHaveBeenCalledTimes(2);
    expect(ops.get).toHaveBeenCalledWith('ms_1');
    expect(ops.complete).toHaveBeenCalledWith('ms_1');
    expect(lease.currentMissionId).toBe('ms_2');

    await lease.close();
    expect(ops.complete).toHaveBeenLastCalledWith('ms_2');
    await expect(lease.getToken()).rejects.toThrow('shutting down');
  });

  it('never replaces a Mission the operator revoked', async () => {
    const { ops, setNow } = harness();
    ops.get.mockResolvedValue({ revoked_at: iso(100) });
    const lease = await MissionLease.open(ops);
    setNow(3490);
    await expect(lease.getToken()).rejects.toThrow('was revoked');
    await expect(lease.getToken()).rejects.toThrow('was revoked');
    expect(ops.start).toHaveBeenCalledTimes(1);
    await lease.close();
    expect(ops.complete).not.toHaveBeenCalled();
  });

  it('surfaces a refresh refusal instead of opening a new Mission', async () => {
    const { ops, setNow } = harness();
    ops.refresh.mockRejectedValueOnce(new Error('Mission ms_1 is completed'));
    const lease = await MissionLease.open(ops);
    setNow(850);
    await expect(lease.getToken()).rejects.toThrow('is completed');
    expect(ops.start).toHaveBeenCalledTimes(1);
  });
});

describe('a Mission a cap paused, and its making allowance', () => {
  it('sends the owner\'s review, with the new limit only for raise, and refuses a bad one before any call', async () => {
    apiMock.mockResolvedValue({ mission_id: 'ms_a', decision: 'raise', result: 'raised' });
    await cmdMissions(['review', 'ms_a', '--decision', 'raise', '--limit', '500', '--json']);
    await cmdMissions(['review', 'ms_a', '--decision', 'continue', '--json']);
    expect(apiMock.mock.calls).toEqual([
      ['POST', '/v1/missions/ms_a/review', { body: { decision: 'raise', limit: 500 } }],
      ['POST', '/v1/missions/ms_a/review', { body: { decision: 'continue' } }],
    ]);
    apiMock.mockClear();
    await expect(cmdMissions(['review', 'ms_a', '--decision', 'raise'])).rejects.toThrow('exit 2');
    await expect(cmdMissions(['review', 'ms_a', '--decision', 'close', '--limit', '5'])).rejects.toThrow('exit 2');
    await expect(cmdMissions(['review', 'ms_a', '--decision', 'pause'])).rejects.toThrow('exit 2');
    expect(apiMock).not.toHaveBeenCalled();
  });

  it('sets the making allowance in cents, or removes it with --none', async () => {
    apiMock.mockResolvedValue({ mission_id: 'ms_a', making_orders_up_to_cents: 25_000 });
    await cmdMissions(['making-allowance', 'ms_a', '--cents', '25000', '--json']);
    await cmdMissions(['making-allowance', 'ms_a', '--none', '--json']);
    expect(apiMock.mock.calls).toEqual([
      ['PUT', '/v1/missions/ms_a/making-allowance', { body: { making_orders_up_to_cents: 25_000 } }],
      ['PUT', '/v1/missions/ms_a/making-allowance', { body: { making_orders_up_to_cents: null } }],
    ]);
    apiMock.mockClear();
    await expect(cmdMissions(['making-allowance', 'ms_a'])).rejects.toThrow('exit 2');
    await expect(cmdMissions(['making-allowance', 'ms_a', '--none', '--cents', '1'])).rejects.toThrow('exit 2');
    expect(apiMock).not.toHaveBeenCalled();
  });
});

describe('missions add-recipients', () => {
  it('posts the recipient flags given to the running Mission, and nothing when none is given', async () => {
    apiMock.mockResolvedValueOnce({ mission_id: 'ms_a', recipient_pins: [] } as never);
    await cmdMissions(['add-recipients', 'ms_a', '--recipients', 'ana@example.com,bob@example.com', '--pin', 'body.to=c@example.com', '--json']);
    expect(apiMock).toHaveBeenCalledWith('POST', '/v1/missions/ms_a/recipients', {
      body: {
        recipients: ['ana@example.com', 'bob@example.com'],
        recipient_pins: [{ path: 'body.to', op: 'eq', value: 'c@example.com' }],
      },
    });
    await expect(cmdMissions(['add-recipients', 'ms_a'])).rejects.toThrow('exit 2');
    await expect(cmdMissions(['add-recipients'])).rejects.toThrow('exit 2');
    expect(apiMock).toHaveBeenCalledTimes(1);
  });
});
