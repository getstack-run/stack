import { describe, expect, it, vi } from 'vitest';
import type { HttpClient } from '../client.js';
import { DropoffService } from './dropoffs.js';

function client(): HttpClient {
  return {
    get: vi.fn(async () => ({})),
    post: vi.fn(async () => ({})),
  } as unknown as HttpClient;
}

describe('DropoffService attribution contract', () => {
  it('sends verified-attribution selectors using the REST wire field names', async () => {
    const http = client();
    const service = new DropoffService(http);

    await service.deposit(
      'dof_one',
      'agt_producer',
      { value: 1 },
      { passportJti: 'pas_one', missionId: 'ms_one' },
    );

    expect(http.post).toHaveBeenCalledWith('/v1/dropoffs/dof_one/deposit', {
      agent_id: 'agt_producer',
      payload: { value: 1 },
      passport_jti: 'pas_one',
      mission_id: 'ms_one',
    }, undefined);
  });

  it('preserves the legacy unattributed deposit call shape', async () => {
    const http = client();
    const service = new DropoffService(http);

    await service.deposit('dof_one', 'agt_producer', { value: 1 });

    expect(http.post).toHaveBeenCalledWith('/v1/dropoffs/dof_one/deposit', {
      agent_id: 'agt_producer',
      payload: { value: 1 },
    }, undefined);
  });

  it('sends the Mission Passport as X-Passport-Token on create, deposit and collect', async () => {
    const http = client();
    const service = new DropoffService(http);
    const headers = { headers: { 'X-Passport-Token': 'jwt.passport.token' } };

    await service.create({ from_agent: 'agt_producer', to_agent: 'agt_consumer', schema: { type: 'object' } },
      { passportToken: 'jwt.passport.token' });
    expect(http.post).toHaveBeenLastCalledWith('/v1/dropoffs',
      { from_agent: 'agt_producer', to_agent: 'agt_consumer', schema: { type: 'object' } }, headers);

    await service.deposit('dof_one', 'agt_producer', { value: 1 }, { passportToken: 'jwt.passport.token' });
    expect(http.post).toHaveBeenLastCalledWith('/v1/dropoffs/dof_one/deposit',
      { agent_id: 'agt_producer', payload: { value: 1 } }, headers);

    await service.collect('dof_one', 'agt_consumer', { passportToken: 'jwt.passport.token' });
    expect(http.post).toHaveBeenLastCalledWith('/v1/dropoffs/dof_one/collect', { agent_id: 'agt_consumer' }, headers);
  });

  it('sends the drive files a deposit hands over, and only when given', async () => {
    const http = client();
    const service = new DropoffService(http);

    await service.deposit('dof_one', 'agt_producer', { value: 1 }, { driveFiles: ['drv_0123456789abcdef'] });
    expect(http.post).toHaveBeenLastCalledWith('/v1/dropoffs/dof_one/deposit', {
      agent_id: 'agt_producer',
      payload: { value: 1 },
      drive_files: ['drv_0123456789abcdef'],
    }, undefined);

    await service.deposit('dof_one', 'agt_producer', { value: 1 }, { passportToken: 'jwt.passport.token' });
    expect(http.post).toHaveBeenLastCalledWith('/v1/dropoffs/dof_one/deposit', {
      agent_id: 'agt_producer',
      payload: { value: 1 },
    }, { headers: { 'X-Passport-Token': 'jwt.passport.token' } });
  });

  it('returns the drive files a collect opens', async () => {
    const file = { id: 'drv_0123456789abcdef', trust: 'untrusted' };
    const http = { post: vi.fn(async () => ({ payload: { value: 1 }, drive_files: [file] })) } as unknown as HttpClient;
    const collected = await new DropoffService(http).collect('dof_one', 'agt_consumer');
    expect(collected.drive_files).toEqual([file]);
  });

  it('sends no passport header when none is given', async () => {
    const http = client();
    await new DropoffService(http).collect('dof_one', 'agt_consumer');
    expect(http.post).toHaveBeenLastCalledWith('/v1/dropoffs/dof_one/collect', { agent_id: 'agt_consumer' }, undefined);
  });
});
