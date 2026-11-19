import { describe, expect, it, vi } from 'vitest';
import { ForbiddenError } from '@stack/shared';
import { AgentService } from './agent-service.js';

describe('internal fleet agent isolation', () => {
  function fixture() {
    const root = { id: 'agt_root', operator_id: 'op_test', pubkey: { kty: 'OKP', crv: 'Ed25519', x: 'key' } };
    const worker = { ...root, id: 'agt_worker' };
    const repository = { findById: vi.fn(async () => root), update: vi.fn(), updateStatus: vi.fn(),
      findByOperatorId: vi.fn(async () => [root, worker]) };
    const service = Reflect.construct(AgentService, [repository]) as AgentService;
    service.setExternalAgentGuard(async (_operatorId, agentId) => {
      if (agentId === 'agt_root') throw new ForbiddenError();
    });
    return { service, repository };
  }

  it('rejects ordinary reads, enrollment and mutation before the repository writes', async () => {
    const { service, repository } = fixture();
    const attempts = [
      () => service.getById('agt_root'),
      () => service.getPublicSigningInfo('agt_root'),
      () => service.updateStatus('agt_root', 'active'),
      () => service.update('agt_root', 'op_test', { accountability_mode: 'standard' }),
      () => service.setPubkey('agt_root', { kty: 'OKP', crv: 'Ed25519', x: 'key' }),
      () => service.delete('agt_root', 'op_test'),
      () => service.allowSkill('agt_root', 'op_test', 'skill'),
      () => service.disallowSkill('agt_root', 'op_test', 'skill'),
    ];
    for (const attempt of attempts) await expect(attempt()).rejects.toBeInstanceOf(ForbiddenError);
    expect(repository.update).not.toHaveBeenCalled();
    expect(repository.updateStatus).not.toHaveBeenCalled();
  });

  it('hides root records without hiding infrastructure errors', async () => {
    const { service } = fixture();
    expect((await service.list('op_test')).map((agent) => agent.id)).toEqual(['agt_worker']);
    service.setExternalAgentGuard(async () => { throw new Error('unavailable'); });
    await expect(service.list('op_test')).rejects.toThrow('unavailable');
  });
});
