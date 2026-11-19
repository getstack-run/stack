import { describe, expect, it, vi } from 'vitest';
import { PassportRevokedError } from '@stack/shared';
import { PassportService, REVOCATION_CHANNEL } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

function makeService(opts?: { blocked?: boolean }) {
  const redisSets: unknown[][] = [];
  const published: Array<{ channel: string; body: string }> = [];
  const passportRepo = {
    findByJti: vi.fn(async () => ({
      jti: 'ppt_root', operator_id: 'op_test', agent_id: 'agt_root', session_id: 'ses_test',
      delegation_depth: 0, parent_passport_id: null, revoked_at: null,
      expires_at: new Date(Date.now() + 60_000),
    })),
    isRevoked: vi.fn(async () => false),
    revoke: vi.fn(async () => undefined),
    blockAgentAndRevokeChain: vi.fn(async () => [{
      jti: 'ppt_root',
      agent_id: 'agt_root',
      parent_passport_id: null,
      expires_at: new Date(Date.now() + 60_000),
    }, {
      jti: 'ppt_child',
      agent_id: 'agt_child',
      parent_passport_id: 'ppt_root',
      expires_at: new Date(Date.now() + 60_000),
    }]),
  };
  const agentRepo = {
    findById: vi.fn(async () => ({
      id: 'agt_root',
      operator_id: 'op_test',
      status: 'active',
      passport_blocked: opts?.blocked ?? false,
    })),
  };
  const signer = {
    verify: vi.fn(async () => ({
      jti: 'ppt_root',
      exp: Math.floor(Date.now() / 1000) + 60,
      stk: {
        operator_id: 'op_test',
        agent_id: 'agt_root',
        session_id: 'ses_test',
        delegation_depth: 0,
        services: [],
      },
    })),
  };
  const redis = {
    get: vi.fn(async () => null),
    pipeline() {
      return {
        set(...args: unknown[]) {
          redisSets.push(args);
          return this;
        },
        async exec() {
          return [];
        },
      };
    },
    async publish(channel: string, body: string) {
      published.push({ channel, body });
      return 1;
    },
  };
  const operatorRepo = {
    findById: vi.fn(async () => ({ id: 'op_test', status: 'active' })),
  };
  const service = new PassportService(
    passportRepo as never,
    agentRepo as never,
    {} as never,
    signer as never,
    redis as never,
    operatorRepo as never,
    '',
    { transaction: async (work: (tx: unknown) => unknown) => work({ execute: async () => undefined }) } as never,
    passportTestWiring().dependencies,
  );
  return { service, passportRepo, redisSets, published };
}

describe('PassportService agent blocking', () => {
  it('rejects online verification when the agent is blocked even if Redis has no marker yet', async () => {
    const { service, passportRepo } = makeService({ blocked: true });
    await expect(service.verify('signed-passport')).rejects.toBeInstanceOf(PassportRevokedError);
    expect(passportRepo.isRevoked).toHaveBeenCalledWith('ppt_root');
  });

  it('does not refresh a Passport belonging to a blocked agent', async () => {
    const { service } = makeService({ blocked: true });
    await expect(service.refresh('op_test', 'signed-passport')).rejects.toBeInstanceOf(PassportRevokedError);
  });

  it('writes Redis markers and one bulk event only after the database block returns', async () => {
    const { service, passportRepo, redisSets, published } = makeService();
    const result = await service.blockAgent('op_test', 'agt_root', 'Incident review');

    expect(result).toEqual({ revoked_count: 2 });
    expect(passportRepo.blockAgentAndRevokeChain).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_test',
      agentId: 'agt_root',
      reason: 'Incident review',
    }));
    expect(redisSets.map((args) => args[0])).toEqual(['revoked:ppt_root', 'revoked:ppt_child']);
    expect(published).toHaveLength(1);
    expect(published[0]?.channel).toBe(REVOCATION_CHANNEL);
    expect(JSON.parse(published[0]!.body)).toMatchObject({
      type: 'bulk_agent',
      operator_id: 'op_test',
      agent_id: 'agt_root',
      revoked_count: 1,
      cascaded_count: 1,
      reason: 'Incident review',
    });
  });
});
