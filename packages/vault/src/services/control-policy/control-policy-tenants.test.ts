import { describe, expect, it, vi } from 'vitest';
import { ConflictError, startingPolicyFromGrants } from '@stack/shared';
import type { ControlPolicyRepository } from '../../repositories/control-policy-repo.js';
import { ControlPolicyService } from './control-policy-service.js';

// The tenant pass of switching controls on, with the storage faked: which
// tenants it visits, what it skips and what it never lets stop the rest. The
// same pass against PostgreSQL is partner-controls.postgres.test.ts.

function world(options: { tenants: string[]; agents: Record<string, string[]>; controls: Record<string, boolean | Error> }) {
  const applied: Array<{ operatorId: string; agentId: string | null }> = [];
  const repo = {
    get: vi.fn(async () => null),
    accountAgents: vi.fn(async (operatorId: string) => options.agents[operatorId] ?? []),
    grantsOf: vi.fn(async (_operatorId: string, agentId: string) => [{ connection_id: `scon_${agentId}`, constraints: null }]),
    tenantsOf: vi.fn(async () => options.tenants),
    apply: vi.fn(async (input: { operatorId: string; agentId: string | null }) => {
      applied.push({ operatorId: input.operatorId, agentId: input.agentId });
      return {};
    }),
  };
  const controls = {
    controlsEnabled: vi.fn(async (operatorId: string) => {
      const answer = options.controls[operatorId];
      if (answer instanceof Error) throw answer;
      return answer ?? false;
    }),
  };
  const service = new ControlPolicyService({ repo: repo as unknown as ControlPolicyRepository, controls });
  return { service, repo, controls, applied };
}

describe('starting policies for a partner and its tenants', () => {
  it('starts the partner\'s own agents and each tenant\'s, every one under its own operator', async () => {
    const { service, applied } = world({
      tenants: ['op_t1', 'op_t2'],
      agents: { op_p: ['agt_p'], op_t1: ['agt_t1'], op_t2: ['agt_t2a', 'agt_t2b'] },
      controls: { op_t1: true, op_t2: true },
    });
    expect((await service.ensureStartingPoliciesWithTenants('op_p', 'controls_subscription')).sort()).toEqual(['agt_p', 'agt_t1', 'agt_t2a', 'agt_t2b']);
    expect(applied).toEqual([
      { operatorId: 'op_p', agentId: 'agt_p' },
      { operatorId: 'op_t1', agentId: 'agt_t1' },
      { operatorId: 'op_t2', agentId: 'agt_t2a' },
      { operatorId: 'op_t2', agentId: 'agt_t2b' },
    ]);
  });

  it('skips a tenant whose controls are off', async () => {
    const { service, applied } = world({
      tenants: ['op_t1', 'op_t2'],
      agents: { op_t1: ['agt_t1'], op_t2: ['agt_t2'] },
      controls: { op_t1: false, op_t2: true },
    });
    expect(await service.ensureStartingPoliciesWithTenants('op_p', 'x')).toEqual(['agt_t2']);
    expect(applied.map((a) => a.operatorId)).toEqual(['op_t2']);
  });

  it('tries every tenant when one cannot be read, then reports the first failure', async () => {
    const unreadable = new Error('billing account unreadable');
    const { service, applied } = world({
      tenants: ['op_t1', 'op_t2', 'op_t3'],
      agents: { op_t1: ['agt_t1'], op_t2: ['agt_t2'], op_t3: ['agt_t3'] },
      controls: { op_t1: true, op_t2: unreadable, op_t3: true },
    });
    await expect(service.ensureStartingPoliciesWithTenants('op_p', 'x')).rejects.toBe(unreadable);
    expect(applied.map((a) => a.operatorId)).toEqual(['op_t1', 'op_t3']);
  });

  it('a policy created at the same moment elsewhere is not a failure', async () => {
    const { service, repo } = world({ tenants: ['op_t1'], agents: { op_t1: ['agt_t1', 'agt_t2'] }, controls: { op_t1: true } });
    repo.apply.mockRejectedValueOnce(new ConflictError('exists'));
    expect(await service.ensureStartingPoliciesWithTenants('op_p', 'x')).toEqual(['agt_t2']);
  });

  it('a tenant\'s starting policy lists only that tenant\'s grants', async () => {
    const { service, repo } = world({ tenants: ['op_t1'], agents: { op_t1: ['agt_t1'] }, controls: { op_t1: true } });
    await service.ensureStartingPoliciesWithTenants('op_p', 'x');
    const stored = repo.apply.mock.calls[0]![0] as unknown as { next: { definition: unknown } };
    expect(stored.next.definition).toEqual(JSON.parse(JSON.stringify(startingPolicyFromGrants('Current access', [{ connection_id: 'scon_agt_t1', constraints: null }]))));
    expect(repo.grantsOf).toHaveBeenCalledWith('op_t1', 'agt_t1');
  });
});
