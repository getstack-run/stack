import { describe, expect, it, vi } from 'vitest';
import { normalizePolicy, policyDigest } from '@stack/shared';
import { ControlPolicyService } from '@stack/vault';
import { planGrantListing } from './grant-listing.js';

const AGENT = 'agt_one';
const NEW_CONNECTION = 'scon_new';

const listed = (...ids: string[]) =>
  normalizePolicy({
    name: 'Current access',
    connections: { mode: 'listed', rules: ids.map((id, i) => ({ id: `connection-${i + 1}`, effect: 'allow', access: { connection_id: id, intents: [], constraints: [] } })) },
  });

const input = (extra: Record<string, unknown> = {}) => ({
  agent_id: AGENT,
  service_connection_id: NEW_CONNECTION,
  scopes: ['read'],
  ...extra,
});

function services(options: {
  controls?: boolean | Error;
  account?: boolean;
  policy?: { definition: ReturnType<typeof normalizePolicy>; revision?: number; source?: 'agent' | 'default'; id?: string } | null;
  ownRow?: boolean;
  planChange?: 'loosen' | 'unchanged';
} = {}) {
  const policy = options.policy === undefined ? { definition: listed('scon_old') } : options.policy;
  const planSet = vi.fn(async (args: { definition: ReturnType<typeof normalizePolicy> }) => ({
    change: options.planChange ?? 'loosen',
    needsApproval: true,
    expectedRevision: 3,
    next: args.definition,
  }));
  return {
    planSet,
    services: {
      entitlements: {
        controlsEnabled: vi.fn(async () => {
          if (options.controls instanceof Error) throw options.controls;
          return options.controls ?? true;
        }),
      },
      controlPolicyRepo: { accountOfAgent: vi.fn(async () => (options.account === false ? null : { accountId: 'acct_1', missionId: null })) },
      controlPolicies: {
        get: vi.fn(async () => (options.ownRow === false || !policy ? null : { id: policy.id ?? 'cpl_agent' })),
        effective: vi.fn(async () =>
          policy ? { id: policy.id ?? 'cpl_agent', revision: policy.revision ?? 3, source: policy.source ?? 'agent', definition: policy.definition } : null,
        ),
        planSet,
      },
    } as never,
  };
}

/**
 * The same plan through the real policy service over an in-memory repository: the revision the grant asks for is
 * one the service accepts (bounded, classified), is a loosening that needs the approval the grant already carries,
 * and applies at the revision it was judged at.
 */
describe('planning the policy listing through the real policy service', () => {
  const connections = new Map([['scon_old', 'custom_grocer'], [NEW_CONNECTION, 'custom_grocer']]);

  function realServices(definition: ReturnType<typeof normalizePolicy>) {
    let row: Record<string, unknown> = {
      id: 'cpl_agent',
      operator_id: 'op_1',
      agent_id: AGENT,
      name: definition.name,
      revision: 3,
      definition,
      last_change: 'create',
      status: 'active',
      created_at: new Date(),
      updated_at: new Date(),
    };
    const applied: Array<Record<string, unknown>> = [];
    const repo = {
      get: vi.fn(async (_op: string, agentId: string | null) => (agentId === AGENT ? row : null)),
      forAgent: vi.fn(async () => ({ agent: row, fallback: null })),
      connectionProviders: vi.fn(async (_op: string, ids: readonly string[]) => new Map(ids.filter((id) => connections.has(id)).map((id) => [id, connections.get(id)!]))),
      apply: vi.fn(async (input: { expectedRevision: number; next: { name: string; definition: unknown } | null; change: string }) => {
        if (input.expectedRevision !== row['revision']) throw new Error('This policy changed since it was read');
        applied.push(input as never);
        row = { ...row, revision: (row['revision'] as number) + 1, definition: input.next!.definition, last_change: input.change };
        return row;
      }),
    };
    const policies = new ControlPolicyService({ repo: repo as never, controls: { controlsEnabled: async () => true } });
    return {
      applied,
      services: {
        entitlements: { controlsEnabled: async () => true },
        controlPolicyRepo: { accountOfAgent: async () => ({ accountId: 'acct_1', missionId: null }) },
        controlPolicies: policies,
      } as never,
      policies,
    };
  }

  it('plans a loosening the service accepts, and applying it lists the connection at the next revision', async () => {
    const { services: s, policies, applied } = realServices(listed('scon_old'));
    const constraints = [{ path: 'url.pathname', op: 'starts_with' as const, value: '/v1/products' }];
    const listing = await planGrantListing(s, 'op_1', input({ constraints }) as never);
    expect(listing).not.toBeNull();
    expect(listing!.plan).toMatchObject({ change: 'loosen', needsApproval: true, expectedRevision: 3 });
    // The grant's approval is what authorizes it: without that, the service refuses a loosening.
    await expect(policies.apply(listing!.plan, { actor: 'operator_key', authorized: false })).rejects.toThrow(/needs a person to approve/);
    const row = await policies.apply(listing!.plan, { actor: 'operator_key', approvalId: 'gvr_1', authorized: true });
    expect(row).toMatchObject({ revision: 4 });
    expect(applied).toHaveLength(1);
    const stored = normalizePolicy((row as unknown as { definition: unknown }).definition);
    expect(stored.connections.rules.map((r) => r.access.connection_id)).toEqual(['scon_old', NEW_CONNECTION]);
    expect(policyDigest(stored)).toBe(listing!.ref.definition_digest);
    // The notice for the same connection is now gone: nothing is left to ask for.
    const again = await planGrantListing(s, 'op_1', input({ constraints }) as never);
    expect(again).toBeNull();
  });

  it('a revision that moved between the plan and the apply is refused, never applied over', async () => {
    const { services: s, policies } = realServices(listed('scon_old'));
    const listing = await planGrantListing(s, 'op_1', input() as never);
    await policies.apply(listing!.plan, { actor: 'operator_key', authorized: true });
    await expect(policies.apply(listing!.plan, { actor: 'operator_key', authorized: true })).rejects.toThrow(/changed since it was read/);
  });
});

describe('planning the policy listing a widened grant needs', () => {
  it('plans a revision that lists the connection within the grant\'s own constraints, bound by digest', async () => {
    const { services: s, planSet } = services();
    const constraints = [{ path: 'url.pathname', op: 'starts_with', value: '/v1/products' }];
    const result = await planGrantListing(s, 'op_1', input({ constraints }) as never);
    expect(result).not.toBeNull();
    const next = planSet.mock.calls[0]![0].definition;
    expect(next.connections.rules.map((r) => r.id)).toEqual(['connection-1', 'connection-2']);
    expect(next.connections.rules[1]).toMatchObject({ effect: 'allow', access: { connection_id: NEW_CONNECTION, constraints } });
    expect(planSet).toHaveBeenCalledWith(expect.objectContaining({ operatorId: 'op_1', agentId: AGENT, expectedRevision: 3 }));
    expect(result!.ref).toEqual({ policy_id: 'cpl_agent', expected_revision: 3, definition_digest: policyDigest(next) });
  });

  it('adds nothing but the grant\'s connection: every other rule of the policy is kept as it was', async () => {
    const before = listed('scon_old', 'scon_other');
    const { services: s, planSet } = services({ policy: { definition: before } });
    await planGrantListing(s, 'op_1', input() as never);
    const next = planSet.mock.calls[0]![0].definition;
    expect(next.connections.rules.slice(0, 2)).toEqual(before.connections.rules);
    expect(next.connections.rules).toHaveLength(3);
  });

  it('never edits the default policy, which governs other agents too', async () => {
    const { services: s, planSet } = services({ policy: { definition: listed('scon_old'), source: 'default' } });
    expect(await planGrantListing(s, 'op_1', input() as never)).toBeNull();
    expect(planSet).not.toHaveBeenCalled();
  });

  it.each([
    ['controls are off', { controls: false }],
    ['the agent is not an account agent', { account: false }],
    ['the agent has no policy of its own', { ownRow: false }],
    ['there is no policy', { policy: null }],
    ['the policy does not list connections', { policy: { definition: normalizePolicy({ name: 'Open', connections: { mode: 'any' } }) } }],
    ['the policy already lists the connection', { policy: { definition: listed('scon_old', NEW_CONNECTION) } }],
    ['the revision would change nothing', { planChange: 'unchanged' as const }],
  ] as const)('plans nothing when %s', async (_label, options) => {
    const { services: s } = services(options as never);
    expect(await planGrantListing(s, 'op_1', input() as never)).toBeNull();
  });

  it('never fails the grant: a policy that cannot be planned means the grant goes ahead on its own', async () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { services: s, planSet } = services();
    planSet.mockRejectedValueOnce(new Error('UNBOUNDED_SEND_RULE'));
    expect(await planGrantListing(s, 'op_1', input() as never)).toBeNull();
    const { services: broken } = services({ controls: new Error('billing account unreadable') });
    expect(await planGrantListing(broken, 'op_1', input() as never)).toBeNull();
    quiet.mockRestore();
  });
});
