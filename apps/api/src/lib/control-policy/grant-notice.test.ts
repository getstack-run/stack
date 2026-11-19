import { describe, expect, it, vi } from 'vitest';
import { normalizePolicy } from '@stack/shared';
import { grantControlPolicyNotice } from './grant-notice.js';

const AGENT = 'agt_one';
const CONNECTION = 'scon_new';

const listed = (...ids: string[]) =>
  normalizePolicy({
    name: 'Current access',
    connections: { mode: 'listed', rules: ids.map((id) => ({ id: `allow-${id}`, effect: 'allow', access: { connection_id: id, intents: [], constraints: [] } })) },
  });

function services(options: {
  controls?: boolean | Error;
  account?: boolean;
  policy?: { definition: ReturnType<typeof normalizePolicy>; revision?: number; source?: 'agent' | 'default' } | null;
} = {}) {
  const effective = vi.fn(async () =>
    options.policy === null
      ? null
      : { id: 'cpl_policy1', revision: options.policy?.revision ?? 3, source: options.policy?.source ?? 'agent', definition: (options.policy ?? { definition: listed('scon_old') }).definition },
  );
  return {
    effective,
    services: {
      entitlements: {
        controlsEnabled: vi.fn(async () => {
          if (options.controls instanceof Error) throw options.controls;
          return options.controls ?? true;
        }),
      },
      controlPolicyRepo: { accountOfAgent: vi.fn(async () => (options.account === false ? null : { accountId: 'acct_1', missionId: null })) },
      controlPolicies: { effective },
    } as never,
  };
}

describe('what a new grant still needs from the agent\'s policy', () => {
  it('names the policy and the revision that lists a connection granted after the policy', async () => {
    const { services: s } = services();
    expect(await grantControlPolicyNotice(s, 'op_1', AGENT, CONNECTION)).toMatchObject({
      policy_id: 'cpl_policy1',
      policy_revision: 3,
      source: 'agent',
      agent_id: AGENT,
      connection_id: CONNECTION,
      action_needed: 'list_connection',
      revision_needed: 4,
      message: expect.stringMatching(/cannot call the connection until a revision of policy cpl_policy1 after revision 3 lists it.*loosening.*browser/),
    });
  });

  it('says the same for the default policy that applies to the agent', async () => {
    const { services: s } = services({ policy: { definition: listed('scon_old'), revision: 7, source: 'default' } });
    expect(await grantControlPolicyNotice(s, 'op_1', AGENT, CONNECTION)).toMatchObject({ source: 'default', policy_revision: 7, revision_needed: 8 });
  });

  it.each([
    ['controls are off', { controls: false }],
    ['the agent is not an account agent', { account: false }],
    ['there is no policy', { policy: null }],
    ['the policy does not list connections', { policy: { definition: normalizePolicy({ name: 'Open', connections: { mode: 'any' } }) } }],
    ['the policy already lists the connection', { policy: { definition: listed('scon_old', CONNECTION) } }],
    ['the policy has a rule for the connection that denies it', { policy: { definition: normalizePolicy({ name: 'Deny', connections: { mode: 'listed', rules: [{ id: 'no', effect: 'deny', access: { connection_id: CONNECTION, intents: [], constraints: [] } }] } }) } }],
  ] as const)('adds nothing when %s', async (_label, options) => {
    const { services: s } = services(options as never);
    expect(await grantControlPolicyNotice(s, 'op_1', AGENT, CONNECTION)).toBeNull();
  });

  it('never fails the grant when the controls cannot be read', async () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { services: s } = services({ controls: new Error('billing account unreadable') });
    expect(await grantControlPolicyNotice(s, 'op_1', AGENT, CONNECTION)).toBeNull();
    quiet.mockRestore();
  });
});
