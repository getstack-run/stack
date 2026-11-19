import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { agents, BillingAccountInactiveError, fleetMemberships, ForbiddenError } from '@stack/shared';
import { FleetService } from './fleet-service.js';

/**
 * a fleet enrollment draws its agent allowance from the BILLING
 * ACCOUNT (the resolver metering uses), not from the acting operator's own
 * `tier` column. A white-label tenant's row reads `free`; its allowance is its
 * partner's plan and overrides. An inactive billing account refuses.
 */

const OPERATOR = 'op_tenant';
const POLICY = 'flp_1';
const PROVISIONER = 'agt_provisioner';

function setup(opts: { activeAgents: number; resolve: () => Promise<unknown> }) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string };
  const challenge = 'challenge-bytes';
  const stored = JSON.stringify({
    operatorId: OPERATOR, policyId: POLICY, principalId: PROVISIONER, tokenDigest: null, revision: 1, challenge,
  });
  const policy = {
    id: POLICY, revision: 1, status: 'active', revoked_at: null, root_agent_id: 'agt_root',
    definition: {
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      provisioner_agent_ids: [PROVISIONER],
      max_members: 100,
      max_enrollments_per_hour: 100,
      identity_lease_seconds: 600,
      operation_rules: [],
    },
  };
  const inserted: unknown[] = [];

  function rowsFor(table: unknown, fields: Record<string, unknown> | undefined) {
    const counting = fields !== undefined && 'count' in fields;
    if (table === agents) {
      if (counting) return [{ count: opts.activeAgents }];
      return [{ id: PROVISIONER, operator_id: OPERATOR, status: 'active', passport_blocked: false }];
    }
    if (table === fleetMemberships) return counting ? [{ count: 0 }] : [];
    return [];
  }
  const db = {
    select: (fields?: Record<string, unknown>) => ({
      from: (table: unknown) => ({
        where: () => Object.assign(Promise.resolve(rowsFor(table, fields)), {
          for: async () => rowsFor(table, fields),
        }),
      }),
    }),
    insert: () => ({ values: async (value: unknown) => { inserted.push(value); } }),
  };
  const repo = {
    db,
    policy: async () => policy,
    rootForAgent: async () => undefined,
    withPolicy: async (_op: string, _id: string, work: (tx: unknown, p: unknown) => Promise<unknown>) => work(db, policy),
  };
  const redis = { get: async () => stored, eval: async () => 1 };
  const resolve = vi.fn(opts.resolve);
  const service = new FleetService({ repo, redis, entitlements: { resolve } } as never);
  const input = {
    idempotency_key: 'enroll-key-1',
    name: 'worker-1',
    public_key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    challenge_id: 'fec_1',
    proof: sign(null, Buffer.from(challenge), privateKey).toString('base64url'),
  };
  return { service, input, resolve, inserted };
}

const account = (agentsAllowed: number) => async () => ({ limits: { agents: agentsAllowed } });

describe('FleetService.enroll — agent allowance from the billing account', () => {
  it('enrolls while the billing account allowance has room, resolving the acting operator', async () => {
    const { service, input, resolve, inserted } = setup({ activeAgents: 1, resolve: account(2) });
    const result = await service.enroll(OPERATOR, POLICY, PROVISIONER, input);
    expect(result.agent_id).toMatch(/^agt_/);
    expect(resolve).toHaveBeenCalledWith(OPERATOR);
    expect(inserted).toHaveLength(2);
  });

  it('refuses once the billing account allowance is used up', async () => {
    const { service, input, inserted } = setup({ activeAgents: 2, resolve: account(2) });
    await expect(service.enroll(OPERATOR, POLICY, PROVISIONER, input)).rejects.toBeInstanceOf(ForbiddenError);
    expect(inserted).toHaveLength(0);
  });

  it('fails closed when the billing account is inactive', async () => {
    const { service, input, inserted } = setup({
      activeAgents: 0,
      resolve: async () => { throw new BillingAccountInactiveError(); },
    });
    await expect(service.enroll(OPERATOR, POLICY, PROVISIONER, input)).rejects.toBeInstanceOf(BillingAccountInactiveError);
    expect(inserted).toHaveLength(0);
  });
});
