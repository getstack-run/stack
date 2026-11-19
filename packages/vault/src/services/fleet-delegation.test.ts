import { describe, expect, it, vi } from 'vitest';
import { ForbiddenError } from '@stack/shared';
import { FleetService } from './fleet-service.js';
import { FleetAdmissionService } from './fleet-admission-service.js';
import type { PassportJWTPayload } from './passport-service.js';

// Any agent of an account may hand its own authority to any other agent of that account, a fleet's members included.
// A fleet's members still hold no unbound Passport of their own, and an agent of another account is never reached.

type Row = { id: string };

function fleetService(options: { member: boolean; root: boolean; owned: boolean }) {
  const repo = {
    rootForAgent: vi.fn(async () => (options.root ? { id: 'root' } : null)),
    membership: vi.fn(async () => (options.member ? { id: 'fmb_one' } : null)),
    db: { select: () => ({ from: () => ({ where: async (): Promise<Row[]> => (options.owned ? [{ id: 'agt_child' }] : []) }) }) },
  };
  return new FleetService({ repo, mission: {}, passport: {}, redis: {}, entitlements: {} } as never);
}

describe('delegating to a fleet member', () => {
  it('refuses a fleet member a Passport of its own', async () => {
    await expect(fleetService({ member: true, root: false, owned: true }).assertUnboundIssue('op_one', 'agt_child')).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('allows another agent of the account to hand a fleet member its own authority', async () => {
    await expect(fleetService({ member: true, root: false, owned: true }).assertUnboundIssue('op_one', 'agt_child', { delegated: true })).resolves.toBeUndefined();
  });

  it('allows it to an agent that is in no fleet', async () => {
    await expect(fleetService({ member: false, root: false, owned: true }).assertUnboundIssue('op_one', 'agt_child', { delegated: true })).resolves.toBeUndefined();
  });

  it('never reaches an agent of another account', async () => {
    await expect(fleetService({ member: true, root: false, owned: false }).assertUnboundIssue('op_one', 'agt_child', { delegated: true })).rejects.toBeInstanceOf(ForbiddenError);
    await expect(fleetService({ member: false, root: false, owned: false }).assertUnboundIssue('op_one', 'agt_child', { delegated: true })).rejects.toBeInstanceOf(ForbiddenError);
  });

  it("never gives a fleet's internal root a delegated Passport", async () => {
    await expect(fleetService({ member: false, root: true, owned: true }).assertUnboundIssue('op_one', 'agt_child', { delegated: true })).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('reads a delegated Passport (depth above zero) as delegated when it is checked again', async () => {
    const service = fleetService({ member: true, root: false, owned: true });
    const claims = (depth: number) => ({ jti: 'pp_one', stk: { operator_id: 'op_one', agent_id: 'agt_child', delegation_depth: depth } }) as unknown as PassportJWTPayload;
    await expect(service.validate(claims(1))).resolves.toBeUndefined();
    await expect(service.validate(claims(0))).rejects.toBeInstanceOf(ForbiddenError);
  });
});

describe('a delegated Passport held by a fleet member', () => {
  const claims = (depth: number) => ({ jti: 'pp_one', stk: { operator_id: 'op_one', agent_id: 'agt_child', delegation_depth: depth, mission_ids: ['ms_one'] } }) as unknown as PassportJWTPayload;
  const repoOf = (member: boolean, root = false) => ({ membership: vi.fn(async () => (member ? { id: 'fmb_one' } : null)), rootForAgent: vi.fn(async () => (root ? { id: 'root' } : null)) });
  const admission = (member: boolean, root = false) => new FleetAdmissionService({ repo: repoOf(member, root) } as never);
  const prepare = (service: FleetAdmissionService, depth: number) =>
    service.prepare({ claims: claims(depth), producer: 'proxy', operationKey: undefined, action: 'GET', normalizedRequest: {}, intent: {} } as never);

  it('is admitted as any unbound Passport is', async () => {
    await expect(prepare(admission(true), 1)).resolves.toBeNull();
  });

  it('is not a way for a member to hold one that nobody delegated', async () => {
    await expect(prepare(admission(true), 0)).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('is refused for the internal root whatever its depth', async () => {
    await expect(prepare(admission(false, true), 2)).rejects.toBeInstanceOf(ForbiddenError);
  });
});
