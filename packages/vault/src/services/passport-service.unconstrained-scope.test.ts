import { describe, it, expect, beforeAll } from 'vitest';
import { PassportSigner } from '../crypto/passport-signer.js';
import { PassportService } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';
import type { SecurityEventService } from './security-event-service.js';

/** every agent Passport is bound to exactly one live Mission. */
const TEST_MISSION_ID = 'ms_test_live';
function liveMissionLookup(operatorId: string) {
  return {
    findById: async (missionId: string) => ({
      mission_id: missionId, operator_id: operatorId, intent_services: [] as string[],
      expires_at: new Date(Date.now() + 3_600_000), completed_at: null, revoked_at: null,
    }),
  };
}

/**
 * a scope with no policy is never silently wide open.
 *
 * A ServiceScope carrying no constraints grants the whole provider: the proxy
 * skips its constraint block by an explicit early-out, so any method, any path
 * and any body on that provider's hosts is permitted. That is a legal grant and
 * occasionally the intended one, so issuance still succeeds — but it stops
 * being silent. Issuing records a `unconstrained_scope` warning naming the
 * services, deduped per (agent, service set) so a 15-minute TTL does not
 * produce four identical warnings an hour.
 *
 * Coverage:
 *   U1: an unconstrained scope records the warning, and issuance still succeeds
 *   U2: the warning names every unconstrained service and no constrained one
 *   U3: a fully constrained scope records nothing
 *   U4: the warning carries the passport's own jti (so the signed
 *       detector_signal claim lands in the chain the passport is judged by)
 *   U5: a dedup key + window are set, and are stable per (agent, service set)
 *   U6: a failure to record the warning never fails a correct issuance
 */

const OPERATOR_ID = 'op_unconstrained_test';
const SYSTEM_OP = 'op_stack_system';

const ACTIVE_AGENT = {
  id: 'agt_test',
  operator_id: OPERATOR_ID,
  status: 'active' as const,
  passport_blocked: false,
  accountability_mode: 'standard' as const,
  name: 'agent',
  pubkey: null,
};

type RecordedEvent = Parameters<SecurityEventService['record']>[0];

/** A granted service whose grant carries `constraints` verbatim. */
function grantFor(provider: string, constraints: unknown[]) {
  return {
    grant: {
      service_connection_id: `scon_${provider}`,
      scopes: ['*'],
      constraints,
    },
    connection: {
      id: `scon_${provider}`,
      service_id: `svc_${provider}`,
      provider,
      status: 'active',
      credential_ref: `ref_${provider}`,
    },
  };
}

const PINNED = [{ path: 'method', op: 'eq', value: 'POST' }];

function makeService(
  signer: PassportSigner,
  grants: ReturnType<typeof grantFor>[],
  opts?: { recordThrows?: boolean },
): { svc: PassportService; events: RecordedEvent[] } {
  const passportRepo = {
    create: async (row: Record<string, unknown>) => row,
    findByJti: async () => null,
    findActiveChildren: async () => [],
    revoke: async () => undefined,
    isRevoked: async () => false,
  } as unknown as ConstructorParameters<typeof PassportService>[0];

  const agentRepo = {
    findById: async (id: string) => (id === ACTIVE_AGENT.id ? { ...ACTIVE_AGENT, id } : null),
  } as unknown as ConstructorParameters<typeof PassportService>[1];

  const serviceRepo = {
    findGrantsByAgent: async () => [],
    findConnectionById: async () => null,
    findGrantsWithConnectionByAgent: async () => grants,
  } as unknown as ConstructorParameters<typeof PassportService>[2];

  const redis = {
    set: async () => 'OK',
    get: async () => null,
    publish: async () => 1,
    pipeline: () => ({ set: () => undefined, exec: async () => [] }),
  } as unknown as ConstructorParameters<typeof PassportService>[4];

  const operatorRepo = {
    findById: async (id: string) => (
      id === OPERATOR_ID ? { id, status: 'active', is_platform_staff: false } : null
    ),
  } as unknown as ConstructorParameters<typeof PassportService>[5];
  const db = {
    transaction: async <T>(work: (tx: { execute: () => Promise<unknown> }) => Promise<T>) =>
      work({ execute: async () => undefined }),
  } as unknown as ConstructorParameters<typeof PassportService>[7];

  const events: RecordedEvent[] = [];
  const securityEvent = {
    record: async (input: RecordedEvent) => {
      if (opts?.recordThrows) throw new Error('security event store unavailable');
      events.push(input);
      return null;
    },
  } as unknown as SecurityEventService;

  const svc = new PassportService(
    passportRepo,
    agentRepo,
    serviceRepo,
    signer,
    redis,
    operatorRepo,
    SYSTEM_OP,
    db,
    passportTestWiring({ missionLookup: liveMissionLookup(OPERATOR_ID), securityEvent }).dependencies,
  );
  return { svc, events };
}

describe('PassportService — unconstrained scope warning at issue time', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  it('U1: an unconstrained scope warns, and the passport is still issued', async () => {
    const { svc, events } = makeService(signer, [grantFor('stripe', [])]);
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: ACTIVE_AGENT.id });

    expect(issued.token).toBeTruthy();
    expect(events).toHaveLength(1);
    expect(events[0]!.signalType).toBe('unconstrained_scope');
    expect(events[0]!.severity).toBe('warning');
  });

  it('U2: the warning names every unconstrained service and no constrained one', async () => {
    const { svc, events } = makeService(signer, [
      grantFor('stripe', []),
      grantFor('resend', PINNED),
      grantFor('slack', []),
    ]);
    await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: ACTIVE_AGENT.id });

    expect(events).toHaveLength(1);
    expect(events[0]!.metadata?.services).toEqual(['slack', 'stripe']);
    expect(events[0]!.message).toContain('slack');
    expect(events[0]!.message).toContain('stripe');
    expect(events[0]!.message).not.toContain('resend');
  });

  it('U3: a fully constrained scope records nothing', async () => {
    const { svc, events } = makeService(signer, [
      grantFor('resend', PINNED),
      grantFor('stripe', PINNED),
    ]);
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: ACTIVE_AGENT.id });

    expect(issued.token).toBeTruthy();
    expect(events).toHaveLength(0);
  });

  it('U4: the warning carries the issued passport\'s own jti', async () => {
    const { svc, events } = makeService(signer, [grantFor('stripe', [])]);
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: ACTIVE_AGENT.id });

    expect(events[0]!.passportJti).toBe(issued.jti);
    expect(events[0]!.agentId).toBe(ACTIVE_AGENT.id);
    expect(events[0]!.operatorId).toBe(OPERATOR_ID);
  });

  it('U5: dedup is keyed on (agent, service set) with an hour window', async () => {
    const { svc, events } = makeService(signer, [grantFor('stripe', []), grantFor('slack', [])]);
    await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: ACTIVE_AGENT.id });
    await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: ACTIVE_AGENT.id });

    // The gate itself lives in SecurityEventService (Redis SETNX); what this
    // asserts is that the producer hands it a key that is stable across
    // re-issues of the same shape, so the gate can actually suppress.
    expect(events[0]!.dedupKey).toBe(`unconstrained_scope:${ACTIVE_AGENT.id}:slack,stripe`);
    expect(events[1]!.dedupKey).toBe(events[0]!.dedupKey);
    expect(events[0]!.dedupWindowSeconds).toBe(3600);
  });

  it('U6: a failure to record the warning does not fail the issuance', async () => {
    const { svc } = makeService(signer, [grantFor('stripe', [])], { recordThrows: true });
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: ACTIVE_AGENT.id });
    expect(issued.token).toBeTruthy();
  });
});
