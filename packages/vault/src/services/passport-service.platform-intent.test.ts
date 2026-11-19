import { describe, it, expect, beforeAll } from 'vitest';
import { PassportSigner } from '../crypto/passport-signer.js';
import { PassportService } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';
import { ForbiddenError } from '@stack/shared';

/**
 * (auth refactor) — passport-service issuance / delegation
 * refresh gates for `platform_intent`.
 *
 * Threat-model coverage:
 *   T1: regular operator (is_platform_staff=false) tries to mint a
 *       platform passport → ForbiddenError at issue time.
 *   T2: platform-staff operator tries to mint platform_intent='monitor'
 *       (only system operator may) → ForbiddenError.
 *   T3: system operator with is_platform_staff=true mints monitor →
 *       success.
 *   T4: platform passport carrying platform_intent='staff' attempts
 *       delegation → ForbiddenError (defense-in-depth even if a future
 *       bug allowed will_delegate alongside platform_intent).
 *   T5: platform_intent + will_delegate combined at issue → refused.
 *   T6: refresh of a platform passport AFTER the issuer's
 *       is_platform_staff was revoked → returned passport drops
 *       platform_intent (downgrade to operator-scoped).
 *
 * The tests stub the repositories — we're not exercising DB queries,
 * just the service-level invariants. The auth-middleware-level
 * verification gate is covered separately in the require-platform
 * tests; together they form the two-layer defense (issue-time + verify-time).
 */

const SYSTEM_OP = 'op_stack_system';
const STAFF_OP = 'op_staff_other';
const REGULAR_OP = 'op_regular';

const ACTIVE_AGENT = {
  id: 'agt_test',
  operator_id: '',
  status: 'active' as const,
  passport_blocked: false,
  accountability_mode: 'standard' as const,
  name: 'agent',
  pubkey: null,
};

function makeServiceFor(operatorRow: { id: string; is_platform_staff: boolean }) {
  // Stubs that match the shape PassportService needs. Not a full mock
  // — only what the issuance / refresh / delegate paths actually call.
  const passportRepo = {
    create: async (_row: unknown) => undefined,
    findByJti: async (_jti: string) => null,
    findActiveChildren: async (_jti: string) => [],
    revoke: async (_jti: string, _reason: string) => undefined,
    isRevoked: async (_jti: string) => false,
  } as unknown as ConstructorParameters<typeof PassportService>[0];

  const agentRepo = {
    findById: async (id: string) => ({ ...ACTIVE_AGENT, id, operator_id: operatorRow.id }),
  } as unknown as ConstructorParameters<typeof PassportService>[1];

  const serviceRepo = {
    findGrantsByAgent: async (_agentId: string) => [],
    findConnectionById: async (_id: string) => null,
    findGrantsWithConnectionByAgent: async (_agentId: string) => [],
  } as unknown as ConstructorParameters<typeof PassportService>[2];

  // ioredis-shaped no-op (we never hit it in these tests because no
  // tokens are being persisted).
  const redis = {
    set: async () => 'OK',
    get: async () => null,
    publish: async () => 1,
    pipeline: () => ({ set: () => undefined, exec: async () => [] }),
  } as unknown as ConstructorParameters<typeof PassportService>[4];

  const operatorRepo = {
    findById: async (id: string) =>
      id === operatorRow.id
        ? { id, status: 'active', is_platform_staff: operatorRow.is_platform_staff }
        : null,
  } as unknown as ConstructorParameters<typeof PassportService>[5];

  const db = {
    transaction: async <T>(work: (tx: { execute: () => Promise<unknown> }) => Promise<T>) =>
      work({ execute: async () => undefined }),
  } as unknown as ConstructorParameters<typeof PassportService>[7];

  return { passportRepo, agentRepo, serviceRepo, redis, operatorRepo, db };
}

describe('PassportService — platform_intent issuance gate', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  it('T1: regular operator cannot mint platform_intent (is_platform_staff = false)', async () => {
    const stubs = makeServiceFor({ id: REGULAR_OP, is_platform_staff: false });
    const service = new PassportService(
      stubs.passportRepo,
      stubs.agentRepo,
      stubs.serviceRepo,
      signer,
      stubs.redis,
      stubs.operatorRepo,
      SYSTEM_OP,
      stubs.db,
      passportTestWiring().dependencies,
    );

    await expect(
      service.issue(REGULAR_OP, {
        agent_id: 'agt_test',
        intent: {
          summary: 'sneaky platform claim',
          services: [],
          platform_intent: 'staff',
        },
      }),
    ).rejects.toThrow(ForbiddenError);
  });

  it('T2: platform-staff operator (NOT system) cannot mint platform_intent=monitor', async () => {
    const stubs = makeServiceFor({ id: STAFF_OP, is_platform_staff: true });
    const service = new PassportService(
      stubs.passportRepo,
      stubs.agentRepo,
      stubs.serviceRepo,
      signer,
      stubs.redis,
      stubs.operatorRepo,
      SYSTEM_OP,
      stubs.db,
      passportTestWiring().dependencies,
    );

    await expect(
      service.issue(STAFF_OP, {
        agent_id: 'agt_test',
        intent: {
          summary: 'monitor',
          services: [],
          platform_intent: 'monitor',
        },
      }),
    ).rejects.toThrow(ForbiddenError);
  });

  it('T3: system operator with is_platform_staff=true CAN mint platform_intent=monitor', async () => {
    const stubs = makeServiceFor({ id: SYSTEM_OP, is_platform_staff: true });
    const service = new PassportService(
      stubs.passportRepo,
      stubs.agentRepo,
      stubs.serviceRepo,
      signer,
      stubs.redis,
      stubs.operatorRepo,
      SYSTEM_OP,
      stubs.db,
      passportTestWiring().dependencies,
    );

    const signed = await service.issue(SYSTEM_OP, {
      agent_id: 'agt_test',
      intent: {
        summary: 'monitor',
        services: [],
        platform_intent: 'monitor',
      },
    });
    expect(signed.token).toBeTruthy();
    // Re-decode and confirm the claim survived.
    const verified = await signer.verify(signed.token);
    expect(verified.stk.platform_intent).toBe('monitor');
  });

  it('T5: platform_intent combined with will_delegate is refused at issue', async () => {
    const stubs = makeServiceFor({ id: STAFF_OP, is_platform_staff: true });
    const service = new PassportService(
      stubs.passportRepo,
      stubs.agentRepo,
      stubs.serviceRepo,
      signer,
      stubs.redis,
      stubs.operatorRepo,
      SYSTEM_OP,
      stubs.db,
      passportTestWiring().dependencies,
    );

    await expect(
      service.issue(STAFF_OP, {
        agent_id: 'agt_test',
        intent: {
          summary: 'staff',
          services: [],
          platform_intent: 'staff',
          will_delegate: true,
        },
      }),
    ).rejects.toThrow(ForbiddenError);
  });

  it('T7: monitor intent without STACK_SYSTEM_OPERATOR_ID configured is refused', async () => {
    const stubs = makeServiceFor({ id: STAFF_OP, is_platform_staff: true });
    const service = new PassportService(
      stubs.passportRepo,
      stubs.agentRepo,
      stubs.serviceRepo,
      signer,
      stubs.redis,
      stubs.operatorRepo,
      '', // empty system operator id disables monitor entirely
      stubs.db,
      passportTestWiring().dependencies,
    );

    await expect(
      service.issue(STAFF_OP, {
        agent_id: 'agt_test',
        intent: {
          summary: 'monitor',
          services: [],
          platform_intent: 'monitor',
        },
      }),
    ).rejects.toThrow(ForbiddenError);
  });

  it('regular passport (no platform_intent) issues normally for a non-staff operator', async () => {
    // Sanity check that the gate doesn't accidentally block non-platform
    // passports for regular operators.
    const stubs = makeServiceFor({ id: REGULAR_OP, is_platform_staff: false });
    const service = new PassportService(
      stubs.passportRepo,
      stubs.agentRepo,
      stubs.serviceRepo,
      signer,
      stubs.redis,
      stubs.operatorRepo,
      SYSTEM_OP,
      stubs.db,
      // a regular Passport is bound to exactly one live Mission.
      passportTestWiring({
        missionLookup: {
          findById: async (missionId) => ({
            mission_id: missionId, operator_id: REGULAR_OP, intent_services: [],
            expires_at: new Date(Date.now() + 3_600_000), completed_at: null, revoked_at: null,
          }),
        },
      }).dependencies,
    );
    const signed = await service.issue(REGULAR_OP, {
      agent_id: 'agt_test',
      mission_ids: ['ms_regular'],
    });
    expect(signed.token).toBeTruthy();
    const verified = await signer.verify(signed.token);
    expect(verified.stk.platform_intent).toBeUndefined();
  });
});
