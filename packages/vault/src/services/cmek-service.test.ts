import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CmekConfigurationError, NotFoundError } from '@stack/shared';
import { CmekService, CMEK_LONG_LIVED_STORES, CMEK_EPHEMERAL_STORES } from './cmek-service.js';

function makeDeps(overrides: Partial<Parameters<typeof makeDeps_>[0]> = {}) {
  return makeDeps_({
    operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
    smokeOk: true,
    stackSystemOperatorId: 'op_stack_system',
    ...overrides,
  });
}

interface Overrides {
  operator: {
    id: string;
    tier: string;
    cmek_status: 'none' | 'migrating' | 'active' | 'revoking' | 'revoked';
    cmek_key_arn: string | null;
    cmek_activated_at: Date | null;
  } | null;
  smokeOk: boolean;
  stackSystemOperatorId: string;
}

function makeDeps_(o: Overrides) {
  let opState = o.operator ? { ...o.operator } : null;
  const setConfigCalls: Array<{ operatorId: string; config: Record<string, unknown> }> = [];
  const publishCalls: string[] = [];
  const migrationRows: Array<{ id: string; operatorId: string; direction: string; table: string; status: string }> = [];
  const smokeCalls: Array<{ keyArn: string; operatorId: string }> = [];

  return {
    deps: {
      operatorRepo: {
        findById: vi.fn(async (id: string) => (opState?.id === id ? opState : null)),
        setCmekConfig: vi.fn(async (operatorId: string, config: Record<string, unknown>) => {
          setConfigCalls.push({ operatorId, config });
          if (opState?.id === operatorId) opState = { ...opState, ...config } as typeof opState;
        }),
      },
      migrationRepo: {
        upsertPending: vi.fn(async (id: string, operatorId: string, direction: string, table: string) => {
          migrationRows.push({ id, operatorId, direction, table, status: 'pending' });
        }),
        markRunning: vi.fn(async (id: string) => {
          const r = migrationRows.find((x) => x.id === id);
          if (r) r.status = 'running';
        }),
        markCompleted: vi.fn(async (id: string) => {
          const r = migrationRows.find((x) => x.id === id);
          if (r) r.status = 'completed';
        }),
        listByOperator: vi.fn(async () => migrationRows),
        listByOperatorAndDirection: vi.fn(async (_op: string, direction: string) =>
          migrationRows.filter((r) => r.direction === direction),
        ),
        deleteByOperator: vi.fn(async () => {
          migrationRows.length = 0;
        }),
      },
      kms: {
        smokeTestCustomerKey: vi.fn(async (keyArn: string, operatorId: string) => {
          smokeCalls.push({ keyArn, operatorId });
          if (!o.smokeOk) throw new Error('smoke failed');
        }),
      },
      stackSystemOperatorId: o.stackSystemOperatorId,
      publishCmekUpdated: vi.fn(async (operatorId: string) => {
        publishCalls.push(operatorId);
      }),
    } as unknown as ConstructorParameters<typeof CmekService>[0],
    inspect: { setConfigCalls, publishCalls, migrationRows, smokeCalls, getOpState: () => opState },
  };
}

const VALID_ARN = 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('CmekService — dogfood carve-out (op_stack_system)', () => {
  it('refuses to enable CMEK on the platform system operator', async () => {
    const { deps } = makeDeps({
      operator: { id: 'op_stack_system', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
      stackSystemOperatorId: 'op_stack_system',
    });
    const svc = new CmekService(deps);
    await expect(svc.enable('op_stack_system', VALID_ARN)).rejects.toThrow(CmekConfigurationError);
    await expect(svc.enable('op_stack_system', VALID_ARN)).rejects.toThrow(/platform operator/i);
  });

  it('does not call the IAM smoke test when refusing the platform operator', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_stack_system', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
      stackSystemOperatorId: 'op_stack_system',
    });
    const svc = new CmekService(deps);
    await expect(svc.enable('op_stack_system', VALID_ARN)).rejects.toThrow();
    expect(inspect.smokeCalls).toHaveLength(0);
  });

  it('does not flip status when refusing the platform operator', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_stack_system', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
      stackSystemOperatorId: 'op_stack_system',
    });
    const svc = new CmekService(deps);
    await expect(svc.enable('op_stack_system', VALID_ARN)).rejects.toThrow();
    expect(inspect.setConfigCalls).toHaveLength(0);
    expect(inspect.getOpState()?.cmek_status).toBe('none');
  });

  it('allows enable on a non-stack-system operator when stackSystemOperatorId is set', async () => {
    const { deps } = makeDeps({
      operator: { id: 'op_real_customer', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
      stackSystemOperatorId: 'op_stack_system',
    });
    const svc = new CmekService(deps);
    await expect(svc.enable('op_real_customer', VALID_ARN)).resolves.toBeDefined();
  });
});

describe('CmekService — no plan gate', () => {
  for (const tier of ['free', 'developer', 'pro', 'business']) {
    it(`enables a customer-managed key for an account whose row says ${tier}`, async () => {
      const { deps, inspect } = makeDeps({
        operator: { id: 'op_test', tier, cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
      });
      const svc = new CmekService(deps);
      await expect(svc.enable('op_test', VALID_ARN)).resolves.toBeDefined();
      expect(inspect.publishCalls).toEqual(['op_test']);
    });
  }
});

describe('CmekService — enable from revoked (the "manually un-revoke" path)', () => {
  it('allows enable when current status is revoked — drill recovery path', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'revoked', cmek_key_arn: VALID_ARN, cmek_activated_at: new Date() },
    });
    const svc = new CmekService(deps);
    const snap = await svc.enable('op_test', VALID_ARN);
    expect(snap.status).toBe('migrating');
    expect(inspect.smokeCalls).toHaveLength(1);
    expect(inspect.getOpState()?.cmek_status).toBe('migrating');
  });

  it('rejects enable when current status is active (already configured)', async () => {
    const { deps } = makeDeps({
      operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'active', cmek_key_arn: VALID_ARN, cmek_activated_at: new Date() },
    });
    const svc = new CmekService(deps);
    await expect(svc.enable('op_test', VALID_ARN)).rejects.toThrow(/already configured/);
  });

  it('seeds migration rows for all long-lived and ephemeral stores on enable', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
    });
    const svc = new CmekService(deps);
    await svc.enable('op_test', VALID_ARN);
    const longLivedSeeded = inspect.migrationRows.filter((r) =>
      (CMEK_LONG_LIVED_STORES as readonly string[]).includes(r.table),
    );
    const ephemeralSeeded = inspect.migrationRows.filter((r) =>
      (CMEK_EPHEMERAL_STORES as readonly string[]).includes(r.table),
    );
    expect(longLivedSeeded).toHaveLength(CMEK_LONG_LIVED_STORES.length);
    expect(ephemeralSeeded).toHaveLength(CMEK_EPHEMERAL_STORES.length);
    expect(ephemeralSeeded.every((r) => r.status === 'completed')).toBe(true);
  });
});

describe('CmekService — recordRevoked publish + idempotency (cross-machine cache invalidation contract)', () => {
  it('publishes stack:cmek-updated when flipping active → revoked', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'active', cmek_key_arn: VALID_ARN, cmek_activated_at: new Date() },
    });
    const svc = new CmekService(deps);
    await svc.recordRevoked('op_test', VALID_ARN);
    expect(inspect.publishCalls).toEqual(['op_test']);
  });

  it('flips status to revoked', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'active', cmek_key_arn: VALID_ARN, cmek_activated_at: new Date() },
    });
    const svc = new CmekService(deps);
    await svc.recordRevoked('op_test', VALID_ARN);
    expect(inspect.setConfigCalls).toHaveLength(1);
    expect(inspect.setConfigCalls[0]!.config.cmek_status).toBe('revoked');
  });

  it('is idempotent — no DB write, no publish, when already revoked', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'revoked', cmek_key_arn: VALID_ARN, cmek_activated_at: new Date() },
    });
    const svc = new CmekService(deps);
    await svc.recordRevoked('op_test', VALID_ARN);
    expect(inspect.setConfigCalls).toHaveLength(0);
    expect(inspect.publishCalls).toHaveLength(0);
  });

  it('no-ops gracefully when operator does not exist (does not throw)', async () => {
    const { deps } = makeDeps({ operator: null });
    const svc = new CmekService(deps);
    await expect(svc.recordRevoked('op_missing')).resolves.toBeUndefined();
  });
});

describe('CmekService — enable publishes the cache invalidation event', () => {
  it('publishes after successful enable so peer machines drop cached state', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
    });
    const svc = new CmekService(deps);
    await svc.enable('op_test', VALID_ARN);
    expect(inspect.publishCalls).toEqual(['op_test']);
  });

  it('does NOT publish when smoke test fails', async () => {
    const { deps, inspect } = makeDeps({
      operator: { id: 'op_test', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null },
      smokeOk: false,
    });
    const svc = new CmekService(deps);
    await expect(svc.enable('op_test', VALID_ARN)).rejects.toThrow();
    expect(inspect.publishCalls).toHaveLength(0);
  });
});

describe('CmekService — unknown operator', () => {
  it('throws NotFoundError on enable for missing operator', async () => {
    const { deps } = makeDeps({ operator: null });
    const svc = new CmekService(deps);
    await expect(svc.enable('op_missing', VALID_ARN)).rejects.toThrow(NotFoundError);
  });

  it('throws NotFoundError on getStatus for missing operator', async () => {
    const { deps } = makeDeps({ operator: null });
    const svc = new CmekService(deps);
    await expect(svc.getStatus('op_missing')).rejects.toThrow(NotFoundError);
  });
});
