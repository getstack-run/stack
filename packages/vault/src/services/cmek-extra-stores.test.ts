import { describe, expect, it, vi } from 'vitest';
import { CmekMigrationWorker, type CmekMigrationStep } from './cmek-migration-worker.js';
import { CMEK_LONG_LIVED_STORES, CmekService } from './cmek-service.js';

// A deployment adds stores of ciphertext to the engine's (STACK's skills): they are seeded with the
// rest, migrated by the step it registered, and the operator flips only when every one is done.

const VALID_ARN = 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';

describe('the stores a customer-managed key covers', () => {
  it('are the engine\'s alone until a deployment adds its own', () => {
    expect(CMEK_LONG_LIVED_STORES).not.toContain('skills');
  });

  it('seeds a migration row for each store the deployment adds, both ways', async () => {
    const rows: Array<{ direction: string; table: string }> = [];
    const migrationRepo = {
      upsertPending: vi.fn(async (_id: string, _operator: string, direction: string, table: string) => { rows.push({ direction, table }); }),
      markRunning: vi.fn(async () => undefined),
      markCompleted: vi.fn(async () => undefined),
      listByOperatorAndDirection: vi.fn(async () => []),
      deleteByOperator: vi.fn(async () => undefined),
    };
    const operator = { id: 'op_a', tier: 'enterprise', cmek_status: 'none', cmek_key_arn: null, cmek_activated_at: null };
    const service = new CmekService({
      operatorRepo: {
        findById: vi.fn(async () => ({ ...operator })),
        setConfigCalls: undefined,
        setCmekConfig: vi.fn(async () => undefined),
      },
      migrationRepo,
      kms: { smokeTestCustomerKey: vi.fn(async () => undefined) },
      stackSystemOperatorId: 'op_stack_system',
      extraLongLivedStores: ['skills'],
    } as unknown as ConstructorParameters<typeof CmekService>[0]);
    await service.enable('op_a', VALID_ARN).catch(() => undefined);
    const enabled = rows.filter((row) => row.direction === 'enable').map((row) => row.table);
    expect(enabled).toEqual(expect.arrayContaining([...CMEK_LONG_LIVED_STORES, 'skills']));
  });
});

describe('the migration of the stores a deployment adds', () => {
  function worker(extraSteps: readonly CmekMigrationStep[] | undefined, tables: string[]) {
    const rows = tables.map((table) => ({ id: `cmkm_${table}`, table_name: table, status: 'pending' }));
    const migrationRepo = {
      listByOperatorAndDirection: vi.fn(async () => rows),
      upsertPending: vi.fn(async (_id: string, _operator: string, _direction: string, table: string) => ({ id: `cmkm_${table}`, table_name: table, status: 'completed' })),
      markFailed: vi.fn(async () => undefined),
    };
    const operatorRepo = { findByCmekStatus: vi.fn(async () => [{ id: 'op_a', cmek_status: 'migrating' as const }]), setCmekConfig: vi.fn(async () => undefined) };
    return {
      migrationRepo,
      operatorRepo,
      worker: new CmekMigrationWorker({
        db: {}, kms: {}, operatorRepo, migrationRepo, stackSystemOperatorId: 'op_stack_system',
        ...(extraSteps ? { extraSteps } : {}),
      } as unknown as ConstructorParameters<typeof CmekMigrationWorker>[0]),
    };
  }

  it('runs the step registered for the store, with the operator and the migration row', async () => {
    const migrate = vi.fn(async () => undefined);
    const { worker: w } = worker([{ table: 'skills', migrate }], ['skills']);
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    await w.tick();
    expect(migrate).toHaveBeenCalledWith('op_a', expect.objectContaining({ table_name: 'skills' }), expect.objectContaining({ db: {}, kms: {} }));
  });

  it('ignores a migration row of a store this deployment does not have', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { worker: w, migrationRepo } = worker(undefined, ['skills']);
    // The engine's own store list does not include skills, so an install ignores a stray row.
    await w.tick();
    expect(migrationRepo.markFailed).not.toHaveBeenCalled();
    consoleError.mockRestore();
  });
});
