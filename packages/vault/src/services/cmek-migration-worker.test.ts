import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { CmekMigrationWorker } from './cmek-migration-worker.js';

beforeEach(() => {
  vi.clearAllMocks();
});

it('re-encrypts every retained proxy payload, including pending post-response work', () => {
  const source = readFileSync(new URL('./cmek-migration-worker.ts', import.meta.url), 'utf8');
  expect(source).toContain('post_response_context_encrypted: proxyOperations.post_response_context_encrypted');
  expect(source).toContain("purpose: 'proxy_post_response_work'");
  expect(source).toContain('update.post_response_context_key_ref = encrypted.keyRef');
});

describe('CmekMigrationWorker — dogfood carve-out (op_stack_system)', () => {
  it('skips op_stack_system even if its status is migrating', async () => {
    const findByCmekStatus = vi.fn(async () => [
      { id: 'op_stack_system', cmek_status: 'migrating' as const },
    ]);
    const migrationRepo = {
      listByOperatorAndDirection: vi.fn(async () => []),
    };
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    const worker = new CmekMigrationWorker({
      db: {},
      kms: {},
      operatorRepo: { findByCmekStatus },
      migrationRepo,
      stackSystemOperatorId: 'op_stack_system',
    } as unknown as ConstructorParameters<typeof CmekMigrationWorker>[0]);

    await worker.tick();

    // The defensive skip means listByOperatorAndDirection is NEVER called for
    // op_stack_system — the carve-out short-circuits before any per-operator
    // work begins.
    expect(migrationRepo.listByOperatorAndDirection).not.toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('refusing to migrate op_stack_system'),
      'migrating',
    );

    consoleSpy.mockRestore();
  });

  it('skips op_stack_system even if its status is revoking', async () => {
    const findByCmekStatus = vi.fn(async () => [
      { id: 'op_stack_system', cmek_status: 'revoking' as const },
    ]);
    const migrationRepo = {
      listByOperatorAndDirection: vi.fn(async () => []),
    };
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    const worker = new CmekMigrationWorker({
      db: {},
      kms: {},
      operatorRepo: { findByCmekStatus },
      migrationRepo,
      stackSystemOperatorId: 'op_stack_system',
    } as unknown as ConstructorParameters<typeof CmekMigrationWorker>[0]);

    await worker.tick();

    expect(migrationRepo.listByOperatorAndDirection).not.toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('op_stack_system'), 'revoking');

    consoleSpy.mockRestore();
  });

  it('still processes non-stack-system operators when the carve-out is configured', async () => {
    const findByCmekStatus = vi.fn(async () => [
      { id: 'op_stack_system', cmek_status: 'migrating' as const },
      { id: 'op_real_customer', cmek_status: 'migrating' as const },
    ]);
    const migrationRepo = {
      listByOperatorAndDirection: vi.fn(async () => []),
    };

    const worker = new CmekMigrationWorker({
      db: {},
      kms: {},
      operatorRepo: { findByCmekStatus },
      migrationRepo,
      stackSystemOperatorId: 'op_stack_system',
    } as unknown as ConstructorParameters<typeof CmekMigrationWorker>[0]);

    await worker.tick();

    // Real customer DOES get processed. processOperator calls
    // listByOperatorAndDirection twice — once at start, once on the "all
    // done" recheck. So 2 calls total, both for op_real_customer. The
    // carve-out's signature is the ABSENCE of any call for op_stack_system.
    expect(migrationRepo.listByOperatorAndDirection).toHaveBeenCalledTimes(2);
    expect(migrationRepo.listByOperatorAndDirection).toHaveBeenCalledWith('op_real_customer', 'enable');
    expect(migrationRepo.listByOperatorAndDirection).not.toHaveBeenCalledWith('op_stack_system', expect.anything());
  });

  it('does not short-circuit anything when stackSystemOperatorId is unset (dev/test mode)', async () => {
    const findByCmekStatus = vi.fn(async () => [
      { id: 'op_stack_system', cmek_status: 'migrating' as const },
    ]);
    const migrationRepo = {
      listByOperatorAndDirection: vi.fn(async () => []),
    };

    const worker = new CmekMigrationWorker({
      db: {},
      kms: {},
      operatorRepo: { findByCmekStatus },
      migrationRepo,
      stackSystemOperatorId: '',
    } as unknown as ConstructorParameters<typeof CmekMigrationWorker>[0]);

    await worker.tick();

    // Carve-out off — op_stack_system gets processed like any other
    // operator. processOperator calls listByOperatorAndDirection twice.
    expect(migrationRepo.listByOperatorAndDirection).toHaveBeenCalledTimes(2);
    expect(migrationRepo.listByOperatorAndDirection).toHaveBeenCalledWith('op_stack_system', 'enable');
  });
});
