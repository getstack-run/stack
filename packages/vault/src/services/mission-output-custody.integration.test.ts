import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { createDb, operators, missions, missionOutputs, passportClaims, canonicalize } from '@stack/shared';
import { MissionRepository } from '../repositories/mission-repo.js';
import { MissionService } from './mission-service.js';
import { CmekMigrationWorker } from './cmek-migration-worker.js';
import { CMEK_LONG_LIVED_STORES } from './cmek-service.js';

const databaseUrl = process.env['STACK_FLEET_TEST_DATABASE_URL'];
if (databaseUrl) {
  const url = new URL(databaseUrl);
  if (!['127.0.0.1', 'localhost'].includes(url.hostname) || !['/stack_fleet_verification', '/stack_fleet_e2e_20260924'].includes(url.pathname)) throw new Error('Isolated fleet fixture required');
}

(databaseUrl ? describe : describe.skip)('Mission output custody with PostgreSQL', () => {
  const db = createDb(databaseUrl ?? 'postgresql://unused:unused@127.0.0.1:56369/stack_fleet_verification');
  const suffix = randomUUID().replaceAll('-', '');
  const operator = `op_output_${suffix}`;
  const missionId = `ms_output_${suffix}`;
  const claimId = `pc_output_${suffix}`;
  const commitment = canonicalize({ salt: 'a'.repeat(64), output: { secret: 'synthetic-output' } });
  const digest = createHash('sha256').update(commitment).digest('hex');
  let keyRef = 'fixture-platform-key';
  const kms = {
    encrypt: vi.fn(async (value: string) => ({ ciphertext: `${keyRef}:${Buffer.from(value).toString('base64')}`, keyRef })),
    decrypt: vi.fn(async (value: string) => Buffer.from(value.slice(value.indexOf(':') + 1), 'base64').toString()),
  };
  const repo = new MissionRepository(db);
  beforeAll(async () => {
    await db.insert(operators).values({ id: operator, email: `${operator}@test.invalid`, api_key_hash: suffix });
    await db.insert(passportClaims).values({ claim_id: claimId, operator_id: operator, type: 'mission',
      body_json: { output_digest: digest }, claim_hash: 'fixture-hash', signature: 'fixture-unchanged-signature', envelope_cose: 'fixture-unchanged-cose' });
    await db.insert(missions).values({ mission_id: missionId, operator_id: operator, claim_id: claimId,
      intent_summary: 'Synthetic custody fixture', expires_at: new Date(Date.now() + 60_000) });
  });
  afterAll(async () => {
    await db.delete(missionOutputs).where(eq(missionOutputs.mission_id, missionId));
    await db.delete(missions).where(eq(missions.mission_id, missionId));
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, operator));
    await db.delete(operators).where(eq(operators.id, operator));
  });

  it('rolls output back if terminal signing fails, then rotates custody without changing evidence', async () => {
    const encrypted = await kms.encrypt(commitment);
    const output = { output_digest: digest, output_encrypted: encrypted.ciphertext, key_ref: encrypted.keyRef };
    await expect(repo.transitionWithClaim(missionId, claimId, { completed_at: new Date() }, async () => {
      throw new Error('Synthetic signer unavailable');
    }, output)).rejects.toThrow('Synthetic signer unavailable');
    expect(await repo.findOutput(operator, missionId)).toBeUndefined();
    expect((await repo.findById(missionId))!.completed_at).toBeNull();

    await repo.transitionWithClaim(missionId, claimId, { completed_at: new Date(), terminal_state: 'completed_successful' }, async () => claimId, output);
    const before = await db.query.passportClaims.findFirst({ where: eq(passportClaims.claim_id, claimId) });
    keyRef = 'fixture-customer-key';
    const migrationRows = CMEK_LONG_LIVED_STORES.map(table => ({ id: table, table_name: table,
      status: table === 'mission_outputs' ? 'pending' : 'completed' }));
    const worker = new CmekMigrationWorker({ db, kms,
      operatorRepo: { findByCmekStatus: async () => [{ id: operator, cmek_status: 'migrating' }], setCmekConfig: vi.fn() },
      migrationRepo: { listByOperatorAndDirection: async () => migrationRows, markRunning: vi.fn(), bumpProgress: vi.fn(),
        markCompleted: async (id: string) => { migrationRows.find(row => row.id === id)!.status = 'completed'; }, markFailed: vi.fn() },
      stackSystemOperatorId: '',
    } as never);
    await worker.tick();
    const after = await db.query.passportClaims.findFirst({ where: eq(passportClaims.claim_id, claimId) });
    expect(after).toEqual(before);
    const stored = await db.query.missionOutputs.findFirst({ where: eq(missionOutputs.mission_id, missionId) });
    expect(stored!.key_ref).toBe(keyRef);
    expect(stored!.output_encrypted).not.toBe(output.output_encrypted);
    expect(stored!.output_digest).toBe(digest);
    const service = new MissionService({ repo, kms, claimRegistry: {} as never });
    await expect(service.readOutput(missionId, { operatorId: operator })).resolves.toEqual({
      output: { secret: 'synthetic-output' }, output_salt: 'a'.repeat(64), output_digest: digest,
    });
    await expect(service.readOutput(missionId, { operatorId: 'op_other' })).rejects.toThrow();
  });
});
