import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { OperatorDecisionRepository } from './operator-decision-repo.js';

describe('OperatorDecisionRepository', () => {
  it('scopes every mutable projection update to the operator', () => {
    const source = readFileSync(new URL('./operator-decision-repo.ts', import.meta.url), 'utf8');
    const passportSource = readFileSync(new URL('./passport-repo.ts', import.meta.url), 'utf8');
    expect(source).toContain('eq(passportCheckouts.operator_id, input.operatorId)');
    expect(source).toContain('eq(securityEvents.operator_id, input.operatorId)');
    expect(source).toContain('blockAgentAndRevokePassportChain(');
    expect((source + passportSource).match(/eq\(agents\.operator_id, input\.operatorId\)/g)).toHaveLength(3);
  });

  it('locks source rows and uses state-conditional updates with exact row counts', () => {
    const source = readFileSync(new URL('./operator-decision-repo.ts', import.meta.url), 'utf8');
    const passportSource = readFileSync(new URL('./passport-repo.ts', import.meta.url), 'utf8');
    expect(source.match(/\.for\('update'\)/g)).toHaveLength(3);
    expect(source).toContain('eq(passportCheckouts.review_status');
    expect(source).toContain('eq(securityEvents.resolved, false)');
    expect(source).toContain('.returning({ id: passportCheckouts.id })');
    expect(source).toContain('.returning({ id: securityEvents.id })');
    expect((source + passportSource).match(/\.returning\(\{ id: agents\.id \}\)/g)).toHaveLength(3);
  });

  it('never clears a global agent block when one checkout is approved', () => {
    const source = readFileSync(new URL('./operator-decision-repo.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('passport_blocked: false');
  });

  it('binds the decision and claim writers to one database transaction', async () => {
    const tx = { marker: 'transaction' };
    const db = {
      transaction: vi.fn(async (callback: (input: unknown) => unknown) => callback(tx)),
    };
    const repo = new OperatorDecisionRepository(db as never);

    const result = await repo.transaction(async ({ decisions, claimPersistence }) => {
      expect(decisions).toBeInstanceOf(OperatorDecisionRepository);
      expect(claimPersistence.constructor.name).toBe('PassportClaimsRepository');
      return 'committed';
    });

    expect(result).toBe('committed');
    expect(db.transaction).toHaveBeenCalledTimes(1);
  });

  it('does not query when a source id set is empty', async () => {
    const repo = new OperatorDecisionRepository({} as never);
    await expect(repo.findCheckoutSources([])).resolves.toEqual([]);
    await expect(repo.findSecurityEventSources([])).resolves.toEqual([]);
  });
});
