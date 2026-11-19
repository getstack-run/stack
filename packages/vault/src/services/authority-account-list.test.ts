import { describe, expect, it, vi } from 'vitest';
import { AuthorityService, type AuthorityServiceDeps } from './authority-service.js';

describe('account authority page safety', () => {
  it.each(['principals', 'proofs', 'receivers'] as const)('rejects foreign %s before reading relationships', async (kind) => {
    const repo = { findPrincipal: vi.fn(async () => null), findProof: vi.fn(async () => null),
      findReceiver: vi.fn(async () => null), listAccountRecordBindings: vi.fn(async () => []) };
    const service = new AuthorityService({ repo } as unknown as AuthorityServiceDeps);
    await expect(service.listAccountRecords('op_owned', kind, 1, 20,
      kind === 'proofs' ? { id: 'foreign', version: 3 } : { id: 'foreign' })).rejects.toThrow();
    expect(repo.listAccountRecordBindings).not.toHaveBeenCalled();
    const lookup = kind === 'principals' ? repo.findPrincipal : kind === 'proofs' ? repo.findProof : repo.findReceiver;
    expect(lookup.mock.calls[0]).toEqual(kind === 'proofs' ? ['op_owned', 'foreign', 3] : ['op_owned', 'foreign']);
  });

  it('uses one extra row for has_more and retains the existing principal projection', async () => {
    const created_at = new Date('2026-09-06T00:00:00Z');
    const row = { id: 'prn_one', kind: 'person', status: 'active', created_at,
      operator_id: 'op_owned', pii_encrypted: 'MUST_NOT_LEAK', internal_note: 'MUST_NOT_LEAK' };
    const repo = { listAccountRecords: vi.fn(async () => ({ principals: [row, { ...row, id: 'prn_two' }] })) };
    const service = new AuthorityService({ repo } as unknown as AuthorityServiceDeps);
    const result = await service.listAccountRecords('op_owned', 'principals', 2, 1);
    expect(result).toEqual({ principals: [{ id: 'prn_one', kind: 'person', status: 'active',
      created_at: created_at.toISOString(), revoked_at: null, erased_at: null }], page: 2, limit: 1, has_more: true });
    expect(repo.listAccountRecords).toHaveBeenCalledWith('op_owned', 'principals', 2, 1);
    expect(JSON.stringify(result)).not.toContain('MUST_NOT_LEAK');
  });

  it('checks the selected proof version and bounds bindings with the existing safe projection', async () => {
    const now = new Date('2026-09-06T00:00:00Z');
    const row = { id: 'abn_one', version: 4, agent_id: 'agt_one', valid_from: now, expires_at: now,
      created_at: now, policy_encrypted: 'MUST_NOT_LEAK', operator_id: 'op_owned' };
    const repo = { findProof: vi.fn(async () => ({ id: 'apf_one', version: 3 })),
      listAccountRecordBindings: vi.fn(async () => [row, { ...row, id: 'abn_two' }]) };
    const service = new AuthorityService({ repo } as unknown as AuthorityServiceDeps);
    const result = await service.listAccountRecords('op_owned', 'proofs', 1, 1, { id: 'apf_one', version: 3 });
    expect(repo.findProof).toHaveBeenCalledWith('op_owned', 'apf_one', 3);
    expect(repo.listAccountRecordBindings).toHaveBeenCalledWith('op_owned', 'proofs', 'apf_one', 3, 1, 1);
    expect(result).toMatchObject({ bindings: [{ id: 'abn_one', version: 4, agent_id: 'agt_one' }], has_more: true });
    expect(JSON.stringify(result)).not.toContain('MUST_NOT_LEAK');
    await expect(service.listAccountRecords('op_owned', 'proofs', 1, 20, { id: 'apf_one' })).rejects.toThrow();
  });
});
