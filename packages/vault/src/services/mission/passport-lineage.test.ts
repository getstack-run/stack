import { describe, expect, it, vi } from 'vitest';
import { PassportLineageReader } from './passport-lineage.js';

const OPERATOR = 'op_lineage';

function rows(table: Record<string, { agent_id: string; parent_passport_id: string | null; operator_id?: string }>) {
  return {
    findLineageRow: vi.fn(async (operatorId: string, jti: string) => {
      const row = table[jti];
      return row && (row.operator_id ?? OPERATOR) === operatorId ? { agent_id: row.agent_id, parent_passport_id: row.parent_passport_id } : null;
    }),
  };
}

describe('the agents above a delegated Passport', () => {
  const chain = {
    leaf: { agent_id: 'agt_child', parent_passport_id: 'mid' },
    mid: { agent_id: 'agt_middle', parent_passport_id: 'root' },
    root: { agent_id: 'agt_root', parent_passport_id: null },
  };

  it('reads every agent that delegated, nearest first, and none for a Passport nobody delegated', async () => {
    const reader = new PassportLineageReader(rows(chain));
    expect(await reader.agentsAbove(OPERATOR, 'leaf')).toEqual(['agt_middle', 'agt_root']);
    expect(await reader.agentsAbove(OPERATOR, 'root')).toEqual([]);
  });

  it('keeps what it read, since a Passport\'s parents never change', async () => {
    const repo = rows(chain);
    const reader = new PassportLineageReader(repo);
    await reader.agentsAbove(OPERATOR, 'leaf');
    await reader.agentsAbove(OPERATOR, 'leaf');
    expect(repo.findLineageRow).toHaveBeenCalledTimes(3);
  });

  it('reads nothing above another operator\'s Passport, and stops at a chain that loops', async () => {
    const reader = new PassportLineageReader(rows({ ...chain, leaf: { ...chain.leaf, operator_id: 'op_other' } }));
    expect(await reader.agentsAbove(OPERATOR, 'leaf')).toEqual([]);
    const loop = new PassportLineageReader(rows({ a: { agent_id: 'agt_a', parent_passport_id: 'b' }, b: { agent_id: 'agt_b', parent_passport_id: 'a' } }));
    expect((await loop.agentsAbove(OPERATOR, 'a')).length).toBeLessThanOrEqual(8);
  });

  it('fails when the read fails, so the check refuses rather than skip the parents', async () => {
    const reader = new PassportLineageReader({ findLineageRow: vi.fn(async () => { throw new Error('database down'); }) });
    await expect(reader.agentsAbove(OPERATOR, 'leaf')).rejects.toThrow('database down');
  });
});
