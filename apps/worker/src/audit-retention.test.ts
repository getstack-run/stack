import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ calls: [] as string[] }));

vi.mock('./jobs/cold-archive.js', () => ({
  maybeRunColdArchive: async () => {
    h.calls.push('archive');
  },
}));
vi.mock('./jobs/retention-prune.js', () => ({
  maybeRunRetentionPrune: async () => {
    h.calls.push('prune');
  },
}));

import { runAuditRetention } from './jobs/audit-retention.js';

const deps = { db: {}, redis: {}, archive: {}, audit: {}, securityEventRepo: {} } as never;

describe('audit retention', () => {
  beforeEach(() => {
    h.calls.length = 0;
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  it('archives and then prunes when a deployment keeps nothing of the rows', async () => {
    await runAuditRetention(deps);
    expect(h.calls).toEqual(['archive', 'prune']);
  });

  it('runs a deployment\'s hook first, then the archive, then the prune', async () => {
    await runAuditRetention(deps, {
      beforeArchive: async () => {
        h.calls.push('hook');
        return true;
      },
    });
    expect(h.calls).toEqual(['hook', 'archive', 'prune']);
  });

  it('runs neither the archive nor the prune when the hook says what it keeps is not durable', async () => {
    await runAuditRetention(deps, {
      beforeArchive: async () => {
        h.calls.push('hook');
        return false;
      },
    });
    expect(h.calls).toEqual(['hook']);
  });

  it('runs neither when the hook throws, and the tick sees the error', async () => {
    await expect(
      runAuditRetention(deps, {
        beforeArchive: async () => {
          throw new Error('rollup failed');
        },
      }),
    ).rejects.toThrow('rollup failed');
    expect(h.calls).toEqual([]);
  });
});
