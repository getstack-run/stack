import { describe, expect, it } from 'vitest';
import { allowedHostsOf, restoreAllowedHosts } from './hosts.js';
import type { ServiceConnectionContext } from './context.js';

/** A connection store with one connection, enough for the two helpers. */
function store(initial: string[] | null) {
  const row = { id: 'scon_a', operator_id: 'op_owner', allowed_hosts: initial as string[] | null, provider: 'custom_grocer', scopes: ['read'] };
  const writes: Array<string[] | null> = [];
  const ctx = {
    serviceRepo: {
      findConnectionById: async (id: string) => (id === row.id ? row : null),
      withOperatorGrantLock: async (_operatorId: string, fn: (tx: unknown) => Promise<unknown>) => fn({}),
      updateConnection: async (_id: string, patch: { allowed_hosts: string[] | null }) => {
        row.allowed_hosts = patch.allowed_hosts;
        writes.push(patch.allowed_hosts);
        return row;
      },
    },
  } as unknown as ServiceConnectionContext;
  return { ctx, row, writes };
}

describe('putting a connection\'s hosts back after a failed setup', () => {
  it('reads the hosts as stored, an empty list when there are none', async () => {
    expect(await allowedHostsOf(store(['api.grocer.example']).ctx, 'scon_a', 'op_owner')).toEqual(['api.grocer.example']);
    expect(await allowedHostsOf(store(null).ctx, 'scon_a', 'op_owner')).toEqual([]);
  });

  it('restores what the connection had while it still holds what the setup wrote', async () => {
    const { ctx, row, writes } = store(['new.example']);
    expect(await restoreAllowedHosts(ctx, 'scon_a', 'op_owner', ['old.example'], ['new.example'])).toBe(true);
    expect(row.allowed_hosts).toEqual(['old.example']);
    expect(writes).toEqual([['old.example']]);
  });

  it('restores a connection that had no hosts to none', async () => {
    const { ctx, row } = store(['new.example']);
    expect(await restoreAllowedHosts(ctx, 'scon_a', 'op_owner', [], ['new.example'])).toBe(true);
    expect(row.allowed_hosts).toBeNull();
  });

  it('leaves a connection someone changed since the setup wrote it as they changed it', async () => {
    const { ctx, row, writes } = store(['someone-else.example']);
    expect(await restoreAllowedHosts(ctx, 'scon_a', 'op_owner', ['old.example'], ['new.example'])).toBe(false);
    expect(row.allowed_hosts).toEqual(['someone-else.example']);
    expect(writes).toEqual([]);
  });

  it('writes nothing when the hosts already are what they were, and nothing for another customer\'s connection', async () => {
    const same = store(['old.example']);
    expect(await restoreAllowedHosts(same.ctx, 'scon_a', 'op_owner', ['old.example'], ['old.example'])).toBe(true);
    expect(same.writes).toEqual([]);
    const other = store(['new.example']);
    expect(await restoreAllowedHosts(other.ctx, 'scon_a', 'op_someone_else', ['old.example'], ['new.example'])).toBe(false);
    expect(other.writes).toEqual([]);
  });
});
