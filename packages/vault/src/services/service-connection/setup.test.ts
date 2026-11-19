import { describe, expect, it, vi } from 'vitest';
import { checkSetup } from './setup.js';
import { connectionNameWhenSeveral } from './queries.js';
import type { ServiceConnectionContext } from './context.js';

// The names an approval shows are read here, from the customer's own connection rows, when the approval is asked:
// a name only while the account holds two or more active connections of that service.

const connection = (id: string, name: string, provider = 'custom_grocer') => ({
  id, operator_id: 'op_1', provider, name, scopes: ['read', 'write'],
});

function context(rows: Array<ReturnType<typeof connection>>) {
  const findActiveConnectionsByOperatorAndProvider = vi.fn(async (operatorId: string, provider: string) =>
    rows.filter((row) => row.operator_id === operatorId && row.provider === provider));
  const ctx = {
    serviceRepo: {
      findConnectionById: async (id: string) => rows.find((row) => row.id === id),
      findActiveConnectionsByOperatorAndProvider,
    },
  } as unknown as ServiceConnectionContext;
  return { ctx, findActiveConnectionsByOperatorAndProvider };
}

describe('checkSetup names each connection it reads', () => {
  it('returns the provider and the name the owner gave each connection while the account holds several of the service', async () => {
    const { ctx } = context([connection('scon_work', 'Work'), connection('scon_home', 'Home')]);
    const named = await checkSetup(ctx, 'op_1', {
      grants: [{ service_connection_id: 'scon_work', scopes: ['read'] }],
      allowed_hosts: [{ service_connection_id: 'scon_home', allowed_hosts: ['api.grocer.example'] }],
    });
    expect(named.get('scon_work')).toEqual({ id: 'scon_work', provider: 'custom_grocer', name: 'Work' });
    expect(named.get('scon_home')).toEqual({ id: 'scon_home', provider: 'custom_grocer', name: 'Home' });
  });

  it('gives no name for the only active connection of a service, even one called default', async () => {
    const { ctx } = context([connection('scon_a', 'default')]);
    const named = await checkSetup(ctx, 'op_1', {
      grants: [{ service_connection_id: 'scon_a', scopes: ['read'] }],
      allowed_hosts: [],
    });
    expect(named.get('scon_a')).toEqual({ id: 'scon_a', provider: 'custom_grocer' });
    expect('name' in (named.get('scon_a') ?? {})).toBe(false);
  });

  it('counts each service on its own and once per call', async () => {
    const { ctx, findActiveConnectionsByOperatorAndProvider } = context([
      connection('scon_work', 'Work'), connection('scon_home', 'Home'), connection('scon_mail', 'Mail', 'agentmail'),
    ]);
    const named = await checkSetup(ctx, 'op_1', {
      grants: [
        { service_connection_id: 'scon_work', scopes: ['read'] },
        { service_connection_id: 'scon_home', scopes: ['read'] },
        { service_connection_id: 'scon_mail', scopes: ['read'] },
      ],
      allowed_hosts: [{ service_connection_id: 'scon_work', allowed_hosts: ['api.grocer.example'] }],
    });
    expect(named.get('scon_work')?.name).toBe('Work');
    expect(named.get('scon_home')?.name).toBe('Home');
    expect(named.get('scon_mail')?.name).toBeUndefined();
    expect(findActiveConnectionsByOperatorAndProvider).toHaveBeenCalledTimes(2);
  });
});

describe('connectionNameWhenSeveral', () => {
  it('returns the name with two or more active connections of the service and null with one', async () => {
    const two = context([connection('scon_work', 'Work'), connection('scon_home', 'Home')]).ctx;
    expect(await connectionNameWhenSeveral(two, connection('scon_work', 'Work'))).toBe('Work');
    const one = context([connection('scon_work', 'Work')]).ctx;
    expect(await connectionNameWhenSeveral(one, connection('scon_work', 'Work'))).toBeNull();
  });
});
