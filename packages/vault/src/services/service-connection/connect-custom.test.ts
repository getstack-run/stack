import { describe, expect, it, vi } from 'vitest';
import { connectApplication, connectCustom, connectService } from './connect.js';

// A custom connect that fails must leave an existing custom service of the same name exactly as it was: the service
// row is written only once every check that can refuse the connection has passed.

function harness(options: { limit?: number; count?: number } = {}) {
  const calls: string[] = [];
  const serviceRepo = {
    findCatalogServiceByProvider: vi.fn(async () => undefined),
    findConfigurationByOperatorAndProvider: vi.fn(async () => undefined),
    findMemberById: vi.fn(async () => undefined),
    findActiveConnectionsForPrincipal: vi.fn(async () => []),
    countConnectionsByOperator: vi.fn(async () => options.count ?? 0),
    upsertCustomService: vi.fn(async (_operator: string, data: { provider: string; name: string }) => {
      calls.push('upsert');
      return { id: 'svc_custom', provider: data.provider, name: data.name };
    }),
    createConnection: vi.fn(async (row: Record<string, unknown>) => { calls.push('create'); return { id: 'scon_new', ...row }; }),
  };
  const kms = { encrypt: vi.fn(async () => ({ ciphertext: 'x', keyRef: 'k' })) };
  const hooks = options.limit === undefined ? {} : { planLimits: () => ({ services: options.limit }) };
  const ctx = { serviceRepo, kms, hooks } as never;
  return { ctx, serviceRepo, calls };
}

const INPUT = { name: 'Acme', credential: { api_key: 'k' }, allowed_hosts: ['api.acme.example'] };

describe('connectCustom', () => {
  it('writes the service and then the connection when everything passes', async () => {
    const { ctx, calls } = harness();
    await connectCustom(ctx, 'op_one', 'free', INPUT);
    expect(calls).toEqual(['upsert', 'create']);
  });

  it('leaves an existing custom service untouched when no host is declared', async () => {
    const { ctx, serviceRepo } = harness();
    await expect(connectCustom(ctx, 'op_one', 'free', { ...INPUT, allowed_hosts: [] })).rejects.toThrow(/allowed_hosts/);
    expect(serviceRepo.upsertCustomService).not.toHaveBeenCalled();
    expect(serviceRepo.createConnection).not.toHaveBeenCalled();
  });

  it('leaves an existing custom service untouched when the plan\'s limit of connections is reached', async () => {
    const { ctx, serviceRepo } = harness({ limit: 2, count: 2 });
    await expect(connectCustom(ctx, 'op_one', 'free', INPUT)).rejects.toThrow();
    expect(serviceRepo.upsertCustomService).not.toHaveBeenCalled();
    expect(serviceRepo.createConnection).not.toHaveBeenCalled();
  });

  it('keeps an mcp_url on the connection when it is https and on one of the hosts of the connection, and none when it is not given', async () => {
    const { ctx, serviceRepo } = harness();
    await connectCustom(ctx, 'op_one', 'free', { ...INPUT, mcp_url: 'https://api.acme.example/mcp' });
    expect(serviceRepo.createConnection).toHaveBeenLastCalledWith(expect.objectContaining({ mcp_url: 'https://api.acme.example/mcp', allowed_hosts: ['api.acme.example'] }));
    await connectCustom(ctx, 'op_one', 'free', INPUT);
    expect(serviceRepo.createConnection).toHaveBeenLastCalledWith(expect.objectContaining({ mcp_url: null }));
  });

  it('refuses an mcp_url that is not https or is on a host the key may not be sent to, and changes nothing', async () => {
    const { ctx, serviceRepo } = harness();
    for (const bad of ['http://api.acme.example/mcp', 'https://evil.example/mcp', 'https://api.acme.example.evil.example/mcp', 'https://u:p@api.acme.example/mcp']) {
      await expect(connectCustom(ctx, 'op_one', 'free', { ...INPUT, mcp_url: bad }), bad).rejects.toThrow(/mcp_url/);
    }
    expect(serviceRepo.upsertCustomService).not.toHaveBeenCalled();
    expect(serviceRepo.createConnection).not.toHaveBeenCalled();
  });

  it('refuses an mcp_url given with no credential, since it belongs to a connection', async () => {
    const { ctx, serviceRepo } = harness();
    await expect(connectCustom(ctx, 'op_one', 'free', { name: 'Acme', mcp_url: 'https://api.acme.example/mcp' })).rejects.toThrow(/credential/);
    expect(serviceRepo.upsertCustomService).not.toHaveBeenCalled();
  });

  it('still registers a service with no credential, as before', async () => {
    const { ctx, serviceRepo } = harness();
    const result = await connectCustom(ctx, 'op_one', 'free', { name: 'Acme' });
    expect(result).toMatchObject({ registered: true });
    expect(serviceRepo.upsertCustomService).toHaveBeenCalledTimes(1);
  });
});

describe('connectService and connectApplication with an mcp_url', () => {
  const service = { id: 'svc_ent', provider: 'microsoft_entra_app', name: 'Entra', scopes_available: ['*'] };

  function catalogHarness() {
    const { ctx, serviceRepo } = harness();
    (serviceRepo as Record<string, unknown>)['findAccessibleServiceById'] = vi.fn(async () => service);
    return { ctx, serviceRepo };
  }

  it('checks the address against the hosts the connection was given, for an application connection', async () => {
    const { ctx, serviceRepo } = catalogHarness();
    const input = { service_id: 'svc_ent', credential: { client_id: 'c' }, allowed_hosts: ['graph.acme.example'] };
    await connectApplication(ctx, 'op_one', 'free', { ...input, mcp_url: 'https://graph.acme.example/mcp' });
    expect(serviceRepo.createConnection).toHaveBeenLastCalledWith(expect.objectContaining({ mcp_url: 'https://graph.acme.example/mcp' }));
    await expect(connectApplication(ctx, 'op_one', 'free', { ...input, mcp_url: 'https://elsewhere.example/mcp' })).rejects.toThrow(/allowed hosts/);
  });

  it('checks the address against the hosts the connection was given, for a catalogue service connection', async () => {
    const { ctx, serviceRepo } = catalogHarness();
    const input = { service_id: 'svc_ent', scopes: ['*'], oauth_token: 'tok', allowed_hosts: ['graph.acme.example'] };
    await connectService(ctx, 'op_one', 'free', { ...input, mcp_url: 'https://graph.acme.example/mcp' });
    expect(serviceRepo.createConnection).toHaveBeenLastCalledWith(expect.objectContaining({ mcp_url: 'https://graph.acme.example/mcp' }));
    await expect(connectService(ctx, 'op_one', 'free', { ...input, mcp_url: 'http://graph.acme.example/mcp' })).rejects.toThrow(/https/);
  });
});
