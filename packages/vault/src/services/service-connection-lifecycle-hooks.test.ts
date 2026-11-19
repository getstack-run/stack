import { describe, expect, it, vi } from 'vitest';
import { ServiceConnectionService, standaloneServiceConnectionHooks, type ServiceConnectionHooks } from './service-connection-service.js';

// A deployment is told when a connection is made and before one is closed, so it can set up and end what a provider needs beside the key.
// A hook that fails when a connection is made removes the connection; one that fails when it is closed keeps it.

function harness(hooks: Partial<ServiceConnectionHooks>, status = 'active') {
  const stored = { id: 'scon_new', operator_id: 'op_one', provider: 'custom_acme', service_id: 'svc_custom', status, credential_encrypted: 'sealed', oauth_managed: false };
  const repo = {
    findCatalogServiceByProvider: vi.fn(async () => undefined),
    findConfigurationByOperatorAndProvider: vi.fn(async () => undefined),
    findMemberById: vi.fn(async () => undefined),
    findActiveConnectionsForPrincipal: vi.fn(async () => []),
    countConnectionsByOperator: vi.fn(async () => 0),
    upsertCustomService: vi.fn(async (_operator: string, data: { provider: string; name: string }) => ({ id: 'svc_custom', provider: data.provider, name: data.name })),
    createConnection: vi.fn(async (row: Record<string, unknown>) => ({ ...stored, ...row })),
    findConnectionById: vi.fn(async () => ({ ...stored })),
    revokeConnection: vi.fn(async () => ({ ...stored, status: 'revoked' })),
  };
  const kms = { encrypt: vi.fn(async () => ({ ciphertext: 'sealed', keyRef: 'k' })), decrypt: vi.fn(async () => JSON.stringify({ api_key: 'the-key' })) };
  const service = new ServiceConnectionService(repo as never, {} as never, kms as never, undefined as never, { ...standaloneServiceConnectionHooks, ...hooks });
  return { service, repo, kms };
}

const INPUT = { name: 'Acme', credential: { api_key: 'the-key' }, allowed_hosts: ['api.acme.example'] };

describe('connection lifecycle hooks', () => {
  it('tells the deployment about a new connection, with the provider and a way to read the key', async () => {
    const seen: Array<{ operatorId: string; provider: string; key: string }> = [];
    const connectionOpened = vi.fn(async (event: Parameters<NonNullable<ServiceConnectionHooks['connectionOpened']>>[0]) => {
      seen.push({ operatorId: event.operatorId, provider: event.connection.provider, key: await event.credential() });
    });
    const { service } = harness({ connectionOpened });
    await service.connectCustom('op_one', 'free', INPUT);
    expect(connectionOpened).toHaveBeenCalledTimes(1);
    expect(seen).toEqual([{ operatorId: 'op_one', provider: expect.stringContaining('acme'), key: expect.stringContaining('the-key') }]);
  });

  it('removes the connection and raises the error when the hook fails, so no key stays that did not work', async () => {
    const { service, repo } = harness({ connectionOpened: async () => { throw new Error('the provider refused the endpoint'); } });
    await expect(service.connectCustom('op_one', 'free', INPUT)).rejects.toThrow('the provider refused the endpoint');
    expect(repo.revokeConnection).toHaveBeenCalledTimes(1);
    expect(repo.revokeConnection).toHaveBeenCalledWith((await repo.createConnection.mock.results[0]!.value as { id: string }).id);
  });

  it('keeps the connection and returns the notice of the hook with it when the hook says something is not ready yet', async () => {
    const { service, repo } = harness({ connectionOpened: async () => ({ notice: 'Connected, but the events are not registered yet.' }) });
    const connection = await service.connectCustom('op_one', 'free', INPUT);
    expect(connection).toMatchObject({ notice: 'Connected, but the events are not registered yet.' });
    expect(repo.revokeConnection).not.toHaveBeenCalled();
  });

  it('returns no notice when the hook has nothing to say', async () => {
    const { service } = harness({ connectionOpened: async () => undefined });
    expect(await service.connectCustom('op_one', 'free', INPUT)).not.toHaveProperty('notice');
  });

  it('does not call the hook for a service registered with no credential, or when the caller skips it', async () => {
    const connectionOpened = vi.fn(async () => undefined);
    const { service } = harness({ connectionOpened });
    expect(await service.connectCustom('op_one', 'free', { name: 'Acme' })).toMatchObject({ registered: true });
    expect(connectionOpened).not.toHaveBeenCalled();
  });

  it('asks the deployment to end what it set up before an active connection is closed, and closes it only after', async () => {
    const order: string[] = [];
    const { service, repo } = harness({ connectionClosing: async () => { order.push('closing'); } });
    repo.revokeConnection.mockImplementation(async () => { order.push('revoked'); return { id: 'scon_new', status: 'revoked' } as never; });
    await service.disconnect('scon_new', 'op_one');
    expect(order).toEqual(['closing', 'revoked']);
  });

  it('keeps the connection when the deployment cannot end what it set up', async () => {
    const { service, repo } = harness({ connectionClosing: async () => { throw new Error('the provider could not be reached'); } });
    await expect(service.disconnect('scon_new', 'op_one')).rejects.toThrow('the provider could not be reached');
    expect(repo.revokeConnection).not.toHaveBeenCalled();
  });

  it('does not ask again for a connection that is already closed', async () => {
    const connectionClosing = vi.fn(async () => undefined);
    const { service, repo } = harness({ connectionClosing }, 'revoked');
    await service.disconnect('scon_new', 'op_one');
    expect(connectionClosing).not.toHaveBeenCalled();
    expect(repo.revokeConnection).toHaveBeenCalledTimes(1);
  });
});
