import { describe, expect, it, vi } from 'vitest';
import type { CredentialFields } from '@stack/vault';
import { systemAppGrantHooks } from './system-app-grants.js';

vi.mock('@sentry/node', () => ({ captureMessage: vi.fn() }));

const binding = { id: 'app', owner_id: 'op_system', provider: 'google', client_id_hash: 'hash', service_id: 'svc', connection_provider: 'gmail', token_url: 'https://token.example.test' };
const credential = { access_token: 'a', refresh_token: 'refresh-1', oauth_app_binding: binding } as CredentialFields;
const connection = { id: 'scon_1', provider: 'gmail', scopes: ['wide'] };

describe('the grant hooks of the connection service', () => {
  it('are none where the deployment ends no grants, so a disconnect never decrypts a credential for a hook that does nothing', () => {
    expect(systemAppGrantHooks({})).toEqual({});
  });

  it('end the grant at the provider with the refresh token for any closed connection that is the last of its app, within the app\'s scopes or not', async () => {
    const revoke = vi.fn(async () => undefined);
    const hooks = systemAppGrantHooks({ revokeSystemAppGrant: revoke });
    expect(hooks.grantDropped).toBeDefined();
    expect(hooks.grantReleaseFailed).toBeDefined();
    await hooks.grantDropped!({ ...connection, scopes: ['narrow'] }, credential, { sharesGrant: async () => false });
    expect(revoke).toHaveBeenCalledWith('google', 'refresh-1');
  });

  it('fall back to the access token when the credential has no refresh token', async () => {
    const revoke = vi.fn(async () => undefined);
    const hooks = systemAppGrantHooks({ revokeSystemAppGrant: revoke });
    await hooks.grantDropped!(connection, { ...credential, refresh_token: undefined } as CredentialFields, { sharesGrant: async () => false });
    expect(revoke).toHaveBeenCalledWith('google', 'a');
  });

  it('leave a grant a live connection of the operator may stand on, and a credential with no binding or no token', async () => {
    const revoke = vi.fn(async () => undefined);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const hooks = systemAppGrantHooks({ revokeSystemAppGrant: revoke });
    await hooks.grantDropped!(connection, credential, { sharesGrant: async () => true });
    await hooks.grantDropped!(connection, { ...credential, refresh_token: undefined, access_token: undefined } as CredentialFields, { sharesGrant: async () => false });
    await hooks.grantDropped!(connection, { ...credential, oauth_app_binding: undefined } as CredentialFields, { sharesGrant: async () => false });
    expect(revoke).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('let a failed revocation reach the connection service, which logs and reports it without the token and does not undo the disconnect', async () => {
    const hooks = systemAppGrantHooks({ revokeSystemAppGrant: async () => { throw new Error('Google could not be reached to revoke a grant'); } });
    await expect(hooks.grantDropped!(connection, credential, { sharesGrant: async () => false })).rejects.toThrow('could not be reached');
  });
});
