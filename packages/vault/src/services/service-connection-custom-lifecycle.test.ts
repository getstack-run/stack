import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ServiceConnectionService,
  standaloneServiceConnectionHooks,
  type ServiceConnectionHooks,
} from './service-connection-service.js';
import type { CredentialFields } from './oauth-token-lifecycle.js';

vi.mock('@stack/shared', async importOriginal => ({
  ...await importOriginal<object>(),
  assertPublicUrl: async (url: string) => new URL(url),
  publicFetch: (url: string, init: RequestInit) => globalThis.fetch(url, init),
}));

function harness(fields: CredentialFields) {
  const encode = (value: string) => `encrypted:${Buffer.from(value).toString('base64')}`;
  const decode = (value: string) => Buffer.from(value.slice(10), 'base64').toString();
  let row = { id: 'scon_fixture', operator_id: 'op_fixture', provider: 'custom_fixture', service_id: 'svc_fixture',
    credential_version: 1, credential_encrypted: encode(JSON.stringify(fields)), credential_ref: 'key', status: 'active',
    scopes: ['read', 'write'], allowed_hosts: ['api.example.test'], proxy_enabled: true };
  let tail = Promise.resolve();
  const tx = {};
  /** The operator's other live connections, as the repository lists them (the connection under test is among them in a real list). */
  const siblings: Array<Record<string, unknown>> = [];
  const repo = {
    findConnectionsByOperator: vi.fn(async () => [{ ...row }, ...siblings]),
    findConnectionById: vi.fn(async () => ({ ...row })),
    findAccessibleServiceById: vi.fn(async () => ({ oauth_token_url: 'https://identity.example.test/token' })),
    withCredentialLock: async (_id: string, _operator: string, work: (conn: typeof row, transaction: object) => Promise<unknown>) => {
      const previous = tail;
      let release!: () => void;
      tail = new Promise<void>(resolve => { release = resolve; });
      await previous;
      try { return await work({ ...row }, tx); } finally { release(); }
    },
    replaceCredential: vi.fn(async (_id: string, _operator: string, version: number, data: Partial<typeof row>, transaction: object) => {
      expect(transaction).toBe(tx);
      if (row.credential_version !== version) return undefined;
      row = { ...row, ...data, credential_version: version + 1 };
      return { ...row };
    }),
    updateConnection: vi.fn(async (_id: string, data: Partial<typeof row>, transaction: object) => {
      expect(transaction).toBe(tx); row = { ...row, ...data }; return { ...row };
    }),
    recordReconnectRequired: vi.fn(async (_row: unknown, transaction: object) => { expect(transaction).toBe(tx); return 'sec_fixture'; }),
    revokeConnection: vi.fn(async () => undefined),
  };
  const kms = { encrypt: vi.fn(async (value: string) => ({ ciphertext: encode(value), keyRef: 'key' })),
    decrypt: vi.fn(async (value: string) => decode(value)) };
  const create = (redis?: unknown, hooks: Partial<ServiceConnectionHooks> = {}) =>
    new ServiceConnectionService(repo as never, {} as never, kms as never, redis as never, {
      ...standaloneServiceConnectionHooks, ...hooks,
    });
  return { create, repo, kms, siblings, encode, row: () => row, stored: () => JSON.parse(decode(row.credential_encrypted)) };
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('connection rotation serialization', () => {
  it('concurrent instances reread the encrypted successor and consume a rotating token once', async () => {
    const h = harness({ access_token: 'expired', refresh_token: 'old-refresh', expires_at: 1 });
    const fetch = vi.fn(async () => new Response(JSON.stringify({
      access_token: 'fresh', refresh_token: 'rotated-refresh', expires_in: 3600, scope: 'read',
    })));
    vi.stubGlobal('fetch', fetch);
    const a = h.create(); const b = h.create();
    const result = await Promise.all(Array.from({ length: 50 }, (_, i) =>
      (i % 2 ? a : b).retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')));
    expect(fetch).toHaveBeenCalledOnce();
    expect(result.every(value => 'credentials' in value && value.credentials.access_token === 'fresh')).toBe(true);
    expect(h.stored().refresh_token).toBe('rotated-refresh');
    expect(h.row().credential_version).toBe(2);
    expect(h.row().credential_encrypted).not.toContain('rotated-refresh');
    expect(h.row().scopes).toEqual(['read']);
    expect(h.repo.findAccessibleServiceById).toHaveBeenCalledWith('svc_fixture', 'op_fixture', expect.any(Object));
    expect(h.kms.encrypt).toHaveBeenCalledWith(expect.any(String), { operator_id: 'op_fixture', provider: 'custom_fixture' });
  });

  it('revoked consent persists once and produces one reconnect signal across concurrent workers', async () => {
    const h = harness({ access_token: 'expired', refresh_token: 'revoked', expires_at: 1 });
    const fetch = vi.fn(async () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 }));
    vi.stubGlobal('fetch', fetch);
    const signal = vi.fn(async () => {}); const service = h.create(undefined, { reconnectRequired: signal });
    const results = await Promise.allSettled(Array.from({ length: 20 }, () =>
      service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')));
    expect(results.every(result => result.status === 'rejected')).toBe(true);
    expect(h.row().status).toBe('expired');
    expect(fetch).toHaveBeenCalledOnce();
    expect(signal).toHaveBeenCalledOnce();
    expect(signal).toHaveBeenCalledWith({ operatorId: 'op_fixture', connectionId: 'scon_fixture', provider: 'custom_fixture', credentialVersion: 1, eventId: 'sec_fixture' });
    expect(h.repo.recordReconnectRequired).toHaveBeenCalledOnce();
  });

  it('expired access without a refresh mechanism pauses work and signals once', async () => {
    const h = harness({ access_token: 'expired', expires_at: 1 });
    const signal = vi.fn(async () => {}); const service = h.create(undefined, { reconnectRequired: signal });
    await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toThrow();
    expect(h.row().status).toBe('expired'); expect(signal).toHaveBeenCalledOnce();
  });

  it('does not decrypt a connection for a different operator', async () => {
    const h = harness({ access_token: 'fresh', refresh_token: 'secret', expires_at: 1 });
    await expect(h.create().retrieveCredentialByConnectionId('op_other', 'scon_fixture')).rejects.toThrow();
    expect(h.kms.decrypt).not.toHaveBeenCalled();
  });

  it('marks a connection made through an app STACK no longer runs as reconnect-required on first use, whatever its token state', async () => {
    const binding = { id: 'system-app', owner_id: 'op_stack_system', provider: 'github', client_id_hash: 'hash',
      service_id: 'svc_fixture', connection_provider: 'custom_fixture', token_url: 'https://identity.example.test/token' };
    // A token that never expires and has no refresh token, and a live refreshable one.
    for (const fields of [
      { access_token: 'never-expires', oauth_app_binding: binding },
      { access_token: 'live', refresh_token: 'refresh', expires_at: Date.now() + 3_600_000, oauth_app_binding: binding },
    ] as CredentialFields[]) {
      const h = harness(fields);
      const resolver = vi.fn();
      const signal = vi.fn(async () => {});
      const service = h.create(undefined, {
        oauthClientResolver: resolver, reconnectRequired: signal, oauthAppRetired: (b) => b.owner_id === 'op_stack_system',
      });
      await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toThrow();
      expect(resolver).not.toHaveBeenCalled();
      expect(h.row().status).toBe('expired');
      expect(h.repo.recordReconnectRequired).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'stack_oauth_app_retired');
      expect(signal).toHaveBeenCalledWith(expect.objectContaining({ eventId: 'sec_fixture', reason: 'stack_oauth_app_retired' }));
      // The stored credential is kept, not deleted.
      expect(h.stored().access_token).toBe(fields.access_token);
    }
  });

  it('marks a connection that holds scopes its app may no longer ask for as reconnect-required, whatever its token state, and leaves others alone', async () => {
    const binding = { id: 'system-app', owner_id: 'op_stack_system', provider: 'google', client_id_hash: 'hash',
      service_id: 'svc_fixture', connection_provider: 'custom_fixture', token_url: 'https://identity.example.test/token' };
    const exceeded = vi.fn((b: { owner_id: string }, provider: string, scopes: readonly string[]) =>
      b.owner_id === 'op_stack_system' && provider === 'custom_fixture' && scopes.some((scope) => scope !== 'read'));
    for (const fields of [
      { access_token: 'never-expires', oauth_app_binding: binding },
      { access_token: 'live', refresh_token: 'refresh', expires_at: Date.now() + 3_600_000, oauth_app_binding: binding },
    ] as CredentialFields[]) {
      const h = harness(fields); // scopes: read, write
      const resolver = vi.fn();
      const signal = vi.fn(async () => {});
      const service = h.create(undefined, { oauthClientResolver: resolver, reconnectRequired: signal, oauthAppScopesExceeded: exceeded });
      await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toMatchObject({
        reconnectRequired: true, reason: 'oauth_app_scopes_narrowed',
      });
      expect(resolver).not.toHaveBeenCalled();
      expect(h.row().status).toBe('expired');
      expect(h.repo.recordReconnectRequired).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'oauth_app_scopes_narrowed');
      expect(signal).toHaveBeenCalledWith(expect.objectContaining({ reason: 'oauth_app_scopes_narrowed' }));
      expect(h.stored().access_token).toBe(fields.access_token);
    }
    // Within the list, or with no hook at all, nothing changes.
    const live = { access_token: 'live', refresh_token: 'refresh', expires_at: Date.now() + 3_600_000, oauth_app_binding: binding } as CredentialFields;
    const within = harness(live);
    expect(await within.create(undefined, { oauthAppScopesExceeded: () => false }).retrieveCredentialByConnectionId('op_fixture', 'scon_fixture'))
      .toHaveProperty('credentials.access_token', 'live');
    expect(within.row().status).toBe('active');
    const unlisted = harness(live);
    await unlisted.create().retrieveCredentialByConnectionId('op_fixture', 'scon_fixture');
    expect(unlisted.row().status).toBe('active');
  });

  describe('the grant of a connection that is closed or marked reconnect-required', () => {
    const binding = { id: 'system-app', owner_id: 'op_stack_system', provider: 'google', client_id_hash: 'hash',
      service_id: 'svc_fixture', connection_provider: 'custom_fixture', token_url: 'https://identity.example.test/token' };
    const fields = (): CredentialFields => ({ access_token: 'live', refresh_token: 'refresh-1', expires_at: Date.now() + 3_600_000, oauth_app_binding: binding });

    it('is handed to the grant hook with the credential when the connection is disconnected, and a failing hook never fails the disconnect', async () => {
      const h = harness(fields());
      Object.assign(h.row(), { oauth_managed: true });
      const dropped = vi.fn(async () => {});
      await h.create(undefined, { grantDropped: dropped }).disconnect('scon_fixture', 'op_fixture');
      expect(h.repo.revokeConnection).toHaveBeenCalledWith('scon_fixture');
      expect(dropped).toHaveBeenCalledWith(
        { id: 'scon_fixture', provider: 'custom_fixture', scopes: ['read', 'write'] },
        expect.objectContaining({ refresh_token: 'refresh-1' }),
        { sharesGrant: expect.any(Function) },
      );

      const broken = harness(fields());
      Object.assign(broken.row(), { oauth_managed: true });
      const failing = vi.fn(async () => { throw new Error('provider down'); });
      await expect(broken.create(undefined, { grantDropped: failing }).disconnect('scon_fixture', 'op_fixture')).resolves.not.toThrow();
      expect(failing).toHaveBeenCalledOnce();
      // No hook: the grant is left alone and nothing else changes.
      await expect(harness(fields()).create().disconnect('scon_fixture', 'op_fixture')).resolves.not.toThrow();
    });

    it('logs and reports a release that failed by connection id and provider only, never the credential, and still never fails the disconnect', async () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const reported = vi.fn();
      const h = harness(fields());
      Object.assign(h.row(), { oauth_managed: true });
      const service = h.create(undefined, {
        grantDropped: async () => { throw new Error('Google said refresh-1 is bad'); },
        grantReleaseFailed: reported,
      });
      await expect(service.disconnect('scon_fixture', 'op_fixture')).resolves.not.toThrow();
      expect(reported).toHaveBeenCalledWith({ connectionId: 'scon_fixture', provider: 'custom_fixture' });
      const logged = warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n');
      expect(logged).toContain('scon_fixture');
      expect(logged).not.toMatch(/refresh-1|Google said/);
      // A reporter that throws never fails it either.
      const loud = harness(fields());
      Object.assign(loud.row(), { oauth_managed: true });
      await expect(loud.create(undefined, {
        grantDropped: async () => { throw new Error('down'); },
        grantReleaseFailed: () => { throw new Error('sentry down'); },
      }).disconnect('scon_fixture', 'op_fixture')).resolves.not.toThrow();
    });

    it('does not read the credential of a disconnect for a connection that was not made through an OAuth app', async () => {
      const h = harness({ api_key: 'a-key' } as CredentialFields);
      const dropped = vi.fn(async () => {});
      await h.create(undefined, { grantDropped: dropped }).disconnect('scon_fixture', 'op_fixture');
      expect(h.repo.revokeConnection).toHaveBeenCalledOnce();
      expect(h.kms.decrypt).not.toHaveBeenCalled();
      expect(dropped).not.toHaveBeenCalled();
    });

    it('is handed to the grant hook when the connection is marked for holding scopes its app may no longer ask for, and for no other reason', async () => {
      const h = harness(fields());
      const dropped = vi.fn(async () => {});
      const service = h.create(undefined, { oauthAppScopesExceeded: () => true, grantDropped: dropped });
      await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toMatchObject({ reason: 'oauth_app_scopes_narrowed' });
      // The release is not waited for: the caller is told at once and the hook runs behind it.
      await vi.waitFor(() => expect(dropped).toHaveBeenCalledOnce());
      expect(dropped).toHaveBeenCalledWith(
        { id: 'scon_fixture', provider: 'custom_fixture', scopes: ['read', 'write'] },
        expect.objectContaining({ refresh_token: 'refresh-1' }),
        { sharesGrant: expect.any(Function) },
      );

      const retired = harness(fields());
      const notDropped = vi.fn(async () => {});
      await expect(retired.create(undefined, { oauthAppRetired: () => true, grantDropped: notDropped })
        .retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toMatchObject({ reason: 'stack_oauth_app_retired' });
      expect(notDropped).not.toHaveBeenCalled();
    });

    describe('whether another live connection of the operator stands on the same grant', () => {
      const ask = async (h: ReturnType<typeof harness>, exceeds: () => boolean = () => false): Promise<boolean> => {
        let answer: boolean | undefined;
        Object.assign(h.row(), { oauth_managed: true });
        await h.create(undefined, {
          oauthAppScopesExceeded: exceeds,
          grantDropped: async (_connection, _credential, context) => { answer = await context.sharesGrant(); },
        }).disconnect('scon_fixture', 'op_fixture');
        return answer!;
      };
      const sibling = (h: ReturnType<typeof harness>, over: Record<string, unknown> = {}, credential: CredentialFields = fields()) => ({
        id: 'scon_sibling', operator_id: 'op_fixture', provider: 'custom_other', status: 'active', oauth_managed: true,
        scopes: ['read'], credential_encrypted: h.encode(JSON.stringify(credential)), ...over,
      });

      it('is yes for a live sibling through the same app within its list, and never counts the connection itself', async () => {
        const h = harness(fields());
        expect(await ask(h)).toBe(false);
        h.siblings.push(sibling(h));
        expect(await ask(h)).toBe(true);
      });

      it('is no for a sibling of another app, one without an app, or one that is itself beyond its list', async () => {
        const other = harness(fields());
        other.siblings.push(sibling(other, {}, { ...fields(), oauth_app_binding: { ...binding, client_id_hash: 'another' } }));
        expect(await ask(other)).toBe(false);
        const keyed = harness(fields());
        keyed.siblings.push(sibling(keyed, { oauth_managed: false }));
        expect(await ask(keyed)).toBe(false);
        const beyond = harness(fields());
        beyond.siblings.push(sibling(beyond, { scopes: ['write'] }));
        expect(await ask(beyond, () => true)).toBe(false);
      });

      it('does not read a connection of a service the app cannot have made, and reads those it can', async () => {
        const h = harness(fields());
        h.siblings.push(sibling(h, { id: 'scon_slack', provider: 'slack' }, { ...fields(), access_token: 'slack-token' }));
        h.siblings.push(sibling(h, { id: 'scon_other', provider: 'custom_other' }, { ...fields(), access_token: 'the-siblings' }));
        const decrypted: string[] = [];
        h.kms.decrypt.mockImplementation(async (value: string) => {
          const plain = Buffer.from(value.slice(10), 'base64').toString();
          decrypted.push(plain);
          return plain;
        });
        let answer: boolean | undefined;
        Object.assign(h.row(), { oauth_managed: true });
        await h.create(undefined, {
          oauthAppServes: (_app, service) => service.startsWith('custom_'),
          grantDropped: async (_connection, _credential, context) => { answer = await context.sharesGrant(); },
        }).disconnect('scon_fixture', 'op_fixture');
        expect(answer).toBe(true);
        expect(decrypted.some((plain) => plain.includes('slack-token'))).toBe(false);
        expect(decrypted.some((plain) => plain.includes('the-siblings'))).toBe(true);
      });

      it('on the lazy mark the wide connection is marked reconnect-required at once, and only the revoke is skipped', async () => {
        const h = harness(fields()); // scopes: read, write
        h.siblings.push(sibling(h)); // scopes: read, within the list
        let shared: boolean | undefined;
        const service = h.create(undefined, {
          oauthAppScopesExceeded: (_binding, _provider, scopes) => scopes.includes('write'),
          grantDropped: async (_connection, _credential, context) => { shared = await context.sharesGrant(); },
        });
        await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toMatchObject({ reason: 'oauth_app_scopes_narrowed' });
        // Marked now, so STACK stops using it; the release is told the grant is shared, so it does not revoke it.
        expect(h.row().status).toBe('expired');
        expect(h.repo.recordReconnectRequired).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'oauth_app_scopes_narrowed');
        await vi.waitFor(() => expect(shared).toBe(true));
      });

      it('fails closed: a sibling that cannot be read counts as sharing', async () => {
        const h = harness(fields());
        h.siblings.push(sibling(h, {}, { ...fields(), access_token: 'the-siblings' }));
        h.kms.decrypt.mockImplementation(async (value: string) => {
          if (value === h.siblings[0]!['credential_encrypted']) throw new Error('kms down');
          return Buffer.from(value.slice(10), 'base64').toString();
        });
        expect(await ask(h)).toBe(true);
      });
    });

    it('does not make the caller wait for a release that is still running', async () => {
      const h = harness(fields());
      let finish!: () => void;
      const slow = vi.fn(() => new Promise<void>((resolve) => { finish = resolve; }));
      const service = h.create(undefined, { oauthAppScopesExceeded: () => true, grantDropped: slow });
      await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toMatchObject({ reason: 'oauth_app_scopes_narrowed' });
      await vi.waitFor(() => expect(slow).toHaveBeenCalledOnce());
      finish();
    });

    it('can be marked reconnect-required now, with the notice a lazy mark gives, once', async () => {
      const h = harness(fields());
      const signal = vi.fn(async () => {});
      const service = h.create(undefined, { reconnectRequired: signal });
      await expect(service.flagReconnectRequired('op_fixture', 'scon_fixture', 'oauth_app_scopes_narrowed')).resolves.toBe(true);
      expect(h.row().status).toBe('expired');
      expect(h.repo.recordReconnectRequired).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'oauth_app_scopes_narrowed');
      expect(signal).toHaveBeenCalledWith(expect.objectContaining({ connectionId: 'scon_fixture', reason: 'oauth_app_scopes_narrowed' }));
      await expect(service.flagReconnectRequired('op_fixture', 'scon_fixture', 'oauth_app_scopes_narrowed')).resolves.toBe(false);
      expect(signal).toHaveBeenCalledOnce();
      expect(h.stored().refresh_token).toBe('refresh-1');
    });
  });

  it('leaves a connection made through an app STACK still runs, or the customer\'s own, alone', async () => {
    const h = harness({ access_token: 'live', refresh_token: 'refresh', expires_at: Date.now() + 3_600_000,
      oauth_app_binding: { id: 'own', owner_id: 'op_fixture', provider: 'google', client_id_hash: 'hash',
        service_id: 'svc_fixture', connection_provider: 'custom_fixture', token_url: 'https://identity.example.test/token' } });
    const service = h.create(undefined, { oauthAppRetired: () => false });
    const result = await service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture');
    expect('credentials' in result && result.credentials.access_token).toBe('live');
    expect(h.row().status).toBe('active');
    expect(h.repo.recordReconnectRequired).not.toHaveBeenCalled();
  });

  it('never resolves system app secrets from forged arbitrary credential JSON', async () => {
    const h = harness({ access_token: 'old', refresh_token: 'old-refresh', expires_at: 1,
      oauth_app_binding: { id: 'system-app', owner_id: 'op_stack_system', provider: 'fixture', client_id_hash: 'hash',
        service_id: 'svc_fixture', connection_provider: 'custom_fixture', token_url: 'https://attacker.example' } });
    const resolver = vi.fn(); const service = h.create(undefined, { oauthClientResolver: resolver });
    await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toThrow();
    expect(resolver).not.toHaveBeenCalled(); expect(h.row().status).toBe('expired');
  });

  it('backs off transient provider failures with only non-secret Redis metadata', async () => {
    const h = harness({ access_token: 'old-secret', refresh_token: 'refresh-secret', expires_at: 1 });
    const cache = new Map<string, string>();
    const redis = { get: vi.fn(async (key: string) => cache.get(key)),
      set: vi.fn(async (key: string, value: string) => { if (!cache.has(key)) cache.set(key, value); return 'OK'; }) };
    const fetch = vi.fn(async () => new Response(JSON.stringify({ error: 'temporarily_unavailable' }), { status: 503 }));
    vi.stubGlobal('fetch', fetch);
    const signal = vi.fn(async () => {}); const service = h.create(redis, { reconnectRequired: signal });
    await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toThrow();
    await expect(service.retrieveCredentialByConnectionId('op_fixture', 'scon_fixture')).rejects.toThrow();
    expect(fetch).toHaveBeenCalledOnce(); expect(signal).not.toHaveBeenCalled();
    expect(h.row().status).toBe('active');
    expect([...cache]).toEqual([['oauth_retry:op_fixture:scon_fixture:1', '1']]);
  });

  it('preserves fail-closed version pinning when a waiter sees a changed connection', async () => {
    const h = harness({ access_token: 'expired', refresh_token: 'old', expires_at: 1 });
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ access_token: 'fresh', refresh_token: 'new', expires_in: 3600 }))));
    const service = h.create();
    const results = await Promise.allSettled(Array.from({ length: 2 }, () =>
      service.retrieveCredentialPinnedByConnectionId('op_fixture', 'scon_fixture', 1)));
    expect(results.filter(value => value.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(value => value.status === 'rejected')).toHaveLength(1);
  });
});
