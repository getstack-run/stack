import { ConflictError, ConnectionAmbiguousError, ForbiddenError, NotFoundError } from '@stack/shared';
import { describe, expect, it, vi } from 'vitest';
import {
  ConnectionPrincipalConflictError,
  ServiceConnectionService,
  allowedHostsWiden,
  grantAuthorityWidens,
  standaloneServiceConnectionHooks,
  type ServiceConnectionHooks,
} from './service-connection-service.js';

const SERVICE = {
  id: 'svc_agentmail',
  provider: 'agentmail',
  name: 'AgentMail',
  scopes_available: ['*'],
};

function makeSubject(
  overrides: Record<string, unknown> = {},
  agentOverrides: Record<string, unknown> = {},
  hooks: Partial<ServiceConnectionHooks> = {},
) {
  const repo = {
    findAccessibleServiceById: vi.fn(async () => SERVICE),
    findCatalogServiceByProvider: vi.fn(async () => undefined),
    upsertCustomService: vi.fn(async (_operatorId, row) => ({ ...row, operator_id: _operatorId })),
    findConfigurationByOperatorAndProvider: vi.fn(async () => undefined),
    findActiveConnectionsForPrincipal: vi.fn(async () => []),
    findActiveConnectionsByOperatorAndProvider: vi.fn(async () => []),
    findMemberById: vi.fn(async (memberId: string) => ({
      id: memberId,
      operator_id: 'op_owner',
      status: 'active',
    })),
    countConnectionsByOperator: vi.fn(async () => 0),
    createConnection: vi.fn(async (row) => row),
    upsertConfiguration: vi.fn(async (row) => row),
    findConnectionById: vi.fn(async () => undefined),
    findConnectionsByOperator: vi.fn(async () => []),
    findActiveConnectionByOperatorAndProvider: vi.fn(async () => undefined),
    findEligibleProxyConnections: vi.fn(async () => []),
    renameConnection: vi.fn(async (id: string, _operatorId: string, name: string) => ({ id, name })),
    replaceCredential: vi.fn(async () => undefined),
    findGrantByAgentAndConnection: vi.fn(async () => undefined),
    deleteGrant: vi.fn(async () => undefined),
    deleteRevokedGrantsForAgentConnection: vi.fn(async () => undefined),
    createGrant: vi.fn(async (row) => row),
    withOperatorGrantLock: vi.fn(async (_operatorId, work) => work({})),
    ...overrides,
  };
  const agentRepo = {
    findById: vi.fn(async () => ({ id: 'agt_support', operator_id: 'op_owner' })),
    ...agentOverrides,
  };
  const kms = {
    encrypt: vi.fn(async () => ({ ciphertext: 'ciphertext', keyRef: 'kms:key' })),
    decrypt: vi.fn(async () => 'decrypted-secret'),
  };
  const subject = new ServiceConnectionService(
    repo as never,
    agentRepo as never,
    kms as never,
    undefined,
    {
      ...standaloneServiceConnectionHooks,
      // No fleet runs agents in these scenarios, so the guard has nothing to refuse.
      externalAgentGuard: async () => undefined,
      ...hooks,
    },
  );
  return { subject, repo, agentRepo, kms };
}

describe('ServiceConnectionService member connection ceiling', () => {
  const connection = {
    id: 'scon_allowed',
    operator_id: 'op_owner',
    service_id: SERVICE.id,
    provider: SERVICE.provider,
    status: 'active',
    credential_encrypted: 'ciphertext',
  };

  it('treats undefined as unrestricted and an empty list as no visible connections', async () => {
    const rows = [connection, { ...connection, id: 'scon_other' }];
    const { subject } = makeSubject({
      findConnectionsByOperator: vi.fn(async () => rows),
    });

    await expect(subject.listConnectedServices('op_owner')).resolves.toEqual(rows);
    await expect(subject.listConnectedServices('op_owner', [])).resolves.toEqual([]);
  });

  it('names a connection for an approval only while the account holds two or more active connections of the service', async () => {
    const named = { ...connection, name: 'Work' };
    const several = makeSubject({
      findConnectionById: vi.fn(async () => named),
      findActiveConnectionsByOperatorAndProvider: vi.fn(async () => [named, { ...named, id: 'scon_home', name: 'Home' }]),
    });
    await expect(several.subject.connectionNameWhenSeveral('scon_allowed', 'op_owner')).resolves.toBe('Work');
    const single = makeSubject({
      findConnectionById: vi.fn(async () => named),
      findActiveConnectionsByOperatorAndProvider: vi.fn(async () => [named]),
    });
    await expect(single.subject.connectionNameWhenSeveral('scon_allowed', 'op_owner')).resolves.toBeNull();
    // A connection of another account is not found: no name. One outside the caller's allowed list is refused.
    await expect(several.subject.connectionNameWhenSeveral('scon_allowed', 'op_other')).resolves.toBeNull();
    await expect(several.subject.connectionNameWhenSeveral('scon_allowed', 'op_owner', ['scon_other'])).rejects.toThrow();
  });

  it('returns only explicitly allowed connections to a restricted member', async () => {
    const { subject } = makeSubject({
      findConnectionsByOperator: vi.fn(async () => [
        connection,
        { ...connection, id: 'scon_other' },
      ]),
    });

    await expect(subject.listConnectedServices('op_owner', ['scon_other'])).resolves.toEqual([
      expect.objectContaining({ id: 'scon_other' }),
    ]);
  });

  it('denies provider lookup before decrypting when the member list is empty', async () => {
    const { subject, kms } = makeSubject({
      findEligibleProxyConnections: vi.fn(async () => [{ ...connection, name: 'default', member_id: null }]),
    });

    await expect(subject.retrieveCredential('op_owner', SERVICE.provider, [])).rejects.toBeInstanceOf(
      ForbiddenError,
    );
    expect(kms.decrypt).not.toHaveBeenCalled();
  });

  it('denies connection-id lookup before decrypting when the id is not allowed', async () => {
    const { subject, kms } = makeSubject({
      findConnectionById: vi.fn(async () => connection),
    });

    await expect(
      subject.retrieveCredentialByConnectionId('op_owner', connection.id, ['scon_other']),
    ).rejects.toBeInstanceOf(ForbiddenError);
    expect(kms.decrypt).not.toHaveBeenCalled();
  });

  it('resolves personal-first proxy metadata without decrypting a credential', async () => {
    const selected = {
      ...connection,
      credential_version: 7,
      proxy_enabled: true,
      allowed_hosts: ['api.agentmail.to'],
      member_id: 'member_alice',
    };
    const { subject, kms, repo } = makeSubject({
      findEligibleProxyConnections: vi.fn(async () => [{ ...selected, name: 'default' }]),
    });
    await expect(subject.resolveProxyConnection(
      'op_owner',
      SERVICE.provider,
      { kind: 'member', memberId: 'member_alice', allowedConnections: [connection.id] },
    )).resolves.toMatchObject({
      connection_id: connection.id,
      name: 'default',
      credential_version: 7,
      allowed_hosts: ['api.agentmail.to'],
    });
    expect(repo.findEligibleProxyConnections).toHaveBeenCalledTimes(1);
    expect(kms.decrypt).not.toHaveBeenCalled();
  });

  it('fails closed before decrypt when the selected credential version changed', async () => {
    const { subject, kms } = makeSubject({
      findConnectionById: vi.fn(async () => ({ ...connection, credential_version: 8 })),
    });
    await expect(subject.retrieveCredentialPinnedByConnectionId(
      'op_owner', connection.id, 7, [connection.id],
    )).rejects.toBeInstanceOf(ConflictError);
    expect(kms.decrypt).not.toHaveBeenCalled();
  });

  it('filters agent-permission views to the member connection ceiling', async () => {
    const { subject } = makeSubject({
      findGrantsWithConnectionByAgent: vi.fn(async () => [
        { grant: { id: 'grant_allowed', service_connection_id: 'scon_allowed', scopes: ['read'] }, connection },
        { grant: { id: 'grant_other', service_connection_id: 'scon_other', scopes: ['write'] }, connection: { ...connection, id: 'scon_other' } },
      ]),
    });

    await expect(subject.getAgentPermissions('agt_support', 'op_owner', ['scon_allowed']))
      .resolves.toEqual([expect.objectContaining({ grant_id: 'grant_allowed' })]);
  });

  it('limits service configurations to the providers of a member\'s allowed connections', async () => {
    const configurations = [
      { id: 'svcfg_slack', operator_id: 'op_owner', service_id: 'svc_slack', provider: 'slack', mode: 'shared' },
      { id: 'svcfg_github', operator_id: 'op_owner', service_id: 'svc_github', provider: 'github', mode: 'per_member' },
    ];
    const { subject } = makeSubject({
      findConfigurationsByOperator: vi.fn(async () => configurations),
      findConnectionsByOperator: vi.fn(async () => [
        { id: 'scon_slack', operator_id: 'op_owner', provider: 'slack' },
        { id: 'scon_github', operator_id: 'op_owner', provider: 'github' },
      ]),
    });

    // Unrestricted principals (operator keys, owners, unrestricted members) see every configuration.
    await expect(subject.getServiceConfigurations('op_owner')).resolves.toEqual(configurations);
    // A member limited to no connections sees none, and the request still succeeds.
    await expect(subject.getServiceConfigurations('op_owner', [])).resolves.toEqual([]);
    // A member limited to named connections sees only those connections' providers.
    await expect(subject.getServiceConfigurations('op_owner', ['scon_slack']))
      .resolves.toEqual([configurations[0]]);
  });

  it('denies operator-wide service mutations to connection-restricted members', () => {
    const { subject } = makeSubject();
    expect(() => subject.assertConnectionAccess([])).toThrow(ForbiddenError);
  });
});

describe('ServiceConnectionService connection principals', () => {
  it('rejects a member connection when the service uses shared mode', async () => {
    const { subject, kms } = makeSubject({
      findConfigurationByOperatorAndProvider: vi.fn(async () => ({ mode: 'shared' })),
    });

    await expect(subject.connectApplication(
      'op_owner',
      'enterprise',
      { service_id: SERVICE.id, credential: { api_key: 'secret' } },
      'member_owner',
      'member_alice',
    )).rejects.toBeInstanceOf(ConflictError);
    expect(kms.encrypt).not.toHaveBeenCalled();
  });

  it('stores every scope for a catalogue service that lists none, and keeps listed or explicit scopes', async () => {
    const input = { service_id: SERVICE.id, credential: { api_key: 'secret' } };
    const noScopes = makeSubject({
      findAccessibleServiceById: vi.fn(async () => ({ ...SERVICE, scopes_available: [] })),
    });
    await noScopes.subject.connectApplication('op_owner', 'enterprise', input);
    expect(noScopes.repo.createConnection).toHaveBeenCalledWith(expect.objectContaining({ scopes: ['*'] }));

    const listed = makeSubject({
      findAccessibleServiceById: vi.fn(async () => ({ ...SERVICE, scopes_available: ['chat:write'] })),
    });
    await listed.subject.connectApplication('op_owner', 'enterprise', input);
    expect(listed.repo.createConnection).toHaveBeenCalledWith(expect.objectContaining({ scopes: ['chat:write'] }));

    const explicit = makeSubject({
      findAccessibleServiceById: vi.fn(async () => ({ ...SERVICE, scopes_available: [] })),
    });
    await explicit.subject.connectApplication('op_owner', 'enterprise', { ...input, scopes: ['read'] });
    expect(explicit.repo.createConnection).toHaveBeenCalledWith(expect.objectContaining({ scopes: ['read'] }));
  });

  it('rejects a shared connection when the service uses per-member mode', async () => {
    const { subject, kms } = makeSubject({
      findConfigurationByOperatorAndProvider: vi.fn(async () => ({ mode: 'per_member' })),
    });

    await expect(subject.connectApplication(
      'op_owner',
      'enterprise',
      { service_id: SERVICE.id, credential: { api_key: 'secret' } },
    )).rejects.toBeInstanceOf(ConflictError);
    expect(kms.encrypt).not.toHaveBeenCalled();
  });

  it('names why a principal cannot connect, so the hosted OAuth flow can refuse before consent', async () => {
    const perMember = makeSubject({
      findConfigurationByOperatorAndProvider: vi.fn(async () => ({ mode: 'per_member' })),
    });
    const refused = perMember.subject.assertConnectionPrincipal('op_owner', 'github');
    await expect(refused).rejects.toBeInstanceOf(ConnectionPrincipalConflictError);
    await expect(refused).rejects.toMatchObject({
      reason: 'service_per_member_mode', code: 'CONFLICT', statusCode: 409,
    });

    const existing = makeSubject({
      findActiveConnectionsForPrincipal: vi.fn(async () => [{ id: 'scon_existing', name: 'default' }]),
    });
    await expect(existing.subject.assertConnectionPrincipal('op_owner', 'github'))
      .rejects.toMatchObject({ reason: 'connection_name_taken' });

    await expect(makeSubject().subject.assertConnectionPrincipal('op_owner', 'github'))
      .resolves.toBeUndefined();
  });

  it('rejects an existing active connection of the same name for the same principal before encryption', async () => {
    const { subject, kms } = makeSubject({
      findActiveConnectionsForPrincipal: vi.fn(async () => [{ id: 'scon_existing', name: 'default' }]),
    });

    await expect(subject.connectApplication(
      'op_owner',
      'enterprise',
      { service_id: SERVICE.id, credential: { api_key: 'secret' }, connection_name: 'Default' },
    )).rejects.toBeInstanceOf(ConflictError);
    expect(kms.encrypt).not.toHaveBeenCalled();
  });

  it('rejects a foreign member principal before encryption', async () => {
    const { subject, kms } = makeSubject({
      findMemberById: vi.fn(async () => ({
        id: 'member_foreign',
        operator_id: 'op_other',
        status: 'active',
      })),
    });

    await expect(subject.connectApplication(
      'op_owner',
      'enterprise',
      { service_id: SERVICE.id, credential: { api_key: 'secret' } },
      'member_owner',
      'member_foreign',
    )).rejects.toBeInstanceOf(ConflictError);
    expect(kms.encrypt).not.toHaveBeenCalled();
  });

  it('rejects a configuration mode that conflicts with active principals', async () => {
    const { subject, repo } = makeSubject({
      findActiveConnectionsByOperatorAndProvider: vi.fn(async () => [
        { id: 'scon_shared', member_id: null },
      ]),
    });

    await expect(subject.configureService(
      'op_owner',
      SERVICE.id,
      SERVICE.provider,
      'per_member',
    )).rejects.toBeInstanceOf(ConflictError);
    expect(repo.upsertConfiguration).not.toHaveBeenCalled();
  });

  it('creates a connection when the selected mode and principal agree', async () => {
    const { subject, repo, kms } = makeSubject({
      findConfigurationByOperatorAndProvider: vi.fn(async () => ({ mode: 'per_member' })),
    });

    const result = await subject.connectApplication(
      'op_owner',
      'enterprise',
      { service_id: SERVICE.id, credential: { api_key: 'secret' } },
      'member_owner',
      'member_alice',
    );

    expect(result).toMatchObject({ provider: SERVICE.provider, member_id: 'member_alice' });
    expect(kms.encrypt).toHaveBeenCalledOnce();
    expect(repo.createConnection).toHaveBeenCalledOnce();
  });

  it('returns a clean conflict when the unique index wins a concurrent insert race', async () => {
    const { subject, repo } = makeSubject({
      createConnection: vi.fn(async () => {
        throw new ConflictError('An active connection already exists for this service principal');
      }),
    });

    await expect(subject.connectApplication(
      'op_owner',
      'enterprise',
      { service_id: SERVICE.id, credential: { api_key: 'secret-not-for-errors' } },
    )).rejects.toMatchObject({
      message: 'An active connection already exists for this service principal',
    });
    expect(repo.createConnection).toHaveBeenCalledOnce();
  });
});

describe('ServiceConnectionService standing data-flow grants', () => {
  const input = {
    agent_id: 'agt_support',
    service_connection_id: 'scon_resend',
    scopes: ['*'],
    allow_data_from: ['guestbook'],
  };
  const connection = {
    id: 'scon_resend',
    operator_id: 'op_owner',
    scopes: ['*'],
  };

  it('classifies a newly added source as widening', async () => {
    const { subject } = makeSubject({
      findConnectionById: vi.fn(async () => connection),
      findGrantByAgentAndConnection: vi.fn(async () => ({
        scopes: ['*'], constraints: null, allow_data_from: null,
      })),
    });

    await expect(subject.grantAccessWidens('op_owner', input)).resolves.toBe(true);
  });

  it('rechecks at mutation time and refuses an unapproved widening', async () => {
    const { subject, repo } = makeSubject({
      findConnectionById: vi.fn(async () => connection),
      findGrantByAgentAndConnection: vi
        .fn()
        .mockResolvedValueOnce({ scopes: ['*'], constraints: null, allow_data_from: ['guestbook'] })
        .mockResolvedValueOnce(undefined),
    });

    await expect(subject.grantAccessWidens('op_owner', input)).resolves.toBe(false);
    await expect(subject.grantAgentAccess('op_owner', input)).rejects.toBeInstanceOf(ForbiddenError);
    expect(repo.createGrant).not.toHaveBeenCalled();
  });

  it('persists the exact approved source list', async () => {
    const { subject, repo } = makeSubject({
      findConnectionById: vi.fn(async () => connection),
      findGrantByAgentAndConnection: vi.fn(async () => undefined),
    });

    await subject.grantAgentAccess('op_owner', input, { authorityExpansionApproved: true });
    expect(repo.createGrant).toHaveBeenCalledWith(
      expect.objectContaining({ allow_data_from: ['guestbook'] }),
      expect.anything(),
    );
  });

  it('classifies scope additions and removed constraints as widening', () => {
    const existing = {
      scopes: ['mail.read'],
      constraints: [{ path: 'method', op: 'eq' as const, value: 'GET' }],
      allow_data_from: null,
    };
    expect(grantAuthorityWidens(existing, {
      scopes: ['mail.read', 'mail.send'], constraints: existing.constraints, allow_data_from: [],
    })).toBe(true);
    expect(grantAuthorityWidens(existing, {
      scopes: ['mail.read'], constraints: [], allow_data_from: [],
    })).toBe(true);
  });

  it('allows pure grant narrowing without approval', () => {
    const baseline = [{ path: 'method', op: 'eq' as const, value: 'GET' }];
    expect(grantAuthorityWidens({
      scopes: ['*'], constraints: baseline, allow_data_from: ['crm'],
    }, {
      scopes: ['mail.read'],
      constraints: [...baseline, { path: 'url.pathname', op: 'starts_with', value: '/safe' }],
      allow_data_from: [],
    })).toBe(false);
  });
});

describe('ServiceConnectionService hooks', () => {
  const complete = {
    ...standaloneServiceConnectionHooks,
    externalAgentGuard: async () => undefined,
  };
  const construct = (hooks: unknown) =>
    new ServiceConnectionService({} as never, {} as never, {} as never, undefined, hooks as never);

  it('builds when every hook is supplied', () => {
    expect(() => construct(complete)).not.toThrow();
  });

  it.each(Object.keys(complete))('cannot be constructed without %s', (key) => {
    const { [key as keyof typeof complete]: _omitted, ...rest } = complete;
    void _omitted;
    expect(() => construct(rest)).toThrow(`requires its ${key} hook`);
  });

  it('asks the external agent guard before a grant touches the repository', async () => {
    const guard = vi.fn(async () => { throw new ForbiddenError('fleet-run agent'); });
    const { subject, repo, agentRepo } = makeSubject({}, {}, { externalAgentGuard: guard });
    const input = { agent_id: 'agt_support', service_connection_id: 'scon_resend', scopes: ['*'] };

    await expect(subject.grantAgentAccess('op_owner', input)).rejects.toBeInstanceOf(ForbiddenError);
    await expect(subject.grantAccessWidens('op_owner', input)).rejects.toBeInstanceOf(ForbiddenError);
    await expect(subject.revokeAgentAccess('agt_support', 'op_owner')).rejects.toBeInstanceOf(ForbiddenError);
    expect(guard).toHaveBeenCalledTimes(3);
    expect(guard).toHaveBeenCalledWith('op_owner', 'agt_support');
    expect(agentRepo.findById).not.toHaveBeenCalled();
    expect(repo.withOperatorGrantLock).not.toHaveBeenCalled();
  });

  it('standalone hooks end managed OAuth renewal as reconnect-required and log only connection identity', async () => {
    await expect(
      standaloneServiceConnectionHooks.oauthClientResolver('op_owner', {} as never, {
        serviceId: 'svc_x',
        provider: 'x',
        tokenUrl: 'https://identity.example.test/token',
      }),
    ).rejects.toMatchObject({ reconnectRequired: true });

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      await standaloneServiceConnectionHooks.reconnectRequired({
        operatorId: 'op_owner',
        connectionId: 'scon_x',
        provider: 'x',
        credentialVersion: 3,
        eventId: 'sec_x',
      });
      expect(warn).toHaveBeenCalledOnce();
      expect((warn.mock.calls[0] ?? []).map(String).join(' ')).toContain('scon_x');
    } finally {
      warn.mockRestore();
    }
  });

  it('refuses grant changes in a process that hosts no fleet guard', async () => {
    const { subject } = makeSubject({}, {}, standaloneServiceConnectionHooks);
    await expect(
      subject.grantAgentAccess('op_owner', { agent_id: 'agt_support', service_connection_id: 'scon_resend', scopes: ['*'] }),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });
});

describe('ServiceConnectionService destination authority', () => {
  it('recognizes narrowing a suffix to one exact host', () => {
    expect(allowedHostsWiden(['.example.com'], ['api.example.com'])).toBe(false);
    expect(allowedHostsWiden(['api.example.com'], ['.example.com'])).toBe(true);
  });
});

describe('ServiceConnectionService connection names', () => {
  const connect = { service_id: SERVICE.id, credential: { api_key: 'secret' } };
  const existing = (name: string, id = 'scon_existing') => ({ id, name });

  it('names a principal\'s first connection default and keeps a name it was given', async () => {
    const first = makeSubject();
    await first.subject.connectApplication('op_owner', 'enterprise', connect);
    expect(first.repo.createConnection).toHaveBeenCalledWith(expect.objectContaining({ name: 'default' }));

    const named = makeSubject();
    await named.subject.connectApplication('op_owner', 'enterprise', { ...connect, connection_name: 'work' });
    expect(named.repo.createConnection).toHaveBeenCalledWith(expect.objectContaining({ name: 'work' }));
  });

  it('adds a second connection of the same service when it has a different name', async () => {
    const { subject, repo } = makeSubject({
      findActiveConnectionsForPrincipal: vi.fn(async () => [existing('default')]),
    });
    await subject.connectApplication('op_owner', 'enterprise', { ...connect, connection_name: 'personal' });
    expect(repo.createConnection).toHaveBeenCalledWith(expect.objectContaining({ name: 'personal' }));
  });

  it('refuses a second connection with no name, and a taken name in any case, before encryption', async () => {
    const { subject, kms } = makeSubject({
      findActiveConnectionsForPrincipal: vi.fn(async () => [existing('Work')]),
    });
    await expect(subject.connectApplication('op_owner', 'enterprise', connect))
      .rejects.toMatchObject({ reason: 'connection_name_taken', statusCode: 409 });
    await expect(subject.connectApplication('op_owner', 'enterprise', { ...connect, connection_name: 'wORK' }))
      .rejects.toBeInstanceOf(ConnectionPrincipalConflictError);
    expect(kms.encrypt).not.toHaveBeenCalled();
  });

  it('carries the name through connect and connectCustom', async () => {
    const viaConnect = makeSubject();
    await viaConnect.subject.connect('op_owner', 'enterprise', {
      service_id: SERVICE.id, scopes: ['read'], oauth_token: 'tok', connection_name: 'ops', allowed_hosts: ['api.agentmail.to'],
    });
    expect(viaConnect.repo.createConnection).toHaveBeenCalledWith(expect.objectContaining({ name: 'ops' }));

    const viaCustom = makeSubject();
    await viaCustom.subject.connectCustom('op_owner', 'enterprise', {
      name: 'Acme', credential: 'key', allowed_hosts: ['api.acme.example'], connection_name: 'eu',
    });
    expect(viaCustom.repo.createConnection).toHaveBeenCalledWith(expect.objectContaining({ name: 'eu' }));
  });

  it('renames an active connection, refuses a name a sibling holds, and keeps other accounts out', async () => {
    const row = { id: 'scon_a', operator_id: 'op_owner', provider: 'agentmail', member_id: null, status: 'active' };
    const { subject, repo } = makeSubject({
      findConnectionById: vi.fn(async () => row),
      findActiveConnectionsForPrincipal: vi.fn(async () => [{ ...row, name: 'default' }, { id: 'scon_b', name: 'Work' }]),
    });
    await expect(subject.renameConnection('op_owner', 'scon_a', 'personal')).resolves.toMatchObject({ name: 'personal' });
    expect(repo.renameConnection).toHaveBeenCalledWith('scon_a', 'op_owner', 'personal');
    // Changing only the case of its own name is allowed.
    await expect(subject.renameConnection('op_owner', 'scon_a', 'Default')).resolves.toMatchObject({ name: 'Default' });
    await expect(subject.renameConnection('op_owner', 'scon_a', 'work'))
      .rejects.toMatchObject({ reason: 'connection_name_taken' });
    await expect(subject.renameConnection('op_other', 'scon_a', 'x')).rejects.toBeInstanceOf(NotFoundError);
    await expect(subject.renameConnection('op_owner', 'scon_a', 'scon_zzz')).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });
});

describe('ServiceConnectionService connection resolver', () => {
  const row = (id: string, name: string, member_id: string | null = null) => ({
    id,
    operator_id: 'op_owner',
    service_id: SERVICE.id,
    provider: SERVICE.provider,
    name,
    member_id,
    status: 'active',
    credential_version: 1,
    proxy_enabled: true,
    allowed_hosts: ['api.agentmail.to'],
  });
  const work = row('scon_work', 'work');
  const personal = row('scon_personal', 'Personal');
  const subjectWith = (rows: ReturnType<typeof row>[]) => {
    // The repository narrows by principal and ids; the fake does the same so the resolver is tested against it.
    const find = vi.fn(async (_op: string, _provider: string, principal: 'shared' | { memberId: string }, ids?: readonly string[]) =>
      rows.filter((r) =>
        (principal === 'shared' ? r.member_id === null : r.member_id === null || r.member_id === principal.memberId)
        && (ids === undefined || ids.includes(r.id))));
    return { ...makeSubject({ findEligibleProxyConnections: find }), find };
  };

  it('returns the only eligible connection with no selector', async () => {
    const { subject, kms } = subjectWith([work]);
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, { kind: 'shared' }))
      .resolves.toMatchObject({ connection_id: 'scon_work', name: 'work' });
    expect(kms.decrypt).not.toHaveBeenCalled();
  });

  it('refuses several eligible connections with no selector, listing only the eligible ones, before any decrypt', async () => {
    const { subject, kms } = subjectWith([work, personal]);
    const refused = subject.resolveProxyConnection('op_owner', SERVICE.provider, {
      kind: 'connections', connectionIds: ['scon_work', 'scon_personal'],
    });
    await expect(refused).rejects.toBeInstanceOf(ConnectionAmbiguousError);
    await expect(refused).rejects.toMatchObject({
      code: 'CONNECTION_AMBIGUOUS',
      statusCode: 409,
      details: { connections: [{ id: 'scon_work', name: 'work' }, { id: 'scon_personal', name: 'Personal' }] },
    });
    expect(kms.decrypt).not.toHaveBeenCalled();

    // A grant to one of the two leaves nothing to choose.
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, {
      kind: 'connections', connectionIds: ['scon_personal'],
    })).resolves.toMatchObject({ connection_id: 'scon_personal' });
  });

  it('picks by name without case and by id, inside the eligible set', async () => {
    const { subject } = subjectWith([work, personal]);
    const eligible = { kind: 'connections' as const, connectionIds: ['scon_work', 'scon_personal'] };
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, eligible, 'PERSONAL'))
      .resolves.toMatchObject({ connection_id: 'scon_personal' });
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, eligible, 'scon_work'))
      .resolves.toMatchObject({ connection_id: 'scon_work' });
  });

  it('answers a name or id outside the eligible set exactly as it answers an unknown one', async () => {
    const { subject } = subjectWith([work, personal]);
    const onlyWork = { kind: 'connections' as const, connectionIds: ['scon_work'] };
    const ungranted = subject.resolveProxyConnection('op_owner', SERVICE.provider, onlyWork, 'personal');
    const unknown = subject.resolveProxyConnection('op_owner', SERVICE.provider, onlyWork, 'nothing-here');
    const byId = subject.resolveProxyConnection('op_owner', SERVICE.provider, onlyWork, 'scon_personal');
    for (const refused of [ungranted, unknown, byId]) {
      await expect(refused).rejects.toBeInstanceOf(NotFoundError);
    }
    const messages = await Promise.all([ungranted, unknown, byId].map((p) => p.catch((error: Error) => error.message)));
    expect(new Set(messages).size).toBe(1);
  });

  it('never offers a connection outside the eligible set, and none at all for an empty one', async () => {
    const { subject } = subjectWith([work, personal]);
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, { kind: 'connections', connectionIds: [] }))
      .rejects.toBeInstanceOf(NotFoundError);
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, { kind: 'connections', connectionIds: ['scon_gone'] }, 'work'))
      .rejects.toBeInstanceOf(NotFoundError);
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, {
      kind: 'member', memberId: 'member_a', allowedConnections: [],
    })).rejects.toBeInstanceOf(NotFoundError);
  });

  it('lets a grant that names no connection stand for the one shared connection, and for none of several', async () => {
    const one = subjectWith([work]);
    await expect(one.subject.resolveProxyConnection('op_owner', SERVICE.provider, {
      kind: 'connections', connectionIds: [], sharedFallback: true,
    })).resolves.toMatchObject({ connection_id: 'scon_work' });

    const two = subjectWith([work, personal]);
    await expect(two.subject.resolveProxyConnection('op_owner', SERVICE.provider, {
      kind: 'connections', connectionIds: [], sharedFallback: true,
    })).rejects.toBeInstanceOf(NotFoundError);
    // A pinned grant still resolves beside the unpinned one.
    await expect(two.subject.resolveProxyConnection('op_owner', SERVICE.provider, {
      kind: 'connections', connectionIds: ['scon_work'], sharedFallback: true,
    })).resolves.toMatchObject({ connection_id: 'scon_work' });
  });

  it('serves a member their own connection first, then the shared ones, and filters both by the allow list', async () => {
    const mine = row('scon_mine', 'mine', 'member_a');
    const { subject } = subjectWith([work, mine, row('scon_theirs', 'theirs', 'member_b')]);
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, { kind: 'member', memberId: 'member_a' }))
      .resolves.toMatchObject({ connection_id: 'scon_mine' });
    // Nothing of their own: the shared one. Another member's is never offered.
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, { kind: 'member', memberId: 'member_c' }))
      .resolves.toMatchObject({ connection_id: 'scon_work' });
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, { kind: 'member', memberId: 'member_a' }, 'theirs'))
      .rejects.toBeInstanceOf(NotFoundError);
    await expect(subject.resolveProxyConnection('op_owner', SERVICE.provider, { kind: 'member', memberId: 'member_a' }, 'work'))
      .resolves.toMatchObject({ connection_id: 'scon_work' });
  });

  it('refuses a by-provider read of a service with several connections instead of picking one', async () => {
    const { subject, kms } = subjectWith([work, personal]);
    await expect(subject.retrieveCredential('op_owner', SERVICE.provider)).rejects.toBeInstanceOf(ConnectionAmbiguousError);
    expect(kms.decrypt).not.toHaveBeenCalled();
  });
});
