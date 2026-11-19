import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { printJson, printRecord, printTable } from './format.js';
import { cmdService } from './services.js';
import { cmdApproval } from './approvals.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn(), printRecord: vi.fn(), printTable: vi.fn() }));
vi.mock('node:process', async importOriginal => ({
  ...await importOriginal<object>(),
  exit: vi.fn((code?: number) => { throw new Error(`exit ${code}`); }),
  stderr: { write: vi.fn(), isTTY: false },
}));

const LINK = { link_id: 'cnl_abc', status: 'pending', url: 'https://getstack.run/app/connect/link/token' };

beforeEach(() => vi.clearAllMocks());

describe('service connect-link', () => {
  it('creates a link for a service and prints it with its one URL', async () => {
    vi.mocked(api).mockResolvedValueOnce(LINK);
    await cmdService(['connect-link', 'create', 'github']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/services/connect-links', { body: { service_id: 'github' } });
    expect(printRecord).toHaveBeenCalledWith(LINK);
  });

  it('sends scopes only when given, and prints JSON on --json', async () => {
    vi.mocked(api).mockResolvedValueOnce(LINK);
    await cmdService(['connect-link', 'create', 'github', '--scopes', 'repo, read:user', '--json']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/services/connect-links', { body: { service_id: 'github', scopes: ['repo', 'read:user'] } });
    expect(printJson).toHaveBeenCalledWith(LINK);
    expect(printRecord).not.toHaveBeenCalled();
  });

  it('creates a link for the account\'s own API from its name and hosts, with no credential', async () => {
    vi.mocked(api).mockResolvedValueOnce(LINK);
    await cmdService(['connect-link', 'create', '--custom', 'Acme', '--hosts', 'api.acme.example, .acme.example', '--description', 'Billing']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/services/connect-links', {
      body: { custom: { name: 'Acme', allowed_hosts: ['api.acme.example', '.acme.example'], description: 'Billing' } },
    });
    expect(printRecord).toHaveBeenCalledWith(LINK);
  });

  it('sends a credential template for the account\'s own API when one is named', async () => {
    vi.mocked(api).mockResolvedValueOnce(LINK);
    await cmdService(['connect-link', 'create', '--custom', 'Acme', '--hosts', 'api.acme.example', '--template', 'bearer']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/services/connect-links', {
      body: { custom: { name: 'Acme', allowed_hosts: ['api.acme.example'], template: 'bearer' } },
    });
  });

  it('refuses a custom link with no hosts before any request', async () => {
    await expect(cmdService(['connect-link', 'create', '--custom', 'Acme'])).rejects.toThrow('exit 2');
    expect(api).not.toHaveBeenCalled();
  });

  it('reads a link by id, escaped', async () => {
    vi.mocked(api).mockResolvedValueOnce({ link_id: 'cnl_abc', status: 'connected' });
    await cmdService(['connect-link', 'get', 'cnl_a/b']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/services/connect-links/cnl_a%2Fb');
    expect(printRecord).toHaveBeenCalledWith({ link_id: 'cnl_abc', status: 'connected' });
  });

  it('lists the links still waiting as a table, and as JSON on --json', async () => {
    const links = [{ link_id: 'cnl_abc', provider: 'github', connection_name: 'Work', method: 'key', expires_at: '2026-11-10T12:10:00.000Z' }];
    vi.mocked(api).mockResolvedValueOnce({ links });
    await cmdService(['connect-link', 'list']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/services/connect-links');
    expect(printTable).toHaveBeenCalledWith(['ID', 'PROVIDER', 'NAME', 'METHOD', 'EXPIRES'], [['cnl_abc', 'github', 'Work', 'key', '2026-11-10T12:10:00.000Z']]);
    vi.mocked(api).mockResolvedValueOnce({ links });
    await cmdService(['connect-link', 'list', '--json']);
    expect(printJson).toHaveBeenCalledWith(links);
  });

  it('refuses a missing service, a missing id or an unknown action before any request', async () => {
    await expect(cmdService(['connect-link', 'create'])).rejects.toThrow('exit 2');
    await expect(cmdService(['connect-link', 'create', '--scopes', 'repo'])).rejects.toThrow('exit 2');
    await expect(cmdService(['connect-link', 'get'])).rejects.toThrow('exit 2');
    await expect(cmdService(['connect-link', 'drop', 'x'])).rejects.toThrow('exit 2');
    expect(api).not.toHaveBeenCalled();
  });
});

describe('service connection names', () => {
  it('sends --connection-name at the top level of a catalog link and inside custom on a custom link, and refuses it with --key', async () => {
    await cmdService(['connect-link', 'create', 'github', '--connection-name', 'Work']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/services/connect-links', { body: { service_id: 'github', connection_name: 'Work' } });
    await cmdService(['connect-link', 'create', '--custom', 'Acme', '--hosts', 'api.acme.example', '--connection-name', 'Work']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/services/connect-links', {
      body: { custom: { name: 'Acme', allowed_hosts: ['api.acme.example'], connection_name: 'Work' } },
    });
    vi.mocked(api).mockClear();
    await expect(cmdService(['connect-link', 'create', '--key', 'post', '--connection-name', 'Work'])).rejects.toThrow('exit 2');
    expect(api).not.toHaveBeenCalled();
    await cmdService(['connect-link', 'create', '--key', 'post']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/services/connect-links', { body: { connect: { kind: 'post_address' } } });
  });

  it('lists connections with a NAME column after ID', async () => {
    vi.mocked(api).mockResolvedValueOnce([{ id: 'scon_1', name: 'Work', provider: 'github', status: 'active', scopes: ['repo'] }]);
    await cmdService(['connections']);
    expect(printTable).toHaveBeenCalledWith(['ID', 'NAME', 'PROVIDER', 'STATUS', 'SCOPES'], [['scon_1', 'Work', 'github', 'active', 'repo']]);
  });

  it('renames a connection with a PATCH, the id escaped, and refuses a missing name before any request', async () => {
    await cmdService(['rename', 'scon_a/b', 'Personal']);
    expect(api).toHaveBeenCalledWith('PATCH', '/v1/services/scon_a%2Fb', { body: { connection_name: 'Personal' } });
    await expect(cmdService(['rename', 'scon_a'])).rejects.toThrow('exit 2');
    expect(api).toHaveBeenCalledTimes(1);
  });

  it('reads a credential for one connection with --connection, and for the provider alone without it', async () => {
    await cmdService(['credential', 'github', '--connection', 'Work']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/credentials/github', { query: { connection: 'Work' } });
    await cmdService(['credential', 'github']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/credentials/github', { query: { connection: undefined } });
  });
});

describe('approval show', () => {
  const DETAIL = {
    approval: { id: 'gvr_abc', status: 'pending', summary: 'Start the platform subscription' },
    payload_hash: 'a'.repeat(64),
    approval_url: 'https://getstack.run/app/approve/gvr_abc',
  };

  it('reads one approval and prints its fields with the hash and the link', async () => {
    vi.mocked(api).mockResolvedValueOnce(DETAIL);
    await cmdApproval(['show', 'gvr_abc']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/governance/approvals/gvr_abc');
    expect(printRecord).toHaveBeenCalledWith({ ...DETAIL.approval, payload_hash: DETAIL.payload_hash, approval_url: DETAIL.approval_url });
  });

  it('prints the whole detail on --json and escapes the id', async () => {
    vi.mocked(api).mockResolvedValueOnce(DETAIL);
    await cmdApproval(['show', 'gvr_a/b', '--json']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/governance/approvals/gvr_a%2Fb');
    expect(printJson).toHaveBeenCalledWith(DETAIL);
  });

  it('lists the approvals, only those in one status when asked, and prints JSON on --json', async () => {
    const rows = [
      { id: 'gvr_1', action: 'agent_unblock', summary: 'Unblock agent', status: 'pending', expires_at: '2026-10-21T12:00:00.000Z' },
      { id: 'gvr_2', action: 'billing_mutate', summary: 'Start the plan', status: 'expired', expires_at: '2026-10-19T12:00:00.000Z' },
    ];
    vi.mocked(api).mockResolvedValue({ approvals: rows });
    await cmdApproval(['list']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/governance/approvals');
    expect(vi.mocked(printTable).mock.calls[0]![1].map((row) => row[0])).toEqual(['gvr_1', 'gvr_2']);
    await cmdApproval(['list', '--status', 'pending']);
    expect(vi.mocked(printTable).mock.calls[1]![1].map((row) => row[0])).toEqual(['gvr_1']);
    await cmdApproval(['list', '--status', 'expired', '--json']);
    expect(printJson).toHaveBeenCalledWith({ approvals: [rows[1]] });
    vi.mocked(api).mockReset();
  });

  it('refuses a status that is not one before calling the API', async () => {
    await expect(cmdApproval(['list', '--status', 'decided'])).rejects.toThrow('exit 2');
    await expect(cmdApproval(['list', '--status'])).rejects.toThrow('exit 2');
    expect(api).not.toHaveBeenCalled();
  });

  it('only reads: no decision verb exists', async () => {
    await expect(cmdApproval(['approve', 'gvr_abc'])).rejects.toThrow('exit 2');
    await expect(cmdApproval(['show'])).rejects.toThrow('exit 2');
    await expect(cmdApproval([])).rejects.toThrow('exit 2');
    expect(api).not.toHaveBeenCalled();
  });
});
