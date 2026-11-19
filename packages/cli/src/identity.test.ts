import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { governedApi } from './governance.js';
import { cmdIdentity } from './identity.js';

const domain = {
  id: 'ssod_1',
  domain: 'corp.example.com',
  status: 'pending',
  record: { type: 'TXT', name: '_stack-sso.corp.example.com', value: 'stack-sso-verification=abc' },
  verified_at: null,
  last_checked_at: null,
  last_check: null,
};

vi.mock('./api.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  api: vi.fn(async () => ({ domains: [] })),
}));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => domain) }));
vi.mock('./format.js', async (importOriginal) => ({ ...(await importOriginal<object>()), printJson: vi.fn(), printTable: vi.fn() }));

class Exit extends Error {
  constructor(readonly code: number) {
    super(`exit ${code}`);
  }
}
vi.mock('node:process', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  exit: (code: number) => {
    throw new Exit(code);
  },
}));

beforeEach(() => vi.clearAllMocks());

describe('identity sso-domains', () => {
  it('lists the domains', async () => {
    await cmdIdentity(['sso-domains', 'list']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/identity/sso-domains');
  });

  it('adds a domain through the governance flow, so a person approves the exact domain in a browser', async () => {
    await cmdIdentity(['sso-domains', 'add', 'corp.example.com']);
    expect(governedApi).toHaveBeenCalledWith('POST', '/v1/identity/sso-domains', { body: { domain: 'corp.example.com' } });
    expect(api).not.toHaveBeenCalled();
  });

  it('checks and removes a domain by id, with the id encoded in the path', async () => {
    vi.mocked(api).mockResolvedValueOnce({ domain, check: 'missing' });
    await cmdIdentity(['sso-domains', 'verify', 'ssod/1']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/identity/sso-domains/ssod%2F1/verify', { body: {} });
    vi.mocked(api).mockResolvedValueOnce(undefined);
    await cmdIdentity(['sso-domains', 'remove', 'ssod_1']);
    expect(api).toHaveBeenLastCalledWith('DELETE', '/v1/identity/sso-domains/ssod_1');
  });

  it('needs what it acts on, and knows its own subcommands, before any request', async () => {
    for (const args of [['sso-domains', 'add'], ['sso-domains', 'verify'], ['sso-domains', 'remove'], ['sso-domains', 'nonsense', 'x']]) {
      await expect(cmdIdentity(args)).rejects.toMatchObject({ code: 2 });
    }
    expect(api).not.toHaveBeenCalled();
    expect(governedApi).not.toHaveBeenCalled();
  });
});
