import { beforeEach, describe, expect, it, vi } from 'vitest';
import { governedApi } from './governance.js';
import { cmdTeam } from './team.js';

vi.mock('./governance.js', () => ({
  governedApi: vi.fn(async () => ({ cleared: [{ id: 'mem_1', email: 'a@corp.example', sso_issuer: 'https://old-idp.example' }] })),
}));
vi.mock('./format.js', async (importOriginal) => ({ ...(await importOriginal<object>()), printJson: vi.fn() }));

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

describe('team sso-unbind', () => {
  it('forgets one member, or every member of one issuer, through the governance flow', async () => {
    await cmdTeam(['sso-unbind', 'mem_1']);
    expect(governedApi).toHaveBeenLastCalledWith('POST', '/v1/team/sso-bindings/clear', { body: { member_id: 'mem_1' } });
    await cmdTeam(['sso-unbind', '--issuer', 'https://old-idp.example']);
    expect(governedApi).toHaveBeenLastCalledWith('POST', '/v1/team/sso-bindings/clear', { body: { issuer: 'https://old-idp.example' } });
  });

  it('takes exactly one target and checks it before any request', async () => {
    for (const args of [['sso-unbind'], ['sso-unbind', 'mem_1', '--issuer', 'https://old-idp.example'], ['sso-unbind', '--issuer', '']]) {
      await expect(cmdTeam(args)).rejects.toMatchObject({ code: 2 });
    }
    expect(governedApi).not.toHaveBeenCalled();
  });
});
