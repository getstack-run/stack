import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { governedApi } from './governance.js';
import { cmdTrust } from './trust.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));

beforeEach(() => vi.clearAllMocks());

describe('trust CLI', () => {
  it('reads the account value and one agent value', async () => {
    await cmdTrust(['get']);
    await cmdTrust(['get', 'agt_one']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', '/v1/trust');
    expect(api).toHaveBeenNthCalledWith(2, 'GET', '/v1/agents/agt_one/trust');
  });

  it('sets the account value, an agent value, and clears an agent value, waiting for a person when a change needs one', async () => {
    await cmdTrust(['set', 'ask_first']);
    await cmdTrust(['set', 'trust_agents', 'agt_one']);
    await cmdTrust(['clear', 'agt_one']);
    expect(governedApi).toHaveBeenNthCalledWith(1, 'PUT', '/v1/trust', { body: { trust: 'ask_first' } });
    expect(governedApi).toHaveBeenNthCalledWith(2, 'PUT', '/v1/agents/agt_one/trust', { body: { trust: 'trust_agents' } });
    expect(governedApi).toHaveBeenNthCalledWith(3, 'PUT', '/v1/agents/agt_one/trust', { body: { trust: null } });
    expect(api).not.toHaveBeenCalled();
  });

  it('refuses an unknown value or command before any request', async () => {
    await expect(cmdTrust(['set', 'always'])).rejects.toThrow(/ask_first or trust_agents/);
    await expect(cmdTrust(['set'])).rejects.toThrow(/ask_first or trust_agents/);
    await expect(cmdTrust(['clear'])).rejects.toThrow(/agent id/);
    await expect(cmdTrust(['purge'])).rejects.toThrow(/trust takes/);
    expect(api).not.toHaveBeenCalled();
    expect(governedApi).not.toHaveBeenCalled();
  });
});
