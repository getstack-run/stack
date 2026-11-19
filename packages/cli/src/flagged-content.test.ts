import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { cmdFlaggedContent } from './flagged-content.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));

beforeEach(() => vi.clearAllMocks());

describe('flagged-content CLI', () => {
  it('reads the setting', async () => {
    await cmdFlaggedContent(['get']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/flagged-content/settings');
  });

  it('changes one severity or both', async () => {
    await cmdFlaggedContent(['set', '--warning', 'deliver']);
    await cmdFlaggedContent(['set', '--critical', 'withhold', '--warning', 'withhold']);
    expect(api).toHaveBeenNthCalledWith(1, 'PUT', '/v1/flagged-content/settings', { body: { warning: 'deliver' } });
    expect(api).toHaveBeenNthCalledWith(2, 'PUT', '/v1/flagged-content/settings', { body: { warning: 'withhold', critical: 'withhold' } });
  });

  it('refuses an empty change or an unknown value before any request', async () => {
    await expect(cmdFlaggedContent(['set'])).rejects.toThrow(/--warning, --critical or both/);
    await expect(cmdFlaggedContent(['set', '--warning', 'block'])).rejects.toThrow(/withhold or deliver/);
    await expect(cmdFlaggedContent(['purge'])).rejects.toThrow(/get or set/);
    expect(api).not.toHaveBeenCalled();
  });
});
