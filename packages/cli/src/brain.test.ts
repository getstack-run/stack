import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { printJson } from './format.js';
import { cmdBrain } from './brain.js';

vi.mock('./api.js', async (importOriginal) => ({ ...(await importOriginal<object>()), api: vi.fn(async () => ({})) }));
vi.mock('./format.js', async (importOriginal) => ({ ...(await importOriginal<object>()), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'passport-from-stdin') }));

const FILE = 'drv_abcdefgh1234';
const FILE2 = 'drv_ijklmnop5678';
const PASSPORT = { headers: { 'X-Passport-Token': 'passport-from-stdin' } };

beforeEach(() => vi.clearAllMocks());

describe('brain CLI wire contract', () => {
  it('adds one file, several files, or a prefix, as operator or agent', async () => {
    await cmdBrain(['add', FILE]);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/brain/files', { body: { file_id: FILE } });

    await cmdBrain(['add', FILE, FILE2, '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/brain/files', { body: { file_ids: [FILE, FILE2] }, ...PASSPORT });

    await cmdBrain(['add', '--prefix', 'contracts/']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/brain/files', { body: { name_prefix: 'contracts/' } });
    expect(printJson).toHaveBeenCalledTimes(3);
  });

  it('removes and searches', async () => {
    await cmdBrain(['remove', FILE]);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/brain/remove', { body: { file_id: FILE } });

    await cmdBrain(['search', 'what is the total?', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/brain/search', { body: { query: 'what is the total?' }, ...PASSPORT });
  });

  it('lists with its query flags', async () => {
    await cmdBrain(['list', '--status', 'searchable', '--limit', '25']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/brain/files', { query: { status: 'searchable', limit: '25' } });
  });

  it('refuses a bad selection or status, and never takes a Passport from argv', async () => {
    await expect(cmdBrain(['add'])).rejects.toThrow(/name a drive file id/);
    await expect(cmdBrain(['add', FILE, '--prefix', 'x'])).rejects.toThrow(/not both/);
    await expect(cmdBrain(['list', '--status', 'reading-soon'])).rejects.toThrow(/--status takes/);
    await expect(cmdBrain(['search'])).rejects.toThrow(/query is required/);
    await expect(cmdBrain(['add', FILE, '--passport', 'secret'])).rejects.toThrow(/must not be placed in argv/);
    await expect(cmdBrain(['wat'])).rejects.toThrow(/brain takes add, remove, search or list/);
    expect(api).not.toHaveBeenCalled();
  });
});
