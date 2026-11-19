import { beforeEach, describe, expect, it, vi } from 'vitest';
import { StackError } from '@getstackrun/sdk';
import { api } from './api.js';
import { printJson } from './format.js';
import { cmdDrive } from './drive.js';
import { BUFFERED_MAX_BYTES, MAX_FILE_BYTES } from './drive-upload.js';

vi.mock('./api.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  api: vi.fn(async () => ({})),
  requireToken: vi.fn(async () => 'signed-in-token'),
}));
vi.mock('./format.js', async (importOriginal) => ({ ...(await importOriginal<object>()), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'passport-from-stdin') }));
vi.mock('node:fs', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  // A name that says how big it is: `big-30.zip` is 30 MiB, `empty.txt` is empty.
  statSync: vi.fn((path: string) => ({
    size: /big-(\d+)\.\w+$/.test(path) ? Number(/big-(\d+)\./.exec(path)![1]) * 1024 * 1024 : path.endsWith('empty.txt') ? 0 : 14,
  })),
}));
const upload = vi.fn(async (_input: unknown, _options?: { onProgress?: (p: unknown) => void }) => ({ id: 'drv_new' }));
const stackOptions = vi.fn();
vi.mock('@getstackrun/sdk', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  Stack: class {
    readonly drive = { upload };
    constructor(options: unknown) {
      stackOptions(options);
    }
  },
}));

const FILE = 'drv_0123456789abcdef0123';
const PASSPORT = { headers: { 'X-Passport-Token': 'passport-from-stdin' } };

beforeEach(() => vi.clearAllMocks());


describe('drive CLI wire contract', () => {
  it('uploads a file as one streamed request, naming it from the path and taking its type from the extension', async () => {
    await cmdDrive(['upload', '/work/notes.md']);
    expect(api).not.toHaveBeenCalled();
    expect(upload).toHaveBeenCalledTimes(1);
    expect(upload).toHaveBeenCalledWith(
      { path: '/work/notes.md', name: 'notes.md', content_type: 'text/markdown' },
      expect.objectContaining({ onProgress: expect.any(Function) }),
    );
    expect(upload.mock.calls[0]![1]).not.toHaveProperty('passportToken');
    expect(stackOptions).toHaveBeenCalledWith(expect.objectContaining({ apiKey: 'signed-in-token' }));
    expect(printJson).toHaveBeenCalledWith({ id: 'drv_new' });
  });

  it('uploads shared with the account, named, with an expiry, as the agent', async () => {
    await cmdDrive(['upload', '/work/report.pdf', '--name', 'Q3 report', '--account', '--expires', '3600', '--passport-stdin']);
    expect(upload).toHaveBeenCalledWith(
      { path: '/work/report.pdf', name: 'Q3 report', content_type: 'application/pdf', visibility: 'account', expires_in_seconds: 3600 },
      expect.objectContaining({ passportToken: 'passport-from-stdin' }),
    );
  });

  it('sends a large file the same way: one call, no parts', async () => {
    await cmdDrive(['upload', '/work/big-900.zip', '--private']);
    expect(upload).toHaveBeenCalledWith(
      { path: '/work/big-900.zip', name: 'big-900.zip', content_type: 'application/zip', visibility: 'agent' },
      expect.anything(),
    );
  });

  it('takes a file of any type: the extension suggests a label, --type names one, and a file with neither is sent unlabelled', async () => {
    await cmdDrive(['upload', '/work/housing.stl']);
    expect(upload).toHaveBeenLastCalledWith({ path: '/work/housing.stl', name: 'housing.stl', content_type: 'model/stl' }, expect.anything());
    await cmdDrive(['upload', '/work/sheet.xlsx']);
    expect(upload).toHaveBeenLastCalledWith(
      { path: '/work/sheet.xlsx', name: 'sheet.xlsx', content_type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
      expect.anything(),
    );
    await cmdDrive(['upload', '/work/page.html']);
    expect(upload).toHaveBeenLastCalledWith({ path: '/work/page.html', name: 'page.html' }, expect.anything());
    await cmdDrive(['upload', '/work/tool.exe', '--type', 'application/x-msdownload']);
    expect(upload).toHaveBeenLastCalledWith({ path: '/work/tool.exe', name: 'tool.exe', content_type: 'application/x-msdownload' }, expect.anything());
  });

  it('refuses an empty file, a file typed as text over 10 MB and any file over 1 GB before sending anything', async () => {
    await expect(cmdDrive(['upload', '/work/empty.txt'])).rejects.toThrow(/file is empty/);
    await expect(cmdDrive(['upload', '/work/big-11.csv'])).rejects.toThrow(/10 MB at most/);
    await expect(cmdDrive(['upload', '/work/big-2048.zip'])).rejects.toThrow(/1 GB at most/);
    await expect(cmdDrive(['upload', '/work/big-10.csv'])).resolves.toBeUndefined();
    expect(upload).toHaveBeenCalledTimes(1);
  });

  it("shows the API's refusal with its code", async () => {
    upload.mockRejectedValueOnce(new StackError('This drive is read-only because the wallet could not pay for storage.', 'DRIVE_READ_ONLY', 409));
    await expect(cmdDrive(['upload', '/work/notes.md'])).rejects.toThrow(/read-only.*\(DRIVE_READ_ONLY\)/);
    upload.mockRejectedValueOnce(new StackError('This drive already has 5 uploads running.', 'DRIVE_TOO_MANY_UPLOADS', 429));
    await expect(cmdDrive(['upload', '/work/notes.md'])).rejects.toThrow(/\(DRIVE_TOO_MANY_UPLOADS\)/);
  });

  it('never takes a Passport from argv', async () => {
    await expect(cmdDrive(['list', '--passport', 'secret'])).rejects.toThrow(/must not be placed in argv/);
    await expect(cmdDrive(['read', FILE, '--token=secret'])).rejects.toThrow(/must not be placed in argv/);
    expect(api).not.toHaveBeenCalled();
  });

  it('lists, reads and gets, as the operator unless told to be the agent', async () => {
    await cmdDrive(['list', '--limit', '10', '--cursor', 'abc']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/drive/files', { query: { limit: '10', cursor: 'abc' } });
    await cmdDrive(['get', FILE]);
    expect(api).toHaveBeenLastCalledWith('GET', `/v1/drive/files/${FILE}`, {});
    await cmdDrive(['read', FILE, '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('GET', `/v1/drive/files/${FILE}/content`, PASSPORT);
    expect(printJson).toHaveBeenCalledTimes(3);
  });

  it('changes visibility and expiry, and removes an expiry', async () => {
    await cmdDrive(['update', FILE, '--private', '--expires', '60']);
    expect(api).toHaveBeenLastCalledWith('PATCH', `/v1/drive/files/${FILE}`, { body: { visibility: 'agent', expires_in_seconds: 60 } });
    await cmdDrive(['update', FILE, '--no-expiry']);
    expect(api).toHaveBeenLastCalledWith('PATCH', `/v1/drive/files/${FILE}`, { body: { expires_in_seconds: null } });
  });

  it('copies a file into one of the caller\'s own, to keep it', async () => {
    await cmdDrive(['copy', FILE]);
    expect(api).toHaveBeenLastCalledWith('POST', `/v1/drive/files/${FILE}/copy`, { body: {} });
    await cmdDrive(['copy', FILE, '--name', 'kept.pdf', '--account', '--expires', '86400']);
    expect(api).toHaveBeenLastCalledWith('POST', `/v1/drive/files/${FILE}/copy`, { body: { name: 'kept.pdf', visibility: 'account', expires_in_seconds: 86400 } });
    await cmdDrive(['copy', FILE, '--private', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', `/v1/drive/files/${FILE}/copy`, { body: { visibility: 'agent' }, ...PASSPORT });
  });

  it('deletes a file and shares it with a link, then lists and ends links', async () => {
    await cmdDrive(['delete', FILE]);
    expect(api).toHaveBeenLastCalledWith('DELETE', `/v1/drive/files/${FILE}`, { expectEmpty: true });
    await cmdDrive(['share', FILE, '--ttl', '600', '--max-downloads', '2']);
    expect(api).toHaveBeenLastCalledWith('POST', `/v1/drive/files/${FILE}/links`, { body: { ttl_seconds: 600, max_downloads: 2 } });
    await cmdDrive(['links', FILE]);
    expect(api).toHaveBeenLastCalledWith('GET', `/v1/drive/files/${FILE}/links`, {});
    await cmdDrive(['unshare', FILE, 'dsl_abc']);
    expect(api).toHaveBeenLastCalledWith('DELETE', `/v1/drive/files/${FILE}/links/dsl_abc`, { expectEmpty: true });
  });

  it('knows the sizes', async () => {
    expect(BUFFERED_MAX_BYTES).toBe(10 * 1024 * 1024);
    expect(MAX_FILE_BYTES).toBe(1024 * 1024 * 1024);
  });

  it('refuses an unknown subcommand and a missing id', async () => {
    await expect(cmdDrive(['frobnicate', FILE])).rejects.toThrow(/drive takes/);
    await expect(cmdDrive(['get'])).rejects.toThrow(/file id is required/);
  });
});
