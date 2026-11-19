import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { governedApi } from './governance.js';
import { readSecretFromStdin } from './secret-input.js';
import { statSync } from 'node:fs';
import { cmdAccounts } from './accounts.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'secret-from-stdin') }));
vi.mock('node:fs', async importOriginal => ({
  ...await importOriginal<object>(),
  statSync: vi.fn((path: string) => ({ size: path === 'huge.stl' ? 21 * 1024 * 1024 : 5 })),
  readFileSync: vi.fn((path: string) => {
    if (path === 'recipient.json') {
      return JSON.stringify({ name: 'Pat Doe', email: 'pat@example.test', phone: '+14155550123', address1: '1 Main St', city: 'Austin', state: 'TX', postal_code: '78701' });
    }
    if (path === 'spec.json') return JSON.stringify({ quantity: 3, material: 'pla' });
    return Buffer.from('solid x');
  }),
}));

const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const BASE = `/v1/accounts/${ACCOUNT}/making`;
const PASSPORT = { headers: { 'X-Passport-Token': 'secret-from-stdin' } };

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env['MAKING_SUPPLIER_KEY'];
  delete process.env['MAKING_SUPPLIER_SECRET'];
});

describe('making CLI wire contract', () => {
  it('uploads the file as base64 under the Passport, with its name', async () => {
    await cmdAccounts(['making', ACCOUNT, 'upload', 'models/bracket.stl', '--description', 'A bracket']);
    expect(api).toHaveBeenCalledWith('POST', `${BASE}/designs`, {
      body: { file_name: 'bracket.stl', content_base64: Buffer.from('solid x').toString('base64'), description: 'A bracket' },
      ...PASSPORT,
    });
  });

  it('refuses a file over 20 MB before sending anything, and points at the drive', async () => {
    await expect(cmdAccounts(['making', ACCOUNT, 'upload', 'huge.stl'])).rejects.toThrow(/--drive-file/);
    expect(api).not.toHaveBeenCalled();
  });

  it('makes a design from a file on the drive by its id, reading nothing locally', async () => {
    await cmdAccounts(['making', ACCOUNT, 'upload', '--drive-file', 'drv_0123456789ab', '--name', 'housing.3mf', '--description', 'A housing']);
    expect(api).toHaveBeenCalledWith('POST', `${BASE}/designs`, {
      body: { drive_file_id: 'drv_0123456789ab', file_name: 'housing.3mf', description: 'A housing' },
      ...PASSPORT,
    });
    expect(statSync).not.toHaveBeenCalled();
  });

  it('quotes with the recipient from a file, so an address is never on the command line', async () => {
    await cmdAccounts(['making', ACCOUNT, 'quote', '--design', 'mkd_abcdefgh12345678', '--recipient-file', 'recipient.json',
      '--supplier', 'afn', '--spec-file', 'spec.json', '--quantity', '2', '--process', 'fdm_print']);
    expect(api).toHaveBeenCalledWith('POST', `${BASE}/quotes`, {
      body: {
        design_id: 'mkd_abcdefgh12345678',
        supplier: 'afn',
        spec: { quantity: 2, material: 'pla', process: 'fdm_print' },
        recipient: expect.objectContaining({ name: 'Pat Doe', state: 'TX' }),
      },
      ...PASSPORT,
    });
  });

  it('orders a quote and cancels as the agent only when it says so', async () => {
    await cmdAccounts(['making', ACCOUNT, 'order', 'mkq_abcdefgh12345678']);
    expect(api).toHaveBeenCalledWith('POST', `${BASE}/orders`, { body: { quote_id: 'mkq_abcdefgh12345678' }, ...PASSPORT });
    await cmdAccounts(['making', ACCOUNT, 'cancel', 'mko_1']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/orders/mko_1/cancel`, {});
    await cmdAccounts(['making', ACCOUNT, 'cancel', 'mko_1', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/orders/mko_1/cancel`, PASSPORT);
  });

  it('reads designs, quotes and orders as the operator unless asked to read as the agent', async () => {
    await cmdAccounts(['making', ACCOUNT, 'designs']);
    await cmdAccounts(['making', ACCOUNT, 'designs', 'mkd_1', '--passport-stdin']);
    await cmdAccounts(['making', ACCOUNT, 'quote-get', 'mkq_1']);
    await cmdAccounts(['making', ACCOUNT, 'orders', '--limit', '5']);
    await cmdAccounts(['making', ACCOUNT, 'orders', 'mko_1']);
    expect((api as ReturnType<typeof vi.fn>).mock.calls.map((c) => [c[0], c[1], c[2]])).toEqual([
      ['GET', `${BASE}/designs`, { query: {} }],
      ['GET', `${BASE}/designs/mkd_1`, PASSPORT],
      ['GET', `${BASE}/quotes/mkq_1`, {}],
      ['GET', `${BASE}/orders`, { query: { limit: '5' } }],
      ['GET', `${BASE}/orders/mko_1`, {}],
    ]);
  });

  it('approves through the governed flow and rejects plainly', async () => {
    await cmdAccounts(['making', ACCOUNT, 'approve', 'mko_1']);
    expect(governedApi).toHaveBeenCalledWith('POST', `${BASE}/orders/mko_1/approve`);
    await cmdAccounts(['making', ACCOUNT, 'reject', 'mko_1']);
    expect(api).toHaveBeenCalledWith('POST', `${BASE}/orders/mko_1/reject`);
  });

  it('connects a supplier key read from the environment or stdin, never from an argument', async () => {
    process.env['MAKING_SUPPLIER_KEY'] = 'key-from-env-0001';
    process.env['MAKING_SUPPLIER_SECRET'] = ['secret', 'from', 'env', '0001'].join('-');
    await cmdAccounts(['making-connect-supplier', 'lulu']);
    expect(api).toHaveBeenCalledWith('PUT', '/v1/accounts/making/suppliers/lulu', {
      body: { api_key: 'key-from-env-0001', api_secret: ['secret', 'from', 'env', '0001'].join('-') },
    });
    delete process.env['MAKING_SUPPLIER_KEY'];
    delete process.env['MAKING_SUPPLIER_SECRET'];
    await cmdAccounts(['making-connect-supplier', 'gelato']);
    expect(readSecretFromStdin).toHaveBeenCalled();
    expect(api).toHaveBeenLastCalledWith('PUT', '/v1/accounts/making/suppliers/gelato', { body: { api_key: 'secret-from-stdin' } });
    await cmdAccounts(['making-suppliers']);
    await cmdAccounts(['making-disconnect-supplier', 'gelato']);
    expect(api).toHaveBeenLastCalledWith('DELETE', '/v1/accounts/making/suppliers/gelato', { expectEmpty: true });
  });

  it('connects Printful by signing in at Printful: asks for the address and sends no key', async () => {
    await cmdAccounts(['making-connect-printful']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/accounts/making/suppliers/printful/connect');
    expect(readSecretFromStdin).not.toHaveBeenCalledTimes(2);
  });

  it('refuses a Passport placed in argv and an unknown action', async () => {
    await expect(cmdAccounts(['making', ACCOUNT, 'order', 'mkq_1', '--passport', 'tok'])).rejects.toThrow(/argv/);
    await expect(cmdAccounts(['making', ACCOUNT, 'frobnicate'])).rejects.toThrow(/Invalid input/);
  });
});
