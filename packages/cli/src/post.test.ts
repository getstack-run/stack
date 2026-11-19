import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { readSecretFromStdin } from './secret-input.js';
import { cmdPost } from './post.js';

vi.mock('./api.js', async (importOriginal) => ({ ...(await importOriginal<object>()), api: vi.fn(async () => ({})) }));
vi.mock('./format.js', async (importOriginal) => ({ ...(await importOriginal<object>()), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'sk_agent_fromstdin whsec_fromstdin') }));
vi.mock('node:fs', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  readFileSync: vi.fn((path: string) => {
    if (path === 'letter.pdf') return Buffer.from('%PDF-1.4 fixture');
    if (path === 'address.json') return JSON.stringify({ name: 'Pat Doe', line1: '1 Main St', city: 'Reno', state: 'NV', postal_code: '89501' });
    return 'Text read from a file';
  }),
}));

const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const BASE = `/v1/accounts/${ACCOUNT}/post`;
const TO = ['--to-name', 'Pat Doe', '--to-line1', '1 Main St', '--to-city', 'Reno', '--to-state', 'NV', '--to-postal-code', '89501'];
const ADDRESS = { name: 'Pat Doe', line1: '1 Main St', city: 'Reno', state: 'NV', postal_code: '89501' };

beforeEach(() => vi.clearAllMocks());

describe('the customer\'s street address', () => {
  it('reads, starts, looks again, pauses, resumes and disconnects', async () => {
    await cmdPost(['address']);
    await cmdPost(['address', 'start']);
    await cmdPost(['address', 'refresh']);
    await cmdPost(['address', 'pause']);
    await cmdPost(['address', 'resume']);
    await cmdPost(['address', 'close']);
    expect((api as ReturnType<typeof vi.fn>).mock.calls.map((c) => `${c[0]} ${c[1]}`)).toEqual([
      'GET /v1/post/address', 'POST /v1/post/address', 'POST /v1/post/address/refresh', 'POST /v1/post/address/pause',
      'POST /v1/post/address/resume', 'DELETE /v1/post/address',
    ]);
  });

  it('reads the supplier key from stdin and never from argv, with the webhook secret as an optional second token', async () => {
    await cmdPost(['address', 'connect']);
    expect(readSecretFromStdin).toHaveBeenCalled();
    expect(api).toHaveBeenCalledWith('POST', '/v1/post/address/connect', { body: { api_key: 'sk_agent_fromstdin', webhook_secret: 'whsec_fromstdin' } });
    await expect(cmdPost(['address', 'connect', '--key', 'sk_agent_x'])).rejects.toThrow(/argv/);
    await expect(cmdPost(['address', 'connect', '--webhook-secret=whsec_x'])).rejects.toThrow(/argv/);
  });

  it('lists every item and gives an unassigned one to an account', async () => {
    await cmdPost(['items', '--routing', 'unassigned', '--limit', '5']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/post/items', { query: { routing: 'unassigned', limit: '5' } });
    await cmdPost(['items', 'assign', 'pit_1', '--account', ACCOUNT]);
    expect(api).toHaveBeenCalledWith('POST', '/v1/post/items/pit_1/assign', { body: { account_id: ACCOUNT } });
  });
});

describe('an account\'s post', () => {
  it('reads the agent\'s line, items and letters, as the operator or with the Passport from stdin', async () => {
    await cmdPost([ACCOUNT, 'address']);
    expect(api).toHaveBeenLastCalledWith('GET', `${BASE}/address`, {});
    await cmdPost([ACCOUNT, 'items', '--limit', '3', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('GET', `${BASE}/items`, { query: { limit: '3' }, headers: { 'X-Passport-Token': 'sk_agent_fromstdin whsec_fromstdin' } });
    await cmdPost([ACCOUNT, 'letter', 'plt_1']);
    expect(api).toHaveBeenLastCalledWith('GET', `${BASE}/letters/plt_1`, {});
    await expect(cmdPost([ACCOUNT, 'items', '--passport', 'pas.x'])).rejects.toThrow(/argv/);
  });

  it('asks for a scan, a forward and a shred, and a shred must be confirmed', async () => {
    await cmdPost([ACCOUNT, 'scan', 'pit_1', '--capture', 'both', '--idempotency-key', 'scan-key-0001']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/items/pit_1/scan`, { body: { capture: 'both' }, headers: { 'Idempotency-Key': 'scan-key-0001' } });
    await cmdPost([ACCOUNT, 'forward', 'pit_1', ...TO, '--mail-class', 'usps_first_class']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/items/pit_1/forward`, { body: { destination: ADDRESS, mail_class: 'usps_first_class' } });
    await cmdPost([ACCOUNT, 'forward', 'pit_1', '--to-address-file', 'address.json']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/items/pit_1/forward`, { body: { destination: ADDRESS } });
    await expect(cmdPost([ACCOUNT, 'shred', 'pit_1'])).rejects.toThrow(/--confirm/);
    await cmdPost([ACCOUNT, 'shred', 'pit_1', '--confirm']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/items/pit_1/shred`, { body: { confirm: true } });
  });

  it('sends a letter from text, from a file, or from a PDF, and a postcard from text', async () => {
    await cmdPost([ACCOUNT, 'send', '--use-type', 'operational', '--sender-name', 'Acme Dental', ...TO, '--text', 'Hello Pat', '--color', '--extra-service', 'certified']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/letters`, {
      body: { to: ADDRESS, sender_name: 'Acme Dental', use_type: 'operational', content: { text: 'Hello Pat' }, color: true, extra_service: 'certified' },
    });
    await cmdPost([ACCOUNT, 'send', '--use-type', 'operational', '--sender-name', 'Acme Dental', '--to-address-file', 'address.json', '--text-file', 'body.txt']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/letters`, { body: { to: ADDRESS, sender_name: 'Acme Dental', use_type: 'operational', content: { text: 'Text read from a file' } } });
    await cmdPost([ACCOUNT, 'send', '--use-type', 'marketing', '--sender-name', 'Acme Dental', ...TO, '--pdf-file', 'letter.pdf', '--idempotency-key', 'letter-key-0001']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/letters`, {
      body: { to: ADDRESS, sender_name: 'Acme Dental', use_type: 'marketing', idempotency_key: 'letter-key-0001', content: { pdf_base64: Buffer.from('%PDF-1.4 fixture').toString('base64') } },
    });
    await cmdPost([ACCOUNT, 'send', '--kind', 'postcard', '--use-type', 'marketing', '--sender-name', 'Acme Dental', ...TO, '--front', 'Hi', '--back', 'There', '--size', '6x9']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/letters`, {
      body: { to: ADDRESS, sender_name: 'Acme Dental', use_type: 'marketing', kind: 'postcard', front: { text: 'Hi' }, back: { text: 'There' }, size: '6x9' },
    });
  });

  it('sends the sender address printed on the letter from --return-* flags or a file, in the form of --to-*', async () => {
    const RETURN = ['--return-name', 'Acme Dental', '--return-line1', '77 Sender Way', '--return-city', 'Carson City', '--return-state', 'NV', '--return-postal-code', '89701'];
    await cmdPost([ACCOUNT, 'send', '--use-type', 'operational', '--sender-name', 'Acme Dental', ...TO, ...RETURN, '--text', 'Hello Pat']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/letters`, {
      body: { to: ADDRESS, sender_name: 'Acme Dental', return_address: { name: 'Acme Dental', line1: '77 Sender Way', city: 'Carson City', state: 'NV', postal_code: '89701' }, use_type: 'operational', content: { text: 'Hello Pat' } },
    });
    await cmdPost([ACCOUNT, 'send', '--use-type', 'operational', '--sender-name', 'Acme Dental', ...TO, '--return-address-file', 'address.json', '--text', 'Hello Pat']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/letters`, { body: { to: ADDRESS, sender_name: 'Acme Dental', return_address: ADDRESS, use_type: 'operational', content: { text: 'Hello Pat' } } });
    await expect(cmdPost([ACCOUNT, 'send', '--use-type', 'operational', '--sender-name', 'Acme Dental', ...TO, '--return-name', 'Acme', '--text', 'x'])).rejects.toThrow(/--return-line1 is required/);
  });

  it('refuses a send that says nothing about what the mail is, names no content, or names two', async () => {
    await expect(cmdPost([ACCOUNT, 'send', ...TO, '--text', 'x'])).rejects.toThrow(/--use-type is required/);
    await expect(cmdPost([ACCOUNT, 'send', '--use-type', 'promo', ...TO, '--text', 'x'])).rejects.toThrow(/operational or marketing/);
    await expect(cmdPost([ACCOUNT, 'send', '--use-type', 'operational', ...TO, '--text', 'x'])).rejects.toThrow(/--sender-name is required/);
    await expect(cmdPost([ACCOUNT, 'send', '--use-type', 'operational', '--sender-name', 'Acme', ...TO])).rejects.toThrow(/exactly one of/);
    await expect(cmdPost([ACCOUNT, 'send', '--use-type', 'operational', '--sender-name', 'Acme', ...TO, '--text', 'x', '--pdf-file', 'letter.pdf'])).rejects.toThrow(/exactly one of/);
    await expect(cmdPost([ACCOUNT, 'send', '--use-type', 'operational', '--sender-name', 'Acme', '--to-name', 'Pat', '--text', 'x'])).rejects.toThrow(/line1/);
    expect(api).not.toHaveBeenCalled();
  });

  it('checks an address', async () => {
    await cmdPost([ACCOUNT, 'check', ...TO]);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/address-check`, { body: { address: ADDRESS } });
  });
});
