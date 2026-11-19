import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { cmdAccounts } from './accounts.js';
import { INLINE_ATTACHMENTS_MAX_BYTES } from './account-email.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));
vi.mock('node:fs', async importOriginal => ({
  ...await importOriginal<object>(),
  statSync: vi.fn((path: string) => {
    if (path === 'big.zip') return { size: INLINE_ATTACHMENTS_MAX_BYTES + 1 };
    if (path === 'half.bin') return { size: INLINE_ATTACHMENTS_MAX_BYTES / 2 + 1 };
    if (path === 'empty.txt') return { size: 0 };
    if (path.endsWith('missing.pdf')) throw new Error('ENOENT');
    return { size: 5 };
  }),
  readFileSync: vi.fn((path: string) => {
    if (path === 'reply.txt') return 'Body read from a file';
    if (path === 'note.html') return '<p>Hi</p>';
    if (path === 'empty.txt') return Buffer.alloc(0);
    return Buffer.from('hello');
  }),
}));

const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const FILE_ID = 'drv_0123456789abcdef';
const HELLO_BASE64 = Buffer.from('hello').toString('base64');

beforeEach(() => vi.clearAllMocks());

describe('account email send', () => {
  it('keeps one address a plain string, as before', async () => {
    await cmdAccounts(['send-email', ACCOUNT, '--to', 'a@example.test', '--subject', 'Hi', '--body', 'Text']);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/email/send`, {
      body: { to: 'a@example.test', subject: 'Hi', body: 'Text' },
    });
  });

  it('takes several recipients from a repeated flag and from commas, and copies the same way', async () => {
    await cmdAccounts([
      'send-email', ACCOUNT, '--to', 'a@example.test,b@example.test', '--to', 'c@example.test',
      '--cc', 'd@example.test', '--cc', 'e@example.test, f@example.test', '--bcc', 'g@example.test',
      '--subject', 'Hi', '--body', 'Text',
    ]);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/email/send`, {
      body: {
        to: ['a@example.test', 'b@example.test', 'c@example.test'],
        cc: ['d@example.test', 'e@example.test', 'f@example.test'],
        bcc: ['g@example.test'],
        subject: 'Hi',
        body: 'Text',
      },
    });
  });

  it('attaches a drive file by its id and a local file inline, named by its file name', async () => {
    await cmdAccounts([
      'send-email', ACCOUNT, '--to', 'a@example.test', '--subject', 'Files', '--body', 'See files',
      '--attach', FILE_ID, '--attach', 'reports/Q3 summary.PDF', '--attach', 'data.unknown',
    ]);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/email/send`, {
      body: {
        to: 'a@example.test',
        attachments: [
          { file_id: FILE_ID },
          { filename: 'Q3 summary.PDF', content_type: 'application/pdf', content_base64: HELLO_BASE64 },
          { filename: 'data.unknown', content_type: 'application/octet-stream', content_base64: HELLO_BASE64 },
        ],
        subject: 'Files',
        body: 'See files',
      },
    });
  });

  it('refuses a local file past the inline limit and says to attach it from the drive', async () => {
    await expect(cmdAccounts(['send-email', ACCOUNT, '--to', 'a@example.test', '--subject', 'x', '--body', 'y', '--attach', 'big.zip']))
      .rejects.toThrow(/drive upload <file>.*drive file id/);
    await expect(cmdAccounts(['send-email', ACCOUNT, '--to', 'a@example.test', '--subject', 'x', '--body', 'y', '--attach', 'half.bin', '--attach', 'half.bin']))
      .rejects.toThrow(/10\.0 MB is the most/);
    expect(api).not.toHaveBeenCalled();
  });

  it('refuses a missing or empty local file', async () => {
    await expect(cmdAccounts(['send-email', ACCOUNT, '--to', 'a@example.test', '--subject', 'x', '--body', 'y', '--attach', 'missing.pdf']))
      .rejects.toThrow(/Attachment not found: missing\.pdf/);
    expect(api).not.toHaveBeenCalled();
  });

  it('sends an empty local file like any other', async () => {
    await cmdAccounts(['send-email', ACCOUNT, '--to', 'a@example.test', '--subject', 'x', '--body', 'y', '--attach', 'empty.txt']);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/email/send`, {
      body: { to: 'a@example.test', attachments: [{ filename: 'empty.txt', content_type: 'text/plain', content_base64: '' }], subject: 'x', body: 'y' },
    });
  });

  it('needs a To: a send with only copies, or with nobody, is refused', async () => {
    for (const more of [['--bcc', 'a@example.test,b@example.test'], ['--cc', 'a@example.test'], []]) {
      await expect(cmdAccounts(['send-email', ACCOUNT, ...more, '--subject', 'x', '--body', 'y'])).rejects.toThrow(/--to is required/);
    }
    expect(api).not.toHaveBeenCalled();
    await cmdAccounts(['send-email', ACCOUNT, '--to', 'a@example.test', '--bcc', 'b@example.test', '--subject', 'x', '--body', 'y']);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/email/send`, {
      body: { to: 'a@example.test', bcc: ['b@example.test'], subject: 'x', body: 'y' },
    });
  });
});

describe('account email reply', () => {
  it('answers in the received message, to its sender', async () => {
    await cmdAccounts(['reply-email', ACCOUNT, 'amsg_1', '--body', 'Thanks']);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/messages/amsg_1/reply`, { body: { body: 'Thanks' } });
  });

  it('takes reply to all, copies, a subject, an HTML body and attachments, with the message id anywhere after the account', async () => {
    await cmdAccounts([
      'reply-email', ACCOUNT, '--all', '--body-file', 'reply.txt', '--body-html-file', 'note.html', '--cc', 'a@example.test,b@example.test',
      '--bcc', 'c@example.test', '--subject', 'Re: Plan', '--attach', FILE_ID, 'amsg_1',
    ]);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/messages/amsg_1/reply`, {
      body: {
        body: 'Body read from a file',
        body_html: '<p>Hi</p>',
        reply_all: true,
        cc: ['a@example.test', 'b@example.test'],
        bcc: ['c@example.test'],
        attachments: [{ file_id: FILE_ID }],
        subject: 'Re: Plan',
      },
    });
  });

  it('leaves the quote out with --no-quote', async () => {
    await cmdAccounts(['reply-email', ACCOUNT, 'amsg_1', '--body', 'Thanks', '--no-quote']);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/messages/amsg_1/reply`, { body: { body: 'Thanks', include_quote: false } });
  });

  it('refuses a missing body or message id and an argument it does not know', async () => {
    await expect(cmdAccounts(['reply-email', ACCOUNT, 'amsg_1'])).rejects.toThrow(/--body/);
    await expect(cmdAccounts(['reply-email', ACCOUNT, '--body', 'x'])).rejects.toThrow(/message id is required/);
    await expect(cmdAccounts(['reply-email', ACCOUNT, 'amsg_1', '--body', 'x', '--bccc'])).rejects.toThrow(/Unexpected argument: --bccc/);
    expect(api).not.toHaveBeenCalled();
  });
});

describe('account email forward', () => {
  it('forwards to several people with a note, copies and extra files, leaving the original files in', async () => {
    await cmdAccounts([
      'forward-email', ACCOUNT, 'amsg_2', '--to', 'a@example.test', '--to', 'b@example.test', '--cc', 'c@example.test',
      '--bcc', 'd@example.test', '--body', 'FYI', '--attach', 'extra.csv',
    ]);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/messages/amsg_2/forward`, {
      body: {
        to: ['a@example.test', 'b@example.test'],
        cc: ['c@example.test'],
        bcc: ['d@example.test'],
        attachments: [{ filename: 'extra.csv', content_type: 'text/csv', content_base64: HELLO_BASE64 }],
        body: 'FYI',
      },
    });
  });

  it('leaves the original files out with --no-attachments, and needs no note', async () => {
    await cmdAccounts(['forward-email', ACCOUNT, 'amsg_2', '--to', 'a@example.test', '--no-attachments']);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/messages/amsg_2/forward`, {
      body: { to: 'a@example.test', include_attachments: false },
    });
  });

  it('leaves the original\'s text out with --no-quote', async () => {
    await cmdAccounts(['forward-email', ACCOUNT, 'amsg_2', '--to', 'a@example.test', '--body', 'FYI', '--no-quote']);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/messages/amsg_2/forward`, {
      body: { to: 'a@example.test', body: 'FYI', include_quote: false },
    });
  });

  it('refuses a forward with no recipient, no message id or a flag it does not know', async () => {
    await expect(cmdAccounts(['forward-email', ACCOUNT, 'amsg_2'])).rejects.toThrow(/--to is required/);
    await expect(cmdAccounts(['forward-email', ACCOUNT, 'amsg_2', '--bcc', 'a@example.test'])).rejects.toThrow(/--to is required/);
    await expect(cmdAccounts(['forward-email', ACCOUNT, '--to', 'a@example.test'])).rejects.toThrow(/message id is required/);
    await expect(cmdAccounts(['forward-email', ACCOUNT, 'amsg_2', '--to', 'a@example.test', '--no-attachment'])).rejects.toThrow(/Unexpected argument: --no-attachment/);
    expect(api).not.toHaveBeenCalled();
  });
});
