import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { governedApi } from './governance.js';
import { readSecretFromStdin } from './secret-input.js';
import { printJson } from './format.js';
import { cmdAccounts } from './accounts.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'passport-from-stdin') }));
vi.mock('node:fs', async importOriginal => ({
  ...await importOriginal<object>(),
  readFileSync: vi.fn((path: string) => {
    if (path === 'open.json') return JSON.stringify({ name: 'from-file', monthly_budget_cents: 2500, skip: ['card'] });
    if (path === 'input.json') return JSON.stringify({ username: 'from-file' });
    if (path === 'list.json') return '[1, 2]';
    if (path === 'toll-free.json') return JSON.stringify({ business_name: 'Acme', business_type: 'SOLE_PROPRIETOR' });
    return 'Body read from a file';
  }),
}));

const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const PASSPORT = { headers: { 'X-Passport-Token': 'passport-from-stdin' } };

beforeEach(() => vi.clearAllMocks());

describe('account CLI wire contract', () => {
  it('opens at once with the idempotency key, with no budget and no approval flow', async () => {
    await cmdAccounts(['open', '--name', 'research-agent', '--idempotency-key', 'open-key-0001']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/accounts', {
      body: { name: 'research-agent' },
      headers: { 'Idempotency-Key': 'open-key-0001' },
    });
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('sends an optional budget', async () => {
    await cmdAccounts(['open', '--name', 'research-agent', '--monthly-budget-cents', '5000', '--idempotency-key', 'open-key-0004']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/accounts', {
      body: { name: 'research-agent', monthly_budget_cents: 5000 },
      headers: { 'Idempotency-Key': 'open-key-0004' },
    });
  });

  it('opens from a request file, and flags override the file', async () => {
    await cmdAccounts(['open', '--file', 'open.json', '--name', 'override', '--idempotency-key', 'open-key-0002']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/accounts', {
      body: { name: 'override', monthly_budget_cents: 2500, skip: ['card'] },
      headers: { 'Idempotency-Key': 'open-key-0002' },
    });
  });

  it('refuses to open without a name, an idempotency key, or with a bad budget', async () => {
    await expect(cmdAccounts(['open', '--name', 'a'])).rejects.toThrow(/idempotency-key/);
    await expect(cmdAccounts(['open', '--idempotency-key', 'open-key-0005'])).rejects.toThrow(/--name is required/);
    await expect(cmdAccounts(['open', '--name', 'a', '--monthly-budget-cents', '1.5', '--idempotency-key', 'open-key-0003']))
      .rejects.toThrow(/monthly-budget-cents/);
    await expect(cmdAccounts(['open', '--name', 'a', '--monthly-budget-cents', '100', '--idempotency-key', 'short']))
      .rejects.toThrow(/idempotency-key/);
    expect(api).not.toHaveBeenCalled();
  });

  it('lists, reads and closes', async () => {
    await cmdAccounts(['list', '--limit', '10']);
    await cmdAccounts(['get', ACCOUNT]);
    await cmdAccounts(['close', ACCOUNT]);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', '/v1/accounts', { query: { limit: '10' } });
    expect(api).toHaveBeenNthCalledWith(2, 'GET', `/v1/accounts/${ACCOUNT}`);
    expect(api).toHaveBeenNthCalledWith(3, 'DELETE', `/v1/accounts/${ACCOUNT}`);
  });

  it('reads messages, with filters in the query', async () => {
    await cmdAccounts(['messages', ACCOUNT, '--channel', 'sms', '--limit', '5', '--cursor', 'c1']);
    await cmdAccounts(['messages', ACCOUNT, 'amsg_1']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', `/v1/accounts/${ACCOUNT}/messages`, {
      query: { channel: 'sms', limit: '5', cursor: 'c1' },
    });
    expect(api).toHaveBeenNthCalledWith(2, 'GET', `/v1/accounts/${ACCOUNT}/messages/amsg_1`);
  });

  it('sends mail with the body from a flag or a file', async () => {
    await cmdAccounts(['send-email', ACCOUNT, '--to', 'person@example.test', '--subject', 'Hello', '--body', 'Hi there']);
    await cmdAccounts(['send-email', ACCOUNT, '--to', 'person@example.test', '--thread-id', 'thr_1', '--body-file', 'reply.txt']);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `/v1/accounts/${ACCOUNT}/email/send`, {
      body: { to: 'person@example.test', subject: 'Hello', body: 'Hi there' },
    });
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `/v1/accounts/${ACCOUNT}/email/send`, {
      body: { to: 'person@example.test', thread_id: 'thr_1', body: 'Body read from a file' },
    });
  });

  it('sends a text with the number in the body, never the URL', async () => {
    await cmdAccounts(['send-sms', ACCOUNT, '--to', '+14155550123', '--body', 'Hi']);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/sms/send`, { body: { to: '+14155550123', body: 'Hi' } });
  });


  it('names the message an email, a text and a call answer with --reply-to-message', async () => {
    await cmdAccounts(['send-email', ACCOUNT, '--to', 'person@example.test', '--subject', 'Re: Hi', '--reply-to-message', 'amsg_1', '--body', 'Thanks']);
    await cmdAccounts(['send-sms', ACCOUNT, '--to', '+14155550123', '--reply-to-message', 'amsg_2', '--body', 'Thanks']);
    await cmdAccounts(['call', ACCOUNT, '--to', '+14155550123', '--reply-to-message', 'amsg_3']);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `/v1/accounts/${ACCOUNT}/email/send`, {
      body: { to: 'person@example.test', subject: 'Re: Hi', reply_to_message: 'amsg_1', body: 'Thanks' },
    });
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `/v1/accounts/${ACCOUNT}/sms/send`, {
      body: { to: '+14155550123', reply_to_message: 'amsg_2', body: 'Thanks' },
    });
    expect(api).toHaveBeenNthCalledWith(3, 'POST', `/v1/accounts/${ACCOUNT}/calls`, {
      body: { to: '+14155550123', reply_to_message: 'amsg_3' },
    });
  });

  it('leaves reply_to_message out of the body unless it is given', async () => {
    await cmdAccounts(['send-email', ACCOUNT, '--to', 'person@example.test', '--subject', 'Hi', '--body', 'Hello']);
    await cmdAccounts(['send-sms', ACCOUNT, '--to', '+14155550123', '--body', 'Hi']);
    await cmdAccounts(['call', ACCOUNT, '--to', '+14155550123']);
    for (const call of vi.mocked(api).mock.calls) expect(JSON.stringify(call[2]?.body)).not.toContain('reply_to_message');
  });

  it('refuses a send without a recipient or body', async () => {
    await expect(cmdAccounts(['send-sms', ACCOUNT, '--body', 'Hi'])).rejects.toThrow(/--to/);
    await expect(cmdAccounts(['send-email', ACCOUNT, '--to', 'a@example.test', '--subject', 'x'])).rejects.toThrow(/--body/);
    expect(api).not.toHaveBeenCalled();
  });

  it('places a call you hold, with its greeting, wait and voice, as the owner without reading a Passport', async () => {
    await cmdAccounts([
      'call', ACCOUNT, '--to', '+14155550123', '--greeting', 'Hello, this is Ada from Acme Dental.', '--wait-seconds', '20',
      '--max-seconds', '300', '--tts-provider', 'Google', '--language', 'fr-FR',
    ]);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/calls`, {
      body: {
        to: '+14155550123', greeting: 'Hello, this is Ada from Acme Dental.', wait_seconds: 20, max_seconds: 300,
        voice: { tts_provider: 'Google', language: 'fr-FR' },
      },
    });
    expect(readSecretFromStdin).not.toHaveBeenCalled();
  });

  it('places a call STACK holds from a brief file, as one of your agents with the Passport from stdin', async () => {
    await cmdAccounts(['call', ACCOUNT, '--to', '+14155550123', '--on-behalf-of', 'Acme', '--brief-file', 'brief.txt', '--passport-stdin']);
    expect(readSecretFromStdin).toHaveBeenCalledTimes(1);
    expect(api).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/calls`, {
      body: { to: '+14155550123', on_behalf_of: 'Acme', brief: 'Body read from a file' },
      ...PASSPORT,
    });
  });

  it('refuses a call with both brief sources or a bad duration', async () => {
    await expect(cmdAccounts(['call', ACCOUNT, '--on-behalf-of', 'Acme'])).rejects.toThrow(/--to/);
    await expect(cmdAccounts([
      'call', ACCOUNT, '--to', '+14155550123', '--on-behalf-of', 'Acme', '--brief', 'a', '--brief-file', 'b.txt',
    ])).rejects.toThrow(/not both/);
    await expect(cmdAccounts(['call', ACCOUNT, '--to', '+14155550123', '--max-seconds', '1.5'])).rejects.toThrow(/--max-seconds/);
    expect(api).not.toHaveBeenCalled();
    expect(readSecretFromStdin).not.toHaveBeenCalled();
  });

  it('answers a ringing call as the owner, and as one of your agents with the Passport from stdin', async () => {
    await cmdAccounts(['answer-call', ACCOUNT, 'acall_1', '--greeting', 'Acme Dental, how can I help?', '--max-seconds', '300']);
    expect(readSecretFromStdin).not.toHaveBeenCalled();
    await cmdAccounts(['answer-call', ACCOUNT, 'acall_2', '--on-behalf-of', 'Acme', '--brief-file', 'brief.txt', '--passport-stdin']);
    expect(readSecretFromStdin).toHaveBeenCalledTimes(1);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/answer`, {
      body: { greeting: 'Acme Dental, how can I help?', max_seconds: 300 },
    });
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `/v1/accounts/${ACCOUNT}/calls/acall_2/answer`, {
      body: { on_behalf_of: 'Acme', brief: 'Body read from a file' },
      ...PASSPORT,
    });
  });

  it('refuses to answer a call without its id, or with a bad duration', async () => {
    await expect(cmdAccounts(['answer-call', ACCOUNT, '--greeting', 'Hi'])).rejects.toThrow(/call id/);
    await expect(cmdAccounts(['answer-call', ACCOUNT, 'acall_1', '--max-seconds', '1.5'])).rejects.toThrow(/--max-seconds/);
    expect(api).not.toHaveBeenCalled();
    expect(readSecretFromStdin).not.toHaveBeenCalled();
  });

  it('speaks, sends keys, changes the voice and hangs up on a live call, and reads and sets the account voice', async () => {
    await cmdAccounts(['call-say', ACCOUNT, 'acall_1', '--text', 'Hello, is this Sam?', '--wait-seconds', '10']);
    await cmdAccounts(['call-say', ACCOUNT, 'acall_1']);
    await cmdAccounts(['call-keys', ACCOUNT, 'acall_1', '--digits', '1w#']);
    await cmdAccounts(['call-voice', ACCOUNT, 'acall_1', '--language', 'es-ES']);
    await cmdAccounts(['hang-up', ACCOUNT, 'acall_1', '--passport-stdin']);
    await cmdAccounts(['call-voice-settings', ACCOUNT]);
    await cmdAccounts(['call-voice-settings', ACCOUNT, '--voice', 'Joanna-Neural', '--voicemail-greeting', 'Leave a message.']);
    const calls = vi.mocked(api).mock.calls;
    expect(calls[0]).toEqual(['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/say`, { body: { text: 'Hello, is this Sam?', wait_seconds: 10 } }]);
    expect(calls[1]).toEqual(['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/say`, { body: {} }]);
    expect(calls[2]).toEqual(['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/keys`, { body: { digits: '1w#' } }]);
    expect(calls[3]).toEqual(['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/voice`, { body: { voice: { language: 'es-ES' } } }]);
    expect(calls[4]).toEqual(['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/hang-up`, { ...PASSPORT }]);
    expect(calls[5]).toEqual(['GET', `/v1/accounts/${ACCOUNT}/phone/voice`, {}]);
    expect(calls[6]).toEqual(['PUT', `/v1/accounts/${ACCOUNT}/phone/voice`, { body: { voice: 'Joanna-Neural', voicemail_greeting: 'Leave a message.' } }]);
    await expect(cmdAccounts(['call-voice', ACCOUNT, 'acall_1'])).rejects.toThrow(/call-voice/);
    await expect(cmdAccounts(['call-keys', ACCOUNT, 'acall_1'])).rejects.toThrow(/--digits/);
  });

  it('declines a ringing call with no body, as the operator or as the agent', async () => {
    await cmdAccounts(['decline-call', ACCOUNT, 'acall_1']);
    await cmdAccounts(['decline-call', ACCOUNT, 'acall_2', '--passport-stdin']);
    await expect(cmdAccounts(['decline-call', ACCOUNT])).rejects.toThrow(/call id/);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/decline`, {});
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `/v1/accounts/${ACCOUNT}/calls/acall_2/decline`, PASSPORT);
    expect(api).toHaveBeenCalledTimes(2);
    expect(readSecretFromStdin).toHaveBeenCalledTimes(1);
  });

  it('lists calls with paging in the query, and reads one call', async () => {
    await cmdAccounts(['calls', ACCOUNT, '--limit', '5', '--cursor', 'c1']);
    await cmdAccounts(['calls', ACCOUNT, 'acall_1']);
    await cmdAccounts(['calls', ACCOUNT, 'acall_2', '--passport-stdin']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', `/v1/accounts/${ACCOUNT}/calls`, { query: { limit: '5', cursor: 'c1' } });
    expect(api).toHaveBeenNthCalledWith(2, 'GET', `/v1/accounts/${ACCOUNT}/calls/acall_1`, {});
    expect(api).toHaveBeenNthCalledWith(3, 'GET', `/v1/accounts/${ACCOUNT}/calls/acall_2`, PASSPORT);
    expect(readSecretFromStdin).toHaveBeenCalledTimes(1);
  });

  it('discovers, inspects and runs tools under the Passport', async () => {
    await cmdAccounts(['tools', ACCOUNT, 'discover', '--query', 'tweets about rust', '--limit', '5']);
    await cmdAccounts(['tools', ACCOUNT, 'inspect', '--provider', 'acme', '--endpoint', '/acme/search']);
    await cmdAccounts([
      'tools', ACCOUNT, 'run', '--provider', 'acme', '--endpoint', '/acme/search', '--input', '{"q":"rust"}', '--max-results', '20',
    ]);
    await cmdAccounts(['tools', ACCOUNT, 'run', '--provider', 'acme', '--endpoint', '/acme/profile', '--input-file', 'input.json']);
    const tools = `/v1/accounts/${ACCOUNT}/tools`;
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `${tools}/discover`, { body: { query: 'tweets about rust', limit: 5 }, ...PASSPORT });
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `${tools}/inspect`, {
      body: { provider: 'acme', endpoint: '/acme/search' }, ...PASSPORT,
    });
    expect(api).toHaveBeenNthCalledWith(3, 'POST', `${tools}/run`, {
      body: { provider: 'acme', endpoint: '/acme/search', input: { q: 'rust' }, max_results: 20 }, ...PASSPORT,
    });
    expect(api).toHaveBeenNthCalledWith(4, 'POST', `${tools}/run`, {
      body: { provider: 'acme', endpoint: '/acme/profile', input: { username: 'from-file' } }, ...PASSPORT,
    });
    expect(readSecretFromStdin).toHaveBeenCalledTimes(4);
  });

  it('refuses a tool action without a Passport, and checks flags before prompting for one', async () => {
    vi.mocked(readSecretFromStdin).mockResolvedValueOnce('');
    await expect(cmdAccounts(['tools', ACCOUNT, 'discover', '--query', 'x'])).rejects.toThrow(/No Passport token/);
    expect(api).not.toHaveBeenCalled();
    vi.mocked(readSecretFromStdin).mockClear();
    await expect(cmdAccounts(['tools', ACCOUNT, 'run', '--provider', 'p'])).rejects.toThrow(/--endpoint/);
    await expect(cmdAccounts(['tools', ACCOUNT, 'run', '--provider', 'p', '--endpoint', '/e', '--input', 'not json']))
      .rejects.toThrow(/not JSON/);
    await expect(cmdAccounts(['tools', ACCOUNT, 'run', '--provider', 'p', '--endpoint', '/e', '--input-file', 'list.json']))
      .rejects.toThrow(/JSON object/);
    await expect(cmdAccounts(['tools', ACCOUNT, 'nope'])).rejects.toThrow(/discover, inspect, run or run-get/);
    expect(readSecretFromStdin).not.toHaveBeenCalled();
    expect(api).not.toHaveBeenCalled();
  });

  it('reads a tool run as the operator or as the agent', async () => {
    await cmdAccounts(['tools', ACCOUNT, 'run-get', 'atr_1']);
    await cmdAccounts(['tools', ACCOUNT, 'run-get', 'atr_2', '--passport-stdin']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', `/v1/accounts/${ACCOUNT}/tools/runs/atr_1`, {});
    expect(api).toHaveBeenNthCalledWith(2, 'GET', `/v1/accounts/${ACCOUNT}/tools/runs/atr_2`, PASSPORT);
    await expect(cmdAccounts(['tools', ACCOUNT, 'run-get'])).rejects.toThrow(/run id/);
  });

  it('never takes a Passport token from argv', async () => {
    for (const argv of [
      ['tools', ACCOUNT, 'discover', '--query', 'x', '--passport', 'eyJ.secret'],
      ['call', ACCOUNT, '--to', '+14155550123', '--passport-token=eyJ.secret'],
      ['calls', ACCOUNT, '--token', 'eyJ.secret'],
    ]) {
      await expect(cmdAccounts(argv)).rejects.toThrow(/must not be placed in argv/);
    }
    expect(readSecretFromStdin).not.toHaveBeenCalled();
    expect(api).not.toHaveBeenCalled();
    const fs = await vi.importActual<typeof import('node:fs')>('node:fs');
    const sources = ['./accounts.ts', './account-args.ts', './account-site.ts'].map((file) =>
      fs.readFileSync(new URL(file, import.meta.url), 'utf8'),
    );
    for (const source of sources) expect(source).not.toMatch(/flag\(args, '--passport/);
    // The one reader of the Passport is the shared helper, and it reads stdin only.
    expect(sources[1]).toContain("readSecretFromStdin('Passport token: ')");
  });

  it('resumes a piece at once, with no approval', async () => {
    await cmdAccounts(['resume', ACCOUNT, '--piece', 'phone']);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', `/v1/accounts/${ACCOUNT}/pieces/resume`, { body: { piece: 'phone' } });
    expect(governedApi).not.toHaveBeenCalled();
    await expect(cmdAccounts(['resume', ACCOUNT, '--piece', 'wallet'])).rejects.toThrow(/inbox or phone/);
    expect(api).toHaveBeenCalledTimes(1);
  });

  it('reads the toll-free status and submits details through the governance approval flow', async () => {
    await cmdAccounts(['toll-free', ACCOUNT]);
    await cmdAccounts(['toll-free', ACCOUNT, 'submit', '--file', 'toll-free.json']);
    expect(api).toHaveBeenCalledWith('GET', `/v1/accounts/${ACCOUNT}/phone/toll-free-verification`);
    expect(governedApi).toHaveBeenCalledWith('POST', `/v1/accounts/${ACCOUNT}/phone/toll-free-verification`, {
      body: { business_name: 'Acme', business_type: 'SOLE_PROPRIETOR' },
    });
  });

  it('refuses a toll-free submission without a JSON object file', async () => {
    await expect(cmdAccounts(['toll-free', ACCOUNT, 'submit'])).rejects.toThrow(/--file/);
    await expect(cmdAccounts(['toll-free', ACCOUNT, 'submit', '--file', 'list.json'])).rejects.toThrow(/JSON object/);
    await expect(cmdAccounts(['toll-free', ACCOUNT, 'resubmit'])).rejects.toThrow(/submit/);
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('deletes one message', async () => {
    await cmdAccounts(['message-delete', ACCOUNT, 'amsg_1']);
    expect(api).toHaveBeenCalledWith('DELETE', `/v1/accounts/${ACCOUNT}/messages/amsg_1`, { expectEmpty: true });
    await expect(cmdAccounts(['message-delete', ACCOUNT])).rejects.toThrow(/message id/);
  });

  it('lists and removes do-not-contact numbers on the owner routes, with no account id', async () => {
    await cmdAccounts(['opt-outs']);
    await cmdAccounts(['opt-out-remove', 'aoo_a/b']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', '/v1/opt-outs');
    expect(api).toHaveBeenNthCalledWith(2, 'DELETE', '/v1/opt-outs/aoo_a%2Fb');
    await expect(cmdAccounts(['opt-out-remove'])).rejects.toThrow(/opt-out id/);
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('lists, adds to and removes from the blocked-callers list on the customer routes, with no account id', async () => {
    await cmdAccounts(['blocked-callers']);
    await cmdAccounts(['blocked-caller-add', '+14155550123']);
    await cmdAccounts(['blocked-caller-remove', 'abk_a/b']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', '/v1/blocked-callers');
    expect(api).toHaveBeenNthCalledWith(2, 'POST', '/v1/blocked-callers', { body: { number: '+14155550123' } });
    expect(api).toHaveBeenNthCalledWith(3, 'DELETE', '/v1/blocked-callers/abk_a%2Fb');
    await expect(cmdAccounts(['blocked-caller-add'])).rejects.toThrow(/phone number/);
    await expect(cmdAccounts(['blocked-caller-remove'])).rejects.toThrow(/blocked-caller id/);
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('lists, connects and verifies the own mail domains on the operator routes, with no account id', async () => {
    await cmdAccounts(['mail-domains']);
    await cmdAccounts(['mail-domain-connect', '--domain', 'mail.example.com']);
    await cmdAccounts(['mail-domain-verify', 'omd_abcdefgh1234']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', '/v1/accounts/mail-domains');
    expect(api).toHaveBeenNthCalledWith(2, 'POST', '/v1/accounts/mail-domains', { body: { domain: 'mail.example.com' } });
    expect(api).toHaveBeenNthCalledWith(3, 'POST', '/v1/accounts/mail-domains/omd_abcdefgh1234/verify');
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('refuses a mail domain connect without a domain and a verify without an id', async () => {
    await expect(cmdAccounts(['mail-domain-connect'])).rejects.toThrow(/--domain is required/);
    await expect(cmdAccounts(['mail-domain-verify'])).rejects.toThrow(/mail domain id/);
    expect(api).not.toHaveBeenCalled();
  });

  it('encodes the mail domain id in the path', async () => {
    await cmdAccounts(['mail-domain-verify', 'omd_a/b']);
    expect(api).toHaveBeenCalledWith('POST', '/v1/accounts/mail-domains/omd_a%2Fb/verify');
  });

  it('encodes ids in paths and refuses unknown subcommands', async () => {
    await cmdAccounts(['get', 'acct_a/b']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/accounts/acct_a%2Fb');
    await expect(cmdAccounts(['nope'])).rejects.toThrow();
  });
});

describe('the generic tool run from the CLI', () => {
  const base = `/v1/accounts/${ACCOUNT}`;

  it('sends a cap of its own', async () => {
    await cmdAccounts(['tools', ACCOUNT, 'run', '--provider', 'acme', '--endpoint', '/acme/x', '--max-cost-cents', '9']);
    expect(api).toHaveBeenCalledWith('POST', `${base}/tools/run`, { body: { provider: 'acme', endpoint: '/acme/x', max_cost_cents: 9 }, ...PASSPORT });
  });

  it('prints the run whole and says so when it is untrusted and when files were saved to the drive', async () => {
    const stderrWrite = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const run = {
      id: 'atr_1', untrusted: true,
      files: [
        { name: 'shot.png', content_type: 'image/png', size_bytes: 10, drive_file_id: 'drv_0123456789abcdef0123', source_url: null, data_base64: null },
        { name: 'inline.txt', content_type: 'text/plain', size_bytes: 2, drive_file_id: null, source_url: null, data_base64: 'aGk=' },
      ],
    };
    vi.mocked(api).mockResolvedValueOnce(run).mockResolvedValueOnce(run);
    await cmdAccounts(['tools', ACCOUNT, 'run', '--provider', 'p', '--endpoint', '/e']);
    await cmdAccounts(['tools', ACCOUNT, 'run-get', 'atr_1']);
    expect(printJson).toHaveBeenNthCalledWith(1, run);
    expect(printJson).toHaveBeenNthCalledWith(2, run);
    const notice = stderrWrite.mock.calls.map(([chunk]) => String(chunk)).join('');
    expect(notice.match(/untrusted: /g)).toHaveLength(2);
    expect(notice.match(/saved to drive: drv_0123456789abcdef0123 \(shot\.png\)/g)).toHaveLength(2);
    expect(notice).not.toContain('inline.txt');
    stderrWrite.mockRestore();
  });

  it('prints nothing extra for a run that is not untrusted and saved nothing', async () => {
    const stderrWrite = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    vi.mocked(api).mockResolvedValueOnce({ id: 'atr_2', untrusted: false, files: [] });
    await cmdAccounts(['tools', ACCOUNT, 'run', '--provider', 'p', '--endpoint', '/e']);
    expect(stderrWrite).not.toHaveBeenCalled();
    stderrWrite.mockRestore();
  });
});

describe('the ready tools are gone from the CLI', () => {
  it('has no ready action, and no source that names a ready tool', async () => {
    await expect(cmdAccounts(['tools', ACCOUNT, 'ready'])).rejects.toThrow(/discover, inspect, run or run-get/);
    await expect(cmdAccounts(['tools', ACCOUNT, 'ready', 'run', '--tool', 'web_search'])).rejects.toThrow(/discover, inspect, run or run-get/);
    expect(api).not.toHaveBeenCalled();
    const { readdirSync, readFileSync } = await vi.importActual<typeof import('node:fs')>('node:fs');
    const dir = new URL('.', import.meta.url);
    const offenders = readdirSync(dir)
      .filter((name) => name.endsWith('.ts') && name !== 'accounts.test.ts')
      .filter((name) => /READY_TOOLS|tools\/ready|ready tool|image_generate|speech_generate|video_generate|web_scrape|social_read/.test(readFileSync(new URL(name, dir), 'utf8')));
    expect(offenders).toEqual([]);
  });
});

describe('signing keys and identity from the CLI', () => {
  const base = `/v1/accounts/${ACCOUNT}`;

  it('lists and rotates', async () => {
    await cmdAccounts(['signing-keys', ACCOUNT]);
    await cmdAccounts(['signing-keys', ACCOUNT, 'rotate']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', `${base}/signing-keys`);
    expect(api).toHaveBeenNthCalledWith(2, 'POST', `${base}/signing-keys/rotate`);
    await expect(cmdAccounts(['signing-keys', ACCOUNT, 'delete'])).rejects.toThrow(/list or rotate/);
    await expect(cmdAccounts(['signing-keys', ACCOUNT, 'directory', '--authority', 'agent.sites.example'])).rejects.toThrow(/list or rotate/);
  });

  it('reads and changes what the public answer shows, and takes nothing else', async () => {
    await cmdAccounts(['identity', ACCOUNT]);
    await cmdAccounts(['identity', ACCOUNT, 'show-name']);
    await cmdAccounts(['identity', ACCOUNT, 'hide-name']);
    await cmdAccounts(['identity', ACCOUNT, 'off']);
    await cmdAccounts(['identity', ACCOUNT, 'on']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', `${base}/identity`);
    expect(api).toHaveBeenNthCalledWith(2, 'PUT', `${base}/identity`, { body: { show_name: true } });
    expect(api).toHaveBeenNthCalledWith(3, 'PUT', `${base}/identity`, { body: { show_name: false } });
    expect(api).toHaveBeenNthCalledWith(4, 'PUT', `${base}/identity`, { body: { enabled: false } });
    expect(api).toHaveBeenNthCalledWith(5, 'PUT', `${base}/identity`, { body: { enabled: true } });
    await expect(cmdAccounts(['identity', ACCOUNT, 'sideways'])).rejects.toThrow(/get, show-name, hide-name, on or off/);
  });

  it('has no AI disclosure command: STACK adds no line to what an agent sends', async () => {
    await expect(cmdAccounts(['disclosure', ACCOUNT])).rejects.toThrow(/Invalid input/);
    expect(api).not.toHaveBeenCalled();
  });
});

describe('account budget', () => {
  it('converts dollars to whole cents exactly and goes through the approval flow', async () => {
    for (const [input, cents] of [['25', 2500], ['25.5', 2550], ['25.50', 2550], ['0.07', 7], ['19.99', 1999], ['1.10', 110]] as const) {
      await cmdAccounts(['budget', ACCOUNT, input]);
      expect(governedApi).toHaveBeenLastCalledWith('PUT', `/v1/accounts/${ACCOUNT}/budget`, { body: { monthly_budget_cents: cents } });
    }
    expect(api).not.toHaveBeenCalled();
  });

  it('removes the budget with none', async () => {
    await cmdAccounts(['budget', ACCOUNT, 'none']);
    expect(governedApi).toHaveBeenCalledWith('PUT', `/v1/accounts/${ACCOUNT}/budget`, { body: { monthly_budget_cents: null } });
  });

  it('refuses zero, negative, non-numeric and over-precise budgets before any request', async () => {
    for (const bad of ['0', '0.00', '-5', 'abc', '25.505', '1e3', '$25', '25,50']) {
      await expect(cmdAccounts(['budget', ACCOUNT, bad])).rejects.toThrow(/budget/);
    }
    await expect(cmdAccounts(['budget', ACCOUNT])).rejects.toThrow(/budget/);
    expect(governedApi).not.toHaveBeenCalled();
  });
});
