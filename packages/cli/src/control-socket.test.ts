import { readFileSync } from 'node:fs';
import { stderr } from 'node:process';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { governedApi } from './governance.js';
import { printJson } from './format.js';
import { cmdControlSocket } from './control-socket.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));

const URL_ = 'https://control.example.com/decide';

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(stderr, 'write').mockImplementation(() => true);
});

describe('control-socket CLI wire contract', () => {
  it('reads the socket without an approval flow', async () => {
    await cmdControlSocket(['get']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/control-socket');
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('sets the decision address through the approval flow, with the timeout only when given', async () => {
    await cmdControlSocket(['set-decision', URL_]);
    await cmdControlSocket(['set-decision', '--timeout-ms', '800', URL_]);
    expect(governedApi).toHaveBeenNthCalledWith(1, 'PUT', '/v1/control-socket/decision', { body: { url: URL_ } });
    expect(governedApi).toHaveBeenNthCalledWith(2, 'PUT', '/v1/control-socket/decision', { body: { url: URL_, timeout_ms: 800 } });
    expect(api).not.toHaveBeenCalled();
  });

  it('sets the events address through the approval flow', async () => {
    await cmdControlSocket(['set-events', 'https://events.example.com/in']);
    expect(governedApi).toHaveBeenCalledWith('PUT', '/v1/control-socket/events', { body: { url: 'https://events.example.com/in' } });
  });

  it('clears, verifies and rotates through the approval flow, and tests without it', async () => {
    await cmdControlSocket(['clear', 'events']);
    await cmdControlSocket(['verify', 'decision']);
    await cmdControlSocket(['rotate-secret', 'decision']);
    await cmdControlSocket(['test', 'events']);
    expect(governedApi).toHaveBeenNthCalledWith(1, 'DELETE', '/v1/control-socket/events');
    expect(governedApi).toHaveBeenNthCalledWith(2, 'POST', '/v1/control-socket/decision/verify');
    expect(governedApi).toHaveBeenNthCalledWith(3, 'POST', '/v1/control-socket/decision/secret/rotate');
    expect(api).toHaveBeenCalledTimes(1);
    expect(api).toHaveBeenCalledWith('POST', '/v1/control-socket/events/test');
  });

  it('switches the mode through the approval flow', async () => {
    await cmdControlSocket(['mode', 'hosted']);
    await cmdControlSocket(['mode', 'none']);
    expect(governedApi).toHaveBeenNthCalledWith(1, 'PUT', '/v1/control-socket/mode', { body: { mode: 'hosted' } });
    expect(governedApi).toHaveBeenNthCalledWith(2, 'PUT', '/v1/control-socket/mode', { body: { mode: 'none' } });
  });

  it('sets checked types from a list, a comma list, or every kind', async () => {
    await cmdControlSocket(['checked-types', 'email.send', 'card.checkout']);
    await cmdControlSocket(['checked-types', 'email.send,sms.send,email.send']);
    await cmdControlSocket(['checked-types', '--all']);
    expect(governedApi).toHaveBeenNthCalledWith(1, 'PUT', '/v1/control-socket/checked-types', { body: { types: ['email.send', 'card.checkout'] } });
    expect(governedApi).toHaveBeenNthCalledWith(2, 'PUT', '/v1/control-socket/checked-types', { body: { types: ['email.send', 'sms.send'] } });
    expect(governedApi).toHaveBeenNthCalledWith(3, 'PUT', '/v1/control-socket/checked-types', { body: { types: null } });
  });

  it('sets what happens when the decision server does not answer, reads it, and takes only refuse or allow', async () => {
    await cmdControlSocket(['on-unavailable', 'allow']);
    await cmdControlSocket(['on-unavailable', 'refuse']);
    expect(governedApi).toHaveBeenNthCalledWith(1, 'PUT', '/v1/control-socket/on-unavailable', { body: { on_unavailable: 'allow' } });
    expect(governedApi).toHaveBeenNthCalledWith(2, 'PUT', '/v1/control-socket/on-unavailable', { body: { on_unavailable: 'refuse' } });
    vi.mocked(api).mockResolvedValueOnce({ decision: { on_unavailable: 'refuse' } });
    await cmdControlSocket(['on-unavailable']);
    expect(printJson).toHaveBeenLastCalledWith({ on_unavailable: 'refuse' });
    await expect(cmdControlSocket(['on-unavailable', 'maybe'])).rejects.toThrow(/refuse or allow/);
  });

  it('reads the checked types when none are given', async () => {
    vi.mocked(api).mockResolvedValueOnce({ checked_types: ['email.send'], checks_all_types: false, mode_setting: 'auto' });
    await cmdControlSocket(['checked-types']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/control-socket');
    expect(printJson).toHaveBeenCalledWith({ checked_types: ['email.send'], checks_all_types: false });
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('lists decisions with only the filters given, and reads one', async () => {
    await cmdControlSocket(['decisions']);
    await cmdControlSocket(['decisions', '--limit', '10', '--account', 'acct_1', '--verdict', 'deny', '--before', '2026-10-21T00:00:00.000Z']);
    await cmdControlSocket(['decision', 'dec_abcdefghijklmnop']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', '/v1/control-decisions', { query: {} });
    expect(api).toHaveBeenNthCalledWith(2, 'GET', '/v1/control-decisions', {
      query: { limit: 10, account_id: 'acct_1', verdict: 'deny', before: '2026-10-21T00:00:00.000Z' },
    });
    expect(api).toHaveBeenNthCalledWith(3, 'GET', '/v1/control-decisions/dec_abcdefghijklmnop');
    expect(governedApi).not.toHaveBeenCalled();
  });
});

describe('control-socket CLI input checks', () => {
  it.each([
    [['set-decision'], /decision address/],
    [['set-decision', URL_, '--timeout-ms', 'fast'], /whole number/],
    [['set-decision', URL_, '--timeout'], /unexpected argument/],
    [['set-events'], /events address/],
    [['clear'], /decision or events/],
    [['clear', 'both'], /decision or events/],
    [['verify', 'nowhere'], /decision or events/],
    [['rotate-secret'], /decision or events/],
    [['mode'], /none or hosted/],
    [['mode', 'remote'], /none or hosted/],
    [['checked-types', 'email.send', 'teleport'], /unknown action type teleport/],
    [['checked-types', '--all', 'email.send'], /not both/],
    [['decisions', '--verdict', 'maybe'], /--verdict must be/],
    [['decisions', '--limit', 'many'], /whole number/],
    [['decision'], /decision id/],
    [['nope'], /control-socket takes/],
    [[], /control-socket takes/],
  ] as Array<[string[], RegExp]>)('refuses %j before any request', async (argv, message) => {
    await expect(cmdControlSocket(argv)).rejects.toThrow(message);
    expect(api).not.toHaveBeenCalled();
    expect(governedApi).not.toHaveBeenCalled();
  });
});

describe('control-socket CLI secrets', () => {
  const SECRET = ['whsec', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='].join('_');

  it('prints a created or rotated secret once, with the store-it-now line on stderr', async () => {
    vi.mocked(governedApi).mockResolvedValueOnce({ socket: {}, secret: SECRET });
    await cmdControlSocket(['set-decision', URL_]);
    expect(printJson).toHaveBeenCalledWith({ socket: {}, secret: SECRET });
    expect(vi.mocked(stderr.write).mock.calls.flat().join('')).toMatch(/Store it now: it is not shown again/);

    vi.mocked(stderr.write).mockClear();
    vi.mocked(governedApi).mockResolvedValueOnce({ target: 'events', secret: SECRET, previous_valid_until: '2026-10-22T00:00:00.000Z' });
    await cmdControlSocket(['rotate-secret', 'events']);
    expect(vi.mocked(stderr.write).mock.calls.flat().join('')).toMatch(/Store it now/);
  });

  it('an OAuth sign-in is not given the secret: it prints the Console link and says to open it signed in', async () => {
    const reveal = { url: 'https://getstack.run/app/control-secret#tok', expires_at: '2026-10-21T11:00:00.000Z' };
    vi.mocked(governedApi).mockResolvedValueOnce({ socket: {}, secret: null, secret_reveal: reveal });
    await cmdControlSocket(['set-decision', URL_]);
    const said = vi.mocked(stderr.write).mock.calls.flat().join('');
    expect(said).toContain(reveal.url);
    expect(said).toMatch(/Open it signed in to the Console/);
    expect(said).not.toMatch(/Store it now/);
  });

  it('says nothing about a secret when the call did not create one', async () => {
    vi.mocked(governedApi).mockResolvedValueOnce({ socket: {}, secret: null });
    await cmdControlSocket(['set-decision', URL_]);
    expect(stderr.write).not.toHaveBeenCalled();
  });

  it('never writes or logs a secret: the module has no file or console output', () => {
    const source = readFileSync(new URL('./control-socket.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/node:fs|writeFile|appendFile|console\./);
    expect(source).not.toMatch(/credentials\.json/);
  });
});
