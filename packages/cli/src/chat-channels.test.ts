import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { readSecretFromStdin } from './secret-input.js';
import { cmdAccounts } from './accounts.js';
import { cmdChat } from './chat-channels.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => '123456789:AAHfixturefixturefixturefixturefixture1') }));

const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const TOKEN = '123456789:AAHfixturefixturefixturefixturefixture1';

beforeEach(() => vi.clearAllMocks());

describe('chat command', () => {
  it('lists the channels and the identities bound', async () => {
    await cmdChat(['list']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/chat-channels');
  });

  it('starts a binding, with a number for a text and only for a text', async () => {
    await cmdChat(['link', 'telegram']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/chat-channels/identities', { body: { channel: 'telegram' } });
    await cmdChat(['link', 'sms', '--phone', '+46701740605']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/chat-channels/identities', { body: { channel: 'sms', phone: '+46701740605' } });
    vi.mocked(api).mockClear();
    await expect(cmdChat(['link', 'sms'])).rejects.toThrow(/phone/);
    await expect(cmdChat(['link', 'slack', '--phone', '+46701740605'])).rejects.toThrow(/phone/);
    await expect(cmdChat(['link', 'whatsapp'])).rejects.toThrow(/telegram, sms or slack/);
    expect(api).not.toHaveBeenCalled();
  });

  it('ends an identity, reads the Slack install address and uninstalls', async () => {
    await cmdChat(['remove', 'cid_abc']);
    expect(api).toHaveBeenLastCalledWith('DELETE', '/v1/chat-channels/identities/cid_abc', { expectEmpty: true });
    await cmdChat(['slack-install-url', '--redirect-uri', 'https://console.example/cb', '--state', 'abcdefgh12']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/chat-channels/slack/install-url', {
      query: { redirect_uri: 'https://console.example/cb', state: 'abcdefgh12' },
    });
    await cmdChat(['slack-remove']);
    expect(api).toHaveBeenLastCalledWith('DELETE', '/v1/chat-channels/slack', { expectEmpty: true });
  });

  it('has no command that confirms an identity, types a code or installs Slack: those are the console\'s', async () => {
    for (const sub of ['confirm', 'verify', 'slack-install']) await expect(cmdChat([sub, 'cid_abc'])).rejects.toThrow(/chat takes/);
    expect(api).not.toHaveBeenCalled();
  });

  it('refuses an unknown subcommand and extra arguments', async () => {
    await expect(cmdChat([])).rejects.toThrow(/chat takes/);
    await expect(cmdChat(['list', 'extra'])).rejects.toThrow(/Unexpected/);
  });
});

describe('the agent\'s Telegram bot', () => {
  it('reads the bot token from stdin, never argv, and sends it once', async () => {
    await cmdAccounts(['telegram-connect', ACCOUNT]);
    expect(readSecretFromStdin).toHaveBeenCalledTimes(1);
    expect(api).toHaveBeenCalledWith('PUT', `/v1/accounts/${ACCOUNT}/telegram`, { body: { bot_token: TOKEN } });
    vi.mocked(api).mockClear();
    await expect(cmdAccounts(['telegram-connect', ACCOUNT, '--token', TOKEN])).rejects.toThrow(/argv/);
    await expect(cmdAccounts(['telegram-connect', ACCOUNT, '--bot-token=' + TOKEN])).rejects.toThrow(/argv/);
    await expect(cmdAccounts(['telegram-connect', ACCOUNT, TOKEN])).rejects.toThrow(/argv/);
    expect(api).not.toHaveBeenCalled();
  });

  it('reads the bot and its chats, and disconnects', async () => {
    await cmdAccounts(['telegram', ACCOUNT]);
    expect(api).toHaveBeenLastCalledWith('GET', `/v1/accounts/${ACCOUNT}/telegram`);
    await cmdAccounts(['telegram-chats', ACCOUNT]);
    expect(api).toHaveBeenLastCalledWith('GET', `/v1/accounts/${ACCOUNT}/telegram/chats`);
    await cmdAccounts(['telegram-disconnect', ACCOUNT]);
    expect(api).toHaveBeenLastCalledWith('DELETE', `/v1/accounts/${ACCOUNT}/telegram`, { expectEmpty: true });
  });

  it('answers a chat, with the chat in the body and the agent\'s Passport only when asked', async () => {
    await cmdAccounts(['send-telegram', ACCOUNT, '--chat-id', '42', '--body', 'Moved to Friday']);
    expect(api).toHaveBeenLastCalledWith('POST', `/v1/accounts/${ACCOUNT}/telegram/messages`, { body: { chat_id: '42', text: 'Moved to Friday' } });
    vi.mocked(readSecretFromStdin).mockResolvedValueOnce('passport.jwt');
    await cmdAccounts(['send-telegram', ACCOUNT, '--chat-id', '42', '--body', 'hi', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', `/v1/accounts/${ACCOUNT}/telegram/messages`, {
      body: { chat_id: '42', text: 'hi' }, headers: { 'X-Passport-Token': 'passport.jwt' },
    });
    await expect(cmdAccounts(['send-telegram', ACCOUNT, '--body', 'hi'])).rejects.toThrow(/--chat-id/);
  });
});
