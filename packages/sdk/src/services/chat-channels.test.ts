import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { ControlLimitExceededError, TelegramSendRefusedError } from '../errors.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const parsed = new URL(url);
      calls.push({
        method: init.method ?? 'GET',
        path: parsed.pathname,
        search: parsed.search,
        body: init.body ? JSON.parse(init.body) : undefined,
        headers: init.headers ?? {},
      });
      return new Response(reply.status === 204 ? null : JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

const stack = () => new Stack({ apiKey: 'sk_live_test', baseUrl: 'https://api.example.test' });

describe('chat channels', () => {
  it('reads the channels and the identities bound', async () => {
    const calls = stubFetch();
    await stack().chatChannels.get();
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/chat-channels' });
  });

  it('starts a binding, types a text code, confirms in the console and ends one', async () => {
    const calls = stubFetch();
    const s = stack().chatChannels;
    await s.createIdentity({ channel: 'telegram' });
    await s.createIdentity({ channel: 'sms', phone: '+46701740605' });
    await s.verifyIdentity('cid_abcdefgh12', '123456');
    await s.confirmIdentity('cid_abcdefgh12');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /v1/chat-channels/identities',
      'POST /v1/chat-channels/identities',
      'POST /v1/chat-channels/identities/cid_abcdefgh12/verify',
      'POST /v1/chat-channels/identities/cid_abcdefgh12/confirm',
    ]);
    expect(calls[1]!.body).toEqual({ channel: 'sms', phone: '+46701740605' });
    expect(calls[2]!.body).toEqual({ code: '123456' });
    const ended = stubFetch({ status: 204 });
    await s.removeIdentity('cid_abcdefgh12');
    expect(ended[0]).toMatchObject({ method: 'DELETE', path: '/v1/chat-channels/identities/cid_abcdefgh12' });
  });

  it('escapes an id so it cannot leave its path', async () => {
    const calls = stubFetch();
    await stack().chatChannels.confirmIdentity('../x');
    expect(calls[0]!.path).toBe('/v1/chat-channels/identities/..%2Fx/confirm');
  });

  it('installs and removes the Slack workspace', async () => {
    const calls = stubFetch({ status: 200, body: { url: 'https://slack.com/oauth/v2/authorize?x=1' } });
    const url = await stack().chatChannels.slackInstallUrl({ redirect_uri: 'https://console.example.test/cb', state: 'abcdefgh1234' });
    expect(url.url).toContain('slack.com');
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/chat-channels/slack/install-url' });
    expect(calls[0]!.search).toContain('state=abcdefgh1234');
    await stack().chatChannels.installSlack({ code: 'c0de', redirect_uri: 'https://console.example.test/cb' });
    expect(calls[1]).toMatchObject({ method: 'POST', path: '/v1/chat-channels/slack/install', body: { code: 'c0de', redirect_uri: 'https://console.example.test/cb' } });
    const ended = stubFetch({ status: 204 });
    await stack().chatChannels.removeSlack();
    expect(ended[0]).toMatchObject({ method: 'DELETE', path: '/v1/chat-channels/slack' });
  });
});

describe('an agent\'s Telegram bot', () => {
  const TOKEN = '123456789:AAHfixturefixturefixturefixturefixture1';

  it('connects, reads, lists chats and disconnects, sending the token once and only to the connect route', async () => {
    const calls = stubFetch();
    const telegram = stack().accounts.telegram;
    await telegram.connect('acct_abc123', TOKEN);
    await telegram.get('acct_abc123');
    await telegram.chats('acct_abc123');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'PUT /v1/accounts/acct_abc123/telegram',
      'GET /v1/accounts/acct_abc123/telegram',
      'GET /v1/accounts/acct_abc123/telegram/chats',
    ]);
    expect(calls[0]!.body).toEqual({ bot_token: TOKEN });
    expect(JSON.stringify(calls.slice(1))).not.toContain(TOKEN);
    const ended = stubFetch({ status: 204 });
    await telegram.disconnect('acct_abc123');
    expect(ended[0]).toMatchObject({ method: 'DELETE', path: '/v1/accounts/acct_abc123/telegram' });
  });

  it('sends under the agent\'s Passport and throws the refusal as a typed error', async () => {
    const calls = stubFetch({ status: 201, body: { channel: 'telegram', status: 'sent' } });
    await stack().accounts.sendTelegram('acct_abc123', { chat_id: '42', text: 'hi' }, { passportToken: 'passport.jwt' });
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/accounts/acct_abc123/telegram/messages', body: { chat_id: '42', text: 'hi' } });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('passport.jwt');

    stubFetch({ status: 403, body: { error: { code: 'TELEGRAM_SEND_REFUSED', message: 'That chat has not written to this bot.', details: { reason: 'chat_unknown' } } } });
    const error = await stack().accounts.sendTelegram('acct_abc123', { chat_id: '9', text: 'hi' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TelegramSendRefusedError);
    expect((error as TelegramSendRefusedError).reason).toBe('chat_unknown');
  });

  it('reads which spend rule refused a payment on a limit error', async () => {
    stubFetch({ status: 403, body: { error: { code: 'CONTROL_LIMIT_EXCEEDED', message: 'limit', details: { limit: { window: 'day', unit: 'cents', scope: 'spend:shop' }, remaining: 0 } } } });
    const error = await stack().accounts.sendTelegram('acct_abc123', { chat_id: '9', text: 'hi' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlLimitExceededError);
    expect((error as ControlLimitExceededError).limit).toEqual({ window: 'day', unit: 'cents', scope: 'spend:shop' });
  });
});
