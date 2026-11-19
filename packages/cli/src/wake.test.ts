import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { printJson } from './format.js';
import { cmdCalendar, cmdMeeting, cmdWake } from './wake.js';

vi.mock('./api.js', async (importOriginal) => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./format.js', async (importOriginal) => ({ ...await importOriginal<object>(), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'ppt_piped_token') }));

const dir = mkdtempSync(join(tmpdir(), 'stack-cli-wake-'));
const file = (name: string, value: unknown): string => {
  const path = join(dir, name);
  writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
  return path;
};

afterAll(() => rmSync(dir, { recursive: true, force: true }));
beforeEach(() => vi.clearAllMocks());

const calls = () => vi.mocked(api).mock.calls;

describe('wake CLI', () => {
  it('reads the queue, one wake and acknowledges it, as the operator or as the agent with its Passport on stdin', async () => {
    await cmdWake(['list', 'agt_1', '--status', 'open', '--limit', '5']);
    await cmdWake(['get', 'agt_1', 'wke_1']);
    await cmdWake(['ack', 'agt_1', 'wke_1', '--passport-stdin']);
    expect(calls()).toEqual([
      ['GET', '/v1/agents/agt_1/wakes', { query: { status: 'open', limit: '5' } }],
      ['GET', '/v1/agents/agt_1/wakes/wke_1', {}],
      ['POST', '/v1/agents/agt_1/wakes/wke_1/acknowledge', { headers: { 'X-Passport-Token': 'ppt_piped_token' } }],
    ]);
  });

  it('never takes a Passport from argv', async () => {
    await expect(cmdWake(['list', 'agt_1', '--passport', 'ppt_leaky'])).rejects.toThrow(/must not be placed in argv/);
    await expect(cmdCalendar(['events', 'acct_1', '--token=ppt_leaky'])).rejects.toThrow(/must not be placed in argv/);
    expect(api).not.toHaveBeenCalled();
  });

  it('addresses an agent with an account and the customer\'s defaults without one', async () => {
    await cmdWake(['settings', 'get']);
    await cmdWake(['settings', 'get', 'agt_1']);
    await cmdWake(['rules']);
    await cmdWake(['rules', 'agt_1']);
    expect(calls().map((c) => `${c[0]} ${c[1]}`)).toEqual([
      'GET /v1/wake/settings', 'GET /v1/agents/agt_1/wake/settings', 'GET /v1/wake/rules', 'GET /v1/agents/agt_1/wake/rules',
    ]);
  });

  it('sets settings from flags, and clears one with none', async () => {
    await cmdWake(['settings', 'set', 'agt_1', '--time-zone', 'Europe/Stockholm', '--quiet', '22:00-07:00', '--quiet-mode', 'drop',
      '--rate-limit', '10', '--rate-window', '600', '--delivery', 'webhook,mission', '--invite-lead', '15', '--webhook-url', 'https://agent.example.com/wake', '--disable']);
    await cmdWake(['settings', 'set', '--quiet', 'none', '--delivery', 'default', '--webhook-url', 'none']);
    await cmdWake(['settings', 'set', 'agt_1', '--no-ring-incoming-calls']);
    await cmdWake(['settings', 'set', '--ring-incoming-calls']);
    expect(calls()[0]).toEqual(['PUT', '/v1/agents/agt_1/wake/settings', { body: {
      time_zone: 'Europe/Stockholm', quiet_start: '22:00', quiet_end: '07:00', quiet_mode: 'drop', rate_limit_max: 10,
      rate_limit_window_seconds: 600, delivery: ['webhook', 'mission'], invite_lead_minutes: 15, webhook_url: 'https://agent.example.com/wake', enabled: false,
    } }]);
    expect(calls()[1]).toEqual(['PUT', '/v1/wake/settings', { body: { quiet_start: null, quiet_end: null, delivery: null, webhook_url: null } }]);
    // Ringing for a call that comes in is the customer's switch, on by default.
    expect(calls()[2]).toEqual(['PUT', '/v1/agents/agt_1/wake/settings', { body: { ring_incoming_calls: false } }]);
    expect(calls()[3]).toEqual(['PUT', '/v1/wake/settings', { body: { ring_incoming_calls: true } }]);
  });

  it('refuses settings it cannot read before calling the API', async () => {
    await expect(cmdWake(['settings', 'set', 'agt_1'])).rejects.toThrow(/at least one setting/);
    await expect(cmdWake(['settings', 'set', '--quiet', '10pm-7am'])).rejects.toThrow(/HH:MM-HH:MM/);
    await expect(cmdWake(['settings', 'set', '--delivery', 'pigeon'])).rejects.toThrow(/mcp, webhook, mission/);
    await expect(cmdWake(['settings', 'set', '--quiet-mode', 'sleep'])).rejects.toThrow(/hold, drop/);
    await expect(cmdWake(['settings', 'set', '--rate-limit', 'lots'])).rejects.toThrow(/whole number/);
    await expect(cmdWake(['settings', 'frob'])).rejects.toThrow(/get or set/);
    expect(api).not.toHaveBeenCalled();
  });

  it('adds, replaces and removes rules', async () => {
    await cmdWake(['rule-add', 'agt_1', '--name', 'Boss', '--source', 'email', '--from', 'boss@example.com,@partner.example', '--task', 'Handle it.']);
    await cmdWake(['rule-add', '--name', 'Paid', '--source', 'payment', '--min-amount-cents', '500', '--disabled']);
    await cmdWake(['rule-update', 'wkr_1', '--file', file('rule.json', { name: 'Texts', source: 'sms', task: 'Reply.' })]);
    await cmdWake(['rule-delete', 'wkr_1']);
    expect(calls()).toEqual([
      ['POST', '/v1/agents/agt_1/wake/rules', { body: { name: 'Boss', source: 'email', task: 'Handle it.', filters: { from: ['boss@example.com', '@partner.example'] } } }],
      ['POST', '/v1/wake/rules', { body: { name: 'Paid', source: 'payment', filters: { min_amount_cents: 500 }, enabled: false } }],
      ['PUT', '/v1/wake/rules/wkr_1', { body: { name: 'Texts', source: 'sms', task: 'Reply.' } }],
      ['DELETE', '/v1/wake/rules/wkr_1', { expectEmpty: true }],
    ]);
    await cmdWake(['rule-add', 'agt_1', '--name', 'Ring', '--source', 'incoming_call', '--task', 'Answer or decline.']);
    expect(calls().at(-1)).toEqual(['POST', '/v1/agents/agt_1/wake/rules', { body: { name: 'Ring', source: 'incoming_call', task: 'Answer or decline.' } }]);
    // The end of a pending item the agent waited on is a source too.
    await cmdWake(['rule-add', 'agt_1', '--name', 'Decided', '--source', 'decision', '--task', 'Carry on.']);
    expect(calls().at(-1)).toEqual(['POST', '/v1/agents/agt_1/wake/rules', { body: { name: 'Decided', source: 'decision', task: 'Carry on.' } }]);
    await expect(cmdWake(['rule-add', '--name', 'x'])).rejects.toThrow(/--name and --source/);
    await expect(cmdWake(['rule-add', '--name', 'x', '--source', 'fax'])).rejects.toThrow(/email, sms/);
  });

  it('manages schedules', async () => {
    await cmdWake(['schedules', 'agt_1']);
    await cmdWake(['schedule-add', 'agt_1', '--name', 'Morning', '--cron', '30 9 * * *', '--task', 'Do the round.', '--time-zone', 'Europe/Stockholm']);
    await cmdWake(['schedule-update', 'agt_1', 'wsc_1', '--name', 'Morning', '--cron', '@daily', '--task', 'Round.', '--disabled']);
    await cmdWake(['schedule-delete', 'agt_1', 'wsc_1']);
    expect(calls()).toEqual([
      ['GET', '/v1/agents/agt_1/wake/schedules'],
      ['POST', '/v1/agents/agt_1/wake/schedules', { body: { name: 'Morning', cron: '30 9 * * *', task: 'Do the round.', time_zone: 'Europe/Stockholm' } }],
      ['PUT', '/v1/agents/agt_1/wake/schedules/wsc_1', { body: { name: 'Morning', cron: '@daily', task: 'Round.', enabled: false } }],
      ['DELETE', '/v1/agents/agt_1/wake/schedules/wsc_1', { expectEmpty: true }],
    ]);
    await expect(cmdWake(['schedule-add', 'agt_1', '--name', 'x'])).rejects.toThrow(/--cron/);
  });

  it('prints a signing secret once, with a reminder, and says where to read it when it was not given', async () => {
    const { stderr } = await import('node:process');
    const write = vi.spyOn(stderr, 'write').mockImplementation(() => true);
    vi.mocked(api).mockResolvedValueOnce({ webhook_secret: 'whsec_x', secret_note: null });
    await cmdWake(['rotate-secret', 'agt_1']);
    vi.mocked(api).mockResolvedValueOnce({ webhook_secret: null, secret_note: 'The signing secret is shown once, to the API.' });
    await cmdWake(['rotate-secret', 'agt_1']);
    expect(write.mock.calls.map((c) => String(c[0]))).toEqual([
      expect.stringMatching(/shown once\. Store it now/),
      'The signing secret is shown once, to the API.\n',
    ]);
    expect(printJson).toHaveBeenCalledTimes(2);
    write.mockRestore();
  });

  it('tests the webhook, and refuses a verb it does not have', async () => {
    await cmdWake(['test-webhook', 'agt_1']);
    expect(calls()).toEqual([['POST', '/v1/agents/agt_1/wake/webhook/test']]);
    await expect(cmdWake(['frob'])).rejects.toThrow(/wake takes list/);
    await expect(cmdWake(['list'])).rejects.toThrow(/agent id is required/);
    await expect(cmdWake(['list', 'agt_1', '--bogus'])).rejects.toThrow(/unexpected argument/);
  });
});

describe('calendar CLI', () => {
  it('lists, reads and answers, the agent with its Passport on stdin', async () => {
    await cmdCalendar(['events', 'acct_1', '--role', 'attendee', '--response', 'pending']);
    await cmdCalendar(['get', 'acct_1', 'cev_1']);
    await cmdCalendar(['agenda', 'acct_1', '--from', '2026-11-01', '--to', '2026-11-30', '--tz', 'Europe/Stockholm']);
    await cmdCalendar(['respond', 'acct_1', 'cev_1', 'accept']);
    await cmdCalendar(['respond', 'acct_1', 'cev_1', 'decline', '--no-notify', '--passport-stdin']);
    expect(calls()).toEqual([
      ['GET', '/v1/accounts/acct_1/calendar/events', { query: { role: 'attendee', response: 'pending' } }],
      ['GET', '/v1/accounts/acct_1/calendar/events/cev_1', {}],
      ['GET', '/v1/accounts/acct_1/calendar/agenda', { query: { from: '2026-11-01', to: '2026-11-30', time_zone: 'Europe/Stockholm' } }],
      ['POST', '/v1/accounts/acct_1/calendar/events/cev_1/respond', { body: { response: 'accept', notify_organizer: true } }],
      ['POST', '/v1/accounts/acct_1/calendar/events/cev_1/respond', { body: { response: 'decline', notify_organizer: false }, headers: { 'X-Passport-Token': 'ppt_piped_token' } }],
    ]);
  });

  it('makes, changes and cancels an event with the body the API takes', async () => {
    await cmdCalendar([
      'create', 'acct_1', '--title', 'Standup', '--start', '2026-11-02T09:00', '--end', '2026-11-02T09:15', '--tz', 'Europe/Stockholm',
      '--repeat', 'FREQ=DAILY;COUNT=5', '--except', '2026-11-03T09:00', '--guests', 'a@example.com,b@example.com', '--wake', '10', '--meeting', '--attend', '--max-seconds', '1800',
    ]);
    await cmdCalendar(['update', 'acct_1', 'cev_1', '--start', '2026-11-04T10:00', '--occurrence', '2026-11-04T09:00', '--scope', 'following', '--no-end', '--counter', 'ccp_1']);
    await cmdCalendar(['cancel', 'acct_1', 'cev_1', '--scope', 'series']);
    await cmdCalendar(['decline-proposal', 'acct_1', 'cev_1', 'ccp_1', '--comment', 'No']);
    expect(calls()).toEqual([
      ['POST', '/v1/accounts/acct_1/calendar/events', { body: {
        title: 'Standup', start: '2026-11-02T09:00', end: '2026-11-02T09:15', time_zone: 'Europe/Stockholm',
        repeat: { rule: 'FREQ=DAILY;COUNT=5', except: ['2026-11-03T09:00'] }, guests: ['a@example.com', 'b@example.com'],
        wake_minutes_before: 10, max_seconds: 1800, meeting: true, attend: true,
      } }],
      ['PATCH', '/v1/accounts/acct_1/calendar/events/cev_1', { body: { start: '2026-11-04T10:00', occurrence: '2026-11-04T09:00', counter_id: 'ccp_1', scope: 'following', end: null } }],
      ['POST', '/v1/accounts/acct_1/calendar/events/cev_1/cancel', { body: { scope: 'series' } }],
      ['POST', '/v1/accounts/acct_1/calendar/events/cev_1/counters/ccp_1/decline', { body: { comment: 'No' } }],
    ]);
  });

  it('makes, rotates and ends the feed', async () => {
    vi.mocked(api).mockResolvedValueOnce({ exists: true, url: 'https://api.example/v1/calendar/feeds/x' });
    await cmdCalendar(['feed', 'acct_1', '--rotate']);
    await cmdCalendar(['feed', 'acct_1', '--revoke']);
    await cmdCalendar(['feed', 'acct_1']);
    expect(calls().map((c) => `${c[0]} ${c[1]}`)).toEqual([
      'POST /v1/accounts/acct_1/calendar/feed', 'DELETE /v1/accounts/acct_1/calendar/feed', 'GET /v1/accounts/acct_1/calendar/feed',
    ]);
    await expect(cmdCalendar(['feed', 'acct_1', '--rotate', '--revoke'])).rejects.toThrow(/two different things/);
  });

  it('refuses what it does not know', async () => {
    await expect(cmdCalendar(['respond', 'acct_1', 'cev_1', 'maybe'])).rejects.toThrow(/accept, tentative, decline/);
    await expect(cmdCalendar(['frob'])).rejects.toThrow(/calendar takes/);
    await expect(cmdCalendar(['create', 'acct_1', '--title', 'x'])).rejects.toThrow(/needs --title and --start/);
    await expect(cmdCalendar(['create', 'acct_1', '--title', 'x', '--start', '2026-11-02', '--except', '2026-11-03'])).rejects.toThrow(/go with --repeat/);
    expect(api).not.toHaveBeenCalled();
  });
});

describe('meeting CLI', () => {
  it('joins, speaks, writes and leaves, the agent with its Passport on stdin', async () => {
    await cmdMeeting(['join', 'acct_1', 'cev_1', '--max-seconds', '1800', '--wait', '5', '--passport-stdin']);
    await cmdMeeting(['say', 'acct_1', 'mtg_1', '--text', 'Hello.', '--wait', '10']);
    await cmdMeeting(['chat', 'acct_1', 'mtg_1', '--text', 'A link.']);
    await cmdMeeting(['leave', 'acct_1', 'mtg_1']);
    expect(calls()).toEqual([
      ['POST', '/v1/accounts/acct_1/meetings', { body: { event_id: 'cev_1', max_seconds: 1800, wait_seconds: 5 }, headers: { 'X-Passport-Token': 'ppt_piped_token' } }],
      ['POST', '/v1/accounts/acct_1/meetings/mtg_1/say', { body: { text: 'Hello.', wait_seconds: 10 } }],
      ['POST', '/v1/accounts/acct_1/meetings/mtg_1/chat', { body: { text: 'A link.' } }],
      ['POST', '/v1/accounts/acct_1/meetings/mtg_1/leave', { body: {} }],
    ]);
  });

  it("reads the account's meeting voice with no flag and sets it, as given, with any", async () => {
    await cmdMeeting(['voice', 'acct_1']);
    await cmdMeeting(['voice', 'acct_1', '--voice', 'Claire', '--language', 'fr', '--passport-stdin']);
    await cmdMeeting(['voice', 'acct_1', '--language', 'de']);
    expect(calls()).toEqual([
      ['GET', '/v1/accounts/acct_1/meetings/voice', {}],
      ['PUT', '/v1/accounts/acct_1/meetings/voice', { body: { voice: 'Claire', language: 'fr' }, headers: { 'X-Passport-Token': 'ppt_piped_token' } }],
      ['PUT', '/v1/accounts/acct_1/meetings/voice', { body: { language: 'de' } }],
    ]);
  });

  it("sets and clears an event's own meeting voice from the calendar command", async () => {
    await cmdCalendar(['create', 'acct_1', '--title', 'Standup', '--start', '2026-11-02T09:00', '--meeting', '--meeting-voice', 'Claire', '--meeting-language', 'fr']);
    await cmdCalendar(['update', 'acct_1', 'cev_1', '--no-meeting-voice']);
    await cmdCalendar(['update', 'acct_1', 'cev_1', '--meeting-language', 'de']);
    expect(calls()).toEqual([
      ['POST', '/v1/accounts/acct_1/calendar/events', { body: { title: 'Standup', start: '2026-11-02T09:00', meeting: true, meeting_voice: { voice: 'Claire', language: 'fr' } } }],
      ['PATCH', '/v1/accounts/acct_1/calendar/events/cev_1', { body: { meeting_voice: null } }],
      ['PATCH', '/v1/accounts/acct_1/calendar/events/cev_1', { body: { meeting_voice: { language: 'de' } } }],
    ]);
    vi.clearAllMocks();
    await expect(cmdCalendar(['update', 'acct_1', 'cev_1', '--no-meeting-voice', '--meeting-voice', 'Claire'])).rejects.toThrow(/does not go with/);
    expect(api).not.toHaveBeenCalled();
  });

  it('lists and reads, and refuses what it does not know and a Passport in argv', async () => {
    await cmdMeeting(['list', 'acct_1', '--status', 'ended', '--limit', '5']);
    await cmdMeeting(['get', 'acct_1', 'mtg_1']);
    expect(calls()).toEqual([
      ['GET', '/v1/accounts/acct_1/meetings', { query: { status: 'ended', limit: '5' } }],
      ['GET', '/v1/accounts/acct_1/meetings/mtg_1', {}],
    ]);
    vi.clearAllMocks();
    await expect(cmdMeeting(['frob'])).rejects.toThrow(/meeting takes/);
    await expect(cmdMeeting(['chat', 'acct_1', 'mtg_1'])).rejects.toThrow(/needs --text/);
    await expect(cmdMeeting(['list', 'acct_1', '--status', 'lost'])).rejects.toThrow();
    await expect(cmdMeeting(['get', 'acct_1', 'mtg_1', '--token=ppt_leaky'])).rejects.toThrow(/must not be placed in argv/);
    expect(api).not.toHaveBeenCalled();
  });
});
