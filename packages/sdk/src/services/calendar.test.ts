import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

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
      return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_calendar_test', baseUrl: 'http://api.fixture' });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('calendar', () => {
  it('reads events, one event, the agenda and the feed, the agent under its Passport', async () => {
    const calls = stubFetch();
    const { calendar } = stack();
    await calendar.listEvents('acct_1', { role: 'attendee', response: 'pending', limit: 10 }, { passportToken: 'ppt' });
    await calendar.getEvent('acct_1', 'cev_1');
    await calendar.agenda('acct_1', { from: '2026-11-01', to: '2026-11-30', time_zone: 'Europe/Stockholm', limit: 50 });
    await calendar.feed('acct_1');
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      'GET /v1/accounts/acct_1/calendar/events?role=attendee&response=pending&limit=10',
      'GET /v1/accounts/acct_1/calendar/events/cev_1',
      'GET /v1/accounts/acct_1/calendar/agenda?from=2026-11-01&to=2026-11-30&time_zone=Europe%2FStockholm&limit=50',
      'GET /v1/accounts/acct_1/calendar/feed',
    ]);
    expect(calls[0]!.headers['X-Passport-Token']).toBe('ppt');
    expect(calls[1]!.headers['X-Passport-Token']).toBeUndefined();
  });

  it('makes, changes, cancels and answers on the routes the API serves', async () => {
    const calls = stubFetch();
    const { calendar } = stack();
    await calendar.createEvent('acct_1', { title: 'Review', start: '2026-11-10T10:00Z', guests: ['a@example.com'], meeting: true, attend: true });
    await calendar.updateEvent('acct_1', 'cev_1', { start: '2026-11-11T10:00Z', occurrence: '2026-11-10T10:00Z', scope: 'following' });
    await calendar.cancelEvent('acct_1', 'cev_1', { scope: 'series' });
    await calendar.respond('acct_1', 'cev_2', { response: 'decline', notify_organizer: false }, { passportToken: 'ppt' });
    await calendar.declineProposal('acct_1', 'cev_1', 'ccp_1', { comment: 'No' });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /v1/accounts/acct_1/calendar/events',
      'PATCH /v1/accounts/acct_1/calendar/events/cev_1',
      'POST /v1/accounts/acct_1/calendar/events/cev_1/cancel',
      'POST /v1/accounts/acct_1/calendar/events/cev_2/respond',
      'POST /v1/accounts/acct_1/calendar/events/cev_1/counters/ccp_1/decline',
    ]);
    expect(calls[3]!.body).toEqual({ response: 'decline', notify_organizer: false });
    expect(calls[3]!.headers['X-Passport-Token']).toBe('ppt');
  });

  it('makes, rotates and ends the feed', async () => {
    const calls = stubFetch({ status: 200, body: { exists: true, url: 'https://api.fixture/v1/calendar/feeds/x', created_at: null, rotated_at: null } });
    const { calendar } = stack();
    const feed = await calendar.rotateFeed('acct_1');
    expect(feed.url).toContain('/v1/calendar/feeds/');
    await calendar.revokeFeed('acct_1');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(['POST /v1/accounts/acct_1/calendar/feed', 'DELETE /v1/accounts/acct_1/calendar/feed']);
  });

  it('turns a refusal into a StackError with the API\'s code', async () => {
    stubFetch({ status: 409, body: { error: { code: 'CALENDAR_EVENT_CANCELLED', message: 'This event is cancelled.' } } });
    await expect(stack().calendar.updateEvent('acct_1', 'cev_1', { title: 'x' })).rejects.toMatchObject({ code: 'CALENDAR_EVENT_CANCELLED', status: 409 });
  });
});
