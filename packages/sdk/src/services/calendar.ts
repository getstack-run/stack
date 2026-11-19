import type { HttpClient } from '../client.js';
import type { AccountAgentCallOptions, AccountSenderTag } from './accounts.js';
import type { MeetingVoice, MeetingVoiceSetting } from './meetings.js';

// The agent's calendar: its own events, the invites sent to its address, the agenda and the private feed.
//
// An event is stored once, with its time zone and repeat rule (RFC 5545 RRULE, EXDATE, RDATE); the occurrences of a
// repeating event are worked out when you read the agenda. The account's own agent (under its Passport) and the owner
// or an admin use these calls.
//
// Times are written the way people write them: `2026-11-03` is a date (an all-day event), `2026-11-03T10:00` is a
// local time in `time_zone` (a floating time with none), and a time with `Z` or an offset is an instant.
//
// Making, changing and cancelling an event, and answering an invite, are one action each; reading the agenda, the
// list and the feed is free. What goes to guests is an email like any other: put to your decider as `email.send` for
// exactly the people it reaches, read by the data-flow rule, counted against the shared domain's daily recipients and
// charged as an email. A change is stored whether or not its mail could go: `notices` says which left.

export type CalendarEventRole = 'organizer' | 'attendee';
export type CalendarEventStatus = 'confirmed' | 'tentative' | 'cancelled';
export type CalendarResponse = 'pending' | 'accepted' | 'tentative' | 'declined';
export type CalendarGuestStatus = 'needs_action' | 'accepted' | 'declined' | 'tentative' | 'delegated';
export type CalendarChangeScope = 'series' | 'occurrence' | 'following';

/** A guest: an address, or an address with the name to show. */
export type CalendarGuestInput = string | { email: string; name?: string };

export interface CalendarRepeatInput {
  /** An RFC 5545 RRULE value, such as `FREQ=WEEKLY;BYDAY=MO,WE;UNTIL=20270101T000000Z`. */
  rule: string;
  /** Occurrences left out (EXDATE), written as `start` is. */
  except?: string[];
  /** Extra occurrences (RDATE), written as `start` is. */
  also?: string[];
}

export interface CreateCalendarEventInput {
  title: string;
  start: string;
  /** The end; with neither end nor a date start, the event has no length. A date start alone lasts the day. */
  end?: string;
  /** The IANA zone `start` and `end` are local to. */
  time_zone?: string;
  repeat?: CalendarRepeatInput;
  /** Any text: a room, an address, a dial-in number. */
  location?: string;
  /** Any absolute URI (https:, zoommtg:, msteams:, tel: and others). With `meeting`, STACK's own room link is used instead. */
  meeting_link?: string;
  description?: string;
  /** Each is sent the invite from the account's own address, and every change after it. */
  guests?: CalendarGuestInput[];
  /** Wake the agent this many minutes before each occurrence. */
  wake_minutes_before?: number;
  /** Give the event a meeting room of STACK's (Daily, EU): its link is the event's meeting link and goes in the invite. */
  meeting?: boolean;
  /** With `meeting`: STACK's meeting worker joins the room as the agent at each occurrence's start and wakes it ("Meeting started."). The customer's decider is asked once; a refusal makes the event without `attend` (`meeting.attend` in the answer). */
  attend?: boolean;
  /** With `attend`: how long the agent's part of each meeting may last, in seconds (60 or more). */
  max_seconds?: number;
  /** With `meeting`: the voice and language of the agent in this event's meetings; they replace the account's meeting voice for this event. */
  meeting_voice?: MeetingVoice;
}

export interface UpdateCalendarEventInput {
  title?: string;
  start?: string;
  end?: string | null;
  time_zone?: string | null;
  repeat?: CalendarRepeatInput | null;
  location?: string;
  meeting_link?: string | null;
  description?: string;
  guests?: CalendarGuestInput[];
  wake_minutes_before?: number | null;
  meeting?: boolean;
  attend?: boolean;
  max_seconds?: number | null;
  /** The voice and language of the agent in this event's meetings; null clears them, so the account's meeting voice applies. */
  meeting_voice?: MeetingVoice | null;
  /** Which occurrence to change (its original start, as the agenda gives it). */
  occurrence?: string;
  /** The whole series (default without `occurrence`), that occurrence (default with it), or it and every later one. */
  scope?: CalendarChangeScope;
  /** The guest's proposal (`ccp_*`) this change accepts. */
  counter_id?: string;
}

export interface CancelCalendarEventInput {
  occurrence?: string;
  scope?: CalendarChangeScope;
}

export interface RespondCalendarEventInput {
  response: 'accept' | 'tentative' | 'decline';
  /** Mail the organizer the answer (default true). False records it without telling anyone. */
  notify_organizer?: boolean;
}

export interface ListCalendarEventsQuery {
  role?: CalendarEventRole;
  response?: CalendarResponse;
  limit?: number;
  cursor?: string;
}

export interface CalendarAgendaQuery {
  from: string;
  to: string;
  /** The zone the agenda is written in. Default: the agent's wake-up time zone. */
  time_zone?: string;
  limit?: number;
  cursor?: string;
}

export interface CalendarCounterProposal {
  id: string;
  from: string;
  occurrence: string | null;
  proposed_start: string | null;
  proposed_end: string | null;
  /** The guest's own words: third-party text. */
  comment: string;
  status: 'pending' | 'accepted' | 'declined';
  received_at: string;
}

export interface CalendarEvent {
  id: string;
  account_id: string;
  uid: string;
  /** organizer: the agent's own event. attendee: an invite sent to it. */
  role: CalendarEventRole;
  status: CalendarEventStatus;
  /** An invite: the agent's answer. Null for an own event. */
  response: CalendarResponse | null;
  sequence: number;
  /** On an invite these are the sender's words: third-party text. */
  title: string;
  description: string;
  location: string;
  meeting_link: string | null;
  start: string | null;
  end: string | null;
  time_zone: string | null;
  all_day: boolean;
  repeat: { rule: string; except: string[]; also: string[] } | null;
  changed_occurrences: Array<{
    occurrence: string;
    cancelled: boolean;
    this_and_following: boolean;
    start: string | null;
    end: string | null;
    title: string;
    location: string;
    meeting_link: string | null;
  }>;
  organizer: { email: string; name: string | null } | null;
  guests: Array<{ email: string; name: string | null; status: CalendarGuestStatus }>;
  counters: CalendarCounterProposal[];
  meeting: { provider: 'daily'; room: string; attend: boolean; max_seconds: number | null; voice: MeetingVoiceSetting | null } | null;
  wake_minutes_before: number | null;
  next_wake_at: string | null;
  /** An invite: who sent the mail, and STACK's own checks of that sender. They warn and never block. */
  sender: string | null;
  organizer_matches_sender: boolean;
  sender_tags: AccountSenderTag[] | null;
  sender_resembles: string | null;
  message_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface CalendarAgendaEntry {
  event_id: string;
  /** Names this occurrence to change or cancel it alone. */
  occurrence: string;
  title: string;
  start: string;
  end: string;
  all_day: boolean;
  location: string;
  meeting_link: string | null;
  role: CalendarEventRole;
  response: CalendarResponse | null;
  /** This occurrence differs from the series (moved or changed). */
  changed: boolean;
}

export interface CalendarAgenda {
  time_zone: string;
  occurrences: CalendarAgendaEntry[];
  next_cursor: string | null;
  /** False when a repeat rule needed more steps than one read takes: what is listed is right, and more may follow. */
  complete: boolean;
}

/** What a change told the guests. */
export interface CalendarNotices {
  sent: boolean;
  reason: string | null;
  message_ids: string[];
}

export interface CalendarChange {
  event: CalendarEvent;
  /** A change of this and the following occurrences: the new event that carries them. */
  following: CalendarEvent | null;
  notices: CalendarNotices;
}

export interface RespondCalendarEventResult {
  event: CalendarEvent;
  reply: { sent: boolean; reason: string | null; message_id: string | null };
}

export interface CalendarFeed {
  exists: boolean;
  /** Only when the feed was just made or rotated: shown once, never stored. */
  url: string | null;
  created_at: string | null;
  rotated_at: string | null;
}

const seg = encodeURIComponent;

function passport(options?: AccountAgentCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

export class CalendarService {
  constructor(private readonly client: HttpClient) {}

  private base(accountId: string): string {
    return `/v1/accounts/${seg(accountId)}/calendar`;
  }

  /** The events and invites on the account's calendar, soonest first. A repeating event is listed once. */
  async listEvents(accountId: string, query: ListCalendarEventsQuery = {}, options?: AccountAgentCallOptions): Promise<{ events: CalendarEvent[]; next_cursor: string | null }> {
    return this.client.get<{ events: CalendarEvent[]; next_cursor: string | null }>(`${this.base(accountId)}/events`, {
      role: query.role,
      response: query.response,
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      cursor: query.cursor,
    }, passport(options));
  }

  async getEvent(accountId: string, eventId: string, options?: AccountAgentCallOptions): Promise<CalendarEvent> {
    return this.client.get<CalendarEvent>(`${this.base(accountId)}/events/${seg(eventId)}`, undefined, passport(options));
  }

  /** Occurrences between two times with repeats expanded, changes and cancellations applied, in a time zone. */
  async agenda(accountId: string, query: CalendarAgendaQuery, options?: AccountAgentCallOptions): Promise<CalendarAgenda> {
    return this.client.get<CalendarAgenda>(`${this.base(accountId)}/agenda`, {
      from: query.from,
      to: query.to,
      time_zone: query.time_zone,
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      cursor: query.cursor,
    }, passport(options));
  }

  /** Make an event. One action; each guest is mailed the invite. */
  async createEvent(accountId: string, input: CreateCalendarEventInput, options?: AccountAgentCallOptions): Promise<CalendarChange> {
    return this.client.post<CalendarChange>(`${this.base(accountId)}/events`, input, passport(options));
  }

  /** Change an event, one occurrence of it, or it and the following. One action; the guests get the update. */
  async updateEvent(accountId: string, eventId: string, input: UpdateCalendarEventInput, options?: AccountAgentCallOptions): Promise<CalendarChange> {
    return this.client.patch<CalendarChange>(`${this.base(accountId)}/events/${seg(eventId)}`, input, passport(options));
  }

  /** Cancel an event, one occurrence of it, or it and the following. One action; the guests are mailed the cancellation. */
  async cancelEvent(accountId: string, eventId: string, input: CancelCalendarEventInput = {}, options?: AccountAgentCallOptions): Promise<CalendarChange> {
    return this.client.post<CalendarChange>(`${this.base(accountId)}/events/${seg(eventId)}/cancel`, input, passport(options));
  }

  /**
   * Accept, decline or mark an invite tentative. One action: it mails the organizer an iCalendar reply from the account's
   * own address (put to your decider as `email.send`), only when the organizer is who sent the invite. An accepted invite
   * still to come wakes the agent before each occurrence, less `invite_lead_minutes`.
   */
  async respond(accountId: string, eventId: string, input: RespondCalendarEventInput, options?: AccountAgentCallOptions): Promise<RespondCalendarEventResult> {
    return this.client.post<RespondCalendarEventResult>(`${this.base(accountId)}/events/${seg(eventId)}/respond`, input, passport(options));
  }

  /** Turn down a guest's proposed time (the guest is mailed the refusal). To accept it, update the event with its `counter_id`. */
  async declineProposal(accountId: string, eventId: string, counterId: string, input: { comment?: string } = {}, options?: AccountAgentCallOptions): Promise<CalendarChange> {
    return this.client.post<CalendarChange>(`${this.base(accountId)}/events/${seg(eventId)}/counters/${seg(counterId)}/decline`, input, passport(options));
  }

  /** Whether the account has a feed (a private, read-only iCalendar URL for Google, Outlook or Apple Calendar). */
  async feed(accountId: string, options?: AccountAgentCallOptions): Promise<CalendarFeed> {
    return this.client.get<CalendarFeed>(`${this.base(accountId)}/feed`, undefined, passport(options));
  }

  /**
   * Make the feed, or give it a new URL (the old one stops at once). The URL is returned once; only a hash of its token is
   * kept. Whoever holds the URL sees every event and the guests' addresses until it is rotated or ended.
   */
  async rotateFeed(accountId: string, options?: AccountAgentCallOptions): Promise<CalendarFeed> {
    return this.client.post<CalendarFeed>(`${this.base(accountId)}/feed`, undefined, passport(options));
  }

  /** End the feed: its URL stops working at once. */
  async revokeFeed(accountId: string, options?: AccountAgentCallOptions): Promise<{ revoked: boolean }> {
    return this.client.delete<{ revoked: boolean }>(`${this.base(accountId)}/feed`, passport(options));
  }
}
