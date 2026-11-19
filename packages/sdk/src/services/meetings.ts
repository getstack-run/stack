import type { HttpClient } from '../client.js';
import type { AccountAgentCallOptions, AccountCallWebSocket, AccountCallWebSocketConstructor } from './accounts.js';

// The agent in the room of one of its own calendar events, with STACK as plumbing: it runs no model and says nothing of its
// own. The agent hears each participant by the name they gave, speaks, writes in the room's chat and leaves.
//
// Make an event with `meeting: true` (`calendar.create`) to get a room: its link goes in the invite. `join` puts the agent in
// the room (one action; events made with `attend: true` are joined for the agent at their start and wake it). Any agent of the
// customer may use the account's meetings, under its own Passport, and so may the owner. What the meeting uses (Daily's
// participant-minutes, Soniox's speech-to-text for each participant and Soniox's speech) is charged at cost, ten minutes
// at a time. What a participant says, writes or is called is a stranger's text.

export type MeetingStatus = 'joining' | 'live' | 'ended';
export type MeetingEndReason = 'agent_left' | 'everyone_left' | 'max_seconds' | 'wallet' | 'revoked' | 'worker_lost' | 'room_ended' | 'join_failed';

export interface MeetingFlag {
  severity: 'suspicious' | 'critical';
  security_event_id: string | null;
}

/** What happens in a meeting, as the agent hears it, numbered from 1 in the order it happened. */
export type MeetingEvent =
  | { seq: number; at: string; type: 'heard'; speaker?: string; text?: string; withheld?: boolean; flag?: MeetingFlag }
  | { seq: number; at: string; type: 'chat'; from?: string; text?: string; withheld?: boolean; flag?: MeetingFlag }
  | { seq: number; at: string; type: 'joined'; name: string }
  | { seq: number; at: string; type: 'left'; name: string }
  | { seq: number; at: string; type: 'paid_time_ends'; in_seconds: number; message: string }
  | { seq: number; at: string; type: 'ended'; reason: MeetingEndReason };

/** One line of a meeting's transcript. A line the owner's controls withhold has no text. */
export interface MeetingLine {
  at: string;
  speaker: string;
  kind: 'participant' | 'agent' | 'chat' | 'agent_chat';
  text?: string;
  withheld?: boolean;
  flag?: MeetingFlag;
}

export interface Meeting {
  id: string;
  account_id: string;
  event_id: string;
  status: MeetingStatus;
  end_reason: MeetingEndReason | null;
  max_seconds: number;
  /** STACK joined at the event's start (`attend`), or the agent asked. */
  attended: boolean;
  /** The other participants in the room now. */
  participants: number;
  created_at: string;
  joined_at: string | null;
  ended_at: string | null;
  charged_cents: number | null;
  /** The end of what is paid for now; the next 10 minutes are held about a minute before it. Null once the meeting has ended. */
  paid_until: string | null;
}

/** What every action on a meeting returns: the meeting, and every event since this caller's last action on it. */
export interface MeetingTurn {
  meeting: Meeting;
  events: MeetingEvent[];
}

export interface JoinMeetingInput {
  /** The calendar event (cev_*) whose room to join. */
  event_id: string;
  /** How long the agent's part may last, in seconds (1 or more). Default: the event's own, else none: the agent's part lasts until it leaves, everyone has left or the money runs out. */
  max_seconds?: number;
  /** How long to wait for the agent to be in the room (0 to 60 seconds, default 30). */
  wait_seconds?: number;
}

export interface SayInMeetingInput {
  /** What to say, as it is. Left out, only waits. */
  text?: string;
  /** How long to wait for what a participant says or writes next (0 to 60 seconds, default 30). */
  wait_seconds?: number;
}

/**
 * The voice and language the agent speaks in during meetings, and listens for: Soniox's own words for them (any voice it takes,
 * a language code such as `fr`). STACK keeps no list of either and does not check them; Soniox's refusal is what comes back.
 * Nothing set: a default voice, English speech and speech recognition that finds the language itself.
 */
export interface MeetingVoice {
  voice?: string;
  language?: string;
}

/** The meeting voice as it is set: a field that is not set is null. */
export interface MeetingVoiceSetting {
  voice: string | null;
  language: string | null;
}

export interface ListMeetingsQuery {
  status?: MeetingStatus;
  limit?: number;
  cursor?: string;
}

export interface ListMeetingsResult {
  meetings: Meeting[];
  next_cursor: string | null;
}

export interface MeetingWithTranscript {
  meeting: Meeting;
  lines: MeetingLine[];
}

const seg = encodeURIComponent;

function passport(options?: AccountAgentCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

export class MeetingsService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Join the room of a calendar event as the agent. One metered action. Returns once the agent is in the room (up to
   * `wait_seconds`) with the events so far. The first ten minutes are held on the account's credit.
   */
  async join(accountId: string, input: JoinMeetingInput, options?: AccountAgentCallOptions): Promise<MeetingTurn> {
    return this.client.post<MeetingTurn>(`/v1/accounts/${seg(accountId)}/meetings`, input, passport(options));
  }

  /** Speak (`text`, as it is) and wait up to `wait_seconds` for what a participant says or writes next. Not metered. */
  async say(accountId: string, meetingId: string, input: SayInMeetingInput = {}, options?: AccountAgentCallOptions): Promise<MeetingTurn> {
    return this.client.post<MeetingTurn>(`/v1/accounts/${seg(accountId)}/meetings/${seg(meetingId)}/say`, input, passport(options));
  }

  /** Write a line in the room's chat. Not metered. */
  async chat(accountId: string, meetingId: string, text: string, options?: AccountAgentCallOptions): Promise<MeetingTurn> {
    return this.client.post<MeetingTurn>(`/v1/accounts/${seg(accountId)}/meetings/${seg(meetingId)}/chat`, { text }, passport(options));
  }

  /** Leave the meeting: the agent's part ends at once. The transcript is stored as a message and the account's agent woken. */
  async leave(accountId: string, meetingId: string, options?: AccountAgentCallOptions): Promise<MeetingTurn> {
    return this.client.post<MeetingTurn>(`/v1/accounts/${seg(accountId)}/meetings/${seg(meetingId)}/leave`, undefined, passport(options));
  }

  /** The account's meetings, newest first. */
  async list(accountId: string, query: ListMeetingsQuery = {}, options?: AccountAgentCallOptions): Promise<ListMeetingsResult> {
    return this.client.get<ListMeetingsResult>(`/v1/accounts/${seg(accountId)}/meetings`, {
      status: query.status,
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      cursor: query.cursor,
    }, passport(options));
  }

  /** The account's meeting voice and language. The owner, an admin or the account's own agent. Free. */
  async getVoice(accountId: string, options?: AccountAgentCallOptions): Promise<MeetingVoiceSetting> {
    return this.client.get<MeetingVoiceSetting>(`/v1/accounts/${seg(accountId)}/meetings/voice`, undefined, passport(options));
  }

  /**
   * Set the account's meeting voice and language; a field left out is cleared. Applies to every meeting of the account unless the
   * event sets its own (`meeting_voice` on `calendar.createEvent` and `updateEvent`). Not metered, no approval.
   */
  async setVoice(accountId: string, input: MeetingVoice, options?: AccountAgentCallOptions): Promise<MeetingVoiceSetting> {
    return this.client.put<MeetingVoiceSetting>(`/v1/accounts/${seg(accountId)}/meetings/voice`, input, passport(options));
  }

  /** One meeting and its transcript so far. */
  async get(accountId: string, meetingId: string, options?: AccountAgentCallOptions): Promise<MeetingWithTranscript> {
    return this.client.get<MeetingWithTranscript>(`/v1/accounts/${seg(accountId)}/meetings/${seg(meetingId)}`, undefined, passport(options));
  }

  /**
   * The live stream of a meeting (a WebSocket): every event as it happens, and the agent's words streamed on to be spoken as they
   * come (`text(token, last)`). The socket closes once the meeting has ended. In Node the global `WebSocket` (Node 22 or later) is
   * used, with the client's credential in the `Authorization` header; pass `webSocket` to use another implementation that takes
   * headers the same way.
   */
  async live(accountId: string, meetingId: string, options: AccountAgentCallOptions & { webSocket?: AccountCallWebSocketConstructor } = {}): Promise<MeetingStream> {
    const Socket = options.webSocket ?? (globalThis as { WebSocket?: AccountCallWebSocketConstructor }).WebSocket;
    if (!Socket) throw new Error('No WebSocket implementation: use Node 22 or later, or pass webSocket');
    const url = `${this.client.apiBaseUrl.replace(/^http/, 'ws')}/v1/accounts/${seg(accountId)}/meetings/${seg(meetingId)}/live`;
    const headers: Record<string, string> = { Authorization: await this.client.authorizationHeader() };
    if (options.passportToken) headers['X-Passport-Token'] = options.passportToken;
    return new MeetingStream(new Socket(url, { headers }));
  }
}

/**
 * A meeting's live stream. `events()` yields every event in order, ending after `ended`; `errors` are the messages the stream
 * could not use. Send with `text`, `chat` and `leave`.
 */
export class MeetingStream {
  private readonly queue: MeetingEvent[] = [];
  private waiting: (() => void) | null = null;
  private done = false;
  private readonly opened: Promise<void>;
  readonly errors: { code: string; message: string }[] = [];

  constructor(private readonly socket: AccountCallWebSocket) {
    this.opened = new Promise((resolve, reject) => {
      socket.addEventListener('open', () => resolve());
      socket.addEventListener('error', () => reject(new Error('The live stream could not be opened')));
    });
    // A rejection nobody awaits is not an unhandled one: `send` awaits it.
    this.opened.catch(() => undefined);
    socket.addEventListener('message', (event) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(String(event.data));
      } catch {
        return;
      }
      const message = parsed as { type?: string; code?: string; message?: string };
      if (message.type === 'error') this.errors.push({ code: String(message.code), message: String(message.message) });
      else this.queue.push(parsed as MeetingEvent);
      this.wake();
    });
    socket.addEventListener('close', () => {
      this.done = true;
      this.wake();
    });
  }

  private wake(): void {
    const waiting = this.waiting;
    this.waiting = null;
    waiting?.();
  }

  /** Every event of the meeting, oldest first from the start, until it ends. */
  async *events(): AsyncGenerator<MeetingEvent> {
    for (;;) {
      const next = this.queue.shift();
      if (next) {
        yield next;
        continue;
      }
      if (this.done) return;
      await new Promise<void>((resolve) => {
        this.waiting = resolve;
      });
    }
  }

  private async send(message: Record<string, unknown>): Promise<void> {
    await this.opened;
    this.socket.send(JSON.stringify(message));
  }

  /** Words to speak, streamed as they come; `last` on the final token of what the agent says. */
  async text(token: string, last = false): Promise<void> {
    await this.send({ type: 'text', token, last });
  }

  /** A line for the room's chat. */
  async chat(text: string): Promise<void> {
    await this.send({ type: 'chat', text });
  }

  /** Leave the meeting. */
  async leave(): Promise<void> {
    await this.send({ type: 'leave' });
  }

  close(): void {
    this.socket.close(1000, 'done');
  }
}
