import { readFileSync } from 'node:fs';
import { stderr } from 'node:process';
import { api, takeFlag } from './api.js';
import { flag, noExtra, positional, takeSwitch, wholeNumber } from './control-socket.js';
import { printJson } from './format.js';
import { readSecretFromStdin } from './secret-input.js';

// Wake-ups: what starts an agent with a task. Every agent of the customer has its own, with or without an agent
// account, so the wake commands take the agent's id; the calendar belongs to an account and takes its id. Nothing wakes an
// agent for mail, texts, voicemail, calls or payments until a rule says so (a call ringing on its number, a schedule, an
// calendar event, a drop-off and the end of a pending item it waited on, the `decision` source, need none); a task is
// your own words and never carries text from the event. The agent's own commands (`list`, `get`, `ack`, and the
// calendar commands) run as the operator, or as the agent with --passport-stdin: the Passport is a secret, so it is read from
// stdin and never from argv.
//
// A webhook signing secret is shown exactly once, by `settings set` when the
// call creates it and by `rotate-secret`. It is printed with a reminder on
// stderr and never written anywhere by this command; a browser sign-in (OAuth)
// is never handed one.

const WAKE_USAGE = 'wake takes list, get, ack, settings, rules, rule-add, rule-update, rule-delete, schedules, schedule-add, schedule-update, schedule-delete, rotate-secret or test-webhook';
const PASSPORT_ARGV_FLAGS = new Set(['--passport', '--passport-token', '--token']);
export const WAKE_SOURCES = ['email', 'sms', 'voicemail', 'call', 'incoming_call', 'payment', 'post', 'invite', 'schedule', 'handoff', 'decision', 'meeting', 'service_event', 'telegram'] as const;
const CHANNELS = ['mcp', 'webhook', 'mission'] as const;

function refusePassportInArgv(args: string[]): void {
  if (args.some((arg) => PASSPORT_ARGV_FLAGS.has(arg.split('=')[0] ?? arg))) {
    throw new Error('Passport tokens must not be placed in argv. Pipe the token on stdin or type it at the hidden prompt.');
  }
}

async function passportHeaders(args: string[]): Promise<{ headers?: Record<string, string> }> {
  if (!takeSwitch(args, '--passport-stdin')) return {};
  const token = await readSecretFromStdin('Passport token: ');
  if (!token) throw new Error("No Passport token: pipe the agent's Passport on stdin or type it at the prompt");
  return { headers: { 'X-Passport-Token': token } };
}

function accountBase(id: string): string {
  return `/v1/accounts/${encodeURIComponent(id)}`;
}

function agentBase(id: string): string {
  return `/v1/agents/${encodeURIComponent(id)}`;
}

/** An agent id when one comes next, else undefined: the customer's default scope. */
function optionalAgent(args: string[]): string | undefined {
  return args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
}

function jsonObject(file: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`Invalid input: ${file} is not valid JSON: ${(error as Error).message}`, { cause: error });
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Invalid input: ${file} must hold one JSON object`);
  return value as Record<string, unknown>;
}

function oneOf<T extends string>(value: string, allowed: readonly T[], what: string): T {
  if (!(allowed as readonly string[]).includes(value)) throw new Error(`Invalid input: ${what} is one of ${allowed.join(', ')}`);
  return value as T;
}

function list(value: string): string[] {
  return value.split(',').map((part) => part.trim()).filter((part) => part !== '');
}

/** Print an answer that may carry a webhook signing secret; the secret is shown only now. */
function printWithSecret(result: unknown): void {
  printJson(result);
  const shown = result as { webhook_secret?: unknown; secret_note?: unknown } | null;
  if (typeof shown?.webhook_secret === 'string') {
    stderr.write('This webhook signing secret is shown once. Store it now: it is not shown again, and STACK cannot show it to you later.\n');
  } else if (typeof shown?.secret_note === 'string') {
    stderr.write(`${shown.secret_note}\n`);
  }
}

function settingsBody(args: string[]): Record<string, unknown> {
  const file = flag(args, '--file');
  const body: Record<string, unknown> = file === undefined ? {} : jsonObject(file);
  const zone = flag(args, '--time-zone');
  if (zone !== undefined) body['time_zone'] = zone === 'none' ? null : zone;
  const quiet = flag(args, '--quiet');
  if (quiet !== undefined) {
    if (quiet === 'none') {
      body['quiet_start'] = null;
      body['quiet_end'] = null;
    } else {
      const match = /^(\d{2}:\d{2})-(\d{2}:\d{2})$/.exec(quiet);
      if (!match) throw new Error('Invalid input: --quiet is HH:MM-HH:MM (24 hours, in the time zone), or none');
      body['quiet_start'] = match[1];
      body['quiet_end'] = match[2];
    }
  }
  const mode = flag(args, '--quiet-mode');
  if (mode !== undefined) body['quiet_mode'] = oneOf(mode, ['hold', 'drop'], '--quiet-mode');
  const rate = wholeNumber(args, '--rate-limit');
  if (rate !== undefined) body['rate_limit_max'] = rate;
  const window = wholeNumber(args, '--rate-window');
  if (window !== undefined) body['rate_limit_window_seconds'] = window;
  const delivery = flag(args, '--delivery');
  if (delivery !== undefined) body['delivery'] = delivery === 'default' ? null : list(delivery).map((c) => oneOf(c, CHANNELS, '--delivery'));
  const lead = wholeNumber(args, '--invite-lead');
  if (lead !== undefined) body['invite_lead_minutes'] = lead;
  if (takeSwitch(args, '--ring-incoming-calls')) body['ring_incoming_calls'] = true;
  if (takeSwitch(args, '--no-ring-incoming-calls')) body['ring_incoming_calls'] = false;
  const url = flag(args, '--webhook-url');
  if (url !== undefined) body['webhook_url'] = url === 'none' ? null : url;
  if (takeSwitch(args, '--enable')) body['enabled'] = true;
  if (takeSwitch(args, '--disable')) body['enabled'] = false;
  if (Object.keys(body).length === 0) throw new Error('Invalid input: give --file or at least one setting to change');
  return body;
}

function ruleBody(args: string[]): Record<string, unknown> {
  const file = flag(args, '--file');
  const body: Record<string, unknown> = file === undefined ? {} : jsonObject(file);
  const name = flag(args, '--name');
  if (name !== undefined) body['name'] = name;
  const source = flag(args, '--source');
  if (source !== undefined) body['source'] = oneOf(source, WAKE_SOURCES, '--source');
  const task = flag(args, '--task');
  if (task !== undefined) body['task'] = task === '' ? null : task;
  const from = flag(args, '--from');
  const min = wholeNumber(args, '--min-amount-cents');
  if (from !== undefined || min !== undefined) {
    const filters = typeof body['filters'] === 'object' && body['filters'] !== null ? { ...(body['filters'] as Record<string, unknown>) } : {};
    if (from !== undefined) filters['from'] = list(from);
    if (min !== undefined) filters['min_amount_cents'] = min;
    body['filters'] = filters;
  }
  if (takeSwitch(args, '--disabled')) body['enabled'] = false;
  if (typeof body['name'] !== 'string' || typeof body['source'] !== 'string') throw new Error('Invalid input: a rule needs --name and --source (or both in --file)');
  return body;
}

function scheduleBody(args: string[]): Record<string, unknown> {
  const file = flag(args, '--file');
  const body: Record<string, unknown> = file === undefined ? {} : jsonObject(file);
  for (const [name, key] of [['--name', 'name'], ['--cron', 'cron'], ['--task', 'task']] as const) {
    const value = flag(args, name);
    if (value !== undefined) body[key] = value;
  }
  const zone = flag(args, '--time-zone');
  if (zone !== undefined) body['time_zone'] = zone === 'none' ? null : zone;
  if (takeSwitch(args, '--disabled')) body['enabled'] = false;
  for (const key of ['name', 'cron', 'task']) {
    if (typeof body[key] !== 'string') throw new Error(`Invalid input: a schedule needs --${key} (or "${key}" in --file)`);
  }
  return body;
}

export async function cmdWake(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  refusePassportInArgv(args);
  const sub = args.shift();

  if (sub === 'list') {
    const agent = positional(args, 'the agent id');
    const query: Record<string, string> = {};
    for (const name of ['status', 'limit', 'cursor'] as const) {
      const value = flag(args, `--${name}`);
      if (value !== undefined) query[name] = value;
    }
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('GET', `${agentBase(agent)}/wakes`, { query, ...auth }));
  }

  if (sub === 'get' || sub === 'ack') {
    const agent = positional(args, 'the agent id');
    const wake = positional(args, 'the wake id');
    const auth = await passportHeaders(args);
    noExtra(args);
    const path = `${agentBase(agent)}/wakes/${encodeURIComponent(wake)}`;
    return printJson(sub === 'get' ? await api('GET', path, auth) : await api('POST', `${path}/acknowledge`, auth));
  }

  if (sub === 'settings') {
    const action = args.shift();
    if (action !== 'get' && action !== 'set') throw new Error('Invalid input: settings takes get or set');
    const agent = optionalAgent(args);
    const path = agent ? `${agentBase(agent)}/wake/settings` : '/v1/wake/settings';
    if (action === 'get') {
      noExtra(args);
      return printJson(await api('GET', path));
    }
    const body = settingsBody(args);
    noExtra(args);
    return printWithSecret(await api('PUT', path, { body }));
  }

  if (sub === 'rules') {
    const agent = optionalAgent(args);
    noExtra(args);
    return printJson(await api('GET', agent ? `${agentBase(agent)}/wake/rules` : '/v1/wake/rules'));
  }

  if (sub === 'rule-add') {
    const agent = optionalAgent(args);
    const body = ruleBody(args);
    noExtra(args);
    return printJson(await api('POST', agent ? `${agentBase(agent)}/wake/rules` : '/v1/wake/rules', { body }));
  }

  if (sub === 'rule-update') {
    const id = positional(args, 'the rule id');
    const body = ruleBody(args);
    noExtra(args);
    return printJson(await api('PUT', `/v1/wake/rules/${encodeURIComponent(id)}`, { body }));
  }

  if (sub === 'rule-delete') {
    const id = positional(args, 'the rule id');
    noExtra(args);
    await api('DELETE', `/v1/wake/rules/${encodeURIComponent(id)}`, { expectEmpty: true });
    return printJson({ deleted: true, id });
  }

  if (sub === 'schedules' || sub === 'schedule-add' || sub === 'schedule-update' || sub === 'schedule-delete') {
    const agent = positional(args, 'the agent id');
    const base = `${agentBase(agent)}/wake/schedules`;
    if (sub === 'schedules') {
      noExtra(args);
      return printJson(await api('GET', base));
    }
    if (sub === 'schedule-add') {
      const body = scheduleBody(args);
      noExtra(args);
      return printJson(await api('POST', base, { body }));
    }
    const id = positional(args, 'the schedule id');
    if (sub === 'schedule-update') {
      const body = scheduleBody(args);
      noExtra(args);
      return printJson(await api('PUT', `${base}/${encodeURIComponent(id)}`, { body }));
    }
    noExtra(args);
    await api('DELETE', `${base}/${encodeURIComponent(id)}`, { expectEmpty: true });
    return printJson({ deleted: true, id });
  }

  if (sub === 'rotate-secret') {
    const agent = positional(args, 'the agent id');
    noExtra(args);
    return printWithSecret(await api('POST', `${agentBase(agent)}/wake/webhook/rotate-secret`));
  }

  if (sub === 'test-webhook') {
    const agent = positional(args, 'the agent id');
    noExtra(args);
    return printJson(await api('POST', `${agentBase(agent)}/wake/webhook/test`));
  }

  throw new Error(WAKE_USAGE);
}

const CALENDAR_USAGE = 'calendar takes events, get, agenda, create, update, cancel, respond, decline-proposal or feed';

function whole(value: string, name: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new Error(`Invalid input: ${name} is a whole number`);
  return n;
}

/** `--except a,b` and `--also a,b` and the rest of an event's fields, as the API's body takes them. */
function eventFields(args: string[], mode: 'create' | 'update'): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  const text = (name: string, key: string) => {
    const value = flag(args, `--${name}`);
    if (value !== undefined) body[key] = value;
  };
  text('title', 'title');
  text('start', 'start');
  text('end', 'end');
  text('tz', 'time_zone');
  text('location', 'location');
  text('link', 'meeting_link');
  text('description', 'description');
  const rule = flag(args, '--repeat');
  const except = flag(args, '--except');
  const also = flag(args, '--also');
  if (rule !== undefined) {
    body['repeat'] = { rule, ...(except !== undefined ? { except: list(except) } : {}), ...(also !== undefined ? { also: list(also) } : {}) };
  } else if (except !== undefined || also !== undefined) {
    throw new Error('Invalid input: --except and --also go with --repeat <rule>');
  }
  const guests = flag(args, '--guests');
  if (guests !== undefined) body['guests'] = list(guests);
  const wake = flag(args, '--wake');
  if (wake !== undefined) body['wake_minutes_before'] = whole(wake, '--wake');
  const maxSeconds = flag(args, '--max-seconds');
  if (maxSeconds !== undefined) body['max_seconds'] = whole(maxSeconds, '--max-seconds');
  if (takeSwitch(args, '--meeting')) body['meeting'] = true;
  if (mode === 'update' && takeSwitch(args, '--no-meeting')) body['meeting'] = false;
  if (takeSwitch(args, '--attend')) body['attend'] = true;
  if (mode === 'update' && takeSwitch(args, '--no-attend')) body['attend'] = false;
  // The voice and language of the agent in this event's meetings (they replace the account's meeting voice for this event).
  const meetingVoice = flag(args, '--meeting-voice');
  const meetingLanguage = flag(args, '--meeting-language');
  const noMeetingVoice = mode === 'update' && takeSwitch(args, '--no-meeting-voice');
  if (noMeetingVoice && (meetingVoice !== undefined || meetingLanguage !== undefined)) {
    throw new Error('Invalid input: --no-meeting-voice does not go with --meeting-voice or --meeting-language');
  }
  if (noMeetingVoice) body['meeting_voice'] = null;
  else if (meetingVoice !== undefined || meetingLanguage !== undefined) {
    body['meeting_voice'] = { ...(meetingVoice !== undefined ? { voice: meetingVoice } : {}), ...(meetingLanguage !== undefined ? { language: meetingLanguage } : {}) };
  }
  return body;
}

const MEETING_USAGE = 'meeting takes join, say, chat, leave, list, get or voice';

/** The agent in the room of one of its own calendar events: STACK runs no model and says nothing of its own. */
export async function cmdMeeting(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  refusePassportInArgv(args);
  const sub = args.shift();

  if (sub === 'join') {
    const account = positional(args, 'the account id');
    const event = positional(args, 'the event id');
    const body: Record<string, unknown> = { event_id: event };
    const maxSeconds = flag(args, '--max-seconds');
    if (maxSeconds !== undefined) body['max_seconds'] = whole(maxSeconds, '--max-seconds');
    const wait = flag(args, '--wait');
    if (wait !== undefined) body['wait_seconds'] = whole(wait, '--wait');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/meetings`, { body, ...auth }));
  }

  if (sub === 'say') {
    const account = positional(args, 'the account id');
    const meeting = positional(args, 'the meeting id');
    const body: Record<string, unknown> = {};
    const text = flag(args, '--text');
    if (text !== undefined) body['text'] = text;
    const wait = flag(args, '--wait');
    if (wait !== undefined) body['wait_seconds'] = whole(wait, '--wait');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/meetings/${encodeURIComponent(meeting)}/say`, { body, ...auth }));
  }

  if (sub === 'chat') {
    const account = positional(args, 'the account id');
    const meeting = positional(args, 'the meeting id');
    const text = flag(args, '--text');
    if (text === undefined) throw new Error('Invalid input: meeting chat needs --text');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/meetings/${encodeURIComponent(meeting)}/chat`, { body: { text }, ...auth }));
  }

  if (sub === 'leave') {
    const account = positional(args, 'the account id');
    const meeting = positional(args, 'the meeting id');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/meetings/${encodeURIComponent(meeting)}/leave`, { body: {}, ...auth }));
  }

  if (sub === 'list') {
    const account = positional(args, 'the account id');
    const query: Record<string, string> = {};
    for (const name of ['status', 'limit', 'cursor'] as const) {
      const value = flag(args, `--${name}`);
      if (value !== undefined) query[name] = value;
    }
    if (query['status'] !== undefined) oneOf(query['status'], ['joining', 'live', 'ended'], '--status');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('GET', `${accountBase(account)}/meetings`, { query, ...auth }));
  }

  if (sub === 'get') {
    const account = positional(args, 'the account id');
    const meeting = positional(args, 'the meeting id');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('GET', `${accountBase(account)}/meetings/${encodeURIComponent(meeting)}`, auth));
  }

  // The account's meeting voice and language. With no flag it is read; with any, it is set as given (a field left out is cleared).
  if (sub === 'voice') {
    const account = positional(args, 'the account id');
    const voice = flag(args, '--voice');
    const language = flag(args, '--language');
    const auth = await passportHeaders(args);
    noExtra(args);
    if (voice === undefined && language === undefined) return printJson(await api('GET', `${accountBase(account)}/meetings/voice`, auth));
    return printJson(await api('PUT', `${accountBase(account)}/meetings/voice`, {
      body: { ...(voice !== undefined ? { voice } : {}), ...(language !== undefined ? { language } : {}) },
      ...auth,
    }));
  }

  throw new Error(MEETING_USAGE);
}

export async function cmdCalendar(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  refusePassportInArgv(args);
  const sub = args.shift();

  if (sub === 'events') {
    const account = positional(args, 'the account id');
    const query: Record<string, string> = {};
    for (const name of ['role', 'response', 'limit', 'cursor'] as const) {
      const value = flag(args, `--${name}`);
      if (value !== undefined) query[name] = value;
    }
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('GET', `${accountBase(account)}/calendar/events`, { query, ...auth }));
  }

  if (sub === 'get') {
    const account = positional(args, 'the account id');
    const event = positional(args, 'the event id');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('GET', `${accountBase(account)}/calendar/events/${encodeURIComponent(event)}`, auth));
  }

  if (sub === 'agenda') {
    const account = positional(args, 'the account id');
    const query: Record<string, string> = {};
    const from = flag(args, '--from');
    const to = flag(args, '--to');
    if (from === undefined || to === undefined) throw new Error('Invalid input: calendar agenda needs --from and --to');
    query['from'] = from;
    query['to'] = to;
    for (const [name, key] of [['tz', 'time_zone'], ['limit', 'limit'], ['cursor', 'cursor']] as const) {
      const value = flag(args, `--${name}`);
      if (value !== undefined) query[key] = value;
    }
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('GET', `${accountBase(account)}/calendar/agenda`, { query, ...auth }));
  }

  if (sub === 'create') {
    const account = positional(args, 'the account id');
    const body = eventFields(args, 'create');
    if (typeof body['title'] !== 'string' || typeof body['start'] !== 'string') throw new Error('Invalid input: calendar create needs --title and --start');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/calendar/events`, { body, ...auth }));
  }

  if (sub === 'update') {
    const account = positional(args, 'the account id');
    const event = positional(args, 'the event id');
    const body = eventFields(args, 'update');
    for (const [name, key] of [['occurrence', 'occurrence'], ['counter', 'counter_id']] as const) {
      const value = flag(args, `--${name}`);
      if (value !== undefined) body[key] = value;
    }
    const scope = flag(args, '--scope');
    if (scope !== undefined) body['scope'] = oneOf(scope, ['series', 'occurrence', 'following'], '--scope');
    if (takeSwitch(args, '--no-end')) body['end'] = null;
    if (takeSwitch(args, '--no-repeat')) body['repeat'] = null;
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('PATCH', `${accountBase(account)}/calendar/events/${encodeURIComponent(event)}`, { body, ...auth }));
  }

  if (sub === 'cancel') {
    const account = positional(args, 'the account id');
    const event = positional(args, 'the event id');
    const body: Record<string, unknown> = {};
    const occurrence = flag(args, '--occurrence');
    if (occurrence !== undefined) body['occurrence'] = occurrence;
    const scope = flag(args, '--scope');
    if (scope !== undefined) body['scope'] = oneOf(scope, ['series', 'occurrence', 'following'], '--scope');
    const auth = await passportHeaders(args);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/calendar/events/${encodeURIComponent(event)}/cancel`, { body, ...auth }));
  }

  if (sub === 'respond') {
    const account = positional(args, 'the account id');
    const event = positional(args, 'the event id');
    const response = oneOf(positional(args, 'the answer (accept, tentative or decline)'), ['accept', 'tentative', 'decline'], 'the answer');
    const notify = !takeSwitch(args, '--no-notify');
    const auth = await passportHeaders(args);
    noExtra(args);
    const body = { response, notify_organizer: notify };
    return printJson(await api('POST', `${accountBase(account)}/calendar/events/${encodeURIComponent(event)}/respond`, { body, ...auth }));
  }

  if (sub === 'decline-proposal') {
    const account = positional(args, 'the account id');
    const event = positional(args, 'the event id');
    const counter = positional(args, 'the proposal id');
    const comment = flag(args, '--comment');
    const auth = await passportHeaders(args);
    noExtra(args);
    const body = comment === undefined ? {} : { comment };
    return printJson(await api('POST', `${accountBase(account)}/calendar/events/${encodeURIComponent(event)}/counters/${encodeURIComponent(counter)}/decline`, { body, ...auth }));
  }

  if (sub === 'feed') {
    const account = positional(args, 'the account id');
    const rotate = takeSwitch(args, '--rotate');
    const revoke = takeSwitch(args, '--revoke');
    if (rotate && revoke) throw new Error('Invalid input: --rotate and --revoke are two different things');
    const auth = await passportHeaders(args);
    noExtra(args);
    if (rotate) {
      const feed = await api('POST', `${accountBase(account)}/calendar/feed`, auth) as { url?: string | null };
      printJson(feed);
      if (feed.url) stderr.write('The feed URL is shown once and only a hash of it is kept. Whoever holds it sees every event and the guests\' addresses until it is rotated or ended.\n');
      return;
    }
    if (revoke) return printJson(await api('DELETE', `${accountBase(account)}/calendar/feed`, auth));
    return printJson(await api('GET', `${accountBase(account)}/calendar/feed`, auth));
  }

  throw new Error(CALENDAR_USAGE);
}
