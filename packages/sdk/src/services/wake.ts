import type { HttpClient } from '../client.js';
import type { AccountAgentCallOptions, AccountSenderTag } from './accounts.js';

// Wake-ups: what starts an agent with a task. Every agent of the customer has its own
// wake-ups, with or without an agent account. An account's agent is also woken by its
// mail, texts, voicemail and call transcripts, a call ringing on its number, payments
// received, post and accepted calendar invites reaching their start; any agent by its
// schedule, a drop-off another of the customer's agents left for it, and the end of a
// pending item it waited on (source `decision`: an approval, an order, a hand-off and the
// rest, with `event.item_kind`, `event.item_id` and `event.result`) and by the events of a service the customer connected
// (source `service_event`: a person applying, delivering or writing at RentAHuman, with `event.service`, `event.event_type` and
// `event.ids`, never a word of what they wrote).
//
// Nothing wakes an agent for mail, texts, voicemail, calls or payments until the owner says so: a rule per source
// (and optionally per sender or amount) names the task, in the owner's own words. A call ringing on its number,
// a schedule, a calendar event, a drop-off, a decision and a service event wake it without a rule.
// The event's text is never put into a task. Each wake is one action on the
// meter and an account's agent's wake is put to your decider as `wake.deliver`.
//
// A wake reaches the agent, in the order you prefer, by an MCP notification on an open
// session of the agent (never the delivery on its own: a client may not show it to the
// model), by a signed webhook (Standard Webhooks) to its own endpoint, and always by its
// queue: `list(agentId, { status: 'open' })` is the queue, `acknowledge` picks a wake up,
// and a delivered wake nobody acknowledged ends as `expired` after 30 days. Quiet hours
// hold wakes (or drop them; a decision is only ever held), a rate limit per agent stops a
// flood (a decision and a call ringing take no part in it), and the same event twice is
// one wake. Settings, rules and schedules are owner or admin calls; an agent reads its
// queue and picks wakes up.

export type WakeSource = 'email' | 'sms' | 'voicemail' | 'call' | 'incoming_call' | 'payment' | 'post' | 'invite' | 'schedule' | 'handoff' | 'decision' | 'meeting' | 'service_event' | 'telegram';

/** The pending items a `decision` wake tells the agent the end of. */
export type DecisionItemKind =
  | 'intent_approval' | 'fleet_review' | 'control_review' | 'authority_request' | 'proxy_operation' | 'dropoff' | 'mission_review'
  | 'card_purchase' | 'making_order' | 'letter' | 'post_action' | 'skill_invocation' | 'website_hostname';
export type WakeChannel = 'mcp' | 'webhook' | 'mission';
export type WakeStatus = 'pending' | 'delivered' | 'acknowledged' | 'refused' | 'expired';
export type WakeQuietMode = 'hold' | 'drop';

/** What an event must match for a rule to apply. Left out, it matches everything. */
export interface WakeFilters {
  /** Senders: an address, `@domain.example` for a whole domain, a phone number, or `telegram:<name>` for a Telegram sender. Message sources only. */
  from?: string[];
  /** Payments of at least this many cents. Payments only. */
  min_amount_cents?: number;
}

/** Every field is optional; `null` clears one so the agent inherits the customer's default. */
export interface WakeSettingsInput {
  enabled?: boolean;
  /** An IANA zone, such as `Europe/Stockholm`. */
  time_zone?: string | null;
  /** `HH:MM`, 24 hours, in `time_zone`. Both quiet times are set together. */
  quiet_start?: string | null;
  quiet_end?: string | null;
  quiet_mode?: WakeQuietMode | null;
  rate_limit_max?: number | null;
  rate_limit_window_seconds?: number | null;
  /** The channels you prefer, most preferred first. The queue always comes last. */
  delivery?: WakeChannel[] | null;
  /** Minutes before an accepted invite's start at which the agent is woken. */
  invite_lead_minutes?: number | null;
  /** Whether a call that comes in rings the agent (default true). `false` sends it to voicemail. */
  ring_incoming_calls?: boolean | null;
  /** The agent's own https endpoint. Setting one the first time returns its signing secret once. */
  webhook_url?: string | null;
}

export interface WakeSettings {
  /** Null for the customer's default. */
  agent_id: string | null;
  enabled: boolean;
  time_zone: string | null;
  quiet_start: string | null;
  quiet_end: string | null;
  quiet_mode: WakeQuietMode | null;
  rate_limit_max: number | null;
  rate_limit_window_seconds: number | null;
  delivery: WakeChannel[] | null;
  invite_lead_minutes: number | null;
  ring_incoming_calls: boolean | null;
  webhook_url: string | null;
  webhook_secret_set: boolean;
  webhook_secret_rotated_at: string | null;
  updated_at: string | null;
}

/** What is in force for an agent: its own settings over the customer's default over STACK's. */
export interface EffectiveWakeSettings {
  enabled: boolean;
  time_zone: string;
  quiet_start: string | null;
  quiet_end: string | null;
  quiet_mode: WakeQuietMode;
  /** The customer's own limit on events in a window; null (the start) means none. */
  rate_limit_max: number | null;
  rate_limit_window_seconds: number;
  delivery: WakeChannel[];
  invite_lead_minutes: number;
  ring_incoming_calls: boolean;
  webhook_configured: boolean;
}

export interface WakeSettingsResult {
  settings: WakeSettings;
  effective: EffectiveWakeSettings;
  /** Set only when a webhook endpoint was created or its secret rotated, and only to an API key or a session. Shown once. */
  webhook_secret: string | null;
  /** Says where to read the secret when it was not returned (an OAuth sign-in never receives it). */
  secret_note: string | null;
}

export interface WakeRuleInput {
  name: string;
  source: WakeSource;
  filters?: WakeFilters;
  /** Your own words for the agent. Left out: STACK's plain default for the source. Never mixed with the event's content. */
  task?: string | null;
  enabled?: boolean;
}

export interface WakeRule {
  id: string;
  /** Null for the customer's default rules. */
  agent_id: string | null;
  name: string;
  source: WakeSource;
  filters: WakeFilters;
  task: string | null;
  enabled: boolean;
  position: number;
  created_at: string;
  updated_at: string;
}

export interface WakeScheduleInput {
  name: string;
  /** Five fields (minute hour day-of-month month day-of-week) or @hourly, @daily, @weekly, @monthly. No more often than every 5 minutes. */
  cron: string;
  /** An IANA zone; left out, the agent's own time zone. */
  time_zone?: string | null;
  task: string;
  enabled?: boolean;
}

export interface WakeSchedule {
  id: string;
  /** The agent's account; null for an agent with no account. */
  account_id: string | null;
  agent_id: string;
  name: string;
  cron: string;
  time_zone: string | null;
  effective_time_zone: string;
  task: string;
  enabled: boolean;
  next_fire_at: string | null;
  last_fire_at: string | null;
  created_at: string;
  updated_at: string;
}

/** Facts about the event, never its content. */
/** One event of a bundled wake: where it came from, what kind it was and the ids it carries. Never content. */
export interface WakeBundledEvent {
  source: WakeSource;
  kind: string | null;
  ids: Record<string, string>;
  occurred_at: string;
}

/**
 * What a bundled wake says of the events it stands for. Events close together become one wake: while a wake waits to be
 * delivered, or within 60 seconds of the last one delivered to the agent, a new event joins one bundled wake. Nothing is
 * dropped. An incoming call is never bundled.
 */
export interface WakeBundle {
  count: number;
  by_source: Record<string, number>;
  events: WakeBundledEvent[];
  /** Events counted but not listed, past the most a bundle lists (500). */
  omitted: number;
}

export interface WakeEvent {
  /** Set when the wake stands for several events: each one, and the count by source. */
  bundled?: WakeBundle;
  message_id?: string;
  channel?: string;
  /** `incoming_call`: the call to answer or decline, and when the ring runs out and it goes to voicemail. */
  call_id?: string;
  answer_by?: string;
  amount_cents?: number;
  currency?: string;
  rail?: string;
  /** A calendar event starting: the event, which occurrence (as the agenda names it) and its start. */
  event_id?: string;
  occurrence?: string;
  starts_at?: string;
  /** `handoff`: the drop-off to collect, the agent that left it, and how many agents it names. */
  dropoff_id?: string;
  from_agent_id?: string;
  recipient_count?: number;
  schedule_id?: string;
  fire_at?: string;
  flagged?: boolean;
  /** `decision`: the pending item, which one, and how it ended (approved, rejected, expired, collected and the rest). */
  item_kind?: DecisionItemKind;
  item_id?: string;
  result?: string;
  /** `service_event`: the connected service that told STACK (`rentahuman`), the kind of event (`application.submitted`, `message.received`, ...) and the ids it names (`bounty_id`, `application_id`, `conversation_id`, ...). Never what a person wrote: read it through the connection (`proxy.serviceCallTool`). */
  service?: string;
  event_type?: string;
  ids?: Record<string, string>;
  [key: string]: unknown;
}

export interface Wake {
  id: string;
  /** The agent's account; null for an agent with no account. */
  account_id: string | null;
  agent_id: string;
  mission_id: string | null;
  source: WakeSource;
  /** Your words, or STACK's default. Never text from the event. */
  task: string;
  rule_id: string | null;
  schedule_id: string | null;
  event: WakeEvent;
  /** For a wake that names a message or a call: STACK's checks of who wrote or is calling. Absent when there are none to say. */
  sender_tags?: AccountSenderTag[];
  sender_resembles?: string | null;
  occurred_at: string;
  status: WakeStatus;
  held_for_quiet: boolean;
  not_before: string;
  attempts: number;
  delivered_via: WakeChannel | null;
  delivered_at: string | null;
  acknowledged_at: string | null;
  refusal_code: string | null;
  last_error_code: string | null;
  created_at: string;
}

export interface ListWakesQuery {
  /** `open` is the agent's queue: delivered and not yet acknowledged, oldest first. `expired` includes a queue wake nobody acknowledged in 30 days. */
  status?: WakeStatus | 'open';
  limit?: number;
  cursor?: string;
}

export interface ListWakesResult {
  wakes: Wake[];
  next_cursor: string | null;
  rate: { window_seconds: number; limit: number | null; accepted: number; dropped: number; window_ends_at: string };
}

export interface WakeWebhookTestResult {
  delivered: boolean;
  /** Why not, as a short code (`http_503`, `timeout`, `unsafe_address`). */
  code: string | null;
}

const seg = encodeURIComponent;

export class WakesService {
  constructor(private readonly client: HttpClient) {}

  // ─── The agent's queue ───────────────────────────────────────────

  /** The agent's wakes, newest first; `status: 'open'` is the agent's queue, oldest first. Any agent of the customer, with or without an account. */
  async list(agentId: string, query: ListWakesQuery = {}, options?: AccountAgentCallOptions): Promise<ListWakesResult> {
    return this.client.get<ListWakesResult>(`/v1/agents/${seg(agentId)}/wakes`, {
      status: query.status,
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      cursor: query.cursor,
    }, passport(options));
  }

  async get(agentId: string, wakeId: string, options?: AccountAgentCallOptions): Promise<Wake> {
    return this.client.get<Wake>(`/v1/agents/${seg(agentId)}/wakes/${seg(wakeId)}`, undefined, passport(options));
  }

  /** The agent has picked the wake up. Only a delivered wake of its own; saying it twice is fine. */
  async acknowledge(agentId: string, wakeId: string, options?: AccountAgentCallOptions): Promise<Wake> {
    return this.client.post<Wake>(`/v1/agents/${seg(agentId)}/wakes/${seg(wakeId)}/acknowledge`, undefined, passport(options));
  }

  // ─── Settings (owner or admin) ───────────────────────────────────

  /** One agent's settings and what is in force; without an agent, the customer's default. */
  async getSettings(agentId?: string): Promise<WakeSettingsResult> {
    return this.client.get<WakeSettingsResult>(settingsPath(agentId));
  }

  /**
   * Change settings, for one agent or (without an agent) the customer's default. The first time a webhook
   * address is set, the signing secret comes back once as `webhook_secret`.
   */
  async setSettings(input: WakeSettingsInput, agentId?: string): Promise<WakeSettingsResult> {
    return this.client.put<WakeSettingsResult>(settingsPath(agentId), input);
  }

  /** A new webhook signing secret, shown once; the old one keeps verifying for 24 hours. */
  async rotateWebhookSecret(agentId: string): Promise<WakeSettingsResult> {
    return this.client.post<WakeSettingsResult>(`/v1/agents/${seg(agentId)}/wake/webhook/rotate-secret`);
  }

  /** Send a signed test to the agent's webhook, to see that it answers. Nothing is waking the agent. */
  async testWebhook(agentId: string): Promise<WakeWebhookTestResult> {
    return this.client.post<WakeWebhookTestResult>(`/v1/agents/${seg(agentId)}/wake/webhook/test`);
  }

  // ─── Rules (owner or admin) ──────────────────────────────────────

  /** One agent's own rules; without an agent, the customer's default rules. */
  async listRules(agentId?: string): Promise<{ rules: WakeRule[] }> {
    return this.client.get<{ rules: WakeRule[] }>(rulesPath(agentId));
  }

  async createRule(input: WakeRuleInput, agentId?: string): Promise<WakeRule> {
    return this.client.post<WakeRule>(rulesPath(agentId), input);
  }

  async updateRule(ruleId: string, input: WakeRuleInput): Promise<WakeRule> {
    return this.client.put<WakeRule>(`/v1/wake/rules/${seg(ruleId)}`, input);
  }

  async deleteRule(ruleId: string): Promise<void> {
    await this.client.delete<void>(`/v1/wake/rules/${seg(ruleId)}`);
  }

  // ─── Schedules (owner or admin) ──────────────────────────────────

  async listSchedules(agentId: string): Promise<{ schedules: WakeSchedule[] }> {
    return this.client.get<{ schedules: WakeSchedule[] }>(`/v1/agents/${seg(agentId)}/wake/schedules`);
  }

  async createSchedule(agentId: string, input: WakeScheduleInput): Promise<WakeSchedule> {
    return this.client.post<WakeSchedule>(`/v1/agents/${seg(agentId)}/wake/schedules`, input);
  }

  async updateSchedule(agentId: string, scheduleId: string, input: WakeScheduleInput): Promise<WakeSchedule> {
    return this.client.put<WakeSchedule>(`/v1/agents/${seg(agentId)}/wake/schedules/${seg(scheduleId)}`, input);
  }

  async deleteSchedule(agentId: string, scheduleId: string): Promise<void> {
    await this.client.delete<void>(`/v1/agents/${seg(agentId)}/wake/schedules/${seg(scheduleId)}`);
  }
}

function settingsPath(agentId?: string): string {
  return agentId ? `/v1/agents/${seg(agentId)}/wake/settings` : '/v1/wake/settings';
}

function rulesPath(agentId?: string): string {
  return agentId ? `/v1/agents/${seg(agentId)}/wake/rules` : '/v1/wake/rules';
}

function passport(options?: AccountAgentCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}
