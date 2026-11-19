import type { HttpClient } from '../client.js';
import type { DriveFileContent } from './drive.js';
import { MakingService } from './making.js';
import { assertPayableUrl, payX402, x402WalletOf, type PayX402Options, type X402Result } from '../x402-pay.js';

// Agent accounts: one call opens an agent with every piece it needs (passport,
// inbox, phone, models, tools, workspace, browser, card, wallet), and one call
// closes it.
//
// Opening needs no approval: the owner's API key, OAuth token or dashboard
// session opens it at once, and a retry with the same input and the same
// `idempotencyKey` returns the same account. A monthly budget is optional and
// needs controls (`BUDGET_NEEDS_CONTROLS` otherwise); without one, prepaid
// credit is the limit. Sends, workspace commands, browser actions and wallet
// payments made by the account's agent run under its Passport's Mission.

export type AccountPieceKind =
  | 'passport' | 'inbox' | 'phone' | 'models' | 'tools' | 'sandbox' | 'browser' | 'card' | 'wallet' | 'making' | 'workspace';
export type AccountPieceState = 'pending' | 'ready' | 'paused' | 'failed' | 'closing' | 'closed';
export type AgentAccountStatus = 'opening' | 'open' | 'suspended' | 'frozen' | 'closing' | 'closed';
export type AccountMessageChannel = 'email' | 'sms' | 'voicemail' | 'call' | 'telegram' | 'post' | 'meeting';

export interface OpenAgentAccountInput {
  name: string;
  description?: string;
  /** Optional per-agent limit, USD cents, 100 to 10,000,000. Needs controls. */
  monthly_budget_cents?: number;
  /** A US number with no `area_code` is toll-free; an `area_code` or `number_type: 'local'` gets a local number. Canadian numbers are local. */
  phone?: { country: 'US' | 'CA'; area_code?: string; number_type?: 'local' | 'toll_free' };
  /** `agent_public_key` is `generateAgentWalletKey().publicKey`; the private half stays with you. */
  /**
   * Caps are optional and a controls feature: with none, or without controls, the wallet's own USDC balance is the limit.
   * STACK sets no maximum. Set or change them later with `accounts.wallet.setCaps`.
   */
  wallet?: { agent_public_key: string; per_payment_cap_usdc?: number; daily_cap_usdc?: number };
  /** The inbox on one of your own verified mail domains instead of the shared agent domain. */
  inbox?: { domain: string };
  /** Pieces not wanted. Passport, models and tools always open. */
  skip?: Array<'inbox' | 'phone' | 'browser' | 'card' | 'wallet' | 'making' | 'workspace'>;
}

export interface OpenAgentAccountOptions {
  /** 8 to 128 characters. Reuse it, with the same input, for every retry of this open. */
  idempotencyKey: string;
  /** Sent as `X-Governance-Approval`. Opening no longer asks for one; kept for older callers. */
  governanceApprovalId?: string;
}

export interface AgentAccountPiece {
  kind: AccountPieceKind;
  state: AccountPieceState;
  provider: string;
  details: Record<string, unknown>;
  error_code: string | null;
  /** Why a paused piece is paused: `unpaid` (its monthly charge), a reputation pause, a provider spend cap. */
  pause_reason: string | null;
  ready_at: string | null;
}

export interface AgentAccount {
  id: string;
  agent_id: string;
  mission_id: string | null;
  status: AgentAccountStatus;
  /** Why a suspended account is suspended: its owner's platform subscription lapsed. */
  suspend_reason: 'platform_lapsed' | null;
  /** Null when the account has no per-agent budget. */
  monthly_budget_cents: number | null;
  /** `limit_cents` is null with no budget; spend is still recorded. */
  budget: { period_start: string; limit_cents: number | null; reserved_cents: number; settled_cents: number };
  pieces: AgentAccountPiece[];
  created_at: string;
  closed_at: string | null;
}

/**
 * An attachment of a message. `file_id` is the drive file that holds it (the receiving agent sees it like a file it
 * uploaded; untrusted like every drive file). `not_saved` is why an attachment that arrived is not in the drive:
 * `too_large`, `unavailable`, `drive_read_only`, `waiting` (STACK is still saving it and tries for 30 days)
 * or `withheld`; the email is kept either way. A received file goes with its message when it is deleted,
 * unless its end is changed (`drive.update`).
 */
export interface AccountMessageAttachment {
  filename: string | null;
  content_type: string | null;
  size_bytes: number | null;
  file_id?: string | null;
  not_saved?: string | null;
}

export interface AccountMessage {
  id: string;
  account_id: string;
  channel: AccountMessageChannel;
  direction: 'inbound' | 'outbound';
  /** `delivered` carries content; `withheld` carries only the notice. */
  status: 'delivered' | 'withheld';
  received_at: string;
  read_at: string | null;
  content: {
    from: string;
    to: string[];
    cc: string[];
    /** On an email the account sent. A message that arrived never shows any. */
    bcc?: string[];
    /** The mail provider's thread of an email: `replyEmail` answers in it. */
    thread_id?: string | null;
    subject: string | null;
    body_text: string;
    attachments: AccountMessageAttachment[];
    truncated: boolean;
    details: Record<string, string>;
  } | null;
  withheld: { verdict: 'flagged' | 'blocked'; security_event_id: string | null; reason: string } | null;
  /** Set on a delivered message that matched a prompt-injection pattern while the owner's controls were off. */
  flag: { severity: 'warning' | 'critical'; security_event_id: string | null; reason: string } | null;
}

/** On content delivered although it matched a prompt-injection pattern (controls off). */
export interface ContentFlag {
  security_event_id: string | null;
  message: string;
}

export interface ListAccountMessagesQuery {
  /** 1 to 100, default 25. */
  limit?: number;
  /** `next_cursor` of the previous page. */
  cursor?: string;
  channel?: AccountMessageChannel;
}

export interface ListAccountMessagesResult {
  messages: AccountMessage[];
  next_cursor: string | null;
}

/**
 * What `accounts.messages.search` filters on. Every filter is optional and they all apply together. Datetimes are ISO 8601
 * with an offset (`2026-11-01T00:00:00Z`). The window is the last 30 days unless `after` and `before` say otherwise; a search
 * on `q`, `sender`, `recipient` or `threadId` needs a window of at most 90 days (400 otherwise).
 */
export interface SearchAccountMessagesQuery {
  /** Only the messages of this agent. */
  agentId?: string;
  channel?: AccountMessageChannel;
  /** The address or number the message came from. */
  sender?: string;
  /** An address or number the message went to. */
  recipient?: string;
  /** The mail provider's thread of an email. */
  threadId?: string;
  after?: string;
  before?: string;
  /** Text to find in the subject and the body. */
  q?: string;
  /** 1 to 50, default 25. */
  limit?: number;
  /** `next_cursor` of the previous page. */
  cursor?: string;
}

/** A message in a search: the summary of one message, without its body (read it with `accounts.messages.get`). */
export interface AccountMessageSearchHit {
  id: string;
  account_id: string;
  agent_id: string | null;
  channel: AccountMessageChannel;
  direction: 'inbound' | 'outbound';
  /** `delivered` carries content; `withheld` is held back by a security check. */
  status: 'delivered' | 'withheld';
  from: string;
  to: string[];
  subject: string | null;
  received_at: string;
  thread_id: string | null;
  attachments: AccountMessageAttachment[];
}

export interface SearchAccountMessagesResult {
  messages: AccountMessageSearchHit[];
  next_cursor: string | null;
  /** The window that was searched. */
  window: { after: string; before: string };
}

/**
 * A file attached to an email: one of the agent's drive files by its id (`filename` renames it in this email only), or
 * a small file sent inline as base64 (up to 10 MB in all). Together the attachments are at most 25 MB, which is the
 * mail provider's limit.
 */
export type SendAccountEmailAttachment =
  | { file_id: string; filename?: string }
  | { filename: string; content_type: string; content_base64: string };

export interface SendAccountEmailInput {
  /**
   * One address or a list. The mail provider takes one To address: the first is the message's To and any further ones
   * are delivered as Cc (the answer's `cc` shows where each went). Required: `cc` or `bcc` alone is refused.
   */
  to: string | string[];
  cc?: string[];
  /** Blind copies: delivered, and shown to nobody else. */
  bcc?: string[];
  /** Required unless `thread_id` is set. One line: line breaks are refused. */
  subject?: string;
  body: string;
  body_html?: string;
  /** To answer an email the account received, use `replyEmail`. */
  thread_id?: string;
  attachments?: SendAccountEmailAttachment[];
  /**
   * The received message (`amsg_...`) this email answers. Needed when the policy sets the account's email recipients to
   * `per_mission`: the email then goes only to whoever wrote that message. Any other id is 404.
   */
  reply_to_message?: string;
}

/**
 * An answer to an email the account received. It goes in that email's thread to the person who wrote it (every address
 * its From names, when it names several), or with `reply_all` to everyone else it was sent to as well.
 */
export interface ReplyAccountEmailInput {
  body: string;
  body_html?: string;
  reply_all?: boolean;
  cc?: string[];
  bcc?: string[];
  /** Replaces the thread's own subject. */
  subject?: string;
  attachments?: SendAccountEmailAttachment[];
  /** The answered email is quoted under your words unless this is `false`. */
  include_quote?: boolean;
}

/** An email the account received, sent on to others as a new email (no thread) with "Fwd:" before its subject. */
export interface ForwardAccountEmailInput {
  to: string | string[];
  cc?: string[];
  bcc?: string[];
  /** Your own words above the forwarded message. */
  body?: string;
  /** The original's attachments are sent too unless this is `false`. */
  include_attachments?: boolean;
  /** More files beside the original's. */
  attachments?: SendAccountEmailAttachment[];
  /** The original's text and headers are carried under your words unless this is `false`. */
  include_quote?: boolean;
}

export interface SendAccountSmsInput {
  /** E.164, e.g. +14155550123: any country Twilio can reach from the account's number. */
  to: string;
  body: string;
  /**
   * The received message (`amsg_...`) this text answers. Needed when the policy sets the account's text recipients to
   * `per_mission`: the text then goes only to whoever wrote that message. Any other id is 404.
   */
  reply_to_message?: string;
}

export interface SendAccountTelegramInput {
  /** A chat that wrote to the agent's bot first (its id is in the received message's `details.chat_id`): a bot cannot message a chat first. */
  chat_id: string;
  /** Up to 4,096 characters. */
  text: string;
}

export interface TelegramBot {
  bot_id: string;
  account_id: string;
  /** The bot's @username, so people can find it. */
  username: string;
  status: 'active' | 'closed';
  created_at: string;
  /** Where a person starts a chat with the bot. */
  start_url: string;
}

/** The link the account's owner opens in Telegram to have the agent's bot made (Telegram's Managed Bots). */
export interface ManagedTelegramBotRequest {
  request_id: string;
  account_id: string;
  /** Open this in Telegram and confirm: only that confirmation creates the bot. Single-use. */
  create_url: string;
  /** The username the link suggests; the owner must keep it, it ties their confirmation to this request. */
  suggested_username: string;
  expires_at: string;
}

export interface TelegramChat {
  chat_id: string;
  chat_type: 'private' | 'group' | 'supergroup';
  label: string;
  first_seen_at: string;
  last_inbound_at: string;
  /** Telegram refused a message to it (blocked or removed); it can write again to unblock it. */
  blocked: boolean;
}

export interface AccountMessageSent {
  message_id: string;
  channel: 'email' | 'sms' | 'telegram';
  provider_message_id: string;
  thread_id: string | null;
  status: string;
}

/** The answer of an email send, reply or forward: who it went to and what it carried. */
export interface AccountEmailSent extends AccountMessageSent {
  channel: 'email';
  /** One address: a further To address of the request is in `cc`. */
  to: string[];
  cc: string[];
  bcc: string[];
  /** `file_id` is the drive file the attachment was read from, or null for an inline one. */
  attachments: Array<{ filename: string; content_type: string; size_bytes: number; file_id: string | null }>;
  /**
   * Addresses left out, each as it was given and why: `not_an_address` (an entry of a received message that is not one
   * plain address). Absent when nothing was left out.
   */
  dropped?: Array<{ value: string; reason: 'not_an_address' }>;
}

export type WorkspaceState = 'starting' | 'running' | 'pausing' | 'paused' | 'deleting' | 'deleted' | 'failed';

/** A command to run in the account's workspace. */
export interface WorkspaceExecInput {
  /** The workspace to run in. Leave it out to make a new one. */
  workspace_id?: string;
  command: string;
  /** Working directory inside the workspace. */
  cwd?: string;
  /** Variables for this command only, at most 32. Names starting with STACK_ are set by STACK. Values are never recorded. */
  env?: Record<string, string>;
  /** Seconds the command may run while you wait for it; the default is 120 and STACK sets no longest. Not with `background`. */
  timeout_seconds?: number;
  /** Start the command and get a `command_id` at once; read it later with `workspaces.command`. It has no timeout and runs until it ends. Not with `timeout_seconds` or `stack_access`. */
  background?: boolean;
  /** Give the command a short-lived Passport of the agent (STACK_PASSPORT, STACK_API_URL) so code in the workspace reaches your connected services through STACK's proxy. Off by default; revoked when the command ends. */
  stack_access?: boolean;
}

export interface WorkspaceReadFileInput { path: string }

/**
 * Exactly one of `content_text` and `content_base64`, at most 1 MB. `mode` is octal permission bits (such as "755")
 * set on the file once it is written; the write fails if they cannot be set.
 */
export type WorkspaceWriteFileInput =
  | { path: string; content_text: string; content_base64?: never; mode?: string }
  | { path: string; content_base64: string; content_text?: never; mode?: string };

export interface WorkspaceSaveFileInput {
  path: string;
  /** The drive file's name; defaults to the file's own. */
  name?: string;
  /** The drive's media type; defaults to the one the extension says. */
  content_type?: string;
  /** `agent` (default): private to this agent. `account`: every agent of the account. */
  visibility?: 'agent' | 'account';
}

export interface WorkspaceStopInput {
  /** Delete the workspace and its files. Without it the workspace is paused and keeps its files. */
  delete?: boolean;
}

/**
 * The customer's workspace settings. Each field left out stays; `null` clears it so the agent account inherits the
 * customer's default (and the default, cleared, is STACK's). What is not a setting is the money hold: a machine is never
 * billed beyond what is held for it, so a machine with no idle pause runs until its hold is used and is then paused.
 */
export interface WorkspaceSettingsInput {
  /** Minutes with no action before a running workspace is paused: 5 or more, or 0 for no idle pause */
  idle_pause_minutes?: number | null;
  /** Days a stopped workspace is kept before it is deleted: 1 or more, or 0 to keep it until it is deleted by hand. A stopped workspace's disk storage is charged to the account until it is deleted. */
  delete_after_days?: number | null;
  /** Workspaces an agent account may have that are not deleted: per agent account, any number from 1. */
  max_workspaces?: number | null;
}

/** One scope's own settings: what was set at this level, null where it inherits. */
export interface WorkspaceSettings {
  /** Null for the customer's default. */
  agent_id: string | null;
  idle_pause_minutes: number | null;
  delete_after_days: number | null;
  max_workspaces: number | null;
  updated_at: string | null;
}

/** What is in force for an agent account: its own over the customer's default over STACK's, within the plan. */
export interface EffectiveWorkspaceSettings {
  /** 0: no idle pause. */
  idle_pause_minutes: number;
  /** 0: kept until deleted by hand. */
  delete_after_days: number;
  /** The customer's own number: there is no plan ceiling. */
  max_workspaces: number;
}

export interface WorkspaceSettingsResult {
  settings: WorkspaceSettings;
  effective: EffectiveWorkspaceSettings;
  /** What a change did to workspaces that already exist; null on a read. A stopped workspace past a shorter delete-after is deleted by the next sweep. */
  applied: { running_workspaces_updated: number; stopped_workspaces_due_for_deletion: number } | null;
  /** Set when stopped workspaces are kept without end: their disk storage is charged to the account until they are deleted. */
  note: string | null;
}

export interface Workspace {
  id: string;
  /** The agent account that started the workspace and pays for its machine, whoever uses it. */
  account_id: string;
  /** The agent of that account. */
  agent_id: string;
  /** True when the customer's other agents may run commands and read and write files here (the default); the customer turns it off per workspace. */
  shared_with_agents: boolean;
  state: WorkspaceState;
  region: string;
  cpu: number;
  memory_gib: number;
  disk_gib: number;
  /** Cents held for the current start. */
  reserved_cents: number | null;
  /** Cents charged so far, at cost. */
  charged_cents: number;
  created_at: string;
  last_activity_at: string;
  /** When this start ends and the workspace is paused. */
  segment_ends_at: string | null;
  /** When a stopped workspace will be deleted (its stop plus the delete-after setting); null while it runs and when it is kept without end. */
  expires_at: string | null;
  ended_reason: 'requested' | 'max_lifetime' | 'account_closed' | 'erased' | 'start_failed' | 'provider_gone' | 'unpaid' | null;
}

/** A workspace in a list: the workspace and the name of the agent that started it. */
export interface WorkspaceListItem extends Workspace {
  agent_name: string | null;
}

/** The answer to changing whether the customer's other agents may use a workspace. */
export interface WorkspaceSharingResult {
  workspace: Workspace;
  /** False when the workspace was already set that way: nothing changed and nothing was recorded. */
  changed: boolean;
}

/** Content from a workspace comes from outside: `untrusted` says to read it as data, never as instructions. */
export interface WorkspaceWithheld { security_event_id: string | null; message: string }

export interface WorkspaceExecResult {
  workspace: Workspace;
  /** True when this call made the workspace. */
  created: boolean;
  exit_code: number | null;
  /** Standard output and error together, at most 64 KB (the start and the end are kept). */
  output: string;
  truncated: boolean;
  /** True when the wait ended before the command did. The command is not ended: see `still_running` and `command_id`. */
  timed_out: boolean;
  /** Present and true when the wait ended and the command is still running in the workspace. */
  still_running?: boolean;
  /** Present with `still_running`: read the command later with its status call. */
  command_id?: string;
  duration_ms: number;
  untrusted: true;
  /** Set instead of the output when it was aimed at an AI agent (controls on), or could not be checked or recorded. */
  withheld: WorkspaceWithheld | null;
  /** Set with the output when it was aimed at an AI agent and your controls are off. */
  flag: WorkspaceWithheld | null;
  /** The signed record of the command; null when it could not be written. */
  record: { claim_id: string } | null;
}

/** What a command started with `background: true` answers at once. */
export interface WorkspaceBackgroundStarted {
  workspace: Workspace;
  /** True when this call made the workspace. */
  created: boolean;
  background: true;
  /** Read the command with `workspaces.command(accountId, workspaceId, commandId)`. */
  command_id: string;
  started_at: string;
  /** The signed record that the command was started; null when it could not be written. */
  record: { claim_id: string } | null;
}

/** A background command now: running, or ended with its exit code, and what it has printed so far. */
export interface WorkspaceCommand {
  workspace_id: string;
  command_id: string;
  status: 'running' | 'succeeded' | 'failed';
  /** Null while it runs. */
  exit_code: number | null;
  /** Standard output and error together, at most 64 KB (the start and the end are kept). */
  output: string;
  truncated: boolean;
  untrusted: true;
  withheld: WorkspaceWithheld | null;
  flag: WorkspaceWithheld | null;
  record: null;
}

export interface WorkspaceFile {
  workspace_id: string;
  path: string;
  size_bytes: number;
  /** UTF-8 text, or null when the bytes are not text (then `content_base64`). */
  content_text: string | null;
  content_base64: string | null;
  untrusted: true;
  withheld: WorkspaceWithheld | null;
  flag: WorkspaceWithheld | null;
  record: { claim_id: string } | null;
}

export interface WorkspaceFileWritten {
  workspace_id: string;
  path: string;
  size_bytes: number;
  sha256: string;
  record: { claim_id: string } | null;
}

export interface WorkspaceFileSaved {
  workspace_id: string;
  path: string;
  /** The drive file the bytes were saved as. */
  drive_file_id: string;
  name: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  record: { claim_id: string } | null;
}

export interface WorkspaceStopped {
  workspace: Workspace;
  /** Cents the start that ended was settled for. */
  charged_cents: number;
  record: { claim_id: string } | null;
}

/** An element by accessible role and name, visible text, label or CSS selector. */
export type BrowserTarget =
  | { role: string; name?: string; exact?: boolean }
  | { text: string; exact?: boolean }
  | { label: string; exact?: boolean }
  | { selector: string };

export type BrowserAction =
  | { action: 'click'; target: BrowserTarget }
  | { action: 'type'; target: BrowserTarget; value: string; sensitive?: boolean }
  | { action: 'select'; target: BrowserTarget; value: string | string[] }
  | { action: 'press'; key: string; target?: BrowserTarget };

export interface BrowserSession {
  session_id: string;
  state: 'active';
  max_minutes: number;
  expires_at: string;
  reserved_cents: number;
}

export type BrowserReading =
  | { withheld: false; url: string; title: string; text: string; accessibility: string; truncated: boolean; flag: ContentFlag | null }
  | { withheld: true; url: string; security_event_id: string; message: string };

export interface BrowserCheckoutInput {
  /** The exact https origin of the checkout page. */
  merchant_origin: string;
  /** The total the page shows, in the currency's smallest unit. */
  amount_minor: number;
  /** ISO 4217. */
  currency: string;
}

export interface BrowserCheckout {
  purchase_id: string;
  state: 'reserved';
  reserved_cents: number;
  /** A test number for the stored card's network, never a real card. */
  placeholder_card: { number: string; security_code: string; expiry_month: string; expiry_year: string; brand: string };
  next: string;
}

export interface CardPurchase {
  purchase_id: string;
  state: string;
  status: string;
  user_action?: string;
  outcome: string | null;
  merchant_origin: string;
  amount_minor: number;
  currency: string;
  created_at: string;
}

export type PurchaseMerchantResult =
  | { status: 'completed'; order_id: string }
  | { status: 'failed' }
  | { status: 'pending' }
  | { status: 'requires_user_action'; reason: '3ds' | 'redirect' | 'other' };

/** The body `signWalletPayment` returns. */
export interface WalletPaymentInput {
  typed_data: Record<string, unknown>;
  agent_signature: string;
}

export interface WalletPayment {
  payment_id: string;
  payload_hash: string;
  /** The wallet's EIP-712 signature: the x402 payment authorization. */
  signature: string;
  from: string;
  to: string;
  amount_atomic: string;
  amount_cents: number;
  valid_before: string;
}

/** The voice a call speaks in. Each is optional; none set means Twilio's default voice and en-US. STACK keeps no list. */
export interface AccountCallVoice {
  /** A text-to-speech provider Twilio's ConversationRelay documents. */
  tts_provider?: 'Google' | 'Amazon' | 'ElevenLabs';
  /** Any voice name the provider takes. */
  voice?: string;
  /** BCP-47, for example `fr-FR`. */
  language?: string;
}

/** The account's own call voice and voicemail greeting, as read. */
export interface AccountCallVoiceSetting {
  tts_provider: 'Google' | 'Amazon' | 'ElevenLabs' | null;
  voice: string | null;
  language: string | null;
  /** What a caller hears before the beep when a call goes to voicemail. Null: only the beep. */
  voicemail_greeting: string | null;
}

/**
 * Placing a call. Without `brief` the agent holds the call itself (STACK runs no model and says nothing: the call opens
 * with `greeting` or with silence, and the agent speaks with `say` or over `live`). With `on_behalf_of` and `brief`, STACK's
 * model holds the call, opening with STACK's line that the other side is speaking with an AI on behalf of `on_behalf_of`.
 */
export interface StartAccountCallInput {
  /** E.164, any country Twilio can reach from the account's number. */
  to: string;
  /** From 30 to 14400 seconds (Twilio's own limit, and the default when omitted). A call is paid for 10 minutes at a time. */
  max_seconds?: number;
  /** The voice of this call; it wins over the account's. */
  voice?: AccountCallVoice;
  /** greeting is spoken only when your agent runs the call; on a call STACK holds, STACK opens with its own line. Words spoken first; left out, nothing is spoken until the other side speaks. */
  greeting?: string;
  /** wait_seconds applies only when your agent runs the call: how long to wait for the other side's first finished sentence (0 to 60 seconds, default 30). Ignored on a call STACK holds. */
  wait_seconds?: number;
  /** A call STACK holds: who it is for, a plain name of up to 60 characters. Given with `brief`. */
  on_behalf_of?: string;
  /** A call STACK holds: what the call is for and what to know, in the agent's own words. Given with `on_behalf_of`. */
  brief?: string;
  /**
   * The received message (`amsg_...`) this call answers. Needed when the policy sets the account's call recipients to
   * `per_mission`: the call then goes only to whoever wrote that message. Any other id is 404.
   */
  reply_to_message?: string;
}

/** Answering a call that rings on the account's number: the same as placing one, without a number to dial. */
export type AnswerAccountCallInput = Omit<StartAccountCallInput, 'to' | 'reply_to_message'>;

/** `ringing` is also an incoming call that the agent can still answer or decline. */
export type AccountCallState = 'queued' | 'ringing' | 'in_progress' | 'completed' | 'failed' | 'refused';
export type AccountCallEndReason =
  | 'agent_hung_up' | 'goal_complete' | 'caller_hung_up' | 'max_duration' | 'revoked' | 'injection' | 'budget_exhausted'
  | 'model_unavailable' | 'no_speech' | 'repeating' | 'voicemail' | 'declined' | 'busy' | 'no_answer' | 'canceled' | 'failed';

/** What an incoming call became: the agent answered it, declined it, or it went to voicemail. */
export type AccountCallDecision = 'answered' | 'declined' | 'voicemail';

/**
 * STACK's own checks of who is writing or calling, worked out when it arrived. A tag warns and never blocks.
 */
export type AccountSenderTag =
  | 'new_sender' | 'new_domain' | 'lookalike_domain' | 'name_matches_known_contact'
  | 'payment_details' | 'organizer_not_sender' | 'unverified_sender';

/** Something STACK recorded about a call on its row. `paid_time_ends`: the next 10 minutes cannot be held, so the call ends at `ends_at`. */
export interface AccountCallEvent {
  at: string;
  type: 'paid_time_ends' | 'no_speech' | 'repeating' | 'do_not_call';
  message: string;
  ends_at?: string;
}

/** A flag on something heard: the detectors found it suspicious. */
export interface AccountCallFlag {
  severity: 'warning' | 'critical';
  security_event_id: string | null;
}

/** What happens on a live call, as the agent hears it, numbered from 1 in the order it happened. */
export type AccountCallLiveEvent =
  | { seq: number; at: string; type: 'heard'; text?: string; withheld?: boolean; flag?: AccountCallFlag }
  | { seq: number; at: string; type: 'keys'; digits: string }
  | { seq: number; at: string; type: 'interrupted'; heard_of_agent: string }
  | { seq: number; at: string; type: 'paid_time_ends'; in_seconds: number }
  | { seq: number; at: string; type: 'ended'; reason: AccountCallEndReason };

/** One line of a call's live transcript. A line the owner's controls withhold has no text. */
export interface AccountCallLine {
  at: string;
  speaker: 'agent' | 'caller';
  text?: string;
  withheld?: boolean;
  flag?: AccountCallFlag;
  /** A switch of the language the call speaks and hears. */
  language?: string;
  scan?: 'unavailable';
}

export interface AccountCall {
  call_id: string;
  account_id: string;
  direction: 'inbound' | 'outbound';
  state: AccountCallState;
  max_seconds: number;
  duration_seconds: number | null;
  end_reason: AccountCallEndReason | null;
  charged_cents: number | null;
  created_at: string;
  started_at: string | null;
  ended_at: string | null;
  /**
   * An incoming call: null while it rings (and when the caller hangs up first), then `answered`, `declined` or
   * `voicemail` (the ring ran out, or the agent let it go). Null on a call the agent placed.
   */
  decision: AccountCallDecision | null;
  /** A ringing call: when the ring runs out and the call goes to voicemail. Null otherwise. */
  answer_by: string | null;
  /** A ringing call: the number calling. Anyone can fake it, so it does not prove who is calling. Null otherwise. */
  caller: string | null;
  /**
   * An incoming call: what the carrier vouches for the number with (STIR/SHAKEN): `A` it knows the caller and the number,
   * `B` it knows the caller, `C` it only carried the call. Null when it did not validate the number, and on a call the
   * agent placed. It says what the carrier checked, not who is calling.
   */
  caller_attestation: 'A' | 'B' | 'C' | null;
  /** An incoming call: STACK's checks of the caller's number, made when it rang. Null: not assessed. */
  sender_tags: AccountSenderTag[] | null;
  /** The known domain a `lookalike_domain` sender imitates. Null when no tag names one. */
  sender_resembles: string | null;
  /** True when STACK holds the call with its own model. */
  held_by_stack: boolean;
  events: AccountCallEvent[];
}

/** What a call action returns: the call, and every event on it since this caller's last call action on it. */
export interface AccountCallTurn {
  call: AccountCall;
  events: AccountCallLiveEvent[];
}

/** One call with its transcript: `lines` while it is on the line, then the stored message on the `call` channel. */
export interface AccountCallWithTranscript extends AccountCall {
  transcript: AccountMessage | null;
  lines: AccountCallLine[];
}

export interface ListAccountCallsQuery {
  /** 1 to 100, default 25. */
  limit?: number;
  /** `next_cursor` of the previous page. */
  cursor?: string;
}

export interface ListAccountCallsResult {
  calls: AccountCall[];
  next_cursor: string | null;
}

/** A tool read that screening flagged (with controls on) or could not check comes back withheld, with only the notice. */
export interface AccountToolWithheld {
  withheld: true;
  security_event_id: string | null;
  message: string;
}

export interface AccountToolSummary {
  provider: string;
  providerName: string | null;
  endpoint: string;
  description: string;
  score: number | null;
  tags: string[];
  price: { type: string; amount_usd: number | null } | null;
}

export type AccountToolDiscovery = { withheld: false; flag: ContentFlag | null; results: AccountToolSummary[] } | AccountToolWithheld;
export type AccountToolInspection = { withheld: false; flag: ContentFlag | null; endpoint: Record<string, unknown> } | AccountToolWithheld;

export interface AccountToolRunInput {
  /** The paid-tools provider's slug for the tool. */
  provider: string;
  /** The tool's endpoint path, such as /acme/search. */
  endpoint: string;
  /** The endpoint's input, at most 64 KiB serialised. */
  input?: Record<string, unknown>;
  /** The most results a PER_RESULT endpoint may return and charge for, 1 to 1000. */
  max_results?: number;
  /** A cap of your own: a run whose worst case would cost more cents than this is refused before anything is held. */
  max_cost_cents?: number;
}

/** One file a tool run produced. */
export interface ToolRunFile {
  name: string;
  content_type: string;
  size_bytes: number | null;
  /** The drive file it was saved to, when the account has a drive. */
  drive_file_id: string | null;
  /** Where the provider hosts it; provider links expire. */
  source_url: string | null;
  /** The bytes, base64, when the file is small and there is no drive to save it to. */
  data_base64: string | null;
}

/** A key an account signs its outbound requests with (Web Bot Auth). */
export interface AccountSigningKey {
  /** The JWK thumbprint: the `keyid` of its signatures and the `kid` in the directory. */
  key_id: string;
  /** The public key, base64url (the JWK `x`). */
  public_key: string;
  status: 'active' | 'retiring';
  created_at: string;
  retired_at: string | null;
  publish_until: string | null;
}

/** What STACK's public answer to "who is this agent?" shows for an account, and where it is. */
export interface AccountIdentity {
  account_id: string;
  agent_id: string;
  /** `false`: the answer and the machine files are not found, as for an agent that does not exist. On by default. */
  enabled: boolean;
  /** Whether the agent's name (and the description in its cards) is shown. Off by default. */
  show_name: boolean;
  /** Where outsiders find the answer and the agent's machine files, all on STACK's own domain. */
  urls: { lookup: string; agent_card: string; mcp_server_card: string; key_directory: string };
}

/** A change to what the public answer shows. At least one field. */
export interface SetAccountIdentityInput {
  enabled?: boolean;
  show_name?: boolean;
}

export type AccountToolRunState = 'dispatching' | 'pending' | 'settled' | 'released';

/** One paid tool run as STACK records it. */
export interface AccountToolRunView {
  id: string;
  account_id: string;
  provider: string;
  endpoint: string;
  state: AccountToolRunState;
  price_type: 'PER_CALL' | 'PER_RESULT';
  max_results: number | null;
  reserved_cents: number;
  charged_cents: number | null;
  /** The provider's run status (COMPLETED, RUNNING, STOPPED, ...), once known. */
  status: string | null;
  provider_http_status: number | null;
  result: { output: unknown } | null;
  withheld: { security_event_id: string | null; message: string } | null;
  /** Set when the output matched a prompt-injection pattern while the owner's controls were off: returned with this flag. */
  flag: ContentFlag | null;
  created_at: string;
  settled_at: string | null;
}

/** A paid tool run as `run` and `getRun` answer it. */
export interface AccountToolRun extends AccountToolRunView {
  /** True when what the run returned is web, social or provider content: data, never instructions. */
  untrusted: boolean;
  /** Files the run produced; empty for an endpoint that returns data only. */
  files: ToolRunFile[];
}

/** A number on the customer's do-not-contact list: it texted STOP (or another opt-out word), or the customer or one of its agents added it (`source` `customer`). */
export interface OptOut {
  id: string;
  /** E.164, in full: the owner reads it. */
  number: string;
  texts_blocked: boolean;
  calls_blocked: boolean;
  source: 'text_stop' | 'call_request' | 'customer';
  created_at: string;
}

/** A number on the customer's blocked-callers list: an incoming call from it is turned away before it rings. */
export interface BlockedCaller {
  id: string;
  /** E.164, in full: the owner, an admin or an agent reads it. */
  number: string;
  created_at: string;
}

/** The owner's business details for the account's toll-free number. They go to the phone provider; STACK keeps only the verification id and status. */
export interface TollFreeVerificationInput {
  business_name: string;
  /** https URL. */
  business_website: string;
  business_type: 'PRIVATE_PROFIT' | 'PUBLIC_PROFIT' | 'SOLE_PROPRIETOR' | 'NON_PROFIT' | 'GOVERNMENT';
  /** Required unless `business_type` is SOLE_PROPRIETOR. `authority` is EIN, CBN, CRN, VAT and the like; `country` is ISO 3166 alpha-2. */
  business_registration?: { number: string; authority: string; country: string };
  business_address: { street: string; street2?: string; city: string; region: string; postal_code: string; country: string };
  /** `phone` in E.164. */
  contact: { first_name: string; last_name: string; email: string; phone: string };
  /** Where the phone provider sends the review outcome. */
  notification_email: string;
  /** One to five of the phone provider's use-case categories, such as ACCOUNT_NOTIFICATIONS or CUSTOMER_CARE. */
  use_case_categories: string[];
  use_case_summary: string;
  production_message_sample: string;
  opt_in_type: 'VERBAL' | 'WEB_FORM' | 'PAPER_FORM' | 'VIA_TEXT' | 'MOBILE_QR_CODE';
  /** One to five public https pages or images showing how recipients agree to receive texts. */
  opt_in_image_urls: string[];
  /** The phone provider's monthly volume bands: '10', '100', '1,000' up to '10,000,000+'. */
  message_volume: string;
  privacy_policy_url: string;
  terms_and_conditions_url: string;
  additional_information?: string;
}

export interface TollFreeVerification {
  account_id: string;
  verification_id: string | null;
  /** The provider's own review status values. */
  status: 'PENDING_REVIEW' | 'IN_REVIEW' | 'TWILIO_APPROVED' | 'TWILIO_REJECTED' | null;
  /** The provider's rejection reason, when rejected. */
  rejection_reason: string | null;
  sending_allowed: boolean;
}

/** One of the customer's own mail domains for agent inboxes. */
export interface MailDomain {
  id: string;
  domain: string;
  /** The mail provider's state for the domain; `verified` once its DNS records check out. */
  status: string;
  /** The DNS records to publish at the domain. */
  records: Array<Record<string, unknown>>;
  warnings: Array<Record<string, unknown>>;
  verified_at: string | null;
  checked_at: string | null;
  created_at: string;
  /** Until when the name is held while unverified; null once verified. */
  claim_expires_at: string | null;
}

export interface ConnectMailDomainInput {
  /** A lower-case DNS name of two labels or more, such as `mail.example.com`. STACK's own mail domains are refused. */
  domain: string;
}

/** Operator actions a human approves first when the credential is not a dashboard session. */
export interface AccountGovernedOptions {
  /** The approval id from `GovernanceApprovalRequiredError`, once a human approved it. Send the same input again. */
  governanceApprovalId?: string;
}

const seg = encodeURIComponent;

/**
 * Calls the account's agent makes run under its Passport's Mission. An agent
 * signing with its own key (`agent_id`) passes the Passport as `passportToken`,
 * sent as `X-Passport-Token`; an operator credential omits it.
 */
export interface AccountAgentCallOptions {
  passportToken?: string;
}

function passport(options?: AccountAgentCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

function governed(options?: AccountGovernedOptions): { headers: Record<string, string> } | undefined {
  return options?.governanceApprovalId ? { headers: { 'X-Governance-Approval': options.governanceApprovalId } } : undefined;
}

export class AccountMessagesService {
  constructor(private readonly client: HttpClient) {}

  /** Inbound mail, SMS, voicemail and call transcripts, newest first. Flagged ones come back withheld with controls on, and with their flag with controls off. */
  async list(accountId: string, query: ListAccountMessagesQuery = {}, options?: AccountAgentCallOptions): Promise<ListAccountMessagesResult> {
    return this.client.get<ListAccountMessagesResult>(`/v1/accounts/${seg(accountId)}/messages`, {
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      cursor: query.cursor,
      channel: query.channel,
    }, passport(options));
  }

  async get(accountId: string, messageId: string, options?: AccountAgentCallOptions): Promise<AccountMessage> {
    return this.client.get<AccountMessage>(`/v1/accounts/${seg(accountId)}/messages/${seg(messageId)}`, undefined, passport(options));
  }

  /**
   * Search every message the caller may read, across the customer's message accounts and channels, newest first. An
   * owner or admin reads all of them; an agent reads those of every account of the customer unless the owner limited it
   * to its own (`stack.messageAccess`). The summary of each message comes back without its body: read one with `get`, and a file
   * it carries with `readAttachment`. Only a search on `q`, `sender`, `recipient` or `threadId` needs a window of at most 90 days.
   */
  async search(query: SearchAccountMessagesQuery = {}, options?: AccountAgentCallOptions): Promise<SearchAccountMessagesResult> {
    return this.client.get<SearchAccountMessagesResult>('/v1/messages', {
      agent_id: query.agentId,
      channel: query.channel,
      sender: query.sender,
      recipient: query.recipient,
      thread_id: query.threadId,
      after: query.after,
      before: query.before,
      q: query.q,
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      cursor: query.cursor,
    }, passport(options));
  }

  /**
   * A file a message carries (`content.attachments[].file_id`), read through the message: the same answer as `drive.read`
   * (UTF-8 text as text, anything else as base64, 256 KiB at most), including for a file that belongs to another agent of
   * the customer whose messages the caller may read. The content is untrusted.
   */
  async readAttachment(accountId: string, messageId: string, fileId: string, options?: AccountAgentCallOptions): Promise<DriveFileContent> {
    return this.client.get<DriveFileContent>(
      `/v1/accounts/${seg(accountId)}/messages/${seg(messageId)}/attachments/${seg(fileId)}`,
      undefined,
      passport(options),
    );
  }

  /** Owner or admin only. */
  async delete(accountId: string, messageId: string): Promise<void> {
    await this.client.delete<void>(`/v1/accounts/${seg(accountId)}/messages/${seg(messageId)}`);
  }
}

/**
 * The customer's do-not-contact list: numbers that texted STOP and numbers the customer or an agent added. Texts and calls
 * to a listed number are refused (`RecipientOptedOutError`). The owner, an admin or an agent's credential may list and add;
 * only the owner or an admin removes.
 */
export class AccountOptOutsService {
  constructor(private readonly client: HttpClient) {}

  /** Every number that asked not to be contacted. An agent may read it. */
  async list(): Promise<{ opt_outs: OptOut[] }> {
    return this.client.get<{ opt_outs: OptOut[] }>('/v1/opt-outs');
  }

  /**
   * Add a number (E.164) to the list, so texts and calls to it are refused. The owner, an admin or the account's agent may add.
   * A number already listed returns its entry as it is.
   */
  async add(number: string): Promise<OptOut> {
    return this.client.post<OptOut>('/v1/opt-outs', { number });
  }

  /** Take a number off the list, by the id `list` returned, so texts and calls to it are allowed again. */
  async remove(optOutId: string): Promise<{ removed: boolean }> {
    return this.client.delete<{ removed: boolean }>(`/v1/opt-outs/${seg(optOutId)}`);
  }
}

/**
 * The customer's blocked-callers list: an incoming call from a listed number is turned away before it rings, wakes no
 * agent, takes no voicemail and costs nothing. The owner, an admin or an agent's credential may list and add; only the
 * owner or an admin removes.
 */
export class AccountBlockedCallersService {
  constructor(private readonly client: HttpClient) {}

  /** Every blocked number. An agent may read it. */
  async list(): Promise<{ blocked_callers: BlockedCaller[] }> {
    return this.client.get<{ blocked_callers: BlockedCaller[] }>('/v1/blocked-callers');
  }

  /**
   * Block a number (E.164). The owner, an admin or the account's agent may add. A number already listed returns its entry
   * as it is.
   */
  async add(number: string): Promise<BlockedCaller> {
    return this.client.post<BlockedCaller>('/v1/blocked-callers', { number });
  }

  /** Take a number off the list, by the id `list` returned, so its calls ring again. The owner or an admin. */
  async remove(blockedCallerId: string): Promise<{ removed: boolean }> {
    return this.client.delete<{ removed: boolean }>(`/v1/blocked-callers/${seg(blockedCallerId)}`);
  }
}

/** The phone provider's toll-free verification for the account's toll-free number, which must be approved before it texts. */
export class AccountTollFreeVerificationService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Submit the owner's business details. Account admin only, and a governance
   * action: without a dashboard session this throws
   * `GovernanceApprovalRequiredError`; retry with the same details and its `approvalId`.
   */
  async submit(accountId: string, details: TollFreeVerificationInput, options?: AccountGovernedOptions): Promise<TollFreeVerification> {
    return this.client.post<TollFreeVerification>(`/v1/accounts/${seg(accountId)}/phone/toll-free-verification`, details, governed(options));
  }

  /** The verification's status. Operator only. */
  async get(accountId: string): Promise<TollFreeVerification> {
    return this.client.get<TollFreeVerification>(`/v1/accounts/${seg(accountId)}/phone/toll-free-verification`);
  }
}

export class AccountCallsService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Place a live call from the account's number to any country Twilio can reach, at cost. Any agent of the customer may
   * place it under its own Passport. Without `brief` the agent holds the call: STACK runs no model and says nothing, the
   * call opens with `greeting` or with silence, and this returns once the call is answered (with what the other side
   * first says, waiting up to `wait_seconds`) or ends unanswered. With `on_behalf_of` and `brief` STACK's model holds the
   * call and this returns at once. One action; the minutes (and a held call's model turns) are charged to the account's
   * budget. A number on the do-not-contact list is refused (`RecipientOptedOutError`), as is one Twilio has no price for
   * or does not allow (`DestinationNotAvailableError`).
   */
  async place(accountId: string, input: StartAccountCallInput, options?: AccountAgentCallOptions): Promise<AccountCallTurn> {
    return this.client.post<AccountCallTurn>(`/v1/accounts/${seg(accountId)}/calls`, input, passport(options));
  }

  /**
   * Answer a call that is ringing on the account's number, held either way as for `place`. A call rings for 30 seconds,
   * then goes to voicemail; `answer_by` on the call says when, and a wake for the source `incoming_call` carries the call
   * id. One action, put to your decider as `call.answer`. A call that is not ringing any more answers 409
   * `CALL_NOT_RINGING` and is not counted.
   */
  async answer(accountId: string, callId: string, input: AnswerAccountCallInput, options?: AccountAgentCallOptions): Promise<AccountCallTurn> {
    return this.client.post<AccountCallTurn>(`/v1/accounts/${seg(accountId)}/calls/${seg(callId)}/answer`, input, passport(options));
  }

  /**
   * Decline a call that is ringing on the account's number: the call is
   * hung up with nothing said. Not an action on the meter.
   * A call that is not ringing any more answers 409 `CALL_NOT_RINGING`.
   */
  async decline(accountId: string, callId: string, options?: AccountAgentCallOptions): Promise<AccountCall> {
    return this.client.post<AccountCall>(`/v1/accounts/${seg(accountId)}/calls/${seg(callId)}/decline`, undefined, passport(options));
  }

  /**
   * Speak on a call the agent holds: `text` is spoken as it is (none: only waits), then this waits up to `wait_seconds`
   * (0 to 60, default 30) for the other side's next finished sentence. Returns every event since your last call action.
   * Not metered. A call STACK holds is 409 `CALL_HELD_BY_STACK`; one not on the line 409 `CALL_NOT_LIVE`.
   */
  async say(accountId: string, callId: string, input: { text?: string; wait_seconds?: number } = {}, options?: AccountAgentCallOptions): Promise<AccountCallTurn> {
    return this.client.post<AccountCallTurn>(`/v1/accounts/${seg(accountId)}/calls/${seg(callId)}/say`, input, passport(options));
  }

  /** Send keys to the other side as tones: 0-9, `*`, `#`, and `w` for a pause. */
  async pressKeys(accountId: string, callId: string, digits: string, options?: AccountAgentCallOptions): Promise<AccountCallTurn> {
    return this.client.post<AccountCallTurn>(`/v1/accounts/${seg(accountId)}/calls/${seg(callId)}/keys`, { digits }, passport(options));
  }

  /** A new voice or language for the rest of a call the agent holds. */
  async setCallVoice(accountId: string, callId: string, voice: AccountCallVoice, options?: AccountAgentCallOptions): Promise<AccountCallTurn> {
    return this.client.post<AccountCallTurn>(`/v1/accounts/${seg(accountId)}/calls/${seg(callId)}/voice`, { voice }, passport(options));
  }

  /** Hang up a call, whoever holds it. STACK says nothing. The transcript is stored and the account's agent woken. */
  async hangUp(accountId: string, callId: string, options?: AccountAgentCallOptions): Promise<AccountCallTurn> {
    return this.client.post<AccountCallTurn>(`/v1/accounts/${seg(accountId)}/calls/${seg(callId)}/hang-up`, undefined, passport(options));
  }

  /**
   * The live stream of a call (a WebSocket): every event of the call as it happens, and the agent's words streamed on to
   * the call as they come (`text(token, last)`). The socket closes once the call has ended. In Node the global
   * `WebSocket` (Node 22 or later) is used, with the client's credential in the `Authorization` header; pass
   * `webSocket` to use another implementation that takes headers the same way.
   */
  async live(accountId: string, callId: string, options: AccountAgentCallOptions & { webSocket?: AccountCallWebSocketConstructor } = {}): Promise<AccountCallStream> {
    const Socket = options.webSocket ?? (globalThis as { WebSocket?: AccountCallWebSocketConstructor }).WebSocket;
    if (!Socket) throw new Error('No WebSocket implementation: use Node 22 or later, or pass webSocket');
    const url = `${this.client.apiBaseUrl.replace(/^http/, 'ws')}/v1/accounts/${seg(accountId)}/calls/${seg(callId)}/live`;
    const headers: Record<string, string> = { Authorization: await this.client.authorizationHeader() };
    if (options.passportToken) headers['X-Passport-Token'] = options.passportToken;
    return new AccountCallStream(new Socket(url, { headers }));
  }

  /** The account's calls, newest first. */
  async list(accountId: string, query: ListAccountCallsQuery = {}, options?: AccountAgentCallOptions): Promise<ListAccountCallsResult> {
    return this.client.get<ListAccountCallsResult>(`/v1/accounts/${seg(accountId)}/calls`, {
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      cursor: query.cursor,
    }, passport(options));
  }

  /** One call: its live transcript while it is on the line, then its stored transcript and outcome. */
  async get(accountId: string, callId: string, options?: AccountAgentCallOptions): Promise<AccountCallWithTranscript> {
    return this.client.get<AccountCallWithTranscript>(`/v1/accounts/${seg(accountId)}/calls/${seg(callId)}`, undefined, passport(options));
  }

  /** The account's call voice and voicemail greeting. The owner, an admin or the account's own agent. */
  async getAccountVoice(accountId: string, options?: AccountAgentCallOptions): Promise<AccountCallVoiceSetting> {
    return this.client.get<AccountCallVoiceSetting>(`/v1/accounts/${seg(accountId)}/phone/voice`, undefined, passport(options));
  }

  /** Set the account's call voice and voicemail greeting; a field left out is cleared. Not metered, no approval. */
  async setAccountVoice(accountId: string, input: AccountCallVoice & { voicemail_greeting?: string }, options?: AccountAgentCallOptions): Promise<AccountCallVoiceSetting> {
    return this.client.put<AccountCallVoiceSetting>(`/v1/accounts/${seg(accountId)}/phone/voice`, input, passport(options));
  }
}

/** A WebSocket as the live stream uses it: the WHATWG shape, with headers given when it is made (Node's undici WebSocket). */
export interface AccountCallWebSocket {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'open' | 'message' | 'close' | 'error', listener: (event: { data?: unknown }) => void): void;
}
export type AccountCallWebSocketConstructor = new (url: string, init: { headers: Record<string, string> }) => AccountCallWebSocket;

/**
 * A call's live stream. `events()` yields every event of the call in order, ending after `ended`; `errors` are the
 * messages the stream could not use. Send with `text`, `pressKeys`, `setVoice` and `hangUp`.
 */
export class AccountCallStream {
  private readonly queue: AccountCallLiveEvent[] = [];
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
      else this.queue.push(parsed as AccountCallLiveEvent);
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

  /** Every event of the call, oldest first from the start of the call, until it ends. */
  async *events(): AsyncGenerator<AccountCallLiveEvent> {
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

  async pressKeys(digits: string): Promise<void> {
    await this.send({ type: 'keys', digits });
  }

  async setVoice(voice: AccountCallVoice): Promise<void> {
    await this.send({ type: 'voice', voice });
  }

  async hangUp(): Promise<void> {
    await this.send({ type: 'hang_up' });
  }

  close(): void {
    this.socket.close(1000, 'done');
  }
}

/**
 * Paid tools: data endpoints of a paid-tools provider, used by the account's agent
 * under its Passport. Discover and inspect are free; a run holds the worst
 * case first and is charged at the provider's cost from the account's credit.
 */
export class AccountToolsService {
  constructor(private readonly client: HttpClient) {}

  async discover(accountId: string, input: { query: string; limit?: number }, options: AccountAgentCallOptions): Promise<AccountToolDiscovery> {
    return this.client.post<AccountToolDiscovery>(`/v1/accounts/${seg(accountId)}/tools/discover`, input, passport(options));
  }

  /** The endpoint's input schema and price. */
  async inspect(accountId: string, input: { provider: string; endpoint: string }, options: AccountAgentCallOptions): Promise<AccountToolInspection> {
    return this.client.post<AccountToolInspection>(`/v1/accounts/${seg(accountId)}/tools/inspect`, input, passport(options));
  }

  /**
   * Run any endpoint the tool provider lists (the catalogue lists them as tools),
   * charged what the provider reports for the run, with no STACK fee. Its worst
   * case is held first, or an estimate where the price and the input do not bound
   * it (`price_type` `ESTIMATED`); a cost above the hold is taken from the
   * account's credit at once; `max_cost_cents` lowers the hold. A run whose
   * `max_results` is outside 1 to 1000 is refused with `TOOL_PRICE_REFUSED`;
   * nothing is held then.
   * A run whose charge is not yet settled comes back `pending`; read it with `getRun`. */
  async run(accountId: string, input: AccountToolRunInput, options: AccountAgentCallOptions): Promise<AccountToolRun> {
    return this.client.post<AccountToolRun>(`/v1/accounts/${seg(accountId)}/tools/run`, input, passport(options));
  }

  async getRun(accountId: string, runId: string, options?: AccountAgentCallOptions): Promise<AccountToolRun> {
    return this.client.get<AccountToolRun>(`/v1/accounts/${seg(accountId)}/tools/runs/${seg(runId)}`, undefined, passport(options));
  }
}

/**
 * The keys an account signs its outbound requests with, so that a site that
 * checks for AI agents can tell whose they are (Web Bot Auth). STACK signs the
 * requests its proxy and cloud browser make for the account's agent, and
 * publishes the public keys at `/.well-known/http-message-signatures-directory`
 * (and, for this account alone, under its agent's id: see `accounts.identity`).
 */
export class AccountSigningKeysService {
  constructor(private readonly client: HttpClient) {}

  /** The key in use and any retired one still published. */
  async list(accountId: string): Promise<{ keys: AccountSigningKey[] }> {
    return this.client.get<{ keys: AccountSigningKey[] }>(`/v1/accounts/${seg(accountId)}/signing-keys`);
  }

  /** A new key signs from now on; the old one stays published for two days. Owner or admin only, never the agent. */
  async rotate(accountId: string): Promise<{ keys: AccountSigningKey[] }> {
    return this.client.post<{ keys: AccountSigningKey[] }>(`/v1/accounts/${seg(accountId)}/signing-keys/rotate`);
  }

}

/**
 * What STACK's public answer to "who is this agent?" shows for an account (the lookup is
 * `stack.agentIdentity`). Two switches, both the owner's, never the agent's: `enabled` (on by
 * default) and `show_name` (off by default). Changing one is a row of the account's signed record.
 */
export class AccountIdentityService {
  constructor(private readonly client: HttpClient) {}

  async get(accountId: string): Promise<AccountIdentity> {
    return this.client.get<AccountIdentity>(`/v1/accounts/${seg(accountId)}/identity`);
  }

  /** Show or hide the agent's name, or switch the answer off or on. Owner or admin only, never an agent. */
  async update(accountId: string, input: SetAccountIdentityInput): Promise<AccountIdentity> {
    return this.client.put<AccountIdentity>(`/v1/accounts/${seg(accountId)}/identity`, input);
  }
}

/**
 * The account's workspace: a machine of its own with a shell and git, with its own internet access, that keeps its
 * files between commands. The agent's calls run under its Passport. The account id of every call is the account that
 * owns the workspace: another agent of the same customer may run commands and read and write files in it while the
 * customer shares it with their agents (the default), under its own Passport and Mission, as its own action; only
 * the machine's time is charged to the owning account. Only the owning account's agent makes a workspace or stops one
 * (the owner may stop it too); listing is open to any principal of the operator. Machine time is held before it
 * starts and charged to the owning account's credit.
 */
export class AccountWorkspaceService {
  constructor(private readonly client: HttpClient) {}

  private base(accountId: string): string {
    return `/v1/accounts/${seg(accountId)}/workspaces`;
  }

  /** Run a command; without `workspace_id` a new workspace is made. What it prints is untrusted. */
  async exec(accountId: string, input: WorkspaceExecInput & { background?: false }, options?: AccountAgentCallOptions): Promise<WorkspaceExecResult>;
  /** Start a command in the background: the answer has its `command_id`; read it with `command`. */
  async exec(accountId: string, input: WorkspaceExecInput & { background: true }, options?: AccountAgentCallOptions): Promise<WorkspaceBackgroundStarted>;
  async exec(accountId: string, input: WorkspaceExecInput, options?: AccountAgentCallOptions): Promise<WorkspaceExecResult | WorkspaceBackgroundStarted> {
    return this.client.post<WorkspaceExecResult | WorkspaceBackgroundStarted>(`${this.base(accountId)}/exec`, input, passport(options));
  }

  /** A command started in the background: whether it has ended, its exit code, and what it has printed so far. The workspace must be running. */
  async command(accountId: string, workspaceId: string, commandId: string, options?: AccountAgentCallOptions): Promise<WorkspaceCommand> {
    return this.client.post<WorkspaceCommand>(`${this.base(accountId)}/${seg(workspaceId)}/commands/read`, { command_id: commandId }, passport(options));
  }

  async readFile(accountId: string, workspaceId: string, input: WorkspaceReadFileInput, options?: AccountAgentCallOptions): Promise<WorkspaceFile> {
    return this.client.post<WorkspaceFile>(`${this.base(accountId)}/${seg(workspaceId)}/files/read`, input, passport(options));
  }

  async writeFile(accountId: string, workspaceId: string, input: WorkspaceWriteFileInput, options?: AccountAgentCallOptions): Promise<WorkspaceFileWritten> {
    return this.client.post<WorkspaceFileWritten>(`${this.base(accountId)}/${seg(workspaceId)}/files/write`, input, passport(options));
  }

  /** Save a file of the workspace to the account's drive. */
  async saveFile(accountId: string, workspaceId: string, input: WorkspaceSaveFileInput, options?: AccountAgentCallOptions): Promise<WorkspaceFileSaved> {
    return this.client.post<WorkspaceFileSaved>(`${this.base(accountId)}/${seg(workspaceId)}/files/save`, input, passport(options));
  }

  /**
   * The workspaces that still exist and the caller may use. With an account, that account's: an agent sees all of its
   * own account's and, of another agent's, only those shared with it. Without one, every workspace the caller may use
   * across the customer's accounts (the owner sees all). Each says whose it is and whether it is shared.
   */
  async list(accountId?: string): Promise<WorkspaceListItem[]> {
    return (await this.client.get<{ workspaces: WorkspaceListItem[] }>(accountId ? this.base(accountId) : '/v1/workspaces')).workspaces;
  }

  /**
   * Whether the customer's other agents may use one workspace (`shared` true, the default for every workspace) or only
   * the agent that owns it (false: every other agent then finds no such workspace). Owner or admin only; an agent
   * cannot change it. Never metered; a change is one audit row.
   */
  async setSharing(accountId: string, workspaceId: string, shared: boolean): Promise<WorkspaceSharingResult> {
    return this.client.put<WorkspaceSharingResult>(`${this.base(accountId)}/${seg(workspaceId)}/sharing`, { shared });
  }

  /** Pause a workspace, or with `delete` delete it and its files. The owning account's agent and the owner only. */
  async stop(accountId: string, workspaceId: string, input: WorkspaceStopInput = {}): Promise<WorkspaceStopped> {
    return this.client.post<WorkspaceStopped>(`${this.base(accountId)}/${seg(workspaceId)}/stop`, input);
  }

  /**
   * The idle pause, the days a stopped workspace is kept and the number of workspaces, with what is in force: for one
   * agent account (its own over the customer's default), or without an account the customer's default. Owner or admin
   * only; an agent cannot read or change its own.
   */
  async getSettings(accountId?: string): Promise<WorkspaceSettingsResult> {
    return this.client.get<WorkspaceSettingsResult>(workspaceSettingsPath(accountId));
  }

  /** Change them, for one agent account or (without an account) the customer's default. Running workspaces take a new idle pause now. */
  async setSettings(input: WorkspaceSettingsInput, accountId?: string): Promise<WorkspaceSettingsResult> {
    return this.client.put<WorkspaceSettingsResult>(workspaceSettingsPath(accountId), input);
  }
}

function workspaceSettingsPath(accountId?: string): string {
  return accountId ? `/v1/accounts/${seg(accountId)}/workspace/settings` : '/v1/workspace/settings';
}

export class AccountBrowserService {
  constructor(private readonly client: HttpClient) {}

  private session(accountId: string, sessionId: string): string {
    return `/v1/accounts/${seg(accountId)}/browser/sessions/${seg(sessionId)}`;
  }

  /** Start a session. `maxMinutes` (1 to 360, 30 when left out) is how long it may run; the credit held is sized to it. */
  async startSession(accountId: string, options?: AccountAgentCallOptions & { maxMinutes?: number }): Promise<BrowserSession> {
    const body = options?.maxMinutes === undefined ? undefined : { max_minutes: options.maxMinutes };
    return this.client.post<BrowserSession>(`/v1/accounts/${seg(accountId)}/browser/sessions`, body, passport(options));
  }

  async navigate(accountId: string, sessionId: string, input: { url: string }, options?: AccountAgentCallOptions): Promise<{ url: string; title: string; status: number | null }> {
    return this.client.post(`${this.session(accountId, sessionId)}/navigate`, input, passport(options));
  }

  async act(accountId: string, sessionId: string, input: BrowserAction, options?: AccountAgentCallOptions): Promise<{ done: true; value_recorded?: boolean; url: string }> {
    return this.client.post(`${this.session(accountId, sessionId)}/act`, input, passport(options));
  }

  /** The page's main text and accessibility snapshot, scanned first; a page aimed at an agent comes back withheld with controls on, and with its flag with controls off. */
  async read(accountId: string, sessionId: string, options?: AccountAgentCallOptions): Promise<BrowserReading> {
    return this.client.post<BrowserReading>(`${this.session(accountId, sessionId)}/read`, undefined, passport(options));
  }

  async screenshot(accountId: string, sessionId: string, options?: AccountAgentCallOptions): Promise<{ url: string; mime: 'image/jpeg'; base64: string }> {
    return this.client.post(`${this.session(accountId, sessionId)}/screenshot`, undefined, passport(options));
  }

  async endSession(accountId: string, sessionId: string): Promise<{ session_id: string; state: string; charged_cents: number | null }> {
    return this.client.delete(this.session(accountId, sessionId));
  }

  /** Reserve the budget and start a card payment the customer approves on their own device. */
  async checkout(accountId: string, sessionId: string, input: BrowserCheckoutInput, options?: AccountAgentCallOptions): Promise<BrowserCheckout> {
    return this.client.post<BrowserCheckout>(`${this.session(accountId, sessionId)}/checkout`, input, passport(options));
  }
}

export class AccountPurchasesService {
  constructor(private readonly client: HttpClient) {}

  async get(accountId: string, purchaseId: string): Promise<CardPurchase> {
    return this.client.get<CardPurchase>(`/v1/accounts/${seg(accountId)}/purchases/${seg(purchaseId)}`);
  }

  /** What the merchant's page showed after the customer approved. It never moves money. */
  async reportMerchantResult(accountId: string, purchaseId: string, input: PurchaseMerchantResult, options?: AccountAgentCallOptions): Promise<CardPurchase> {
    return this.client.post<CardPurchase>(`/v1/accounts/${seg(accountId)}/purchases/${seg(purchaseId)}/merchant-result`, input, passport(options));
  }
}

/** A wallet's caps as strings of USDC, `null` for none. */
export interface WalletCaps {
  per_payment_cap_usdc: string | null;
  daily_cap_usdc: string | null;
  signer_policy: { per_payment_cap_usdc: string | null; covers_caps: boolean };
}

export class AccountWalletService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Pay from the account's wallet with a payment the agent signed with its own
   * wallet key (`signWalletPayment`). STACK checks the budget, the caps and the
   * customer's controls, then passes the request to the wallet provider
   * unchanged, or refuses it (and a refused payment is never sent). STACK holds
   * no key to the wallet. The agent's Passport is required.
   */
  async pay(accountId: string, input: WalletPaymentInput, options?: AccountAgentCallOptions): Promise<WalletPayment> {
    return this.client.post<WalletPayment>(`/v1/accounts/${seg(accountId)}/wallet/payments`, input, passport(options));
  }

  /**
   * Buy from an x402 seller in one step: ask `url`, and when the seller answers 402, make the payment it asks for,
   * sign it with the agent's own wallet `key` (here, never sent anywhere), pay through STACK (the same checks as
   * `pay`) and ask again with the payment attached. The seller's answer is what was bought. An answer that is not
   * a 402 comes back unpaid. Only USDC on Base with x402's `exact` scheme can be paid (x402 versions 1 and 2); any
   * other ask, a price over `maxCents` or a URL that is not https is refused with `X402PaymentError` before STACK is
   * asked. The agent's Passport is required.
   */
  async payUrl(accountId: string, url: string, options: PayX402Options & AccountAgentCallOptions & { fetch?: typeof fetch }): Promise<X402Result> {
    assertPayableUrl(url);
    const account = await this.client.get<AgentAccount>(`/v1/accounts/${seg(accountId)}`, undefined, passport(options));
    return payX402(url, {
      ...options,
      wallet: x402WalletOf(account.pieces),
      pay: (input) => this.pay(accountId, input, options),
    });
  }

  /**
   * Set or change a wallet's caps after it is open (owner or admin, needs controls; an agent context is refused). A cap left
   * out is not changed and `null` removes it. `signer_policy` says what the wallet provider's own rule, fixed when the wallet
   * opened, still holds per payment.
   */
  async setCaps(
    accountId: string,
    caps: { per_payment_cap_usdc?: number | null; daily_cap_usdc?: number | null },
  ): Promise<WalletCaps> {
    return this.client.put<WalletCaps>(`/v1/accounts/${seg(accountId)}/wallet/caps`, caps);
  }

  /** Whether the customer has become the owner of their agents' wallets (done at the STACK console). */
  async ownerStatus(): Promise<{ owner_set: boolean }> {
    return this.client.get<{ owner_set: boolean }>('/v1/accounts/wallet-owner');
  }
}

/**
 * The customer's own mail domains for agent inboxes. An account opened with
 * `inbox: { domain }` gets its inbox there once the domain is verified.
 * Operator only; an agent context is refused. There is no remove call: an
 * unverified claim lapses on its own (`claim_expires_at`).
 */
export class AccountMailDomainsService {
  constructor(private readonly client: HttpClient) {}

  /** Every connected domain, with its records and status. */
  async list(): Promise<{ domains: MailDomain[] }> {
    return this.client.get<{ domains: MailDomain[] }>('/v1/accounts/mail-domains');
  }

  /**
   * Connect a domain and get the DNS records to publish. Needs the platform
   * subscription (`PLATFORM_SUBSCRIPTION_REQUIRED` otherwise) and an owner or
   * admin. Connecting the same name again returns the same domain; a name
   * another customer holds is a 409.
   */
  async connect(input: ConnectMailDomainInput): Promise<MailDomain> {
    return this.client.post<MailDomain>('/v1/accounts/mail-domains', input);
  }

  /** Ask the mail provider to check the domain's DNS records now. Owner or admin. */
  async verify(domainId: string): Promise<MailDomain> {
    return this.client.post<MailDomain>(`/v1/accounts/mail-domains/${seg(domainId)}/verify`);
  }
}

/**
 * An agent's own Telegram bot: its identity on Telegram. `start` returns a link
 * the owner opens in Telegram to have STACK's manager bot make the bot (no
 * BotFather, no pasted token); or you make the bot with BotFather and give
 * STACK its token once with `connect`. People write to it, what they write
 * arrives with the account's other messages (`messages.list({ channel:
 * 'telegram' })`, scanned like mail and texts), and the agent answers with
 * `accounts.sendTelegram`. A bot cannot message a chat first.
 *
 * Operator only: an agent context is refused. The token is sent once, to STACK's
 * own route, and never returned; no OAuth token may connect a bot (the secret
 * would pass through a chat), so use an API key or the console.
 */
export class AccountTelegramService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Ask for the agent's bot to be made through STACK's Telegram manager bot. Returns `create_url`, which the
   * owner opens in Telegram and confirms: nothing is created until then, and STACK reads the new bot's token
   * itself. The link is single-use and lasts 10 minutes. Throws `NOT_CONFIGURED` when the deployment has no
   * manager bot: use `connect` then.
   */
  async start(accountId: string, input: { suggested_name?: string } = {}): Promise<ManagedTelegramBotRequest> {
    return this.client.post<ManagedTelegramBotRequest>(`/v1/accounts/${seg(accountId)}/telegram/start`, input);
  }

  /** Give the agent its bot. `botToken` is the token BotFather gave you. */
  async connect(accountId: string, botToken: string): Promise<TelegramBot> {
    return this.client.put<TelegramBot>(`/v1/accounts/${seg(accountId)}/telegram`, { bot_token: botToken });
  }

  /** The agent's bot. Throws a 404 `NOT_FOUND` when it has none. */
  async get(accountId: string): Promise<TelegramBot> {
    return this.client.get<TelegramBot>(`/v1/accounts/${seg(accountId)}/telegram`);
  }

  /** The chats that have written to the bot, which the agent may answer. */
  async chats(accountId: string): Promise<{ chats: TelegramChat[] }> {
    return this.client.get<{ chats: TelegramChat[] }>(`/v1/accounts/${seg(accountId)}/telegram/chats`);
  }

  /** Take the bot away: STACK removes its webhook and stops receiving. */
  async disconnect(accountId: string): Promise<void> {
    await this.client.delete<void>(`/v1/accounts/${seg(accountId)}/telegram`);
  }
}

export class AccountsService {
  readonly telegram: AccountTelegramService;
  readonly messages: AccountMessagesService;
  readonly optOuts: AccountOptOutsService;
  readonly blockedCallers: AccountBlockedCallersService;
  readonly tollFreeVerification: AccountTollFreeVerificationService;
  readonly calls: AccountCallsService;
  readonly tools: AccountToolsService;
  readonly workspace: AccountWorkspaceService;
  readonly browser: AccountBrowserService;
  readonly purchases: AccountPurchasesService;
  readonly wallet: AccountWalletService;
  readonly mailDomains: AccountMailDomainsService;
  readonly signingKeys: AccountSigningKeysService;
  readonly identity: AccountIdentityService;
  /** Making: designs, quotes and orders with manufacturing and print-on-demand suppliers. */
  readonly making: MakingService;

  constructor(private readonly client: HttpClient) {
    this.telegram = new AccountTelegramService(client);
    this.messages = new AccountMessagesService(client);
    this.optOuts = new AccountOptOutsService(client);
    this.blockedCallers = new AccountBlockedCallersService(client);
    this.tollFreeVerification = new AccountTollFreeVerificationService(client);
    this.calls = new AccountCallsService(client);
    this.tools = new AccountToolsService(client);
    this.workspace = new AccountWorkspaceService(client);
    this.browser = new AccountBrowserService(client);
    this.purchases = new AccountPurchasesService(client);
    this.wallet = new AccountWalletService(client);
    this.mailDomains = new AccountMailDomainsService(client);
    this.signingKeys = new AccountSigningKeysService(client);
    this.identity = new AccountIdentityService(client);
    this.making = new MakingService(client);
  }

  /**
   * Open an agent account. 201 when created, 200 when the same key already
   * opened it. Without a dashboard session this throws
   * `GovernanceApprovalRequiredError` first; retry with its `approvalId`.
   */
  async open(input: OpenAgentAccountInput, options: OpenAgentAccountOptions): Promise<AgentAccount> {
    const key = options.idempotencyKey;
    if (typeof key !== 'string' || key.length < 8 || key.length > 128) {
      throw new TypeError('idempotencyKey must be 8 to 128 characters');
    }
    return this.client.post<AgentAccount>('/v1/accounts', input, {
      headers: {
        'Idempotency-Key': key,
        ...(options.governanceApprovalId ? { 'X-Governance-Approval': options.governanceApprovalId } : {}),
      },
    });
  }

  async get(accountId: string): Promise<AgentAccount> {
    return this.client.get<AgentAccount>(`/v1/accounts/${seg(accountId)}`);
  }

  async list(query: { limit?: number } = {}): Promise<AgentAccount[]> {
    return this.client.get<AgentAccount[]>('/v1/accounts', {
      limit: query.limit !== undefined ? String(query.limit) : undefined,
    });
  }

  /**
   * Set, change or remove (`null`) the account's monthly spend budget, USD cents, a positive whole number. Owner or
   * admin only, never metered. Lowering applies at once. Raising or removing is a governance action: without a
   * dashboard session this throws `GovernanceApprovalRequiredError` first; once the owner approves at its link, send
   * the same call again with `governanceApprovalId`. Setting or raising needs controls (`CONTROLS_REQUIRED` otherwise).
   */
  async setBudget(accountId: string, monthlyBudgetCents: number | null, options?: AccountGovernedOptions): Promise<AgentAccount> {
    if (monthlyBudgetCents !== null && (!Number.isSafeInteger(monthlyBudgetCents) || monthlyBudgetCents <= 0)) {
      throw new TypeError('monthlyBudgetCents must be a positive whole number of cents, or null to remove the budget');
    }
    return this.client.put<AgentAccount>(`/v1/accounts/${seg(accountId)}/budget`, { monthly_budget_cents: monthlyBudgetCents }, governed(options));
  }

  /** Refuse the agent at once and close every piece at its provider. No approval needed. */
  async close(accountId: string): Promise<AgentAccount> {
    return this.client.delete<AgentAccount>(`/v1/accounts/${seg(accountId)}`);
  }

  /**
   * Send an email to one or several people, with copies and attachments. The mail provider takes one To address, so
   * further `to` addresses are delivered as Cc. Attach a drive file by `file_id` or a small file inline as base64.
   */
  async sendEmail(accountId: string, input: SendAccountEmailInput, options?: AccountAgentCallOptions): Promise<AccountEmailSent> {
    return this.client.post<AccountEmailSent>(`/v1/accounts/${seg(accountId)}/email/send`, input, passport(options));
  }

  /**
   * Answer an email the account received (`messageId` is its message id), in its thread, quoting that message unless
   * `include_quote` is `false`. `reply_all` also reaches everyone it was sent to. A message that cannot be answered throws `EmailMessageNotAnswerableError`.
   */
  async replyEmail(accountId: string, messageId: string, input: ReplyAccountEmailInput, options?: AccountAgentCallOptions): Promise<AccountEmailSent> {
    return this.client.post<AccountEmailSent>(`/v1/accounts/${seg(accountId)}/messages/${seg(messageId)}/reply`, input, passport(options));
  }

  /**
   * Send an email the account received on to others, as a new email in no thread, with its text unless `include_quote`
   * is `false` and, unless `include_attachments` is `false`, the attachments that were kept.
   */
  async forwardEmail(accountId: string, messageId: string, input: ForwardAccountEmailInput, options?: AccountAgentCallOptions): Promise<AccountEmailSent> {
    return this.client.post<AccountEmailSent>(`/v1/accounts/${seg(accountId)}/messages/${seg(messageId)}/forward`, input, passport(options));
  }

  async sendSms(accountId: string, input: SendAccountSmsInput, options?: AccountAgentCallOptions): Promise<AccountMessageSent> {
    return this.client.post<AccountMessageSent>(`/v1/accounts/${seg(accountId)}/sms/send`, input, passport(options));
  }

  /**
   * Answer a chat on the agent's own Telegram bot. The chat must have written
   * to the bot first (`TelegramSendRefusedError` with reason `chat_unknown`
   * otherwise); the same admission, controls and data-flow rule as a text. Only the account's own agent (or the owner) sends from its bot.
   */
  async sendTelegram(accountId: string, input: SendAccountTelegramInput, options?: AccountAgentCallOptions): Promise<AccountMessageSent> {
    return this.client.post<AccountMessageSent>(`/v1/accounts/${seg(accountId)}/telegram/messages`, input, passport(options));
  }

  /**
   * Lift a pause on the inbox or phone. Owner or admin only; it applies at
   * once and asks no one.
   */
  async resumePiece(accountId: string, piece: 'inbox' | 'phone'): Promise<{ state: string }> {
    return this.client.post<{ state: string }>(`/v1/accounts/${seg(accountId)}/pieces/resume`, { piece });
  }
}
