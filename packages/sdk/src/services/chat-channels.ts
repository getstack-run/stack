import type { HttpClient } from '../client.js';

// Chat channels: approving a held payment from Telegram, a text or Slack.
//
// A policy can hold a card purchase or a wallet payment for a person. If you set
// both chat limits in the policy (`review.chat`: `max_per_payment_cents` and
// `max_per_day_cents`; there is no default, so it is off until you do), the
// owner can answer from a chat they have bound, and only for a payment within
// those limits. Above them, or with no limits, the approval page in a signed-in
// browser is the only way. Every chat answer comes from the owner's own
// verified chat identity, is single-use, is bound to the exact payment and
// amount, expires in ten minutes, and is recorded in the signed record with its
// channel (`decided_via`: `chat_telegram`, `chat_sms` or `chat_slack`).
//
// Binding an identity is the owner's own act in their own browser:
//
//   Telegram, Slack   `createIdentity` returns a link or a slash command to
//                     carry into the chat; then `confirmIdentity` in the console.
//   Text              `createIdentity` with a phone number texts a code; type it
//                     with `verifyIdentity` in the console.
//
// `verifyIdentity`, `confirmIdentity` and `installSlack` need a signed-in
// dashboard session: an API key, a CLI or an OAuth token (a chat assistant) gets
// a 403. Starting a text binding does too. Nothing here is metered.
//
// SIM-swap and chat-account takeover: anyone who controls the bound number or
// account can answer, so keep the limits small. They are yours to set and
// there is no STACK default.

export type ChatApprovalChannel = 'telegram' | 'sms' | 'slack';
export type ChatIdentityStatus = 'awaiting_chat' | 'awaiting_code' | 'awaiting_confirm' | 'active' | 'revoked';

export interface ChatIdentity {
  id: string;
  channel: ChatApprovalChannel;
  /** The member it belongs to; null for the account's owner. */
  member_id: string | null;
  status: ChatIdentityStatus;
  /** A masked form to recognise it by. */
  display: string;
  created_at: string;
  confirmed_at: string | null;
  /** Only on the response that creates it. */
  link?: {
    /** Telegram: open this in Telegram and press Start. */
    url?: string;
    /** Slack: send this slash command in the workspace STACK is installed in. */
    command?: string;
    expires_at: string;
  };
}

export interface CreateChatIdentityInput {
  channel: ChatApprovalChannel;
  /** E.164. Required for `sms`, refused for the others. */
  phone?: string;
}

export interface ChatChannels {
  channels: {
    telegram: { configured: boolean; bot_username: string | null };
    sms: { configured: boolean };
    slack: { configured: boolean; installed_team: string | null };
  };
  identities: ChatIdentity[];
  /** A typed code is good for this many wrong tries. */
  code_attempts: number;
}

export interface SlackInstallation {
  team_id: string;
  team_name: string;
  installed_at: string;
}

export class ChatChannelsService {
  constructor(private readonly client: HttpClient) {}

  /** Which channels this deployment has, and the identities bound. Owner or admin. */
  async get(): Promise<ChatChannels> {
    return this.client.get<ChatChannels>('/v1/chat-channels');
  }

  /** Start binding an identity. A text binding needs a signed-in dashboard session. */
  async createIdentity(input: CreateChatIdentityInput): Promise<ChatIdentity> {
    return this.client.post<ChatIdentity>('/v1/chat-channels/identities', input);
  }

  /** The six-digit code texted to a number. Dashboard session only. */
  async verifyIdentity(identityId: string, code: string): Promise<ChatIdentity> {
    return this.client.post<ChatIdentity>(`/v1/chat-channels/identities/${encodeURIComponent(identityId)}/verify`, { code });
  }

  /** Confirm an identity the chat proved. Dashboard session only. */
  async confirmIdentity(identityId: string): Promise<ChatIdentity> {
    return this.client.post<ChatIdentity>(`/v1/chat-channels/identities/${encodeURIComponent(identityId)}/confirm`, {});
  }

  /** End an identity at once. It only narrows who can approve, so any admin credential may. */
  async removeIdentity(identityId: string): Promise<void> {
    await this.client.delete<void>(`/v1/chat-channels/identities/${encodeURIComponent(identityId)}`);
  }

  /**
   * Where the workspace's admin installs STACK's Slack app. `state` is yours: the
   * console keeps it and checks it when Slack sends the admin back.
   */
  async slackInstallUrl(input: { redirect_uri: string; state: string }): Promise<{ url: string }> {
    return this.client.get<{ url: string }>('/v1/chat-channels/slack/install-url', input);
  }

  /** Exchange the code Slack sent back for the workspace's token. Dashboard session only. */
  async installSlack(input: { code: string; redirect_uri: string }): Promise<SlackInstallation> {
    return this.client.post<SlackInstallation>('/v1/chat-channels/slack/install', input);
  }

  /** Uninstall the workspace; the Slack identities bound through it end. */
  async removeSlack(): Promise<void> {
    await this.client.delete<void>('/v1/chat-channels/slack');
  }
}
