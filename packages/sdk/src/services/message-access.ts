import type { HttpClient } from '../client.js';

/** Where an effective value comes from: the agent's own value, else the account's, else STACK's default. */
export type MessageAccessSource = 'agent' | 'account' | 'default';

/** The two message access settings. */
export type MessageAccessKey = 'read_teammates' | 'messages_read_only';

/** The values to change. A key left out is not touched; `null` removes the value at this scope, so it follows the next scope. */
export interface MessageAccessValues {
  read_teammates?: boolean | null;
  messages_read_only?: boolean | null;
}

/** What is set at one scope, and what is in force there. */
export interface MessageAccessSetting {
  /** The agent this is for, or null for the account. */
  agent_id: string | null;
  /** What is set at this scope: null when it has no value of its own. */
  read_teammates: boolean | null;
  messages_read_only: boolean | null;
  /** What is in force here: the agent's value, else the account's, else STACK's default. */
  effective: { read_teammates: boolean; messages_read_only: boolean };
  /** Which scope each effective value comes from. */
  source: { read_teammates: MessageAccessSource; messages_read_only: MessageAccessSource };
}

/**
 * Message access: what the account's agents may do with the customer's messages, for the account and per agent.
 *
 * - `read_teammates` (default `true`): the agent reads the messages of every message account of the customer, search
 *   included. With `false` it reads only its own.
 * - `messages_read_only` (default `false`): with `true` the agent may read but cannot send, reply, forward, text or post
 *   from any account.
 *
 * An agent's own value wins over the account's, and the account's over the default. Owner or admin only; an agent is
 * refused. A change applies at once and needs no approval from a person.
 */
export class MessageAccessService {
  constructor(private readonly client: HttpClient) {}

  /** The account's values, or one agent's own values over the account's. */
  async get(agentId?: string): Promise<MessageAccessSetting> {
    return this.client.get<MessageAccessSetting>(accessPath(agentId));
  }

  /** Change the account's values, or one agent's (they win over the account's). At least one key; `null` removes a value. */
  async set(values: MessageAccessValues, agentId?: string): Promise<MessageAccessSetting> {
    return this.client.put<MessageAccessSetting>(accessPath(agentId), values);
  }

  /** Remove the values an agent set for itself, so it follows the account again. Name the keys to remove. */
  async clear(agentId: string, keys: readonly MessageAccessKey[]): Promise<MessageAccessSetting> {
    const values: MessageAccessValues = {};
    for (const key of keys) values[key] = null;
    return this.client.put<MessageAccessSetting>(accessPath(agentId), values);
  }
}

function accessPath(agentId: string | undefined): string {
  return agentId === undefined ? '/v1/message-access' : `/v1/agents/${encodeURIComponent(agentId)}/message-access`;
}
