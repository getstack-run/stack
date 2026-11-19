import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Discord API v10 — https://discord.com/developers/docs/reference. Base:
// discord.com/api/v10/…. Bot auth via `Authorization: Bot <token>`.
// Many operations are scoped by guild_id or channel_id in the path, so
// allowlisting those IDs is the main scope-reducing pattern here.

const idFmt = z
  .string()
  .min(1)
  .max(32)
  .regex(/^\d+$/, 'Discord snowflake ID must be numeric');
const idList = z.union([idFmt, z.array(idFmt).min(1)]);
type IdList = z.infer<typeof idList>;

const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function idAlt(ids: IdList): string {
  const list = toList(ids);
  return list.length === 1 ? list[0]! : `(${list.join('|')})`;
}

function channelPathConstraint(channel: IdList, suffix: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/v10/channels/${idAlt(channel)}${suffix}$`,
  };
}

function guildPathConstraint(guild: IdList, suffix: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/v10/guilds/${idAlt(guild)}${suffix}$`,
  };
}

export const discordIntents = [
  defineIntent({
    name: 'discord.send_channel_message',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Send a message to specific Discord channels. Binds POST /api/v10/channels/{channel_id}/messages to the declared channel allowlist.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      channelPathConstraint(channel, '/messages'),
    ],
  }),

  defineIntent({
    name: 'discord.edit_channel_message',
    effect: 'write',
    description:
      'Edit a previously sent message. Binds PATCH /api/v10/channels/{channel_id}/messages/{message_id} to the declared channels.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      channelPathConstraint(channel, '/messages/\\d+'),
    ],
  }),

  defineIntent({
    name: 'discord.delete_channel_message',
    effect: 'destructive',
    description:
      'Delete a message in a channel. Binds DELETE /api/v10/channels/{channel_id}/messages/{message_id} to the channel allowlist.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      channelPathConstraint(channel, '/messages/\\d+'),
    ],
  }),

  defineIntent({
    name: 'discord.bulk_delete_messages',
    effect: 'destructive',
    description:
      'Delete between 2 and 100 messages in one call. Binds POST /api/v10/channels/{channel_id}/messages/bulk-delete to the channel allowlist.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      channelPathConstraint(channel, '/messages/bulk-delete'),
    ],
  }),

  defineIntent({
    name: 'discord.get_channel_messages',
    effect: 'read',
    description:
      'Retrieve messages from specific channels. Binds GET /api/v10/channels/{channel_id}/messages.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      channelPathConstraint(channel, '/messages'),
    ],
  }),

  defineIntent({
    name: 'discord.add_reaction',
    effect: 'write',
    description:
      'Add an emoji reaction to a message. Binds PUT /api/v10/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      channelPathConstraint(channel, '/messages/\\d+/reactions/[^/]+/@me'),
    ],
  }),

  defineIntent({
    name: 'discord.remove_own_reaction',
    effect: 'destructive',
    description:
      'Remove the bot’s own reaction from a message. Binds DELETE /api/v10/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      channelPathConstraint(channel, '/messages/\\d+/reactions/[^/]+/@me'),
    ],
  }),

  defineIntent({
    name: 'discord.create_dm',
    effect: 'write',
    description:
      'Open or fetch a DM channel with a specific user. Binds POST /api/v10/users/@me/channels — the recipient_id is set in the body.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v10/users/@me/channels' },
    ],
  }),

  defineIntent({
    name: 'discord.list_guilds',
    effect: 'read',
    description:
      'List guilds the bot is a member of. Binds GET /api/v10/users/@me/guilds.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v10/users/@me/guilds' },
    ],
  }),

  defineIntent({
    name: 'discord.list_guild_channels',
    effect: 'read',
    description:
      'List all channels in specific guilds. Binds GET /api/v10/guilds/{guild_id}/channels to the declared guild allowlist.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      guildPathConstraint(guild, '/channels'),
    ],
  }),

  defineIntent({
    name: 'discord.create_guild_channel',
    effect: 'write',
    description:
      'Create a new channel in specific guilds. Binds POST /api/v10/guilds/{guild_id}/channels.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      guildPathConstraint(guild, '/channels'),
    ],
  }),

  defineIntent({
    name: 'discord.list_guild_members',
    effect: 'read',
    description:
      'List members of specific guilds. Binds GET /api/v10/guilds/{guild_id}/members.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      guildPathConstraint(guild, '/members'),
    ],
  }),

  defineIntent({
    name: 'discord.add_guild_member_role',
    effect: 'write',
    description:
      'Assign a role to a member in specific guilds. Binds PUT /api/v10/guilds/{guild_id}/members/{user_id}/roles/{role_id}.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      guildPathConstraint(guild, '/members/\\d+/roles/\\d+'),
    ],
  }),

  defineIntent({
    name: 'discord.remove_guild_member_role',
    effect: 'destructive',
    description:
      'Remove a role from a member in specific guilds. Binds DELETE /api/v10/guilds/{guild_id}/members/{user_id}/roles/{role_id}.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      guildPathConstraint(guild, '/members/\\d+/roles/\\d+'),
    ],
  }),

  defineIntent({
    name: 'discord.kick_guild_member',
    effect: 'destructive',
    description:
      'Remove a member from specific guilds. Binds DELETE /api/v10/guilds/{guild_id}/members/{user_id} — destructive.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      guildPathConstraint(guild, '/members/\\d+'),
    ],
  }),

  defineIntent({
    name: 'discord.ban_guild_member',
    effect: 'write',
    description:
      'Ban a member from specific guilds. Binds PUT /api/v10/guilds/{guild_id}/bans/{user_id} — destructive.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      guildPathConstraint(guild, '/bans/\\d+'),
    ],
  }),

  defineIntent({
    name: 'discord.create_webhook',
    effect: 'write',
    description:
      'Create a webhook on specific channels. Binds POST /api/v10/channels/{channel_id}/webhooks.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      channelPathConstraint(channel, '/webhooks'),
    ],
  }),

  defineIntent({
    name: 'discord.execute_webhook',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Execute a webhook to post as a bot-branded entity. Binds POST /api/v10/webhooks/{webhook_id}/{webhook_token}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v10/webhooks/\\d+/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'discord.start_thread',
    effect: 'write',
    description:
      'Start a new thread from a message in specific channels. Binds POST /api/v10/channels/{channel_id}/messages/{message_id}/threads.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      channelPathConstraint(channel, '/messages/\\d+/threads'),
    ],
  }),

  defineIntent({
    name: 'discord.list_active_threads',
    effect: 'read',
    description:
      'List active threads in specific guilds. Binds GET /api/v10/guilds/{guild_id}/threads/active.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      guildPathConstraint(guild, '/threads/active'),
    ],
  }),

  defineIntent({
    name: 'discord.create_interaction_response',
    effect: 'send',
    description:
      'Respond to a slash-command interaction. Binds POST /api/v10/interactions/{interaction_id}/{interaction_token}/callback.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v10/interactions/\\d+/[^/]+/callback$' },
    ],
  }),

  defineIntent({
    name: 'discord.create_followup_message',
    effect: 'send',
    description:
      'Send a follow-up message for a deferred interaction. Binds POST /api/v10/webhooks/{application_id}/{interaction_token}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v10/webhooks/\\d+/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'discord.list_scheduled_events',
    effect: 'read',
    description:
      'List scheduled events for specific guilds. Binds GET /api/v10/guilds/{guild_id}/scheduled-events.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      guildPathConstraint(guild, '/scheduled-events'),
    ],
  }),

  defineIntent({
    name: 'discord.create_scheduled_event',
    effect: 'write',
    description:
      'Create a scheduled event for specific guilds. Binds POST /api/v10/guilds/{guild_id}/scheduled-events.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      guildPathConstraint(guild, '/scheduled-events'),
    ],
  }),

  defineIntent({
    name: 'discord.list_guild_roles',
    effect: 'read',
    description:
      'List roles in specific guilds. Binds GET /api/v10/guilds/{guild_id}/roles.',
    params: z.object({ guild: idList }),
    expand: ({ guild }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      guildPathConstraint(guild, '/roles'),
    ],
  }),

  defineIntent({
    name: 'discord.pin_message',
    effect: 'write',
    description:
      'Pin a message in specific channels. Binds PUT /api/v10/channels/{channel_id}/pins/{message_id}.',
    params: z.object({ channel: idList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      channelPathConstraint(channel, '/pins/\\d+'),
    ],
  }),
];
