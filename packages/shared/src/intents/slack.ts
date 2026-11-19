import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Slack Web API — https://api.slack.com/methods. All calls POST JSON to
// slack.com/api/{method}. Intents gate on method path + (where relevant)
// the channel the request targets via body.channel.
//
// Channels are Slack channel IDs (C0123…) — Slack accepts names but ID
// is the safer form for allowlisting.

const channelList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type ChannelList = z.infer<typeof channelList>;
const toList = (v: ChannelList): string[] => (Array.isArray(v) ? v : [v]);

const userList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type UserList = z.infer<typeof userList>;

function channelConstraint(channel: ChannelList): Constraint {
  const list = toList(channel);
  return list.length === 1
    ? { path: 'body.channel', op: 'eq', value: list[0]! }
    : { path: 'body.channel', op: 'in', value: list };
}

function channelQueryConstraint(channel: ChannelList): Constraint {
  const list = toList(channel);
  return list.length === 1
    ? { path: 'query.channel', op: 'eq', value: list[0]! }
    : { path: 'query.channel', op: 'in', value: list };
}

function userBodyConstraint(user: UserList): Constraint {
  const list = Array.isArray(user) ? user : [user];
  return list.length === 1
    ? { path: 'body.user', op: 'eq', value: list[0]! }
    : { path: 'body.user', op: 'in', value: list };
}

export const slackIntents = [
  defineIntent({
    name: 'slack.post_to_channel',
    effect: 'send',
    recipient_paths: ['body.channel'],
    description:
      'Post a new message to specific Slack channel IDs. Binds POST /api/chat.postMessage to the declared channel allowlist.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/chat.postMessage' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.update_message',
    effect: 'write',
    description:
      'Edit an existing Slack message in specific channels. Binds POST /api/chat.update to the declared channel allowlist.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/chat.update' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.reply_in_thread',
    effect: 'send',
    recipient_paths: ['body.channel'],
    description:
      'Reply to a thread in specific Slack channels. Binds POST /api/chat.postMessage to channels + requires body.thread_ts to be present.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/chat.postMessage' },
      channelConstraint(channel),
      { path: 'body.thread_ts', op: 'matches', value: '^\\d+\\.\\d+$' },
    ],
  }),

  defineIntent({
    name: 'slack.read_channel_history',
    effect: 'read',
    description:
      'Read message history for specific Slack channels. Binds GET /api/conversations.history to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/conversations.history' },
      channelQueryConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.upload_file',
    effect: 'send',
    recipient_paths: ['body.channel', 'body.channels'],
    description:
      'Upload a file to specific Slack channels. Binds POST /api/files.upload to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/files.upload' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.delete_message',
    effect: 'destructive',
    description:
      'Delete a message in specific Slack channels. Binds POST /api/chat.delete to the declared channel allowlist.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/chat.delete' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.schedule_message',
    effect: 'send',
    recipient_paths: ['body.channel'],
    description:
      'Schedule a future message for specific Slack channels. Binds POST /api/chat.scheduleMessage to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/chat.scheduleMessage' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.delete_scheduled_message',
    effect: 'destructive',
    description:
      'Cancel a previously scheduled message in specific Slack channels. Binds POST /api/chat.deleteScheduledMessage.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/chat.deleteScheduledMessage' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.post_ephemeral',
    effect: 'send',
    recipient_paths: ['body.channel'],
    description:
      'Send an ephemeral (single-user visible) message in specific channels. Binds POST /api/chat.postEphemeral to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/chat.postEphemeral' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.list_channels',
    effect: 'read',
    description:
      'List conversations the workspace has access to. Binds GET /api/conversations.list.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/conversations.list' },
    ],
  }),

  defineIntent({
    name: 'slack.list_users',
    effect: 'read',
    description:
      'List users in the workspace. Binds GET /api/users.list.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/users.list' },
    ],
  }),

  defineIntent({
    name: 'slack.get_user_info',
    effect: 'read',
    description:
      'Look up a single user profile by ID. Binds GET /api/users.info.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/users.info' },
    ],
  }),

  defineIntent({
    name: 'slack.invite_to_channel',
    effect: 'write',
    description:
      'Invite users to specific Slack channels. Binds POST /api/conversations.invite to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/conversations.invite' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.kick_from_channel',
    effect: 'write',
    description:
      'Remove a user from specific Slack channels. Binds POST /api/conversations.kick to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/conversations.kick' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.archive_channel',
    effect: 'write',
    description:
      'Archive specific Slack channels. Binds POST /api/conversations.archive to the declared channel allowlist — destructive.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/conversations.archive' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.add_reaction',
    effect: 'write',
    description:
      'Add an emoji reaction to a message in specific channels. Binds POST /api/reactions.add to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/reactions.add' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.remove_reaction',
    effect: 'write',
    description:
      'Remove an emoji reaction from a message in specific channels. Binds POST /api/reactions.remove to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/reactions.remove' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.pin_message',
    effect: 'write',
    description:
      'Pin a message in specific Slack channels. Binds POST /api/pins.add to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/pins.add' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.unpin_message',
    effect: 'write',
    description:
      'Unpin a message in specific Slack channels. Binds POST /api/pins.remove to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/pins.remove' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.open_dm',
    effect: 'write',
    description:
      'Open a direct message conversation with specific users. Binds POST /api/conversations.open.',
    params: z.object({ user: userList }),
    expand: ({ user }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/conversations.open' },
      (() => {
        const list = Array.isArray(user) ? user : [user];
        return list.length === 1
          ? { path: 'body.users', op: 'eq', value: list[0]! }
          : { path: 'body.users', op: 'in', value: list };
      })(),
    ],
  }),

  defineIntent({
    name: 'slack.search_messages',
    effect: 'read',
    description:
      'Search messages across the workspace. Binds GET /api/search.messages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/search.messages' },
    ],
  }),

  defineIntent({
    name: 'slack.list_files',
    effect: 'read',
    description:
      'List uploaded files in the workspace. Binds GET /api/files.list.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/files.list' },
    ],
  }),

  defineIntent({
    name: 'slack.delete_file',
    effect: 'destructive',
    description:
      'Delete a previously uploaded file. Binds POST /api/files.delete — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/files.delete' },
    ],
  }),

  defineIntent({
    name: 'slack.set_channel_topic',
    effect: 'write',
    description:
      'Set the topic on specific Slack channels. Binds POST /api/conversations.setTopic to the declared channels.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/conversations.setTopic' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.set_channel_purpose',
    effect: 'write',
    description:
      'Set the purpose (description) on specific Slack channels. Binds POST /api/conversations.setPurpose.',
    params: z.object({ channel: channelList }),
    expand: ({ channel }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/conversations.setPurpose' },
      channelConstraint(channel),
    ],
  }),

  defineIntent({
    name: 'slack.add_reminder',
    effect: 'send',
    recipient_paths: ['body.user'],
    description:
      'Create a reminder for a specific user. Binds POST /api/reminders.add to the declared user allowlist.',
    params: z.object({ user: userList }),
    expand: ({ user }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/reminders.add' },
      userBodyConstraint(user),
    ],
  }),

  defineIntent({
    name: 'slack.canvas_create',
    effect: 'write',
    description:
      'Create a new standalone canvas. Binds POST /api/canvases.create.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/canvases.create' },
    ],
  }),
];
