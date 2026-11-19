import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Microsoft Graph (Teams) — https://learn.microsoft.com/graph/api/resources/teams-api-overview.
// Base: graph.microsoft.com/v1.0/…. Auth is bearer token from Azure AD.
//
// Team and channel IDs are GUIDs / Graph-formatted IDs. Chat IDs are
// opaque strings like "19:xxx@thread.v2" — we keep allowlists as
// regex alternations on url.pathname.

const idFmt = z.string().min(1).max(256);
const idList = z.union([idFmt, z.array(idFmt).min(1)]);
type IdList = z.infer<typeof idList>;

const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function pathAlt(ids: IdList): string {
  const list = toList(ids);
  const escaped = list.map((r) => r.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
}

function teamPath(team: IdList, suffix: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1\\.0/teams/${pathAlt(team)}${suffix}$`,
  };
}

function chatPath(chat: IdList, suffix: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1\\.0/chats/${pathAlt(chat)}${suffix}$`,
  };
}

export const msTeamsIntents = [
  defineIntent({
    name: 'ms_teams.list_joined_teams',
    effect: 'read',
    description:
      'List teams the signed-in user is a member of. Binds GET /v1.0/me/joinedTeams.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/joinedTeams' },
    ],
  }),

  defineIntent({
    name: 'ms_teams.get_team',
    effect: 'read',
    description:
      'Fetch details for specific teams. Binds GET /v1.0/teams/{teamId} to the declared team allowlist.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      teamPath(team, ''),
    ],
  }),

  defineIntent({
    name: 'ms_teams.list_channels',
    effect: 'read',
    description:
      'List channels in specific teams. Binds GET /v1.0/teams/{teamId}/channels.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      teamPath(team, '/channels'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.create_channel',
    effect: 'write',
    description:
      'Create a new channel in specific teams. Binds POST /v1.0/teams/{teamId}/channels.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      teamPath(team, '/channels'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.delete_channel',
    effect: 'destructive',
    description:
      'Delete a channel in specific teams. Binds DELETE /v1.0/teams/{teamId}/channels/{channelId} — destructive.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      teamPath(team, '/channels/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.send_channel_message',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Post a message to a channel in specific teams. Binds POST /v1.0/teams/{teamId}/channels/{channelId}/messages.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      teamPath(team, '/channels/[^/]+/messages'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.list_channel_messages',
    effect: 'read',
    description:
      'List messages in a team channel. Binds GET /v1.0/teams/{teamId}/channels/{channelId}/messages.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      teamPath(team, '/channels/[^/]+/messages'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.reply_to_channel_message',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Reply to a channel message in specific teams. Binds POST /v1.0/teams/{teamId}/channels/{channelId}/messages/{messageId}/replies.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      teamPath(team, '/channels/[^/]+/messages/[^/]+/replies'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.list_team_members',
    effect: 'read',
    description:
      'List members of specific teams. Binds GET /v1.0/teams/{teamId}/members.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      teamPath(team, '/members'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.add_team_member',
    effect: 'write',
    description:
      'Add a member to specific teams. Binds POST /v1.0/teams/{teamId}/members.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      teamPath(team, '/members'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.remove_team_member',
    effect: 'destructive',
    description:
      'Remove a member from specific teams. Binds DELETE /v1.0/teams/{teamId}/members/{membershipId}.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      teamPath(team, '/members/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.list_chats',
    effect: 'read',
    description:
      'List 1:1 and group chats for the signed-in user. Binds GET /v1.0/me/chats.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/chats' },
    ],
  }),

  defineIntent({
    name: 'ms_teams.get_chat',
    effect: 'read',
    description:
      'Fetch details for specific chats. Binds GET /v1.0/chats/{chatId}.',
    params: z.object({ chat: idList }),
    expand: ({ chat }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      chatPath(chat, ''),
    ],
  }),

  defineIntent({
    name: 'ms_teams.send_chat_message',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Send a message in a specific chat. Binds POST /v1.0/chats/{chatId}/messages to the declared chat allowlist.',
    params: z.object({ chat: idList }),
    expand: ({ chat }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      chatPath(chat, '/messages'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.list_chat_messages',
    effect: 'read',
    description:
      'List messages in specific chats. Binds GET /v1.0/chats/{chatId}/messages.',
    params: z.object({ chat: idList }),
    expand: ({ chat }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      chatPath(chat, '/messages'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.create_online_meeting',
    effect: 'write',
    description:
      'Create a Teams online meeting for the signed-in user. Binds POST /v1.0/me/onlineMeetings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/onlineMeetings' },
    ],
  }),

  defineIntent({
    name: 'ms_teams.list_online_meetings',
    effect: 'read',
    description:
      'List Teams online meetings for the signed-in user. Binds GET /v1.0/me/onlineMeetings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/onlineMeetings' },
    ],
  }),

  defineIntent({
    name: 'ms_teams.get_online_meeting',
    effect: 'read',
    description:
      'Fetch a single online meeting. Binds GET /v1.0/me/onlineMeetings/{meetingId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1\\.0/me/onlineMeetings/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'ms_teams.delete_online_meeting',
    effect: 'destructive',
    description:
      'Delete a Teams online meeting. Binds DELETE /v1.0/me/onlineMeetings/{meetingId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1\\.0/me/onlineMeetings/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'ms_teams.get_channel_message',
    effect: 'read',
    description:
      'Fetch a single channel message. Binds GET /v1.0/teams/{teamId}/channels/{channelId}/messages/{messageId}.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      teamPath(team, '/channels/[^/]+/messages/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'ms_teams.list_channel_replies',
    effect: 'read',
    description:
      'List replies to a channel message. Binds GET /v1.0/teams/{teamId}/channels/{channelId}/messages/{messageId}/replies.',
    params: z.object({ team: idList }),
    expand: ({ team }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      teamPath(team, '/channels/[^/]+/messages/[^/]+/replies'),
    ],
  }),
];
