import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Intercom API — https://developers.intercom.com/docs/references/rest-api/.
// Base: api.intercom.io/…. Most resources are top-level collections with
// id path segments. Conversation intents pin the conversation id via
// regex; contact/company operations gate on method + path shape.

const idList = z.union([
  z.string().min(1).max(64),
  z.array(z.string().min(1).max(64)).min(1),
]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function escapeRegex(s: string): string {
  return s.replace(/[.\\+*?()|[\]{}^$]/g, (m) => `\\${m}`);
}

function conversationPath(
  conversation_id: IdList,
  suffix: string,
): Constraint {
  const ids = toList(conversation_id).map(escapeRegex);
  const group = ids.length === 1 ? ids[0] : `(${ids.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/conversations/${group}${suffix}$`,
  };
}

export const intercomIntents = [
  defineIntent({
    name: 'intercom.list_conversations',
    effect: 'read',
    description:
      'List Intercom conversations. Binds GET /conversations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/conversations' },
    ],
  }),

  defineIntent({
    name: 'intercom.read_conversation',
    effect: 'read',
    description:
      'Read a single Intercom conversation by id. Binds GET /conversations/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/conversations/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'intercom.reply_conversation',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Reply to specific Intercom conversations. Binds POST /conversations/{id}/reply pinned to the conversation id allowlist.',
    params: z.object({ conversation_id: idList }),
    expand: ({ conversation_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      conversationPath(conversation_id, '/reply'),
    ],
  }),

  defineIntent({
    name: 'intercom.close_conversation',
    effect: 'write',
    description:
      'Close specific Intercom conversations via the management endpoint. Binds POST /conversations/{id}/parts with body.message_type = close.',
    params: z.object({ conversation_id: idList }),
    expand: ({ conversation_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      conversationPath(conversation_id, '/parts'),
      { path: 'body.message_type', op: 'eq', value: 'close' },
    ],
  }),

  defineIntent({
    name: 'intercom.snooze_conversation',
    effect: 'write',
    description:
      'Snooze specific Intercom conversations. Binds POST /conversations/{id}/parts with body.message_type = snoozed.',
    params: z.object({ conversation_id: idList }),
    expand: ({ conversation_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      conversationPath(conversation_id, '/parts'),
      { path: 'body.message_type', op: 'eq', value: 'snoozed' },
    ],
  }),

  defineIntent({
    name: 'intercom.assign_conversation',
    effect: 'write',
    description:
      'Assign specific Intercom conversations to a teammate or team. Binds POST /conversations/{id}/parts with body.message_type = assignment.',
    params: z.object({ conversation_id: idList }),
    expand: ({ conversation_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      conversationPath(conversation_id, '/parts'),
      { path: 'body.message_type', op: 'eq', value: 'assignment' },
    ],
  }),

  defineIntent({
    name: 'intercom.tag_conversation',
    effect: 'write',
    description:
      'Add a tag to an Intercom conversation. Binds POST /conversations/{id}/tags.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/conversations/[^/]+/tags$',
      },
    ],
  }),

  defineIntent({
    name: 'intercom.list_contacts',
    effect: 'read',
    description:
      'List Intercom contacts (users + leads). Binds GET /contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/contacts' },
    ],
  }),

  defineIntent({
    name: 'intercom.create_contact',
    effect: 'write',
    description:
      'Create an Intercom contact. Binds POST /contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/contacts' },
    ],
  }),

  defineIntent({
    name: 'intercom.update_contact',
    effect: 'write',
    description:
      'Update an Intercom contact by id. Binds PUT /contacts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/contacts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'intercom.delete_contact',
    effect: 'destructive',
    description:
      'Delete an Intercom contact by id. Binds DELETE /contacts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/contacts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'intercom.search_contacts',
    effect: 'read',
    description:
      'Search Intercom contacts with a structured query. Binds POST /contacts/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/contacts/search' },
    ],
  }),

  defineIntent({
    name: 'intercom.list_companies',
    effect: 'read',
    description:
      'List Intercom companies. Binds GET /companies.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/companies' },
    ],
  }),

  defineIntent({
    name: 'intercom.create_company',
    effect: 'write',
    description:
      'Create or update an Intercom company. Binds POST /companies.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/companies' },
    ],
  }),

  defineIntent({
    name: 'intercom.list_articles',
    effect: 'read',
    description:
      'List Intercom help center articles. Binds GET /articles.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/articles' },
    ],
  }),

  defineIntent({
    name: 'intercom.create_article',
    effect: 'write',
    description:
      'Create an Intercom help center article. Binds POST /articles.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/articles' },
    ],
  }),

  defineIntent({
    name: 'intercom.list_segments',
    effect: 'read',
    description:
      'List Intercom user segments. Binds GET /segments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/segments' },
    ],
  }),

  defineIntent({
    name: 'intercom.list_tags',
    effect: 'read',
    description:
      'List Intercom tags on the workspace. Binds GET /tags.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/tags' },
    ],
  }),

  defineIntent({
    name: 'intercom.add_note',
    effect: 'write',
    description:
      'Add a private note to specific Intercom conversations. Binds POST /conversations/{id}/parts with body.message_type = note.',
    params: z.object({ conversation_id: idList }),
    expand: ({ conversation_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      conversationPath(conversation_id, '/parts'),
      { path: 'body.message_type', op: 'eq', value: 'note' },
    ],
  }),

  defineIntent({
    name: 'intercom.track_event',
    effect: 'write',
    description:
      'Track a custom user event on Intercom. Binds POST /events.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/events' },
    ],
  }),

  defineIntent({
    name: 'intercom.list_admins',
    effect: 'read',
    description:
      'List Intercom admins (teammates). Binds GET /admins.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/admins' },
    ],
  }),
];
