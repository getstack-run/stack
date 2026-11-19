import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Zendesk Support API v2 — https://developer.zendesk.com/api-reference/.
// Base: <subdomain>.zendesk.com/api/v2/…. The subdomain lives in the host
// (not pathname); intents pin the pathname + method. Where an intent
// supports per-ticket scoping, the ticket id is pinned via regex.

const idList = z.union([
  z.string().min(1).max(64),
  z.array(z.string().min(1).max(64)).min(1),
]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function escapeRegex(s: string): string {
  return s.replace(/[.\\+*?()|[\]{}^$]/g, (m) => `\\${m}`);
}

function ticketPath(ticket_id: IdList, suffix: string): Constraint {
  const ids = toList(ticket_id).map(escapeRegex);
  const group = ids.length === 1 ? ids[0] : `(${ids.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/v2/tickets/${group}${suffix}$`,
  };
}

export const zendeskIntents = [
  defineIntent({
    name: 'zendesk.list_tickets',
    effect: 'read',
    description:
      'List Zendesk tickets on the instance. Binds GET /api/v2/tickets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/tickets' },
    ],
  }),

  defineIntent({
    name: 'zendesk.read_ticket',
    effect: 'read',
    description:
      'Read a single Zendesk ticket by id. Binds GET /api/v2/tickets/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/v2/tickets/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'zendesk.create_ticket',
    effect: 'write',
    description:
      'Create a new Zendesk ticket. Binds POST /api/v2/tickets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/tickets' },
    ],
  }),

  defineIntent({
    name: 'zendesk.update_ticket',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Update specific Zendesk tickets by id. Binds PUT /api/v2/tickets/{id} pinned to the allowlist.',
    params: z.object({ ticket_id: idList }),
    expand: ({ ticket_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      ticketPath(ticket_id, ''),
    ],
  }),

  defineIntent({
    name: 'zendesk.delete_ticket',
    effect: 'destructive',
    description:
      'Delete a Zendesk ticket by id. Binds DELETE /api/v2/tickets/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/v2/tickets/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'zendesk.list_ticket_comments',
    effect: 'read',
    description:
      'List comments on specific Zendesk tickets. Binds GET /api/v2/tickets/{id}/comments pinned to the allowlist.',
    params: z.object({ ticket_id: idList }),
    expand: ({ ticket_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      ticketPath(ticket_id, '/comments'),
    ],
  }),

  defineIntent({
    name: 'zendesk.apply_macro',
    effect: 'write',
    description:
      'Apply a Zendesk macro to a ticket. Binds PUT /api/v2/tickets/{id}/macros/{macro_id}/apply.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/v2/tickets/[^/]+/macros/[^/]+/apply$',
      },
    ],
  }),

  defineIntent({
    name: 'zendesk.list_users',
    effect: 'read',
    description:
      'List Zendesk users. Binds GET /api/v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/users' },
    ],
  }),

  defineIntent({
    name: 'zendesk.create_user',
    effect: 'write',
    description:
      'Create a Zendesk user. Binds POST /api/v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/users' },
    ],
  }),

  defineIntent({
    name: 'zendesk.update_user',
    effect: 'write',
    description:
      'Update a Zendesk user by id. Binds PUT /api/v2/users/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/v2/users/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'zendesk.delete_user',
    effect: 'destructive',
    description:
      'Delete a Zendesk user by id. Binds DELETE /api/v2/users/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/v2/users/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'zendesk.list_organizations',
    effect: 'read',
    description:
      'List Zendesk organizations. Binds GET /api/v2/organizations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/organizations' },
    ],
  }),

  defineIntent({
    name: 'zendesk.create_organization',
    effect: 'write',
    description:
      'Create a Zendesk organization. Binds POST /api/v2/organizations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/organizations' },
    ],
  }),

  defineIntent({
    name: 'zendesk.list_groups',
    effect: 'read',
    description:
      'List Zendesk agent groups. Binds GET /api/v2/groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/groups' },
    ],
  }),

  defineIntent({
    name: 'zendesk.search',
    effect: 'read',
    description:
      'Run a Zendesk search query across tickets, users, and organizations. Binds GET /api/v2/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/search' },
    ],
  }),

  defineIntent({
    name: 'zendesk.list_satisfaction_ratings',
    effect: 'read',
    description:
      'List CSAT ratings collected on the instance. Binds GET /api/v2/satisfaction_ratings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: '/api/v2/satisfaction_ratings',
      },
    ],
  }),

  defineIntent({
    name: 'zendesk.list_views',
    effect: 'read',
    description:
      'List Zendesk views defined on the instance. Binds GET /api/v2/views.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/views' },
    ],
  }),

  defineIntent({
    name: 'zendesk.list_triggers',
    effect: 'read',
    description:
      'List Zendesk business rule triggers. Binds GET /api/v2/triggers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/triggers' },
    ],
  }),

  defineIntent({
    name: 'zendesk.list_side_conversations',
    effect: 'read',
    description:
      'List side conversations associated with a Zendesk ticket. Binds GET /api/v2/tickets/{id}/side_conversations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/v2/tickets/[^/]+/side_conversations$',
      },
    ],
  }),

  defineIntent({
    name: 'zendesk.create_side_conversation',
    effect: 'send',
    recipient_paths: ['body.message.to[].email'],
    description:
      'Open a side conversation on specific Zendesk tickets. Binds POST /api/v2/tickets/{id}/side_conversations pinned to the allowlist.',
    params: z.object({ ticket_id: idList }),
    expand: ({ ticket_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      ticketPath(ticket_id, '/side_conversations'),
    ],
  }),
];
