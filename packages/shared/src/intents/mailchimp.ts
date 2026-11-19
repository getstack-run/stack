import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Mailchimp Marketing API — https://mailchimp.com/developer/marketing/api/.
// Base: <dc>.api.mailchimp.com/3.0/… where <dc> is the account data
// center. Intents pin the pathname (dc is in the host, not pathname) and,
// where useful, the list_id segment.

const idList = z.union([
  z.string().min(1).max(64),
  z.array(z.string().min(1).max(64)).min(1),
]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function escapeRegex(s: string): string {
  return s.replace(/[.\\+*?()|[\]{}^$]/g, (m) => `\\${m}`);
}

function listIdPathConstraint(
  list_id: IdList,
  suffixRegex: string,
): Constraint {
  const ids = toList(list_id).map(escapeRegex);
  const group = ids.length === 1 ? ids[0] : `(${ids.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/3\\.0/lists/${group}${suffixRegex}$`,
  };
}

export const mailchimpIntents = [
  defineIntent({
    name: 'mailchimp.list_audiences',
    effect: 'read',
    description:
      'List audiences (lists) on the Mailchimp account. Binds GET /3.0/lists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/3.0/lists' },
    ],
  }),

  defineIntent({
    name: 'mailchimp.create_audience',
    effect: 'write',
    description:
      'Create a new Mailchimp audience. Binds POST /3.0/lists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/3.0/lists' },
    ],
  }),

  defineIntent({
    name: 'mailchimp.get_audience',
    effect: 'read',
    description:
      'Retrieve a Mailchimp audience by id. Binds GET /3.0/lists/{list_id}.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      listIdPathConstraint(list_id, ''),
    ],
  }),

  defineIntent({
    name: 'mailchimp.update_audience',
    effect: 'write',
    description:
      'Update a Mailchimp audience by id. Binds PATCH /3.0/lists/{list_id}.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      listIdPathConstraint(list_id, ''),
    ],
  }),

  defineIntent({
    name: 'mailchimp.delete_audience',
    effect: 'destructive',
    description:
      'Delete a Mailchimp audience by id. Binds DELETE /3.0/lists/{list_id}.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      listIdPathConstraint(list_id, ''),
    ],
  }),

  defineIntent({
    name: 'mailchimp.add_member',
    effect: 'write',
    description:
      'Add a new member to a specific Mailchimp audience. Binds POST /3.0/lists/{list_id}/members.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      listIdPathConstraint(list_id, '/members'),
    ],
  }),

  defineIntent({
    name: 'mailchimp.upsert_member',
    effect: 'write',
    description:
      'Create or update a Mailchimp audience member by subscriber hash. Binds PUT /3.0/lists/{list_id}/members/{hash}.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      listIdPathConstraint(list_id, '/members/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'mailchimp.update_member',
    effect: 'write',
    description:
      'Patch fields on a Mailchimp audience member. Binds PATCH /3.0/lists/{list_id}/members/{hash}.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      listIdPathConstraint(list_id, '/members/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'mailchimp.remove_member',
    effect: 'destructive',
    description:
      'Archive a Mailchimp audience member (soft delete). Binds DELETE /3.0/lists/{list_id}/members/{hash}.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      listIdPathConstraint(list_id, '/members/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'mailchimp.list_members',
    effect: 'read',
    description:
      'List members of a Mailchimp audience. Binds GET /3.0/lists/{list_id}/members.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      listIdPathConstraint(list_id, '/members'),
    ],
  }),

  defineIntent({
    name: 'mailchimp.list_campaigns',
    effect: 'read',
    description:
      'List Mailchimp campaigns on the account. Binds GET /3.0/campaigns.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/3.0/campaigns' },
    ],
  }),

  defineIntent({
    name: 'mailchimp.create_campaign',
    effect: 'write',
    description:
      'Create a Mailchimp campaign. Binds POST /3.0/campaigns.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/3.0/campaigns' },
    ],
  }),

  defineIntent({
    name: 'mailchimp.update_campaign',
    effect: 'write',
    description:
      'Update a Mailchimp campaign by id. Binds PATCH /3.0/campaigns/{campaign_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/3\\.0/campaigns/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'mailchimp.send_campaign',
    effect: 'send',
    description:
      'Send a previously created Mailchimp campaign. Binds POST /3.0/campaigns/{campaign_id}/actions/send.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/3\\.0/campaigns/[^/]+/actions/send$',
      },
    ],
  }),

  defineIntent({
    name: 'mailchimp.delete_campaign',
    effect: 'destructive',
    description:
      'Delete a Mailchimp campaign by id. Binds DELETE /3.0/campaigns/{campaign_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/3\\.0/campaigns/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'mailchimp.list_automations',
    effect: 'read',
    description:
      'List classic Mailchimp automations. Binds GET /3.0/automations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/3.0/automations' },
    ],
  }),

  defineIntent({
    name: 'mailchimp.list_segments',
    effect: 'read',
    description:
      'List segments inside a Mailchimp audience. Binds GET /3.0/lists/{list_id}/segments.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      listIdPathConstraint(list_id, '/segments'),
    ],
  }),

  defineIntent({
    name: 'mailchimp.create_segment',
    effect: 'write',
    description:
      'Create a segment within a Mailchimp audience. Binds POST /3.0/lists/{list_id}/segments.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      listIdPathConstraint(list_id, '/segments'),
    ],
  }),

  defineIntent({
    name: 'mailchimp.list_reports',
    effect: 'read',
    description:
      'List campaign performance reports. Binds GET /3.0/reports.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/3.0/reports' },
    ],
  }),

  defineIntent({
    name: 'mailchimp.list_templates',
    effect: 'read',
    description:
      'List Mailchimp email templates. Binds GET /3.0/templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/3.0/templates' },
    ],
  }),
];
