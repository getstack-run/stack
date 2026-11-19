import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// SendGrid v3 API — https://docs.sendgrid.com/api-reference. Base:
// api.sendgrid.com/v3/…. Mail send recipients live under
// body.personalizations[].to/cc/bcc[].email (every personalization delivers),
// plus the account-wide copy in body.mail_settings.bcc.email; sender under
// body.from.email. Scoping is feasible on all of them: a `[]` path is checked
// for every element.

const stringList = z.union([
  z.string().min(1).max(256),
  z.array(z.string().min(1).max(256)).min(1),
]);
type StringList = z.infer<typeof stringList>;
const toList = (v: StringList): string[] => (Array.isArray(v) ? v : [v]);

function eqOrIn(path: string, values: StringList): Constraint {
  const list = toList(values);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

function escapeRegex(s: string): string {
  return s.replace(/[.\\+*?()|[\]{}^$]/g, (m) => `\\${m}`);
}

export const sendgridIntents = [
  defineIntent({
    name: 'sendgrid.send_mail',
    effect: 'send',
    recipient_paths: ['body.personalizations[].to[].email', 'body.personalizations[].cc[].email', 'body.personalizations[].bcc[].email', 'body.mail_settings.bcc.email'],
    description:
      'Send a transactional email via SendGrid. Binds POST /v3/mail/send.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/mail/send' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.send_mail_from',
    effect: 'send',
    recipient_paths: ['body.personalizations[].to[].email', 'body.personalizations[].cc[].email', 'body.personalizations[].bcc[].email', 'body.mail_settings.bcc.email'],
    description:
      'Send a SendGrid email pinned to an allowlisted from address. Binds POST /v3/mail/send with body.from.email fixed.',
    params: z.object({ from: stringList }),
    expand: ({ from }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/mail/send' },
      eqOrIn('body.from.email', from),
    ],
  }),

  defineIntent({
    name: 'sendgrid.send_mail_from_domain',
    effect: 'send',
    recipient_paths: ['body.personalizations[].to[].email', 'body.personalizations[].cc[].email', 'body.personalizations[].bcc[].email', 'body.mail_settings.bcc.email'],
    description:
      'Send a SendGrid email only when the from address uses one of the allowlisted domains. Binds POST /v3/mail/send and matches body.from.email against @domain suffixes.',
    params: z.object({ domain: stringList }),
    expand: ({ domain }) => {
      const alt = toList(domain).map(escapeRegex).join('|');
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/v3/mail/send' },
        {
          path: 'body.from.email',
          op: 'matches',
          value: `^[^@]+@(${alt})$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'sendgrid.send_mail_to',
    effect: 'send',
    recipient_paths: ['body.personalizations[].to[].email', 'body.personalizations[].cc[].email', 'body.personalizations[].bcc[].email', 'body.mail_settings.bcc.email'],
    description:
      'Send a SendGrid email pinned to allowlisted recipients. Binds POST /v3/mail/send with every personalization\'s to addresses in the list. Cc and Bcc are refused unless listed in cc or bcc, and the account-wide mail_settings.bcc copy is always refused.',
    params: z.object({ to: stringList, cc: stringList.optional(), bcc: stringList.optional() }),
    // Every recipient of every personalization is checked, not just the first.
    // An absent cc/bcc list means no personalization may carry one at all.
    expand: ({ to, cc, bcc }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/mail/send' },
      eqOrIn('body.personalizations[].to[].email', to),
      cc ? eqOrIn('body.personalizations[].cc[].email', cc) : { path: 'body.personalizations[].cc', op: 'not_exists', value: true },
      bcc ? eqOrIn('body.personalizations[].bcc[].email', bcc) : { path: 'body.personalizations[].bcc', op: 'not_exists', value: true },
      // mail_settings.bcc copies every message to one more address, outside
      // the personalizations, so it is refused outright here.
      { path: 'body.mail_settings.bcc', op: 'not_exists', value: true },
    ],
  }),

  defineIntent({
    name: 'sendgrid.list_campaigns',
    effect: 'read',
    description:
      'List SendGrid marketing campaigns (single sends). Binds GET /v3/marketing/singlesends.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/marketing/singlesends' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.create_campaign',
    effect: 'write',
    description:
      'Create a SendGrid marketing single-send campaign. Binds POST /v3/marketing/singlesends.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/marketing/singlesends' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.send_campaign',
    effect: 'send',
    description:
      'Schedule a SendGrid single-send campaign to deliver. Binds PUT /v3/marketing/singlesends/{id}/schedule.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v3/marketing/singlesends/[^/]+/schedule$',
      },
    ],
  }),

  defineIntent({
    name: 'sendgrid.delete_campaign',
    effect: 'destructive',
    description:
      'Delete a SendGrid single-send campaign by id. Binds DELETE /v3/marketing/singlesends/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v3/marketing/singlesends/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'sendgrid.list_contacts',
    effect: 'read',
    description:
      'List SendGrid marketing contacts. Binds GET /v3/marketing/contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/marketing/contacts' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.upsert_contacts',
    effect: 'write',
    description:
      'Create or update SendGrid marketing contacts in bulk. Binds PUT /v3/marketing/contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/v3/marketing/contacts' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.delete_contacts',
    effect: 'destructive',
    description:
      'Delete SendGrid marketing contacts by ids. Binds DELETE /v3/marketing/contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'eq', value: '/v3/marketing/contacts' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.list_lists',
    effect: 'read',
    description:
      'List SendGrid marketing contact lists. Binds GET /v3/marketing/lists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/marketing/lists' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.create_list',
    effect: 'write',
    description:
      'Create a SendGrid marketing contact list. Binds POST /v3/marketing/lists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/marketing/lists' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.list_templates',
    effect: 'read',
    description:
      'List SendGrid dynamic templates. Binds GET /v3/templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/templates' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.create_template',
    effect: 'write',
    description:
      'Create a SendGrid dynamic template. Binds POST /v3/templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/templates' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.list_suppressions',
    effect: 'read',
    description:
      'List global suppression (unsubscribe) entries. Binds GET /v3/asm/suppressions/global.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: '/v3/asm/suppressions/global',
      },
    ],
  }),

  defineIntent({
    name: 'sendgrid.list_bounces',
    effect: 'read',
    description:
      'List recent bounce events. Binds GET /v3/suppression/bounces.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/suppression/bounces' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.list_blocks',
    effect: 'read',
    description:
      'List recent block events. Binds GET /v3/suppression/blocks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/suppression/blocks' },
    ],
  }),

  defineIntent({
    name: 'sendgrid.read_stats',
    effect: 'read',
    description:
      'Read aggregated SendGrid mail stats for a time window. Binds GET /v3/stats.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/stats' },
    ],
  }),
];
