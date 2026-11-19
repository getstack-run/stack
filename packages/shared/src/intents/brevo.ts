import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Brevo (formerly Sendinblue) API — https://developers.brevo.com/reference.
// Base: api.brevo.com/v3/…. Transactional email recipients live under
// body.to/cc/bcc[].email (and the same under body.messageVersions[], which
// carries its own recipient lists); sender under body.sender.email. Both are
// scopable: a `[]` path is checked for every element.

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

export const brevoIntents = [
  defineIntent({
    name: 'brevo.send_transactional_email',
    effect: 'send',
    recipient_paths: ['body.to[].email', 'body.cc[].email', 'body.bcc[].email', 'body.messageVersions[].to[].email', 'body.messageVersions[].cc[].email', 'body.messageVersions[].bcc[].email'],
    description:
      'Send a transactional email via Brevo. Binds POST /v3/smtp/email.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/smtp/email' },
    ],
  }),

  defineIntent({
    name: 'brevo.send_transactional_email_from',
    effect: 'send',
    recipient_paths: ['body.to[].email', 'body.cc[].email', 'body.bcc[].email', 'body.messageVersions[].to[].email', 'body.messageVersions[].cc[].email', 'body.messageVersions[].bcc[].email'],
    description:
      'Send a Brevo transactional email pinned to an allowlisted sender. Binds POST /v3/smtp/email with body.sender.email fixed.',
    params: z.object({ sender: stringList }),
    expand: ({ sender }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/smtp/email' },
      eqOrIn('body.sender.email', sender),
    ],
  }),

  defineIntent({
    name: 'brevo.send_transactional_email_from_domain',
    effect: 'send',
    recipient_paths: ['body.to[].email', 'body.cc[].email', 'body.bcc[].email', 'body.messageVersions[].to[].email', 'body.messageVersions[].cc[].email', 'body.messageVersions[].bcc[].email'],
    description:
      'Send a Brevo transactional email only when the sender uses an allowlisted domain. Binds POST /v3/smtp/email and matches body.sender.email against @domain suffixes.',
    params: z.object({ domain: stringList }),
    expand: ({ domain }) => {
      const alt = toList(domain).map(escapeRegex).join('|');
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/v3/smtp/email' },
        {
          path: 'body.sender.email',
          op: 'matches',
          value: `^[^@]+@(${alt})$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'brevo.send_transactional_email_to',
    effect: 'send',
    recipient_paths: ['body.to[].email', 'body.cc[].email', 'body.bcc[].email', 'body.messageVersions[].to[].email', 'body.messageVersions[].cc[].email', 'body.messageVersions[].bcc[].email'],
    description:
      'Send a Brevo transactional email pinned to allowlisted recipients. Binds POST /v3/smtp/email with every to address in the list. Cc and Bcc are refused unless listed in cc or bcc; message versions are refused.',
    params: z.object({ to: stringList, cc: stringList.optional(), bcc: stringList.optional() }),
    // Every recipient is checked, not just the first. Message versions carry
    // their own recipient lists, so they are refused outright here.
    expand: ({ to, cc, bcc }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/smtp/email' },
      eqOrIn('body.to[].email', to),
      cc ? eqOrIn('body.cc[].email', cc) : { path: 'body.cc', op: 'not_exists', value: true },
      bcc ? eqOrIn('body.bcc[].email', bcc) : { path: 'body.bcc', op: 'not_exists', value: true },
      { path: 'body.messageVersions', op: 'not_exists', value: true },
    ],
  }),

  defineIntent({
    name: 'brevo.send_transactional_sms',
    effect: 'send',
    recipient_paths: ['body.recipient'],
    description:
      'Send a transactional SMS via Brevo. Binds POST /v3/transactionalSMS/sms.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/transactionalSMS/sms' },
    ],
  }),

  defineIntent({
    name: 'brevo.list_contacts',
    effect: 'read',
    description:
      'List Brevo contacts on the account. Binds GET /v3/contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/contacts' },
    ],
  }),

  defineIntent({
    name: 'brevo.create_contact',
    effect: 'write',
    description:
      'Create a new Brevo contact. Binds POST /v3/contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/contacts' },
    ],
  }),

  defineIntent({
    name: 'brevo.update_contact',
    effect: 'write',
    description:
      'Update a Brevo contact by identifier. Binds PUT /v3/contacts/{identifier}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v3/contacts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'brevo.delete_contact',
    effect: 'destructive',
    description:
      'Delete a Brevo contact by identifier. Binds DELETE /v3/contacts/{identifier}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v3/contacts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'brevo.list_campaigns',
    effect: 'read',
    description:
      'List Brevo email campaigns. Binds GET /v3/emailCampaigns.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/emailCampaigns' },
    ],
  }),

  defineIntent({
    name: 'brevo.create_campaign',
    effect: 'write',
    description:
      'Create a Brevo email campaign. Binds POST /v3/emailCampaigns.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/emailCampaigns' },
    ],
  }),

  defineIntent({
    name: 'brevo.send_campaign_now',
    effect: 'send',
    description:
      'Send a created Brevo email campaign immediately. Binds POST /v3/emailCampaigns/{id}/sendNow.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v3/emailCampaigns/[^/]+/sendNow$',
      },
    ],
  }),

  defineIntent({
    name: 'brevo.delete_campaign',
    effect: 'destructive',
    description:
      'Delete a Brevo email campaign by id. Binds DELETE /v3/emailCampaigns/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v3/emailCampaigns/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'brevo.list_templates',
    effect: 'read',
    description:
      'List Brevo email templates. Binds GET /v3/smtp/templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/smtp/templates' },
    ],
  }),

  defineIntent({
    name: 'brevo.create_template',
    effect: 'write',
    description:
      'Create a Brevo transactional email template. Binds POST /v3/smtp/templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/smtp/templates' },
    ],
  }),

  defineIntent({
    name: 'brevo.list_webhooks',
    effect: 'read',
    description:
      'List Brevo webhook endpoints. Binds GET /v3/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/webhooks' },
    ],
  }),

  defineIntent({
    name: 'brevo.create_webhook',
    effect: 'write',
    description:
      'Register a Brevo webhook endpoint. Binds POST /v3/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v3/webhooks' },
    ],
  }),

  defineIntent({
    name: 'brevo.list_attributes',
    effect: 'read',
    description:
      'List contact attributes defined on the Brevo account. Binds GET /v3/contacts/attributes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/contacts/attributes' },
    ],
  }),

  defineIntent({
    name: 'brevo.list_folders',
    effect: 'read',
    description:
      'List Brevo contact list folders. Binds GET /v3/contacts/folders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/contacts/folders' },
    ],
  }),

  defineIntent({
    name: 'brevo.list_lists',
    effect: 'read',
    description:
      'List Brevo contact lists. Binds GET /v3/contacts/lists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v3/contacts/lists' },
    ],
  }),
];
