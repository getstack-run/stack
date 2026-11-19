import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Resend API — https://resend.com/docs/api-reference. Base:
// api.resend.com/…. Transactional send is POST /emails; recipients are in
// the JSON body. We can pin `body.from` to a sender identity and/or
// `body.to` to a single allowlisted address — domain allowlisting is
// available via a regex on the from field.

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

export const resendIntents = [
  defineIntent({
    name: 'resend.send_email',
    effect: 'send',
    recipient_paths: ['body.to', 'body.cc', 'body.bcc'],
    description:
      'Send a transactional email via Resend. Binds POST /emails.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/emails' },
    ],
  }),

  defineIntent({
    name: 'resend.send_email_from',
    effect: 'send',
    recipient_paths: ['body.to', 'body.cc', 'body.bcc'],
    description:
      'Send a Resend email pinned to an allowlisted from address. Binds POST /emails with body.from fixed.',
    params: z.object({ from: stringList }),
    expand: ({ from }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/emails' },
      eqOrIn('body.from', from),
    ],
  }),

  defineIntent({
    name: 'resend.send_email_from_domain',
    effect: 'send',
    recipient_paths: ['body.to', 'body.cc', 'body.bcc'],
    description:
      'Send a Resend email only when the from address uses one of the allowlisted domains. Binds POST /emails and matches body.from against @domain suffixes.',
    params: z.object({ domain: stringList }),
    expand: ({ domain }) => {
      const alt = toList(domain).map(escapeRegex).join('|');
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/emails' },
        {
          path: 'body.from',
          op: 'matches',
          value: `^[^@<]*<?[^@]+@(${alt})>?$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'resend.send_email_to',
    effect: 'send',
    recipient_paths: ['body.to', 'body.cc', 'body.bcc'],
    description:
      'Send a Resend email pinned to allowlisted recipients. Binds POST /emails with body.to fixed. Cc and Bcc are refused unless listed in cc or bcc.',
    params: z.object({ to: stringList, cc: stringList.optional(), bcc: stringList.optional() }),
    // Every recipient field is bound, so a Cc or Bcc cannot carry the email
    // anywhere the operator did not name.
    expand: ({ to, cc, bcc }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/emails' },
      eqOrIn('body.to', to),
      cc ? eqOrIn('body.cc', cc) : { path: 'body.cc', op: 'not_exists', value: true },
      bcc ? eqOrIn('body.bcc', bcc) : { path: 'body.bcc', op: 'not_exists', value: true },
    ],
  }),

  defineIntent({
    name: 'resend.get_email',
    effect: 'read',
    description:
      'Retrieve a previously sent email by id. Binds GET /emails/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/emails/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'resend.batch_send',
    effect: 'send',
    description:
      'Send up to 100 emails in a single batch. Binds POST /emails/batch.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/emails/batch' },
    ],
  }),

  defineIntent({
    name: 'resend.list_audiences',
    effect: 'read',
    description:
      'List Resend audiences. Binds GET /audiences.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/audiences' },
    ],
  }),

  defineIntent({
    name: 'resend.create_audience',
    effect: 'write',
    description:
      'Create a new Resend audience. Binds POST /audiences.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/audiences' },
    ],
  }),

  defineIntent({
    name: 'resend.get_audience',
    effect: 'read',
    description:
      'Retrieve a Resend audience by id. Binds GET /audiences/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/audiences/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'resend.delete_audience',
    effect: 'destructive',
    description:
      'Delete a Resend audience by id. Binds DELETE /audiences/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/audiences/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'resend.list_contacts',
    effect: 'read',
    description:
      'List contacts in the Resend account. Binds GET /contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/contacts' },
    ],
  }),

  defineIntent({
    name: 'resend.create_contact',
    effect: 'write',
    description:
      'Create a contact in the Resend account. Binds POST /contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/contacts' },
    ],
  }),

  defineIntent({
    name: 'resend.update_contact',
    effect: 'write',
    description:
      'Update a Resend contact by id. Binds PATCH /contacts/{contact_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/contacts/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'resend.delete_contact',
    effect: 'destructive',
    description:
      'Delete a Resend contact by id. Binds DELETE /contacts/{contact_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/contacts/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'resend.list_domains',
    effect: 'read',
    description:
      'List Resend sending domains. Binds GET /domains.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/domains' },
    ],
  }),

  defineIntent({
    name: 'resend.get_domain',
    effect: 'read',
    description:
      'Retrieve a Resend sending domain by id. Binds GET /domains/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/domains/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'resend.create_domain',
    effect: 'write',
    description:
      'Register a new Resend sending domain. Binds POST /domains.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/domains' },
    ],
  }),

  defineIntent({
    name: 'resend.verify_domain',
    effect: 'write',
    description:
      'Trigger DNS verification for a Resend sending domain. Binds POST /domains/{id}/verify.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/domains/[^/]+/verify$',
      },
    ],
  }),

  defineIntent({
    name: 'resend.delete_domain',
    effect: 'destructive',
    description:
      'Delete a Resend sending domain. Binds DELETE /domains/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/domains/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'resend.list_api_keys',
    effect: 'read',
    description:
      'List Resend API keys on the account. Binds GET /api-keys.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api-keys' },
    ],
  }),
];
