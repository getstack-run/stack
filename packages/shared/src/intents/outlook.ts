import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Microsoft Graph Mail — https://learn.microsoft.com/en-us/graph/api/resources/mail-api-overview.
// Calls go to graph.microsoft.com/v1.0/me/…. Recipients live inside the
// JSON body under {to,cc,bcc}Recipients[].emailAddress.address, or inside a
// base64 MIME message when the body is sent as text/plain. Both forms are
// read into `derived.email.recipients` (utils/derived-email.ts), which the
// recipient-pinning intents bind so an added Cc or Bcc cannot slip past.
// Replying and sending a stored draft carry no recipients in the request (the
// reply goes to whoever the message names), so those stay review-only.

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

export const outlookIntents = [
  defineIntent({
    name: 'outlook.send_mail',
    effect: 'send',
    recipient_paths: ['derived.email.recipients'],
    description:
      'Send a mail message from the signed-in mailbox. Binds POST /v1.0/me/sendMail.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/sendMail' },
    ],
  }),

  defineIntent({
    name: 'outlook.send_mail_to',
    effect: 'send',
    recipient_paths: ['derived.email.recipients'],
    description:
      'Send a mail message only to one allowlisted address. Binds POST /v1.0/me/sendMail and requires every To, Cc and Bcc recipient, in JSON or MIME form, to be that address.',
    params: z.object({ to: z.string().min(3).max(256) }),
    expand: ({ to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/sendMail' },
      {
        path: 'body.message.toRecipients.0.emailAddress.address',
        op: 'eq',
        value: to,
      },
      { path: 'derived.email.recipients', op: 'in', value: [to.toLowerCase()] },
    ],
  }),

  defineIntent({
    name: 'outlook.create_draft',
    effect: 'write',
    description:
      'Create a mail draft in the mailbox without sending. Binds POST /v1.0/me/messages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/messages' },
    ],
  }),

  defineIntent({
    name: 'outlook.send_draft',
    effect: 'send',
    description:
      'Send an existing mail draft. Binds POST /v1.0/me/messages/{id}/send.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+/send$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.list_messages',
    effect: 'read',
    description:
      'List messages from the mailbox or a specific folder. Binds GET /v1.0/me/messages and /v1.0/me/mailFolders/{id}/messages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/(messages|mailFolders/[^/]+/messages)$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.read_message',
    effect: 'read',
    description:
      'Read a single mail message by id. Binds GET /v1.0/me/messages/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.delete_message',
    effect: 'destructive',
    description:
      'Delete a mail message by id. Binds DELETE /v1.0/me/messages/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.move_message',
    effect: 'write',
    description:
      'Move a mail message to another mail folder. Binds POST /v1.0/me/messages/{id}/move.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+/move$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.forward_message',
    effect: 'send',
    recipient_paths: ['derived.email.recipients'],
    description:
      'Forward an existing mail message. Binds POST /v1.0/me/messages/{id}/forward.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+/forward$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.reply_message',
    effect: 'send',
    description:
      'Reply to an existing mail message. Binds POST /v1.0/me/messages/{id}/reply.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+/reply$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.reply_all_message',
    effect: 'send',
    description:
      'Reply-all to an existing mail message. Binds POST /v1.0/me/messages/{id}/replyAll.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+/replyAll$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.set_categories',
    effect: 'write',
    description:
      'Set categories (labels) on a mail message. Binds PATCH /v1.0/me/messages/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.search_messages',
    effect: 'read',
    description:
      'Run a Microsoft Graph search against the mailbox. Binds POST /v1.0/search/query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/search/query' },
    ],
  }),

  defineIntent({
    name: 'outlook.list_mail_folders',
    effect: 'read',
    description:
      'List mail folders in the mailbox. Binds GET /v1.0/me/mailFolders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/mailFolders' },
    ],
  }),

  defineIntent({
    name: 'outlook.create_rule',
    effect: 'send',
    recipient_paths: ['body.actions.forwardTo[].emailAddress.address', 'body.actions.redirectTo[].emailAddress.address', 'body.actions.forwardAsAttachmentTo[].emailAddress.address'],
    description:
      'Create an inbox rule on the default inbox folder. Binds POST /v1.0/me/mailFolders/inbox/messageRules.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: '/v1.0/me/mailFolders/inbox/messageRules',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.set_automatic_replies',
    effect: 'send',
    recipient_paths: ['body.automaticRepliesSetting.externalAudience'],
    description:
      'Configure automatic replies (out-of-office) on the mailbox. Binds PATCH /v1.0/me/mailboxSettings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'eq', value: '/v1.0/me/mailboxSettings' },
    ],
  }),

  defineIntent({
    name: 'outlook.list_attachments',
    effect: 'read',
    description:
      'List attachments on a mail message. Binds GET /v1.0/me/messages/{id}/attachments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1\\.0/me/messages/[^/]+/attachments$',
      },
    ],
  }),

  defineIntent({
    name: 'outlook.send_mail_to_domain',
    effect: 'send',
    recipient_paths: ['derived.email.recipients'],
    description:
      'Send a mail message only to addresses in the allowlisted domains. Binds POST /v1.0/me/sendMail and requires every To, Cc and Bcc recipient, in JSON or MIME form, to end in one of the domains.',
    params: z.object({ domain: stringList }),
    expand: ({ domain }) => {
      const list = toList(domain);
      // Build a RE2-safe anchored regex: .+@(d1|d2|…)$
      const alt = list
        .map((d) => d.replace(/[.\\+*?()|[\]{}^$]/g, (m) => `\\${m}`))
        .join('|');
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/v1.0/me/sendMail' },
        {
          path: 'body.message.toRecipients.0.emailAddress.address',
          op: 'matches',
          value: `^[^@]+@(${alt})$`,
        },
        // Derived recipients are lowercased, so the domain list is too.
        { path: 'derived.email.recipients', op: 'matches', value: `^[^@]+@(${alt.toLowerCase()})$` },
      ];
    },
  }),

  // Quiet the "unused" warning for eqOrIn — kept for future scoping exts.
  defineIntent({
    name: 'outlook.list_inbox_messages',
    effect: 'read',
    description:
      'List messages from the inbox folder specifically. Binds GET /v1.0/me/mailFolders/inbox/messages.',
    params: z.object({ folder: stringList.optional() }),
    expand: ({ folder }) => {
      const base: Constraint[] = [
        { path: 'method', op: 'eq', value: 'GET' },
        {
          path: 'url.pathname',
          op: 'eq',
          value: '/v1.0/me/mailFolders/inbox/messages',
        },
      ];
      if (folder) base.push(eqOrIn('query.$filter', folder));
      return base;
    },
  }),
];
