import { z } from 'zod';
import { defineIntent } from './types.js';

// Gmail API — https://developers.google.com/gmail/api. Calls go to
// gmail.googleapis.com/gmail/v1/users/me/…. The email body (`raw` field)
// is base64url-encoded RFC 822. The constraint engine decodes its headers
// with the one bounded, fail-closed reader (utils/rfc822.ts, through
// utils/derived-email.ts) into `derived.email.recipients` (To + Cc + Bcc,
// lowercased) and `derived.email.text`, so recipient allowlists are
// enforceable on messages/send. A message that cannot be read has no derived
// recipients, and a recipient constraint then refuses it. Sending a stored
// draft by id carries no message, so its recipients cannot be named.
//
// Label IDs (`Label_123` or system labels like `INBOX`, `SENT`) can be
// passed via body paths for scoping label operations.

const labelList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
const emailAddress = z.string().min(3).max(254).regex(/^[^\s@<>",;]+@[^\s@<>",;]+$/, 'Must be a plain email address');
const emailList = z.union([emailAddress, z.array(emailAddress).min(1).max(100)]);

export const gmailIntents = [
  defineIntent({
    name: 'gmail.send_email',
    effect: 'send',
    recipient_paths: ['derived.email.recipients'],
    description:
      'Send email from the authenticated account to any recipient. Binds POST /gmail/v1/users/me/messages/send. Use gmail.send_email_to to limit recipients.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/messages/send' },
    ],
  }),

  defineIntent({
    name: 'gmail.send_email_to',
    effect: 'send',
    recipient_paths: ['derived.email.recipients'],
    description:
      'Send email only to allowlisted addresses. Binds POST /gmail/v1/users/me/messages/send and requires every To, Cc and Bcc address in the message to be on the list. A message whose headers cannot be read is refused.',
    params: z.object({ to: emailList }),
    expand: ({ to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/messages/send' },
      {
        path: 'derived.email.recipients',
        op: 'in',
        value: [...new Set((Array.isArray(to) ? to : [to]).map((a) => a.toLowerCase()))],
      },
    ],
  }),

  defineIntent({
    name: 'gmail.create_draft',
    effect: 'write',
    description:
      'Create an email draft (not sent). Binds POST /gmail/v1/users/me/drafts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/drafts' },
    ],
  }),

  defineIntent({
    name: 'gmail.read_messages',
    effect: 'read',
    description:
      'Read-only access to the mailbox. Binds GET on /gmail/v1/users/me/messages and /gmail/v1/users/me/threads.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/gmail/v1/users/me/(messages|threads)(/[^/]+)?$',
      },
    ],
  }),

  defineIntent({
    name: 'gmail.list_messages',
    effect: 'read',
    description:
      'List message IDs matching a query string. Binds GET /gmail/v1/users/me/messages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/messages' },
    ],
  }),

  defineIntent({
    name: 'gmail.get_message',
    effect: 'read',
    description:
      'Fetch a single message including headers and body. Binds GET /gmail/v1/users/me/messages/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/messages/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gmail.delete_message',
    effect: 'destructive',
    description:
      'Permanently delete a single message (skips trash). Binds DELETE /gmail/v1/users/me/messages/{id} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/messages/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gmail.trash_message',
    effect: 'write',
    description:
      'Move a message to the trash (recoverable). Binds POST /gmail/v1/users/me/messages/{id}/trash.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/messages/[^/]+/trash$' },
    ],
  }),

  defineIntent({
    name: 'gmail.untrash_message',
    effect: 'write',
    description:
      'Restore a message from trash. Binds POST /gmail/v1/users/me/messages/{id}/untrash.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/messages/[^/]+/untrash$' },
    ],
  }),

  defineIntent({
    name: 'gmail.modify_message_labels',
    effect: 'write',
    description:
      'Add or remove labels on a single message. Binds POST /gmail/v1/users/me/messages/{id}/modify.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/messages/[^/]+/modify$' },
    ],
  }),

  defineIntent({
    name: 'gmail.batch_modify_messages',
    effect: 'write',
    description:
      'Add or remove labels on up to 1000 messages at once. Binds POST /gmail/v1/users/me/messages/batchModify.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/messages/batchModify' },
    ],
  }),

  defineIntent({
    name: 'gmail.batch_delete_messages',
    effect: 'destructive',
    description:
      'Permanently delete up to 1000 messages at once. Binds POST /gmail/v1/users/me/messages/batchDelete — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/messages/batchDelete' },
    ],
  }),

  defineIntent({
    name: 'gmail.list_threads',
    effect: 'read',
    description:
      'List thread IDs matching a query string. Binds GET /gmail/v1/users/me/threads.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/threads' },
    ],
  }),

  defineIntent({
    name: 'gmail.get_thread',
    effect: 'read',
    description:
      'Fetch a full thread with all messages. Binds GET /gmail/v1/users/me/threads/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/threads/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gmail.modify_thread_labels',
    effect: 'write',
    description:
      'Add or remove labels on all messages in a thread. Binds POST /gmail/v1/users/me/threads/{id}/modify.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/threads/[^/]+/modify$' },
    ],
  }),

  defineIntent({
    name: 'gmail.list_labels',
    effect: 'read',
    description:
      'List all labels in the mailbox. Binds GET /gmail/v1/users/me/labels.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/labels' },
    ],
  }),

  defineIntent({
    name: 'gmail.create_label',
    effect: 'write',
    description:
      'Create a new user label. Binds POST /gmail/v1/users/me/labels.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/labels' },
    ],
  }),

  defineIntent({
    name: 'gmail.delete_label',
    effect: 'destructive',
    description:
      'Delete a user label. Binds DELETE /gmail/v1/users/me/labels/{id}.',
    params: z.object({ labelId: labelList }),
    expand: ({ labelId }) => {
      const list = Array.isArray(labelId) ? labelId : [labelId];
      const escaped = list.map((r) => r.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/gmail/v1/users/me/labels/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'gmail.update_draft',
    effect: 'write',
    description:
      'Replace the contents of an existing draft. Binds PUT /gmail/v1/users/me/drafts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/drafts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gmail.send_draft',
    effect: 'send',
    description:
      'Send an existing draft. Binds POST /gmail/v1/users/me/drafts/send.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/drafts/send' },
    ],
  }),

  defineIntent({
    name: 'gmail.list_drafts',
    effect: 'read',
    description:
      'List all drafts in the mailbox. Binds GET /gmail/v1/users/me/drafts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/drafts' },
    ],
  }),

  defineIntent({
    name: 'gmail.delete_draft',
    effect: 'destructive',
    description:
      'Permanently delete a draft. Binds DELETE /gmail/v1/users/me/drafts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/drafts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gmail.list_filters',
    effect: 'read',
    description:
      'List mail server-side filters. Binds GET /gmail/v1/users/me/settings/filters.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/settings/filters' },
    ],
  }),

  defineIntent({
    name: 'gmail.create_filter',
    effect: 'send',
    recipient_paths: ['body.action.forward'],
    description:
      'Create a server-side filter rule. Binds POST /gmail/v1/users/me/settings/filters.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/settings/filters' },
    ],
  }),

  defineIntent({
    name: 'gmail.delete_filter',
    effect: 'destructive',
    description:
      'Delete a server-side filter. Binds DELETE /gmail/v1/users/me/settings/filters/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/gmail/v1/users/me/settings/filters/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gmail.list_forwarding_addresses',
    effect: 'read',
    description:
      'List verified forwarding addresses. Binds GET /gmail/v1/users/me/settings/forwardingAddresses.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/settings/forwardingAddresses' },
    ],
  }),

  defineIntent({
    name: 'gmail.get_attachment',
    effect: 'read',
    description:
      'Download a message attachment by ID. Binds GET /gmail/v1/users/me/messages/{id}/attachments/{aid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/gmail/v1/users/me/messages/[^/]+/attachments/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'gmail.get_profile',
    effect: 'read',
    description:
      'Fetch mailbox profile (email address, total messages, history id). Binds GET /gmail/v1/users/me/profile.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/profile' },
    ],
  }),

  defineIntent({
    name: 'gmail.watch_mailbox',
    effect: 'write',
    description:
      'Set up Pub/Sub push notifications for mailbox changes. Binds POST /gmail/v1/users/me/watch.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/gmail/v1/users/me/watch' },
    ],
  }),
];
