import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// AgentMail API — https://docs.agentmail.to. Base: api.agentmail.to/v0/….
// Auth via Authorization Bearer header (the API key) — proxy injects this
// server-side so the agent never holds the raw token.
//
// Endpoint shapes verified against AgentMail's published OpenAPI surface
// as of 2026-05-03. The version prefix is /v0; if AgentMail bumps to /v1
// we re-pin the matches expressions here. Inbox IDs and message IDs are
// opaque path segments.

const idString = z.string().min(1).max(256);
const idList = z.union([idString, z.array(idString).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function escapeRegex(s: string): string {
  return s.replace(/[.\\+*?()|[\]{}^$]/g, (m) => `\\${m}`);
}

function pathEqOrAlt(template: (id: string) => string, ids: IdList): Constraint {
  const list = toList(ids);
  if (list.length === 1) {
    return { path: 'url.pathname', op: 'eq', value: template(list[0]!) };
  }
  const alt = list.map((id) => escapeRegex(template(id))).join('|');
  return { path: 'url.pathname', op: 'matches', value: `^(${alt})$` };
}

export const agentmailIntents = [
  // ─── Inboxes ──────────────────────────────────────────────────────
  defineIntent({
    name: 'agentmail.list_inboxes',
    effect: 'read',
    description: 'List all inboxes on the connected AgentMail account. Binds GET /v0/inboxes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v0/inboxes' },
    ],
  }),

  defineIntent({
    name: 'agentmail.create_inbox',
    effect: 'write',
    description: 'Create a new inbox. Binds POST /v0/inboxes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v0/inboxes' },
    ],
  }),

  defineIntent({
    name: 'agentmail.get_inbox',
    effect: 'read',
    description: 'Retrieve an inbox by id. Binds GET /v0/inboxes/{inbox_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.update_inbox',
    effect: 'write',
    description: 'Update an inbox by id. Binds PATCH /v0/inboxes/{inbox_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.delete_inbox',
    effect: 'destructive',
    description: 'Delete an inbox by id. Binds DELETE /v0/inboxes/{inbox_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+$' },
    ],
  }),

  // ─── Messages ─────────────────────────────────────────────────────
  defineIntent({
    name: 'agentmail.send_email',
    effect: 'send',
    recipient_paths: ['body.to', 'body.cc', 'body.bcc'],
    description:
      'Send an email from any inbox under the connected AgentMail account. Binds POST /v0/inboxes/{inbox_id}/messages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.send_email_from_inbox',
    effect: 'send',
    recipient_paths: ['body.to', 'body.cc', 'body.bcc'],
    description:
      'Send an email pinned to a specific allowlisted inbox id. Binds POST /v0/inboxes/{inbox_id}/messages with inbox_id fixed. Pass a single id or an allowlist.',
    params: z.object({ inbox_id: idList }),
    expand: ({ inbox_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      pathEqOrAlt((id) => `/v0/inboxes/${id}/messages`, inbox_id),
    ],
  }),

  defineIntent({
    name: 'agentmail.list_messages',
    effect: 'read',
    description: 'List messages in an inbox. Binds GET /v0/inboxes/{inbox_id}/messages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.list_messages_in_inbox',
    effect: 'read',
    description:
      'List messages pinned to a specific inbox id. Binds GET /v0/inboxes/{inbox_id}/messages with inbox_id fixed.',
    params: z.object({ inbox_id: idList }),
    expand: ({ inbox_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      pathEqOrAlt((id) => `/v0/inboxes/${id}/messages`, inbox_id),
    ],
  }),

  defineIntent({
    name: 'agentmail.get_message',
    effect: 'read',
    description: 'Retrieve a single message by id. Binds GET /v0/inboxes/{inbox_id}/messages/{message_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.update_message',
    effect: 'write',
    description: 'Update a message by id (e.g. mark read). Binds PATCH /v0/inboxes/{inbox_id}/messages/{message_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.delete_message',
    effect: 'destructive',
    description: 'Delete a message by id. Binds DELETE /v0/inboxes/{inbox_id}/messages/{message_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.reply_to_message',
    effect: 'send',
    description: 'Reply to a message. Binds POST /v0/inboxes/{inbox_id}/messages/{message_id}/reply.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages/[^/]+/reply$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.reply_all_to_message',
    effect: 'send',
    description: 'Reply-all to a message. Binds POST /v0/inboxes/{inbox_id}/messages/{message_id}/reply-all.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages/[^/]+/reply-all$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.forward_message',
    effect: 'send',
    recipient_paths: ['body.to', 'body.cc', 'body.bcc'],
    description: 'Forward a message. Binds POST /v0/inboxes/{inbox_id}/messages/{message_id}/forward.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages/[^/]+/forward$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.get_message_attachment',
    effect: 'read',
    description:
      'Retrieve a message attachment. Binds GET /v0/inboxes/{inbox_id}/messages/{message_id}/attachment.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/messages/[^/]+/attachment$' },
    ],
  }),

  // ─── Threads ──────────────────────────────────────────────────────
  defineIntent({
    name: 'agentmail.list_threads',
    effect: 'read',
    description: 'List threads in an inbox. Binds GET /v0/inboxes/{inbox_id}/threads.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/threads$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.get_thread',
    effect: 'read',
    description: 'Retrieve a thread by id. Binds GET /v0/inboxes/{inbox_id}/threads/{thread_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/threads/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.update_thread',
    effect: 'write',
    description: 'Update a thread by id. Binds PATCH /v0/inboxes/{inbox_id}/threads/{thread_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/threads/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.delete_thread',
    effect: 'destructive',
    description: 'Delete a thread by id. Binds DELETE /v0/inboxes/{inbox_id}/threads/{thread_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/threads/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.get_thread_attachment',
    effect: 'read',
    description:
      'Retrieve a thread attachment. Binds GET /v0/inboxes/{inbox_id}/threads/{thread_id}/attachment.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/inboxes/[^/]+/threads/[^/]+/attachment$' },
    ],
  }),

  // ─── Webhooks ─────────────────────────────────────────────────────
  defineIntent({
    name: 'agentmail.list_webhooks',
    effect: 'read',
    description: 'List configured webhooks. Binds GET /v0/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v0/webhooks' },
    ],
  }),

  defineIntent({
    name: 'agentmail.create_webhook',
    effect: 'write',
    description: 'Register a new webhook. Binds POST /v0/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v0/webhooks' },
    ],
  }),

  defineIntent({
    name: 'agentmail.get_webhook',
    effect: 'read',
    description: 'Retrieve a webhook by id. Binds GET /v0/webhooks/{webhook_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/webhooks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.update_webhook',
    effect: 'write',
    description: 'Update a webhook by id. Binds PATCH /v0/webhooks/{webhook_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/webhooks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'agentmail.delete_webhook',
    effect: 'destructive',
    description: 'Delete a webhook by id. Binds DELETE /v0/webhooks/{webhook_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v0/webhooks/[^/]+$' },
    ],
  }),
];
