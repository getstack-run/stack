import { z } from 'zod';
import { defineIntent } from './types.js';

// Strapi v4/v5 — https://docs.strapi.io/dev-docs/api/rest.
// Content API paths are /api/{contentType}/…; admin / plugin routes
// live under /upload, /users-permissions, /i18n, /admin. The host
// is operator-specific so we allowlist via pathname only.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);
const esc = (s: string) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
const alt = (list: string[]) => (list.length === 1 ? esc(list[0]!) : `(${list.map(esc).join('|')})`);

export const strapiIntents = [
  defineIntent({
    name: 'strapi.find',
    effect: 'read',
    description:
      'List entries of a specific content type. Binds GET /api/{contentType} to the declared content type allowlist.',
    params: z.object({ content_type: idList }),
    expand: ({ content_type }) => {
      const list = toList(content_type);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/api/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'strapi.find_one',
    effect: 'read',
    description:
      'Fetch a single entry of a specific content type by ID. Binds GET /api/{contentType}/{id}.',
    params: z.object({ content_type: idList }),
    expand: ({ content_type }) => {
      const list = toList(content_type);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/api/${alt(list)}/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'strapi.create',
    effect: 'write',
    description:
      'Create a new entry for a specific content type. Binds POST /api/{contentType}.',
    params: z.object({ content_type: idList }),
    expand: ({ content_type }) => {
      const list = toList(content_type);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/api/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'strapi.update',
    effect: 'write',
    description:
      'Update a specific entry by ID. Binds PUT /api/{contentType}/{id}.',
    params: z.object({ content_type: idList }),
    expand: ({ content_type }) => {
      const list = toList(content_type);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/api/${alt(list)}/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'strapi.delete',
    effect: 'destructive',
    description:
      'Delete a specific entry by ID. Binds DELETE /api/{contentType}/{id}. Destructive.',
    params: z.object({ content_type: idList }),
    expand: ({ content_type }) => {
      const list = toList(content_type);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/api/${alt(list)}/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'strapi.upload_file',
    effect: 'write',
    description:
      'Upload a new file via the upload plugin. Binds POST /api/upload.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/upload' },
    ],
  }),

  defineIntent({
    name: 'strapi.list_files',
    effect: 'read',
    description:
      'List uploaded files. Binds GET /api/upload/files.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/upload/files' },
    ],
  }),

  defineIntent({
    name: 'strapi.delete_file',
    effect: 'destructive',
    description:
      'Delete an uploaded file by ID. Binds DELETE /api/upload/files/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/upload/files/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'strapi.list_folders',
    effect: 'read',
    description:
      'List upload folders. Binds GET /api/upload/folders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/upload/folders' },
    ],
  }),

  defineIntent({
    name: 'strapi.create_folder',
    effect: 'write',
    description:
      'Create an upload folder. Binds POST /api/upload/folders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/upload/folders' },
    ],
  }),

  defineIntent({
    name: 'strapi.delete_folder',
    effect: 'destructive',
    description:
      'Delete an upload folder by ID. Binds DELETE /api/upload/folders/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/upload/folders/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'strapi.send_email',
    effect: 'send',
    recipient_paths: ['body.to', 'body.cc', 'body.bcc'],
    description:
      'Send an email via the email plugin. Binds POST /api/email.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/email' },
    ],
  }),

  defineIntent({
    name: 'strapi.list_users',
    effect: 'read',
    description:
      'List users via the users-permissions plugin. Binds GET /api/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/users' },
    ],
  }),

  defineIntent({
    name: 'strapi.create_user',
    effect: 'write',
    description:
      'Create a user via the users-permissions plugin. Binds POST /api/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/users' },
    ],
  }),

  defineIntent({
    name: 'strapi.update_user',
    effect: 'write',
    description:
      'Update a user by ID. Binds PUT /api/users/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'strapi.delete_user',
    effect: 'destructive',
    description:
      'Delete a user by ID. Binds DELETE /api/users/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'strapi.list_user_roles',
    effect: 'read',
    description:
      'List configured user roles. Binds GET /api/users-permissions/roles.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/users-permissions/roles' },
    ],
  }),

  defineIntent({
    name: 'strapi.list_locales',
    effect: 'read',
    description:
      'List configured i18n locales. Binds GET /api/i18n/locales.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/i18n/locales' },
    ],
  }),

  defineIntent({
    name: 'strapi.admin_list_webhooks',
    effect: 'read',
    description:
      'List admin webhooks. Binds GET /admin/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/admin/webhooks' },
    ],
  }),

  defineIntent({
    name: 'strapi.admin_create_webhook',
    effect: 'write',
    description:
      'Create an admin webhook. Binds POST /admin/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/admin/webhooks' },
    ],
  }),
];
