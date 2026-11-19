import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Supabase REST (PostgREST) — https://supabase.com/docs/guides/api.
// Base: {project}.supabase.co/rest/v1/{table}. Host varies per project;
// intents gate on pathname only. Supabase's MCP incident (Apr 2025)
// hinged on a service-role key with full table access — these intents
// let you grant per-table scope instead.

const tableList = z.union([
  z.string().min(1).max(128),
  z.array(z.string().min(1).max(128)).min(1),
]);
type TableList = z.infer<typeof tableList>;
const toList = (v: TableList): string[] => (Array.isArray(v) ? v : [v]);

function pathConstraint(table: TableList): Constraint {
  const list = toList(table);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return { path: 'url.pathname', op: 'matches', value: `^/rest/v1/${alt}$` };
}

export const supabaseIntents = [
  defineIntent({
    name: 'supabase.select_table',
    effect: 'read',
    description:
      'Read rows from specific Supabase tables. Binds GET /rest/v1/{table} to the declared table allowlist.',
    params: z.object({ table: tableList }),
    expand: ({ table }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      pathConstraint(table),
    ],
  }),

  defineIntent({
    name: 'supabase.insert_to_table',
    effect: 'write',
    description:
      'Insert rows into specific Supabase tables. Binds POST /rest/v1/{table}.',
    params: z.object({ table: tableList }),
    expand: ({ table }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      pathConstraint(table),
    ],
  }),

  defineIntent({
    name: 'supabase.update_in_table',
    effect: 'write',
    description:
      'Update rows in specific Supabase tables. Binds PATCH /rest/v1/{table}.',
    params: z.object({ table: tableList }),
    expand: ({ table }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      pathConstraint(table),
    ],
  }),

  defineIntent({
    name: 'supabase.delete_from_table',
    effect: 'destructive',
    description:
      'Delete rows from specific Supabase tables. Destructive, prefer a narrow allowlist and consider additional body constraints.',
    params: z.object({ table: tableList }),
    expand: ({ table }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      pathConstraint(table),
    ],
  }),

  defineIntent({
    name: 'supabase.upsert_to_table',
    effect: 'write',
    description:
      'Upsert rows into specific Supabase tables using PostgREST Prefer: resolution. Binds POST /rest/v1/{table}.',
    params: z.object({ table: tableList }),
    expand: ({ table }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      pathConstraint(table),
    ],
  }),

  defineIntent({
    name: 'supabase.call_rpc',
    effect: 'write',
    description:
      'Invoke specific Postgres functions via PostgREST RPC. Binds POST /rest/v1/rpc/{function} to the declared function allowlist.',
    params: z.object({ function: tableList }),
    expand: ({ function: fn }) => {
      const list = toList(fn);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/rest/v1/rpc/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'supabase.auth_list_users',
    effect: 'read',
    description:
      'List authenticated users via the Supabase Auth admin API. Binds GET /auth/v1/admin/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/auth/v1/admin/users' },
    ],
  }),

  defineIntent({
    name: 'supabase.auth_create_user',
    effect: 'write',
    description:
      'Create a new user via the Supabase Auth admin API. Binds POST /auth/v1/admin/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/auth/v1/admin/users' },
    ],
  }),

  defineIntent({
    name: 'supabase.auth_update_user',
    effect: 'write',
    description:
      'Update an existing user via the Supabase Auth admin API. Binds PUT /auth/v1/admin/users/{uid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/auth/v1/admin/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'supabase.auth_delete_user',
    effect: 'destructive',
    description:
      'Delete a user via the Supabase Auth admin API. Binds DELETE /auth/v1/admin/users/{uid}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/auth/v1/admin/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'supabase.list_buckets',
    effect: 'read',
    description:
      'List storage buckets for the project. Binds GET /storage/v1/bucket.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/storage/v1/bucket' },
    ],
  }),

  defineIntent({
    name: 'supabase.create_bucket',
    effect: 'write',
    description:
      'Create a new storage bucket. Binds POST /storage/v1/bucket.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/storage/v1/bucket' },
    ],
  }),

  defineIntent({
    name: 'supabase.manage_bucket',
    effect: 'destructive',
    description:
      'Update or delete specific storage buckets. Binds PUT/DELETE /storage/v1/bucket/{bucket} to the declared bucket allowlist.',
    params: z.object({ bucket: tableList }),
    expand: ({ bucket }) => {
      const list = toList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'in', value: ['PUT', 'DELETE'] },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/bucket/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'supabase.read_object',
    effect: 'read',
    description:
      'Download objects from specific storage buckets. Binds GET /storage/v1/object/{bucket}/... to the declared bucket allowlist.',
    params: z.object({ bucket: tableList }),
    expand: ({ bucket }) => {
      const list = toList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/object/(authenticated/|public/)?${alt}/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'supabase.upload_object',
    effect: 'write',
    description:
      'Upload or overwrite objects in specific storage buckets. Binds POST/PUT /storage/v1/object/{bucket}/... to the declared bucket allowlist.',
    params: z.object({ bucket: tableList }),
    expand: ({ bucket }) => {
      const list = toList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'in', value: ['POST', 'PUT'] },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/object/${alt}/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'supabase.delete_object',
    effect: 'destructive',
    description:
      'Delete objects from specific storage buckets. Binds DELETE /storage/v1/object/{bucket}/... to the declared bucket allowlist. Destructive.',
    params: z.object({ bucket: tableList }),
    expand: ({ bucket }) => {
      const list = toList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/object/${alt}/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'supabase.sign_object_url',
    effect: 'write',
    description:
      'Generate a signed URL for an object in specific buckets. Binds POST /storage/v1/object/sign/{bucket}/... to the declared bucket allowlist.',
    params: z.object({ bucket: tableList }),
    expand: ({ bucket }) => {
      const list = toList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/object/sign/${alt}/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'supabase.list_bucket_objects',
    effect: 'read',
    description:
      'List objects in a specific storage bucket. Binds POST /storage/v1/object/list/{bucket} to the declared bucket allowlist.',
    params: z.object({ bucket: tableList }),
    expand: ({ bucket }) => {
      const list = toList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/object/list/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'supabase.realtime_connect',
    effect: 'read',
    description:
      'Connect to the Realtime websocket endpoint. Binds GET /realtime/v1/websocket (upgrade).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/realtime/v1/websocket' },
    ],
  }),
];
