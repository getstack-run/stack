import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Airtable API — https://airtable.com/developers/web/api/introduction.
// Base is api.airtable.com/v0/{baseId}/{tableIdOrName}. Intents scope on
// baseId and tableId to prevent cross-base or cross-table access.

const idRe = /^[A-Za-z0-9_]+$/;
const idToken = z.string().min(1).max(128).regex(idRe, 'must be alphanumeric/underscore');
const idList = z.union([idToken, z.array(idToken).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function alt(ids: IdList): string {
  const list = toList(ids);
  return list.length === 1 ? list[0]! : `(${list.join('|')})`;
}

function tablePath(baseId: string, tableId: IdList, suffix: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v0/${baseId}/${alt(tableId)}${suffix}$`,
  };
}

export const airtableIntents = [
  defineIntent({
    name: 'airtable.list_records',
    effect: 'read',
    description:
      'List records from specific tables in a base. Binds GET /v0/{baseId}/{tableId}.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      tablePath(base_id, table_id, ''),
    ],
  }),

  defineIntent({
    name: 'airtable.get_record',
    effect: 'read',
    description:
      'Read a single record from specific tables. Binds GET /v0/{baseId}/{tableId}/{recordId}.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      tablePath(base_id, table_id, '/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'airtable.create_records',
    effect: 'write',
    description:
      'Create records in specific tables. Binds POST /v0/{baseId}/{tableId}.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      tablePath(base_id, table_id, ''),
    ],
  }),

  defineIntent({
    name: 'airtable.update_records',
    effect: 'write',
    description:
      'Patch (non-destructive update) records in specific tables. Binds PATCH /v0/{baseId}/{tableId}(/{recordId})?.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      tablePath(base_id, table_id, '(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'airtable.replace_records',
    effect: 'write',
    description:
      'Replace (destructive update) records in specific tables. Binds PUT /v0/{baseId}/{tableId}(/{recordId})?. Overwrites unspecified fields.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      tablePath(base_id, table_id, '(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'airtable.delete_records',
    effect: 'destructive',
    description:
      'Delete records from specific tables. Binds DELETE /v0/{baseId}/{tableId}(/{recordId})?. Destructive.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      tablePath(base_id, table_id, '(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'airtable.upsert_records',
    effect: 'write',
    description:
      'Upsert records in specific tables using performUpsert merge. Binds PATCH /v0/{baseId}/{tableId} with body.performUpsert pinned.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      tablePath(base_id, table_id, ''),
      { path: 'body.performUpsert', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'airtable.list_bases',
    effect: 'read',
    description:
      'List all bases visible to the authenticated token. Binds GET /v0/meta/bases.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v0/meta/bases' },
    ],
  }),

  defineIntent({
    name: 'airtable.get_base_schema',
    effect: 'read',
    description:
      'Read the table/field schema of a specific base. Binds GET /v0/meta/bases/{baseId}/tables.',
    params: z.object({ base_id: idToken }),
    expand: ({ base_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: `/v0/meta/bases/${base_id}/tables`,
      },
    ],
  }),

  defineIntent({
    name: 'airtable.create_table',
    effect: 'write',
    description:
      'Create a new table in a specific base. Binds POST /v0/meta/bases/{baseId}/tables.',
    params: z.object({ base_id: idToken }),
    expand: ({ base_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: `/v0/meta/bases/${base_id}/tables`,
      },
    ],
  }),

  defineIntent({
    name: 'airtable.update_table',
    effect: 'write',
    description:
      'Update a table (rename, description) in a specific base. Binds PATCH /v0/meta/bases/{baseId}/tables/{tableId}.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/v0/meta/bases/${base_id}/tables/${alt(table_id)}$`,
      },
    ],
  }),

  defineIntent({
    name: 'airtable.create_field',
    effect: 'write',
    description:
      'Create a new field on a specific table. Binds POST /v0/meta/bases/{baseId}/tables/{tableId}/fields.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/v0/meta/bases/${base_id}/tables/${alt(table_id)}/fields$`,
      },
    ],
  }),

  defineIntent({
    name: 'airtable.list_webhooks',
    effect: 'read',
    description:
      'List webhooks configured on a specific base. Binds GET /v0/bases/{baseId}/webhooks.',
    params: z.object({ base_id: idToken }),
    expand: ({ base_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: `/v0/bases/${base_id}/webhooks`,
      },
    ],
  }),

  defineIntent({
    name: 'airtable.create_webhook',
    effect: 'write',
    description:
      'Register a webhook on a specific base. Binds POST /v0/bases/{baseId}/webhooks.',
    params: z.object({ base_id: idToken }),
    expand: ({ base_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: `/v0/bases/${base_id}/webhooks`,
      },
    ],
  }),

  defineIntent({
    name: 'airtable.delete_webhook',
    effect: 'destructive',
    description:
      'Delete a webhook from a specific base. Binds DELETE /v0/bases/{baseId}/webhooks/{webhookId}. Destructive.',
    params: z.object({ base_id: idToken }),
    expand: ({ base_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/v0/bases/${base_id}/webhooks/[^/]+$`,
      },
    ],
  }),

  defineIntent({
    name: 'airtable.manage_comments',
    effect: 'destructive',
    description:
      'Create, update, and delete record comments in specific tables. Binds POST/PATCH/DELETE /v0/{baseId}/{tableId}/{recordId}/comments(/{commentId})?.',
    params: z.object({ base_id: idToken, table_id: idList }),
    expand: ({ base_id, table_id }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/v0/${base_id}/${alt(table_id)}/[^/]+/comments(/[^/]+)?$`,
      },
    ],
  }),

  defineIntent({
    name: 'airtable.get_whoami',
    effect: 'read',
    description:
      'Read metadata about the authenticated user/token. Binds GET /v0/meta/whoami.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v0/meta/whoami' },
    ],
  }),
];
