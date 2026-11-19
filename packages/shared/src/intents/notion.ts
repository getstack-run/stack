import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Notion API — https://developers.notion.com/reference. All requests go
// to api.notion.com/v1/…. Pages and databases are identified by UUID
// (dashed or undashed). Intents gate on the pathname + body parent IDs.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function eqOrIn(path: string, ids: IdList): Constraint {
  const list = toList(ids);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

export const notionIntents = [
  defineIntent({
    name: 'notion.query_database',
    effect: 'read',
    description:
      'Query one or more specific Notion databases. Binds POST /v1/databases/{id}/query to the declared database IDs.',
    params: z.object({ database_id: idList }),
    expand: ({ database_id }) => {
      const list = toList(database_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/databases/${alt}/query$` },
      ];
    },
  }),

  defineIntent({
    name: 'notion.create_page_in_database',
    effect: 'write',
    description:
      'Create a new page whose parent is a specific Notion database. Binds POST /v1/pages with body.parent.database_id pinned.',
    params: z.object({ database_id: idList }),
    expand: ({ database_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/pages' },
      eqOrIn('body.parent.database_id', database_id),
    ],
  }),

  defineIntent({
    name: 'notion.update_page',
    effect: 'write',
    description:
      'Update the properties of specific Notion pages. Binds PATCH /v1/pages/{id} to the declared page IDs.',
    params: z.object({ page_id: idList }),
    expand: ({ page_id }) => {
      const list = toList(page_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'PATCH' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/pages/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'notion.read_page',
    effect: 'read',
    description:
      'Read specific Notion pages. Binds GET /v1/pages/{id} to the declared page IDs.',
    params: z.object({ page_id: idList }),
    expand: ({ page_id }) => {
      const list = toList(page_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/pages/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'notion.archive_page',
    effect: 'write',
    description:
      'Archive or unarchive a Notion page by toggling the archived flag. Binds PATCH /v1/pages/{id} (constraint is pathname-only; callers must set body.archived).',
    params: z.object({ page_id: idList }),
    expand: ({ page_id }) => {
      const list = toList(page_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'PATCH' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/pages/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'notion.retrieve_page_property',
    effect: 'read',
    description:
      'Retrieve a property value from a Notion page. Binds GET /v1/pages/{id}/properties/{prop}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/pages/[^/]+/properties/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'notion.create_page_under_page',
    effect: 'write',
    description:
      'Create a subpage whose parent is another Notion page. Binds POST /v1/pages with body.parent.page_id pinned.',
    params: z.object({ parent_page_id: idList }),
    expand: ({ parent_page_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/pages' },
      eqOrIn('body.parent.page_id', parent_page_id),
    ],
  }),

  defineIntent({
    name: 'notion.create_database',
    effect: 'write',
    description:
      'Create a new Notion database under a parent page. Binds POST /v1/databases.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/databases' },
    ],
  }),

  defineIntent({
    name: 'notion.update_database',
    effect: 'write',
    description:
      'Update the schema or metadata of a Notion database. Binds PATCH /v1/databases/{id}.',
    params: z.object({ database_id: idList }),
    expand: ({ database_id }) => {
      const list = toList(database_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'PATCH' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/databases/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'notion.retrieve_database',
    effect: 'read',
    description:
      'Retrieve a Notion database schema. Binds GET /v1/databases/{id}.',
    params: z.object({ database_id: idList }),
    expand: ({ database_id }) => {
      const list = toList(database_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/databases/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'notion.list_block_children',
    effect: 'read',
    description:
      'List the children of a Notion block (page or container). Binds GET /v1/blocks/{id}/children.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/blocks/[^/]+/children$' },
    ],
  }),

  defineIntent({
    name: 'notion.append_block_children',
    effect: 'write',
    description:
      'Append child blocks to a Notion block. Binds PATCH /v1/blocks/{id}/children.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/blocks/[^/]+/children$' },
    ],
  }),

  defineIntent({
    name: 'notion.retrieve_block',
    effect: 'read',
    description:
      'Retrieve a single Notion block by ID. Binds GET /v1/blocks/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/blocks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'notion.update_block',
    effect: 'write',
    description:
      'Update a Notion block in place. Binds PATCH /v1/blocks/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/blocks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'notion.delete_block',
    effect: 'destructive',
    description:
      'Delete (archive) a Notion block. Binds DELETE /v1/blocks/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/blocks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'notion.search',
    effect: 'read',
    description:
      'Search across accessible Notion pages and databases. Binds POST /v1/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/search' },
    ],
  }),

  defineIntent({
    name: 'notion.list_users',
    effect: 'read',
    description:
      'List workspace users in Notion. Binds GET /v1/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/users' },
    ],
  }),

  defineIntent({
    name: 'notion.list_comments',
    effect: 'read',
    description:
      'List comments on a Notion block or page. Binds GET /v1/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/comments' },
    ],
  }),

  defineIntent({
    name: 'notion.create_comment',
    effect: 'write',
    description:
      'Create a comment on a Notion page or discussion. Binds POST /v1/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/comments' },
    ],
  }),

  defineIntent({
    name: 'notion.create_file_upload',
    effect: 'write',
    description:
      'Initiate a Notion file upload. Binds POST /v1/file_uploads.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/file_uploads' },
    ],
  }),
];
