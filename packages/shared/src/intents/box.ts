import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Box API v2 — https://developer.box.com/reference. Base is
// api.box.com/2.0/{resource}. File and folder IDs appear in the path,
// so intents scope on ID where provided.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function idAlt(ids: IdList): string {
  const list = toList(ids);
  const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
}

function boxPath(resource: string, ids: IdList, suffix: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/2.0/${resource}/${idAlt(ids)}${suffix}$`,
  };
}

export const boxIntents = [
  defineIntent({
    name: 'box.get_file',
    effect: 'read',
    description:
      'Read metadata for specific Box files. Binds GET /2.0/files/{id} to the declared file allowlist.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      boxPath('files', file_id, ''),
    ],
  }),

  defineIntent({
    name: 'box.download_file',
    effect: 'read',
    description:
      'Download content for specific Box files. Binds GET /2.0/files/{id}/content to the declared file allowlist.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      boxPath('files', file_id, '/content'),
    ],
  }),

  defineIntent({
    name: 'box.upload_file',
    effect: 'write',
    description:
      'Upload a new file to Box via the upload host. Binds POST https://upload.box.com/api/2.0/files/content.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'upload.box.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2.0/files/content' },
    ],
  }),

  defineIntent({
    name: 'box.delete_file',
    effect: 'destructive',
    description:
      'Delete specific Box files. Binds DELETE /2.0/files/{id} to the declared file allowlist. Destructive.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      boxPath('files', file_id, ''),
    ],
  }),

  defineIntent({
    name: 'box.copy_file',
    effect: 'write',
    description:
      'Copy specific Box files into another folder. Binds POST /2.0/files/{id}/copy.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      boxPath('files', file_id, '/copy'),
    ],
  }),

  defineIntent({
    name: 'box.update_file',
    effect: 'write',
    description:
      'Rename, move, or update metadata on specific Box files. Binds PUT /2.0/files/{id}.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      boxPath('files', file_id, ''),
    ],
  }),

  defineIntent({
    name: 'box.get_folder',
    effect: 'read',
    description:
      'Read metadata for specific Box folders. Binds GET /2.0/folders/{id} to the declared folder allowlist.',
    params: z.object({ folder_id: idList }),
    expand: ({ folder_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      boxPath('folders', folder_id, ''),
    ],
  }),

  defineIntent({
    name: 'box.list_folder_items',
    effect: 'read',
    description:
      'List items in specific Box folders. Binds GET /2.0/folders/{id}/items to the declared folder allowlist.',
    params: z.object({ folder_id: idList }),
    expand: ({ folder_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      boxPath('folders', folder_id, '/items'),
    ],
  }),

  defineIntent({
    name: 'box.create_folder',
    effect: 'write',
    description:
      'Create a new folder. Binds POST /2.0/folders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2.0/folders' },
    ],
  }),

  defineIntent({
    name: 'box.manage_folder',
    effect: 'destructive',
    description:
      'Rename, move, or delete specific Box folders. Binds PUT/DELETE /2.0/folders/{id} to the declared folder allowlist. Destructive for DELETE.',
    params: z.object({ folder_id: idList }),
    expand: ({ folder_id }) => [
      { path: 'method', op: 'in', value: ['PUT', 'DELETE'] },
      boxPath('folders', folder_id, ''),
    ],
  }),

  defineIntent({
    name: 'box.manage_collaborations',
    effect: 'send',
    recipient_paths: ['body.accessible_by.id', 'body.accessible_by.login'],
    description:
      'Create, update, and delete collaborations (shares). Binds POST/PUT/DELETE /2.0/collaborations(/{id})?.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/2.0/collaborations(/[^/]+)?$',
      },
    ],
  }),

  defineIntent({
    name: 'box.create_shared_link',
    effect: 'send',
    description:
      'Create or update a shared link on specific files. Binds PUT /2.0/files/{id} with body.shared_link pinned.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      boxPath('files', file_id, ''),
      { path: 'body.shared_link', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'box.manage_comments',
    effect: 'destructive',
    description:
      'Create, update, and delete comments on Box items. Binds POST/PUT/DELETE /2.0/comments(/{id})?.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/2.0/comments(/[^/]+)?$',
      },
    ],
  }),

  defineIntent({
    name: 'box.manage_tasks',
    effect: 'destructive',
    description:
      'Create, update, and delete tasks on Box items. Binds POST/PUT/DELETE /2.0/tasks(/{id})?.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/2.0/tasks(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'box.read_users',
    effect: 'read',
    description:
      'Read enterprise user directory. Binds GET /2.0/users(/{id})?.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/2.0/users(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'box.read_groups',
    effect: 'read',
    description:
      'Read enterprise group membership. Binds GET /2.0/groups(/{id}(/memberships)?)?.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/2.0/groups(/[^/]+(/memberships)?)?$',
      },
    ],
  }),

  defineIntent({
    name: 'box.read_events',
    effect: 'read',
    description:
      'Read the enterprise or user event stream. Binds GET /2.0/events.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/2.0/events' },
    ],
  }),

  defineIntent({
    name: 'box.search',
    effect: 'read',
    description:
      'Search the Box content graph. Binds GET /2.0/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/2.0/search' },
    ],
  }),
];
