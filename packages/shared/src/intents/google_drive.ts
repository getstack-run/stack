import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Google Drive API v3 — https://developers.google.com/drive/api/v3.
// Metadata + reads go through www.googleapis.com/drive/v3/files…;
// uploads go through www.googleapis.com/upload/drive/v3/files.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function pathmatch(ids: IdList, suffix: string): Constraint {
  const list = toList(ids);
  const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/drive/v3/files/${alt}${suffix}$`,
  };
}

export const googleDriveIntents = [
  defineIntent({
    name: 'google_drive.read_file',
    effect: 'read',
    description:
      'Read metadata and content for specific Drive files. Binds GET /drive/v3/files/{id} to the declared file IDs.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      pathmatch(file_id, ''),
    ],
  }),

  defineIntent({
    name: 'google_drive.export_file',
    effect: 'read',
    description:
      'Export a Google Doc/Sheet to a format (PDF, CSV, etc.). Binds GET /drive/v3/files/{id}/export.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      pathmatch(file_id, '/export'),
    ],
  }),

  defineIntent({
    name: 'google_drive.list_in_folder',
    effect: 'read',
    description:
      'List files in specific parent folder(s). Binds GET /drive/v3/files + query.q to contain the folder ID.',
    params: z.object({ folder_id: idList }),
    expand: ({ folder_id }) => {
      const list = toList(folder_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'eq', value: '/drive/v3/files' },
        { path: 'query.q', op: 'matches', value: `'${alt}'\\s+in\\s+parents` },
      ];
    },
  }),

  defineIntent({
    name: 'google_drive.create_in_folder',
    effect: 'write',
    description:
      'Create a new file whose parent is a specific folder. Binds POST /drive/v3/files (or the upload endpoint) with body.parents pinned.',
    params: z.object({ folder_id: z.string().min(1) }),
    expand: ({ folder_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^(/drive/v3/files|/upload/drive/v3/files)$',
      },
      { path: 'body.parents.0', op: 'eq', value: folder_id },
    ],
  }),

  defineIntent({
    name: 'google_drive.list_files',
    effect: 'read',
    description:
      'List files visible to the caller with optional filters applied server-side. Binds GET /drive/v3/files.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/drive/v3/files' },
    ],
  }),

  defineIntent({
    name: 'google_drive.get_file_metadata',
    effect: 'read',
    description:
      'Fetch file metadata without content. Binds GET /drive/v3/files/{id} to the declared file IDs.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      pathmatch(file_id, ''),
    ],
  }),

  defineIntent({
    name: 'google_drive.delete_file',
    effect: 'destructive',
    description:
      'Permanently delete specific Drive files. Binds DELETE /drive/v3/files/{id} to the declared file IDs. Destructive.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      pathmatch(file_id, ''),
    ],
  }),

  defineIntent({
    name: 'google_drive.copy_file',
    effect: 'write',
    description:
      'Create a copy of specific files. Binds POST /drive/v3/files/{id}/copy to the declared file IDs.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      pathmatch(file_id, '/copy'),
    ],
  }),

  defineIntent({
    name: 'google_drive.update_file',
    effect: 'write',
    description:
      'Update metadata (including rename) or media for specific files. Binds PATCH /drive/v3/files/{id} to the declared IDs.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      pathmatch(file_id, ''),
    ],
  }),

  defineIntent({
    name: 'google_drive.move_file',
    effect: 'write',
    description:
      'Move a file into a specific destination folder. Binds PATCH /drive/v3/files/{id} with body.addParents pinned to the target folder.',
    params: z.object({ file_id: idList, destination_folder_id: z.string().min(1) }),
    expand: ({ file_id, destination_folder_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      pathmatch(file_id, ''),
      { path: 'body.addParents', op: 'eq', value: destination_folder_id },
    ],
  }),

  defineIntent({
    name: 'google_drive.watch_file',
    effect: 'write',
    description:
      'Subscribe to change notifications on specific files. Binds POST /drive/v3/files/{id}/watch to the declared IDs.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      pathmatch(file_id, '/watch'),
    ],
  }),

  defineIntent({
    name: 'google_drive.manage_permissions',
    effect: 'send',
    recipient_paths: ['body.type', 'body.emailAddress', 'body.domain'],
    description:
      'Create, update, and delete permissions on specific files or folders. Binds POST/PATCH/DELETE /drive/v3/files/{id}/permissions(/{pid})?.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => {
      const list = toList(file_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/drive/v3/files/${alt}/permissions(/[^/]+)?$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'google_drive.read_permissions',
    effect: 'read',
    description:
      'List or read permission entries on specific files. Binds GET /drive/v3/files/{id}/permissions(/{pid})?.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => {
      const list = toList(file_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/drive/v3/files/${alt}/permissions(/[^/]+)?$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'google_drive.manage_comments',
    effect: 'destructive',
    description:
      'Create, update, and delete comments on specific files. Binds POST/PATCH/DELETE /drive/v3/files/{id}/comments(/{cid})?.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => {
      const list = toList(file_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/drive/v3/files/${alt}/comments(/[^/]+)?$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'google_drive.manage_replies',
    effect: 'destructive',
    description:
      'Create, update, and delete replies on comments in specific files. Binds POST/PATCH/DELETE /drive/v3/files/{id}/comments/{cid}/replies(/{rid})?.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => {
      const list = toList(file_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/drive/v3/files/${alt}/comments/[^/]+/replies(/[^/]+)?$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'google_drive.read_revisions',
    effect: 'read',
    description:
      'List or read revision metadata for specific files. Binds GET /drive/v3/files/{id}/revisions(/{rid})?.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => {
      const list = toList(file_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/drive/v3/files/${alt}/revisions(/[^/]+)?$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'google_drive.manage_revisions',
    effect: 'destructive',
    description:
      'Update or delete revisions on specific files. Binds PATCH/DELETE /drive/v3/files/{id}/revisions/{rid}. Destructive.',
    params: z.object({ file_id: idList }),
    expand: ({ file_id }) => {
      const list = toList(file_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'in', value: ['PATCH', 'DELETE'] },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/drive/v3/files/${alt}/revisions/[^/]+$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'google_drive.list_shared_drives',
    effect: 'read',
    description:
      'List shared drives visible to the caller. Binds GET /drive/v3/drives.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/drive/v3/drives' },
    ],
  }),

  defineIntent({
    name: 'google_drive.read_shared_drive',
    effect: 'read',
    description:
      'Read metadata for a specific shared drive. Binds GET /drive/v3/drives/{id}.',
    params: z.object({ drive_id: idList }),
    expand: ({ drive_id }) => {
      const list = toList(drive_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/drive/v3/drives/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'google_drive.manage_shared_drives',
    effect: 'destructive',
    description:
      'Create, rename, hide, or delete shared drives. Binds POST /drive/v3/drives and PATCH/DELETE /drive/v3/drives/{id}. Destructive for DELETE.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/drive/v3/drives(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'google_drive.read_about',
    effect: 'read',
    description:
      'Read quota, user, and importFormats metadata for the authenticated account. Binds GET /drive/v3/about.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/drive/v3/about' },
    ],
  }),

  defineIntent({
    name: 'google_drive.stop_channel',
    effect: 'write',
    description:
      'Stop a push notification channel previously created via files.watch. Binds POST /drive/v3/channels/stop.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/drive/v3/channels/stop' },
    ],
  }),
];
