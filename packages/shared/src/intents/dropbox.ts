import { z } from 'zod';
import { defineIntent } from './types.js';

// Dropbox API v2 — https://www.dropbox.com/developers/documentation/http/documentation.
// Metadata/mutation RPCs live at api.dropboxapi.com/2/{namespace}/{verb};
// uploads and downloads live at content.dropboxapi.com/2/files/{verb}.
// Dropbox scopes at the namespace + verb level; there is no path ID to
// bind on, so body-level path pinning is used where practical.

const pathList = z.union([
  z.string().min(1).max(1024),
  z.array(z.string().min(1).max(1024)).min(1),
]);
type PathList = z.infer<typeof pathList>;
const toList = (v: PathList): string[] => (Array.isArray(v) ? v : [v]);

export const dropboxIntents = [
  defineIntent({
    name: 'dropbox.list_folder',
    effect: 'read',
    description:
      'List contents of a Dropbox folder. Binds POST /2/files/list_folder and pins body.path to the declared folder.',
    params: z.object({ path: pathList }),
    expand: ({ path }) => {
      const list = toList(path);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/2/files/list_folder' },
        { path: 'body.path', op: 'in', value: list },
      ];
    },
  }),

  defineIntent({
    name: 'dropbox.list_folder_continue',
    effect: 'read',
    description:
      'Continue paging through a list_folder result. Binds POST /2/files/list_folder/continue.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/list_folder/continue' },
    ],
  }),

  defineIntent({
    name: 'dropbox.upload_file',
    effect: 'write',
    description:
      'Upload a file to Dropbox via the content endpoint. Binds POST /2/files/upload on content.dropboxapi.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'content.dropboxapi.com' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/upload' },
    ],
  }),

  defineIntent({
    name: 'dropbox.download_file',
    effect: 'read',
    description:
      'Download a file from Dropbox via the content endpoint. Binds POST /2/files/download on content.dropboxapi.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'content.dropboxapi.com' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/download' },
    ],
  }),

  defineIntent({
    name: 'dropbox.delete_file',
    effect: 'destructive',
    description:
      'Delete a Dropbox file or folder. Binds POST /2/files/delete_v2 and pins body.path to the declared allowlist. Destructive.',
    params: z.object({ path: pathList }),
    expand: ({ path }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/delete_v2' },
      { path: 'body.path', op: 'in', value: toList(path) },
    ],
  }),

  defineIntent({
    name: 'dropbox.move_file',
    effect: 'write',
    description:
      'Move or rename a Dropbox file or folder. Binds POST /2/files/move_v2 and pins body.from_path to the declared allowlist.',
    params: z.object({ from_path: pathList }),
    expand: ({ from_path }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/move_v2' },
      { path: 'body.from_path', op: 'in', value: toList(from_path) },
    ],
  }),

  defineIntent({
    name: 'dropbox.copy_file',
    effect: 'write',
    description:
      'Copy a Dropbox file or folder. Binds POST /2/files/copy_v2 and pins body.from_path to the declared allowlist.',
    params: z.object({ from_path: pathList }),
    expand: ({ from_path }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/copy_v2' },
      { path: 'body.from_path', op: 'in', value: toList(from_path) },
    ],
  }),

  defineIntent({
    name: 'dropbox.create_folder',
    effect: 'write',
    description:
      'Create a new Dropbox folder. Binds POST /2/files/create_folder_v2 and pins body.path to the declared parent allowlist.',
    params: z.object({ path: pathList }),
    expand: ({ path }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/create_folder_v2' },
      { path: 'body.path', op: 'in', value: toList(path) },
    ],
  }),

  defineIntent({
    name: 'dropbox.get_metadata',
    effect: 'read',
    description:
      'Get metadata for a Dropbox file or folder. Binds POST /2/files/get_metadata and pins body.path to the declared allowlist.',
    params: z.object({ path: pathList }),
    expand: ({ path }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/get_metadata' },
      { path: 'body.path', op: 'in', value: toList(path) },
    ],
  }),

  defineIntent({
    name: 'dropbox.search_files',
    effect: 'read',
    description:
      'Search Dropbox for files and folders. Binds POST /2/files/search_v2.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/search_v2' },
    ],
  }),

  defineIntent({
    name: 'dropbox.create_shared_link',
    effect: 'send',
    description:
      'Create a shared link for a Dropbox file or folder. Binds POST /2/sharing/create_shared_link_with_settings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: '/2/sharing/create_shared_link_with_settings',
      },
    ],
  }),

  defineIntent({
    name: 'dropbox.list_shared_links',
    effect: 'read',
    description:
      'List existing shared links for the authenticated account. Binds POST /2/sharing/list_shared_links.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/sharing/list_shared_links' },
    ],
  }),

  defineIntent({
    name: 'dropbox.revoke_shared_link',
    effect: 'write',
    description:
      'Revoke a previously created shared link. Binds POST /2/sharing/revoke_shared_link. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/sharing/revoke_shared_link' },
    ],
  }),

  defineIntent({
    name: 'dropbox.get_current_account',
    effect: 'read',
    description:
      'Read profile and account metadata for the authenticated user. Binds POST /2/users/get_current_account.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/users/get_current_account' },
    ],
  }),

  defineIntent({
    name: 'dropbox.list_team_members',
    effect: 'read',
    description:
      'List members of a Dropbox Business team. Binds POST /2/team/members/list_v2.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/team/members/list_v2' },
    ],
  }),

  defineIntent({
    name: 'dropbox.list_revisions',
    effect: 'read',
    description:
      'List prior revisions for a specific Dropbox file. Binds POST /2/files/list_revisions and pins body.path.',
    params: z.object({ path: pathList }),
    expand: ({ path }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/files/list_revisions' },
      { path: 'body.path', op: 'in', value: toList(path) },
    ],
  }),
];
