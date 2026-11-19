import { z } from 'zod';
import { defineIntent } from './types.js';

// Backblaze B2 API v3 — https://api.backblazeb2.com/b2api/v3/b2_…
// After b2_authorize_account, subsequent calls are redirected to an
// account-specific host (e.g. api000.backblazeb2.com) — intents bind on
// pathname only because the host is dynamic. Upload endpoints are
// separately issued (pod host from b2_get_upload_url).

function b2Path(action: string): [{ path: string; op: 'eq'; value: string }, { path: string; op: 'matches'; value: string }] {
  return [
    { path: 'method', op: 'eq', value: 'POST' },
    { path: 'url.pathname', op: 'matches', value: `^/b2api/v[0-9]+/${action}$` },
  ];
}

export const backblazeIntents = [
  defineIntent({
    name: 'backblaze.authorize_account',
    effect: 'read',
    description:
      'Exchange an applicationKey for a session authorization token. Binds GET /b2api/v3/b2_authorize_account.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/b2api/v[0-9]+/b2_authorize_account$' },
    ],
  }),

  defineIntent({
    name: 'backblaze.list_buckets',
    effect: 'read',
    description:
      'List B2 buckets on the account. Binds POST /b2api/v3/b2_list_buckets.',
    params: z.object({}),
    expand: () => b2Path('b2_list_buckets'),
  }),

  defineIntent({
    name: 'backblaze.create_bucket',
    effect: 'write',
    description:
      'Create a new B2 bucket. Binds POST /b2api/v3/b2_create_bucket.',
    params: z.object({}),
    expand: () => b2Path('b2_create_bucket'),
  }),

  defineIntent({
    name: 'backblaze.delete_bucket',
    effect: 'destructive',
    description:
      'Delete a B2 bucket. Binds POST /b2api/v3/b2_delete_bucket. Destructive.',
    params: z.object({}),
    expand: () => b2Path('b2_delete_bucket'),
  }),

  defineIntent({
    name: 'backblaze.update_bucket',
    effect: 'write',
    description:
      'Update bucket metadata or lifecycle rules. Binds POST /b2api/v3/b2_update_bucket.',
    params: z.object({}),
    expand: () => b2Path('b2_update_bucket'),
  }),

  defineIntent({
    name: 'backblaze.get_upload_url',
    effect: 'read',
    description:
      'Request an upload URL and token for a bucket. Binds POST /b2api/v3/b2_get_upload_url.',
    params: z.object({}),
    expand: () => b2Path('b2_get_upload_url'),
  }),

  defineIntent({
    name: 'backblaze.upload_file',
    effect: 'write',
    description:
      'Upload a file to a B2 bucket using the URL from b2_get_upload_url. Binds POST to the dynamic upload host path /b2api/v3/b2_upload_file/{bucket_id}/{upload_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/b2api/v[0-9]+/b2_upload_file/[^/]+(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'backblaze.list_file_names',
    effect: 'read',
    description:
      'List current file versions in a bucket. Binds POST /b2api/v3/b2_list_file_names.',
    params: z.object({}),
    expand: () => b2Path('b2_list_file_names'),
  }),

  defineIntent({
    name: 'backblaze.list_file_versions',
    effect: 'read',
    description:
      'List all file versions (including hidden) in a bucket. Binds POST /b2api/v3/b2_list_file_versions.',
    params: z.object({}),
    expand: () => b2Path('b2_list_file_versions'),
  }),

  defineIntent({
    name: 'backblaze.download_file_by_id',
    effect: 'read',
    description:
      'Download a file by its fileId. Binds GET /b2api/v3/b2_download_file_by_id.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      { path: 'url.pathname', op: 'matches', value: '^/b2api/v[0-9]+/b2_download_file_by_id$' },
    ],
  }),

  defineIntent({
    name: 'backblaze.delete_file_version',
    effect: 'destructive',
    description:
      'Delete a specific file version. Binds POST /b2api/v3/b2_delete_file_version. Destructive.',
    params: z.object({}),
    expand: () => b2Path('b2_delete_file_version'),
  }),

  defineIntent({
    name: 'backblaze.hide_file',
    effect: 'write',
    description:
      'Hide the current version of a file in a bucket. Binds POST /b2api/v3/b2_hide_file.',
    params: z.object({}),
    expand: () => b2Path('b2_hide_file'),
  }),

  defineIntent({
    name: 'backblaze.copy_file',
    effect: 'write',
    description:
      'Server-side copy a file into a target bucket. Binds POST /b2api/v3/b2_copy_file.',
    params: z.object({}),
    expand: () => b2Path('b2_copy_file'),
  }),

  defineIntent({
    name: 'backblaze.create_key',
    effect: 'write',
    description:
      'Create a new application key scoped to specific buckets or capabilities. Binds POST /b2api/v3/b2_create_key. Sensitive.',
    params: z.object({}),
    expand: () => b2Path('b2_create_key'),
  }),

  defineIntent({
    name: 'backblaze.list_keys',
    effect: 'read',
    description:
      'List application keys on the account. Binds POST /b2api/v3/b2_list_keys.',
    params: z.object({}),
    expand: () => b2Path('b2_list_keys'),
  }),

  defineIntent({
    name: 'backblaze.delete_key',
    effect: 'destructive',
    description:
      'Delete an application key by id. Binds POST /b2api/v3/b2_delete_key. Destructive.',
    params: z.object({}),
    expand: () => b2Path('b2_delete_key'),
  }),

  defineIntent({
    name: 'backblaze.start_large_file',
    effect: 'write',
    description:
      'Begin a large-file (multipart) upload session. Binds POST /b2api/v3/b2_start_large_file.',
    params: z.object({}),
    expand: () => b2Path('b2_start_large_file'),
  }),

  defineIntent({
    name: 'backblaze.finish_large_file',
    effect: 'write',
    description:
      'Finalize a large-file upload by joining its parts. Binds POST /b2api/v3/b2_finish_large_file.',
    params: z.object({}),
    expand: () => b2Path('b2_finish_large_file'),
  }),
];
