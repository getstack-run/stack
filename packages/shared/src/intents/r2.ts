import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Cloudflare R2 — S3-compatible data plane plus a Cloudflare API control
// plane. Data plane host: {account}.r2.cloudflarestorage.com with
// path-style bucket/key under the pathname. Control plane host:
// api.cloudflare.com/client/v4/accounts/{id}/r2/buckets for bucket CRUD.

const bucketName = z.string().min(3).max(63).regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, 'invalid bucket name');
const bucketList = z.union([bucketName, z.array(bucketName).min(1)]);
type BucketList = z.infer<typeof bucketList>;
const toList = (v: BucketList): string[] => (Array.isArray(v) ? v : [v]);

function r2HostConstraint(): Constraint {
  return { path: 'url.host', op: 'matches', value: '^[^/]+\\.r2\\.cloudflarestorage\\.com$' };
}

function r2BucketPath(bucket: BucketList, keyPrefix?: string): Constraint {
  const list = toList(bucket);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  const prefix = keyPrefix ? keyPrefix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&') : '';
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/${alt}/${prefix}.*$`,
  };
}

function r2BucketRoot(bucket: BucketList): Constraint {
  const list = toList(bucket);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/${alt}/?$`,
  };
}

export const r2Intents = [
  defineIntent({
    name: 'r2.get_object',
    effect: 'read',
    description:
      'Download an object from specific R2 buckets. Binds GET {account}.r2.cloudflarestorage.com/{bucket}/{key}.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      r2HostConstraint(),
      r2BucketPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'r2.put_object',
    effect: 'write',
    description:
      'Upload or overwrite an object in specific R2 buckets. Binds PUT {account}.r2.cloudflarestorage.com/{bucket}/{key}.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      r2HostConstraint(),
      r2BucketPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'r2.delete_object',
    effect: 'destructive',
    description:
      'Delete an object from specific R2 buckets. Binds DELETE {account}.r2.cloudflarestorage.com/{bucket}/{key}. Destructive.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      r2HostConstraint(),
      r2BucketPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'r2.head_object',
    effect: 'read',
    description:
      'Retrieve metadata for an R2 object without downloading its body. Binds HEAD on the object path.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'HEAD' },
      r2HostConstraint(),
      r2BucketPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'r2.list_objects',
    effect: 'read',
    description:
      'List objects in specific R2 buckets (ListObjectsV2). Binds GET on the bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      r2HostConstraint(),
      r2BucketRoot(bucket),
    ],
  }),

  defineIntent({
    name: 'r2.copy_object',
    effect: 'write',
    description:
      'Server-side copy an object into specific R2 buckets. Binds PUT with x-amz-copy-source header.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      r2HostConstraint(),
      r2BucketPath(bucket),
    ],
  }),

  defineIntent({
    name: 'r2.create_multipart_upload',
    effect: 'write',
    description:
      'Initiate a multipart upload in specific R2 buckets. Binds POST {bucket}/{key}?uploads.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      r2HostConstraint(),
      r2BucketPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'r2.complete_multipart_upload',
    effect: 'write',
    description:
      'Finalize a multipart upload in specific R2 buckets. Binds POST {bucket}/{key}?uploadId=.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      r2HostConstraint(),
      r2BucketPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'r2.abort_multipart_upload',
    effect: 'destructive',
    description:
      'Abort an in-progress multipart upload in specific R2 buckets. Binds DELETE {bucket}/{key}?uploadId=.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      r2HostConstraint(),
      r2BucketPath(bucket),
    ],
  }),

  defineIntent({
    name: 'r2.list_parts',
    effect: 'read',
    description:
      'List parts uploaded for an in-progress multipart upload. Binds GET {bucket}/{key}?uploadId=.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      r2HostConstraint(),
      r2BucketPath(bucket),
    ],
  }),

  defineIntent({
    name: 'r2.bucket_cors',
    effect: 'destructive',
    description:
      'Read or update CORS configuration for specific R2 buckets. Binds GET/PUT/DELETE ?cors on the bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT', 'DELETE'] },
      r2HostConstraint(),
      r2BucketRoot(bucket),
    ],
  }),

  defineIntent({
    name: 'r2.mgmt_list_buckets',
    effect: 'read',
    description:
      'List R2 buckets on the Cloudflare account via the control plane. Binds GET /client/v4/accounts/{id}/r2/buckets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'api.cloudflare.com' },
      { path: 'url.pathname', op: 'matches', value: '^/client/v4/accounts/[0-9a-f]+/r2/buckets$' },
    ],
  }),

  defineIntent({
    name: 'r2.mgmt_create_bucket',
    effect: 'write',
    description:
      'Create a new R2 bucket via the Cloudflare control plane. Binds POST /client/v4/accounts/{id}/r2/buckets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.cloudflare.com' },
      { path: 'url.pathname', op: 'matches', value: '^/client/v4/accounts/[0-9a-f]+/r2/buckets$' },
    ],
  }),

  defineIntent({
    name: 'r2.mgmt_delete_bucket',
    effect: 'destructive',
    description:
      'Delete an R2 bucket via the Cloudflare control plane. Binds DELETE /client/v4/accounts/{id}/r2/buckets/{name}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.host', op: 'eq', value: 'api.cloudflare.com' },
      { path: 'url.pathname', op: 'matches', value: '^/client/v4/accounts/[0-9a-f]+/r2/buckets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'r2.mgmt_read_bucket',
    effect: 'read',
    description:
      'Read metadata for an R2 bucket via the Cloudflare control plane. Binds GET /client/v4/accounts/{id}/r2/buckets/{name}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'api.cloudflare.com' },
      { path: 'url.pathname', op: 'matches', value: '^/client/v4/accounts/[0-9a-f]+/r2/buckets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'r2.mgmt_bucket_cors',
    effect: 'write',
    description:
      'Read or update CORS rules for an R2 bucket via the control plane. Binds GET/PUT /client/v4/accounts/{id}/r2/buckets/{name}/cors.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['GET', 'PUT'] },
      { path: 'url.host', op: 'eq', value: 'api.cloudflare.com' },
      { path: 'url.pathname', op: 'matches', value: '^/client/v4/accounts/[0-9a-f]+/r2/buckets/[^/]+/cors$' },
    ],
  }),
];
