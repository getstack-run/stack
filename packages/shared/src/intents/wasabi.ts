import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Wasabi — S3-compatible. Hosts: s3.wasabisys.com or regional
// s3.{region}.wasabisys.com. Both virtual-hosted and path-style URL
// forms are accepted. Intents bind host + pathname in the same shape as
// aws_s3, but narrowed to Wasabi hosts.

const bucketName = z.string().min(3).max(63).regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, 'invalid bucket name');
const bucketList = z.union([bucketName, z.array(bucketName).min(1)]);
type BucketList = z.infer<typeof bucketList>;
const toList = (v: BucketList): string[] => (Array.isArray(v) ? v : [v]);

function wasabiHost(bucket: BucketList): Constraint {
  const list = toList(bucket);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return {
    path: 'url.host',
    op: 'matches',
    value: `^(${alt}\\.s3[.-][^/]*\\.wasabisys\\.com|s3[.-]?[^/]*\\.wasabisys\\.com)$`,
  };
}

function wasabiObjectPath(bucket: BucketList, keyPrefix?: string): Constraint {
  const list = toList(bucket);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  const prefix = keyPrefix ? keyPrefix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&') : '';
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^(/${alt}/${prefix}.*|/${prefix}.*)$`,
  };
}

function wasabiBucketRoot(bucket: BucketList): Constraint {
  const list = toList(bucket);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^(/${alt}/?|/)$`,
  };
}

export const wasabiIntents = [
  defineIntent({
    name: 'wasabi.get_object',
    effect: 'read',
    description:
      'Download an object from specific Wasabi buckets. Binds GET on the declared bucket and host allowlist.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      wasabiHost(bucket),
      wasabiObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'wasabi.put_object',
    effect: 'write',
    description:
      'Upload or overwrite an object in specific Wasabi buckets. Binds PUT on the declared bucket.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      wasabiHost(bucket),
      wasabiObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'wasabi.delete_object',
    effect: 'destructive',
    description:
      'Delete an object from specific Wasabi buckets. Destructive. Binds DELETE on the declared bucket.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      wasabiHost(bucket),
      wasabiObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'wasabi.head_object',
    effect: 'read',
    description:
      'Retrieve metadata for a Wasabi object without downloading. Binds HEAD on the declared bucket.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'HEAD' },
      wasabiHost(bucket),
      wasabiObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'wasabi.list_objects',
    effect: 'read',
    description:
      'List objects in specific Wasabi buckets (ListObjectsV2). Binds GET on the bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      wasabiHost(bucket),
      wasabiBucketRoot(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.copy_object',
    effect: 'write',
    description:
      'Server-side copy an object into specific Wasabi buckets. Binds PUT with x-amz-copy-source.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      wasabiHost(bucket),
      wasabiObjectPath(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.create_multipart_upload',
    effect: 'write',
    description:
      'Initiate a multipart upload in specific Wasabi buckets. Binds POST ?uploads on the object path.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      wasabiHost(bucket),
      wasabiObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'wasabi.complete_multipart_upload',
    effect: 'write',
    description:
      'Finalize a multipart upload in specific Wasabi buckets. Binds POST ?uploadId= on the object path.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      wasabiHost(bucket),
      wasabiObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'wasabi.abort_multipart_upload',
    effect: 'destructive',
    description:
      'Abort an in-progress multipart upload in specific Wasabi buckets. Binds DELETE ?uploadId=.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      wasabiHost(bucket),
      wasabiObjectPath(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.bucket_lifecycle',
    effect: 'destructive',
    description:
      'Read or update bucket lifecycle rules on specific Wasabi buckets. Binds GET/PUT/DELETE ?lifecycle on bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT', 'DELETE'] },
      wasabiHost(bucket),
      wasabiBucketRoot(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.bucket_cors',
    effect: 'destructive',
    description:
      'Read or update CORS configuration on specific Wasabi buckets. Binds GET/PUT/DELETE ?cors on bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT', 'DELETE'] },
      wasabiHost(bucket),
      wasabiBucketRoot(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.bucket_policy',
    effect: 'destructive',
    description:
      'Read or update the bucket policy on specific Wasabi buckets. Binds GET/PUT ?policy on bucket root. Sensitive.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT', 'DELETE'] },
      wasabiHost(bucket),
      wasabiBucketRoot(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.bucket_versioning',
    effect: 'write',
    description:
      'Read or update versioning configuration on specific Wasabi buckets. Binds GET/PUT ?versioning on bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT'] },
      wasabiHost(bucket),
      wasabiBucketRoot(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.object_tagging',
    effect: 'destructive',
    description:
      'Read, set, or delete tags on specific Wasabi objects. Binds GET/PUT/DELETE ?tagging on object path.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT', 'DELETE'] },
      wasabiHost(bucket),
      wasabiObjectPath(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.list_buckets',
    effect: 'read',
    description:
      'List all Wasabi buckets on the account. Binds GET on s3.wasabisys.com/ root.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'matches', value: '^s3[.-]?[^/]*\\.wasabisys\\.com$' },
      { path: 'url.pathname', op: 'eq', value: '/' },
    ],
  }),

  defineIntent({
    name: 'wasabi.create_bucket',
    effect: 'write',
    description:
      'Create a new Wasabi bucket. Binds PUT on the bucket root of the declared allowlist.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      wasabiHost(bucket),
      wasabiBucketRoot(bucket),
    ],
  }),

  defineIntent({
    name: 'wasabi.delete_bucket',
    effect: 'destructive',
    description:
      'Delete a Wasabi bucket. Destructive. Binds DELETE on the bucket root of the declared allowlist.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      wasabiHost(bucket),
      wasabiBucketRoot(bucket),
    ],
  }),
];
