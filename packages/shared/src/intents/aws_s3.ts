import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Amazon S3 REST — two URL styles:
//   Virtual-hosted: https://{bucket}.s3.{region}.amazonaws.com/{key}
//   Path-style:     https://s3.{region}.amazonaws.com/{bucket}/{key}
// Operations are identified by HTTP method + sub-resource query. The
// bucket is visible either in `url.host` or the first path segment, so
// we bind on both via regex alternation. Keys are the remainder of the
// pathname and can be further narrowed with key prefixes.

const bucketName = z.string().min(3).max(63).regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, 'invalid bucket name');
const bucketList = z.union([bucketName, z.array(bucketName).min(1)]);
type BucketList = z.infer<typeof bucketList>;
const toList = (v: BucketList): string[] => (Array.isArray(v) ? v : [v]);

function bucketHostOrPath(bucket: BucketList): Constraint {
  const list = toList(bucket);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  // Host form: {bucket}.s3... matched on url.host; path form matched on pathname.
  // We emit both as alternation on pathname via a regex that also tolerates the
  // path-style prefix. To bind the host form, we pair with a host starts_with
  // in the intent body.
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^(/${alt}(/.*)?|/.*)$`,
  };
}

function bucketHostConstraint(bucket: BucketList): Constraint {
  const list = toList(bucket);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  // Virtual-hosted: starts with bucket. Path-style: starts with s3.
  return {
    path: 'url.host',
    op: 'matches',
    value: `^(${alt}\\.s3[.-][^/]+\\.amazonaws\\.com|s3[.-][^/]+\\.amazonaws\\.com|s3\\.amazonaws\\.com)$`,
  };
}

function bucketObjectPath(bucket: BucketList, keyPrefix?: string): Constraint {
  const list = toList(bucket);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  const prefix = keyPrefix ? keyPrefix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&') : '';
  // Matches either virtual-hosted (/{key}) or path-style (/{bucket}/{key}).
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^(/${alt}/${prefix}.*|/${prefix}.*)$`,
  };
}

export const awsS3Intents = [
  defineIntent({
    name: 'aws_s3.get_object',
    effect: 'read',
    description:
      'Download an object from specific S3 buckets. Binds GET {bucket}.s3.amazonaws.com/{key} or path-style to the declared bucket allowlist.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'aws_s3.put_object',
    effect: 'write',
    description:
      'Upload or overwrite an object in specific S3 buckets. Binds PUT {bucket}.s3.amazonaws.com/{key}.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'aws_s3.delete_object',
    effect: 'destructive',
    description:
      'Delete an object from specific S3 buckets. Binds DELETE {bucket}.s3.amazonaws.com/{key}. Destructive.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'aws_s3.head_object',
    effect: 'read',
    description:
      'Retrieve metadata for an object without downloading its body. Binds HEAD {bucket}.s3.amazonaws.com/{key}.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'HEAD' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'aws_s3.list_objects',
    effect: 'read',
    description:
      'List objects in specific S3 buckets (ListObjectsV2). Binds GET on the bucket root with list-type=2.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      bucketHostConstraint(bucket),
      bucketHostOrPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.copy_object',
    effect: 'write',
    description:
      'Server-side copy an object into specific S3 buckets. Binds PUT {bucket}.s3.amazonaws.com/{key} with x-amz-copy-source.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.create_multipart_upload',
    effect: 'write',
    description:
      'Initiate a multipart upload in specific S3 buckets. Binds POST {bucket}.s3.amazonaws.com/{key}?uploads.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'aws_s3.complete_multipart_upload',
    effect: 'write',
    description:
      'Finalize a multipart upload in specific S3 buckets. Binds POST {bucket}.s3.amazonaws.com/{key}?uploadId=.',
    params: z.object({ bucket: bucketList, key_prefix: z.string().max(512).optional() }),
    expand: ({ bucket, key_prefix }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket, key_prefix),
    ],
  }),

  defineIntent({
    name: 'aws_s3.abort_multipart_upload',
    effect: 'destructive',
    description:
      'Abort an in-progress multipart upload in specific S3 buckets. Binds DELETE {bucket}.s3.amazonaws.com/{key}?uploadId=.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.put_object_acl',
    effect: 'write',
    description:
      'Set an object-level ACL in specific S3 buckets. Binds PUT with ?acl on the object path.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.get_object_acl',
    effect: 'read',
    description:
      'Read an object-level ACL from specific S3 buckets. Binds GET with ?acl on the object path.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.put_bucket_policy',
    effect: 'write',
    description:
      'Update the bucket policy on specific S3 buckets. Binds PUT ?policy on the bucket root. Sensitive.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      bucketHostConstraint(bucket),
      bucketHostOrPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.get_bucket_policy',
    effect: 'read',
    description:
      'Read the current bucket policy on specific S3 buckets. Binds GET ?policy on the bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      bucketHostConstraint(bucket),
      bucketHostOrPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.list_buckets',
    effect: 'read',
    description:
      'List all buckets on the account. Binds GET https://s3.amazonaws.com/.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'matches', value: '^s3[.-]?[^/]*\\.amazonaws\\.com$' },
      { path: 'url.pathname', op: 'eq', value: '/' },
    ],
  }),

  defineIntent({
    name: 'aws_s3.create_bucket',
    effect: 'write',
    description:
      'Create a new S3 bucket. Binds PUT on the bucket root of the declared bucket allowlist.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      bucketHostConstraint(bucket),
      bucketHostOrPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.delete_bucket',
    effect: 'destructive',
    description:
      'Delete an S3 bucket. Binds DELETE on the bucket root of the declared allowlist. Destructive.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      bucketHostConstraint(bucket),
      bucketHostOrPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.bucket_cors',
    effect: 'destructive',
    description:
      'Read or update CORS configuration for specific S3 buckets. Binds GET/PUT/DELETE ?cors on the bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT', 'DELETE'] },
      bucketHostConstraint(bucket),
      bucketHostOrPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.bucket_versioning',
    effect: 'write',
    description:
      'Read or update versioning configuration for specific S3 buckets. Binds GET/PUT ?versioning on the bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT'] },
      bucketHostConstraint(bucket),
      bucketHostOrPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.bucket_tagging',
    effect: 'destructive',
    description:
      'Read, set, or delete tags on specific S3 buckets. Binds GET/PUT/DELETE ?tagging on the bucket root.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT', 'DELETE'] },
      bucketHostConstraint(bucket),
      bucketHostOrPath(bucket),
    ],
  }),

  defineIntent({
    name: 'aws_s3.object_tagging',
    effect: 'destructive',
    description:
      'Read, set, or delete tags on specific S3 objects. Binds GET/PUT/DELETE ?tagging on the object path.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => [
      { path: 'method', op: 'in', value: ['GET', 'PUT', 'DELETE'] },
      bucketHostConstraint(bucket),
      bucketObjectPath(bucket),
    ],
  }),
];
