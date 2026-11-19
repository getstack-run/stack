import {
  MemoryObjectStore,
  S3ObjectStore,
  type StreamingObjectStore,
} from '@stack/vault';

/**
 * Decide where the cold archive's bytes go, once, at boot.
 *
 * With `AUDIT_ARCHIVE_BUCKET` set, that is S3 (or any S3-compatible endpoint —
 * Tigris, Cloudflare R2, MinIO — via `AUDIT_ARCHIVE_ENDPOINT`). Without
 * it, an in-memory store that `AuditArchiveService` refuses to archive or
 * delete against. Production boot rejects this store.
 *
 * The AWS SDK is imported dynamically for the same reason `@aws-sdk/client-kms`
 * is: the worker should not pay for the module when the feature is off, and
 * @stack/vault should not depend on it at all.
 */
export async function createObjectStore(): Promise<StreamingObjectStore> {
  const bucket = process.env['AUDIT_ARCHIVE_BUCKET'];
  if (!bucket) {
    console.warn(
      '[ARCHIVE] bucket not set so using in-memory store:',
      'AUDIT_ARCHIVE_BUCKET is not set, so the store is non-durable. ' +
        'No archive metadata or objects will be written. Nothing will be deleted from Postgres. ' +
        'This is the correct behaviour for dev and a misconfiguration in production.',
    );
    return new MemoryObjectStore();
  }

  const region = process.env['AUDIT_ARCHIVE_REGION'] ?? process.env['AWS_REGION'] ?? 'eu-north-1';
  const endpoint = process.env['AUDIT_ARCHIVE_ENDPOINT'];

  const {
    S3Client,
    PutObjectCommand,
    GetObjectCommand,
    HeadObjectCommand,
    HeadBucketCommand,
    ListObjectsV2Command,
    DeleteObjectCommand,
    CreateMultipartUploadCommand,
    UploadPartCommand,
    CompleteMultipartUploadCommand,
    AbortMultipartUploadCommand,
    ListMultipartUploadsCommand,
  } = await import(
    '@aws-sdk/client-s3'
  );

  const client = new S3Client({
    region,
    ...(endpoint ? { endpoint, forcePathStyle: true } : {}),
  });

  return new S3ObjectStore(
    client as unknown as ConstructorParameters<typeof S3ObjectStore>[0],
    bucket,
    {
      CreateMultipartUploadCommand: CreateMultipartUploadCommand as unknown as new (i: Record<string, unknown>) => unknown,
      UploadPartCommand: UploadPartCommand as unknown as new (i: Record<string, unknown>) => unknown,
      CompleteMultipartUploadCommand: CompleteMultipartUploadCommand as unknown as new (i: Record<string, unknown>) => unknown,
      AbortMultipartUploadCommand: AbortMultipartUploadCommand as unknown as new (i: Record<string, unknown>) => unknown,
      ListMultipartUploadsCommand: ListMultipartUploadsCommand as unknown as new (i: Record<string, unknown>) => unknown,
      PutObjectCommand: PutObjectCommand as unknown as new (i: Record<string, unknown>) => unknown,
      GetObjectCommand: GetObjectCommand as unknown as new (i: Record<string, unknown>) => unknown,
      HeadObjectCommand: HeadObjectCommand as unknown as new (i: Record<string, unknown>) => unknown,
      HeadBucketCommand: HeadBucketCommand as unknown as new (i: Record<string, unknown>) => unknown,
      ListObjectsV2Command: ListObjectsV2Command as unknown as new (i: Record<string, unknown>) => unknown,
      DeleteObjectCommand: DeleteObjectCommand as unknown as new (i: Record<string, unknown>) => unknown,
    },
    region,
  );
}
