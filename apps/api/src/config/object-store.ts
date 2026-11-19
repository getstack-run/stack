import { MemoryObjectStore, S3ObjectStore, type StreamingObjectStore } from '@stack/vault';

/**
 * The API's handle on cold storage and account erasure.
 *
 * Writing segments and deleting hot rows is the worker's daily job; the API
 * reads it back for audit exports and evidence packs. Account erasure lists
 * and deletes the exact operator prefix. The shared env contract prevents
 * the API and worker from using different buckets.
 *
 * In development, no bucket gives an empty in-memory store. Production boot
 * rejects that store because account erasure cannot prove durable deletion.
 */
export async function createApiObjectStore(): Promise<StreamingObjectStore> {
  const bucket = process.env['AUDIT_ARCHIVE_BUCKET'];
  if (!bucket) return new MemoryObjectStore();

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
