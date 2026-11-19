import { Readable } from 'node:stream';
import { ServiceUnavailableError } from '@stack/shared';

/**
 * Somewhere to put bytes that is not Postgres.
 *
 * The cold archive needs put, get, existence, paginated listing and delete.
 * The interface exists so the
 * archiver can be tested without an AWS account and run in dev without one —
 * the same shape as the KMS dev-mock, which has served this codebase well.
 */
export interface ObjectStore {
  /** Store bytes at `key`. Overwrites. */
  put(key: string, body: Buffer, opts?: { contentType?: string }): Promise<void>;
  /** Fetch bytes at `key`, or null when the key does not exist. */
  get(key: string): Promise<Buffer | null>;
  /** Cheap existence check — used to make re-archiving a day idempotent. */
  exists(key: string): Promise<boolean>;
  /** List one page of keys under `prefix`. The cursor is opaque to callers. */
  list(prefix: string, cursor?: string): Promise<ObjectStoreListPage>;
  /** Delete a key. Missing keys are a successful no-op. */
  delete(key: string): Promise<void>;
  /**
   * Is the store itself usable (the bucket exists and these credentials may
   * use it)? Resolves when it is; throws `ObjectStoreUnavailableError`, with
   * the reason, when it is not. Used by the boot and scheduled health probes.
   */
  check(): Promise<void>;
  /** For logs and health output. */
  readonly description: string;
  /**
   * Do these bytes survive a restart?
   *
   * A property rather than an instanceof check, because the archiver gates an
   * irreversible DELETE on it and "is it this class" is the wrong question to
   * stake audit rows on — a wrapper, a decorator or a subclass would all get
   * the answer wrong in the dangerous direction.
   */
  readonly durable: boolean;
}

export interface ObjectStoreListPage {
  keys: string[];
  cursor?: string;
  /** When each listed key was last written (ms since the epoch), for a store that says. A multipart object counts from when its upload began. */
  modified?: Record<string, number>;
}

/** A store a file can be streamed through: size without the bytes, a read that streams, and a write that streams. */
export interface StreamingObjectStore extends ObjectStore {
  /** The object's size, or null when it does not exist. */
  head(key: string): Promise<{ size: number } | null>;
  /** The object as a stream, or null when it does not exist. */
  getStream(key: string): Promise<{ body: AsyncIterable<Uint8Array>; size: number } | null>;
  /** Store `length` bytes from `body` at `key`. Throws when the stream is not exactly that long. Overwrites. */
  putStream(key: string, body: AsyncIterable<Uint8Array>, length: number, opts?: { contentType?: string }): Promise<void>;
  /**
   * Store the bytes of `body` at `key` without knowing their length first and without holding them: an S3 store sends them as a
   * multipart upload a part at a time (aborted at the store when the body throws, so nothing is left), a small body as one PUT.
   * Answers how many bytes were stored. Nothing is stored when the body throws; the error is the body's own.
   */
  putStreaming(key: string, body: AsyncIterable<Uint8Array>, opts?: { contentType?: string }): Promise<{ size: number }>;
  /**
   * Abort the uploads begun under `prefix` before `olderThan` and not finished: the parts of such an upload are not objects (no prefix
   * delete finds them) and are billed until it is aborted, so whoever finds one nothing is running aborts it. Reads at most `pages`
   * pages of the store's list; answers how many it aborted. Absent on a store that has no such uploads.
   */
  abortUploads?(prefix: string, olderThan: Date, pages?: number): Promise<number>;
  /** The AWS region the store's bucket is in, which decides what a stored or served byte costs; absent for a store that is not AWS's. */
  readonly region?: string;
}

async function* chunked(bytes: Buffer, size = 64 * 1024): AsyncGenerator<Uint8Array> {
  for (let offset = 0; offset < bytes.length; offset += size) yield bytes.subarray(offset, Math.min(offset + size, bytes.length));
}

/** Why a store call failed; the operator's cue, never sent to a caller. */
export type ObjectStoreFailureReason = 'access_denied' | 'bucket_missing' | 'unreachable';

/**
 * The store could not do what was asked, for any reason other than the key
 * being absent. It is a retriable 503 with a fixed message: the provider's own
 * text (bucket names, ARNs, request ids) stays on `cause` for the log. A store
 * answers 403 where it hides that a key is missing, so a 403 is a failure and
 * is never read as "not there".
 */
export class ObjectStoreUnavailableError extends ServiceUnavailableError {
  constructor(
    readonly operation: string,
    readonly reason: ObjectStoreFailureReason,
    cause?: unknown,
  ) {
    super('Object storage is temporarily unavailable, please retry');
    this.name = 'ObjectStoreUnavailableError';
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * In-memory store. Dev and tests only.
 *
 * Loud about what it is, because an archive that silently evaporates on
 * restart is worse than no archive: the rows are deleted from Postgres either
 * way. `AuditArchiveService` refuses to delete anything when the store is not
 * durable, which is the guard that makes this safe to ship.
 */
export class MemoryObjectStore implements StreamingObjectStore {
  readonly description = 'in-memory (NOT durable — dev only)';
  readonly durable: boolean = false;
  /** Priced as STACK's own bucket is, so the drive's tests and a dev machine charge as production does. */
  readonly region: string = 'eu-north-1';
  private readonly objects = new Map<string, Buffer>();
  private readonly modifiedAt = new Map<string, number>();
  /** Test only: when false, `putStreaming` counts and hashes nothing and keeps nothing, so a test can push a gigabyte through. */
  retainStreamedBytes = true;
  /** Test only: the size of every stream stored, in order. */
  readonly streamedSizes: number[] = [];

  /** Test helper: forget every object. */
  reset(): void {
    this.objects.clear();
    this.modifiedAt.clear();
  }

  /** Test helper: say when an object was last written. */
  setModified(key: string, at: Date): void {
    this.modifiedAt.set(key, at.getTime());
  }

  /** Test helper: forget when an object was written, as a store that does not say. */
  forgetModified(key: string): void {
    this.modifiedAt.delete(key);
  }

  private keep(key: string, body: Buffer): void {
    this.objects.set(key, body);
    this.modifiedAt.set(key, Date.now());
  }

  /** Test helper: the keys of the objects held. */
  keys(): string[] {
    return [...this.objects.keys()];
  }

  async head(key: string): Promise<{ size: number } | null> {
    const found = this.objects.get(key);
    return found ? { size: found.length } : null;
  }

  async getStream(key: string): Promise<{ body: AsyncIterable<Uint8Array>; size: number } | null> {
    const found = this.objects.get(key);
    return found ? { body: chunked(Buffer.from(found)), size: found.length } : null;
  }

  async putStreaming(key: string, body: AsyncIterable<Uint8Array>): Promise<{ size: number }> {
    const parts: Buffer[] = [];
    let total = 0;
    for await (const part of body) {
      total += part.length;
      if (this.retainStreamedBytes) parts.push(Buffer.from(part));
    }
    // Only a body that ended is stored: one that threw never reaches here, as in S3 where its upload is aborted.
    this.streamedSizes.push(total);
    if (this.retainStreamedBytes) this.keep(key, Buffer.concat(parts));
    return { size: total };
  }

  async putStream(key: string, body: AsyncIterable<Uint8Array>, length: number): Promise<void> {
    const parts: Buffer[] = [];
    let total = 0;
    for await (const part of body) {
      total += part.length;
      if (total > length) throw new Error('The stream is longer than its declared length');
      parts.push(Buffer.from(part));
    }
    if (total !== length) throw new Error('The stream is shorter than its declared length');
    this.keep(key, Buffer.concat(parts));
  }

  async put(key: string, body: Buffer): Promise<void> {
    this.keep(key, Buffer.from(body));
  }

  async get(key: string): Promise<Buffer | null> {
    return this.objects.get(key) ?? null;
  }

  async exists(key: string): Promise<boolean> {
    return this.objects.has(key);
  }

  async list(prefix: string, cursor?: string): Promise<ObjectStoreListPage> {
    const pageSize = 1_000;
    const matches = [...this.objects.keys()]
      .filter((key) => key.startsWith(prefix) && (cursor === undefined || compareKeys(key, cursor) > 0))
      .sort(compareKeys);
    const keys = matches.slice(0, pageSize);
    // An object with no time recorded is left out, as the S3 store leaves out one with no `LastModified`: unknown is never old.
    const modified = Object.fromEntries(keys.filter((key) => this.modifiedAt.has(key)).map((key) => [key, this.modifiedAt.get(key)!]));
    return matches.length > pageSize
      ? { keys, cursor: keys[keys.length - 1], modified }
      : { keys, modified };
  }

  async delete(key: string): Promise<void> {
    this.objects.delete(key);
    this.modifiedAt.delete(key);
  }

  async check(): Promise<void> {}

  /** Test helper — how many objects are held. */
  get size(): number {
    return this.objects.size;
  }
}

function compareKeys(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

interface S3Client {
  send(command: unknown): Promise<unknown>;
}

/** The size of one part of a streamed upload (S3 takes 5 MiB at least for all but the last): a file in flight holds about this much. */
export const STREAM_PART_BYTES = 5 * 1024 * 1024;

type S3Command = new (input: Record<string, unknown>) => unknown;

/**
 * S3-compatible store.
 *
 * Constructed from an injected client rather than importing the AWS SDK here,
 * so @stack/vault does not grow a hard dependency on it and the API/worker
 * decide whether S3 exists at all. `apps/worker/src/config/object-store.ts`
 * does the wiring.
 */
export class S3ObjectStore implements StreamingObjectStore {
  readonly description: string;
  readonly durable = true;

  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly commands: {
      PutObjectCommand: new (input: Record<string, unknown>) => unknown;
      GetObjectCommand: new (input: Record<string, unknown>) => unknown;
      HeadObjectCommand: new (input: Record<string, unknown>) => unknown;
      ListObjectsV2Command: new (input: Record<string, unknown>) => unknown;
      DeleteObjectCommand: new (input: Record<string, unknown>) => unknown;
      /** Optional so a caller that never probes need not load it; `check()` needs it. */
      HeadBucketCommand?: new (input: Record<string, unknown>) => unknown;
      /** Only for a store that streams a file of unknown length (`putStreaming`): without them a body past one part is refused. */
      CreateMultipartUploadCommand?: S3Command;
      UploadPartCommand?: S3Command;
      CompleteMultipartUploadCommand?: S3Command;
      AbortMultipartUploadCommand?: S3Command;
      /** Optional: with it the store can find the uploads nothing is running (`abortUploads`). */
      ListMultipartUploadsCommand?: S3Command;
    },
    readonly region = 'unknown',
    /** The size of one part of a streamed upload; S3 takes 5 MiB at least for every part but the last. Tests lower it only on a store that allows. */
    private readonly partBytes = STREAM_PART_BYTES,
  ) {
    this.description = `s3://${bucket} (${region})`;
  }

  async putStreaming(key: string, body: AsyncIterable<Uint8Array>, opts?: { contentType?: string }): Promise<{ size: number }> {
    const c = this.commands;
    const contentType = opts?.contentType;
    let size = 0;
    let uploadId: string | null = null;
    const parts: Array<{ PartNumber: number; ETag: string }> = [];
    // One buffer of one part, filled as the body arrives and sent when full: the upload holds this and nothing else of the file.
    // (Nothing in it is touched until bytes arrive, so a small file does not cost a part of memory.)
    let part: Buffer | null = null;
    let held = 0;

    const sendPart = async (bytes: Buffer): Promise<void> => {
      if (!c.CreateMultipartUploadCommand || !c.UploadPartCommand || !c.CompleteMultipartUploadCommand) {
        throw unavailable('put', new Error('streaming uploads are not wired'));
      }
      try {
        if (uploadId === null) {
          const created = (await this.client.send(
            new c.CreateMultipartUploadCommand({ Bucket: this.bucket, Key: key, ...(contentType ? { ContentType: contentType } : {}) }),
          )) as { UploadId?: string };
          if (!created.UploadId) throw new Error('The store gave no upload id');
          uploadId = created.UploadId;
        }
        const partNumber = parts.length + 1;
        const sent = (await this.client.send(
          new c.UploadPartCommand({ Bucket: this.bucket, Key: key, UploadId: uploadId, PartNumber: partNumber, Body: bytes, ContentLength: bytes.length }),
        )) as { ETag?: string };
        if (!sent.ETag) throw new Error('The store gave no ETag for a part');
        parts.push({ PartNumber: partNumber, ETag: sent.ETag });
      } catch (err) {
        throw unavailable('put', err);
      }
    };

    try {
      for await (const piece of body) {
        const bytes = Buffer.from(piece.buffer, piece.byteOffset, piece.byteLength);
        size += bytes.length;
        let at = 0;
        while (at < bytes.length) {
          part ??= Buffer.allocUnsafe(this.partBytes);
          const take = Math.min(bytes.length - at, this.partBytes - held);
          bytes.copy(part, held, at, at + take);
          held += take;
          at += take;
          if (held === this.partBytes) {
            // Sent before another byte is taken, so the buffer is free again when the store has answered.
            await sendPart(part);
            held = 0;
          }
        }
      }
      const tail = part && held > 0 ? part.subarray(0, held) : Buffer.alloc(0);
      if (uploadId === null) {
        // The whole body fits in one part: one PUT, and no upload to abort.
        await this.put(key, tail, contentType ? { contentType } : undefined);
        return { size };
      }
      if (tail.length > 0) await sendPart(tail);
      try {
        await this.client.send(
          new c.CompleteMultipartUploadCommand!({ Bucket: this.bucket, Key: key, UploadId: uploadId, MultipartUpload: { Parts: parts } }),
        );
      } catch (err) {
        throw unavailable('put', err);
      }
      return { size };
    } catch (err) {
      // A body that broke (the sender left, the file was too large) or a store that refused: nothing of this upload stays at the store.
      if (uploadId !== null && c.AbortMultipartUploadCommand) {
        await this.client.send(new c.AbortMultipartUploadCommand({ Bucket: this.bucket, Key: key, UploadId: uploadId })).catch(() => undefined);
      }
      throw err;
    }
  }

  async abortUploads(prefix: string, olderThan: Date, pages = 10): Promise<number> {
    const c = this.commands;
    if (!c.ListMultipartUploadsCommand || !c.AbortMultipartUploadCommand) return 0;
    let aborted = 0;
    let keyMarker: string | undefined;
    let uploadIdMarker: string | undefined;
    for (let page = 0; page < pages; page++) {
      let res: {
        Uploads?: Array<{ Key?: string; UploadId?: string; Initiated?: Date }>;
        IsTruncated?: boolean;
        NextKeyMarker?: string;
        NextUploadIdMarker?: string;
      };
      try {
        res = (await this.client.send(
          new c.ListMultipartUploadsCommand({
            Bucket: this.bucket,
            Prefix: prefix,
            ...(keyMarker ? { KeyMarker: keyMarker } : {}),
            ...(uploadIdMarker ? { UploadIdMarker: uploadIdMarker } : {}),
          }),
        )) as typeof res;
      } catch (err) {
        throw unavailable('abortUploads', err);
      }
      for (const upload of res.Uploads ?? []) {
        if (!upload.Key || !upload.UploadId || !upload.Initiated || new Date(upload.Initiated) >= olderThan) continue;
        try {
          await this.client.send(new c.AbortMultipartUploadCommand({ Bucket: this.bucket, Key: upload.Key, UploadId: upload.UploadId }));
          aborted++;
        } catch (err) {
          if ((err as { name?: string } | null)?.name === 'NoSuchUpload' || isNotFound(err)) continue;
          throw unavailable('abortUploads', err);
        }
      }
      if (!res.IsTruncated || !res.NextKeyMarker) break;
      keyMarker = res.NextKeyMarker;
      uploadIdMarker = res.NextUploadIdMarker;
    }
    return aborted;
  }

  async head(key: string): Promise<{ size: number } | null> {
    try {
      const res = (await this.client.send(new this.commands.HeadObjectCommand({ Bucket: this.bucket, Key: key }))) as {
        ContentLength?: number;
      };
      return { size: res.ContentLength ?? 0 };
    } catch (err) {
      if (isNotFound(err)) return null;
      throw unavailable('head', err);
    }
  }

  async getStream(key: string): Promise<{ body: AsyncIterable<Uint8Array>; size: number } | null> {
    try {
      const res = (await this.client.send(new this.commands.GetObjectCommand({ Bucket: this.bucket, Key: key }))) as {
        Body?: AsyncIterable<Uint8Array>;
        ContentLength?: number;
      };
      if (!res.Body) return null;
      return { body: res.Body, size: res.ContentLength ?? 0 };
    } catch (err) {
      if (isNotFound(err)) return null;
      throw unavailable('get', err);
    }
  }

  async putStream(key: string, body: AsyncIterable<Uint8Array>, length: number, opts?: { contentType?: string }): Promise<void> {
    // The length is declared to the store, which refuses a body of any other length: the stream is never taken on trust.
    try {
      await this.client.send(
        new this.commands.PutObjectCommand({
          Bucket: this.bucket,
          Key: key,
          Body: Readable.from(body),
          ContentLength: length,
          ...(opts?.contentType ? { ContentType: opts.contentType } : {}),
        }),
      );
    } catch (err) {
      throw unavailable('put', err);
    }
  }

  async put(key: string, body: Buffer, opts?: { contentType?: string }): Promise<void> {
    try {
      await this.client.send(
        new this.commands.PutObjectCommand({
          Bucket: this.bucket,
          Key: key,
          Body: body,
          ...(opts?.contentType ? { ContentType: opts.contentType } : {}),
        }),
      );
    } catch (err) {
      throw unavailable('put', err);
    }
  }

  async get(key: string): Promise<Buffer | null> {
    try {
      const res = (await this.client.send(
        new this.commands.GetObjectCommand({ Bucket: this.bucket, Key: key }),
      )) as { Body?: { transformToByteArray?: () => Promise<Uint8Array> } };
      const bytes = await res.Body?.transformToByteArray?.();
      return bytes ? Buffer.from(bytes) : null;
    } catch (err) {
      if (isNotFound(err)) return null;
      throw unavailable('get', err);
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      await this.client.send(new this.commands.HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return true;
    } catch (err) {
      // Only a 404 means the key is absent. A 403 is the store refusing us (it
      // also answers 403 for a missing key when the credentials may not list),
      // which must fail the call rather than read as "not there".
      if (isNotFound(err)) return false;
      throw unavailable('exists', err);
    }
  }

  async list(prefix: string, cursor?: string): Promise<ObjectStoreListPage> {
    let response: {
      Contents?: Array<{ Key?: string; LastModified?: Date }>;
      NextContinuationToken?: string;
    };
    try {
      response = (await this.client.send(
        new this.commands.ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: prefix,
          ...(cursor ? { ContinuationToken: cursor } : {}),
        }),
      )) as typeof response;
    } catch (err) {
      throw unavailable('list', err);
    }
    const keys = (response.Contents ?? [])
      .map((object) => object.Key)
      .filter((key): key is string => typeof key === 'string');
    const modified: Record<string, number> = {};
    for (const object of response.Contents ?? []) {
      if (typeof object.Key === 'string' && object.LastModified instanceof Date) modified[object.Key] = object.LastModified.getTime();
    }
    const times = Object.keys(modified).length > 0 ? { modified } : {};
    return response.NextContinuationToken ? { keys, cursor: response.NextContinuationToken, ...times } : { keys, ...times };
  }

  async delete(key: string): Promise<void> {
    try {
      await this.client.send(
        new this.commands.DeleteObjectCommand({ Bucket: this.bucket, Key: key }),
      );
    } catch (err) {
      if (isNotFound(err)) return;
      throw unavailable('delete', err);
    }
  }

  async check(): Promise<void> {
    const HeadBucketCommand = this.commands.HeadBucketCommand;
    if (!HeadBucketCommand) throw new ObjectStoreUnavailableError('check', 'unreachable', new Error('HeadBucketCommand is not wired'));
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
    } catch (err) {
      throw unavailable('check', err);
    }
  }
}

function httpStatus(err: unknown): number | undefined {
  return (err as { $metadata?: { httpStatusCode?: number } } | null)?.$metadata?.httpStatusCode;
}

/** Wrap a provider failure; an error that already is one passes through. */
function unavailable(operation: string, err: unknown): ObjectStoreUnavailableError {
  if (err instanceof ObjectStoreUnavailableError) return err;
  const name = (err as { name?: string } | null)?.name;
  const status = httpStatus(err);
  const reason: ObjectStoreFailureReason =
    status === 403 || name === 'AccessDenied' || name === 'Forbidden'
      ? 'access_denied'
      : operation === 'check' && (status === 404 || name === 'NoSuchBucket' || name === 'NotFound')
        ? 'bucket_missing'
        : 'unreachable';
  return new ObjectStoreUnavailableError(operation, reason, err);
}

function isNotFound(err: unknown): boolean {
  const e = err as { name?: string; $metadata?: { httpStatusCode?: number } };
  return e?.name === 'NoSuchKey' || e?.name === 'NotFound' || e?.$metadata?.httpStatusCode === 404;
}

/** True for stores whose contents survive a restart. Gates the delete step. */
export function isDurable(store: ObjectStore): boolean {
  return store.durable === true;
}
