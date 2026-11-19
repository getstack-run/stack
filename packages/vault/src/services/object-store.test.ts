import { describe, expect, it, vi } from 'vitest';
import { ServiceUnavailableError } from '@stack/shared';
import { MemoryObjectStore, ObjectStoreUnavailableError, S3ObjectStore } from './object-store.js';

class Command {
  constructor(readonly input: Record<string, unknown>) {}
}
class PutObjectCommand extends Command {}
class GetObjectCommand extends Command {}
class HeadObjectCommand extends Command {}
class ListObjectsV2Command extends Command {}
class DeleteObjectCommand extends Command {}
class HeadBucketCommand extends Command {}

function s3Error(name: string, httpStatusCode: number, message = 'raw provider text with arn:aws:s3:::secret-bucket') {
  return Object.assign(new Error(message), { name, $metadata: { httpStatusCode } });
}

function storeThatFails(error: unknown) {
  const send = vi.fn(async () => {
    throw error;
  });
  const store = new S3ObjectStore(
    { send },
    'bucket',
    { PutObjectCommand, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command, DeleteObjectCommand, HeadBucketCommand },
    'eu-north-1',
  );
  return { store, send };
}

describe('S3ObjectStore failures', () => {
  it('reports a missing key as absent, not as a failure', async () => {
    const { store } = storeThatFails(s3Error('NotFound', 404));
    await expect(store.exists('a')).resolves.toBe(false);
    await expect(store.get('a')).resolves.toBeNull();
    await expect(store.delete('a')).resolves.toBeUndefined();
  });

  it('treats a 403 on exists as a failure the caller can retry, never as "not there"', async () => {
    const { store } = storeThatFails(s3Error('Forbidden', 403));
    const outcome = await store.exists('a').catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ObjectStoreUnavailableError);
    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
    expect((outcome as ObjectStoreUnavailableError).statusCode).toBe(503);
    expect((outcome as ObjectStoreUnavailableError).reason).toBe('access_denied');
  });

  it.each([
    ['get', (store: S3ObjectStore) => store.get('a')],
    ['put', (store: S3ObjectStore) => store.put('a', Buffer.from('x'))],
    ['list', (store: S3ObjectStore) => store.list('p/')],
    ['delete', (store: S3ObjectStore) => store.delete('a')],
    ['exists', (store: S3ObjectStore) => store.exists('a')],
  ])('maps a provider failure on %s to a 503 with a safe message', async (_name, call) => {
    const { store } = storeThatFails(s3Error('InternalError', 500));
    const outcome = await call(store).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ObjectStoreUnavailableError);
    const error = outcome as ObjectStoreUnavailableError;
    expect(error.statusCode).toBe(503);
    expect(error.code).toBe('SERVICE_UNAVAILABLE');
    expect(error.message).toBe('Object storage is temporarily unavailable, please retry');
    expect(error.message).not.toContain('secret-bucket');
    expect(error.reason).toBe('unreachable');
    // The original stays on the error for the operator's log.
    expect((error.cause as Error).message).toContain('secret-bucket');
  });

  it('does not wrap an error that is already an object-store failure', async () => {
    const original = new ObjectStoreUnavailableError('get', 'unreachable', new Error('x'));
    const { store } = storeThatFails(original);
    await expect(store.get('a')).rejects.toBe(original);
  });
});

describe('object store check', () => {
  it('passes when the bucket answers HeadBucket', async () => {
    const send = vi.fn(async () => ({}));
    const store = new S3ObjectStore(
      { send },
      'bucket',
      { PutObjectCommand, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command, DeleteObjectCommand, HeadBucketCommand },
    );
    await expect(store.check()).resolves.toBeUndefined();
    expect((send.mock.calls[0] as unknown as [HeadBucketCommand])[0]).toBeInstanceOf(HeadBucketCommand);
    expect((send.mock.calls[0] as unknown as [HeadBucketCommand])[0].input).toEqual({ Bucket: 'bucket' });
  });

  it.each([
    [s3Error('Forbidden', 403), 'access_denied'],
    [s3Error('NotFound', 404), 'bucket_missing'],
    [s3Error('TimeoutError', 0), 'unreachable'],
  ])('names why the bucket is not usable', async (error, reason) => {
    const { store } = storeThatFails(error);
    const outcome = await store.check().catch((e: unknown) => e);
    expect(outcome).toBeInstanceOf(ObjectStoreUnavailableError);
    expect((outcome as ObjectStoreUnavailableError).reason).toBe(reason);
  });

  it('the in-memory store is always reachable', async () => {
    await expect(new MemoryObjectStore().check()).resolves.toBeUndefined();
  });
});

class CreateMultipartUploadCommand extends Command {}
class UploadPartCommand extends Command {}
class CompleteMultipartUploadCommand extends Command {}
class AbortMultipartUploadCommand extends Command {}
class ListMultipartUploadsCommand extends Command {}

const PART = 1024;

describe('MemoryObjectStore listing with times', () => {
  it('lists the time of every object it knows one for, and leaves out an object with no time, as the S3 store does', async () => {
    const memory = new MemoryObjectStore();
    await memory.put('drive/op/a', Buffer.from('a'));
    await memory.put('drive/op/b', Buffer.from('b'));
    memory.forgetModified('drive/op/b');
    const page = await memory.list('drive/');
    expect(page.keys).toEqual(['drive/op/a', 'drive/op/b']);
    expect(Object.keys(page.modified ?? {})).toEqual(['drive/op/a']);
  });
});

describe('S3ObjectStore streaming puts', () => {
  const commands = {
    PutObjectCommand, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command, DeleteObjectCommand, HeadBucketCommand,
    CreateMultipartUploadCommand, UploadPartCommand, CompleteMultipartUploadCommand, AbortMultipartUploadCommand, ListMultipartUploadsCommand,
  };
  function store(send: (command: unknown) => Promise<unknown>) {
    return new S3ObjectStore({ send }, 'bucket', commands, 'eu-north-1', PART);
  }
  async function* bytes(...pieces: number[]): AsyncGenerator<Uint8Array> {
    for (const n of pieces) yield Buffer.alloc(n, 7);
  }
  const names = (send: { mock: { calls: unknown[][] } }) => send.mock.calls.map((c) => (c[0] as Command).constructor.name);

  it('puts a body smaller than one part in one request and starts no upload', async () => {
    const send = vi.fn(async () => ({}));
    expect(await store(send).putStreaming('k', bytes(300, 200), { contentType: 'application/octet-stream' })).toEqual({ size: 500 });
    expect(names(send)).toEqual(['PutObjectCommand']);
  });

  it('sends a longer body as parts of the part size, the last shorter, and joins them; the length is not known beforehand', async () => {
    const sent: number[] = [];
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof CreateMultipartUploadCommand) return { UploadId: 'up-1' };
      if (command instanceof UploadPartCommand) {
        sent.push((command.input['Body'] as Buffer).length);
        return { ETag: `"e${command.input['PartNumber']}"` };
      }
      return {};
    });
    const result = await store(send).putStreaming('k', bytes(700, 700, 700, 100));
    expect(result).toEqual({ size: 2200 });
    expect(sent).toEqual([PART, PART, 152]);
    const done = send.mock.calls.map((c) => c[0] as Command).find((c) => c instanceof CompleteMultipartUploadCommand)!;
    expect(done.input).toMatchObject({ UploadId: 'up-1', MultipartUpload: { Parts: [{ PartNumber: 1, ETag: '"e1"' }, { PartNumber: 2, ETag: '"e2"' }, { PartNumber: 3, ETag: '"e3"' }] } });
  });

  it('sends every byte once and in order from the one buffer it reuses, whatever size the pieces arrive in', async () => {
    const whole = Buffer.alloc(PART * 3 + 333);
    for (let i = 0; i < whole.length; i++) whole[i] = (i * 31 + (i >> 8)) & 0xff;
    const pieces = [1, 5, 1023, 1, 1500, 64, 700, 2, 1281].reduce<Buffer[]>((out, size) => {
      const taken = out.reduce((n, b) => n + b.length, 0);
      if (taken < whole.length) out.push(whole.subarray(taken, Math.min(whole.length, taken + size)));
      return out;
    }, []);
    const taken = pieces.reduce((n, b) => n + b.length, 0);
    if (taken < whole.length) pieces.push(whole.subarray(taken));
    const sent: Buffer[] = [];
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof CreateMultipartUploadCommand) return { UploadId: 'u' };
      // The buffer is the store's to reuse once the part is answered: what a client keeps of it is a copy.
      if (command instanceof UploadPartCommand) {
        sent.push(Buffer.from(command.input['Body'] as Buffer));
        return { ETag: '"x"' };
      }
      return {};
    });
    async function* body(): AsyncGenerator<Uint8Array> {
      for (const piece of pieces) yield piece;
    }
    expect(await store(send).putStreaming('k', body())).toEqual({ size: whole.length });
    expect(sent.map((part) => part.length)).toEqual([PART, PART, PART, 333]);
    expect(Buffer.concat(sent).equals(whole)).toBe(true);
  });

  it('lists keys with when each was last written, for the sweep of objects nothing names', async () => {
    const at = new Date('2026-10-30T08:00:00Z');
    const send = vi.fn(async () => ({ Contents: [{ Key: 'drive/op/a', LastModified: at }, { Key: 'drive/op/b' }], NextContinuationToken: 'next' }));
    expect(await store(send).list('drive/')).toEqual({ keys: ['drive/op/a', 'drive/op/b'], cursor: 'next', modified: { 'drive/op/a': at.getTime() } });
  });

  it('sends no extra empty part when the body ends exactly on a part', async () => {
    const send = vi.fn(async (command: unknown) => (command instanceof CreateMultipartUploadCommand ? { UploadId: 'u' } : command instanceof UploadPartCommand ? { ETag: '"x"' } : {}));
    await store(send).putStreaming('k', bytes(PART, PART));
    expect(names(send).filter((n) => n === 'UploadPartCommand')).toHaveLength(2);
  });

  it('aborts the upload at the store when the body throws, and stores nothing', async () => {
    const send = vi.fn(async (command: unknown) => (command instanceof CreateMultipartUploadCommand ? { UploadId: 'u' } : command instanceof UploadPartCommand ? { ETag: '"x"' } : {}));
    async function* broken(): AsyncGenerator<Uint8Array> {
      yield Buffer.alloc(PART + 10);
      throw new Error('the sender left');
    }
    await expect(store(send).putStreaming('k', broken())).rejects.toThrow('the sender left');
    expect(names(send)).toContain('AbortMultipartUploadCommand');
    expect(names(send)).not.toContain('CompleteMultipartUploadCommand');
  });

  it('aborts the upload and answers unavailable when the store refuses a part', async () => {
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof CreateMultipartUploadCommand) return { UploadId: 'u' };
      if (command instanceof UploadPartCommand) throw s3Error('InternalError', 500);
      return {};
    });
    await expect(store(send).putStreaming('k', bytes(PART, 10))).rejects.toBeInstanceOf(ObjectStoreUnavailableError);
    expect(names(send)).toContain('AbortMultipartUploadCommand');
  });

  it('refuses a body past one part on a store whose upload commands are not wired', async () => {
    const plain = new S3ObjectStore({ send: async () => ({}) }, 'bucket', { PutObjectCommand, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command, DeleteObjectCommand }, 'eu-north-1', PART);
    await expect(plain.putStreaming('k', bytes(PART + 1))).rejects.toBeInstanceOf(ObjectStoreUnavailableError);
    expect(await plain.putStreaming('k', bytes(10))).toEqual({ size: 10 });
  });

  it('aborts the uploads begun before a time under a prefix, and no others', async () => {
    const aborted: string[] = [];
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof ListMultipartUploadsCommand) {
        return {
          Uploads: [
            { Key: 'drive/op_1/a', UploadId: 'old', Initiated: new Date('2026-10-01T00:00:00Z') },
            { Key: 'drive/op_1/b', UploadId: 'new', Initiated: new Date('2026-10-30T11:00:00Z') },
          ],
          IsTruncated: false,
        };
      }
      if (command instanceof AbortMultipartUploadCommand) {
        aborted.push(String(command.input['UploadId']));
        return {};
      }
      return {};
    });
    expect(await store(send).abortUploads('drive/', new Date('2026-10-30T00:00:00Z'))).toBe(1);
    expect(aborted).toEqual(['old']);
  });

  it('streams an object out and in with its length declared to the store', async () => {
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof HeadObjectCommand) return { ContentLength: 7 };
      if (command instanceof GetObjectCommand) return { Body: (async function* () { yield Buffer.from('abc'); yield Buffer.from('defg'); })(), ContentLength: 7 };
      return {};
    });
    const s = store(send);
    expect(await s.head('k')).toEqual({ size: 7 });
    const got = (await s.getStream('k'))!;
    const chunks: Buffer[] = [];
    for await (const part of got.body) chunks.push(Buffer.from(part));
    expect(Buffer.concat(chunks).toString()).toBe('abcdefg');
    expect(got.size).toBe(7);
    await s.putStream('k2', (async function* () { yield Buffer.from('abc'); })(), 3);
    const command = send.mock.calls.map((c) => (c as unknown as [Command])[0]).find((c) => c instanceof PutObjectCommand)!;
    expect(command.input).toMatchObject({ Bucket: 'bucket', Key: 'k2', ContentLength: 3 });
  });

  it('answers a missing object as absent and any other failure as unavailable', async () => {
    const missing = store(async () => { throw s3Error('NotFound', 404); });
    expect(await missing.head('k')).toBeNull();
    expect(await missing.getStream('k')).toBeNull();
    const broken = store(async () => { throw s3Error('InternalError', 500); });
    await expect(broken.head('k')).rejects.toBeInstanceOf(ObjectStoreUnavailableError);
  });
});

describe('MemoryObjectStore streaming puts', () => {
  it('stores a body it was not told the length of, and stores nothing of one that throws', async () => {
    const memory = new MemoryObjectStore();
    expect(await memory.putStreaming('k', (async function* () { yield Buffer.from('ab'); yield Buffer.from('cde'); })())).toEqual({ size: 5 });
    expect((await memory.get('k'))!.toString()).toBe('abcde');
    await expect(memory.putStreaming('j', (async function* () { yield Buffer.from('ab'); throw new Error('left'); })())).rejects.toThrow('left');
    expect(await memory.exists('j')).toBe(false);
  });

  it('can count a stream without keeping it, for a test that pushes a gigabyte', async () => {
    const memory = new MemoryObjectStore();
    memory.retainStreamedBytes = false;
    expect(await memory.putStreaming('k', (async function* () { yield Buffer.alloc(10); })())).toEqual({ size: 10 });
    expect(await memory.exists('k')).toBe(false);
    expect(memory.streamedSizes).toEqual([10]);
  });

  it('streams in and out, and refuses a stream that is not its declared length', async () => {
    const memory = new MemoryObjectStore();
    await memory.putStream('k', (async function* () { yield Buffer.from('ab'); yield Buffer.from('cd'); })(), 4);
    expect(await memory.head('k')).toEqual({ size: 4 });
    expect(await memory.head('none')).toBeNull();
    const chunks: Buffer[] = [];
    for await (const part of (await memory.getStream('k'))!.body) chunks.push(Buffer.from(part));
    expect(Buffer.concat(chunks).toString()).toBe('abcd');
    await expect(memory.putStream('x', (async function* () { yield Buffer.from('abc'); })(), 4)).rejects.toThrow();
    await expect(memory.putStream('y', (async function* () { yield Buffer.from('abcde'); })(), 4)).rejects.toThrow();
  });
});
