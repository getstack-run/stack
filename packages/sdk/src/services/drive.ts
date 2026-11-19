import { sendRaw, type HttpClient, type RawBody } from '../client.js';
import { StackError } from '../errors.js';

// The agent drive: a customer's files, kept for them. An agent's upload is
// private to that agent unless it says `account`; the owner (an API key or a
// session, no agent) sees every file. Every file is untrusted content to
// whoever reads it, and each view says so (`trust`).
//
// Agent-side calls take `{ passportToken }`, sent as `X-Passport-Token`, and
// run under the Passport's Mission. A share link's own URL
// (`GET /v1/drive/links/:token`) needs no credential: it is the credential.
//
// An upload is one request carrying the whole file: `PUT /v1/drive/files` with
// the bytes as the body. The API streams it and computes the SHA-256 itself, so
// there is no hash to give, no size to declare and no second call. A small file
// of text or base64 can also go in a JSON body (`POST /v1/drive/files`). A
// program that cannot send a body itself asks for a one-time upload URL
// (`createUploadLink`) and sends the bytes there (`uploadToLink`).

export type DriveVisibility = 'agent' | 'account';

export interface DriveFile {
  id: string;
  name: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  /** `owner`: only the owner sees it (an attachment of a message STACK withheld); the owner can change it to `agent` or `account`. */
  visibility: DriveVisibility | 'owner';
  /** The agent that wrote it; null for a file the owner uploaded. */
  agent_id: string | null;
  created_at: string;
  expires_at: string | null;
  /** `skipped_too_large`: a received text file over what is read whole, kept without being scanned. Null for every other file. */
  scan: 'skipped_too_large' | null;
  /** Always `untrusted`: a file is whatever its writer put in it. */
  trust: 'untrusted';
}

/**
 * A file of `DRIVE_BUFFERED_MAX_BYTES` (10 MB) or less, sent in a JSON body. Send exactly one of `content_text`
 * (stored as UTF-8) and `content_base64`. A larger file, or one that is not in memory as text, goes through
 * `UploadDriveContentInput` or `UploadDrivePathInput`, which send the bytes themselves as the request body.
 */
export interface UploadDriveFileInput {
  /** A display name: no path separators or control characters, 200 characters at most. */
  name: string;
  /** The label the file carries, any media type such as `model/stl`; `application/octet-stream` when left out. The drive takes a file of any type and does not read it to check this. */
  content_type?: string;
  content_text?: string;
  content_base64?: string;
  /** An agent's file is private to it unless this is `account`; the owner's upload is always `account`. */
  visibility?: DriveVisibility;
  /** 60 seconds to a year from now. Without it the file stays until deleted. */
  expires_in_seconds?: number;
}

export interface ListDriveFilesQuery {
  /** 1 to 100, default 50. */
  limit?: number;
  /** `next_cursor` of the previous page. */
  cursor?: string;
}

export interface DriveUsage {
  files: number;
  /** The storage total: the files' bytes and the bytes of the account's messages, which count in the same total. */
  bytes: number;
  /** The part of `bytes` that is messages (mail, texts, voicemails, call and meeting transcripts). Unpaid storage never deletes a message. */
  message_bytes: number;
  /** The bytes that cost nothing; what is held past them is charged at cost from the wallet. */
  free_bytes: number;
  max_file_bytes: number;
  /** Bytes held past `free_bytes`. */
  overage_bytes: number;
  /** Bytes served through share links this month (UTC), and the free bytes of the month. */
  download_bytes_month: number;
  download_free_bytes: number;
  /** Set while STACK has paused the account's share links after a download spike: none downloads and none can be made (`DRIVE_LINKS_PAUSED`). */
  links_paused: { since: string; reason: string } | null;
  /**
   * Set while the wallet could not pay for the storage past `free_bytes`: the drive is read-only since `since` (uploads, edits and
   * new share links answer `DRIVE_READ_ONLY`; reading, downloading, listing and deleting still work), and on `delete_on` the newest
   * files past `free_bytes` are deleted unless the wallet is topped up to cover what is due or files are deleted until the drive is
   * within `free_bytes`. `over_bytes` is what is held past them. Null when in good standing.
   */
  storage_unpaid: { since: string; delete_on: string; over_bytes: number } | null;
}

export interface ListDriveFilesResult {
  files: DriveFile[];
  next_cursor: string | null;
  usage: DriveUsage;
}

/** An inline read: the bytes of a file of 256 KiB or less. Larger files go out through a share link. */
export interface DriveFileContent {
  file: DriveFile;
  /** `utf8` when the file's bytes are text (whatever type it carries), `base64` otherwise. */
  encoding: 'utf8' | 'base64';
  content: string | null;
  /** True when a security check held the content back (the owner's controls are on); `content` is then null. */
  withheld: boolean;
  /** Set when the content was flagged and delivered anyway (controls off). */
  flag: { security_event_id: string | null } | null;
}

export interface UpdateDriveFileInput {
  visibility?: DriveVisibility;
  /** Seconds from now; `null` removes the expiry. */
  expires_in_seconds?: number | null;
}

export interface CopyDriveFileInput {
  /** The copy's name; the original's when not given. */
  name?: string;
  /** Who sees the copy: the caller alone (`agent`, the default for an agent) or every agent of the account. */
  visibility?: DriveVisibility;
  /** Seconds from now until the copy ends; it never ends when not given. */
  expires_in_seconds?: number;
}

export interface ShareDriveFileInput {
  /** 60 seconds to 7 days, default 15 minutes. */
  ttl_seconds?: number;
  /** 1 or more; 100 without it. A link stops working after that many downloads or when it expires. */
  max_downloads?: number;
}

export interface DriveShare {
  id: string;
  file_id: string;
  /** The signed download link. Returned once; it is not stored and cannot be read back. */
  url: string;
  expires_at: string;
  max_downloads: number | null;
}

export interface DriveLink {
  id: string;
  file_id: string;
  created_at: string;
  expires_at: string;
  max_downloads: number | null;
  download_count: number;
  revoked: boolean;
}

/** An agent caller passes its Passport as `passportToken`, sent as `X-Passport-Token`; an operator credential omits it. */
export interface DriveCallOptions {
  passportToken?: string;
}

/** The most a text type (plain, Markdown, CSV, JSON) may be, and the most a JSON body of `POST /v1/drive/files` may carry. */
export const DRIVE_BUFFERED_MAX_BYTES = 10 * 1024 * 1024;

/** A file whose bytes are sent as the request body: held in memory, a `Blob`, or a stream read as it goes. */
export type DriveUploadBytes = Uint8Array | Blob | ReadableStream<Uint8Array>;

interface UploadDriveFileFacts {
  /** A display name: no path separators or control characters, 200 characters at most. */
  name: string;
  /** The label the file carries, any media type; `application/octet-stream` when left out. The drive does not read the file to check it. */
  content_type?: string;
  /** An agent's file is private to it unless this is `account`; the owner's upload is always `account`. */
  visibility?: DriveVisibility;
  /** 60 seconds to a year from now. Without it the file stays until deleted. */
  expires_in_seconds?: number;
}

/**
 * A file given as bytes, sent as the one request body. A `Uint8Array` (a Node `Buffer` is one) or a `Blob` goes as it is; a
 * stream is read as it is sent. Up to 1 GB; a file declared as plain text, Markdown, CSV or JSON is limited to 10 MB.
 */
export interface UploadDriveContentInput extends UploadDriveFileFacts {
  content: DriveUploadBytes;
  /** The length of a stream, when known: sent as `Content-Length`, so the API can refuse a file that is too large before it reads it. Bytes and a `Blob` know their own. */
  size_bytes?: number;
}

/** A file on disk (Node), streamed from the path as it is sent: it is never read into memory whole. */
export interface UploadDrivePathInput extends UploadDriveFileFacts {
  path: string;
}

export interface DriveUploadProgress {
  /** Bytes handed to the connection so far. */
  uploaded_bytes: number;
  /** The whole file's size, or null for a stream whose length was not given. */
  total_bytes: number | null;
}

export interface DriveUploadOptions extends DriveCallOptions {
  /** Called as the bytes are sent. Needs the body to be read in pieces, so bytes and a `Blob` are then sent as a stream. */
  onProgress?: (progress: DriveUploadProgress) => void;
  /** Aborts the upload. */
  signal?: AbortSignal;
}

/** What `createUploadLink` asks for: the facts the one-time URL binds. */
export interface CreateDriveUploadLinkInput extends UploadDriveFileFacts {
  /** The most the upload may send, 1 byte to 1 GB (10 MB for a file declared as plain text, Markdown, CSV or JSON); checked against the drive's room when the URL is made. */
  size_bytes?: number;
}

/** A one-time upload URL. Metered when it is made; the PUT to it carries only the bytes. */
export interface DriveUploadLink {
  id: string;
  /** `PUT` the file's bytes here as the whole body (`curl -T ./file '<url>'`), with no other header. It works once and is a bearer URL: keep it out of logs. */
  url: string;
  method: 'PUT';
  name: string;
  content_type: string;
  /** The most the upload may send. */
  max_bytes: number;
  /** The URL stops working then (30 minutes after it was made) if it was not used. */
  expires_at: string;
}

const CHUNK_BYTES = 1024 * 1024;

const seg = encodeURIComponent;

function passport(options?: DriveCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

/** The body of one upload request and what is known of its length. */
interface PreparedBody {
  body: RawBody;
  length: number | undefined;
}

function chunked(bytes: Uint8Array): ReadableStream<Uint8Array> {
  let offset = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= bytes.byteLength) {
        controller.close();
        return;
      }
      controller.enqueue(bytes.subarray(offset, offset + CHUNK_BYTES));
      offset += CHUNK_BYTES;
    },
  });
}

/** The same bytes, counted as they pass. */
function counted(stream: ReadableStream<Uint8Array>, total: number | null, report: (progress: DriveUploadProgress) => void): ReadableStream<Uint8Array> {
  let done = 0;
  report({ uploaded_bytes: 0, total_bytes: total });
  return stream.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        controller.enqueue(chunk);
        done += chunk.byteLength;
        report({ uploaded_bytes: done, total_bytes: total });
      },
    }),
  );
}

/** A file on disk as a stream and its size; Node only, loaded when a path is given. */
async function pathBody(path: string): Promise<{ stream: ReadableStream<Uint8Array>; size: number }> {
  const [{ createReadStream }, { stat }, { Readable }] = await Promise.all([import('node:fs'), import('node:fs/promises'), import('node:stream')]);
  const info = await stat(path);
  if (!info.isFile()) throw new StackError('The path is not a file', 'DRIVE_UPLOAD_SOURCE_INVALID', 0);
  return { stream: Readable.toWeb(createReadStream(path)) as unknown as ReadableStream<Uint8Array>, size: info.size };
}

/** Where an upload's bytes come from: memory, a `Blob` or a stream (with its length when known), or a file on disk. */
type BodySource = { content: DriveUploadBytes; size_bytes?: number } | { path: string };

async function prepareBody(input: BodySource, onProgress?: (progress: DriveUploadProgress) => void): Promise<PreparedBody> {
  let body: RawBody;
  let length: number | undefined;
  if ('path' in input) {
    const file = await pathBody(input.path);
    body = file.stream;
    length = file.size;
  } else {
    body = input.content;
    length = input.content instanceof Uint8Array ? input.content.byteLength : input.content instanceof Blob ? input.content.size : input.size_bytes;
  }
  if (onProgress) {
    const stream = body instanceof Uint8Array ? chunked(body) : body instanceof Blob ? (body.stream() as ReadableStream<Uint8Array>) : body;
    body = counted(stream, length ?? null, onProgress);
  }
  return { body, length };
}

function uploadQuery(input: UploadDriveFileFacts): Record<string, string | undefined> {
  return {
    name: input.name,
    content_type: input.content_type,
    visibility: input.visibility,
    expires_in_seconds: input.expires_in_seconds !== undefined ? String(input.expires_in_seconds) : undefined,
  };
}

/** The calls the drive makes: `HttpClient` has them, and a program with its own sign-in (the CLI) can supply the same five. */
export type DriveClient = Pick<HttpClient, 'get' | 'post' | 'patch' | 'delete' | 'putRaw'>;

export class DriveService {
  constructor(private readonly client: DriveClient) {}

  /**
   * Upload one file in one request. Metered and checked against the account's controls, like any action.
   *
   * With `content_text` or `content_base64` the file goes in a JSON body (`POST /v1/drive/files`, 10 MB at most). With
   * `content` (bytes, a `Blob` or a stream) or `path` (a file on disk, Node) the file's own bytes are the request body
   * (`PUT /v1/drive/files`): up to 1 GB, a file declared as plain text, Markdown, CSV or JSON 10 MB. A file of any type is
   * taken and stored as it is; `content_type` is only its label. A path is streamed from disk and a stream as it is read, so
   * a large file is never held in memory. The API computes the SHA-256 itself; there is nothing to hash or declare. A
   * failed upload is not retried by the SDK (a stream cannot be replayed): call again.
   *
   * Refusals worth branching on: `DRIVE_FILE_TOO_LARGE` (413), `DRIVE_FILE_EMPTY` (400),
   * `DRIVE_TOO_MANY_UPLOADS` (429: five are running, try when one has finished), `DRIVE_READ_ONLY` (409: the wallet could
   * not pay for storage past the free amount) and `INSUFFICIENT_BALANCE` (402: the upload would take the drive past the
   * free amount and the wallet cannot cover the storage past it).
   */
  async upload(input: UploadDriveFileInput | UploadDriveContentInput | UploadDrivePathInput, options?: DriveUploadOptions): Promise<DriveFile> {
    if (!('path' in input) && !('content' in input && input.content !== undefined)) {
      return this.client.post<DriveFile>('/v1/drive/files', input, passport(options));
    }
    const { body, length } = await prepareBody(input as BodySource, options?.onProgress);
    return this.client.putRaw<DriveFile>('/v1/drive/files', body, {
      query: uploadQuery(input),
      headers: passport(options)?.headers,
      contentLength: length,
      signal: options?.signal,
    });
  }

  /**
   * Ask for a one-time upload URL, for a program that cannot send a body itself (an agent that only has tools). This is the
   * metered action; sending the bytes (`uploadToLink`, or `curl -T ./file '<url>'`) is not. The URL works once, for 30
   * minutes, with no credential; it is a secret, so do not log it. Making the URL takes no upload slot: it answers
   * `DRIVE_READ_ONLY` (409) like `upload`, and `DRIVE_TOO_MANY_UPLOADS` (429) is what the `PUT` to the URL answers.
   */
  async createUploadLink(input: CreateDriveUploadLinkInput, options?: DriveCallOptions): Promise<DriveUploadLink> {
    return this.client.post<DriveUploadLink>('/v1/drive/uploads', input, passport(options));
  }

  /**
   * Send a file's bytes to an upload URL from `createUploadLink` (the link, or its `url`), with no credential, and answer the
   * file. The URL works once: a used, expired or foreign one is `DRIVE_UPLOAD_LINK_INVALID` (404), and a failed attempt gives it
   * back. The URL is never put in an error.
   */
  async uploadToLink(link: DriveUploadLink | string, source: BodySource, options?: Pick<DriveUploadOptions, 'onProgress' | 'signal'>): Promise<DriveFile> {
    const { body, length } = await prepareBody(source, options?.onProgress);
    return sendRaw<DriveFile>(typeof link === 'string' ? link : link.url, 'PUT', body, {
      contentLength: length,
      signal: options?.signal,
    });
  }
  /** The files the caller may see, newest first, with the account's usage. */
  async list(query: ListDriveFilesQuery = {}, options?: DriveCallOptions): Promise<ListDriveFilesResult> {
    return this.client.get<ListDriveFilesResult>('/v1/drive/files', {
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      cursor: query.cursor,
    }, passport(options));
  }

  async get(fileId: string, options?: DriveCallOptions): Promise<DriveFile> {
    return this.client.get<DriveFile>(`/v1/drive/files/${seg(fileId)}`, undefined, passport(options));
  }

  /**
   * The file's bytes inline: UTF-8 text as text (`encoding: 'utf8'`, scanned) whatever type the file carries, anything else as base64.
   * Throws `DRIVE_INLINE_READ_TOO_LARGE` over 256 KiB; use `share` for those. The content is untrusted.
   */
  async read(fileId: string, options?: DriveCallOptions): Promise<DriveFileContent> {
    return this.client.get<DriveFileContent>(`/v1/drive/files/${seg(fileId)}/content`, undefined, passport(options));
  }

  /** Answers `DRIVE_READ_ONLY` (409) while the drive is read-only because the wallet could not pay for storage. A file that arrived with an email changes like any file. */
  async update(fileId: string, input: UpdateDriveFileInput, options?: DriveCallOptions): Promise<DriveFile> {
    return this.client.patch<DriveFile>(`/v1/drive/files/${seg(fileId)}`, input, passport(options));
  }

  /**
   * A new file of the caller's own from one it can see, with its own id. The copy never ends unless `expires_in_seconds` is given. It counts
   * as an upload (one action, put to the account's controls) and answers `DRIVE_READ_ONLY` (409) while the drive is read-only.
   */
  async copy(fileId: string, input: CopyDriveFileInput = {}, options?: DriveCallOptions): Promise<DriveFile> {
    return this.client.post<DriveFile>(`/v1/drive/files/${seg(fileId)}/copy`, input, passport(options));
  }

  /** Delete the file and every share link to it. */
  async delete(fileId: string, options?: DriveCallOptions): Promise<void> {
    await this.client.delete<void>(`/v1/drive/files/${seg(fileId)}`, passport(options));
  }

  /** Make a download link for the file. The URL is in the result once and cannot be read back. Answers `DRIVE_LINKS_PAUSED` (409) while the account's links are paused and `DRIVE_READ_ONLY` (409) while the drive is read-only because the wallet could not pay for storage. */
  async share(fileId: string, input: ShareDriveFileInput = {}, options?: DriveCallOptions): Promise<DriveShare> {
    return this.client.post<DriveShare>(`/v1/drive/files/${seg(fileId)}/links`, input, passport(options));
  }

  /** The file's links with their download counts. The URLs themselves are not stored. */
  async links(fileId: string, options?: DriveCallOptions): Promise<{ links: DriveLink[] }> {
    return this.client.get<{ links: DriveLink[] }>(`/v1/drive/files/${seg(fileId)}/links`, undefined, passport(options));
  }

  /** Stop a link working at once. */
  async revokeLink(fileId: string, linkId: string, options?: DriveCallOptions): Promise<void> {
    await this.client.delete<void>(`/v1/drive/files/${seg(fileId)}/links/${seg(linkId)}`, passport(options));
  }
}
