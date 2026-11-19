import { statSync } from 'node:fs';
import { basename, extname } from 'node:path';
import { Stack, StackError, type UploadDrivePathInput } from '@getstackrun/sdk';
import { API_URL, api, currentControlRef, requireToken, takeFlag } from './api.js';
import { BUFFERED_MAX_BYTES, MAX_FILE_BYTES, progressWriter } from './drive-upload.js';
import { printJson } from './format.js';
import { readSecretFromStdin } from './secret-input.js';

// The agent drive: an account's files. An agent's file is private to it unless
// it is shared with the account; the owner sees every file. Every file is
// untrusted content to whoever reads it.
//
// An agent acts under its Passport. The Passport is a secret, so it is read from
// stdin (piped, or typed at a hidden prompt) and never from argv, and only with
// --passport-stdin: without it the call runs as the operator.

// The drive takes a file of any type and stores it as it is: the type is only a label. This is the label a file's extension suggests
// (the same as the API's, which a test keeps in step); a file whose extension is not here is sent with no type and the API labels it
// application/octet-stream. --type names another.
const TYPE_BY_EXTENSION: Record<string, string> = {
  '.txt': 'text/plain',
  '.log': 'text/plain',
  '.md': 'text/markdown',
  '.markdown': 'text/markdown',
  '.csv': 'text/csv',
  '.json': 'application/json',
  '.pdf': 'application/pdf',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.ogg': 'audio/ogg',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.zip': 'application/zip',
  '.gz': 'application/gzip',
  '.stl': 'model/stl',
  '.3mf': 'model/3mf',
  '.step': 'model/step',
  '.stp': 'model/step',
  '.dxf': 'image/vnd.dxf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};
/** A file declared as one of these is read whole by the API, so it is held to 10 MB. */
const TEXT_TYPES = new Set(['text/plain', 'text/markdown', 'text/csv', 'application/json']);

const PASSPORT_ARGV_FLAGS = new Set(['--passport', '--passport-token', '--token']);

function flag(args: string[], name: string): string | undefined {
  const value = takeFlag(args, name);
  if (value === true) throw new Error(`${name} needs a value`);
  return typeof value === 'string' ? value : undefined;
}

function wholeNumber(args: string[], name: string): number | undefined {
  const value = flag(args, name);
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a whole number`);
  return Number(value);
}

/** A switch never takes a value, so it cannot swallow the positional after it. */
function takeSwitch(args: string[], name: string): boolean {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

function positional(args: string[], what: string): string {
  const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (!value) throw new Error(`Invalid input: ${what} is required`);
  return value;
}

function refusePassportInArgv(args: string[]): void {
  if (args.some((arg) => PASSPORT_ARGV_FLAGS.has(arg.split('=')[0] ?? arg))) {
    throw new Error('Passport tokens must not be placed in argv. Pipe the token on stdin or type it at the hidden prompt.');
  }
}

async function passportHeaders(args: string[]): Promise<{ headers?: Record<string, string> }> {
  if (!takeSwitch(args, '--passport-stdin')) return {};
  const token = await readSecretFromStdin('Passport token: ');
  if (!token) throw new Error("No Passport token: pipe the account agent's Passport on stdin or type it at the prompt");
  return { headers: { 'X-Passport-Token': token } };
}

function filePath(id: string): string {
  return `/v1/drive/files/${encodeURIComponent(id)}`;
}

/** What `drive upload` sends: one file on disk, streamed as the body of a single request. */
function planUpload(args: string[]): UploadDrivePathInput {
  const file = positional(args, 'file');
  const type = flag(args, '--type') ?? TYPE_BY_EXTENSION[extname(file).toLowerCase()];
  const isText = type !== undefined && TEXT_TYPES.has(type);
  const name = flag(args, '--name') ?? basename(file);
  const expires = wholeNumber(args, '--expires');
  const visibility = takeSwitch(args, '--account') ? 'account' : takeSwitch(args, '--private') ? 'agent' : undefined;
  const size = statSync(file).size;
  if (size === 0) throw new Error('Invalid input: the file is empty');
  if (size > MAX_FILE_BYTES) throw new Error('Invalid input: a drive file is 1 GB at most');
  if (isText && size > BUFFERED_MAX_BYTES) throw new Error('Invalid input: a file typed as text, Markdown, CSV or JSON is 10 MB at most');
  return {
    path: file,
    name,
    ...(type !== undefined ? { content_type: type } : {}),
    ...(visibility ? { visibility } : {}),
    ...(expires !== undefined ? { expires_in_seconds: expires } : {}),
  };
}

/** The file goes up as one request, streamed from disk, under the CLI's own sign-in; progress is on stderr. */
async function uploadFile(input: UploadDrivePathInput, passportToken: string | undefined): Promise<unknown> {
  const signedIn = new Stack({ apiKey: await requireToken(), baseUrl: API_URL });
  const ref = currentControlRef();
  const stack = ref === undefined ? signedIn : signedIn.withControlRef(ref);
  try {
    return await stack.drive.upload(input, { ...(passportToken ? { passportToken } : {}), onProgress: progressWriter() });
  } catch (error) {
    if (error instanceof StackError && error.status > 0) throw new Error(`${error.message} (${error.code})`, { cause: error });
    throw error;
  }
}

export async function cmdDrive(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  refusePassportInArgv(args);
  const sub = args.shift();

  if (sub === 'list') {
    const limit = flag(args, '--limit');
    const cursor = flag(args, '--cursor');
    const headers = await passportHeaders(args);
    return printJson(await api('GET', '/v1/drive/files', { query: { ...(limit ? { limit } : {}), ...(cursor ? { cursor } : {}) }, ...headers }));
  }

  if (sub === 'upload') {
    const input = planUpload(args);
    const headers = await passportHeaders(args);
    return printJson(await uploadFile(input, headers.headers?.['X-Passport-Token']));
  }

  const id = positional(args, 'file id');
  if (sub === 'get') return printJson(await api('GET', filePath(id), await passportHeaders(args)));
  if (sub === 'read') return printJson(await api('GET', `${filePath(id)}/content`, await passportHeaders(args)));
  if (sub === 'delete') {
    const headers = await passportHeaders(args);
    await api('DELETE', filePath(id), { expectEmpty: true, ...headers });
    return printJson({ deleted: id });
  }
  if (sub === 'update') {
    const body: Record<string, unknown> = {};
    if (takeSwitch(args, '--account')) body['visibility'] = 'account';
    if (takeSwitch(args, '--private')) body['visibility'] = 'agent';
    if (takeSwitch(args, '--no-expiry')) body['expires_in_seconds'] = null;
    const expires = wholeNumber(args, '--expires');
    if (expires !== undefined) body['expires_in_seconds'] = expires;
    const headers = await passportHeaders(args);
    return printJson(await api('PATCH', filePath(id), { body, ...headers }));
  }
  if (sub === 'copy') {
    const body: Record<string, unknown> = {};
    const name = flag(args, '--name');
    if (name !== undefined) body['name'] = name;
    if (takeSwitch(args, '--account')) body['visibility'] = 'account';
    if (takeSwitch(args, '--private')) body['visibility'] = 'agent';
    const expires = wholeNumber(args, '--expires');
    if (expires !== undefined) body['expires_in_seconds'] = expires;
    const headers = await passportHeaders(args);
    return printJson(await api('POST', `${filePath(id)}/copy`, { body, ...headers }));
  }
  if (sub === 'share') {
    const ttl = wholeNumber(args, '--ttl');
    const max = wholeNumber(args, '--max-downloads');
    const headers = await passportHeaders(args);
    const body = { ...(ttl !== undefined ? { ttl_seconds: ttl } : {}), ...(max !== undefined ? { max_downloads: max } : {}) };
    return printJson(await api('POST', `${filePath(id)}/links`, { body, ...headers }));
  }
  if (sub === 'links') return printJson(await api('GET', `${filePath(id)}/links`, await passportHeaders(args)));
  if (sub === 'unshare') {
    const linkId = positional(args, 'link id');
    const headers = await passportHeaders(args);
    await api('DELETE', `${filePath(id)}/links/${encodeURIComponent(linkId)}`, { expectEmpty: true, ...headers });
    return printJson({ ended: linkId });
  }
  throw new Error('Invalid input: drive takes list, upload, get, read, update, copy, delete, share, links or unshare');
}
