import { readFileSync, statSync } from 'node:fs';
import { basename, extname } from 'node:path';
import { api } from './api.js';
import { invokeHint } from './auth.js';
import { printJson } from './format.js';
import { flag, positional, takeSwitch } from './account-args.js';

// The email commands of an agent account: send, reply and forward. The wire shapes are the API's
// (`POST /v1/accounts/:id/email/send`, `.../messages/:messageId/reply` and `.../forward`). The CLI
// depends on nothing of the API's, so the one number it checks, what the files sent from this machine
// may come to, is copied here.

/** What the files sent from this machine come to at most, in all (10 MB): the size of one JSON request. A larger file goes up to the drive and is attached by its id. */
export const INLINE_ATTACHMENTS_MAX_BYTES = 10 * 1024 * 1024;

const DRIVE_FILE_ID = /^drv_[\w-]{8,64}$/;

/** The media type of a local file by its extension; anything not listed goes as application/octet-stream. */
const MEDIA_TYPE_BY_EXTENSION: Record<string, string> = {
  '.txt': 'text/plain',
  '.md': 'text/markdown',
  '.csv': 'text/csv',
  '.html': 'text/html',
  '.ics': 'text/calendar',
  '.json': 'application/json',
  '.pdf': 'application/pdf',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.zip': 'application/zip',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.mp4': 'video/mp4',
};

type EmailAttachment = { file_id: string } | { filename: string; content_type: string; content_base64: string };

/** Every use of a flag that may repeat, each value split at commas: `--to a@x.test,b@x.test --to c@x.test`. */
function addressList(args: string[], name: string): string[] {
  const values: string[] = [];
  for (let value = flag(args, name); value !== undefined; value = flag(args, name)) {
    values.push(...value.split(',').map((part) => part.trim()).filter((part) => part !== ''));
  }
  return values;
}

/** Every use of a flag that may repeat, each value kept whole (a file name may hold a comma). */
function repeated(args: string[], name: string): string[] {
  const values: string[] = [];
  for (let value = flag(args, name); value !== undefined; value = flag(args, name)) values.push(value);
  return values;
}

function megabytes(bytes: number): string {
  return `${(Math.ceil((bytes / (1024 * 1024)) * 10) / 10).toFixed(1)} MB`;
}

/** A drive file id attaches that drive file; anything else is a local file, read and sent inline. */
export function readAttachments(args: string[]): EmailAttachment[] {
  const attachments: EmailAttachment[] = [];
  let inlineBytes = 0;
  for (const value of repeated(args, '--attach')) {
    if (DRIVE_FILE_ID.test(value)) {
      attachments.push({ file_id: value });
      continue;
    }
    let size: number;
    try {
      size = statSync(value).size;
    } catch {
      throw new Error(`Attachment not found: ${value}. Give a file on this machine or the id of a drive file (drv_...).`);
    }
    inlineBytes += size;
    if (inlineBytes > INLINE_ATTACHMENTS_MAX_BYTES) {
      throw new Error(
        `The files sent from this machine come to ${megabytes(inlineBytes)}; ${megabytes(INLINE_ATTACHMENTS_MAX_BYTES)} is the most. ` +
          `Upload the larger file with \`${invokeHint('drive upload <file>')}\` and attach it by the drive file id it prints.`,
      );
    }
    attachments.push({
      filename: basename(value),
      content_type: MEDIA_TYPE_BY_EXTENSION[extname(value).toLowerCase()] ?? 'application/octet-stream',
      content_base64: Buffer.from(readFileSync(value)).toString('base64'),
    });
  }
  return attachments;
}

/** A text from a flag or from a file, never both. */
function text(args: string[], name: string, fileName: string): string | undefined {
  const value = flag(args, name);
  const file = flag(args, fileName);
  if (value !== undefined && file !== undefined) throw new Error(`Use ${name} or ${fileName}, not both`);
  return file !== undefined ? readFileSync(file, 'utf8') : value;
}

function readBodyText(args: string[]): string {
  const body = text(args, '--body', '--body-file');
  if (body === undefined) throw new Error('--body or --body-file is required');
  return body;
}

/** A typo in a flag must not send a mail the person did not mean, so a reply and a forward take no argument they do not know. */
function refuseLeftovers(args: string[]): void {
  if (args.length > 0) throw new Error(`Unexpected ${args.length === 1 ? 'argument' : 'arguments'}: ${args.join(' ')}`);
}

/** The To of a send or a forward: one address stays a plain string, as it always was; several go as a list. A To is required: --cc or --bcc alone is refused. */
function recipients(args: string[]): string | string[] {
  const to = addressList(args, '--to');
  if (to.length === 0) throw new Error('--to is required');
  return to.length === 1 ? (to[0] as string) : to;
}

/** The copies and the attachments every one of the three commands may carry. */
function copiesAndFiles(args: string[]): Record<string, unknown> {
  const cc = addressList(args, '--cc');
  const bcc = addressList(args, '--bcc');
  const attachments = readAttachments(args);
  return {
    ...(cc.length > 0 ? { cc } : {}),
    ...(bcc.length > 0 ? { bcc } : {}),
    ...(attachments.length > 0 ? { attachments } : {}),
  };
}

export async function cmdSendEmail(path: string, args: string[]): Promise<void> {
  const to = recipients(args);
  const subject = flag(args, '--subject');
  const threadId = flag(args, '--thread-id');
  const html = flag(args, '--body-html-file');
  const replyToMessage = flag(args, '--reply-to-message');
  const more = copiesAndFiles(args);
  const body: Record<string, unknown> = {
    to,
    ...more,
    ...(subject !== undefined ? { subject } : {}),
    ...(threadId !== undefined ? { thread_id: threadId } : {}),
    ...(replyToMessage !== undefined ? { reply_to_message: replyToMessage } : {}),
    body: readBodyText(args),
    ...(html !== undefined ? { body_html: readFileSync(html, 'utf8') } : {}),
  };
  return printJson(await api('POST', `${path}/email/send`, { body }));
}

export async function cmdReplyEmail(path: string, args: string[]): Promise<void> {
  const replyAll = takeSwitch(args, '--all');
  const noQuote = takeSwitch(args, '--no-quote');
  const subject = flag(args, '--subject');
  const html = flag(args, '--body-html-file');
  const more = copiesAndFiles(args);
  const body: Record<string, unknown> = {
    body: readBodyText(args),
    ...(html !== undefined ? { body_html: readFileSync(html, 'utf8') } : {}),
    ...(replyAll ? { reply_all: true } : {}),
    ...more,
    ...(subject !== undefined ? { subject } : {}),
    ...(noQuote ? { include_quote: false } : {}),
  };
  const messageId = positional(args, 'message id');
  refuseLeftovers(args);
  return printJson(await api('POST', `${path}/messages/${encodeURIComponent(messageId)}/reply`, { body }));
}

export async function cmdForwardEmail(path: string, args: string[]): Promise<void> {
  const to = recipients(args);
  const noAttachments = takeSwitch(args, '--no-attachments');
  const noQuote = takeSwitch(args, '--no-quote');
  const more = copiesAndFiles(args);
  const note = text(args, '--body', '--body-file');
  const body: Record<string, unknown> = {
    to,
    ...more,
    ...(note !== undefined ? { body: note } : {}),
    ...(noAttachments ? { include_attachments: false } : {}),
    ...(noQuote ? { include_quote: false } : {}),
  };
  const messageId = positional(args, 'message id');
  refuseLeftovers(args);
  return printJson(await api('POST', `${path}/messages/${encodeURIComponent(messageId)}/forward`, { body }));
}
