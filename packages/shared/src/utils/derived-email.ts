// `derived.email.*` — the recipients and text of an outbound email whose
// headers are not plain JSON fields.
//
// Gmail sends a whole RFC 822 message as base64url `raw`; Microsoft Graph
// accepts either JSON recipient objects or a base64 MIME message. Constraints
// cannot see recipients inside an encoded string, so this reads them once per
// request and exposes them as `derived.email.recipients` (every To, Cc and
// Bcc address, lowercased) and `derived.email.text` (subject plus decoded
// text parts).
//
// Fail closed: an endpoint not listed here, an upload variant that cannot be
// read (multipart, resumable), a draft sent by id, or any parse failure gives
// `undefined`. A constraint on an undefined path fails, so a recipient
// allowlist refuses everything it cannot read.
//
// Data-flow hook (for the scope wall): `deriveRequestEmail(req)?.text` is the
// decoded message content to fingerprint. `undefined` on a send endpoint
// means the content could not be read and must not be treated as clean.

import type { NormalizedRequest } from './constraints.js';
import { parseRawEmail, parseAddressList, type ParsedEmail } from './rfc822.js';

export interface DerivedEmail {
  provider: 'gmail' | 'outlook';
  recipients: string[];
  from: string[];
  subject: string;
  text: string;
  text_truncated: boolean;
  opaque_parts: number;
}

const GMAIL_HOSTS = new Set(['gmail.googleapis.com', 'www.googleapis.com']);
const GRAPH_HOSTS = new Set(['graph.microsoft.com']);

const GMAIL_SEND = /^\/gmail\/v1\/users\/[^/]+\/messages\/send$/;
const GMAIL_DRAFTS = /^\/gmail\/v1\/users\/[^/]+\/drafts$/;
const GMAIL_DRAFT = /^\/gmail\/v1\/users\/[^/]+\/drafts\/[^/]+$/;
const GMAIL_UPLOAD_SEND = /^\/upload\/gmail\/v1\/users\/[^/]+\/messages\/send$/;
const GMAIL_UPLOAD_DRAFTS = /^\/upload\/gmail\/v1\/users\/[^/]+\/drafts$/;
const GMAIL_UPLOAD_DRAFT = /^\/upload\/gmail\/v1\/users\/[^/]+\/drafts\/[^/]+$/;

const GRAPH_SEND = /^\/(?:v1\.0|beta)\/(?:me|users\/[^/]+)\/sendMail$/;
const GRAPH_CREATE = /^\/(?:v1\.0|beta)\/(?:me|users\/[^/]+)\/(?:mailFolders\/[^/]+\/)?messages$/;
const GRAPH_FORWARD = /^\/(?:v1\.0|beta)\/(?:me|users\/[^/]+)\/(?:mailFolders\/[^/]+\/)?messages\/[^/]+\/(?:forward|createForward)$/;

const cache = new WeakMap<NormalizedRequest, DerivedEmail | null>();

/** The outbound email a request carries, or undefined when it cannot be read. */
export function deriveRequestEmail(req: NormalizedRequest): DerivedEmail | undefined {
  if (cache.has(req)) return cache.get(req) ?? undefined;
  let result: DerivedEmail | null;
  try {
    result = derive(req);
  } catch {
    result = null; // a reader bug must never become an allow
  }
  cache.set(req, result);
  return result ?? undefined;
}

/**
 * Does this request send or stage an email whose content is encoded (Gmail
 * `raw`, a Graph MIME or JSON message)? True exactly for the endpoints
 * deriveRequestEmail reads, whether or not the message could be read. When
 * this is true and deriveRequestEmail gives undefined, the content is
 * unknown and a data-flow check must not treat it as clean.
 */
export function isEncodedEmailRequest(req: NormalizedRequest): boolean {
  const path = req.url.pathname;
  const host = req.url.host.replace(/:443$/, '');
  if (GMAIL_HOSTS.has(host)) {
    return (req.method === 'POST' && (GMAIL_SEND.test(path) || GMAIL_DRAFTS.test(path) || GMAIL_UPLOAD_SEND.test(path) || GMAIL_UPLOAD_DRAFTS.test(path))) ||
      (req.method === 'PUT' && (GMAIL_DRAFT.test(path) || GMAIL_UPLOAD_DRAFT.test(path)));
  }
  return GRAPH_HOSTS.has(host) && req.method === 'POST' && (GRAPH_SEND.test(path) || GRAPH_CREATE.test(path) || GRAPH_FORWARD.test(path));
}

function fromParsed(provider: DerivedEmail['provider'], parsed: ParsedEmail | null): DerivedEmail | null {
  if (!parsed) return null;
  return {
    provider, recipients: parsed.recipients, from: parsed.from, subject: parsed.subject,
    text: parsed.text, text_truncated: parsed.text_truncated, opaque_parts: parsed.opaque_parts,
  };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function derive(req: NormalizedRequest): DerivedEmail | null {
  const path = req.url.pathname;
  const host = req.url.host.replace(/:443$/, '');
  if (GMAIL_HOSTS.has(host)) {
    if (req.method === 'POST' && GMAIL_SEND.test(path)) {
      return fromParsed('gmail', parseRawEmail(asRecord(req.body)?.['raw'], 'base64url'));
    }
    if ((req.method === 'POST' && GMAIL_DRAFTS.test(path)) || (req.method === 'PUT' && GMAIL_DRAFT.test(path))) {
      const message = asRecord(asRecord(req.body)?.['message']);
      return fromParsed('gmail', parseRawEmail(message?.['raw'], 'base64url'));
    }
    const upload = (req.method === 'POST' && (GMAIL_UPLOAD_SEND.test(path) || GMAIL_UPLOAD_DRAFTS.test(path))) ||
      (req.method === 'PUT' && GMAIL_UPLOAD_DRAFT.test(path));
    if (upload) {
      // Only a simple media upload carries the bare message. Multipart and
      // resumable uploads interleave metadata and chunks; they are refused.
      if (req.query['uploadType'] !== 'media') return null;
      return fromParsed('gmail', parseRawEmail(req.body, 'none'));
    }
    return null;
  }
  if (GRAPH_HOSTS.has(host) && req.method === 'POST') {
    if (GRAPH_SEND.test(path)) {
      if (typeof req.body === 'string') return fromParsed('outlook', parseRawEmail(req.body, 'base64'));
      const message = asRecord(asRecord(req.body)?.['message']);
      return message ? graphMessage(message, []) : null;
    }
    if (GRAPH_CREATE.test(path)) {
      if (typeof req.body === 'string') return fromParsed('outlook', parseRawEmail(req.body, 'base64'));
      const message = asRecord(req.body);
      return message ? graphMessage(message, []) : null;
    }
    if (GRAPH_FORWARD.test(path)) {
      const body = asRecord(req.body);
      if (!body) return null;
      const extra = graphRecipients(body['toRecipients']);
      if (!extra) return null;
      const message = body['message'] === undefined ? {} : asRecord(body['message']);
      if (!message) return null;
      const comment = typeof body['comment'] === 'string' ? body['comment'] : '';
      return graphMessage(message, extra, comment);
    }
  }
  return null;
}

/** Graph recipient arrays: [{ emailAddress: { address } }]. Absent is empty. */
function graphRecipients(value: unknown): string[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > 1_000) return null;
  const out: string[] = [];
  for (const entry of value) {
    const address = asRecord(asRecord(entry)?.['emailAddress'])?.['address'];
    if (typeof address !== 'string') return null;
    const parsed = parseAddressList(address);
    if (!parsed || parsed.length !== 1) return null;
    out.push(parsed[0]!);
  }
  return out;
}

function graphMessage(message: Record<string, unknown>, extra: string[], comment = ''): DerivedEmail | null {
  const to = graphRecipients(message['toRecipients']);
  const cc = graphRecipients(message['ccRecipients']);
  const bcc = graphRecipients(message['bccRecipients']);
  if (!to || !cc || !bcc) return null;
  const subject = typeof message['subject'] === 'string' ? message['subject'] : '';
  const bodyContent = asRecord(message['body'])?.['content'];
  const attachments = message['attachments'];
  if (attachments !== undefined && !Array.isArray(attachments)) return null;
  const text = [subject, comment, typeof bodyContent === 'string' ? bodyContent : ''].filter(Boolean).join('\n');
  return {
    provider: 'outlook',
    recipients: [...new Set([...extra, ...to, ...cc, ...bcc])],
    from: [],
    subject,
    text,
    text_truncated: false,
    opaque_parts: Array.isArray(attachments) ? attachments.length : 0,
  };
}
