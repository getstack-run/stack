// Bounded, fail-closed RFC 822 / 5322 reader for outbound email.
//
// WHY. Gmail's `messages.send` takes the whole message as base64url `raw`, so
// the recipients live in the To/Cc/Bcc headers inside an opaque string. A
// constraint could never see them, and a recipient allowlist was impossible.
// This module decodes the headers so `derived.email.recipients` can be
// constrained like any other field.
//
// THREAT MODEL. The message is written by the agent, which may be under
// prompt injection. The danger is a parser differential: STACK reads fewer
// recipients than the mail provider delivers to. So every rule here errs
// toward refusing:
//
// - Anything this reader does not fully understand returns `null`, and a
//   constraint on a derived field then fails (unresolved path = deny).
// - Every To/Cc/Bcc header is read, including repeats and Resent-* variants,
//   and folded continuation lines are joined first, so a Bcc hidden on a
//   folded line or in a second header is still seen.
// - An RFC 2047 encoded word that decodes to anything containing "@" in a
//   recipient header is refused: a provider that decodes before parsing would
//   find an address this reader never saw.
// - Only plain ASCII addr-specs are accepted. Quoted local parts, source
//   routes, IDN and SMTPUTF8 addresses are refused rather than guessed at.
// - Bare CR, NUL, a header line without a colon, and malformed MIME all fail.
//
// COST. Every loop is a single linear pass over bounded input. There is no
// regular expression with nested or overlapping quantifiers. Hard caps bound
// the encoded size, header block, header count, address count, comment
// nesting, MIME depth and part count.

export const RFC822_LIMITS = {
  /** Largest encoded message considered (Gmail's own ceiling is 35 MB). */
  maxEncodedChars: 48 * 1024 * 1024,
  /** Largest header block, per message or MIME part. */
  maxHeaderBytes: 256 * 1024,
  maxHeaderFields: 1_000,
  maxAddresses: 1_000,
  maxCommentDepth: 16,
  maxMimeDepth: 6,
  maxMimeParts: 200,
  /** Text beyond this is cut; the cut is recorded in `text_truncated`. */
  maxTextChars: 2 * 1024 * 1024,
} as const;

export interface ParsedEmail {
  /** Every delivery address from To, Cc, Bcc and Resent-*, lowercased, de-duplicated. */
  recipients: string[];
  to: string[];
  cc: string[];
  bcc: string[];
  from: string[];
  subject: string;
  /** Subject plus every decoded text part, for content inspection. */
  text: string;
  text_truncated: boolean;
  /** Parts that were not text (images, PDFs, archives): present but not inspected. */
  opaque_parts: number;
}

export type RawEmailEncoding = 'base64url' | 'base64' | 'none';

/**
 * Decode and parse an outbound message. `raw` is the provider's field value:
 * base64url for Gmail, standard base64 for Microsoft Graph MIME, or the
 * message itself for a media upload. Returns null whenever the message cannot
 * be read completely.
 */
export function parseRawEmail(raw: unknown, encoding: RawEmailEncoding): ParsedEmail | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > RFC822_LIMITS.maxEncodedChars) return null;
  let bytes: Buffer | null;
  if (encoding === 'none') {
    // A JS string above U+00FF cannot be the octets that were sent; reading
    // it as latin1 would silently truncate characters.
    for (let i = 0; i < raw.length; i++) if (raw.charCodeAt(i) > 0xff) return null;
    bytes = Buffer.from(raw, 'latin1');
  } else bytes = strictBase64Decode(raw, encoding);
  if (!bytes) return null;
  return parseRfc822(bytes);
}

/**
 * Strict base64 / base64url decoding. Node's decoder silently skips
 * characters outside the alphabet, which would let two parties read the same
 * string differently, so the alphabet is checked first. Graph MIME may be
 * wrapped at 76 columns, so CR and LF are dropped in `base64` mode only.
 */
export function strictBase64Decode(input: string, encoding: 'base64url' | 'base64'): Buffer | null {
  const text = encoding === 'base64' ? input.replace(/[\r\n]/g, '') : input;
  let end = text.length;
  while (end > 0 && text.charCodeAt(end - 1) === 0x3d /* = */) end--;
  if (text.length - end > 2) return null;
  for (let i = 0; i < end; i++) {
    const c = text.charCodeAt(i);
    const alnum = (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39);
    const extra = encoding === 'base64url' ? c === 0x2d || c === 0x5f : c === 0x2b || c === 0x2f;
    if (!alnum && !extra) return null;
  }
  if (end % 4 === 1) return null;
  if (end !== text.length && text.length % 4 !== 0) return null;
  return Buffer.from(text.slice(0, end), encoding);
}

interface HeaderField { name: string; value: string }

/** Parse a complete message. Exported for tests and for media uploads. */
export function parseRfc822(message: Buffer): ParsedEmail | null {
  const state = { parts: 0, opaque: 0, text: [] as string[], textChars: 0, truncated: false };
  const top = splitHeaderBlock(message);
  if (!top) return null;

  const fieldsByName = new Map<string, string[]>();
  for (const field of top.fields) {
    const list = fieldsByName.get(field.name) ?? [];
    list.push(field.value);
    fieldsByName.set(field.name, list);
  }

  const read = (names: string[]): string[] | null => {
    const out: string[] = [];
    for (const name of names) {
      for (const value of fieldsByName.get(name) ?? []) {
        const parsed = parseRecipientHeader(value);
        if (!parsed) return null;
        out.push(...parsed);
      }
    }
    return out;
  };

  const to = read(['to', 'resent-to']);
  const cc = read(['cc', 'resent-cc']);
  const bcc = read(['bcc', 'resent-bcc']);
  const from = read(['from']);
  if (!to || !cc || !bcc || !from) return null;
  const recipients = [...new Set([...to, ...cc, ...bcc])];
  if (recipients.length > RFC822_LIMITS.maxAddresses) return null;

  const subject = (fieldsByName.get('subject') ?? []).map(decodeEncodedWords).join(' ');
  pushText(state, subject);
  if (!collectText(top.fields, top.body, 0, state)) return null;

  return {
    recipients,
    to: [...new Set(to)],
    cc: [...new Set(cc)],
    bcc: [...new Set(bcc)],
    from: [...new Set(from)],
    subject,
    text: state.text.join('\n'),
    text_truncated: state.truncated,
    opaque_parts: state.opaque,
  };
}

/**
 * Split a header block from its body and unfold it. Accepts CRLF or LF line
 * ends; a bare CR or NUL anywhere in the header block is refused.
 */
function splitHeaderBlock(bytes: Buffer): { fields: HeaderField[]; body: Buffer } | null {
  // A part may have no headers at all: it then opens with the blank line.
  if (bytes[0] === 0x0a) return { fields: [], body: bytes.subarray(1) };
  if (bytes[0] === 0x0d && bytes[1] === 0x0a) return { fields: [], body: bytes.subarray(2) };
  const limit = Math.min(bytes.length, RFC822_LIMITS.maxHeaderBytes + 4);
  let headerEnd = -1;
  let bodyStart = bytes.length;
  for (let i = 0; i < limit; i++) {
    if (bytes[i] !== 0x0a) continue;
    if (bytes[i + 1] === 0x0a) { headerEnd = i + 1; bodyStart = i + 2; break; }
    if (bytes[i + 1] === 0x0d && bytes[i + 2] === 0x0a) { headerEnd = i + 1; bodyStart = i + 3; break; }
  }
  if (headerEnd === -1) {
    // A message may legally have no body, but then the whole thing is header.
    if (bytes.length > RFC822_LIMITS.maxHeaderBytes) return null;
    headerEnd = bytes.length;
  }
  // `headerEnd` includes the last header line's own LF, so every line is
  // terminated and a CR before it is a line end, not a bare CR.
  const head = bytes.subarray(0, headerEnd).toString('latin1');
  const lines: string[] = [];
  let start = 0;
  for (let i = 0; i <= head.length; i++) {
    const c = head.charCodeAt(i);
    if (i < head.length && c === 0) return null;
    if (i < head.length && c === 0x0d && head.charCodeAt(i + 1) !== 0x0a) return null;
    if (i === head.length || c === 0x0a) {
      const end = i > start && head.charCodeAt(i - 1) === 0x0d ? i - 1 : i;
      lines.push(head.slice(start, end));
      start = i + 1;
    }
  }
  const fields: HeaderField[] = [];
  for (const line of lines) {
    if (line.length === 0) continue;
    const first = line.charCodeAt(0);
    if (first === 0x20 || first === 0x09) {
      // Continuation of the previous field (folding). A leading continuation
      // has nothing to continue.
      const previous = fields[fields.length - 1];
      if (!previous) return null;
      previous.value += line;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) return null;
    const name = line.slice(0, colon).trimEnd().toLowerCase();
    if (!/^[\x21-\x39\x3b-\x7e]+$/.test(name)) return null;
    fields.push({ name, value: line.slice(colon + 1) });
    if (fields.length > RFC822_LIMITS.maxHeaderFields) return null;
  }
  return { fields, body: bytes.subarray(Math.min(bodyStart, bytes.length)) };
}

// ── Addresses ──────────────────────────────────────────────────────────────

const ADDR_SPEC = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/;

/** Parse one To/Cc/Bcc/From value into lowercased addresses, or null. */
export function parseRecipientHeader(value: string): string[] | null {
  for (const word of encodedWords(value)) {
    if (word.decoded === null || word.decoded.includes('@')) return null;
  }
  return parseAddressList(value);
}

/**
 * RFC 5322 address-list with groups, quoted strings and nested comments, in a
 * single character loop. Each mailbox must yield exactly one addr-spec.
 */
export function parseAddressList(value: string): string[] | null {
  const out: string[] = [];
  let i = 0;
  let inGroup = false;
  let item = '';          // display text outside quotes and comments
  let angle: string | null = null;
  let angleCount = 0;
  let sawQuoted = false;

  const finish = (): boolean => {
    const bare = item.trim();
    if (angleCount > 1) return false;
    if (angleCount === 1) {
      // Display name may be words and quoted strings, never an address.
      if (bare.includes('@') || bare.includes('<') || bare.includes('>')) return false;
      const addr = (angle ?? '').trim();
      if (!ADDR_SPEC.test(addr) || addr.length > 254) return false;
      out.push(addr.toLowerCase());
    } else if (bare.length > 0 || sawQuoted) {
      if (sawQuoted || !ADDR_SPEC.test(bare) || bare.length > 254) return false;
      out.push(bare.toLowerCase());
    }
    item = ''; angle = null; angleCount = 0; sawQuoted = false;
    return out.length <= RFC822_LIMITS.maxAddresses;
  };

  while (i < value.length) {
    const c = value[i]!;
    if (c === '"') {
      if (angle !== null) return null;
      i++;
      let closed = false;
      while (i < value.length) {
        const q = value[i]!;
        if (q === '\\') { i += 2; continue; }
        if (q === '"') { closed = true; i++; break; }
        i++;
      }
      if (!closed) return null;
      sawQuoted = true;
      item += ' ';
      continue;
    }
    if (c === '(') {
      let depth = 0;
      while (i < value.length) {
        const q = value[i]!;
        if (q === '\\') { i += 2; continue; }
        if (q === '(') { depth++; if (depth > RFC822_LIMITS.maxCommentDepth) return null; }
        else if (q === ')') { depth--; if (depth === 0) { i++; break; } }
        i++;
      }
      if (depth !== 0) return null;
      if (angle === null) item += ' ';
      continue;
    }
    if (c === '<') {
      if (angle !== null) return null;
      const close = value.indexOf('>', i + 1);
      if (close === -1) return null;
      angle = value.slice(i + 1, close);
      // Obsolete source routes (<@a,@b:x@y>) are refused, as are nested angles.
      if (angle.includes('<') || angle.includes(':') || angle.includes(',') || angle.includes('(') || angle.includes('"')) return null;
      angleCount++;
      i = close + 1;
      continue;
    }
    if (c === '>') return null;
    if (c === ':') {
      // Group start: "display-name:". The text so far is the group name.
      if (inGroup || angle !== null) return null;
      if (item.includes('@')) return null;
      inGroup = true;
      item = ''; sawQuoted = false;
      i++;
      continue;
    }
    if (c === ';') {
      if (!inGroup) return null;
      if (!finish()) return null;
      inGroup = false;
      i++;
      continue;
    }
    if (c === ',') {
      if (!finish()) return null;
      i++;
      continue;
    }
    if (c === '\\' || c === '[' || c === ']') return null;
    const code = c.charCodeAt(0);
    if (code < 0x20 && c !== '\t') return null;
    if (code > 0x7e) return null;
    if (angle !== null && c.trim() !== '') return null; // text after <addr> in the same mailbox
    item += c;
    i++;
  }
  if (inGroup) return null;
  if (!finish()) return null;
  return out;
}

// ── RFC 2047 encoded words ─────────────────────────────────────────────────

interface EncodedWord { start: number; end: number; decoded: string | null }

/** Find every =?charset?enc?text?= token. `decoded` is null when undecodable. */
function encodedWords(value: string): EncodedWord[] {
  const out: EncodedWord[] = [];
  let from = 0;
  while (from < value.length) {
    const start = value.indexOf('=?', from);
    if (start === -1) break;
    const q1 = value.indexOf('?', start + 2);
    const q2 = q1 === -1 ? -1 : value.indexOf('?', q1 + 1);
    const end = q2 === -1 ? -1 : value.indexOf('?=', q2 + 1);
    if (q1 === -1 || q2 === -1 || end === -1 || end - start > 1_000) {
      // An opener with no well-formed close: treat as undecodable so a
      // recipient header carrying it is refused.
      out.push({ start, end: value.length, decoded: null });
      break;
    }
    const charset = value.slice(start + 2, q1);
    const enc = value.slice(q1 + 1, q2).toUpperCase();
    const text = value.slice(q2 + 1, end);
    out.push({ start, end: end + 2, decoded: decodeWord(charset, enc, text) });
    from = end + 2;
  }
  return out;
}

function decodeWord(charsetRaw: string, enc: string, text: string): string | null {
  const charset = charsetRaw.split('*')[0]!.toLowerCase();
  let bytes: Buffer;
  if (enc === 'B') {
    const decoded = strictBase64Decode(text, 'base64');
    if (!decoded) return null;
    bytes = decoded;
  } else if (enc === 'Q') {
    const out: number[] = [];
    for (let i = 0; i < text.length; i++) {
      const c = text[i]!;
      if (c === '_') out.push(0x20);
      else if (c === '=') {
        const hex = text.slice(i + 1, i + 3);
        if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null;
        out.push(parseInt(hex, 16));
        i += 2;
      } else out.push(c.charCodeAt(0));
    }
    bytes = Buffer.from(out);
  } else return null;
  return decodeCharset(bytes, charset);
}

function decodeCharset(bytes: Buffer, charset: string): string | null {
  try {
    return new TextDecoder(charset || 'us-ascii', { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

/** Decode encoded words for display text (Subject). Undecodable words stay as written. */
export function decodeEncodedWords(value: string): string {
  const words = encodedWords(value);
  if (words.length === 0) return value.trim();
  let out = '';
  let cursor = 0;
  for (const word of words) {
    const between = value.slice(cursor, word.start);
    // Whitespace between two adjacent encoded words is dropped (RFC 2047 §6.2).
    out += cursor > 0 && between.trim() === '' ? '' : between;
    out += word.decoded ?? value.slice(word.start, word.end);
    cursor = word.end;
  }
  return (out + value.slice(cursor)).trim();
}

// ── MIME body text ─────────────────────────────────────────────────────────

interface TextState { parts: number; opaque: number; text: string[]; textChars: number; truncated: boolean }

function pushText(state: TextState, text: string) {
  if (!text) return;
  const room = RFC822_LIMITS.maxTextChars - state.textChars;
  if (room <= 0) { state.truncated = true; return; }
  const slice = text.length > room ? text.slice(0, room) : text;
  if (slice.length < text.length) state.truncated = true;
  state.text.push(slice);
  state.textChars += slice.length;
}

interface ContentType { type: string; params: Map<string, string> }

function parseContentType(value: string | undefined): ContentType | null {
  if (value === undefined) return { type: 'text/plain', params: new Map() };
  const [head, ...rest] = splitParams(value);
  const type = (head ?? '').trim().toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(type)) return null;
  const params = new Map<string, string>();
  for (const raw of rest) {
    const eq = raw.indexOf('=');
    if (eq <= 0) continue;
    const key = raw.slice(0, eq).trim().toLowerCase();
    let val = raw.slice(eq + 1).trim();
    if (val.startsWith('"')) {
      if (!val.endsWith('"') || val.length < 2) return null;
      val = val.slice(1, -1).replace(/\\(.)/g, '$1');
    }
    if (params.has(key)) return null; // ambiguous duplicate (e.g. two boundaries)
    params.set(key, val);
  }
  return { type, params };
}

/** Split on ';' outside quoted strings. */
function splitParams(value: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!;
    if (c === '\\' && quoted) { cur += c + (value[i + 1] ?? ''); i++; continue; }
    if (c === '"') quoted = !quoted;
    if (c === ';' && !quoted) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
}

const TEXTUAL = /^(text\/[a-z0-9.+-]+|application\/(json|xml|csv|x-csv|ld\+json))$/;

function single(fields: HeaderField[], name: string): string | undefined | null {
  const matches = fields.filter((f) => f.name === name);
  if (matches.length > 1) return null; // two Content-Types is a differential waiting to happen
  return matches[0]?.value;
}

function collectText(fields: HeaderField[], body: Buffer, depth: number, state: TextState): boolean {
  if (depth > RFC822_LIMITS.maxMimeDepth) return false;
  if (++state.parts > RFC822_LIMITS.maxMimeParts) return false;
  const ctRaw = single(fields, 'content-type');
  const cteRaw = single(fields, 'content-transfer-encoding');
  if (ctRaw === null || cteRaw === null) return false;
  const ct = parseContentType(ctRaw);
  if (!ct) return false;
  const cte = (cteRaw ?? '7bit').trim().toLowerCase();

  if (ct.type.startsWith('multipart/')) {
    if (cte !== '7bit' && cte !== '8bit' && cte !== 'binary') return false;
    const boundary = ct.params.get('boundary');
    if (!boundary || boundary.length > 200) return false;
    const split = splitMultipart(body, boundary);
    if (!split) return false;
    // Mail clients hide the preamble and epilogue, but they travel with the
    // message, so they are content all the same.
    pushText(state, split.outside.trim());
    for (const part of split.parts) {
      const parsed = splitHeaderBlock(part);
      if (!parsed) return false;
      if (!collectText(parsed.fields, parsed.body, depth + 1, state)) return false;
    }
    return true;
  }

  const decoded = decodeTransfer(body, cte);
  if (!decoded) return false;

  if (ct.type === 'message/rfc822' || ct.type === 'message/global') {
    // A forwarded message: its text is content, its headers are not recipients.
    const inner = splitHeaderBlock(decoded);
    if (!inner) return false;
    const subject = inner.fields.filter((f) => f.name === 'subject').map((f) => decodeEncodedWords(f.value)).join(' ');
    pushText(state, subject);
    return collectText(inner.fields, inner.body, depth + 1, state);
  }

  if (!TEXTUAL.test(ct.type)) {
    if (decoded.length > 0) state.opaque++;
    return true;
  }
  const text = decodeCharset(decoded, (ct.params.get('charset') ?? 'utf-8').toLowerCase());
  if (text === null) return false;
  pushText(state, text);
  return true;
}

function decodeTransfer(body: Buffer, cte: string): Buffer | null {
  if (cte === '7bit' || cte === '8bit' || cte === 'binary') return body;
  if (cte === 'base64') {
    const compact = body.toString('latin1').replace(/[\r\n\t ]/g, '');
    return strictBase64Decode(compact, 'base64');
  }
  if (cte === 'quoted-printable') {
    const src = body.toString('latin1');
    const out: number[] = [];
    for (let i = 0; i < src.length; i++) {
      const c = src.charCodeAt(i);
      if (c !== 0x3d) { out.push(c); continue; }
      if (src[i + 1] === '\r' && src[i + 2] === '\n') { i += 2; continue; }
      if (src[i + 1] === '\n') { i += 1; continue; }
      const hex = src.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null;
      out.push(parseInt(hex, 16));
      i += 2;
    }
    return Buffer.from(out);
  }
  return null;
}

/** Split a multipart body on its boundary. Requires the closing delimiter. */
function splitMultipart(body: Buffer, boundary: string): { parts: Buffer[]; outside: string } | null {
  const text = body.toString('latin1');
  const delimiter = `--${boundary}`;
  const parts: Buffer[] = [];
  let pos = 0;
  let open = -1;
  let firstDelimiter = -1;
  while (pos <= text.length) {
    const lineEnd = text.indexOf('\n', pos);
    const end = lineEnd === -1 ? text.length : lineEnd;
    const line = text.slice(pos, end).replace(/\r$/, '');
    if (line.startsWith(delimiter)) {
      const tail = line.slice(delimiter.length).trimEnd();
      if (tail === '' || tail === '--') {
        if (firstDelimiter === -1) firstDelimiter = pos;
        if (open !== -1) {
          // The CRLF before a delimiter belongs to the delimiter.
          let partEnd = pos;
          if (text[partEnd - 1] === '\n') partEnd--;
          if (text[partEnd - 1] === '\r') partEnd--;
          parts.push(Buffer.from(text.slice(open, Math.max(open, partEnd)), 'latin1'));
          if (parts.length > RFC822_LIMITS.maxMimeParts) return null;
        }
        if (tail === '--') {
          const epilogue = lineEnd === -1 ? '' : text.slice(lineEnd + 1);
          return { parts, outside: `${text.slice(0, firstDelimiter)}\n${epilogue}` };
        }
        open = lineEnd === -1 ? text.length : lineEnd + 1;
      }
    }
    if (lineEnd === -1) break;
    pos = lineEnd + 1;
  }
  return null; // no closing delimiter
}
