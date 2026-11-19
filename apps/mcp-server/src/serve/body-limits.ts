import type { IncomingMessage, ServerResponse } from 'node:http';

export class PayloadTooLargeError extends Error {}
export class RequestBodySyntaxError extends Error {}
export class RequestDeadlineError extends Error {}
/** A large body arrived while the process was already reading as much as it holds in memory. */
export class LargeBodyCapacityError extends Error {}

export function declaredBodyIsTooLarge(req: IncomingMessage, maxBytes: number): boolean {
  const raw = req.headers['content-length'];
  if (raw === undefined) return false;
  if (Array.isArray(raw) || !/^\d+$/u.test(raw)) return true;
  const length = Number(raw);
  return !Number.isSafeInteger(length) || length > maxBytes;
}

export async function readBoundedJsonBody(
  req: IncomingMessage,
  maxBytes: number,
  signal: AbortSignal,
  /**
   * A body that passes `after` bytes is a large one, and the process holds only so much of them at once: every byte past
   * `after` is offered to `take`, which answers false when there is no room for it.
   */
  large?: { after: number; take: (bytes: number) => boolean },
): Promise<unknown> {
  const body = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const cleanup = () => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('aborted', onAborted);
      signal.removeEventListener('abort', onDeadline);
    };
    const fail = (error: Error) => {
      cleanup();
      req.resume();
      reject(error);
    };
    const onData = (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.byteLength;
      if (size > maxBytes) {
        fail(new PayloadTooLargeError());
        return;
      }
      if (large && size > large.after) {
        // The piece that crosses the small size takes every byte sent so far; each piece after it takes its own.
        const crossing = size - buffer.byteLength <= large.after;
        if (!large.take(crossing ? size : buffer.byteLength)) {
          fail(new LargeBodyCapacityError());
          return;
        }
      }
      chunks.push(buffer);
    };
    const onEnd = () => {
      cleanup();
      resolve(Buffer.concat(chunks, size));
    };
    const onError = () => fail(new Error('Request stream failed'));
    const onAborted = () => fail(new Error('Request stream aborted'));
    const onDeadline = () => fail(new RequestDeadlineError());

    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
    req.once('aborted', onAborted);
    signal.addEventListener('abort', onDeadline, { once: true });
    if (signal.aborted) onDeadline();
  });

  if (body.byteLength === 0) return undefined;
  try {
    return JSON.parse(body.toString('utf8')) as unknown;
  } catch {
    throw new RequestBodySyntaxError();
  }
}

// Node's `write`, `end` and `writeHead` are overloaded on the shape of their
// arguments. The patched versions below inspect each argument at runtime, so
// they accept `unknown` and narrow it where it is used.
type PatchedWrite = (chunk: unknown, encodingOrCallback?: unknown, callback?: unknown) => boolean;
type PatchedEnd = (chunkOrCallback?: unknown, encodingOrCallback?: unknown, callback?: unknown) => ServerResponse;
type PatchedWriteHead = (statusCode: number, statusMessageOrHeaders?: unknown, headers?: unknown) => ServerResponse;

function toBuffer(chunk: unknown, encoding: BufferEncoding | undefined): Buffer {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (typeof chunk === 'string') return Buffer.from(chunk, encoding);
  // Node only accepts a string or a Uint8Array here; anything else throws, as it did before.
  return Buffer.from(chunk as Uint8Array);
}

/** Every request in a message: the ids that were sent, to answer each. A notification (no id) and a response are left out. */
export function requestIdsOf(body: unknown): Array<string | number> {
  const messages = Array.isArray(body) ? body : [body];
  const ids: Array<string | number> = [];
  for (const message of messages) {
    if (!message || typeof message !== 'object') continue;
    const m = message as { id?: unknown; method?: unknown };
    if (typeof m.method !== 'string') continue;
    if (typeof m.id === 'string' || typeof m.id === 'number') ids.push(m.id);
  }
  return ids;
}

const RESPONSE_TOO_LARGE = 'MCP response exceeds size limit';
const RESPONSE_TOO_LARGE_IN_BODY = 'The answer to this call is larger than this connection can return. The session is still open.';

/**
 * Answers a response that passed the byte ceiling. Before the headers went out it is a 413. After them (a keepalive already
 * committed a 200) the status can no longer change, so the answer is a JSON-RPC error for each request in the body already
 * started (or an event in the stream already open), and the session is left alone.
 */
function answerTooLarge(res: ServerResponse, requestIds: ReadonlyArray<string | number>, end: (body: string) => void): void {
  if (!res.headersSent) {
    res.statusCode = 413;
    res.removeHeader('Content-Length');
    res.setHeader('Content-Type', 'application/json');
    end(JSON.stringify({ error: RESPONSE_TOO_LARGE }));
    return;
  }
  const errors = (requestIds.length > 0 ? requestIds : [null]).map((id) => ({
    jsonrpc: '2.0',
    id,
    error: { code: -32000, message: RESPONSE_TOO_LARGE_IN_BODY },
  }));
  const body = JSON.stringify(errors.length === 1 ? errors[0] : errors);
  end(String(res.getHeader('content-type') ?? '').startsWith('text/event-stream') ? `event: message\ndata: ${body}\n\n` : body);
}

/**
 * Buffer finite POST responses so the byte ceiling can return a clean 413. A response still being made after
 * `keepaliveMs` is committed as a 200 JSON answer and kept open with a space every `keepaliveMs` (leading white space
 * is part of JSON), because a hosting proxy closes a connection that has carried nothing for 60 s and a tool may run
 * for minutes; the message that follows is the answer, error or result, as it would have been.
 */
export function installResponseByteLimit(
  res: ServerResponse,
  maxBytes: number,
  onExceeded: () => void,
  keepaliveMs = 0,
  requestIds: ReadonlyArray<string | number> = [],
): void {
  const response = res as Omit<ServerResponse, 'write' | 'end' | 'writeHead' | 'flushHeaders'> & {
    write: PatchedWrite;
    end: PatchedEnd;
    writeHead: PatchedWriteHead;
    flushHeaders: () => void;
  };
  const originalEnd = res.end.bind(res) as PatchedEnd;
  const originalWrite = res.write.bind(res) as PatchedWrite;
  const originalWriteHead = res.writeHead.bind(res);
  const chunks: Buffer[] = [];
  let size = 0;
  let exceeded = false;
  let keepalive: NodeJS.Timeout | undefined;
  const stopKeepalive = () => {
    if (keepalive) clearInterval(keepalive);
    keepalive = undefined;
  };
  if (keepaliveMs > 0) {
    res.once('finish', stopKeepalive);
    res.once('close', stopKeepalive);
    keepalive = setInterval(() => {
      if (res.writableEnded || exceeded) {
        stopKeepalive();
        return;
      }
      if (!res.headersSent) {
        // The answer is not ready: commit it as a JSON answer. Content-Length is dropped, the length is not known yet.
        res.statusCode = 200;
        res.removeHeader('Content-Length');
        res.setHeader('Content-Type', 'application/json');
        originalWriteHead(200);
      }
      originalWrite(' ');
    }, keepaliveMs);
    keepalive.unref();
  }
  const commitHeaders = () => {
    if (!res.headersSent) originalWriteHead(res.statusCode);
  };

  // Keep POST headers mutable until the finite response passes the ceiling.
  // This lets an oversized tool result return a clean 413 instead of a
  // truncated 200 after an eager SSE flush.
  response.flushHeaders = () => {};

  response.writeHead = (statusCode, statusMessageOrHeaders, headers) => {
    // Already committed by a keepalive: the answer follows as the body of that 200.
    if (res.headersSent) return res;
    res.statusCode = statusCode;
    if (typeof statusMessageOrHeaders === 'string') res.statusMessage = statusMessageOrHeaders;
    const values = typeof statusMessageOrHeaders === 'string' ? headers : statusMessageOrHeaders;
    if (values && typeof values === 'object') {
      for (const [name, value] of Object.entries(values)) {
        if (value !== undefined) res.setHeader(name, value as string | number | readonly string[]);
      }
    }
    return res;
  };

  response.write = (chunk, encodingOrCallback, callback) => {
    if (exceeded || res.writableEnded) return false;
    const encoding = typeof encodingOrCallback === 'string' && Buffer.isEncoding(encodingOrCallback)
      ? encodingOrCallback
      : undefined;
    const done = (typeof encodingOrCallback === 'function' ? encodingOrCallback : callback) as (() => void) | undefined;
    const buffer = toBuffer(chunk, encoding);
    size += buffer.byteLength;
    if (size > maxBytes) {
      exceeded = true;
      onExceeded();
      answerTooLarge(res, requestIds, (body) => {
        commitHeaders();
        originalEnd(body);
      });
      if (typeof done === 'function') queueMicrotask(done);
      return false;
    }
    chunks.push(buffer);
    if (typeof done === 'function') queueMicrotask(done);
    return true;
  };

  response.end = (chunkOrCallback, encodingOrCallback, callback) => {
    if (exceeded || res.writableEnded) return res;
    let chunk = chunkOrCallback;
    let encoding: BufferEncoding | undefined;
    let done: (() => void) | undefined;
    if (typeof chunkOrCallback === 'function') {
      chunk = undefined;
      done = chunkOrCallback as () => void;
    } else if (typeof encodingOrCallback === 'function') {
      done = encodingOrCallback as () => void;
    } else {
      encoding = typeof encodingOrCallback === 'string' && Buffer.isEncoding(encodingOrCallback)
        ? encodingOrCallback
        : undefined;
      done = typeof callback === 'function' ? (callback as () => void) : undefined;
    }
    if (chunk !== undefined && chunk !== null) {
      const buffer = toBuffer(chunk, encoding);
      size += buffer.byteLength;
      if (size > maxBytes) {
        exceeded = true;
        onExceeded();
        answerTooLarge(res, requestIds, (body) => {
          commitHeaders();
          originalEnd(body, done);
        });
        return res;
      }
      chunks.push(buffer);
    }
    commitHeaders();
    return originalEnd(Buffer.concat(chunks, size), done);
  };
}

/**
 * Byte ceiling for a streamed (SSE) POST response, plus SSE comment
 * keepalives while the stream is open (the hosting proxy closes idle connections at 60 s).
 * Bytes flow as they are written; past the ceiling the stream is cut and the
 * session torn down, so no oversized result is ever completed. Used for a
 * session whose client can answer an elicitation: the server asks it
 * mid-call, so the response cannot be buffered.
 */
export function installStreamingResponseLimit(
  res: ServerResponse,
  maxBytes: number,
  onExceeded: () => void,
  keepaliveMs: number,
  requestIds: ReadonlyArray<string | number> = [],
): void {
  const response = res as Omit<ServerResponse, 'write' | 'end' | 'writeHead'> & {
    write: PatchedWrite;
    end: PatchedEnd;
    writeHead: PatchedWriteHead;
  };
  const originalWrite = res.write.bind(res) as PatchedWrite;
  const originalEnd = res.end.bind(res) as PatchedEnd;
  const originalWriteHead = res.writeHead.bind(res) as PatchedWriteHead;
  let size = 0;
  let exceeded = false;
  let keepalive: NodeJS.Timeout | undefined;
  const stopKeepalive = () => {
    if (keepalive) clearInterval(keepalive);
    keepalive = undefined;
  };
  res.once('finish', stopKeepalive);
  res.once('close', stopKeepalive);
  const count = (chunk: unknown, encoding?: unknown): boolean => {
    if (chunk === undefined || chunk === null || typeof chunk === 'function') return true;
    size += toBuffer(chunk, typeof encoding === 'string' && Buffer.isEncoding(encoding) ? encoding : undefined).byteLength;
    if (size <= maxBytes) return true;
    exceeded = true;
    stopKeepalive();
    onExceeded();
    // The oversized chunk is never sent: the stream ends with an error event for each call in it, and the session carries on.
    answerTooLarge(res, requestIds, (body) => {
      originalEnd(body);
    });
    return false;
  };

  response.writeHead = (statusCode, statusMessageOrHeaders, headers) => {
    const result = originalWriteHead(statusCode, statusMessageOrHeaders, headers);
    const type = String(res.getHeader('content-type') ?? '');
    if (type.startsWith('text/event-stream') && !keepalive && keepaliveMs > 0) {
      keepalive = setInterval(() => {
        if (res.writableEnded || exceeded) {
          stopKeepalive();
          return;
        }
        // An SSE comment between whole events; clients ignore it.
        originalWrite(': keepalive\n\n');
      }, keepaliveMs);
      keepalive.unref();
    }
    return result;
  };
  response.write = (chunk, encodingOrCallback, callback) => {
    if (exceeded || res.writableEnded) return false;
    if (!count(chunk, encodingOrCallback)) return false;
    return originalWrite(chunk, encodingOrCallback, callback);
  };
  response.end = (chunkOrCallback, encodingOrCallback, callback) => {
    if (exceeded || res.writableEnded) return res;
    stopKeepalive();
    if (!count(chunkOrCallback, encodingOrCallback)) return res;
    return originalEnd(chunkOrCallback, encodingOrCallback, callback);
  };
}

/** True when the body is (or contains) an initialize request advertising elicitation. */
export function advertisesElicitation(body: unknown): boolean {
  const messages = Array.isArray(body) ? body : [body];
  return messages.some((message) => {
    if (!message || typeof message !== 'object') return false;
    const m = message as { method?: unknown; params?: { capabilities?: { elicitation?: unknown } } };
    const elicitation = m.method === 'initialize' ? m.params?.capabilities?.elicitation : undefined;
    return Boolean(elicitation) && typeof elicitation === 'object';
  });
}

/** The tool calls in a request: each one's id and the tool it names. A message with no id is a notification and is left out. */
export function toolCallsOf(body: unknown): Array<{ id: string | number; tool: string }> {
  const messages = Array.isArray(body) ? body : [body];
  const calls: Array<{ id: string | number; tool: string }> = [];
  for (const message of messages) {
    if (!message || typeof message !== 'object') continue;
    const m = message as { id?: unknown; method?: unknown; params?: { name?: unknown } };
    if (m.method !== 'tools/call' || typeof m.params?.name !== 'string') continue;
    if (typeof m.id !== 'string' && typeof m.id !== 'number') continue;
    calls.push({ id: m.id, tool: m.params.name });
  }
  return calls;
}
