import type { ApiFn } from './api-client.js';
import { runInToolCall, type ToolCallExtra } from './elicitation.js';
import {
  TOOL_PROGRESS_INTERVAL_MS,
  TOOL_RESULT_MAX_BYTES,
  TOOL_RESULT_WITHOUT_HANDOFF_MAX_BYTES,
  runWithCallScope,
  toolDeadlineMs,
} from './tool-deadlines.js';

/** A progress notification of a call, as the MCP specification names it. */
export interface ToolProgressNotification {
  method: 'notifications/progress';
  params: { progressToken: string | number; progress: number };
}

/**
 * What the MCP SDK hands a tool handler beside the request id and signal: the request's `_meta` (its progress token,
 * when the client asked for progress) and the way to send a notification on the call's own stream.
 */
export interface ToolProgressExtra {
  _meta?: { progressToken?: string | number; [key: string]: unknown };
  sendNotification?: (notification: ToolProgressNotification) => Promise<void>;
}

/**
 * Tell the client a call is still running every TOOL_PROGRESS_INTERVAL_MS, with `progress` the whole seconds it has
 * run, when it sent a progress token; nothing without one. The returned stop ends it, and a client that went away ends
 * it too.
 */
function startProgress(extra: ToolCallExtra & ToolProgressExtra, startedAt: number): () => void {
  const token = extra._meta?.progressToken;
  const send = extra.sendNotification;
  if ((typeof token !== 'string' && typeof token !== 'number') || !send) return () => undefined;
  const interval = setInterval(() => {
    const progress = Math.floor((Date.now() - startedAt) / 1000);
    // A notification that cannot be sent (the stream closed) is no reason to fail the call.
    send({ method: 'notifications/progress', params: { progressToken: token, progress } }).catch(() => undefined);
  }, TOOL_PROGRESS_INTERVAL_MS);
  interval.unref();
  const stop = () => {
    clearInterval(interval);
    extra.signal?.removeEventListener('abort', stop);
  };
  extra.signal?.addEventListener('abort', stop, { once: true });
  return stop;
}

/** What a tool handler returns. */
export interface ToolResult {
  content: Array<{ type: string; text?: string; data?: string; [key: string]: unknown }>;
  isError?: boolean;
  [key: string]: unknown;
}

/**
 * Saves a result that is too large for the call and answers with the words that replace it, or null when it cannot be
 * saved. A deployment with a place to keep files supplies one (STACK's hosted server saves it to the account's drive); the
 * engine has none, and a result that is too large is then refused in words.
 */
export type ResultHandoff = (input: { tool: string; args: unknown; text: string; api: ApiFn }) => Promise<string | null>;

const mb = (bytes: number): string => `${(bytes / 1_000_000).toFixed(1)} MB`;

const errorResult = (text: string): ToolResult => ({ isError: true, content: [{ type: 'text', text }] });

function secondsOf(ms: number): string {
  const seconds = Math.round(ms / 1000);
  return `${seconds} ${seconds === 1 ? 'second' : 'seconds'}`;
}

/** What the model reads when a call passed its deadline. Only this call ends; the session and its other calls carry on. */
export function deadlineResult(tool: string, deadlineMs: number): ToolResult {
  return errorResult(
    `${tool} did not finish within ${secondsOf(deadlineMs)}, so STACK stopped waiting for it. It may have finished or still be running: read its state before running it again.`,
  );
}

/** The bytes a result takes on the wire, once its message is escaped. Only measured when it could be near the limit. */
export function resultBytes(result: ToolResult): number {
  let chars = 0;
  for (const block of result.content) {
    chars += (block.text?.length ?? 0) + (block.data?.length ?? 0);
    // An embedded resource carries its text or bytes inside the block.
    const resource = block['resource'];
    if (resource && typeof resource === 'object') {
      const { text, blob } = resource as { text?: unknown; blob?: unknown };
      chars += (typeof text === 'string' ? text.length : 0) + (typeof blob === 'string' ? blob.length : 0);
    }
  }
  // A character takes at most six bytes once the message is escaped (a control character is written as \u00xx), so a
  // result of fewer than a sixth of the limit in characters cannot reach it. Anything larger is counted in bytes.
  if (chars * 6 <= TOOL_RESULT_MAX_BYTES) return chars;
  return Buffer.byteLength(JSON.stringify(result), 'utf8');
}

export interface ToolCallRunnerOptions {
  /** How many confirmations asked of the person are open on the session now. A call waiting on the person is not timed. */
  pendingConfirmations: () => number;
  /** When the last confirmation on the session was answered (ms since the epoch), 0 when none was: a call has its whole deadline from then. */
  lastConfirmationEndedAt?: () => number;
  /** The longest a confirmation waits for the person. */
  confirmationTimeoutMs: number;
  api: ApiFn;
  handoff?: ResultHandoff;
}

/**
 * Runs every tool call of a session: it stops waiting for a call at the tool's own deadline (`toolDeadlineMs`) and answers
 * that call with an error, and a result too large for a call is saved through the deployment's hand-off or refused in
 * words. Neither ends the session.
 */
export function createToolCallRunner(options: ToolCallRunnerOptions) {
  async function limit(tool: string, args: unknown, result: ToolResult): Promise<ToolResult> {
    const size = resultBytes(result);
    if (size <= TOOL_RESULT_MAX_BYTES) return result;
    const sizeText = mb(size);
    const limitText = mb(TOOL_RESULT_MAX_BYTES);
    if (result.isError) {
      return errorResult(`${tool} failed with an error message of ${sizeText}, more than this connection can return (${limitText}).`);
    }
    if (!options.handoff) {
      // With no drive to hand a result to, it is returned whole up to what the connection's own ceiling takes.
      if (size <= TOOL_RESULT_WITHOUT_HANDOFF_MAX_BYTES) return result;
      return errorResult(
        `The result of ${tool} is ${sizeText}, more than this connection can return (${mb(TOOL_RESULT_WITHOUT_HANDOFF_MAX_BYTES)}). Ask for less: add a filter or a limit, or read it a page at a time.`,
      );
    }
    let replacement: string | null;
    try {
      replacement = await options.handoff({ tool, args, text: JSON.stringify(result), api: options.api });
    } catch (error) {
      const reason = error instanceof Error && error.message ? ` ${error.message}` : '';
      return errorResult(
        `The result of ${tool} is ${sizeText}, more than this connection can return (${limitText}), and it could not be saved to the drive.${reason}`,
      );
    }
    if (replacement === null) {
      return errorResult(
        `The result of ${tool} is ${sizeText}, more than this connection can return (${limitText}), and it is too large to save to the drive. Ask for less: add a filter or a limit, or read it a page at a time.`,
      );
    }
    return { content: [{ type: 'text', text: replacement }] };
  }

  return async function run(
    tool: string,
    args: unknown,
    extra: ToolCallExtra & ToolProgressExtra,
    handler: (args: unknown, extra: unknown) => unknown,
  ): Promise<ToolResult> {
    const deadlineMs = toolDeadlineMs(tool);
    const controller = new AbortController();
    const startedAt = Date.now();
    const stopProgress = startProgress(extra, startedAt);
    let timer: NodeJS.Timeout | undefined;
    const timedOut = new Promise<ToolResult>((resolve) => {
      const arm = (ms: number) => {
        timer = setTimeout(() => {
          // A call waiting on the person's answer is not slow: it waits up to the confirmation's own time.
          const waiting = options.pendingConfirmations() > 0;
          if (waiting && Date.now() - startedAt < options.confirmationTimeoutMs + deadlineMs) {
            arm(deadlineMs);
            return;
          }
          // Once the person has answered, the approved action has its whole deadline from that moment: the call is never ended
          // while it is still inside it, whatever the time it spent waiting.
          const since = Math.max(startedAt, options.lastConfirmationEndedAt?.() ?? 0);
          const left = deadlineMs - (Date.now() - since);
          if (!waiting && left > 0) {
            arm(left);
            return;
          }
          controller.abort();
          resolve(deadlineResult(tool, deadlineMs));
        }, ms);
        timer.unref();
      };
      arm(deadlineMs);
    });
    try {
      // The hand-off of a large result runs inside the same deadline as the call: one clock covers both.
      const work = Promise.resolve(
        runWithCallScope({ signal: controller.signal, deadlineMs }, async () => {
          const result = (await runInToolCall(extra, () => handler(args, extra))) as ToolResult;
          return limit(tool, args, result);
        }),
      ) as Promise<ToolResult>;
      // A call that ends after its deadline has nobody waiting: its failure is not an unhandled rejection.
      work.catch(() => undefined);
      return await Promise.race([work, timedOut]);
    } finally {
      clearTimeout(timer);
      stopProgress();
    }
  };
}
