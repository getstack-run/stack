import { AsyncLocalStorage } from 'node:async_hooks';
import { OPENROUTER_CALL_TIMEOUT_MS } from '@stack/shared';

/**
 * How long a tool call may run before STACK stops waiting for it, per tool: the longest the tool may legitimately take,
 * plus a margin. A call past its deadline is answered as an error on that call alone; the session stays open and its other
 * calls carry on. The numbers come from the longest each tool's own work can run:
 *
 *   workspace command   a command that waits for its end: the longest start STACK holds money for (4 hours) + restoring an archived
 *                       machine (300 s) + starting it (120 s); a background command answers at once and has none of its own
 *   workspace file      restoring + starting a machine that was paused or archived
 *   paid tool           the provider's own wait (150 s)
 *   model call          the gateway's whole OpenRouter call (OPENROUTER_CALL_TIMEOUT_MS, 30 minutes), a stream or a video included
 *   browser step        opening the provider's browser (15 s) and attaching (30 s), or a page load (30 s) and what follows
 *   sealed skill        the sealed run (300 s) + its machine's set-up and tear-down (120 s)
 *   inline memory write the engine's write limit (270 s) + the wait for a turn (30 s)
 *   website publish     the scan, then uploading up to 50 MB of files (120 s per upload)
 *   making quote, order each supplier's own deadline (55 s and 60 s)
 *   proxied request     the upstream wait (30 s) and the checks around it
 *   placing a call      the ring (30 s) and the wait for the first sentence (60 s at most)
 *   answering a call    the relay joining (15 s) and the wait for the first sentence (60 s at most)
 *   saying on a call    the wait for the other side's next sentence (60 s at most)
 *
 * Every other tool answers from STACK's own data and gets `TOOL_DEFAULT_DEADLINE_SECONDS`.
 */
export const TOOL_DEADLINE_MARGIN_SECONDS = 30;
export const TOOL_DEFAULT_DEADLINE_SECONDS = 60;

const WORKSPACE_RESTORE_SECONDS = 300;
const WORKSPACE_START_SECONDS = 120;
/** A command that waits holds its call open: the call ends when the start it runs in does (4 hours). The hosted deadline test pins this to the start's own limit. */
const WORKSPACE_COMMAND_LIMIT_SECONDS = 4 * 60 * 60;

const withMargin = (seconds: number): number => seconds + TOOL_DEADLINE_MARGIN_SECONDS;

const BROWSER = withMargin(90);
const WORKSPACE_FILE = withMargin(WORKSPACE_RESTORE_SECONDS + WORKSPACE_START_SECONDS);

export const TOOL_DEADLINE_SECONDS: Readonly<Record<string, number>> = {
  stack_workspace_run: withMargin(WORKSPACE_COMMAND_LIMIT_SECONDS + WORKSPACE_RESTORE_SECONDS + WORKSPACE_START_SECONDS),
  stack_workspace_read_file: WORKSPACE_FILE,
  stack_workspace_write_file: WORKSPACE_FILE,
  stack_workspace_save_file: WORKSPACE_FILE,
  stack_stop_workspace: withMargin(60),
  stack_run_account_tool: withMargin(150),
  stack_call_openrouter: withMargin(OPENROUTER_CALL_TIMEOUT_MS / 1000),
  stack_start_browser_session: BROWSER,
  stack_browser_navigate: BROWSER,
  stack_browser_act: BROWSER,
  stack_browser_read: BROWSER,
  stack_browser_screenshot: BROWSER,
  stack_browser_checkout: BROWSER,
  stack_end_browser_session: BROWSER,
  stack_invoke_skill: withMargin(300 + 120),
  stack_website_publish: withMargin(300),
  stack_quote_making: withMargin(55),
  stack_order_making: withMargin(60),
  stack_place_making_order: withMargin(60),
  stack_proxy_request: withMargin(60),
  stack_service_tools: withMargin(60),
  stack_service_call_tool: withMargin(60),
  stack_place_account_call: withMargin(30 + 60),
  stack_answer_account_call: withMargin(15 + 60),
  stack_call_say: withMargin(60),
  stack_meeting_join: withMargin(60),
  stack_meeting_say: withMargin(60),
};

/** The deadline of a tool call in milliseconds. */
export function toolDeadlineMs(tool: string): number {
  return (TOOL_DEADLINE_SECONDS[tool] ?? TOOL_DEFAULT_DEADLINE_SECONDS) * 1000;
}

/**
 * A call still running is told to its client this often, as an MCP progress notification, when the client sent a
 * progress token with it: a client that resets its own request timeout on progress keeps waiting for a long tool.
 */
export const TOOL_PROGRESS_INTERVAL_MS = 20_000;

/** The longest any tool may run, for the transport's backstop. */
export const LONGEST_TOOL_DEADLINE_SECONDS = Math.max(TOOL_DEFAULT_DEADLINE_SECONDS, ...Object.values(TOOL_DEADLINE_SECONDS));

/**
 * The most a tool result may carry before it is handed off instead of returned in the call: what the transport's
 * response ceiling (4 MiB, `DEFAULT_MAX_RESPONSE_BYTES`) leaves once the result is wrapped in its message and escaped.
 */
export const TOOL_RESULT_MAX_BYTES = 3_000_000;

/**
 * The most a tool result may carry where there is no hand-off (an install's engine, which has no drive): the response
 * ceiling of 4 MiB less room for the message the result travels in.
 */
export const TOOL_RESULT_WITHOUT_HANDOFF_MAX_BYTES = 4 * 1024 * 1024 - 1024;

/** What the tool call a piece of code runs in allows: the signal that fires at its deadline, and how long that is. */
export interface ToolCallScope {
  signal: AbortSignal;
  deadlineMs: number;
}

const callScope = new AsyncLocalStorage<ToolCallScope>();

/** Runs `fn` with the call's deadline in scope, so the API requests it makes stop when the deadline passes. */
export function runWithCallScope<T>(scope: ToolCallScope, fn: () => T): T {
  return callScope.run(scope, fn);
}

/** The deadline scope of the tool call the caller is running in, when there is one. */
export function currentCallScope(): ToolCallScope | undefined {
  return callScope.getStore();
}
