// The OpenRouter passthrough of the model gateway: every OpenRouter endpoint under
// `/v1/llm/openrouter/*` goes to `https://openrouter.ai/api/v1/*` with the body and
// the answer as they are. These are the numbers and names the route, the account's
// billing and the clients that call it agree on (the system architecture, the
// model gateway section).

/** Where the gateway's OpenRouter route lives on STACK's API; the rest of the path is OpenRouter's own. */
export const OPENROUTER_GATEWAY_PREFIX = '/v1/llm/openrouter';

/** The one host and base path a call to OpenRouter goes to. No caller names where a key goes. */
export const OPENROUTER_API_BASE = 'https://openrouter.ai/api/v1';

/**
 * The header with which a caller sets the most it accepts one call to cost: a whole number of cents, at least
 * `OPENROUTER_HOLD_MIN_CENTS`, with no upper bound (it only lowers a hold). The hold of a call on STACK's key (its worst case or estimate,
 * `openRouterWorstCase`) is lowered to it when it is below; a cost above the hold is taken from the wallet once the call is
 * charged. It is never a default.
 */
export const OPENROUTER_HOLD_HEADER = 'X-Max-Cost-Cents';
export const OPENROUTER_HOLD_MIN_CENTS = 1;

/**
 * What a video job id looks like: OpenRouter documents ids such as `abc123` and `y34x1YREG4Pkdcj7f02v`, not the `gen-` ids
 * of a generation, so any short run of letters, digits, `-` and `_` is read as one.
 */
export const OPENROUTER_VIDEO_JOB_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** The most of a request the gateway reads and forwards (a base64 image or audio file inside a JSON body is the large case). */
export const OPENROUTER_REQUEST_MAX_BYTES = 64 * 1024 * 1024;

/** How long one call may run in all: a reasoning model's long answer, a generated image, a video's finished file. */
export const OPENROUTER_CALL_TIMEOUT_MS = 30 * 60 * 1000;

/** How long a call may go without a byte from OpenRouter (its keep-alive comments on a stream count). */
export const OPENROUTER_IDLE_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Set to `drive` by a caller that cannot take a binary or very large answer (the MCP tool): the answer is then saved to
 * the agent's drive, private to it, and the call returns the file. Absent, the answer is passed on untouched.
 */
export const OPENROUTER_SAVE_OUTPUT_HEADER = 'X-Stack-Save-Output';

/** With the header above, a text or JSON answer up to this many bytes still comes back inline; anything else is saved. */
export const OPENROUTER_INLINE_OUTPUT_MAX_BYTES = 256 * 1024;
