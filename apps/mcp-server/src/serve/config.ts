export const DEFAULT_SESSION_IDLE_TTL_MS = 2 * 60 * 60 * 1000;
export const DEFAULT_SESSION_SWEEP_INTERVAL_MS = 5 * 60 * 1000;
export const DEFAULT_AUTH_VALIDATION_TIMEOUT_MS = 5_000;
export const DEFAULT_MAX_SESSIONS_PER_BEARER = 256;
export const DEFAULT_MAX_SESSIONS_PER_PROCESS = 1024;
/**
 * What a request may carry on a session whose bearer is the one the session was opened with: the largest input that
 * should travel through MCP, a drive file of 10 MB inline (13.4 MiB in base64) and the message around it, with room to
 * spare. A larger input does not go through the body: a drive file of up to 1 GiB, and a website as a zip, go to a
 * one-time upload URL that the agent sends with `curl -T`.
 */
export const DEFAULT_MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024;
/**
 * What any other request may carry: one that opens a session or names none, before its bearer has been checked. A message
 * that opens a session is small, and this keeps an unauthenticated caller from making the server buffer more.
 */
export const DEFAULT_MAX_NEW_SESSION_BODY_BYTES = 1024 * 1024;
/** How long a body larger than `DEFAULT_MAX_NEW_SESSION_BODY_BYTES` may take to arrive: 16 MiB in five minutes is under half a Mbit a second. */
export const DEFAULT_BODY_RECEIVE_TIMEOUT_MS = 5 * 60 * 1000;
/**
 * How many bytes of the bodies larger than `DEFAULT_MAX_NEW_SESSION_BODY_BYTES` one process holds at once, counted as the raw
 * bytes in flight: a body that declares its length takes that length before a byte is read, and one that declares none takes
 * every byte it has sent once it passes the small size. A body that would pass it is told to retry in a few seconds.
 */
export const DEFAULT_MAX_LARGE_BODY_BYTES_IN_FLIGHT = 150 * 1024 * 1024;
export const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
/** The time a request has to be read, and to be answered when it is not a tool call. A tool call has its tool's own deadline. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
/** How long after a tool's own deadline the transport waits before it ends the request itself: the tool answers first. */
export const TOOL_REQUEST_BACKSTOP_MS = 15_000;
/** A buffered response is kept alive with a space this often while its tool runs: a proxy closes a connection that is silent for 60 s. */
export const DEFAULT_JSON_KEEPALIVE_MS = 20_000;
export const DEFAULT_MAX_IN_FLIGHT_REQUESTS = 128;
export const DEFAULT_MAX_IN_FLIGHT_PER_BEARER = 64;
// A tool call waiting on an in-chat confirmation stays open while the client
// posts the person's answer on the same session, and a client may also hold
// the GET notification stream: three concurrent requests plus one spare.
export const DEFAULT_MAX_IN_FLIGHT_PER_SESSION = 4;
/** SSE comment interval. A hosting proxy may close a connection idle for 60 s. */
export const DEFAULT_SSE_KEEPALIVE_MS = 20_000;
/** Machine ids are lowercase hex. Anything else never reaches a header. */
export const MACHINE_ID = /^[0-9a-f]{8,32}$/;
export const MACHINE_SESSION_ID = /^([0-9a-f]{8,32})\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
export const CAPACITY_RETRY_AFTER_SECONDS = 5;
export const MCP_PATH = '/mcp';
export const DIRECTORY_PATH = '/directory';
export const PROTECTED_RESOURCE_PREFIX = '/.well-known/oauth-protected-resource';
