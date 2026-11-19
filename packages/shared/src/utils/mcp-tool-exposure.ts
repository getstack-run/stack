// Which MCP tools a session lists. The list is visibility only: every tool still
// checks its scope, `denyAgentContexts`, the Mission and the customer's controls on
// the server. The rules are pure so the MCP server (which hides a tool), the
// catalogue (which says whether an agent's list holds it) and the specification
// all read the same ones (the MCP tool list design).

/**
 * Who a tool is for.
 *
 * - `agent`: only a session of an agent (a Passport-bearing principal). The tool is
 *   for an agent acting, and means nothing to a person managing STACK.
 * - `owner`: only a session of an owner or a member (an API key or an OAuth sign-in):
 *   administration and settings, where a person decides what an agent may do.
 * - `both`: the tools an agent uses and a person may also need.
 */
export const MCP_AUDIENCES = ['agent', 'owner', 'both'] as const;
export type McpAudience = (typeof MCP_AUDIENCES)[number];

/** Whose session is listing. */
export const MCP_SESSION_AUDIENCES = ['agent', 'owner'] as const;
export type McpSessionAudience = (typeof MCP_SESSION_AUDIENCES)[number];

/** What a tool says about where it is listed. An empty `pieces` is the core: always listed to its audience. */
export interface McpToolListing {
  audience: McpAudience;
  /** The account pieces the tool belongs to, any one of which lists it. Empty: the core. */
  pieces: readonly string[];
}

/** The session a list is made for: whose it is, and which pieces are switched on for it. */
export interface McpToolSession {
  audience: McpSessionAudience;
  /**
   * An agent's session: the pieces its account has switched on. An owner's or a member's: the pieces any of
   * the customer's accounts has switched on. A tool for the person's own setup is listed whichever it is.
   */
  pieces: ReadonlySet<string>;
}

/**
 * Whether a session lists a tool.
 *
 * An `owner` tool is the person's own setup and administration of a piece: it is listed to every owner
 * session, switched on or not, because it is how a piece is switched on. An agent's tool of a piece is
 * listed only while a piece it belongs to is on.
 */
export function isToolListed(tool: McpToolListing, session: McpToolSession): boolean {
  if (tool.audience === 'owner') return session.audience === 'owner';
  if (tool.audience === 'agent' && session.audience !== 'agent') return false;
  if (tool.pieces.length === 0) return true;
  return tool.pieces.some((piece) => session.pieces.has(piece));
}
