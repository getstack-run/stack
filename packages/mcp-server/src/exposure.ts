import type { McpServer, RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import { isToolListed, type McpAudience, type McpToolListing, type McpToolSession } from '@stack/shared';
import type { McpToolModule } from './modules.js';

// Which tools a session lists (the MCP tool list design).
//
// Every module says, for its tools, who they are for (`audience`), which account
// pieces they belong to (`piece`; none is the core, always listed) and which are
// rarely used (`deferred`). The server registers every tool of its modules, as
// ever, and a `ToolSetController` decides which of them the session lists. A tool
// that is not listed is disabled in the SDK: `tools/list` leaves it out and
// `tools/call` refuses it, so what a session never listed it cannot call either.
// Listing is visibility only. Every tool still checks its scope, the Passport, the
// Mission and the customer's controls on the server.

/** What a module says about the listing of its tools. A tool's own entry, if any, overrides the module's. */
export interface ToolExposureRule {
  audience?: McpAudience;
  /** The piece the tool belongs to (any of a list); `null` makes a tool of a piece module part of the core. */
  piece?: string | readonly string[] | null;
  /** Rarely used: the tool carries the load-on-demand hint clients with tool search honour. */
  deferred?: boolean;
}

export interface ModuleExposure extends ToolExposureRule {
  audience: McpAudience;
  /** Exceptions to the module's rule, by tool name. */
  tools?: Readonly<Record<string, ToolExposureRule>>;
}

/** What a tool is, resolved from its module's rules. */
export interface ToolExposure extends McpToolListing {
  group: string;
  /** Carries the load-on-demand hint. */
  deferred: boolean;
}

/**
 * The hint a client with tool search reads. MCP has no field for it: the spec leaves `_meta` to the implementer,
 * and Claude Code reads `anthropic/alwaysLoad` there (`false` keeps the tool behind tool search even when the
 * person's own configuration loads the server's tools upfront). Other clients ignore the key. No tool is marked
 * `true`: a client with tool search defers a server's tools by default (https://code.claude.com/docs/en/mcp).
 */
export const LOAD_ON_DEMAND_META = { 'anthropic/alwaysLoad': false } as const;

function piecesOf(piece: ToolExposureRule['piece']): readonly string[] {
  if (piece === undefined || piece === null) return [];
  return typeof piece === 'string' ? [piece] : [...piece];
}

/** Every tool's exposure across the modules. A module that names a tool it does not annotate is a wiring mistake. */
export function exposureOf(modules: readonly McpToolModule[]): Readonly<Record<string, ToolExposure>> {
  const resolved: Record<string, ToolExposure> = {};
  for (const module of modules) {
    const rule = module.exposure;
    for (const name of Object.keys(rule.tools ?? {})) {
      if (!Object.hasOwn(module.annotations, name)) throw new Error(`MCP module ${module.id} sets the exposure of ${name}, which it does not annotate`);
    }
    for (const name of Object.keys(module.annotations)) {
      if (Object.hasOwn(resolved, name)) throw new Error(`MCP tool ${name} has its exposure set twice`);
      const own = rule.tools?.[name];
      const piece = own && own.piece !== undefined ? own.piece : rule.piece;
      resolved[name] = {
        group: module.id,
        audience: own?.audience ?? rule.audience,
        pieces: piecesOf(piece),
        deferred: own?.deferred ?? rule.deferred ?? false,
      };
    }
  }
  return resolved;
}

/**
 * Decides which of a session's tools are listed, and tells the client when that changes.
 *
 * Built by the transport with what it knows of the session (whose it is, which pieces
 * are on) and handed to `createStackMcpServer`, which registers every tool with it. The
 * transport calls `update` when the pieces change; the controller disables or enables
 * the tools and sends `notifications/tools/list_changed` once, so a client that acts on
 * it refreshes its list and one that does not sees the change on its next connection.
 */
export class ToolSetController {
  private readonly tools = new Map<string, { registered: Pick<RegisteredTool, 'enabled'>; exposure: ToolExposure }>();
  private mcp: McpServer | null = null;
  private pieces: ReadonlySet<string>;

  constructor(private readonly audience: McpToolSession['audience'], pieces: Iterable<string>) {
    this.pieces = new Set(pieces);
  }

  /** Whether a tool is listed for the session as it stands. */
  listed(exposure: McpToolListing): boolean {
    return isToolListed(exposure, { audience: this.audience, pieces: this.pieces });
  }

  /** Called by the server as it registers a tool. */
  attach(name: string, registered: Pick<RegisteredTool, 'enabled'>, exposure: ToolExposure): void {
    this.tools.set(name, { registered, exposure });
    registered.enabled = this.listed(exposure);
  }

  bind(mcp: McpServer): void {
    this.mcp = mcp;
  }

  get currentPieces(): ReadonlySet<string> {
    return this.pieces;
  }

  /** The tools the session lists now, in registration order. */
  listedNames(): string[] {
    return [...this.tools].filter(([, tool]) => tool.registered.enabled).map(([name]) => name);
  }

  /**
   * The pieces are now these. Returns true, and sends one list-changed notice, when a tool was
   * listed or unlisted by it.
   */
  update(pieces: Iterable<string>): boolean {
    this.pieces = new Set(pieces);
    let changed = false;
    for (const { registered, exposure } of this.tools.values()) {
      const listed = this.listed(exposure);
      if (registered.enabled !== listed) {
        registered.enabled = listed;
        changed = true;
      }
    }
    if (changed) this.mcp?.sendToolListChanged();
    return changed;
  }
}
