import type { ToolCallback } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { z } from 'zod';
import type { ApiFn, ApiRawFn } from '../api-client.js';

/**
 * The registration surface a tool module sees. createStackMcpServer builds it:
 * it attaches the title and annotations, applies the directory profile and
 * refuses a tool that has no annotation entry. The `server.tool(` call form is
 * kept because a repository check counts registrations by that text.
 */
export interface ToolRegistrar {
  tool<Args extends z.ZodRawShape>(
    name: string,
    description: string,
    shape: Args,
    cb: ToolCallback<Args>,
    options?: ToolRegistrationOptions,
  ): void;
}

/** Per-tool registration choices that are not part of the argument shape. */
export interface ToolRegistrationOptions {
  /**
   * Refuse any argument the shape does not declare, with this message, instead
   * of silently dropping it. Used where a caller might pass a secret the tool
   * must never take: the call fails before the handler runs, and the message
   * names no value.
   */
  refuseUnknownArguments?: string;
  /**
   * What the directory profile registers instead, for a tool whose reviewed text or shape must stay as it was
   * reviewed while the standard profile moves on. Absent: the directory registers the tool as the standard does.
   */
  forDirectory?: { description?: string; shape?: z.ZodRawShape };
}

/** What a tool handler may call. Handlers hold no business logic: they proxy to the REST API. */
export interface ToolContext {
  /** Calls the API and returns the parsed body, or throws on a non-2xx response. */
  api: ApiFn;
  /** Calls the API and returns the response whatever its status, for handlers that act on a specific status. */
  apiRaw: ApiRawFn;
}
