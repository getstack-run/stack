import { ToolSetController } from '@stack/mcp-server';
import type { ToolSetSource } from '../extension.js';
import type { SessionToolSet } from './types.js';

/** A session that has not been asked about its pieces for this long is asked again before it answers `tools/list`. */
export const TOOL_SET_STALE_MS = 5_000;

/**
 * What decides which tools one session lists (the MCP tool list design): an agent's session lists the
 * agent's tools of the pieces its account has on, an owner's or a member's the administration tools and the
 * agent-level tools of any piece one of its accounts has on. The pieces are read from the API with the
 * session's own bearer, so what the API says about the caller is all there is to it.
 *
 * A read that fails leaves the list as it was (a new session lists the core only): fewer tools is the safe way
 * to be wrong, and the next `tools/list`, the interval and the API's notice read again.
 */
export async function createSessionToolSet(
  source: ToolSetSource,
  session: { apiUrl: string; bearer: string; fetchImpl: typeof fetch; timeoutMs: number; audience: 'agent' | 'owner'; now: () => number },
): Promise<SessionToolSet> {
  const read = () => source.read({ apiUrl: session.apiUrl, bearer: session.bearer, fetchImpl: session.fetchImpl, timeoutMs: session.timeoutMs });
  const first = await read().catch(() => null);
  const controller = new ToolSetController(session.audience, first?.pieces ?? []);
  let inFlight: Promise<void> | null = null;
  const toolSet: SessionToolSet = {
    controller,
    operatorId: first?.operatorId,
    readAt: first ? session.now() : 0,
    refresh: async () => {
      if (inFlight) return inFlight;
      const run = (async () => {
        try {
          const latest = await read();
          if (!latest) return;
          toolSet.operatorId = latest.operatorId;
          toolSet.readAt = session.now();
          controller.update(latest.pieces);
        } catch {
          // The list stays as it was.
        }
      })();
      inFlight = run;
      try {
        await run;
      } finally {
        if (inFlight === run) inFlight = null;
      }
    },
  };
  return toolSet;
}

/** Whether a request body asks for the tool list: a single call or a batch containing one. */
export function asksForToolList(body: unknown): boolean {
  const isList = (message: unknown) =>
    typeof message === 'object' && message !== null && (message as { method?: unknown }).method === 'tools/list';
  return Array.isArray(body) ? body.some(isList) : isList(body);
}
