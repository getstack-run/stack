import type { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { ServerSettings } from './settings.js';
import type { SessionEntry } from './types.js';

/**
 * The in-memory session table and the admission counters around it: how many
 * sessions a bearer and the process may hold, how many requests may be in
 * flight, and the idle sweep. Nothing here is persisted; a restart drops it.
 */
export function createSessionRegistry(
  settings: Pick<
    ServerSettings,
    | 'now' | 'logger' | 'sessionIdleTtlMs' | 'maxSessionsPerBearer' | 'maxSessionsPerProcess'
    | 'maxInFlightRequests' | 'maxInFlightPerBearer' | 'maxInFlightPerSession'
  >,
) {
  const {
    now, logger, sessionIdleTtlMs, maxSessionsPerBearer, maxSessionsPerProcess,
    maxInFlightRequests, maxInFlightPerBearer, maxInFlightPerSession,
  } = settings;
  const transports = new Map<string, SessionEntry>();
  const pendingByBearer = new Map<string, number>();
  let pendingInitializations = 0;
  const inFlightByBearer = new Map<string, number>();
  const inFlightBySession = new Map<string, number>();
  let inFlightRequests = 0;

  async function closeTransports(
    entries: StreamableHTTPServerTransport[],
  ): Promise<void> {
    const results = await Promise.allSettled(entries.map((transport) => transport.close()));
    for (const result of results) {
      if (result.status === 'rejected') {
        logger.error('MCP transport cleanup failed');
      }
    }
  }

  async function closeEntries(entries: SessionEntry[]): Promise<void> {
    await closeTransports(entries.map((entry) => entry.transport));
  }

  async function pruneIdleSessions(): Promise<void> {
    const cutoff = now() - sessionIdleTtlMs;
    const expired: SessionEntry[] = [];
    for (const [sessionId, entry] of transports) {
      if (entry.lastSeenAt <= cutoff) {
        // Delete before close. close() calls transport.onclose, which is then
        // an idempotent second delete rather than a race with request routing.
        transports.delete(sessionId);
        expired.push(entry);
      }
    }
    await closeEntries(expired);
  }

  /**
   * Make room for one more session of a bearer. Never a session with a request
   * in flight, and nothing is evicted unless room is made. `ownNeeded` is how
   * many the bearer's own cap and the process cap together require of its own
   * sessions: its least recently used idle ones go, oldest first. At the
   * per-bearer cap a bearer only ever evicts its own sessions.
   *
   * When only the process is full (`fairNeeded`) and the caller has no idle
   * session of its own left to give, the least recently used idle session of
   * the bearer holding the most sessions goes instead, but only if that bearer
   * holds strictly more than the caller (the caller's active plus pending
   * count). If no bearer holds more, or the largest holder has no idle
   * session, it refuses. This keeps one leaky login from holding every slot
   * of the process while other customers are refused until the idle sweep.
   */
  function evictForNewSession(
    bearerFingerprint: string,
    ownNeeded: number,
    processNeeded: number,
    callerHolds: number,
  ): boolean {
    const idleOf = (holder: string): Array<[string, SessionEntry]> => {
      const idle: Array<[string, SessionEntry]> = [];
      for (const [sessionId, entry] of transports) {
        if (entry.bearerFingerprint !== holder) continue;
        if ((inFlightBySession.get(sessionId) ?? 0) > 0) continue;
        idle.push([sessionId, entry]);
      }
      return idle.sort((left, right) => left[1].lastSeenAt - right[1].lastSeenAt);
    };
    const victims: Array<[string, SessionEntry]> = [];
    const own = idleOf(bearerFingerprint);
    const ownTake = Math.max(ownNeeded, Math.min(processNeeded, own.length));
    if (own.length < ownTake) return false;
    victims.push(...own.slice(0, ownTake));
    const stillNeeded = processNeeded - victims.length;
    if (stillNeeded > 0) {
      if (stillNeeded > 1) return false;
      const held = new Map<string, number>();
      for (const entry of transports.values()) {
        held.set(entry.bearerFingerprint, (held.get(entry.bearerFingerprint) ?? 0) + 1);
      }
      let largest: string | undefined;
      let largestCount = 0;
      for (const [holder, count] of held) {
        if (holder === bearerFingerprint) continue;
        if (count > largestCount) { largest = holder; largestCount = count; }
      }
      if (largest === undefined || largestCount <= callerHolds) return false;
      const victim = idleOf(largest)[0];
      if (!victim) return false;
      victims.push(victim);
    }
    if (victims.length === 0) return true;
    for (const [sessionId] of victims) {
      // Delete before close, as in pruneIdleSessions; a rejected close is
      // logged by closeTransports and never fails the initialization.
      transports.delete(sessionId);
      logger.warn?.('MCP session evicted at capacity');
    }
    void closeEntries(victims.map(([, entry]) => entry));
    return true;
  }

  function reserveInitialization(bearerFingerprint: string): (() => void) | null {
    let activeForBearer = 0;
    for (const entry of transports.values()) {
      if (entry.bearerFingerprint === bearerFingerprint) activeForBearer += 1;
    }
    const pendingForBearer = pendingByBearer.get(bearerFingerprint) ?? 0;
    // Pending initializations hold slots that no eviction can free.
    if (pendingForBearer >= maxSessionsPerBearer) return null;
    if (pendingInitializations >= maxSessionsPerProcess) return null;
    const overBearer = activeForBearer + pendingForBearer - maxSessionsPerBearer + 1;
    const overProcess = transports.size + pendingInitializations - maxSessionsPerProcess + 1;
    if (!evictForNewSession(bearerFingerprint, Math.max(overBearer, 0), Math.max(overProcess, 0), activeForBearer + pendingForBearer)) return null;

    pendingInitializations += 1;
    pendingByBearer.set(bearerFingerprint, pendingForBearer + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      pendingInitializations -= 1;
      const remaining = (pendingByBearer.get(bearerFingerprint) ?? 1) - 1;
      if (remaining === 0) pendingByBearer.delete(bearerFingerprint);
      else pendingByBearer.set(bearerFingerprint, remaining);
    };
  }

  function reserveRequest(
    bearerFingerprint: string,
    sessionId: string | undefined,
  ): (() => void) | null {
    const bearerCount = inFlightByBearer.get(bearerFingerprint) ?? 0;
    const sessionCount = sessionId ? (inFlightBySession.get(sessionId) ?? 0) : 0;
    if (
      inFlightRequests >= maxInFlightRequests
      || bearerCount >= maxInFlightPerBearer
      || (sessionId !== undefined && sessionCount >= maxInFlightPerSession)
    ) return null;
    inFlightRequests += 1;
    inFlightByBearer.set(bearerFingerprint, bearerCount + 1);
    if (sessionId) inFlightBySession.set(sessionId, sessionCount + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      inFlightRequests -= 1;
      const nextBearer = (inFlightByBearer.get(bearerFingerprint) ?? 1) - 1;
      if (nextBearer === 0) inFlightByBearer.delete(bearerFingerprint);
      else inFlightByBearer.set(bearerFingerprint, nextBearer);
      if (sessionId) {
        const nextSession = (inFlightBySession.get(sessionId) ?? 1) - 1;
        if (nextSession === 0) inFlightBySession.delete(sessionId);
        else inFlightBySession.set(sessionId, nextSession);
      }
    };
  }

  return {
    transports,
    closeTransports,
    closeEntries,
    pruneIdleSessions,
    reserveInitialization,
    reserveRequest,
  };
}

export type SessionRegistry = ReturnType<typeof createSessionRegistry>;
