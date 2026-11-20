import type { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

/** The two tables of the SDK's transport that matter here: its open streams, and which stream each pending request answers on. */
interface TransportTables {
  _streamMapping?: Map<string, { resolveJson?: unknown }>;
  _requestToStreamMapping?: Map<unknown, string>;
}

/**
 * Releases what the SDK transport keeps for the requests it has answered in JSON mode.
 *
 * In that mode the transport holds a stream entry for each request, whose resolver keeps the whole answer (a tool list is
 * about a megabyte), and it removes the entry only when the session closes. A session of an ordinary client therefore
 * grew with every call it made until the idle sweep. Called once the transport has finished a request, this removes the
 * entries of JSON requests that no request is waiting on any more: an entry some pending request still answers on stays,
 * and so does the standalone notification stream, which has no resolver. A transport without these tables is left alone.
 */
export function releaseAnsweredJsonStreams(transport: StreamableHTTPServerTransport): void {
  const tables = (transport as unknown as { _webStandardTransport?: TransportTables })._webStandardTransport;
  const streams = tables?._streamMapping;
  const pending = tables?._requestToStreamMapping;
  if (!streams || !pending) return;
  const waitedOn = new Set(pending.values());
  for (const [streamId, stream] of streams) {
    if (stream.resolveJson !== undefined && !waitedOn.has(streamId)) streams.delete(streamId);
  }
}
