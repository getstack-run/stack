import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createStackMcpServer, ENGINE_TOOL_MODULES } from '@stack/mcp-server';
import type { McpServeExtension } from '../extension.js';
import { apiKeyMatches, hashApiKey } from './bearer-binding.js';
import {
  LargeBodyCapacityError,
  PayloadTooLargeError,
  RequestBodySyntaxError,
  RequestDeadlineError,
  advertisesElicitation,
  declaredBodyIsTooLarge,
  requestIdsOf,
  toolCallsOf,
  installResponseByteLimit,
  installStreamingResponseLimit,
  readBoundedJsonBody,
} from './body-limits.js';
import { MACHINE_SESSION_ID } from './config.js';
import { resolveAuthContext } from './auth-context.js';
import { handleHealth, handleOpenaiAppsChallenge } from './health.js';
import { isAllowedOrigin, setCorsHeaders } from './origin.js';
import { handleProtectedResourceMetadata } from './resource-metadata.js';
import {
  sendAuthenticationUnavailable,
  sendBodyCapacityUnavailable,
  sendCapacityUnavailable,
  sendInvalidToken,
  sendSubscriptionRequired,
  sendPayloadTooLarge,
  sendRequestDeadlineError,
  sendRequestTimeout,
  sendSessionNotFound,
  sendTooManyRequests,
} from './responses.js';
import type { SessionRegistry } from './sessions.js';
import { asksForToolList, createSessionToolSet, TOOL_SET_STALE_MS } from './tool-sets.js';
import type { ServerSettings } from './settings.js';
import type { SessionState } from './types.js';

/**
 * The request pipeline for every path: CORS and Origin, health, discovery,
 * then the two MCP endpoints (bearer validation, session lookup or creation,
 * admission limits, request deadline).
 */
export function createHttpRequestHandler(
  settings: ServerSettings,
  registry: SessionRegistry,
  extension: McpServeExtension | null = null,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const {
    apiUrl, oauthEnabled, fetchImpl, now, sessionIdleTtlMs, authValidationTimeoutMs,
    maxRequestBodyBytes, maxNewSessionBodyBytes, bodyReceiveTimeoutMs, jsonKeepaliveMs, maxResponseBytes, requestTimeoutMs,
    openaiAppsChallengeToken, endpoints, elicitationAttestationKey, elicitationTimeoutMs, sseKeepaliveMs, machineId,
    toolDeadlineMs, toolBackstopMs, maxLargeBodyBytesInFlight,
  } = settings;
  const {
    transports, closeTransports, closeEntries, pruneIdleSessions, reserveInitialization, reserveRequest,
  } = registry;

  // The memory the bodies over the size of a message that opens a session take now, across requests, counted as they arrive.
  let largeBodyBytesInFlight = 0;

  async function handleHttpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Scanner probes like `GET //.env.save.1` parse as protocol-relative
    // URLs (`//host` -> hostname ".env.save.1" -> TypeError). Return 400.
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'bad request' }));
      return;
    }

    setCorsHeaders(res);

    // A request that has a body still arriving has this long to deliver it, whoever it is from and whatever it is answered
    // with; a body that was admitted as a large one is given longer (below). The server's own limit on receiving a request is off:
    // it is one number for every request, and a long one would hold an unauthenticated socket as long as an admitted upload.
    let bodyGuard: NodeJS.Timeout | undefined;
    const guardBody = (ms: number) => {
      clearTimeout(bodyGuard);
      if (req.complete) return;
      // A little after the handler's own deadline, so the answer to a slow body (a 504) is sent before the connection is closed.
      bodyGuard = setTimeout(() => {
        if (!req.complete) req.destroy();
      }, ms + 2_000);
      bodyGuard.unref();
    };
    guardBody(requestTimeoutMs);
    const bodyArrived = () => clearTimeout(bodyGuard);
    req.once('end', bodyArrived);
    req.once('close', bodyArrived);
    // An answer sent before the body was read (a refusal, a 404) ends the connection once it is sent, so a sender that keeps
    // sending cannot hold it: the half-close lets the answer arrive, and what is left of the connection is cut a second later.
    res.once('finish', () => {
      if (req.complete || req.destroyed) return;
      req.socket.end();
      setTimeout(() => req.destroy(), 1_000).unref();
    });

    if (!isAllowedOrigin(req.headers['origin'])) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Origin not allowed' }));
      req.resume();
      return;
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (handleHealth(url, res)) return;

    if (handleOpenaiAppsChallenge(url, req, res, openaiAppsChallengeToken)) return;

    if (handleProtectedResourceMetadata(url, res, settings)) return;

    const endpoint = Object.hasOwn(endpoints, url.pathname) ? endpoints[url.pathname]! : undefined;
    if (!endpoint) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    if (req.method === 'POST' && declaredBodyIsTooLarge(req, maxRequestBodyBytes)) {
      sendPayloadTooLarge(res, 'request');
      req.resume();
      return;
    }

    const authHeader = req.headers['authorization'];
    const apiKey = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!apiKey) {
      sendInvalidToken(res, oauthEnabled, endpoint);
      return;
    }

    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    // Session affinity: a session lives in the memory of the machine that
    // created it (an in-flight tool call waiting on the person's answer
    // cannot move). Send the request to that machine once; a request that
    // already was replayed is never replayed again.
    const owner = typeof sessionId === 'string' ? MACHINE_SESSION_ID.exec(sessionId)?.[1] : undefined;
    if (owner && machineId && owner !== machineId) {
      req.resume();
      if (req.headers['fly-replay-src'] !== undefined) {
        sendSessionNotFound(res);
        return;
      }
      res.writeHead(409, { 'Content-Type': 'application/json', 'fly-replay': `instance=${owner}` });
      res.end(JSON.stringify({ error: 'Session is held by another instance' }));
      return;
    }
    // A session id from the other endpoint is unknown here, so a /mcp
    // session can never be driven through /directory or the reverse.
    const candidate = sessionId ? transports.get(sessionId) : undefined;
    const entry = candidate && candidate.profile === endpoint.profile ? candidate : undefined;
    const apiKeyHash = hashApiKey(apiKey);
    const bearerFingerprint = apiKeyHash.toString('hex');
    // A session's own bearer may send the largest input a tool advertises; anything else, before its bearer is
    // checked, the small body that opens a session.
    const ownSession = entry !== undefined && apiKeyMatches(apiKey, entry.apiKeyHash);
    const bodyLimit = ownSession ? maxRequestBodyBytes : maxNewSessionBodyBytes;
    if (req.method === 'POST' && declaredBodyIsTooLarge(req, bodyLimit)) {
      sendPayloadTooLarge(res, 'request');
      req.resume();
      return;
    }
    const releaseRequest = reserveRequest(bearerFingerprint, sessionId);
    if (!releaseRequest) {
      sendTooManyRequests(res);
      req.resume();
      return;
    }

    // A large body holds its raw bytes against the process's budget from the moment it is known to be large until the request
    // ends: the bytes it declared before a byte is read, or, when it declared none, every byte it has sent once it passes the
    // small size and each piece after.
    let largeBodyBytes = 0;
    let largeBodyAdmitted = false;
    const takeLargeBody = (bytes: number): boolean => {
      if (largeBodyBytesInFlight + bytes > maxLargeBodyBytesInFlight) return false;
      largeBodyBytesInFlight += bytes;
      largeBodyBytes += bytes;
      if (!largeBodyAdmitted) {
        largeBodyAdmitted = true;
        // Admitted: it has longer to arrive.
        armDeadline(bodyReceiveTimeoutMs);
        guardBody(bodyReceiveTimeoutMs);
      }
      return true;
    };
    const deadline = new AbortController();
    let teardownRequest: () => Promise<void> = async () => {};
    if (sessionId && entry) {
      teardownRequest = async () => {
        if (transports.get(sessionId) === entry) transports.delete(sessionId);
        await closeEntries([entry]);
      };
    }
    let teardownStarted = false;
    const teardownOnce = () => {
      if (teardownStarted) return;
      teardownStarted = true;
      deadline.abort();
      void teardownRequest();
    };
    let startedAt = now();
    let timeout: NodeJS.Timeout | undefined;
    // The window the request is in: reading it (a large body has longer), then, for a tool call, its tool's deadline.
    let windowMs = requestTimeoutMs;
    // The tool calls of the request once it is read: the ids that were sent, to answer each, and nothing else.
    let toolCallIds: Array<string | number> | null = null;
    const onDeadline = () => {
      // A tool call waiting for the person's in-chat answer keeps its
      // stream open, bounded by the confirmation timeout.
      const state = sessionId ? transports.get(sessionId)?.state : undefined;
      const waiting = (state?.pendingElicitations ?? 0) > 0;
      if (waiting && now() - startedAt < elicitationTimeoutMs + windowMs) {
        timeout = setTimeout(onDeadline, windowMs);
        timeout.unref();
        return;
      }
      // A call the person approved is not ended while the approved action runs: its window starts again when the last
      // answer came, as the tool server's own deadline does, so this backstop never answers before the tool server could.
      const left = windowMs - (now() - Math.max(startedAt, state?.lastElicitationEndedAt ?? 0));
      if (!waiting && left > 0) {
        timeout = setTimeout(onDeadline, left);
        timeout.unref();
        return;
      }
      if (req.method === 'GET') {
        // The GET notification stream ends; the session stays. The client
        // reconnects, and an in-flight tool call is not cancelled.
        deadline.abort();
        if (!res.writableEnded) res.end();
        return;
      }
      if (toolCallIds && sessionId && entry) {
        // A tool call past its tool's deadline (the tool answers first, so this is the backstop): only this request
        // ends, with an error for each call in it. The session and its other calls carry on.
        deadline.abort();
        sendRequestDeadlineError(res, toolCallIds);
        return;
      }
      teardownOnce();
      sendRequestTimeout(res);
    };
    const armDeadline = (ms: number) => {
      clearTimeout(timeout);
      windowMs = ms;
      startedAt = now();
      timeout = setTimeout(onDeadline, ms);
      timeout.unref();
    };
    // Every request starts with the ordinary time; a large body is given longer once its sender has been checked (below).
    armDeadline(requestTimeoutMs);
    let released = false;
    const releaseOnFinish = () => {
      if (released) return;
      released = true;
      clearTimeout(timeout);
      largeBodyBytesInFlight -= largeBodyBytes;
      largeBodyBytes = 0;
      releaseRequest();
    };
    res.once('finish', releaseOnFinish);
    res.once('close', releaseOnFinish);

    let parsedBody: unknown;
    if (req.method === 'POST') {
      const declaredLength = Number(req.headers['content-length']);
      const lengthDeclared = Number.isFinite(declaredLength);
      if (lengthDeclared && declaredLength > maxNewSessionBodyBytes) {
        // A body that declares itself large takes the memory it will need before a byte is read.
        if (!takeLargeBody(declaredLength)) {
          sendBodyCapacityUnavailable(res);
          return;
        }
      }
      try {
        // A body that declared no length takes its memory piece by piece once it passes the size of a message that opens a session.
        parsedBody = await readBoundedJsonBody(req, bodyLimit, deadline.signal, {
          after: maxNewSessionBodyBytes,
          take: lengthDeclared ? () => true : takeLargeBody,
        });
      } catch (error) {
        if (error instanceof PayloadTooLargeError) {
          sendPayloadTooLarge(res, 'request');
        } else if (error instanceof LargeBodyCapacityError) {
          sendBodyCapacityUnavailable(res);
        } else if (error instanceof RequestBodySyntaxError) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Request body is not valid JSON' }));
        } else if (!(error instanceof RequestDeadlineError)) {
          throw error;
        }
        return;
      }
      // The body is read: a tool call now has its tool's own deadline, from the longest tool in the request, and
      // the transport backs it up a little later.
      const calls = toolCallsOf(parsedBody);
      if (calls.length > 0) {
        toolCallIds = calls.map((call) => call.id);
        armDeadline(Math.max(...calls.map((call) => toolDeadlineMs(call.tool))) + toolBackstopMs);
      } else {
        armDeadline(requestTimeoutMs);
      }
      // A session that asked for SSE streams its responses so the server can
      // send an elicitation mid-call; the ceiling then ends an oversized
      // stream. Every other POST is buffered so an oversized result is a
      // clean 413 before any byte reaches the client. A result past the ceiling
      // ends that response only: the session stays, and every other call carries on.
      const sse = entry ? entry.sse : advertisesElicitation(parsedBody);
      const resultTooLarge = () => undefined;
      // Past the ceiling after the headers went out (a keepalive sent them), the answer is an error for each request in the body.
      const requestIds = requestIdsOf(parsedBody);
      if (sse) installStreamingResponseLimit(res, maxResponseBytes, resultTooLarge, sseKeepaliveMs, requestIds);
      else installResponseByteLimit(res, maxResponseBytes, resultTooLarge, jsonKeepaliveMs, requestIds);
    }

    if (sessionId && entry) {
      if (entry.lastSeenAt <= now() - sessionIdleTtlMs) {
        transports.delete(sessionId);
        await closeEntries([entry]);
        sendSessionNotFound(res);
        return;
      }

      // A new OAuth access token is a new MCP session identity. Return the
      // MCP session-expired status so clients rebuild the session and the
      // tool server captures the new token. Never rebind or delete the old
      // session here: a leaked session id without its bearer must not be a
      // session-destruction primitive.
      if (!apiKeyMatches(apiKey, entry.apiKeyHash)) {
        sendSessionNotFound(res);
        return;
      }

      const authContext = await resolveAuthContext(
        apiUrl,
        apiKey,
        fetchImpl,
        authValidationTimeoutMs,
      );
      if (deadline.signal.aborted) return;
      if (authContext.status !== 'valid') {
        if (authContext.status === 'invalid') {
          sendInvalidToken(res, oauthEnabled, endpoint);
        } else if (authContext.status === 'subscription_required') {
          sendSubscriptionRequired(res, authContext.body);
        } else {
          sendAuthenticationUnavailable(res, authContext.retryAfterSeconds);
        }
        return;
      }
      if (!endpoint.acceptsResource(authContext.oauthResource)) {
        sendInvalidToken(res, oauthEnabled, endpoint);
        return;
      }

      // Re-check the entry after the network call. A sweep or a concurrent
      // DELETE can close it while credential validation is in flight.
      if (transports.get(sessionId) !== entry || entry.lastSeenAt <= now() - sessionIdleTtlMs) {
        if (transports.get(sessionId) === entry) {
          transports.delete(sessionId);
          await closeEntries([entry]);
        }
        sendSessionNotFound(res);
        return;
      }
      if (
        authContext.principalFingerprint !== entry.principalFingerprint
        || authContext.isPlatformStaff !== entry.isPlatformStaff
      ) {
        // The credential is valid, but its effective security context changed.
        // Rebuild the MCP server so its registered tool set matches that context.
        sendSessionNotFound(res);
        return;
      }

      // A session that lists by who is connected and which pieces are on reads them again before it answers a
      // tool list that is more than a few seconds old, so `tools/list` is always answered with the current set.
      if (entry.toolSet && req.method === 'POST' && asksForToolList(parsedBody) && now() - entry.toolSet.readAt > TOOL_SET_STALE_MS) {
        await entry.toolSet.refresh();
        if (deadline.signal.aborted) return;
      }

      entry.lastSeenAt = now();
      if (req.method === 'GET') {
        // The notification stream: where a wake-up for an agent's session is sent. Counted while it is open.
        entry.state.notificationStreams += 1;
        let ended = false;
        res.once('close', () => {
          if (ended) return;
          ended = true;
          entry.state.notificationStreams = Math.max(0, entry.state.notificationStreams - 1);
        });
      }
      await entry.transport.handleRequest(req, res, parsedBody);
      return;
    }

    if (sessionId) {
      sendSessionNotFound(res);
      return;
    }

    // Only POST can initialize a new session.
    if (req.method !== 'POST') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session ID required for GET and DELETE requests' }));
      return;
    }

    // Delete expired entries before the admission decision. A stale session
    // must not block a valid reconnect.
    await pruneIdleSessions();
    const releaseReservation = reserveInitialization(bearerFingerprint);
    if (!releaseReservation) {
      sendCapacityUnavailable(res);
      return;
    }

    let partialTransport: StreamableHTTPServerTransport | undefined;
    let retained = false;
    let partialClosed = false;
    try {
      const authContext = await resolveAuthContext(
        apiUrl,
        apiKey,
        fetchImpl,
        authValidationTimeoutMs,
      );
      if (deadline.signal.aborted) return;
      if (authContext.status !== 'valid') {
        if (authContext.status === 'invalid') {
          sendInvalidToken(res, oauthEnabled, endpoint);
        } else if (authContext.status === 'subscription_required') {
          sendSubscriptionRequired(res, authContext.body);
        } else {
          sendAuthenticationUnavailable(res, authContext.retryAfterSeconds);
        }
        return;
      }
      // Resource binding: a token granted for one MCP resource is refused on
      // the other path with that path's OAuth challenge.
      if (!endpoint.acceptsResource(authContext.oauthResource)) {
        sendInvalidToken(res, oauthEnabled, endpoint);
        return;
      }

      // A client that advertises elicitation gets SSE responses: the only way
      // to send it `elicitation/create` on the stream of the tool call that
      // needs the person's answer. JSON responses would drop that request.
      // Every other POST response is finite, so the response-byte ceiling can
      // make an admission decision before any tool output reaches the client.
      // GET remains the Streamable HTTP notification channel.
      const sse = advertisesElicitation(parsedBody);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => (machineId ? `${machineId}.${randomUUID()}` : randomUUID()),
        enableJsonResponse: !sse,
      });
      const state: SessionState = { pendingElicitations: 0, lastElicitationEndedAt: 0, notificationStreams: 0 };
      partialTransport = transport;
      teardownRequest = async () => {
        partialClosed = true;
        if (transport.sessionId && transports.get(transport.sessionId)?.transport === transport) {
          transports.delete(transport.sessionId);
        }
        await closeTransports([transport]);
      };

      transport.onclose = () => {
        if (transport.sessionId && transports.get(transport.sessionId)?.transport === transport) {
          transports.delete(transport.sessionId);
        }
      };

      const principal = authContext.principalFingerprint.startsWith('operator:')
        || authContext.principalFingerprint.startsWith('member:')
        ? authContext.principalFingerprint
        : undefined;
      // Who is connected and which pieces are on decide which tools are listed, in the standard profile only: the
      // directory's list is the reviewed one. Without a deployment that says so, every tool is listed.
      const toolSet = extension?.toolSets && endpoint.profile === 'standard'
        ? await createSessionToolSet(extension.toolSets, {
          apiUrl,
          bearer: apiKey,
          fetchImpl,
          timeoutMs: authValidationTimeoutMs,
          audience: authContext.principalFingerprint.startsWith('agent:') ? 'agent' : 'owner',
          now,
        })
        : undefined;
      if (deadline.signal.aborted) return;
      const server = createStackMcpServer(apiUrl, apiKey, {
        isPlatformStaff: authContext.isPlatformStaff,
        ...(toolSet ? { toolSet: toolSet.controller } : {}),
        profile: endpoint.profile,
        // The engine serves the engine's tools and opens an approval's page for the person; a deployment adds its own.
        modules: extension?.modules ?? ENGINE_TOOL_MODULES,
        ...(extension?.confirmer ? { confirmer: extension.confirmer } : {}),
        // Where a result too large for one call is saved: the deployment's, or nowhere (the engine), where it is refused in words.
        ...(extension?.resultHandoff ? { resultHandoff: extension.resultHandoff } : {}),
        // An agent's own session can be sent a wake-up; an operator's chat never is.
        ...(extension?.wakeNotifications && authContext.principalFingerprint.startsWith('agent:') ? { wakeNotifications: true } : {}),
        // Where the guides are, told at initialize; never on the directory profile, whose text was reviewed.
        ...(extension?.instructions && endpoint.profile === 'standard' ? { instructions: extension.instructions } : {}),
        chat: {
          // Without a key of at least 32 characters, chat approval is
          // unavailable and every approval falls back to its link.
          ...(elicitationAttestationKey ? { attestationKey: elicitationAttestationKey } : {}),
          sessionId: () => transport.sessionId,
          ...(principal ? { principal } : {}),
          // Only an OAuth access token can relay an approval: the API refuses
          // plain API keys, so this server does not even ask for one.
          oauth: authContext.oauthResource !== undefined,
          timeoutMs: elicitationTimeoutMs,
          onElicitationPending: (delta) => {
            state.pendingElicitations = Math.max(0, state.pendingElicitations + delta);
            if (state.pendingElicitations === 0) state.lastElicitationEndedAt = now();
          },
        },
      });
      await server.connect(transport);

      // handleRequest processes initialize and assigns transport.sessionId.
      await transport.handleRequest(req, res, parsedBody);

      if (deadline.signal.aborted) return;

      if (!transport.sessionId) return;
      if (transports.has(transport.sessionId)) {
        throw new Error('MCP transport generated a duplicate session id');
      }
      transports.set(transport.sessionId, {
        transport,
        server,
        apiKeyHash,
        bearerFingerprint,
        principalFingerprint: authContext.principalFingerprint,
        isPlatformStaff: authContext.isPlatformStaff,
        profile: endpoint.profile,
        lastSeenAt: now(),
        sse,
        state,
        ...(toolSet ? { toolSet } : {}),
      });
      retained = true;
    } finally {
      releaseReservation();
      if (partialTransport && !retained && !partialClosed) {
        await closeTransports([partialTransport]);
      }
    }
  }

  return handleHttpRequest;
}
