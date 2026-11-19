import type { IncomingMessage, ServerResponse } from 'node:http';

/** `GET /health`. Returns true when the request was answered. */
export function handleHealth(url: URL, res: ServerResponse): boolean {
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return true;
  }
  return false;
}

/**
 * OpenAI apps domain verification. The token is public by design; it is
 * served only when configured. Returns true when the request was answered.
 */
export function handleOpenaiAppsChallenge(
  url: URL,
  req: IncomingMessage,
  res: ServerResponse,
  openaiAppsChallengeToken: string,
): boolean {
  if (url.pathname === '/.well-known/openai-apps-challenge') {
    if (!openaiAppsChallengeToken || (req.method !== 'GET' && req.method !== 'HEAD')) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return true;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(req.method === 'HEAD' ? undefined : openaiAppsChallengeToken);
    return true;
  }
  return false;
}
