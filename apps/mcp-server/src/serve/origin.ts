/**
 * MCP Streamable HTTP requires servers to reject a present but invalid Origin
 * with 403 (DNS-rebinding defence). Valid: an https origin, or http on
 * localhost / 127.0.0.1 for local development. Absent: valid, because native
 * and server-side clients send no Origin.
 *
 * Any well-formed https origin passes. That is safe here because every MCP
 * request authenticates with an explicit Authorization: Bearer header, never
 * a cookie or other ambient credential. A page on another origin cannot make
 * a browser attach a credential it does not hold, so there is no CSRF
 * exposure, and CORS stays open for browser-based MCP clients.
 */
export function isAllowedOrigin(origin: string | string[] | undefined): boolean {
  if (origin === undefined) return true;
  if (Array.isArray(origin) || origin.length === 0 || origin.length > 2048) return false;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  // An Origin is scheme://host[:port] only; anything else is malformed.
  if (url.origin === 'null' || url.origin !== origin) return false;
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
}

export function setCorsHeaders(res: import('node:http').ServerResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id');
  res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id, WWW-Authenticate');
}
