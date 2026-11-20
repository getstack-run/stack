import { createHmac } from 'node:crypto';
import { isUsableMcpElicitationAttestationKey } from './mcp-elicitation-attestation.js';

/** What the key for the hosted MCP server's forwarded-client header is derived for. */
export const MCP_FORWARDED_CLIENT_KEY_PURPOSE = 'stack:forwarded-client:mcp';

/**
 * The key the hosted MCP server signs `x-stack-forwarded-client` with and the API verifies it under: an HMAC-SHA256 of a
 * fixed purpose string under the attestation key the two already share, as hex. It is a different key from the
 * attestation key itself, so a header signature can never stand in for a chat confirmation, nor the reverse. Null when the
 * shared key is unset or too short: neither side then signs or trusts such a header.
 */
export function deriveMcpForwardedClientKey(attestationKey: string | undefined | null): string | null {
  if (!isUsableMcpElicitationAttestationKey(attestationKey)) return null;
  return createHmac('sha256', attestationKey.trim()).update(MCP_FORWARDED_CLIENT_KEY_PURPOSE).digest('hex');
}

/**
 * The `x-stack-forwarded-client` header value for an end client's address: `<client-ip>.<unix-seconds>.<hex hmac-sha256>`, the
 * MAC over `stack-forwarded-client:v1:<client-ip>:<unix-seconds>` under the key. The API reads it with its own verifier
 * (`apps/api/src/middleware/forwarded-client.ts`). It is signed fresh for each call, since the API accepts a header only
 * within a minute of its own clock.
 */
export function signForwardedClient(clientIp: string, key: string, nowMs: number): string {
  const unixSeconds = String(Math.floor(nowMs / 1000));
  const mac = createHmac('sha256', key).update(`stack-forwarded-client:v1:${clientIp}:${unixSeconds}`).digest('hex');
  return `${clientIp}.${unixSeconds}.${mac}`;
}
