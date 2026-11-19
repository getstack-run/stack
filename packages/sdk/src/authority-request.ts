export const AUTHORITY_REQUEST_ID_HEADER = 'X-STACK-Authority-Request-Id';

const AUTHORITY_REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{22,256}$/;

/**
 * Create a browser-safe, cryptographically random runtime operation handle.
 * Eighteen random bytes encode to 24 base64url characters.
 */
export function createAuthorityRequestId(): string {
  const bytes = new Uint8Array(18);
  globalThis.crypto.getRandomValues(bytes);

  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let encoded = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1] ?? 0;
    const third = bytes[index + 2] ?? 0;
    const value = (first << 16) | (second << 8) | third;
    encoded += alphabet[(value >>> 18) & 63];
    encoded += alphabet[(value >>> 12) & 63];
    if (index + 1 < bytes.length) encoded += alphabet[(value >>> 6) & 63];
    if (index + 2 < bytes.length) encoded += alphabet[value & 63];
  }
  return encoded;
}

/**
 * Build the runtime authority correlation header. Callers create this stable,
 * high-entropy identifier once and reuse it for exact retries.
 */
export function authorityRequestHeaders(authorityRequestId?: string): Record<string, string> {
  if (authorityRequestId === undefined) return {};
  if (!AUTHORITY_REQUEST_ID_PATTERN.test(authorityRequestId)) {
    throw new Error(
      'authorityRequestId must be 22-256 base64url characters and must be reused for exact retries',
    );
  }
  return { [AUTHORITY_REQUEST_ID_HEADER]: authorityRequestId };
}
