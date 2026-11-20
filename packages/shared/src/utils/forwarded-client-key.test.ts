import { describe, expect, it } from 'vitest';
import { deriveMcpForwardedClientKey, MCP_FORWARDED_CLIENT_KEY_PURPOSE, signForwardedClient } from './forwarded-client-key.js';

const SHARED = 'forwarded-client-key-test-attestation-key-0123456789';

describe('deriveMcpForwardedClientKey', () => {
  it('is a fixed HMAC-SHA256 of the purpose under the shared key, as hex', () => {
    expect(MCP_FORWARDED_CLIENT_KEY_PURPOSE).toBe('stack:forwarded-client:mcp');
    // Both servers derive the key with this function; this vector pins the result.
    expect(deriveMcpForwardedClientKey(SHARED)).toBe('b960365a6ba66273d6218da66e252ca0818691cf6828715f8d1f9fbf82c97aca');
  });

  it('is not the attestation key, and another shared key gives another key', () => {
    const derived = deriveMcpForwardedClientKey(SHARED);
    expect(derived).not.toBe(SHARED);
    expect(derived).not.toBe(deriveMcpForwardedClientKey(`${SHARED}x`));
  });

  it('gives no key when the shared key is unset or shorter than 32 characters', () => {
    expect(deriveMcpForwardedClientKey(undefined)).toBeNull();
    expect(deriveMcpForwardedClientKey(null)).toBeNull();
    expect(deriveMcpForwardedClientKey('')).toBeNull();
    expect(deriveMcpForwardedClientKey('short-key')).toBeNull();
  });
});

describe('signForwardedClient', () => {
  // The same vector the API's own verifier is tested against (apps/api/src/middleware/forwarded-client.test.ts): the two
  // copies of the format are pinned to one header.
  const SECRET = 'forwarded-client-test-vector-secret-0123456789';

  it('makes the header the API verifies: <ip>.<unix-seconds>.<hex hmac-sha256>', () => {
    expect(signForwardedClient('203.0.113.7', SECRET, 1_700_000_000_000)).toBe(
      '203.0.113.7.1700000000.c5f23ef0bc9618ba035fbc34536f815d365ca00e0a5b76a2bc63dd2a3001cde5',
    );
    expect(signForwardedClient('2001:db8::1', SECRET, 1_700_000_000_999)).toBe(
      '2001:db8::1.1700000000.3ab5baecbaa329b1a18b61d025be5872f06c454a421a0460442d0682cb0459b1',
    );
  });
});
