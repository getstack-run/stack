import { describe, expect, it } from 'vitest';
import {
  FORWARDED_CLIENT_TOLERANCE_SECONDS,
  forwardedClientMac,
  verifyForwardedClient,
} from './forwarded-client.js';

// The Console's server asserts the same vector in its own test: it cannot import this code, so
// the two copies of the format are pinned to one header.
const SECRET = 'forwarded-client-test-vector-secret-0123456789';
const VECTOR_IP = '203.0.113.7';
const VECTOR_TIME = 1_700_000_000;
const VECTOR_HEADER = '203.0.113.7.1700000000.c5f23ef0bc9618ba035fbc34536f815d365ca00e0a5b76a2bc63dd2a3001cde5';
const VECTOR_IPV6_HEADER = '2001:db8::1.1700000000.3ab5baecbaa329b1a18b61d025be5872f06c454a421a0460442d0682cb0459b1';
const NOW_MS = VECTOR_TIME * 1000;

function header(ip: string, seconds: number, secret = SECRET): string {
  return `${ip}.${seconds}.${forwardedClientMac(ip, String(seconds), secret)}`;
}

describe('verifyForwardedClient', () => {
  it('matches the shared test vector', () => {
    expect(header(VECTOR_IP, VECTOR_TIME)).toBe(VECTOR_HEADER);
    expect(header('2001:db8::1', VECTOR_TIME)).toBe(VECTOR_IPV6_HEADER);
  });

  it('accepts a valid header and answers the client address', () => {
    expect(verifyForwardedClient(VECTOR_HEADER, SECRET, NOW_MS)).toBe(VECTOR_IP);
  });

  it('accepts an IPv6 address', () => {
    expect(verifyForwardedClient(VECTOR_IPV6_HEADER, SECRET, NOW_MS)).toBe('2001:db8::1');
  });

  it('accepts an IPv4-mapped IPv6 address, which holds dots itself', () => {
    expect(verifyForwardedClient(header('::ffff:203.0.113.7', VECTOR_TIME), SECRET, NOW_MS)).toBe('::ffff:203.0.113.7');
  });

  it('refuses a wrong MAC', () => {
    const wrong = VECTOR_HEADER.slice(0, -1) + (VECTOR_HEADER.endsWith('5') ? '6' : '5');
    expect(verifyForwardedClient(wrong, SECRET, NOW_MS)).toBeUndefined();
    expect(verifyForwardedClient(header(VECTOR_IP, VECTOR_TIME, 'another-secret-another-secret-123456'), SECRET, NOW_MS)).toBeUndefined();
  });

  it('refuses a MAC made for another address', () => {
    const other = `198.51.100.9.${VECTOR_TIME}.${VECTOR_HEADER.split('.').pop()}`;
    expect(verifyForwardedClient(other, SECRET, NOW_MS)).toBeUndefined();
  });

  it('refuses a stale and a future header, and accepts the edge of the window', () => {
    const edge = FORWARDED_CLIENT_TOLERANCE_SECONDS;
    expect(verifyForwardedClient(header(VECTOR_IP, VECTOR_TIME - edge - 1), SECRET, NOW_MS)).toBeUndefined();
    expect(verifyForwardedClient(header(VECTOR_IP, VECTOR_TIME + edge + 1), SECRET, NOW_MS)).toBeUndefined();
    expect(verifyForwardedClient(header(VECTOR_IP, VECTOR_TIME - edge), SECRET, NOW_MS)).toBe(VECTOR_IP);
    expect(verifyForwardedClient(header(VECTOR_IP, VECTOR_TIME + edge), SECRET, NOW_MS)).toBe(VECTOR_IP);
  });

  it.each([
    ['empty', ''],
    ['no dots', 'abc'],
    ['one dot', '203.0.113.7.1700000000'],
    ['no address', `.${VECTOR_TIME}.${'a'.repeat(64)}`],
    ['non-numeric time', `203.0.113.7.17e8.${'a'.repeat(64)}`],
    ['short MAC', `203.0.113.7.${VECTOR_TIME}.abcd`],
    ['long MAC', `203.0.113.7.${VECTOR_TIME}.${'a'.repeat(66)}`],
    ['non-hex MAC', `203.0.113.7.${VECTOR_TIME}.${'g'.repeat(64)}`],
    ['oversized', 'x'.repeat(500)],
  ])('ignores a malformed header (%s) without throwing', (_name, value) => {
    expect(verifyForwardedClient(value, SECRET, NOW_MS)).toBeUndefined();
  });

  it('refuses a signed value that is not an IP address', () => {
    expect(verifyForwardedClient(header('not-an-ip', VECTOR_TIME), SECRET, NOW_MS)).toBeUndefined();
    expect(verifyForwardedClient(header('999.1.1.1', VECTOR_TIME), SECRET, NOW_MS)).toBeUndefined();
    expect(verifyForwardedClient(header('203.0.113.7:8080', VECTOR_TIME), SECRET, NOW_MS)).toBeUndefined();
  });

  it('ignores the header when no secret is configured', () => {
    expect(verifyForwardedClient(VECTOR_HEADER, undefined, NOW_MS)).toBeUndefined();
    expect(verifyForwardedClient(VECTOR_HEADER, '', NOW_MS)).toBeUndefined();
  });

  it('ignores a missing or repeated header', () => {
    expect(verifyForwardedClient(undefined, SECRET, NOW_MS)).toBeUndefined();
    expect(verifyForwardedClient([VECTOR_HEADER, VECTOR_HEADER], SECRET, NOW_MS)).toBeUndefined();
  });
});
