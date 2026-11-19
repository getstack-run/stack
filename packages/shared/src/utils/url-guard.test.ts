import { describe, expect, it } from 'vitest';
import { isBlockedIp } from './url-guard.js';

describe('public destination IP classification', () => {
  it.each([
    '::ffff:7f00:1', '0:0:0:0:0:ffff:0a00:1', '::ffff:a9fe:a9fe',
    '2002:7f00:1::', '64:ff9b::7f00:1', '2001:db8::1', '3fff::1',
    '192.0.2.1', '198.51.100.1', '203.0.113.1', '192.88.99.1',
  ])('rejects private, transition or reserved address %s', (address) => {
    expect(isBlockedIp(address)).toBe(true);
  });
  it.each(['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '2001:4860:4860::8888'])(
    'allows globally routable address %s', (address) => expect(isBlockedIp(address)).toBe(false),
  );
});
