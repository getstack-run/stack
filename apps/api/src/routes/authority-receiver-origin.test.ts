import { describe, expect, it } from 'vitest';
import { assertNormalizedNativeReceiverOrigin } from './authority.js';

describe('native receiver origin boundary', () => {
  it('accepts only a normalized HTTPS origin', () => {
    expect(() => assertNormalizedNativeReceiverOrigin({
      mode: 'native',
      canonical_identifier: 'https://receiver.example',
    })).not.toThrow();
  });

  it.each([
    'http://receiver.example',
    'https://receiver.example/path',
    'https://receiver.example?query=1',
    'https://receiver.example/#fragment',
    'https://user@receiver.example',
    'https://127.0.0.1',
    'https://[::1]',
    'HTTPS://RECEIVER.EXAMPLE',
  ])('rejects non-normalized or literal-address native origin %s', (canonical_identifier) => {
    expect(() => assertNormalizedNativeReceiverOrigin({
      mode: 'native',
      canonical_identifier,
    })).toThrow('Native receiver identifier must be a normalized HTTPS origin');
  });

  it('leaves proxy receiver identifiers to tenant-scoped connection validation', () => {
    expect(() => assertNormalizedNativeReceiverOrigin({
      mode: 'proxy_bridge',
      canonical_identifier: 'provider:account',
    })).not.toThrow();
  });
});
