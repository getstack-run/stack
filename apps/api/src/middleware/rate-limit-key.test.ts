import { describe, expect, it } from 'vitest';
import { preAuthRateLimitKey } from './rate-limit-key.js';

function jwt(payload: Record<string, unknown>): string {
  return [
    Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url'),
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
    'signature',
  ].join('.');
}

describe('preAuthRateLimitKey with a verified client address', () => {
  it('keys by the vouched address in place of the source address, in the same shapes', () => {
    expect(preAuthRateLimitKey('Bearer sk_live_x', '10.0.0.1', '198.51.100.20')).toBe('bearer-ip:198.51.100.20');
    expect(preAuthRateLimitKey(undefined, '10.0.0.1', '198.51.100.20')).toBe('ip:198.51.100.20');
    expect(preAuthRateLimitKey(`Bearer ${'x'.repeat(4_097)}`, '10.0.0.1', '198.51.100.20')).toBe('ip:198.51.100.20');
  });

  it('keys by the source address when none is vouched for', () => {
    expect(preAuthRateLimitKey('Bearer sk_live_x', '10.0.0.1', undefined)).toBe('bearer-ip:10.0.0.1');
    expect(preAuthRateLimitKey(undefined, '10.0.0.1')).toBe('ip:10.0.0.1');
  });
});

describe('preAuthRateLimitKey', () => {
  it.each([
    ['agent', { iss: 'stack-sdk', sub: 'agt_attacker' }],
    ['OAuth', { iss: 'https://api.getstack.run', sub: 'op_attacker', token_use: 'access' }],
    ['session', { iss: 'stack-api', sub: 'mem_attacker', role: 'admin' }],
  ])('keeps an unverified %s JWT in the source-IP bucket', (_kind, payload) => {
    expect(preAuthRateLimitKey(`Bearer ${jwt(payload)}`, '203.0.113.8'))
      .toBe('bearer-ip:203.0.113.8');
  });

  it('does not let rotating issuer or subject claims rotate the bucket', () => {
    const candidates = [
      jwt({ iss: 'stack-sdk', sub: 'agt_one' }),
      jwt({ iss: 'stack-api', sub: 'op_two' }),
      jwt({ iss: 'https://attacker.invalid', sub: 'mem_three' }),
    ];
    expect(candidates.map((token) => preAuthRateLimitKey(
      `Bearer ${token}`,
      '203.0.113.8',
    ))).toEqual([
      'bearer-ip:203.0.113.8',
      'bearer-ip:203.0.113.8',
      'bearer-ip:203.0.113.8',
    ]);
  });

  it('keeps malformed and oversized bearer values on the source-IP bucket', () => {
    expect(preAuthRateLimitKey('Bearer not.a.jwt', '203.0.113.8'))
      .toBe('bearer-ip:203.0.113.8');
    expect(preAuthRateLimitKey(`Bearer ${'x'.repeat(4_097)}`, '203.0.113.8'))
      .toBe('ip:203.0.113.8');
  });

  it('does not let fake API-key-shaped values rotate the bucket', () => {
    expect(preAuthRateLimitKey('Bearer sk_live_example', '203.0.113.8'))
      .toBe('bearer-ip:203.0.113.8');
    expect(preAuthRateLimitKey('Bearer sk_live_rotated', '203.0.113.8'))
      .toBe('bearer-ip:203.0.113.8');
  });
});
