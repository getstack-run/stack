import { describe, it, expect } from 'vitest';
import { computePassportClaimHash } from './passport-claim-hash.js';

describe('computePassportClaimHash', () => {
  const baseInput = {
    passport_id: 'pas_abc',
    type: 'svid_attestation' as const,
    body: {
      type: 'svid_attestation',
      spiffe_id: 'spiffe://acme.example/wl/foo',
      trust_domain: 'acme.example',
      not_after_svid: 1700000000,
      issuer: 'https://spire.acme.example',
      attested_at: 1699999000,
      svid_format: 'jwt-svid' as const,
    },
  };

  it('produces 64-char hex sha256', () => {
    const h = computePassportClaimHash(baseInput);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic — same input, same hash', () => {
    expect(computePassportClaimHash(baseInput)).toBe(
      computePassportClaimHash({ ...baseInput, body: { ...baseInput.body } }),
    );
  });

  it('object key order independent (canonical sort)', () => {
    const reordered = {
      passport_id: baseInput.passport_id,
      type: baseInput.type,
      body: {
        // intentionally different insertion order
        svid_format: 'jwt-svid',
        attested_at: 1699999000,
        issuer: 'https://spire.acme.example',
        not_after_svid: 1700000000,
        trust_domain: 'acme.example',
        spiffe_id: 'spiffe://acme.example/wl/foo',
        type: 'svid_attestation',
      },
    };
    expect(computePassportClaimHash(reordered)).toBe(computePassportClaimHash(baseInput));
  });

  it('binds to passport_id — same body, different passport → different hash', () => {
    const h1 = computePassportClaimHash(baseInput);
    const h2 = computePassportClaimHash({ ...baseInput, passport_id: 'pas_def' });
    expect(h1).not.toBe(h2);
  });

  it('tamper detection — flipping any body field changes the hash', () => {
    const h0 = computePassportClaimHash(baseInput);
    expect(
      computePassportClaimHash({
        ...baseInput,
        body: { ...baseInput.body, spiffe_id: 'spiffe://attacker.example/wl/foo' },
      }),
    ).not.toBe(h0);
    expect(
      computePassportClaimHash({
        ...baseInput,
        body: { ...baseInput.body, not_after_svid: baseInput.body.not_after_svid + 1 },
      }),
    ).not.toBe(h0);
  });

  it('arrays preserve order (sequence semantics)', () => {
    const a = computePassportClaimHash({
      passport_id: 'pas_x',
      type: 'fake_array_claim',
      body: { items: ['a', 'b', 'c'] },
    });
    const b = computePassportClaimHash({
      passport_id: 'pas_x',
      type: 'fake_array_claim',
      body: { items: ['c', 'b', 'a'] },
    });
    expect(a).not.toBe(b);
  });

  it('nested objects sort recursively', () => {
    const a = computePassportClaimHash({
      passport_id: 'pas_x',
      type: 'fake_nested',
      body: { outer: { z: 1, a: 2 } },
    });
    const b = computePassportClaimHash({
      passport_id: 'pas_x',
      type: 'fake_nested',
      body: { outer: { a: 2, z: 1 } },
    });
    expect(a).toBe(b);
  });

  it('undefined values dropped (JSON.stringify parity)', () => {
    const a = computePassportClaimHash({
      passport_id: 'pas_x',
      type: 'fake',
      body: { a: 1, b: undefined as unknown as number },
    });
    const b = computePassportClaimHash({
      passport_id: 'pas_x',
      type: 'fake',
      body: { a: 1 },
    });
    expect(a).toBe(b);
  });
});
