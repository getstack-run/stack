import { describe, expect, it } from 'vitest';
import { safeAuthorityResponse } from './authority-safe-response.js';

describe('safeAuthorityResponse', () => {
  it('allows opaque refs, digests and non-sensitive metadata', () => {
    const view = {
      id: 'prf_one',
      evidence_digest: 'sha256:abc',
      subject_ref: 'prn_one',
      nested: [{ fact_id: 'se.personal_number', disclosure_mode: 'exact_private' }],
    };
    expect(safeAuthorityResponse(view)).toBe(view);
  });

  it.each([
    'assertion_encrypted',
    'payload_encrypted',
    'native_evidence',
    'signed_callback',
    'normalized_request',
    'signed_decision',
    'signed_request',
    'signed_receipt',
    'passport',
    'ciphertext',
    'plaintext',
    'personal_number',
    'national_id',
    'full_name',
    'date_of_birth',
    'credential_encrypted',
    'private_key',
  ])('fails closed when %s appears anywhere in a response', (field) => {
    expect(() => safeAuthorityResponse({ safe: { nested: [{ [field]: 'secret' }] } })).toThrow(
      'Authority response could not be safely projected',
    );
  });

  it('handles repeated object references without recursion failure', () => {
    const object: Record<string, unknown> = { id: 'abn_one' };
    object['self'] = object;
    expect(safeAuthorityResponse(object)).toBe(object);
  });
});
