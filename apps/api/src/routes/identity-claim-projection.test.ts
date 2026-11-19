import { describe, expect, it } from 'vitest';
import { publicIdentityClaim } from './identity.js';

describe('identity claim public projection', () => {
  it('keeps lifecycle fields and removes encrypted material', () => {
    const verifiedAt = new Date('2026-08-17T10:00:00.000Z');
    const expiresAt = new Date('2026-11-15T10:00:00.000Z');
    const createdAt = new Date('2026-08-17T10:00:01.000Z');

    const privateClaim = {
      id: 'clm_one',
      operator_id: 'op_one',
      provider_id: 'idp_stripe',
      provider_key: 'stripe_identity',
      layer: 'identity',
      claim_type: 'verified_identity',
      assurance_level: 'high',
      verified_at: verifiedAt,
      expires_at: expiresAt,
      assertion_encrypted: 'kms:assertion-ciphertext',
      payload_encrypted: 'kms:pii-ciphertext',
      delegated_scopes: null,
      revoked_at: null,
      created_at: createdAt,
      claim_id: 'pc_one',
    };

    expect(publicIdentityClaim(privateClaim)).toEqual({
      id: 'clm_one',
      operator_id: 'op_one',
      provider_id: 'idp_stripe',
      provider_key: 'stripe_identity',
      layer: 'identity',
      claim_type: 'verified_identity',
      assurance_level: 'high',
      verified_at: verifiedAt,
      expires_at: expiresAt,
      delegated_scopes: null,
      revoked_at: null,
      created_at: createdAt,
      claim_id: 'pc_one',
    });
  });
});
