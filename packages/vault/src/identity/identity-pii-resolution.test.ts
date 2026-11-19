import { describe, expect, it, vi } from 'vitest';
import { IdentityVerificationService } from './identity-verification-service.js';
import { IdentityProviderRegistry } from './provider-registry.js';

function service(claim: Record<string, unknown> | null) {
  const decrypt = vi.fn(async () => JSON.stringify({ personal_number: 'private-value' }));
  const identityRepo = {
    findClaimById: vi.fn(async () => claim),
    revokeClaim: vi.fn(async () => undefined),
  };
  const verification = new IdentityVerificationService(
    {} as never,
    new IdentityProviderRegistry(),
    identityRepo as never,
    { decrypt } as never,
  );
  return { verification, decrypt, identityRepo };
}

function liveClaim(overrides: Record<string, unknown> = {}) {
  return {
    id: 'ic_live',
    operator_id: 'op_owner',
    layer: 'identity',
    payload_encrypted: 'kms-ciphertext',
    revoked_at: null,
    expires_at: new Date(Date.now() + 60_000),
    ...overrides,
  };
}

describe('identity PII resolution lifecycle', () => {
  it('decrypts only a live identity claim owned by the requesting tenant', async () => {
    const { verification, decrypt } = service(liveClaim());

    await expect(verification.resolvePii('ic_live', 'op_owner')).resolves.toEqual({
      personal_number: 'private-value',
    });
    expect(decrypt).toHaveBeenCalledWith('kms-ciphertext', {
      operator_id: 'op_owner',
      store: 'identity_claim_pii',
    });
  });

  it.each([
    ['foreign', liveClaim({ operator_id: 'op_other' })],
    ['wrong layer', liveClaim({ layer: 'humanity' })],
    ['revoked', liveClaim({ revoked_at: new Date() })],
    ['expired', liveClaim({ expires_at: new Date(Date.now() - 1) })],
    ['erased', liveClaim({ payload_encrypted: null })],
  ])('does not decrypt a %s claim', async (_name, claim) => {
    const { verification, decrypt } = service(claim);

    await expect(verification.resolvePii('ic_live', 'op_owner')).resolves.toBeNull();
    expect(decrypt).not.toHaveBeenCalled();
  });

  it('cascades a legacy identity revocation into authority invalidation', async () => {
    const { verification, identityRepo } = service(liveClaim());
    const invalidate = vi.fn(async () => undefined);
    verification.setAuthorityInvalidationHandler(invalidate);

    await verification.revokeClaim('ic_live', 'op_owner');

    expect(identityRepo.revokeClaim).toHaveBeenCalledWith('ic_live');
    expect(invalidate).toHaveBeenCalledWith(
      'op_owner',
      'ic_live',
      'legacy_identity_claim_revoked',
    );
  });
});
