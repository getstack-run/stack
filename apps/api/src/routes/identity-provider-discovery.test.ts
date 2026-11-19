import { describe, expect, it, vi } from 'vitest';
import { IdentityProviderRegistry } from '../../../../packages/vault/src/identity/provider-registry.js';
import { IdentityVerificationService } from '../../../../packages/vault/src/identity/identity-verification-service.js';
import type { IdentityVerificationProvider } from '../../../../packages/vault/src/identity/types.js';

function provider(
  providerKey: string,
  displayName: string,
  options?: {
    connect?: { flow: 'inline' | 'redirect'; requestedClaim: 'verified_human' | 'verified_identity' };
    layers?: readonly ('humanity' | 'identity')[];
    assurance?: 'low' | 'substantial' | 'high';
  },
) {
  return {
    providerKey,
    displayName,
    claimTypes: options?.layers?.includes('identity')
      ? ['verified_human', 'verified_identity']
      : ['verified_human'],
    supportedLayers: options?.layers ?? ['humanity'],
    assuranceLevel: options?.assurance ?? 'low',
    connect: options?.connect,
    initiate: vi.fn(),
    complete: vi.fn(),
  } as IdentityVerificationProvider;
}

function serviceWithCatalog(lifetimeL2Claims = 1) {
  const registry = new IdentityProviderRegistry();
  registry.register(provider('cloudflare_turnstile', 'Cloudflare Turnstile', {
    connect: { flow: 'inline', requestedClaim: 'verified_human' },
  }));
  registry.register(provider('stripe_identity', 'Stripe Identity', {
    connect: { flow: 'redirect', requestedClaim: 'verified_identity' },
    layers: ['humanity', 'identity'],
    assurance: 'high',
  }));
  registry.register(provider('oidc', 'OIDC', {
    layers: ['humanity', 'identity'],
    assurance: 'substantial',
  }));
  registry.register(provider('unlisted_mock', 'Unlisted mock'));

  const identityRepo = {
    listActiveProviders: vi.fn(async () => [
      { provider_key: 'cloudflare_turnstile' },
      { provider_key: 'stripe_identity' },
      { provider_key: 'spiffe' },
      { provider_key: 'wimse' },
      { provider_key: 'oidc' },
      { provider_key: 'deltest_msw67l0z' },
      { provider_key: 'unlisted_mock' },
    ]),
    countLifetimeL2ClaimsForOperator: vi.fn(async () => lifetimeL2Claims),
  };

  const service = new IdentityVerificationService(
    {} as never,
    registry,
    identityRepo as never,
    {} as never,
  );
  // What a verification costs is the deployment's price list; this one charges for Stripe Identity alone (STACK's own
  // is checked in the deployment's own tests).
  service.setVerificationPricing((providerKey) => (providerKey === 'stripe_identity' ? 150 : 0));
  return service;
}

describe('identity provider discovery', () => {
  it('returns only runtime-ready human verification providers', async () => {
    const providers = await serviceWithCatalog().listProviders('op_one');

    expect(providers).toEqual([
      {
        provider_key: 'cloudflare_turnstile',
        name: 'Cloudflare Turnstile',
        supported_layers: ['humanity'],
        claim_types: ['verified_human'],
        assurance_level: 'low',
        verification_flow: 'inline',
        requested_claim: 'verified_human',
        price_cents: 0,
      },
      {
        provider_key: 'stripe_identity',
        name: 'Stripe Identity',
        supported_layers: ['humanity', 'identity'],
        claim_types: ['verified_human', 'verified_identity'],
        assurance_level: 'high',
        verification_flow: 'redirect',
        requested_claim: 'verified_identity',
        price_cents: 150,
      },
    ]);
  });

  it('shows the first L2 verification as free', async () => {
    const providers = await serviceWithCatalog(0).listProviders('op_new');
    expect(providers.find((item) => item.provider_key === 'stripe_identity')?.price_cents).toBe(0);
  });
});
