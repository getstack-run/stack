import type { IdentityVerificationProvider } from './types.js';

/**
 * In-memory registry of identity verification providers.
 * Loaded at startup from DB + code-registered adapters.
 */
export class IdentityProviderRegistry {
  private providers = new Map<string, IdentityVerificationProvider>();

  register(provider: IdentityVerificationProvider, replace = false): void {
    if (this.providers.has(provider.providerKey) && !replace) {
      throw new Error(`Provider "${provider.providerKey}" already registered`);
    }
    this.providers.set(provider.providerKey, provider);
  }

  get(providerKey: string): IdentityVerificationProvider | undefined {
    return this.providers.get(providerKey);
  }

  has(providerKey: string): boolean {
    return this.providers.has(providerKey);
  }

  listAll(): IdentityVerificationProvider[] {
    return [...this.providers.values()];
  }
}
