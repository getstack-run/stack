import type { WorkloadIdentityProvider } from './types.js';

/**
 * In-memory registry of workload-identity providers (SPIFFE today;
 * future: AWS IAM Roles Anywhere, GCP Workload Identity Federation, …).
 *
 * Kept separate from the human-flow `IdentityProviderRegistry` because
 * the two interfaces have fundamentally different shapes — one is a
 * session-driven flow, one is a one-shot validator. Sharing a registry
 * would mean union types throughout the call sites for negligible
 * benefit; a dedicated registry keeps each domain crisp.
 *
 * The dashboard's provider list is sourced from the
 * identity_providers DB table (the seed inserted in migration 0029
 * carries the SPIFFE row), not from this in-memory map. This map exists
 * solely so the workload route can dispatch by provider_key.
 */
export class WorkloadProviderRegistry {
  private providers = new Map<string, WorkloadIdentityProvider>();

  register(provider: WorkloadIdentityProvider, replace = false): void {
    if (this.providers.has(provider.providerKey) && !replace) {
      throw new Error(`Workload provider "${provider.providerKey}" already registered`);
    }
    this.providers.set(provider.providerKey, provider);
  }

  get(providerKey: string): WorkloadIdentityProvider | undefined {
    return this.providers.get(providerKey);
  }

  has(providerKey: string): boolean {
    return this.providers.has(providerKey);
  }

  listAll(): WorkloadIdentityProvider[] {
    return [...this.providers.values()];
  }
}
