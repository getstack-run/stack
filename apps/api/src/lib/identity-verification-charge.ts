/**
 * What is charged when a person completes an identity verification. STACK's
 * hosted product charges the provider's price from credit after the first
 * verification; an install uses its own identity providers with its own keys
 * and charges nobody, which is `NO_IDENTITY_CHARGE`.
 */
export interface IdentityVerificationCharge {
  /** Called once the verified claims have safely landed. Never throws: a failed charge is logged, not surfaced. */
  charge(operatorId: string, providerKey: string, claims: ReadonlyArray<{ layer: string }>): Promise<void>;
  /** What a verification by this provider costs, in cents, once the first one is free: the price shown beside it. */
  priceCents(providerKey: string): number;
}

export const NO_IDENTITY_CHARGE: IdentityVerificationCharge = {
  async charge() {},
  priceCents: () => 0,
};
