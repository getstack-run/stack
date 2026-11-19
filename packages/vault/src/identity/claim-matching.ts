import type { AssuranceLevel, PassportClaimRef } from '@stack/shared';
import type { ServiceRequirementRecord, ClaimMatchResult, ClaimMatch } from './types.js';

/**
 * Assurance level ordering for comparison.
 * A claim at a higher level satisfies a requirement at a lower level.
 */
const ASSURANCE_RANK: Record<AssuranceLevel, number> = {
  low: 1,
  substantial: 2,
  high: 3,
};

function meetsAssurance(claimLevel: AssuranceLevel, requiredLevel: AssuranceLevel): boolean {
  return ASSURANCE_RANK[claimLevel] >= ASSURANCE_RANK[requiredLevel];
}

/**
 * Matches passport identity claim references against service requirements.
 * Used at passport verification time to auto-enforce identity requirements.
 *
 * Three-layer matching:
 *   Layer 1 (humanity):   claim_type + assurance_level + provider
 *   Layer 2 (identity):   claim_type + assurance_level + provider + requires_pii check
 *   Layer 3 (delegation): claim_type + assurance_level + provider + delegated_scopes ⊇ required_scopes
 */
export class ClaimMatchingService {
  satisfies(
    passportClaims: PassportClaimRef[],
    requirements: ServiceRequirementRecord[],
  ): ClaimMatchResult {
    const now = Math.floor(Date.now() / 1000);
    const matches: ClaimMatch[] = [];
    const unmet: ServiceRequirementRecord[] = [];

    for (const req of requirements) {
      const match = passportClaims.find((claim) => {
        // Layer must match
        if (claim.layer !== req.layer) return false;

        // Claim type must match
        if (claim.claim_type !== req.requires_claim) return false;

        // Provider must be accepted (empty list = any provider accepted)
        if (req.accepted_providers.length > 0 && !req.accepted_providers.includes(claim.provider)) {
          return false;
        }

        // Assurance level must meet minimum
        if (!meetsAssurance(claim.assurance_level, req.minimum_assurance)) return false;

        // Claim must not be expired
        if (claim.expires_at <= now) return false;

        // Layer 3 — delegated scopes must include all required scopes
        if (req.layer === 'delegation' && req.required_scopes && req.required_scopes.length > 0) {
          const claimScopes = claim.delegated_scopes ?? [];
          const hasAll = req.required_scopes.every((s) => claimScopes.includes(s));
          if (!hasAll) return false;
        }

        return true;
      });

      if (match) {
        matches.push({
          requirement: req,
          claim: {
            provider: match.provider,
            claim_type: match.claim_type,
            assurance_level: match.assurance_level,
          },
        });
      } else {
        unmet.push(req);
      }
    }

    return {
      satisfied: unmet.length === 0,
      matches,
      unmet,
    };
  }

  /**
   * Check if any requirements need PII but the verify call didn't request it.
   * Services must explicitly declare requires_pii: true with a lawful basis.
   */
  requiresPii(requirements: ServiceRequirementRecord[]): boolean {
    return requirements.some((r) => r.requires_pii);
  }

  /**
   * Validate GDPR compliance of requirements — Layer 2 requirements
   * MUST have requires_pii: true and a lawful basis.
   */
  validateGdprCompliance(requirements: ServiceRequirementRecord[]): string[] {
    const violations: string[] = [];
    for (const req of requirements) {
      if (req.layer === 'identity' && !req.requires_pii) {
        violations.push(`Requirement "${req.requires_claim}" is Layer 2 (identity) but requires_pii is false`);
      }
      if (req.requires_pii && !req.lawful_basis) {
        violations.push(`Requirement "${req.requires_claim}" requires PII but no lawful_basis declared`);
      }
    }
    return violations;
  }
}
