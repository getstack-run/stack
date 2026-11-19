// requires_unmet enforcement helper.
//
// Pure function. Called from two sites that MUST agree:
//   1. ApprovalGateService.check (runtime — producer side)
//   2. IntentSimulationService.simulate section 2g (simulator side)
//
// Single code path = simulator and runtime cannot drift. If the
// simulator says allowed=true on requires_unmet, the runtime gate
// must also accept; if the simulator denies, the runtime must also
// deny — for the same passport at the same instant.
//
// An IntentClaim's `requires: string[]` field carries pc_* claim ids
// of prior intent_outcome claims that must satisfy ALL of:
//   - exists in passport_claims with the matching claim_id
//   - revoked_at IS NULL
//   - type = 'intent_outcome'  (the registry binds the type at register
//     time; this is a defense-in-depth filter)
//   - body_json.status === 'succeeded'
//   - source passport's session_id === this passport's session_id
//
// The first four are pinned at the repo SQL layer
// (`findActiveOutcomesByClaimIdsAndSessionId`). The status check lives
// here because it reads inside the body_json blob.
//
// Empty requires → always satisfied (no SQL fired).

import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';

export interface RequiresEnforcerDeps {
  /**
   * Narrowed to the one method we use, so callers can pass a stub or
   * a partial mock without faking the full PassportClaimsRepository
   * surface.
   */
  passportClaimsRepo: Pick<
    PassportClaimsRepository,
    'findActiveOutcomesByClaimIdsAndSessionId'
  >;
}

export interface RequiresInput {
  sessionId: string;
  /** pc_* claim ids from IntentClaim.requires */
  requires: string[];
}

export type RequiresResult =
  | { allowed: true }
  | { allowed: false; failingRequires: string[] };

/**
 * Verify each `requires[]` claim id resolves to a succeeded
 * intent_outcome on the same delegation chain. Returns the FULL list
 * of failing ids on denial (not just the first) so the gate / simulator
 * can populate `failing_requires` metadata for operator visibility.
 */
export async function enforceRequires(
  deps: RequiresEnforcerDeps,
  input: RequiresInput,
): Promise<RequiresResult> {
  if (input.requires.length === 0) return { allowed: true };

  const rows = await deps.passportClaimsRepo.findActiveOutcomesByClaimIdsAndSessionId(
    input.requires,
    input.sessionId,
  );

  // Build the satisfied set from rows whose body_json.status === 'succeeded'.
  // Defensive `type` check even though the repo SQL already filters; if a
  // future repo change drops the filter we degrade safely (no false
  // satisfaction).
  const satisfied = new Set<string>();
  for (const row of rows) {
    if (row.type !== 'intent_outcome') continue;
    const body = row.body_json as { status?: unknown };
    if (body && body.status === 'succeeded') {
      satisfied.add(row.claim_id);
    }
  }

  const failingRequires = input.requires.filter((id) => !satisfied.has(id));
  if (failingRequires.length === 0) return { allowed: true };
  return { allowed: false, failingRequires };
}
