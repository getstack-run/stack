import { vi } from 'vitest';
import type {
  MissionLookup,
  PassportAuthorityLookup,
  PassportFleetLookup,
  PassportServiceDependencies,
} from './passport-service.js';

/**
 * The dependencies a PassportService test does not care about, as inert stubs.
 *
 * PassportService cannot be built without its dependencies, so every test
 * supplies all of them. A test overrides the ones its scenario exercises and
 * takes these for the rest. Each default refuses loudly rather than answering:
 * a lookup the scenario never expected throws, and a mission lookup that knows
 * no Mission reports every Mission as missing.
 *
 * The four collaborators the service reads through accessors are held in
 * mutable fields, so a test can swap one between calls the way the composition
 * root's accessor would see a later-built collaborator. The identity services
 * and the claims repository are read when `dependencies` is built, so set them
 * before constructing the service.
 */
export interface PassportTestWiring {
  identityVerification: unknown;
  claimMatcher: unknown;
  identityRepo: unknown;
  passportClaimsRepo: unknown;
  missionLookup: MissionLookup;
  securityEvent: unknown;
  authorityLookup: PassportAuthorityLookup;
  fleetLookup: PassportFleetLookup;
  readonly dependencies: PassportServiceDependencies;
}

function unexpected(name: string) {
  return async () => {
    throw new Error(`unexpected call to ${name} in this test`);
  };
}

export function passportTestWiring(
  overrides: Partial<Omit<PassportTestWiring, 'dependencies'>> = {},
): PassportTestWiring {
  const wiring: PassportTestWiring = {
    identityVerification: { buildPassportClaimRefs: vi.fn(async () => []) },
    claimMatcher: { satisfies: vi.fn(() => ({ satisfied: true, unmet: [] })) },
    identityRepo: {
      findRequirementsByService: vi.fn(async () => []),
      findClaimById: vi.fn(async () => null),
    },
    passportClaimsRepo: {
      markAllRevokedByPassportId: vi.fn(async () => []),
      insert: vi.fn(unexpected('passportClaimsRepo.insert')),
    },
    missionLookup: { findById: vi.fn(async () => null) },
    securityEvent: { record: vi.fn(async () => undefined) },
    authorityLookup: {
      resolvePassportRefs: unexpected('authorityLookup.resolvePassportRefs'),
      delegatePassportRefs: unexpected('authorityLookup.delegatePassportRefs'),
      verifyPassportRefs: unexpected('authorityLookup.verifyPassportRefs'),
      linkPassportRefs: unexpected('authorityLookup.linkPassportRefs'),
    },
    fleetLookup: {
      assertUnboundIssue: vi.fn(async () => undefined),
      validate: vi.fn(async () => undefined),
      validateDelegation: unexpected('fleetLookup.validateDelegation'),
      authorizeIssue: unexpected('fleetLookup.authorizeIssue'),
    },
    ...overrides,
    get dependencies(): PassportServiceDependencies {
      return {
        identityVerification: this.identityVerification as never,
        claimMatcher: this.claimMatcher as never,
        identityRepo: this.identityRepo as never,
        passportClaimsRepo: this.passportClaimsRepo as never,
        missionLookup: () => this.missionLookup,
        securityEvent: () => this.securityEvent as never,
        authorityLookup: () => this.authorityLookup,
        fleetLookup: () => this.fleetLookup,
      };
    },
  };
  return wiring;
}
