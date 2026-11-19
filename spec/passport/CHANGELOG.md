# Changelog: STACK Passport

This specification follows semantic versioning. A major version changes what a conforming verifier must accept or reject; a minor version adds optional claims, operators or endpoints that existing verifiers can ignore; a patch version corrects wording.

## 1.3.0 - 2026-11-01

An operator-like constraint for a choice of rules.

- `any_of`: a constraint that holds several groups of constraints and is met when any one group is met in full. A verifier that does not know it must refuse the call (fail closed), so it is a minor version for the issuer and for verifiers that enforce constraints.
- Delegation: a child scope carries its parent's choice of rules whole and narrows it by adding constraints, an `any_of` of its own included. A scope holds at most eight of them.

## 1.2.0 - 2026-10-25

An optional claim, which existing verifiers can ignore.

- `workspace_command`: marks a Passport made for one command in an agent account's workspace. It is set only by the issuer, never accepted from a caller, carried by delegation, and a Passport that has it is not refreshed.

## 1.1.0 - 2026-10-24

Additions that document what the reference issuer already did, found while writing the conformance suite for online verification, revocation and delegation.

- The revoke calls (`revoke`, `revoke-agent`, `revoke-session`, `revoke-all`) and their answers.
- The delegation rule on declared intent (an `enforced` parent must have declared that it would delegate), how the parent's accountability is read, and how a connection is named in older tokens.
- A token that is not a Passport of the issuer (unreadable, tampered, signed by another key, or made for another audience or issuer) is `401 PASSPORT_INVALID`; a revoked or unknown Passport is `401 PASSPORT_REVOKED`; an expired one is `401 PASSPORT_EXPIRED`. A tampered or foreign token is no longer a server error.
- Verification may be rate limited.
- The `passport-online` conformance suite.

## 1.0.0 - 2026-10-21

Initial public release.

- Token: JWT in JWS compact form, EdDSA over Ed25519, issuer `getstack.run`, audience `stack:passport`, one `stk` claim object.
- Claims, service scopes, constraints (paths, operators, fail-closed evaluation), operation policies and data-flow declarations.
- Lifetimes: 15 minutes by default, 1 hour at most, 24 hours of refresh grace, delegation depth of at most 4, accountability modes.
- Issue, refresh and delegate rules, including narrowing-only delegation.
- Offline verification procedure, JWKS publication, and the online verification endpoint with its ordered checks.
- Revocation by `jti`, cascades, and the `stack:revoked` notification channel with its six event types.
- JSON Schemas generated from the reference implementation.
