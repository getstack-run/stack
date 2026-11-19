# Changelog: STACK OAuth Server Profile

This specification follows semantic versioning. A major version changes what a conforming implementation must accept or reject; a minor version adds optional fields, endpoints or values that existing implementations can ignore; a patch version corrects wording.

## 2.0.0 - 2026-10-25

- Removed: the scopes `partner-grants:read` and `partner-grants:write`, with the partner grants they governed. A request that names either is `invalid_scope`.

## 1.0.0 - 2026-10-24

Initial public release.

- The profile of OAuth 2.1 STACK's authorization server implements, and what it leaves out.
- Discovery, client identification by metadata document and by registration, redirect URI rules, resources and scopes.
- Authorization code with PKCE S256, refresh with rotation and reuse detection, the device grant, token exchange for a Passport, token formats and lifetimes, revocation, and the flat OAuth error shape.
