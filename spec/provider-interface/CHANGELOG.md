# Changelog: STACK Provider Interface

This specification follows semantic versioning. A change that makes a previously conforming adapter non-conforming is a major version; a new optional method or a new piece kind is a minor version; a wording fix is a patch.

## 1.0.0 - 2026-10-21

Initial public release.

- The adapter interface: `find`, `open`, `close` and the optional `afterClose`, with the context and result types.
- The four outcome classes (`RetryablePieceError`, `PermanentPieceError`, `AwaitingCustomerError`, `PieceNotConfiguredError`) and how the caller treats each.
- The crash-safety and idempotency rules, the rules for public details and secrets, and the rule for an unconfigured provider.
- The `classifyPieceError` helper and the `@getstackrun/provider-interface` TypeScript package.
- The reference registry's piece kinds, providers and teardown order.
