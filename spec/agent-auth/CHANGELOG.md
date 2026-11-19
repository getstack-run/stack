# Changelog: STACK Agent Runtime Sign-in

This specification follows semantic versioning. A major version changes what a conforming implementation must accept or reject; a minor version adds optional fields, endpoints or values that existing implementations can ignore; a patch version corrects wording.

## 1.0.0 - 2026-10-24

Initial public release.

- Key enrollment by proof of possession: challenge, enroll, rotation and enrollment tickets.
- The agent JWT: issuer `stack-sdk`, audience `stack:agent`, EdDSA, 60 seconds minted, 120 seconds at most, single-use `jti`, the ordered checks of a server and the replay record.
- Fleet enrollment by a provisioner agent or a workload identity: challenge, enroll, idempotence, key replacement with a proof by the previous key, quotas and leases.
- JSON Schemas generated from the reference implementation.
