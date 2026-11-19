# Changelog: STACK Workload Identity Exchange

This specification follows semantic versioning. A major version changes what a conforming implementation must accept or reject; a minor version adds optional fields, endpoints or values that existing implementations can ignore; a patch version corrects wording.

## 1.0.0 - 2026-10-24

Initial public release.

- Acceptance of a SPIFFE JWT-SVID and a WIMSE Workload Identity Token: configuration, ordered checks, algorithm rules, key set fetching and caching.
- The exchange calls `POST /v1/workload/passport` and `POST /v1/workload/wit`: the Mission-bound Passport, the attestation claim, rate limits and error codes.
- Fleet enrollment by workload identity: exact trust entries, configuration selection, confirmation keys.
