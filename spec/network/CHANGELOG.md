# Changelog: STACK Network

This specification follows semantic versioning. A claim set that carries its own version (`"v": 1`) changes it only in a major version of this specification. New optional claims, new fields in answers, new reasons and new endpoints are minor versions: verifiers ignore claims they do not know.

## 1.0.0 - 2026-10-24

Initial public release. The wire contract of the services a self-hosted install, or a company that deals with one, calls on STACK's network.

- The signed objects: install proof and key proof of possession (signed by an install key), countersignature, signed revocation list, STACK-verified statement and detection rule set (signed by STACK), each with its own `typ` and `aud`, and the rules every verifier applies.
- Install keys: the RFC 7638 thumbprint, the registration challenge and proof of possession, rollover and revocation.
- Install authentication: the single-use install proof, its claims per action, the refusal reasons, replay and rate handling, and which calls take which credential.
- Countersigning a passport by its digest, and checking a countersigned passport offline and online (`POST /v1/network/verify`).
- The STACK-verified statement and its status.
- Revocation: what a revocation names and covers, publishing by an install or the owner, the signed list and its cursor, and subscriptions that push the list as a Standard Webhooks request (signing, retries and secrets are those of the Webhooks specification).
- Detection rules and the classifier.
- Licence keys: their format, their use as a credential for rules and classify, and their revocation and check.
- Test vectors, produced by a public script from public test keys, and the `network-verifier` and `network-service` suites of the conformance kit.
