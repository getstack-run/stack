# Changelog: STACK Agent Keys

This specification follows semantic versioning. A major version changes what a conforming implementation must accept or reject; a minor version adds optional fields, endpoints or values that existing implementations can ignore; a patch version corrects wording.

## 1.0.0 - 2026-10-24

Initial public release.

- The key identifier `agent:{agent_id}:v1` and the agent's public key set at `/v1/agents/{agent_id}/.well-known/jwks.json`.
- Signing a claim envelope with an agent's own key as COSE_Sign1, and the rules for verifying it, including pinning the key identifier to the agent.
- What this version does not define: submission of a pre-signed claim, rotation history.
